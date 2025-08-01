/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.iceberg.spark.source;

import org.apache.iceberg.IsolationLevel;
import org.apache.iceberg.MetadataColumns;
import org.apache.iceberg.Schema;
import org.apache.iceberg.Table;
import org.apache.iceberg.TableUtil;
import org.apache.iceberg.UpdateSchema;
import org.apache.iceberg.expressions.Expression;
import org.apache.iceberg.expressions.Expressions;
import org.apache.iceberg.relocated.com.google.common.base.Preconditions;
import org.apache.iceberg.spark.SparkFilters;
import org.apache.iceberg.spark.SparkSchemaUtil;
import org.apache.iceberg.spark.SparkUtil;
import org.apache.iceberg.spark.SparkWriteConf;
import org.apache.iceberg.spark.SparkWriteRequirements;
import org.apache.iceberg.types.TypeUtil;
import org.apache.spark.sql.SparkSession;
import org.apache.spark.sql.connector.read.Scan;
import org.apache.spark.sql.connector.write.BatchWrite;
import org.apache.spark.sql.connector.write.LogicalWriteInfo;
import org.apache.spark.sql.connector.write.RowLevelOperation.Command;
import org.apache.spark.sql.connector.write.SupportsDynamicOverwrite;
import org.apache.spark.sql.connector.write.SupportsOverwrite;
import org.apache.spark.sql.connector.write.Write;
import org.apache.spark.sql.connector.write.WriteBuilder;
import org.apache.spark.sql.connector.write.streaming.StreamingWrite;
import org.apache.spark.sql.sources.Filter;
import org.apache.spark.sql.types.LongType$;
import org.apache.spark.sql.types.StructType;

class SparkWriteBuilder implements WriteBuilder, SupportsDynamicOverwrite, SupportsOverwrite {
  private final SparkSession spark;
  private final Table table;
  private final SparkWriteConf writeConf;
  private final LogicalWriteInfo writeInfo;
  private final StructType dsSchema;
  private final String overwriteMode;
  private final String rewrittenFileSetId;
  private boolean overwriteDynamic = false;
  private boolean overwriteByFilter = false;
  private Expression overwriteExpr = null;
  private boolean overwriteFiles = false;
  private SparkCopyOnWriteScan copyOnWriteScan = null;
  private Command copyOnWriteCommand = null;
  private IsolationLevel copyOnWriteIsolationLevel = null;

  SparkWriteBuilder(SparkSession spark, Table table, String branch, LogicalWriteInfo info) {
    this.spark = spark;
    this.table = table;
    this.writeConf = new SparkWriteConf(spark, table, branch, info.options());
    this.writeInfo = info;
    this.dsSchema = info.schema();
    this.overwriteMode = writeConf.overwriteMode();
    this.rewrittenFileSetId = writeConf.rewrittenFileSetId();
  }

  public WriteBuilder overwriteFiles(Scan scan, Command command, IsolationLevel isolationLevel) {
    Preconditions.checkState(!overwriteByFilter, "Cannot overwrite individual files and by filter");
    Preconditions.checkState(
        !overwriteDynamic, "Cannot overwrite individual files and dynamically");
    Preconditions.checkState(
        rewrittenFileSetId == null, "Cannot overwrite individual files and rewrite");

    this.overwriteFiles = true;
    this.copyOnWriteScan = (SparkCopyOnWriteScan) scan;
    this.copyOnWriteCommand = command;
    this.copyOnWriteIsolationLevel = isolationLevel;
    return this;
  }

  @Override
  public WriteBuilder overwriteDynamicPartitions() {
    Preconditions.checkState(
        !overwriteByFilter, "Cannot overwrite dynamically and by filter: %s", overwriteExpr);
    Preconditions.checkState(!overwriteFiles, "Cannot overwrite individual files and dynamically");
    Preconditions.checkState(
        rewrittenFileSetId == null, "Cannot overwrite dynamically and rewrite");

    this.overwriteDynamic = true;
    return this;
  }

  @Override
  public WriteBuilder overwrite(Filter[] filters) {
    Preconditions.checkState(
        !overwriteFiles, "Cannot overwrite individual files and using filters");
    Preconditions.checkState(rewrittenFileSetId == null, "Cannot overwrite and rewrite");

    this.overwriteExpr = SparkFilters.convert(filters);
    if (overwriteExpr == Expressions.alwaysTrue() && "dynamic".equals(overwriteMode)) {
      // use the write option to override truncating the table. use dynamic overwrite instead.
      this.overwriteDynamic = true;
    } else {
      Preconditions.checkState(
          !overwriteDynamic, "Cannot overwrite dynamically and by filter: %s", overwriteExpr);
      this.overwriteByFilter = true;
    }
    return this;
  }

  @Override
  public Write build() {
    // The write schema should only include row lineage in the output if it's an overwrite
    // operation or if it's a compaction.
    // In any other case, only null row IDs and sequence numbers would be produced which
    // means the row lineage columns can be excluded from the output files
    boolean writeRequiresRowLineage =
        TableUtil.supportsRowLineage(table)
            && (overwriteFiles || writeConf.rewrittenFileSetId() != null);
    boolean writeAlreadyIncludesLineage =
        dsSchema.exists(field -> field.name().equals(MetadataColumns.ROW_ID.name()));
    StructType sparkWriteSchema = dsSchema;
    if (writeRequiresRowLineage && !writeAlreadyIncludesLineage) {
      sparkWriteSchema = sparkWriteSchema.add(MetadataColumns.ROW_ID.name(), LongType$.MODULE$);
      sparkWriteSchema =
          sparkWriteSchema.add(
              MetadataColumns.LAST_UPDATED_SEQUENCE_NUMBER.name(), LongType$.MODULE$);
    }

    Schema writeSchema =
        validateOrMergeWriteSchema(table, sparkWriteSchema, writeConf, writeRequiresRowLineage);
    SparkUtil.validatePartitionTransforms(table.spec());

    // Get application id
    String appId = spark.sparkContext().applicationId();

    return new SparkWrite(
        spark, table, writeConf, writeInfo, appId, writeSchema, dsSchema, writeRequirements()) {

      @Override
      public BatchWrite toBatch() {
        if (rewrittenFileSetId != null) {
          return asRewrite(rewrittenFileSetId);
        } else if (overwriteByFilter) {
          return asOverwriteByFilter(overwriteExpr);
        } else if (overwriteDynamic) {
          return asDynamicOverwrite();
        } else if (overwriteFiles) {
          return asCopyOnWriteOperation(copyOnWriteScan, copyOnWriteIsolationLevel);
        } else {
          return asBatchAppend();
        }
      }

      @Override
      public StreamingWrite toStreaming() {
        Preconditions.checkState(
            !overwriteDynamic, "Unsupported streaming operation: dynamic partition overwrite");
        Preconditions.checkState(
            !overwriteByFilter || overwriteExpr == Expressions.alwaysTrue(),
            "Unsupported streaming operation: overwrite by filter: %s",
            overwriteExpr);
        Preconditions.checkState(
            rewrittenFileSetId == null, "Unsupported streaming operation: rewrite");

        if (overwriteByFilter) {
          return asStreamingOverwrite();
        } else {
          return asStreamingAppend();
        }
      }
    };
  }

  private SparkWriteRequirements writeRequirements() {
    if (overwriteFiles) {
      return writeConf.copyOnWriteRequirements(copyOnWriteCommand);
    } else {
      return writeConf.writeRequirements();
    }
  }

  private static Schema validateOrMergeWriteSchema(
      Table table, StructType dsSchema, SparkWriteConf writeConf, boolean writeIncludesRowLineage) {
    Schema writeSchema;
    boolean caseSensitive = writeConf.caseSensitive();
    if (writeConf.mergeSchema()) {
      // convert the dataset schema and assign fresh ids for new fields
      Schema newSchema =
          SparkSchemaUtil.convertWithFreshIds(table.schema(), dsSchema, caseSensitive);

      // update the table to get final id assignments and validate the changes
      UpdateSchema update =
          table.updateSchema().caseSensitive(caseSensitive).unionByNameWith(newSchema);
      Schema mergedSchema = update.apply();
      if (writeIncludesRowLineage) {
        mergedSchema =
            TypeUtil.join(mergedSchema, MetadataColumns.schemaWithRowLineage(table.schema()));
      }

      // reconvert the dsSchema without assignment to use the ids assigned by UpdateSchema
      writeSchema = SparkSchemaUtil.convert(mergedSchema, dsSchema, caseSensitive);

      TypeUtil.validateWriteSchema(
          mergedSchema, writeSchema, writeConf.checkNullability(), writeConf.checkOrdering());

      // if the validation passed, update the table schema
      update.commit();
    } else {
      Schema schema =
          writeIncludesRowLineage
              ? MetadataColumns.schemaWithRowLineage(table.schema())
              : table.schema();
      writeSchema = SparkSchemaUtil.convert(schema, dsSchema, caseSensitive);
      TypeUtil.validateWriteSchema(
          table.schema(), writeSchema, writeConf.checkNullability(), writeConf.checkOrdering());
    }

    return writeSchema;
  }
}
