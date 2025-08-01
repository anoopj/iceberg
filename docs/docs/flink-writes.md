---
title: "Flink Writes"
---
<!--
 - Licensed to the Apache Software Foundation (ASF) under one or more
 - contributor license agreements.  See the NOTICE file distributed with
 - this work for additional information regarding copyright ownership.
 - The ASF licenses this file to You under the Apache License, Version 2.0
 - (the "License"); you may not use this file except in compliance with
 - the License.  You may obtain a copy of the License at
 -
 -   http://www.apache.org/licenses/LICENSE-2.0
 -
 - Unless required by applicable law or agreed to in writing, software
 - distributed under the License is distributed on an "AS IS" BASIS,
 - WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 - See the License for the specific language governing permissions and
 - limitations under the License.
 -->
# Flink Writes

Iceberg support batch and streaming writes With [Apache Flink](https://flink.apache.org/)'s DataStream API and Table API.

## Writing with SQL

Iceberg support both `INSERT INTO` and `INSERT OVERWRITE`.

### `INSERT INTO`

To append new data to a table with a Flink streaming job, use `INSERT INTO`:

```sql
INSERT INTO `hive_catalog`.`default`.`sample` VALUES (1, 'a');
INSERT INTO `hive_catalog`.`default`.`sample` SELECT id, data from other_kafka_table;
```

### `INSERT OVERWRITE`

To replace data in the table with the result of a query, use `INSERT OVERWRITE` in batch job (flink streaming job does not support `INSERT OVERWRITE`). Overwrites are atomic operations for Iceberg tables.

Partitions that have rows produced by the SELECT query will be replaced, for example:

```sql
INSERT OVERWRITE sample VALUES (1, 'a');
```

Iceberg also support overwriting given partitions by the `select` values:

```sql
INSERT OVERWRITE `hive_catalog`.`default`.`sample` PARTITION(data='a') SELECT 6;
```

For a partitioned iceberg table, when all the partition columns are set a value in `PARTITION` clause, it is inserting into a static partition, otherwise if partial partition columns (prefix part of all partition columns) are set a value in `PARTITION` clause, it is writing the query result into a dynamic partition.
For an unpartitioned iceberg table, its data will be completely overwritten by `INSERT OVERWRITE`.

### `UPSERT`

Iceberg supports `UPSERT` based on the primary key when writing data into v2 table format. There are two ways to enable upsert.

1. Enable the `UPSERT` mode as table-level property `write.upsert.enabled`. Here is an example SQL statement to set the table property when creating a table. It would be applied for all write paths to this table (batch or streaming) unless overwritten by write options as described later.

    ```sql
    CREATE TABLE `hive_catalog`.`default`.`sample` (
        `id` INT COMMENT 'unique id',
        `data` STRING NOT NULL,
        PRIMARY KEY(`id`) NOT ENFORCED
    ) with ('format-version'='2', 'write.upsert.enabled'='true');
    ```

2. Enabling `UPSERT` mode using `upsert-enabled` in the [write options](#write-options) provides more flexibility than a table level config. Note that you still need to use v2 table format and specify the [primary key](flink-ddl.md/#primary-key) or [identifier fields](../../spec.md#identifier-field-ids) when creating the table.

    ```sql
    INSERT INTO tableName /*+ OPTIONS('upsert-enabled'='true') */
    ...
    ```

!!! info
    OVERWRITE and UPSERT modes are mutually exclusive and cannot be enabled at the same time. When using UPSERT mode with a partitioned table, source columns of corresponding partition fields must be included in the equality fields. For example, if the partition field is `days(ts)`, then `ts` must be part of the equality fields. 

## Writing with DataStream

Iceberg support writing to iceberg table from different DataStream input.


### Appending data

Flink supports writing `DataStream<RowData>` and `DataStream<Row>` to the sink iceberg table natively.

```java
StreamExecutionEnvironment env = ...;

DataStream<RowData> input = ... ;
Configuration hadoopConf = new Configuration();
TableLoader tableLoader = TableLoader.fromHadoopTable("hdfs://nn:8020/warehouse/path", hadoopConf);

FlinkSink.forRowData(input)
    .tableLoader(tableLoader)
    .append();

env.execute("Test Iceberg DataStream");
```

### Overwrite data

Set the `overwrite` flag in FlinkSink builder to overwrite the data in existing iceberg tables:

```java
StreamExecutionEnvironment env = ...;

DataStream<RowData> input = ... ;
Configuration hadoopConf = new Configuration();
TableLoader tableLoader = TableLoader.fromHadoopTable("hdfs://nn:8020/warehouse/path", hadoopConf);

FlinkSink.forRowData(input)
    .tableLoader(tableLoader)
    .overwrite(true)
    .append();

env.execute("Test Iceberg DataStream");
```

### Upsert data

Set the `upsert` flag in FlinkSink builder to upsert the data in existing iceberg table. The table must use v2 table format and have a primary key.

```java
StreamExecutionEnvironment env = ...;

DataStream<RowData> input = ... ;
Configuration hadoopConf = new Configuration();
TableLoader tableLoader = TableLoader.fromHadoopTable("hdfs://nn:8020/warehouse/path", hadoopConf);

FlinkSink.forRowData(input)
    .tableLoader(tableLoader)
    .upsert(true)
    .append();

env.execute("Test Iceberg DataStream");
```

!!! info
    OVERWRITE and UPSERT modes are mutually exclusive and cannot be enabled at the same time. When using UPSERT mode with a partitioned table, source columns of corresponding partition fields must be included in the equality fields. For example, if the partition field is `days(ts)`, then `ts` must be part of the equality fields.



### Write with Avro GenericRecord

Flink Iceberg sink provides `AvroGenericRecordToRowDataMapper` that converts
Avro `GenericRecord` to Flink `RowData`. You can use the mapper to write
Avro GenericRecord DataStream to Iceberg.

Please make sure `flink-avro` jar is included in the classpath.
Also `iceberg-flink-runtime` shaded bundle jar can't be used
because the runtime jar shades the avro package.
Please use non-shaded `iceberg-flink` jar instead.

```java
DataStream<org.apache.avro.generic.GenericRecord> dataStream = ...;

Schema icebergSchema = table.schema();


// The Avro schema converted from Iceberg schema can't be used
// due to precision difference between how Iceberg schema (micro)
// and Flink AvroToRowDataConverters (milli) deal with time type.
// Instead, use the Avro schema defined directly.
// See AvroGenericRecordToRowDataMapper Javadoc for more details.
org.apache.avro.Schema avroSchema = AvroSchemaUtil.convert(icebergSchema, table.name());

GenericRecordAvroTypeInfo avroTypeInfo = new GenericRecordAvroTypeInfo(avroSchema);
RowType rowType = FlinkSchemaUtil.convert(icebergSchema);

FlinkSink.builderFor(
    dataStream,
    AvroGenericRecordToRowDataMapper.forAvroSchema(avroSchema),
    FlinkCompatibilityUtil.toTypeInfo(rowType))
  .table(table)
  .tableLoader(tableLoader)
  .append();
```

### Branch Writes
Writing to branches in Iceberg tables is also supported via the `toBranch` API in `FlinkSink`
For more information on branches please refer to [branches](branching.md).
```java
FlinkSink.forRowData(input)
    .tableLoader(tableLoader)
    .toBranch("audit-branch")
    .append();
```

### Metrics

The following Flink metrics are provided by the Flink Iceberg sink.

Parallel writer metrics are added under the sub group of `IcebergStreamWriter`.
They should have the following key-value tags.

* table: full table name (like iceberg.my_db.my_table)
* subtask_index: writer subtask index starting from 0

 Metric name                | Metric type | Description                                                                                         |
| ------------------------- |------------|-----------------------------------------------------------------------------------------------------|
| lastFlushDurationMs       | Gauge      | The duration (in milli) that writer subtasks take to flush and upload the files during checkpoint.  |
| flushedDataFiles          | Counter    | Number of data files flushed and uploaded.                                                          |
| flushedDeleteFiles        | Counter    | Number of delete files flushed and uploaded.                                                        |
| flushedReferencedDataFiles| Counter    | Number of data files referenced by the flushed delete files.                                        |
| dataFilesSizeHistogram    | Histogram  | Histogram distribution of data file sizes (in bytes).                                               |
| deleteFilesSizeHistogram  | Histogram  | Histogram distribution of delete file sizes (in bytes).                                             |

Committer metrics are added under the sub group of `IcebergFilesCommitter`.
They should have the following key-value tags.

* table: full table name (like iceberg.my_db.my_table)

 Metric name                      | Metric type | Description                                                                |
|---------------------------------|--------|----------------------------------------------------------------------------|
| lastCheckpointDurationMs        | Gauge  | The duration (in milli) that the committer operator checkpoints its state. |
| lastCommitDurationMs            | Gauge  | The duration (in milli) that the Iceberg table commit takes.               |
| committedDataFilesCount         | Counter | Number of data files committed.                                            |
| committedDataFilesRecordCount   | Counter | Number of records contained in the committed data files.                   |
| committedDataFilesByteCount     | Counter | Number of bytes contained in the committed data files.                     |
| committedDeleteFilesCount       | Counter | Number of delete files committed.                                          |
| committedDeleteFilesRecordCount | Counter | Number of records contained in the committed delete files.                 |
| committedDeleteFilesByteCount   | Counter | Number of bytes contained in the committed delete files.                   |
| elapsedSecondsSinceLastSuccessfulCommit| Gauge  | Elapsed time (in seconds) since last successful Iceberg commit.            |

`elapsedSecondsSinceLastSuccessfulCommit` is an ideal alerting metric
to detect failed or missing Iceberg commits.

* Iceberg commit happened after successful Flink checkpoint in the `notifyCheckpointComplete` callback.
  It could happen that Iceberg commits failed (for whatever reason), while Flink checkpoints succeeding.
* It could also happen that `notifyCheckpointComplete` wasn't triggered (for whatever bug).
  As a result, there won't be any Iceberg commits attempted.

If the checkpoint interval (and expected Iceberg commit interval) is 5 minutes, set up alert with rule like `elapsedSecondsSinceLastSuccessfulCommit > 60 minutes` to detect failed or missing Iceberg commits in the past hour.



## Options

### Write options

Flink write options are passed when configuring the FlinkSink, like this:

```java
FlinkSink.Builder builder = FlinkSink.forRow(dataStream, SimpleDataUtil.FLINK_SCHEMA)
    .table(table)
    .tableLoader(tableLoader)
    .set("write-format", "orc")
    .set(FlinkWriteOptions.OVERWRITE_MODE, "true");
```

For Flink SQL, write options can be passed in via SQL hints like this:

```sql
INSERT INTO tableName /*+ OPTIONS('upsert-enabled'='true') */
...
```

Check out all the options here: [write-options](flink-configuration.md#write-options) 

## Distribution mode

Flink streaming writer supports both `HASH` and `RANGE` distribution mode.
You can enable it via `FlinkSink#Builder#distributionMode(DistributionMode)`
or via [write-options](flink-configuration.md#write-options).

### Hash distribution

HASH distribution shuffles data by partition key (partitioned table) or
equality fields (non-partitioned table). It simply leverages Flink's
`DataStream#keyBy` to distribute the data.

HASH distribution has a few limitations.
<ul>
<li>It doesn't handle skewed data well. E.g. some partitions have a lot more data than others.
<li>It can result in unbalanced traffic distribution if cardinality of the partition key or
equality fields is low as demonstrated by [PR 4228](https://github.com/apache/iceberg/pull/4228).
<li>Writer parallelism is limited to the cardinality of the hash key.
If the cardinality is 10, only at most 10 writer tasks would get the traffic.
Having higher writer parallelism (even if traffic volume requires) won't help.
</ul>

### Range distribution (experimental)

RANGE distribution shuffles data by partition key or sort order via a custom range partitioner.
Range distribution collects traffic statistics to guide the range partitioner to
evenly distribute traffic to writer tasks.

Range distribution only shuffle the data via range partitioner. Rows are *not* sorted within
a data file, which Flink streaming writer doesn't support yet.

#### Use cases

RANGE distribution can be applied to an Iceberg table that either is partitioned or
has SortOrder defined. For a partitioned table without SortOrder, partition columns
are used as sort order. If SortOrder is explicitly defined for the table, it is used by
the range partitioner.

Range distribution can handle skewed data. E.g.
<ul>
<li>Table is partitioned by event time. Typically, recent hours have more data,
while the long-tail hours have less and less data.
<li>Table is partitioned by country code, where some countries (like US) have
a lot more traffic and smaller countries have a lot less data
<li>Table is partitioned by event type, where some types have a lot more data than others.
</ul>

Range distribution can also cluster data on non-partition columns.
E.g., table is partitioned hourly on ingestion time. Queries often include
predicate on a non-partition column like `device_id` or `country_code`.
Range partition would improve the query performance by clustering on the non-partition column
when table `SortOrder` is defined with the non-partition column.

#### Traffic statistics

Statistics are collected by every shuffle operator subtask and aggregated by the coordinator
for every checkpoint cycle. Aggregated statistics are broadcast to all subtasks and
applied to the range partitioner in the next checkpoint. So it may take up to two checkpoint
cycles to detect traffic distribution change and apply the new statistics to range partitioner.

Range distribution can work with low cardinality (like `country_code`)
or high cardinality (like `device_id`) scenarios.
<ul>
<li>For low cardinality scenario (like hundreds or thousands),
HashMap is used to track traffic distribution for every key.
If a new sort key value shows up, range partitioner would just
round-robin it to the writer tasks before traffic distribution has been learned
about the new key.
<li>For high cardinality scenario (like millions or billions),
uniform random sampling (reservoir sampling) is used to compute range bounds
that split the sort key space evenly.
It keeps the memory footprint and network exchange low.
Reservoir sampling work well if key distribution is relatively even.
If a single hot key has unbalanced large share of the traffic,
range split by uniform sampling probably won't work very well.
</ul>

#### Usage

Here is how to enable range distribution in Java. There are two optional advanced configs. Default should
work well for most cases. See [write-options](flink-configuration.md#write-options) for details.
```java
FlinkSink.forRowData(input)
    ...
    .distributionMode(DistributionMode.RANGE)
    .rangeDistributionStatisticsType(StatisticsType.Auto)
    .rangeDistributionSortKeyBaseWeight(0.0d)
    .append();
```

### Overhead

Data shuffling (hash or range) has computational overhead of serialization/deserialization 
and network I/O. Expect some increase of CPU utilization.

Range distribution also collect and aggregate data distribution statistics.
That would also incur some CPU overhead. Memory overhead is typically
small if using default statistics type of `Auto`. Don't use `Map` statistics
type if key cardinality is high. That could result in significant memory footprint
and large network exchange for statistics aggregation.

## Notes

Flink streaming write jobs rely on snapshot summary to keep the last committed checkpoint ID, and
store uncommitted data as temporary files. Therefore, [expiring snapshots](maintenance.md#expire-snapshots)
and [deleting orphan files](maintenance.md#delete-orphan-files) could possibly corrupt
the state of the Flink job. To avoid that, make sure to keep the last snapshot created by the Flink
job (which can be identified by the `flink.job-id` property in the summary), and only delete
orphan files that are old enough.

# Flink Writes (SinkV2 based implementation)

At the time when the current default, `FlinkSink` implementation was created, Flink Sink's interface had some
limitations that were not acceptable for the Iceberg tables purpose. Due to these limitations, `FlinkSink` is based 
on a custom chain of `StreamOperator`s  terminated by `DiscardingSink`.

In the 1.15 version of Flink [SinkV2 interface](https://cwiki.apache.org/confluence/display/FLINK/FLIP-191%3A+Extend+unified+Sink+interface+to+support+small+file+compaction)
was introduced. This interface is used in the new `IcebergSink` implementation which is available in the `iceberg-flink` module.
The new implementation is a base for further work on features such as [table maintenance](maintenance.md).
The SinkV2 based implementation is currently an experimental feature so use it with caution.

## Writing with SQL

To turn on SinkV2 based implementation in SQL, set this configuration option:
```sql
SET table.exec.iceberg.use-v2-sink = true;
```

## Writing with DataStream

To use SinkV2 based implementation, replace `FlinkSink` with `IcebergSink` in the provided snippets.
!!! warning
    There are some slight differences between these implementations:

     - The `RANGE` distribution mode is not yet available for the `IcebergSink`
     - When using `IcebergSink` use `uidSuffix` instead of the `uidPrefix`


## Dynamic Iceberg Flink Sink

Dynamic Flink Iceberg Sink allows:

1. **Writing to any number of tables**  
   A single sink can dynamically route records to multiple Iceberg tables.

2. **Dynamic table creation and updates**  
   Tables are created and updated based on user-defined routing logic.

3. **Dynamic schema and partition evolution**  
   Table schemas and partition specs update during streaming execution.

All configurations are controlled through the `DynamicRecord` class, eliminating the need for Flink job restarts when requirements change.

```java

    DynamicIcebergSink.forInput(dataStream)
        .generator((inputRecord, out) -> out.collect(
                new DynamicRecord(
                        TableIdentifier.of("db", "table"),
                        "branch",
                        SCHEMA,
                        (RowData) inputRecord,
                        PartitionSpec.unpartitioned(),
                        DistributionMode.HASH,
                        2)))
        .catalogLoader(CatalogLoader.hive("hive", new Configuration(), Map.of()))
        .writeParallelism(10)
        .immediateTableUpdate(true)
        .append();
```

### Configuration Example

```java
DynamicIcebergSink.Builder<RowData> builder = DynamicIcebergSink.forInput(inputStream);

// Set common properties
builder
    .set("write.parquet.compression-codec", "gzip");

// Set Dynamic Sink specific options
builder
    .writeParallelism(4)
    .uidPrefix("dynamic-sink")
    .cacheMaxSize(500)
    .cacheRefreshMs(5000);

// Add generator and append sink
builder.generator(new CustomRecordGenerator());
builder.append();
```

### Dynamic Routing Configuration

Dynamic table routing can be customized by implementing the `DynamicRecordGenerator` interface:

```java
public class CustomRecordGenerator implements DynamicRecordGenerator<RowData> {
    @Override
    public DynamicRecord generate(RowData row) {
        DynamicRecord record = new DynamicRecord();
        // Set table name based on business logic
        TableIdentifier tableIdentifier = TableIdentifier.of(database, tableName);
        record.setTableIdentifier(tableIdentifier);
        record.setData(row);
        // Set the maximum number of parallel writers for a given table/branch/schema/spec
        record.writeParallelism(2);
        return record;
    }
}

// Set custom record generator when building the sink
DynamicIcebergSink.Builder<RowData> builder = DynamicIcebergSink.forInput(inputStream);
builder.generator(new CustomRecordGenerator());
// ... other config ...
builder.append();
```
The user should provide a converter which converts the input record to a DynamicRecord.
We need the following information (DynamicRecord) for every record:

| Property           | Description                                                                               |
|--------------------|-------------------------------------------------------------------------------------------|
| `TableIdentifier`  | The target table to which the record will be written.                                     |
| `Branch`           | The target branch for writing the record (optional).                                      |
| `Schema`           | The schema of the record.                                                                 |
| `Spec`             | The expected partitioning specification for the record.                                   |
| `RowData`          | The actual row data to be written.                                                        |
| `DistributionMode` | The distribution mode for writing the record (currently supports NONE or HASH).           |
| `Parallelism`      | The maximum number of parallel writers for a given table/branch/schema/spec (WriteTarget). |
| `UpsertMode`       | Overrides this table's write.upsert.enabled (optional).                                   |
| `EqualityFields`   | The equality fields for the table(optional).                                                        |

### Schema Evolution

The dynamic sink tries to match the schema provided in `DynamicRecord` with the existing table schemas.
- If there is a direct match with one of the existing table schemas, that table schema will be used for writing to the table.
- If there is no direct match, DynamicSink tries to adapt the provided schema such that it matches one of table schemas. For example, if there is an additional optional column in the table schema, a null value will be added to the RowData provided via DynamicRecord.
- Otherwise, we evolve the table schema to match the input schema, within the constraints described below.

The dynamic sink maintains an LRU cache for both table metadata and incoming schemas, with eviction based on size and time constraints. When a DynamicRecord contains a schema that is incompatible with the current table schema, a schema update is triggered. This update can occur either immediately or via a centralized executor, depending on the `immediateTableUpdate` configuration. While centralized updates reduce load on the Catalog, they may introduce backpressure on the sink.

Supported schema updates:

- Adding new columns
- Widening existing column types (e.g., Integer → Long, Float → Double)
- Making required columns optional

Unsupported schema updates:

- Dropping columns
- Renaming columns

Dropping columns is avoided to prevent issues with late or out-of-order data, as removed fields cannot be easily restored without data loss. Renaming is unsupported because schema comparison is name-based, and renames would require additional metadata or hints to resolve.


#### Cache

There are two distinct caches involved: the table metadata cache and the input schema cache.

- The table metadata cache holds metadata such as schema definitions and partition specs to reduce repeated Catalog lookups. Its size is governed by the `cacheMaxSize` setting.
- The input schema cache stores incoming schemas per table along with their compatibility resolution results. Its size is controlled by `inputSchemasPerTableCacheMaxSize`.

To improve cache hit rates and performance, reuse the same DynamicRecord.schema instance if the record schema is unchanged.

### Dynamic Sink Configuration

The Dynamic Iceberg Flink Sink is configured using the Builder pattern. Here are the key configuration methods:

| Method                                               | Description                                                                                                                                                             |
|------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `overwrite(boolean enabled)`                         | Enable overwrite mode                                                                                                                                                   |
| `writeParallelism(int parallelism)`                  | Set writer parallelism                                                                                                                                                  |
| `uidPrefix(String prefix)`                           | Set operator UID prefix                                                                                                                                                 |
| `snapshotProperties(Map<String, String> properties)` | Set snapshot metadata properties                                                                                                                                        |
| `toBranch(String branch)`                            | Write to a specific branch                                                                                                                                              |
| `cacheMaxSize(int maxSize)`                          | Set cache size for table metadata                                                                                                                                       |
| `cacheRefreshMs(long refreshMs)`                     | Set cache refresh interval                                                                                                                                              |
| `inputSchemasPerTableCacheMaxSize(int size)`         | Set max input schemas to cache per table                                                                                                                                |
| `immediateTableUpdate(boolean enabled)`              | Controls whether table metadata (schema/partition spec) updates immediately (default: false)                                                                                                                                                                   |
| `set(String property, String value)`                 | Set any Iceberg write property (e.g., `"write.format"`, `"write.upsert.enabled"`).Check out all the options here: [write-options](flink-configuration.md#write-options) |
| `setAll(Map<String, String> properties)`             | Set multiple properties at once                                                                                                                                         |


### Notes

- **Range distribution mode**: Currently, the dynamic sink does not support the `RANGE` distribution mode, if set, it will fall back to `HASH`.
- **Property Precedence Note**: When conflicts occur between table properties and sink properties, the sink properties will override the table properties configuration.
