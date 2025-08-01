---
title: "How To Release"
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

## Introduction

This page walks you through the release process of the Iceberg project. [Here](https://www.apache.org/legal/release-policy.html) you can read about the release process in general for an Apache project.

Decisions about releases are made by three groups:

* Release Manager: Does the work of creating the release, signing it, counting [votes](#voting), announcing the release and so on. Requires the assistance of a committer for some steps.
* The community: Performs the discussion of whether it is the right time to create a release and what that release should contain. The community can also cast non-binding votes on the release.
* PMC: Gives binding votes on the release.

This page describes the procedures that the release manager and voting PMC members take during the release process.

## Setup

To create a release candidate, you will need:

* Apache LDAP credentials for Nexus and SVN
* A [GPG key for signing](https://www.apache.org/dev/release-signing#generate), published in [KEYS](https://downloads.apache.org/iceberg/KEYS)

If you have not published your GPG key yet, you must publish it before sending the vote email by doing:

```shell
svn co https://dist.apache.org/repos/dist/release/iceberg icebergsvn
cd icebergsvn
echo "" >> KEYS # append a newline
gpg --list-sigs <YOUR KEY ID HERE> >> KEYS # append signatures
gpg --armor --export <YOUR KEY ID HERE> >> KEYS # append public key block
svn commit -m "add key for <YOUR NAME HERE>"
```

### Nexus access

Nexus credentials are configured in your personal `~/.gradle/gradle.properties` file using `mavenUser` and `mavenPassword`:

```
mavenUser=yourApacheID
mavenPassword=SomePassword
```

### PGP signing

The release scripts use the command-line `gpg` utility so that signing can use the gpg-agent and does not require writing your private key's passphrase to a configuration file.

To configure gradle to sign convenience binary artifacts, add the following settings to `~/.gradle/gradle.properties`:

```
signing.gnupg.keyName=Your Name (CODE SIGNING KEY)
```

To use `gpg` instead of `gpg2`, also set `signing.gnupg.executable=gpg`

For more information, see the Gradle [signing documentation](https://docs.gradle.org/current/userguide/signing_plugin.html#sec:signatory_credentials).

### Apache repository

The release should be executed against `https://github.com/apache/iceberg.git` instead of any fork.
Set it as remote with name `apache` for release if it is not already set up.

## Creating a release candidate

### Initiate a discussion about the release with the community

This step can be useful to gather ongoing patches that the community thinks should be in the upcoming release.

The communication can be started via a [DISCUSS] mail on the dev@ channel and the desired tickets can be added to the github milestone of the next release.

Note, creating a milestone in github requires a committer. However, a non-committer can assign tasks to a milestone if added to the list of collaborators in [.asf.yaml](https://github.com/apache/iceberg/blob/main/.asf.yaml)

The release status is discussed during each community sync meeting. Release manager should join the meeting to report status and discuss any release blocker.

### Build the source release

To create the source release artifacts, run the `source-release.sh` script with the release version and release candidate number:

```bash
dev/source-release.sh -v 1.8.0 -r 0 -k <YOUR KEY ID HERE>
```

Example console output:

```text
Preparing source for apache-iceberg-1.8.0-rc0
Adding version.txt and tagging release...
[main ca8bb7d0] Add version.txt for release 1.8.0
 1 file changed, 1 insertion(+)
 create mode 100644 version.txt
Pushing apache-iceberg-1.8.0-rc0 to origin...
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 12 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (4/4), 433 bytes | 433.00 KiB/s, done.
Total 4 (delta 1), reused 0 (delta 0)
remote: Resolving deltas: 100% (1/1), completed with 1 local object.
To https://github.com/apache/iceberg.git
 * [new tag]           apache-iceberg-1.8.0-rc0 -> apache-iceberg-1.8.0-rc0
Creating tarball  using commit ca8bb7d0821f35bbcfa79a39841be8fb630ac3e5
Signing the tarball...
Checking out Iceberg RC subversion repo...
Checked out revision 52260.
Adding tarball to the Iceberg distribution Subversion repo...
A         tmp/apache-iceberg-1.8.0-rc0
A         tmp/apache-iceberg-1.8.0-rc0/apache-iceberg-1.8.0.tar.gz.asc
A  (bin)  tmp/apache-iceberg-1.8.0-rc0/apache-iceberg-1.8.0.tar.gz
A         tmp/apache-iceberg-1.8.0-rc0/apache-iceberg-1.8.0.tar.gz.sha512
Adding         tmp/apache-iceberg-1.8.0-rc0
Adding  (bin)  tmp/apache-iceberg-1.8.0-rc0/apache-iceberg-1.8.0.tar.gz
Adding         tmp/apache-iceberg-1.8.0-rc0/apache-iceberg-1.8.0.tar.gz.asc
Adding         tmp/apache-iceberg-1.8.0-rc0/apache-iceberg-1.8.0.tar.gz.sha512
Transmitting file data ...done
Committing transaction...
Committed revision 52261.
Creating release-announcement-email.txt...
Success! The release candidate is available here:
  https://dist.apache.org/repos/dist/dev/iceberg/apache-iceberg-1.8.0-rc0

Commit SHA1: ca8bb7d0821f35bbcfa79a39841be8fb630ac3e5

We have generated a release announcement email for you here:
/Users/jackye/iceberg/release-announcement-email.txt

Please note that you must update the Nexus repository URL
contained in the mail before sending it out.
```

The source release script will create a candidate tag based on the HEAD revision in git and will prepare the release tarball, signature, and checksum files. It will also upload the source artifacts to SVN.

Note the commit SHA1 and candidate location because those will be added to the vote thread.

Once the source release is ready, use it to stage convenience binary artifacts in Nexus.

### Build and stage convenience binaries

Convenience binaries are created using the source release tarball from in the last step.

Untar the source release and go into the release directory:

```bash
tar xzf apache-iceberg-1.8.0.tar.gz
cd apache-iceberg-1.8.0
```

To build and publish the convenience binaries, run the `dev/stage-binaries.sh` script. This will push to a release staging repository.

Disable gradle parallelism by setting `org.gradle.parallel=false` in `gradle.properties`.

```
dev/stage-binaries.sh
```

Next, you need to close the staging repository:

1. Go to [Nexus](https://repository.apache.org/) and log in
2. In the menu on the left, choose "Staging Repositories"
3. Select the Iceberg repository
   * If multiple staging repositories are created after running the script, verify that gradle parallelism is disabled and try again.
4. At the top, select "Close" and follow the instructions
   * In the comment field use "Apache Iceberg &lt;version&gt; RC&lt;num&gt;"

### Start a VOTE thread

The last step for a candidate is to create a VOTE thread on the dev mailing list.
The email template is already generated in `release-announcement-email.txt` with some details filled.

Example title subject:

```text
[VOTE] Release Apache Iceberg <VERSION> RC<NUM>
```

Example content:

```text
Hi everyone,

I propose the following RC to be released as official Apache Iceberg <VERSION> release.

The commit id is <SHA1>
* This corresponds to the tag: apache-iceberg-<VERSION>-rc<NUM>
* https://github.com/apache/iceberg/commits/apache-iceberg-<VERSION>-rc<NUM>
* https://github.com/apache/iceberg/tree/<SHA1>

The release tarball, signature, and checksums are here:
* https://dist.apache.org/repos/dist/dev/iceberg/apache-iceberg-<VERSION>-rc<NUM>/

You can find the KEYS file here:
* https://downloads.apache.org/iceberg/KEYS

Convenience binary artifacts are staged in Nexus. The Maven repository URL is:
* https://repository.apache.org/content/repositories/orgapacheiceberg-<ID>/

This release includes important changes that I should have summarized here, but I'm lazy.

Please download, verify, and test.

Please vote in the next 72 hours. (Weekends excluded)

[ ] +1 Release this as Apache Iceberg <VERSION>
[ ] +0
[ ] -1 Do not release this because...

Only PMC members have binding votes, but other community members are encouraged to cast
non-binding votes. This vote will pass if there are 3 binding +1 votes and more binding
+1 votes than -1 votes.
```

When a candidate is passed or rejected, reply with the voting result:

```text
Subject: [RESULT][VOTE] Release Apache Iceberg <VERSION> RC<NUM>
```

```text
Thanks everyone who participated in the vote for Release Apache Iceberg <VERSION> RC<NUM>.

The vote result is:

+1: 3 (binding), 5 (non-binding)
+0: 0 (binding), 0 (non-binding)
-1: 0 (binding), 0 (non-binding)

Therefore, the release candidate is passed/rejected.
```


### Finishing the release

After the release vote has passed, you need to release the last candidate's artifacts.

But note that releasing the artifacts should happen around the same time the new docs are released
so make sure the [documentation changes](#documentation-release)
are prepared when going through the below steps.

#### Publishing the release

First, copy the source release directory to releases:

```bash
svn mv https://dist.apache.org/repos/dist/dev/iceberg/apache-iceberg-<VERSION>-rcN https://dist.apache.org/repos/dist/release/iceberg/apache-iceberg-<VERSION> -m "Iceberg: Add release <VERSION>"
```

!!! Note
    The above step requires PMC privileges to execute.

Next, add a release tag to the git repository based on the passing candidate tag:

```bash
git tag -am 'Release Apache Iceberg <VERSION>' apache-iceberg-<VERSION> apache-iceberg-<VERSION>-rcN
```

Create a new release in the iceberg repository on GitHub, using the tag created above [Steps](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)

Then release the candidate repository in [Nexus](https://repository.apache.org/#stagingRepositories).

#### Announcing the release

To announce the release, wait until Maven central has mirrored the Apache binaries, then update the Iceberg site and send an announcement email:

```text
[ANNOUNCE] Apache Iceberg release <VERSION>
```
```text
I'm pleased to announce the release of Apache Iceberg <VERSION>!

Apache Iceberg is an open table format for huge analytic datasets. Iceberg
delivers high query performance for tables with tens of petabytes of data,
along with atomic commits, concurrent writes, and SQL-compatible table
evolution.

This release can be downloaded from: https://www.apache.org/dyn/closer.cgi/iceberg/<TARBALL NAME WITHOUT .tar.gz>/<TARBALL NAME>

Release notes: https://iceberg.apache.org/releases/#XYZ-release

Java artifacts are available from Maven Central.

Thanks to everyone for contributing!
```

#### Update revapi

Create a PR in the `iceberg` repo to make revapi run on the new release. For an example see [this PR](https://github.com/apache/iceberg/pull/6275).

#### Update GitHub

- Create a PR in the `iceberg` repo to add the new version to the github issue template. For an example see [this PR](https://github.com/apache/iceberg/pull/6287).
- Draft [a new release to update Github](https://github.com/apache/iceberg/releases/new) to show the latest release. A changelog can be generated automatically using Github.

#### Update DOAP (ASF Project Description)

- Create a PR to update the release version in [doap.rdf](https://github.com/apache/iceberg/blob/main/doap.rdf) file, in the `<release/>` section:

```xml
    <release>
      <Version>
        <name>x.y.z</name>
        <created>yyyy-mm-dd</created>
        <revision>x.y.z</revision>
      </Version>
    </release>
```

### Documentation Release

Please follow the instructions on the GitHub repository in the [`README.md` in the `site/`](https://github.com/apache/iceberg/tree/main/site) directory.

#### Versioned Docs

The versioned docs is located in the `docs` directory within the source of the released tag (e.g. https://github.com/apache/iceberg/tree/apache-iceberg-1.8.0/docs). 
Check out the `docs` branch in the `iceberg` repo and copy the versioned docs over:

```
cp -R iceberg/docs 1.8.0
```

Once this is done, create a PR against the `docs` branch containing the changes under the `1.8.0` folder, similar to https://github.com/apache/iceberg/pull/12411.

Note: Update the site name from `docs/latest` to `docs/1.8.0` in the copied `mkdocs.yml` file.

#### Versioned Javadoc

Navigate to the source tarball and generate Javadoc:

Note: When generating Javadoc, make sure to use JDK 17+.

```
cd apache-iceberg-1.8.0
./gradlew refreshJavadoc
```

The versioned Javadoc will be generated under `site/docs/javadoc/1.8.0`.

Check out the `javadoc` branch in the `iceberg` repo and copy the generated Javadoc over:

```
cp -R apache-iceberg-1.8.0/site/docs/javadoc/1.8.0 1.8.0
```

Once this is done, create a PR against the `javadoc` branch, similar to https://github.com/apache/iceberg/pull/12412.

#### Site update

Submit a PR, following the approach in https://github.com/apache/iceberg/pull/12242, 
to update the Iceberg version, the links to the new version's documentation, and the release notes.

# How to Verify a Release

Each Apache Iceberg release is validated by the community by holding a vote. A community release manager
will prepare a release candidate and call a vote on the Iceberg
[dev list](community.md#mailing-lists).
To validate the release candidate, community members will test it out in their downstream projects and environments.
It's recommended to report the Java, Scala, Spark, Flink and Hive versions you have tested against when you vote.

In addition to testing in downstream projects, community members also check the release's signatures, checksums, and
license documentation.

## Validating a source release candidate

Release announcements include links to the following:

- **A source tarball**
- **A signature (.asc)**
- **A checksum (.sha512)**
- **KEYS file**
- **GitHub change comparison**

After downloading the source tarball, signature, checksum, and KEYS file, here are instructions on how to
verify signatures, checksums, and documentation.

### Verifying Signatures

First, import the keys.
```bash
curl https://downloads.apache.org/iceberg/KEYS -o KEYS
gpg --import KEYS
```

Next, verify the `.asc` file.
```bash
gpg --verify apache-iceberg-{{ icebergVersion }}.tar.gz.asc
```

### Verifying Checksums

```bash
shasum -a 512 --check apache-iceberg-{{ icebergVersion }}.tar.gz.sha512
```

### Verifying License Documentation

Untar the archive and change into the source directory.
```bash
tar xzf apache-iceberg-{{ icebergVersion }}.tar.gz
cd apache-iceberg-{{ icebergVersion }}
```

Run RAT checks to validate license headers.
```bash
dev/check-license
```

### Verifying Build and Test

To verify that the release candidate builds properly, run the following command.
```bash
./gradlew build
```

## Testing release binaries

Release announcements will also include a maven repository location. You can use this
location to test downstream dependencies by adding it to your maven or gradle build.

To use the release in your maven build, add the following to your `POM` or `settings.xml`:
```xml
...
  <repositories>
    <repository>
      <id>iceberg-release-candidate</id>
      <name>Iceberg Release Candidate</name>
      <url>${MAVEN_URL}</url>
    </repository>
  </repositories>
...
```

To use the release in your gradle build, add the following to your `build.gradle`:
```groovy
repositories {
    mavenCentral()
    maven {
        url "${MAVEN_URL}"
    }
}
```

!!! Note
    Replace `${MAVEN_URL}` with the URL provided in the release announcement

### Verifying with Spark

To verify using spark, start a `spark-shell` with a command like the following command (use the appropriate
spark-runtime jar for the Spark installation):
```bash
spark-shell \
    --conf spark.jars.repositories=${MAVEN_URL} \
    --packages org.apache.iceberg:iceberg-spark-runtime-3.5_2.12:{{ icebergVersion }} \
    --conf spark.sql.extensions=org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions \
    --conf spark.sql.catalog.local=org.apache.iceberg.spark.SparkCatalog \
    --conf spark.sql.catalog.local.type=hadoop \
    --conf spark.sql.catalog.local.warehouse=$PWD/warehouse \
    --conf spark.sql.catalog.local.default-namespace=default \
    --conf spark.sql.defaultCatalog=local
```

### Verifying with Flink

To verify using Flink, start a Flink SQL Client with the following command:
```bash
wget ${MAVEN_URL}/iceberg-flink-runtime-1.20/{{ icebergVersion }}/iceberg-flink-runtime-1.20-{{ icebergVersion }}.jar

sql-client.sh embedded \
    -j iceberg-flink-runtime-1.20-{{ icebergVersion }}.jar \
    -j flink-connector-hive_2.12-1.20.jar \
    shell
```


## Voting

Votes are cast by replying to the release candidate announcement email on the dev mailing list
with either `+1`, `0`, or `-1`.

> [ ] +1 Release this as Apache Iceberg {{ icebergVersion }}
>
> [ ] +0
>
> [ ] -1 Do not release this because...

In addition to your vote, it's customary to specify if your vote is binding or non-binding. Only members
of the Project Management Committee have formally binding votes. If you're unsure, you can specify that your
vote is non-binding. To read more about voting in the Apache framework, checkout the
[Voting](https://www.apache.org/foundation/voting.html) information page on the Apache foundation's website.
