<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 The CipherSift Authors -->

# CipherSift — Behavioural Specification

Version 1.0 of the specification (rule format version 1), with the later amendments recorded in
`DECISIONS.md` (evaluation fixes, owner decisions, CycloneDX 1.7, Go support, fix round). Status:
implemented (CipherSift 1.0.0-SNAPSHOT).

CipherSift is an open-source (Apache-2.0) static scanner written in Java. It finds
cryptographic assets in **Java**, **Python** and **Go** source code and in **Maven/Gradle**,
**PyPI** and **Go module** dependency manifests, and writes a **CycloneDX 1.7** Cryptography Bill of Materials
(CBOM) as JSON (CycloneDX 1.6 on request, `--cyclonedx-version 1.6`).

This document is the only description of the behaviour. It is written for an engineer who
implements CipherSift from it, together with the rule files in `rules/` and the conformance
suite in `spec/conformance/`. It describes behaviour, not an implementation; where it
suggests a design, the suggestion is marked *(advice)* and may be replaced by anything with
the same observable behaviour.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## Contents

1. Scope and terminology
2. Architecture
3. Command-line interface
4. File collection and classification
5. Rule format
6. Parsing
7. Java source analysis
8. Python source analysis
9. Dependency manifests
10. Normalisation: findings to components
11. CBOM output
12. Determinism
13. Error handling
14. Performance
15. Build, packaging and licensing
16. Testing and conformance
17. Go source analysis (added after 1.0)
18. Wrapper propagation (added after 1.0)
- Appendix A. Intentional differences from the reference tool
- Appendix B. Known limitations (by design)
- Appendix C. Tree-sitter node types and fields used
- Appendix D. Roadmap: deep mode (potentially later)

---

## 1. Scope and terminology

### 1.1 In scope

* Source-code discovery in files with the extension `.java` (Java), `.py` (Python) and `.go`
  (Go, section 17).
  Detection is rule-driven: the cryptographic knowledge lives in rule files (section 5),
  the scanner provides language analysis (name resolution, constant resolution, argument
  analysis).
* Dependency discovery in Maven `pom.xml`, Gradle `build.gradle`, `build.gradle.kts` and
  version catalogs (`*.versions.toml`), and Python `requirements*.txt`, `pyproject.toml`,
  `Pipfile`, `Pipfile.lock`, `poetry.lock`, `setup.cfg` and the literal requirements of `setup.py`
  (9.8), and Go `go.mod` and `go.sum` (17.10); lock files and `// indirect` requirements only with
  `--transitive-deps` (3.1). Only packages on the crypto-library lists of the
  dependency rules are reported.
* Output: one CycloneDX 1.7 JSON document (1.6 with `--cyclonedx-version 1.6`).

### 1.2 Out of scope

Ruby, Kotlin and other languages; configuration files (nginx, sshd, …); parsing of
certificate, key or keystore files; weakness / CVE assessment; data-flow analysis beyond
the constant resolution and the call-site propagation of the project's own wrappers (section 18)
described here; type inference; reading compiled code (jars, wheels).

### 1.3 Terms

| Term | Meaning |
|---|---|
| scan root | The directory given on the command line, after resolving it to an absolute, canonical path. |
| relative path | The path of a file relative to the scan root, with `/` as separator, no leading `./`. All paths in the output are relative paths. |
| rule | A YAML or JSON document of kind `source` or `dependency` (section 5). |
| pattern | One element of a source rule's `match` list. A rule matches a code location if at least one of its patterns matches. |
| anchor | The key of a pattern that says *what kind of code location* it looks at (`call`, `new`, `method`, `field`, `override`, `anyCall`, `assign`, `ref`, `composite`). |
| condition | Any further key of a pattern that restricts the anchor (`firstString`, `kwargs`, …). All conditions of a pattern must hold. |
| finding | One match: (file, line, rule, extra data). Produced by the extractors. |
| component | A CycloneDX component. Findings with the same identity (section 10) form one component; each finding becomes one occurrence. |
| reference tool | The Python tool CipherSift's behaviour was derived from (see `PROVENANCE.md`). Mentioned only to explain intentional differences (Appendix A). |

Line numbers are 1-based. Line *n* starts after the (*n*−1)-th line-feed byte (`0x0A`) of
the file; a carriage return alone does not start a line.

---

## 2. Architecture

A scan runs five phases in this order. Phases 3 and 4 run per file and MAY run in parallel
(section 14); all other phases are sequential.

```
  rules ──► (0) rule loading
                 │
  scan root ─► (1) file collection ─► (2) classification ─► (3) extraction ─► (4) normalisation ─► (5) CBOM writing
                                         java / python / go /    per file:        findings →            JSON
                                         manifest / ignored      findings         components
```

0. **Rule loading** (section 5): read all rule documents from the bundled rule set or from
   `--rules DIR`, validate them, build the per-language indexes.
1. **File collection** (section 4.1–4.4): walk the scan root, apply exclusions, size limit.
2. **Classification** (section 4.5–4.7): decide for every collected file whether it is Java,
   Python or Go source, a manifest of a known format, or ignored; detect test files;
   detect binary content.
3. **Extraction**: Java analysis (section 7), Python analysis (section 8), Go analysis
   (section 17), manifest parsing (sections 9, 17.10). Each produces findings.
   Then, across files, **wrapper propagation** (section 18): the call sites of the project's own
   crypto wrappers become further findings. It needs a project-wide definition index, so it runs
   after all files are extracted (its parsing MAY run in parallel).
4. **Normalisation** (section 10): group findings into components by identity; build
   occurrences; deduplicate.
5. **CBOM writing** (section 11): serialise components in a fixed order.

### 2.1 Data model

A **source finding** has: relative path, line, rule, *name* (the component name, section
10.2), *symbol* (the API the finding is anchored on), *snippet* (source text, at most 500
code points), *param* (optional parameter-set identifier, e.g. `2048` or `SECP256R1`), and
the flag *test* (the file is a test file, section 4.7).

A **dependency finding** has: relative path of the manifest, rule, ecosystem (`maven`, `pypi`
or `golang`), package (Maven `groupId:artifactId`, PyPI normalised name, Go module path), version (or none),
manifest format, snippet (the coordinate as text) and the *test* flag. It has no line.

Asset properties (type, primitive, family, variant, …) are never stored in a finding; they
come from the rule.

---

## 3. Command-line interface

The jar's main class implements the command `ciphersift`. The distribution SHOULD contain
a launcher script `bin/ciphersift` that runs
`java --enable-native-access=ALL-UNNAMED -jar <jar> "$@"`.

**Java runtime** *(DECISIONS follow-up F1)*. The launcher uses `$CIPHERSIFT_JAVA` (a `java` executable),
else `$JAVA_HOME/bin/java`, else `java` on `PATH`. If the chosen runtime is older than Java 23,
the next *explicitly configured* one (`CIPHERSIFT_JAVA`, then `JAVA_HOME`) is tried; the file
system is never searched. Without a suitable runtime it prints one line,
`ciphersift: error: CipherSift needs Java 23 or newer; found <version> (<path>); set CIPHERSIFT_JAVA or JAVA_HOME`,
and exits with code 6. The jar's entry point is compiled for Java 8 and performs the same
check itself, so `java -jar` on Java 8–22 gives the same message and exit code instead of an
`UnsupportedClassVersionError`.

### 3.1 Commands

```
ciphersift scan <dir> -o <out.cdx.json> [--exclude GLOB]... [--include-tests | --exclude-tests]
                [--threads N] [--rules DIR] [--weakness-indicators] [--python-thin-wrappers]
                [--transitive-deps] [--feature ID=on|off]... [--cyclonedx-version V] [--quiet | --verbose]
ciphersift rules validate [--rules DIR]
ciphersift rules export <dir>
ciphersift --version
ciphersift --help | ciphersift <command> --help
```

| Option | Meaning |
|---|---|
| `<dir>` | Scan root. Must be an existing directory; a missing path or a regular file is rejected with exit code 3. |
| `-o, --output FILE` | Required. Output file; `-` writes to standard output. Parent directories are not created. The file is written atomically (temporary file in the same directory, then rename); on failure no partial file is left. |
| `--exclude GLOB` | Repeatable. Exclude files and directories (section 4.2). |
| `--include-tests` | Default. Test files are scanned; their occurrences carry `"test": true` (section 11.4). |
| `--exclude-tests` | Test files (section 4.7) are not scanned and not reported. The two test options are mutually exclusive (usage error otherwise); the last one does not win. |
| `--threads N` | Number of worker threads for phases 3–4. Default: the number of available processors, at most 8. `N` must be ≥ 1. The output does not depend on `N`. |
| `--rules DIR` | Use the rule documents under `DIR` (recursively) **instead of** the bundled rules. To extend the bundled rules, run `rules export`, edit, and pass the directory. |
| `--weakness-indicators` | Also report the findings of rules with `indicator: weakness` (5.3), e.g. non-cryptographic random generators. **Off by default**: without the option these findings are dropped after extraction, so every other finding is exactly the one of a scan with the option; the document metadata records the option (11.2.1) *(DECISIONS E2, decided by owner)*. |
| `--python-thin-wrappers` | Also treat thin Python functions (at most 8 lines, one family; section 18.5, W6) as crypto wrappers whose call sites are reported. **Off by default** for Python (on for Java and Go, where it has no option); the metadata records the option (11.2.1) *(DECISIONS T3)*. |
| `--transitive-deps` | Also report transitive dependencies: `go.mod` requirements marked `// indirect` (17.10) and the entries of the lock files `go.sum`, `poetry.lock` and `Pipfile.lock` (9.4). **Off by default**: these manifests list what the build resolved, not what the project chose; a lock file still counts as a scanned manifest. Same as `--feature transitive-deps=on` *(DECISIONS B-G1, B-G2)*. |
| `--feature ID=on\|off` | Repeatable. Switches one detection feature (table below) on or off; a later setting of the same id wins; an unknown id or value is a usage error (exit 2). The non-default settings are recorded in the metadata (11.2.1) *(DECISIONS B0)*. |
| `--cyclonedx-version V` | CycloneDX version of the output: `1.7` (default) or `1.6`. Any other value is a usage error (exit 2). The findings, components, their order and bom-refs are the same for both; 1.7 adds the registry fields of 11.3.1 *(DECISIONS C1)*. |
| `--quiet` | Only errors on standard error. |
| `--verbose` | Debug messages on standard error (one line per skipped file and the reason). |

**Feature switches** *(DECISIONS B0)*. The detection boosters of the t2 round (DECISIONS B-…) can be switched
individually; the table lists every id and its default.

| Id | Default | Behaviour when on | Section |
|---|---|---|---|
| `transitive-deps` | off | `// indirect` requirements and lock files are reported | 9.4, 17.10 |
| `go-thin-wrappers` | on | Go thin wrappers (W6, 12 lines, fallback-getter guard) | 18, 18.5 |
| `java-any-call` | on | Java `anyCall` patterns with `feature: java-any-call` (registry names as arguments of any call) | 5.5 |
| `java-any-call-short` | on | Java `anyCall` patterns with `feature: java-any-call-short` (short JCA names, JOSE names) | 5.5 |
| `java-constant-getters` | on | constant getters and `SecretKeySpec.getAlgorithm()` in Java string resolution (7.4.1) | 7.4.1 |
| `java-deferred-locals` | on | Java locals assigned after their declaration (7.4.3, 7.7.1) | 7.4.3 |
| `python-unresolved` | on | the Python fallbacks `python.hash.unresolved`, `python.cipher.unresolved` (8.6) | 8.6 |
| `python-hash-wrappers` | on | Python wrapper names with `hash` / `digest` carry `python.hash.unresolved` (18.6) | 18.6 |
| `wrapper-evidence-by-name` | on | W7 evidence prefers the body finding whose rule id names a token of the wrapper's name (18.5) | 18.5 |
| `python-isinstance-keys` | on | key classes of one family in `isinstance` (8.6.1) | 8.6.1 |
| `python-reexports` | on | pyca classes re-exported by other packages, by their last two name segments (8.6) | 8.6 |
| `go-package-names` | on | calls into a project Go package named after a family (18.8) | 18.8 |
| `go-typed-methods` | on | Go method events on receivers of a known type (17.12) | 17.12 |
| `java-propagate-random` | on | Java `prng-secure` findings are propagatable (18.1) | 18.1 |
| `java-thin-12` | on | Java thin wrappers (W6) of up to 12 lines (else 8) | 18.5 |
| `wrapper-depth-4` | on | wrapper chains of up to 4 definitions (else 3) | 18.5 |
| `wrapper-aliases-v2` | on | the V2 aliases of 18.6 (certificates, keys, TLS/SSH, `hash160`) name family keys | 18.6 |

`rules validate` loads and validates the bundled rules (or `--rules DIR`), prints one line
per rule kind and language with the count, and exits 0 or 4. `rules export <dir>` writes
the bundled rule files, with their bundled relative paths, into `<dir>` (created if
missing; existing files are overwritten).

### 3.2 Standard error

Log lines have the form `ciphersift: <level>: <message>` with level `error`, `warning`,
`info` or `debug`. By default `info` and above are written. A successful `scan` ends with
one info line:

```
ciphersift: info: scanned 9874 files (java 8120, python 12, manifests 310) in 41.2 s; 1532 findings, 214 components; 3 files skipped
```

When Go files were scanned, `, go <n>` follows the Python count (`(java 0, python 0, go 41,
manifests 2)`); otherwise the line is exactly as above.

Nothing but the CBOM is ever written to standard output.

### 3.3 Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. Files that could not be read or parsed are skipped with a warning; they do not change the exit code. |
| 1 | Internal error (unexpected exception, native library cannot be loaded). |
| 2 | Usage error (unknown option, missing `-o`, conflicting options, `--threads 0`). |
| 3 | The scan root does not exist, is not a directory or cannot be read. |
| 4 | Rule loading or validation failed (message names the file and the problem). |
| 5 | The output cannot be written. |
| 6 | No Java runtime of version 23 or newer (launcher, or the jar started on an older runtime; section 3). |

---

## 4. File collection and classification

### 4.1 Walk

The scan root is walked recursively. Within a directory, entries are visited in ascending
order of their names compared as sequences of Unicode code points (this order is only used
to make logging deterministic; the output order is defined in section 11.6).

* Directories named `.git`, `.hg` or `.svn` are never entered.
* Symbolic links are not followed and not scanned, whether they point to files or to
  directories. (They are logged at debug level.)
* Special files (devices, sockets, FIFOs) are ignored.
* A directory that cannot be listed is skipped with a warning.

### 4.2 Exclusion globs

Each `--exclude GLOB` is matched against the relative path of every directory and file.
If a directory matches, its whole subtree is skipped. Glob syntax:

* `*` matches any sequence of characters except `/`; `?` matches one character except `/`;
  `[abc]`, `[a-z]` and `[!abc]` match one character from (or not from) a set.
* `**` as a whole path segment matches zero or more path segments: `vendor/**` matches
  everything below `vendor`; `**/gen/*.py` matches `gen/x.py` and `a/b/gen/x.py`.
* A glob without `/` is matched against the last segment (the base name) at any depth:
  `*_pb2.py` excludes `x_pb2.py` and `a/b/x_pb2.py`; `node_modules` excludes every
  directory of that name.
* A glob with `/` is matched against the whole relative path. A leading `/` is ignored.
  A trailing `/` restricts the glob to directories.
* Matching is case-sensitive.

### 4.3 Size limit

Files larger than 10 MiB (10 485 760 bytes) are not read; they are skipped with a debug
message and counted as skipped. The limit applies to source files and manifests.

### 4.4 Reading and encoding

A file is read completely as bytes. Text is decoded as UTF-8; a leading byte-order mark
(`EF BB BF`) is removed; malformed or unmappable byte sequences are replaced by U+FFFD
(each maximal invalid subsequence by one U+FFFD, as `CharsetDecoder` with
`CodingErrorAction.REPLACE` does). Line numbers are unaffected because LF bytes are always
valid. No other encoding is detected; Latin-1 and Windows-1252 files therefore work for
everything that is ASCII.

### 4.5 Classification

Each collected file is classified by its relative path and name; the first matching row
wins. Comparisons of extensions and names are case-insensitive.

| Class | Condition |
|---|---|
| Java source | extension `.java` |
| Python source | extension `.py` (including `setup.py`, whose requirements are also read, 9.8) |
| Go source | extension `.go` (17.1) |
| Maven POM | name `pom.xml` |
| Gradle build script | name `build.gradle` or `build.gradle.kts` |
| Gradle version catalog | name ends with `.versions.toml` |
| pip requirements | name matches `requirements*.txt`, or extension `.txt` and the parent directory is named `requirements` |
| pyproject | name `pyproject.toml` |
| Pipfile | name `Pipfile` (compared case-insensitively, like the other names) *(DECISIONS B-G2)* |
| Pipfile lock | name `Pipfile.lock` |
| Poetry lock | name `poetry.lock` |
| setup.cfg | name `setup.cfg` *(DECISIONS E10)* |
| Go module file | name `go.mod` (17.10) |
| Go checksum file | name `go.sum` (17.10) |
| Python source | a name without `.` whose first line is a Python interpreter line (below) *(DECISIONS F7)* |
| ignored | everything else |

**Python interpreter line** *(DECISIONS F7)*. For a regular file whose name contains no `.` and
that no row above classifies, the first 256 bytes are read; the file is Python source if they
contain a line end (LF) or the file is shorter, and the first line (without a trailing CR, decoded
as ISO-8859-1) matches, as a whole,
`#![ \t]*/\S*/(python[0-9.]*|env([ \t]+-\S*)*[ \t]+(\S*/)?python[0-9.]*)([ \t].*)?`
(case-sensitive): an absolute interpreter path whose base name is `python` with an optional
version, or `env` (options skipped) followed by such a name. `#!/usr/bin/env python3`,
`#!/usr/bin/python3.12 -u` and `#!/usr/bin/env -S python3 -I` qualify; `#!/bin/sh` and a name
with an extension (`run.sh`) do not. Such files are analysed, marked (4.7: only the directory rule
applies, the `.py` name rules do not) and counted like `.py` files.

### 4.6 Binary detection

Source files (Java, Python and Go) are checked for binary content before parsing: take the
first `n = min(8192, size)` bytes and count the bytes in the ranges `0x00–0x08` and
`0x0E–0x1F`. If `count × 10 > n`, the file is binary; it is skipped with a debug message
and counted as skipped. Empty files are not binary (and produce no findings). Manifests
are not checked (their parsers reject garbage).

### 4.7 Test files

A file is a **test file** if its relative path satisfies at least one rule below. The
directory rule matches case-insensitively; the file-name rules are case-*sensitive*, as in the
Maven Surefire and pytest conventions (so `Latest.java` or `Contest.java` are not tests).

1. *Directory rule (all classes).* A directory segment of the relative path (not the file
   name) is one of: `test`, `tests`, `testing`, `__tests__`, `testdata`, `test-data`,
   `testfixtures`, `test-fixtures`, `integrationtest`, `integration-test`,
   `integration-tests`; or the segment is `it` and the segment before it is `src`
   (Maven Failsafe layout `src/it/`).
2. *Java file names* (case-sensitive). The base name matches `*Test.java`, `*Tests.java`,
   `*TestCase.java`, `*IT.java`, or `Test*.java` where the character after `Test` is an
   upper-case letter (`TestUtils.java` but not `Testament.java`).
3. *Python file names* (case-sensitive). The base name matches `test_*.py`, `*_test.py`,
   `tests.py` or `conftest.py`.
4. *Go file names* (case-sensitive). The base name matches `*_test.go` (17.1).

With `--exclude-tests`, test files are dropped after collection, like excluded files (but
see 7.4.5: Java constant lookup may still read them). With `--include-tests` (default) they
are scanned and every occurrence from them is marked (section 11.4).

---

## 5. Rule format

### 5.1 Documents and files

The rule set is a directory tree. Every regular file under it with the extension `.yaml`,
`.yml` or `.json` is one **rule document**; other files are ignored. YAML files MUST
contain exactly one document; they are parsed with YAML 1.2 core-schema semantics
(`yes`/`no`/`on`/`off` are strings, not booleans). A document is an object with a `kind`:

| `kind` | Purpose | Section |
|---|---|---|
| `source` | detection rule for Java, Python or Go source | 5.3–5.6, 17.3 |
| `dependency` | crypto-library list for one package ecosystem | 5.9 |
| `constants` | values of well-known library constants used by Java string resolution | 5.10 |

Every document has an `id`, unique across the rule set, matching
`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`. By convention the file name is `<id>.yaml` and
source-rule ids start with the language (`java.`, `python.`, `go.`); dependency rule ids start
with `dep.`. The JSON Schema `spec/rule-schema.json` is normative for the structure;
section 5.8 lists the semantic checks the schema cannot express.

The bundled rule set is the directory `rules/` of the repository, packaged into the jar
under `/rules/`. It contains:

| Directory | Documents |
|---|---|
| `rules/java/` | 105 source rules (`java.*`) and the constants document `_constants.yaml` (`java.constants`) |
| `rules/python/` | 91 source rules (`python.*`) |
| `rules/go/` | 70 source rules (`go.*`, section 17) |
| `rules/dependencies/` | `dep.maven.yaml`, `dep.pypi.yaml`, `dep.golang.yaml` |

The Java rules `java.key.load.public` and `java.key.load.private` report the decoding of keys whose
algorithm is not visible statically (`KeyFactory.generatePublic` / `generatePrivate`, X.509 / PKCS #8 key
specs, Bouncy Castle key factories), mirroring the Python rules of E4 *(DECISIONS B-J-KL)*.

Three bundled rules are weakness indicators (`indicator: weakness`, 5.3): `java.rand.prng.insecure`,
`python.rand.prng.insecure` and `go.rand.prng.insecure` (non-cryptographic random generators). Their findings appear only
with `--weakness-indicators` *(DECISIONS E2)*. The Java rules `java.lib.shiro.*` cover Apache
Shiro's public crypto API *(DECISIONS E16)*.

Rules are processed in ascending order of `id` (code-point order) wherever order matters.
Patterns are processed in the order they appear in the `match` list.

### 5.2 Example

```yaml
# SPDX-License-Identifier: Apache-2.0
id: java.sym.aes.gcm
kind: source
language: java
name: AES-GCM usage in Java
description: >-
  Detects AES-GCM via JCA Cipher/GCMParameterSpec, BouncyCastle GCMBlockCipher, ...
asset:
  type: algorithm
  primitive: block-cipher
  family: AES
  variant: GCM
match:
- call: javax.crypto.Cipher.getInstance
  firstString: (AES(_(128|192|256))?|Rijndael)/GCM(/.*)?$
- new: javax.crypto.spec.GCMParameterSpec
- field: com.google.crypto.tink.aead.AeadKeyTemplates.AES128_GCM
- new: org.springframework.security.crypto.encrypt.AesBytesEncryptor
  argsTextContains: [GCM]
```

### 5.3 Source rule: top-level keys

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | Rule id, e.g. `python.hash.sha2`. Written to every occurrence. |
| `kind` | yes | `source` |
| `language` | yes | `java`, `python` or `go`. The rule is applied only to source files of that language. |
| `name` | yes | Human-readable rule name. Not part of the output except as the component name of non-algorithm, non-protocol assets (10.2). |
| `description` | no | Free text. |
| `indicator` | no | `weakness`: the findings are indicators of a possible weakness, not cryptographic assets (e.g. a non-cryptographic random generator, reported wherever it is used). They are reported only with `--weakness-indicators` (3.1); their components then carry the property `ciphersift:indicator` (11.3.4) *(DECISIONS E2, decided by owner)*. |
| `asset` | yes | What a match denotes (5.4). |
| `match` | yes | Non-empty list of patterns (5.5 Java, 5.6 Python, 17.3 Go). |

### 5.4 The `asset` block

| Key | Values | Meaning |
|---|---|---|
| `type` | `algorithm`, `protocol`, `certificate`, `related-crypto-material`, `key-material` | Asset type. `key-material` is written to CycloneDX as `related-crypto-material` (11.3.3). |
| `subtype` | string | Refinement, e.g. `hardcoded-key`, `static-iv`, `prng-insecure`, `cert-validation-disabled`, `rc4-cipher`, `pkcs1-v1_5-encrypt`. |
| `primitive` | CycloneDX primitive (1.6 set, valid in 1.7): `block-cipher`, `stream-cipher`, `hash`, `mac`, `signature`, `pke`, `kem`, `kdf`, `key-agree`, `ae`, `drbg`, `xof`, `combiner`, `other` | Algorithm primitive. Absent = unknown. |
| `family` | string | Algorithm family, e.g. `AES`, `SHA2`, `RSA`, `EC`. Absent = unknown (the `*.unresolved` fallback rules). |
| `variant` | string | Mode, padding or scheme variant, e.g. `GCM`, `OAEP`, `PKCS1v15`. |
| `securityLevel` | integer | Classical security level in bits. |
| `protocol` | `tls`, `ssh`, `ipsec`, `ike`, `sstp`, `wpa`, `other` | Required iff `type` is `protocol`. |
| `version` | string | Protocol version, e.g. `1.2`. Only for protocols. |

### 5.5 Java patterns

A Java pattern has exactly one anchor:

| Anchor | Value | Fires on |
|---|---|---|
| `call` | `pkg.Class.method` (fully qualified class, then member). A trailing `*` turns the member into a prefix: `org.apache.commons.codec.digest.DigestUtils.sha256*`. Nested classes are written with dots: `org.bouncycastle.crypto.params.Argon2Parameters.Builder.build`. | A method invocation whose method name equals (or starts with) the member and whose receiver denotes the class (7.3.2). |
| `new` | `pkg.Class` | An object-creation expression of that class, including anonymous subclasses (`new Class() { … }`). No `*`. |
| `method` | `name`, optional trailing `*` (prefix) | A method invocation with this name, whatever the receiver (the receiver's type is not known). |
| `field` | `pkg.Class.FIELD`, optional trailing `*` on the member | A field access `X.FIELD` (static constant, enum constant) whose qualifier denotes the class, and that is not itself the receiver of a method invocation (7.2). |
| `override` | `name`, optional trailing `*` | A method declaration with this name. |
| `anyCall` | `true` | A method invocation of any name except the excluded names below, whatever its receiver *(DECISIONS B-J-SNx)*. Requires `firstString`, `anyString` or `stringContains`. An `anyCall` pattern is a **fallback**: it is evaluated for an event only if no other pattern (of any rule) holds for it (7.7.1). |

**Excluded names of `anyCall`** (comparisons and look-ups, logging and printing, collection builders, the JCA
factories whose own patterns decide, messages and properties): `equals`, `equalsIgnoreCase`, `contains`,
`containsKey`, `containsValue`, `startsWith`, `endsWith`, `indexOf`, `lastIndexOf`, `matches`, `compareTo`,
`compareToIgnoreCase`, `regionMatches`, `getInstance`, `debug`, `info`, `warn`, `warning`, `error`, `trace`,
`fine`, `finer`, `finest`, `log`, `println`, `printf`, `print`, `format`, `append`, `fail`, `getProperty`,
`getString`, `getMessage`, `isLoggable`, `add`, `addAll`, `of`, `setOf`, `asList`, `stream`, `copyOf`, and every
name starting with `assert`, `equals`, `contains` or `log`.

**`feature`** (optional, any anchor; a feature id of 3.1): the pattern takes part only while that feature is
on (3.1); it is ignored by the index (7.5) and by the pre-filter (14) otherwise. An unknown id is a rule
error *(DECISIONS B0)*. The bundled `anyCall` patterns carry `feature: java-any-call` (registry names of the
"SNx" list: XML-Security URIs, multi-token JCA standard names, TLS groups and suites, provider service keys
`Signature.SHA256withRSA`) or `feature: java-any-call-short` (the short JCA names `AES`, `RSA`, `EC`, …, JOSE
names); the names and their sources are listed in `spec/anycall-names.csv`.
Conditions (all optional; all present conditions must hold):

| Key | Value | Allowed with | Holds when |
|---|---|---|---|
| `firstString` | regex | call, new, method | The **first** element of the event's string list (7.4.6) exists and the regex matches at its start (`lookingAt`), case-insensitively. |
| `anyString` | regex | call, new, method | Some element of the string list matches at its start, case-insensitively. |
| `stringContains` | list of strings | call, new, method | Some element of the string list contains some listed string, case-insensitively. |
| `argsText` | regex | call, new, method | The regex is found anywhere (`find`, case-sensitive) in the source text of the argument list — from `(` to `)` inclusive — after replacing every run of whitespace characters by one space. |
| `argsTextContains` | list of strings | call, new, method | The raw source text of the argument list (from `(` to `)`) contains some listed string (case-sensitive). |
| `constantArg` | integer *i* ≥ 0 | call, new, method | The event has more than *i* arguments and argument *i* (0-based) is constant bytes (7.4.7). |
| `inType` | list of simple type names | override | The enclosing type extends or implements one of the names (7.6). |
| `body` | regex | override | The regex is found (`find`, case-sensitive) in the method body text after removing comments, collapsing whitespace runs to one space and trimming (7.6). |
| `param` | `{index: i}` | call, new, method | *Not a filter.* The resolved string of argument *i* is reported as the finding's param (7.8). Used by the bundled Java rules for `SecureRandom.getInstance` *(DECISIONS E17)* and for named-curve OIDs (5.11). Java patterns accept no other `param` key. |

A pattern that has a condition key other than `param` is **specific** (specificity 2); a
pattern with only its anchor, or only its anchor and `param`, is **bare** (specificity 1):
`param` is not a filter and does not make a pattern specific *(DECISIONS O2)*. Specificity
drives rule selection (7.7.1).

### 5.6 Python patterns

A Python pattern has exactly one of `call`, `anyCall`, `assign` or `ref`, or it has `method`
without `call`:

| Anchor | Value | Fires on |
|---|---|---|
| `call` | dotted name, e.g. `cryptography.hazmat.primitives.ciphers.Cipher` | A call whose resolved name (8.4) equals the value or starts with the value followed by `.`. `Crypto.Hash.MD5` fires on `Crypto.Hash.MD5.new`; `hashlib.sha1` does not fire on `hashlib.sha1x`. A `call` pattern without filter conditions also fires on a **bare reference** in value position whose resolved name *equals* the value (8.6.1): `MACS = [(b"hmac-sha1", sha1)]`, `digest=hashlib.sha256` *(DECISIONS E1)*. |
| `ref` | dotted name | A bare reference (8.6.1) in any expression position whose resolved name equals the value, e.g. an enum member `pkcs11.Mechanism.SHA256_RSA_PKCS` or a class used as a value, `algorithms.AES`. Never a call. *(DECISIONS E1)* |
| `method` | name or list of names | A call whose method name (8.4.3) is one of the names, whatever the receiver. May also be combined with `call` (then both must hold). |
| `anyCall` | `true`; requires `kwargs` | Any call (e.g. `verify=False` on any function). |
| `assign` | attribute name | An assignment `expr.NAME = value` or augmented assignment `expr.NAME op= value`. |

Conditions:

| Key | Value | Allowed with | Holds when |
|---|---|---|---|
| `firstString` | regex | call, method, anyCall | The first element of the call's string list (8.5.1) exists and the regex matches at its start, case-insensitively. |
| `stringContains` | list | call, method, anyCall | Some element of the string list contains some listed string, case-insensitively. |
| `anySymbol` | list of dotted names | call, method, anyCall | Some listed name *hits* the call's symbol set (8.5.2): it equals a symbol, or a symbol ends with `.` + name. |
| `allSymbols` | list | call, method, anyCall | Every listed name hits the symbol set. |
| `kwargs` | map keyword → regex | call, method, anyCall | For every entry, the call has that keyword argument and the regex is found (`find`, case-insensitive) in at least one of its value texts (8.5.3). |
| `dictItems` | map key → regex | call, method, anyCall | For every entry, some argument (positional, or a keyword value) is a `dictionary` display — or an `identifier` with a binding (8.3) whose right-hand side is one — that has a `pair` whose `key` has the entry's key as string value (8.5.1) and in one of whose `value`'s value texts (8.5.3, in the dictionary's scope) the regex is found (case-insensitive). `algos.DigestAlgorithm({'algorithm': 'sha256'})` *(DECISIONS E3)*. |
| `notInside` | list of method names | call, method, anyCall | The walk of 8.7 from the call finds no enclosing call whose method name is listed: `padding.PKCS1v15()` not passed (directly or nested) to `sign`, `verify`, `encrypt` or `decrypt` *(DECISIONS E12)*. |
| `noSymbolPrefix` | list of strings | call, method, anyCall | No symbol of the call's symbol set (8.5.2) starts with a listed string *(DECISIONS B-P-U1)*: `hashes.Hash(alg)` whose argument is not one of pyca's hash classes. |
| `minArgs` | integer *n* ≥ 1 | call, method, anyCall | The call has at least *n* positional arguments (and no generator argument) *(DECISIONS B-P-U1)*. |
| `value` | regex | assign | The regex is found (case-insensitive) in at least one value text of the right-hand side (8.5.3). |
| `valueContains` | list | assign | Some value text contains some listed string (case-insensitive). |
| `param` | `{keyword: k, index: i}` (either or both), `{self: true}` or `{value: s}` | call, method, anyCall, ref (`self` or `value` only) | *Not a filter.* Names the argument reported as param (8.8); `value` reports the fixed string *s* (a library whose curve is implied, e.g. secp256k1 bindings). |
| `reportAt` | list of method names | call, method, anyCall | *Not a filter.* Report the finding at the enclosing call to one of these methods (8.7). |

**`feature`** (optional, any anchor): as for Java (5.5), the pattern takes part only while that feature is on
(3.1) *(DECISIONS B0)*.

`*` prefixes are not supported in Python patterns. A `ref` pattern takes no condition and no
`reportAt`; its `param` can only be `{self: true}` or `{value: s}` (the schema enforces this).

### 5.7 Regular expressions

Rule regexes are written in the common subset of `java.util.regex` and Python `re`: no
named groups `(?P<…>)`, no `\Z`, no inline comments `(?#…)`, no possessive quantifiers, no
`\p{…}` classes. Implementations compile them with `java.util.regex.Pattern`; case-insensitive
modes use `CASE_INSENSITIVE | UNICODE_CASE`. "Matches at its start" means
`Matcher.lookingAt()`; "is found" means `Matcher.find()`. `$` has Java's default meaning
(end of input or before a final line terminator). The tool `spec/tools/regex_parity.py`
checks all bundled regexes for identical behaviour in both engines (106 722 probes, no
difference; `kwargs` and `dictItems` values included).

### 5.8 Validation

At load time, every document MUST validate against `spec/rule-schema.json` (draft 2020-12),
and additionally:

* ids are unique; a `source` rule's id starts with its `language` followed by `.`;
* every regex compiles with `java.util.regex.Pattern`;
* the rule set contains at most one `constants` document per language and at most one
  `dependency` rule per ecosystem;
* a Java pattern's `param` contains only `index`;
* a Java `new` anchor does not end with `*` (5.5; the schema's `if`/`then` branch for `new`
  rejects it as well); the message says so in words, "a new anchor names a class; "*" is not
  allowed" *(DECISIONS O6)*.

A rule directory given with `--rules` may itself be a symbolic link to a directory, but
symbolic links inside it are not followed: each one is a rule error ("symbolic links are not
allowed in a rule directory"), so that no rule is silently dropped or read from outside the
directory *(DECISIONS O6)*. File names in rule paths are decoded as UTF-8 (section 12).

The **bundled** rule set is validated in full when the jar is built; the build fails on any
problem. At run time an implementation MAY skip the JSON-schema validation (and use
pre-parsed documents recorded by that build step) for the bundled set if its files and the
schema are byte-identical to the validated ones, verified by a digest recorded at build
time *(DECISIONS follow-up F2)*. The semantic checks above and all checks of `--rules` directories and
`rules validate --rules DIR` always run.

A violation aborts the scan with exit code 4 and a message naming the file, the JSON pointer
of the offending value and the problem. Unknown keys are errors (the schema forbids them).

### 5.9 Dependency rules

```yaml
id: dep.maven
kind: dependency
ecosystem: maven            # maven | pypi | golang
name: Cryptographic Java libraries
asset: {type: library}
packages:
  - {package: "org.bouncycastle:*", note: "Bouncy Castle"}
  - {package: "com.google.crypto.tink:*"}
```

`package` is a pattern over the package key of the ecosystem: for Maven
`groupId:artifactId`, for PyPI the normalised name (section 9.1), for Go the module path (17.10). `*` matches any run of
characters (including `.`, `-`, `:`); matching is case-insensitive and covers the whole key.
A manifest entry is reported iff its key matches at least one pattern of the rule of its
ecosystem. `note` is documentation only.

`usedIf` (optional, a non-empty string) makes an entry conditional *(DECISIONS B-J4)*: a key that
matches only patterns with `usedIf` is reported only if the text of at least one of them occurs
(plain substring, case-sensitive) in some source file of the ecosystem's language — Maven: Java,
PyPI: Python, Go: Go — that the scan collects (4.1–4.6: excluded, too large, binary and unreadable
files do not count; files skipped by the pre-filter do). A key that also matches a pattern without
`usedIf` is reported as before. The bundled `dep.maven` uses it for `commons-codec:commons-codec`
with `usedIf: org.apache.commons.codec.digest`: the library is reported only where the project
imports (or names fully qualified) its digest package, not where it is used for Base64 or Hex.

### 5.10 Constants document

```yaml
id: java.constants
kind: constants
language: java
constants:
  MessageDigestAlgorithms:   # simple class name
    SHA_256: SHA-256         # field name: string value
```

Used by Java string resolution (7.4): a reference `C.F`, where `C`'s simple name (the last
segment of the qualifier as written) has an entry with field `F`, resolves to the listed
string, regardless of imports. The bundled table covers commons-codec
`MessageDigestAlgorithms` and `HmacAlgorithms`, Android `KeyProperties`, the
`ALGORITHM_NAME` / `DEFAULT_ALGORITHM_NAME` constants of Apache Shiro's hash classes
*(DECISIONS E16)*, the algorithm OIDs of Bouncy Castle's `NISTObjectIdentifiers`, `PKCSObjectIdentifiers`,
`X9ObjectIdentifiers` and `TeleTrusTObjectIdentifiers` that the OID table (5.11) knows *(DECISIONS
B-J-JP2)*, and the algorithm URIs of the Java SE XML signature API (JSR 105)
`javax.xml.crypto.dsig.DigestMethod` and `SignatureMethod` *(DECISIONS B-J-XD2)*.

### 5.11 Algorithm OIDs *(DECISIONS E15, decided by owner)*

CipherSift has a built-in, fixed table of algorithm object identifiers (below; not part of
the rule set and not configurable). A string is a **table OID** if it is exactly a dotted OID
(`[0-2](\.(0|[1-9][0-9]*))+`), optionally prefixed with the JCA alias prefix `OID.` (in any
case), with no surrounding white space, whose dotted form is listed in the table.

* **Matching.** Wherever a string list is built — Java 7.4.6, Python 8.5.1 — every element
  that is a table OID is replaced by the table's *name* for it, and the element remembers the
  OID. Python value texts (8.5.3) list the name right after a string value or constant value
  that is a table OID. A reported param (Java 7.8, Python 8.8) that is a table OID is replaced
  by its name. Rule conditions therefore see the name, exactly as if the source had used it:
  `Signature.getInstance("1.2.840.10045.4.3.2")` is matched like
  `Signature.getInstance("SHA256withECDSA")`, through a constant as well.
* **Names** are the JCA standard names where Java has one (`SHA256withECDSA`, `SHA-256`,
  `HmacSHA256`, cipher OIDs as transformations such as `AES_256/CBC/NoPadding`), else the
  usual name (`PBKDF2`, `PBES2`, `SCRYPT`, `secp256r1`, `ML-KEM-768`).
* **OID constructors.** The bundled rules match the OID-taking constructors
  `new org.bouncycastle.asn1.ASN1ObjectIdentifier("…")` (Java) and
  `cryptography.x509.ObjectIdentifier`, `cryptography.x509.oid.ObjectIdentifier`,
  `asn1crypto.core.ObjectIdentifier`, `pyasn1.type.univ.ObjectIdentifier` (Python) with a
  `firstString` of exactly the names the table assigns to that rule (the "reported by" columns
  below, which also give the family / variant of that rule); the asn1crypto `algos.*Algorithm`
  / `*AlgorithmId` patterns also accept the table names of those OIDs that asn1crypto maps to the
  names the pattern already accepts (`DigestAlgorithmId("2.16.840.1.101.3.4.2.1")` like
  `DigestAlgorithmId("sha256")`). Named curves report the curve name as param. JCA factories need no new patterns: their existing conditions see the
  name.
* **Unknown OIDs** (not in the table, or not exactly a dotted OID) stay unchanged; no bundled
  pattern matches a dotted string, so they produce no finding of their own (a JCA call with an
  unknown OID still gives its `*.unresolved` fallback, as for any unknown name).
* **Output.** The OID behind the matched string of a finding is its *oid*: Java — the element
  that was the matched string (7.7.1); Python — the first string for `firstString`, the first
  string containing a needle for `stringContains`, the value that satisfied the first
  `dictItems` entry. An algorithm component with an oid writes it as `cryptoProperties.oid`
  (11.3) and has the oid in its key (10.1).
* **Not covered:** OIDs computed at run time or held in library constants other than the Bouncy Castle
  constants of the constants document (5.10, *DECISIONS B-J-JP2*: `NISTObjectIdentifiers.id_sha256.getId()`
  is covered; Bouncy Castle OID constants used as values are anchors of their rules, *B-J-BCOID*), and
  Java locals assigned different values after their declaration unless the values agree (7.4.3, 7.7.1,
  Appendix B). OIDs whose family
  has no rule in a language (PBES2 and SLH-DSA in Python) give no Python finding.

| OID | ASN.1 name | treated as | defined in | reported by (Java) | reported by (Python) |
|---|---|---|---|---|---|
| `1.2.840.113549.1.1.1` | rsaEncryption | `RSA` | RFC 8017 | `java.asym.rsa` (RSA) | `python.asym.rsa` (RSA) |
| `1.2.840.113549.1.1.7` | id-RSAES-OAEP | `OAEP` | RFC 8017 | `java.asym.rsa.oaep` (RSA) | `python.asym.rsa.oaep` (RSA / OAEP) |
| `1.2.840.113549.1.1.10` | id-RSASSA-PSS | `RSASSA-PSS` | RFC 8017 | `java.asym.rsa` (RSA) | `python.asym.rsa.pss` (RSA / PSS) |
| `1.2.840.113549.1.1.2` | md2WithRSAEncryption | `MD2withRSA` | RFC 8017 | `java.asym.rsa` (RSA) | `python.asym.rsa.pkcs1v15.sign` (RSA / PKCS1v15) |
| `1.2.840.113549.1.1.4` | md5WithRSAEncryption | `MD5withRSA` | RFC 8017 | `java.asym.rsa` (RSA) | `python.asym.rsa.pkcs1v15.sign` (RSA / PKCS1v15) |
| `1.2.840.113549.1.1.5` | sha1WithRSAEncryption | `SHA1withRSA` | RFC 8017 | `java.asym.rsa` (RSA) | `python.asym.rsa.pkcs1v15.sign` (RSA / PKCS1v15) |
| `1.2.840.113549.1.1.14` | sha224WithRSAEncryption | `SHA224withRSA` | RFC 8017 | `java.asym.rsa` (RSA) | `python.asym.rsa.pkcs1v15.sign` (RSA / PKCS1v15) |
| `1.2.840.113549.1.1.11` | sha256WithRSAEncryption | `SHA256withRSA` | RFC 8017 | `java.asym.rsa` (RSA) | `python.asym.rsa.pkcs1v15.sign` (RSA / PKCS1v15) |
| `1.2.840.113549.1.1.12` | sha384WithRSAEncryption | `SHA384withRSA` | RFC 8017 | `java.asym.rsa` (RSA) | `python.asym.rsa.pkcs1v15.sign` (RSA / PKCS1v15) |
| `1.2.840.113549.1.1.13` | sha512WithRSAEncryption | `SHA512withRSA` | RFC 8017 | `java.asym.rsa` (RSA) | `python.asym.rsa.pkcs1v15.sign` (RSA / PKCS1v15) |
| `1.2.840.113549.1.1.15` | sha512-224WithRSAEncryption | `SHA512/224withRSA` | RFC 8017 | `java.asym.rsa` (RSA) | `python.asym.rsa.pkcs1v15.sign` (RSA / PKCS1v15) |
| `1.2.840.113549.1.1.16` | sha512-256WithRSAEncryption | `SHA512/256withRSA` | RFC 8017 | `java.asym.rsa` (RSA) | `python.asym.rsa.pkcs1v15.sign` (RSA / PKCS1v15) |
| `2.16.840.1.101.3.4.3.13` | id-rsassa-pkcs1-v1_5-with-sha3-224 | `SHA3-224withRSA` | NIST CSOR | `java.asym.rsa` (RSA) | `python.asym.rsa.pkcs1v15.sign` (RSA / PKCS1v15) |
| `2.16.840.1.101.3.4.3.14` | id-rsassa-pkcs1-v1_5-with-sha3-256 | `SHA3-256withRSA` | NIST CSOR | `java.asym.rsa` (RSA) | `python.asym.rsa.pkcs1v15.sign` (RSA / PKCS1v15) |
| `2.16.840.1.101.3.4.3.15` | id-rsassa-pkcs1-v1_5-with-sha3-384 | `SHA3-384withRSA` | NIST CSOR | `java.asym.rsa` (RSA) | `python.asym.rsa.pkcs1v15.sign` (RSA / PKCS1v15) |
| `2.16.840.1.101.3.4.3.16` | id-rsassa-pkcs1-v1_5-with-sha3-512 | `SHA3-512withRSA` | NIST CSOR | `java.asym.rsa` (RSA) | `python.asym.rsa.pkcs1v15.sign` (RSA / PKCS1v15) |
| `1.2.840.10040.4.1` | id-dsa | `DSA` | RFC 3279 | `java.asym.dsa` (DSA) | `python.asym.dsa` (DSA) |
| `1.2.840.10040.4.3` | id-dsa-with-sha1 | `SHA1withDSA` | RFC 3279 | `java.asym.dsa` (DSA) | `python.asym.dsa` (DSA) |
| `2.16.840.1.101.3.4.3.1` | id-dsa-with-sha224 | `SHA224withDSA` | RFC 5758 | `java.asym.dsa` (DSA) | `python.asym.dsa` (DSA) |
| `2.16.840.1.101.3.4.3.2` | id-dsa-with-sha256 | `SHA256withDSA` | RFC 5758 | `java.asym.dsa` (DSA) | `python.asym.dsa` (DSA) |
| `2.16.840.1.101.3.4.3.3` | id-dsa-with-sha384 | `SHA384withDSA` | NIST CSOR | `java.asym.dsa` (DSA) | `python.asym.dsa` (DSA) |
| `2.16.840.1.101.3.4.3.4` | id-dsa-with-sha512 | `SHA512withDSA` | NIST CSOR | `java.asym.dsa` (DSA) | `python.asym.dsa` (DSA) |
| `2.16.840.1.101.3.4.3.5` | id-dsa-with-sha3-224 | `SHA3-224withDSA` | NIST CSOR | `java.asym.dsa` (DSA) | `python.asym.dsa` (DSA) |
| `2.16.840.1.101.3.4.3.6` | id-dsa-with-sha3-256 | `SHA3-256withDSA` | NIST CSOR | `java.asym.dsa` (DSA) | `python.asym.dsa` (DSA) |
| `2.16.840.1.101.3.4.3.7` | id-dsa-with-sha3-384 | `SHA3-384withDSA` | NIST CSOR | `java.asym.dsa` (DSA) | `python.asym.dsa` (DSA) |
| `2.16.840.1.101.3.4.3.8` | id-dsa-with-sha3-512 | `SHA3-512withDSA` | NIST CSOR | `java.asym.dsa` (DSA) | `python.asym.dsa` (DSA) |
| `1.2.840.10045.2.1` | id-ecPublicKey | `EC` | RFC 5480 | `java.asym.ec` (EC) | `python.asym.ec` (EC) |
| `1.3.132.1.12` | id-ecDH | `ECDH` | RFC 5480 | `java.asym.ecdh` (EC) | `python.asym.ecdh` (EC) |
| `1.2.840.10045.4.1` | ecdsa-with-SHA1 | `SHA1withECDSA` | RFC 3279 | `java.asym.ecdsa` (EC) | `python.asym.ecdsa` (EC) |
| `1.2.840.10045.4.3.1` | ecdsa-with-SHA224 | `SHA224withECDSA` | RFC 5758 | `java.asym.ecdsa` (EC) | `python.asym.ecdsa` (EC) |
| `1.2.840.10045.4.3.2` | ecdsa-with-SHA256 | `SHA256withECDSA` | RFC 5758 | `java.asym.ecdsa` (EC) | `python.asym.ecdsa` (EC) |
| `1.2.840.10045.4.3.3` | ecdsa-with-SHA384 | `SHA384withECDSA` | RFC 5758 | `java.asym.ecdsa` (EC) | `python.asym.ecdsa` (EC) |
| `1.2.840.10045.4.3.4` | ecdsa-with-SHA512 | `SHA512withECDSA` | RFC 5758 | `java.asym.ecdsa` (EC) | `python.asym.ecdsa` (EC) |
| `2.16.840.1.101.3.4.3.9` | id-ecdsa-with-sha3-224 | `SHA3-224withECDSA` | NIST CSOR | `java.asym.ecdsa` (EC) | `python.asym.ecdsa` (EC) |
| `2.16.840.1.101.3.4.3.10` | id-ecdsa-with-sha3-256 | `SHA3-256withECDSA` | NIST CSOR | `java.asym.ecdsa` (EC) | `python.asym.ecdsa` (EC) |
| `2.16.840.1.101.3.4.3.11` | id-ecdsa-with-sha3-384 | `SHA3-384withECDSA` | NIST CSOR | `java.asym.ecdsa` (EC) | `python.asym.ecdsa` (EC) |
| `2.16.840.1.101.3.4.3.12` | id-ecdsa-with-sha3-512 | `SHA3-512withECDSA` | NIST CSOR | `java.asym.ecdsa` (EC) | `python.asym.ecdsa` (EC) |
| `1.2.840.10045.3.1.1` | prime192v1 | `secp192r1` | RFC 5480 / SEC 2 | `java.asym.ec` (EC), param | `python.asym.ec` (EC), param |
| `1.3.132.0.33` | secp224r1 | `secp224r1` | RFC 5480 / SEC 2 | `java.asym.ec` (EC), param | `python.asym.ec` (EC), param |
| `1.2.840.10045.3.1.7` | prime256v1 | `secp256r1` | RFC 5480 / SEC 2 | `java.asym.ec` (EC), param | `python.asym.ec` (EC), param |
| `1.3.132.0.34` | secp384r1 | `secp384r1` | RFC 5480 / SEC 2 | `java.asym.ec` (EC), param | `python.asym.ec` (EC), param |
| `1.3.132.0.35` | secp521r1 | `secp521r1` | RFC 5480 / SEC 2 | `java.asym.ec` (EC), param | `python.asym.ec` (EC), param |
| `1.3.132.0.10` | secp256k1 | `secp256k1` | RFC 5480 / SEC 2 | `java.asym.ec` (EC), param | `python.asym.ec` (EC), param |
| `1.3.36.3.3.2.8.1.1.1` | brainpoolP160r1 | `brainpoolP160r1` | RFC 5639 | `java.asym.ec` (EC), param | `python.asym.ec` (EC), param |
| `1.3.36.3.3.2.8.1.1.3` | brainpoolP192r1 | `brainpoolP192r1` | RFC 5639 | `java.asym.ec` (EC), param | `python.asym.ec` (EC), param |
| `1.3.36.3.3.2.8.1.1.5` | brainpoolP224r1 | `brainpoolP224r1` | RFC 5639 | `java.asym.ec` (EC), param | `python.asym.ec` (EC), param |
| `1.3.36.3.3.2.8.1.1.7` | brainpoolP256r1 | `brainpoolP256r1` | RFC 5639 | `java.asym.ec` (EC), param | `python.asym.ec` (EC), param |
| `1.3.36.3.3.2.8.1.1.9` | brainpoolP320r1 | `brainpoolP320r1` | RFC 5639 | `java.asym.ec` (EC), param | `python.asym.ec` (EC), param |
| `1.3.36.3.3.2.8.1.1.11` | brainpoolP384r1 | `brainpoolP384r1` | RFC 5639 | `java.asym.ec` (EC), param | `python.asym.ec` (EC), param |
| `1.3.36.3.3.2.8.1.1.13` | brainpoolP512r1 | `brainpoolP512r1` | RFC 5639 | `java.asym.ec` (EC), param | `python.asym.ec` (EC), param |
| `1.3.101.110` | id-X25519 | `X25519` | RFC 8410 | `java.asym.ecdh` (EC) | `python.asym.x25519` (Curve25519) |
| `1.3.101.111` | id-X448 | `X448` | RFC 8410 | `java.asym.ecdh` (EC) | `python.asym.x448` (Curve448) |
| `1.3.101.112` | id-Ed25519 | `Ed25519` | RFC 8410 | `java.asym.ed25519` (Ed25519) | `python.asym.ed25519` (Ed25519) |
| `1.3.101.113` | id-Ed448 | `Ed448` | RFC 8410 | `java.asym.ed25519` (Ed25519) | `python.asym.ed448` (Ed448) |
| `1.2.840.113549.1.3.1` | dhKeyAgreement | `DH` | PKCS #3 | `java.asym.dh` (DH) | `python.asym.dh` (DH) |
| `1.2.840.10046.2.1` | dhpublicnumber | `DH` | RFC 3279 | `java.asym.dh` (DH) | `python.asym.dh` (DH) |
| `1.2.840.113549.2.2` | md2 | `MD2` | RFC 3279 | `java.hash.md2` (MD2) | `python.hash.md2` (MD2) |
| `1.2.840.113549.2.5` | md5 | `MD5` | RFC 3279 | `java.hash.md5` (MD5) | `python.hash.md5` (MD5) |
| `1.3.14.3.2.26` | id-sha1 | `SHA-1` | RFC 3279 | `java.hash.sha1` (SHA1) | `python.hash.sha1` (SHA1) |
| `2.16.840.1.101.3.4.2.4` | id-sha224 | `SHA-224` | RFC 5754 / NIST CSOR | `java.hash.sha2` (SHA2) | `python.hash.sha2` (SHA2) |
| `2.16.840.1.101.3.4.2.1` | id-sha256 | `SHA-256` | RFC 5754 / NIST CSOR | `java.hash.sha2` (SHA2) | `python.hash.sha2` (SHA2) |
| `2.16.840.1.101.3.4.2.2` | id-sha384 | `SHA-384` | RFC 5754 / NIST CSOR | `java.hash.sha2` (SHA2) | `python.hash.sha2` (SHA2) |
| `2.16.840.1.101.3.4.2.3` | id-sha512 | `SHA-512` | RFC 5754 / NIST CSOR | `java.hash.sha2` (SHA2) | `python.hash.sha2` (SHA2) |
| `2.16.840.1.101.3.4.2.5` | id-sha512-224 | `SHA-512/224` | RFC 5754 / NIST CSOR | `java.hash.sha2` (SHA2) | `python.hash.sha2` (SHA2) |
| `2.16.840.1.101.3.4.2.6` | id-sha512-256 | `SHA-512/256` | RFC 5754 / NIST CSOR | `java.hash.sha2` (SHA2) | `python.hash.sha2` (SHA2) |
| `2.16.840.1.101.3.4.2.7` | id-sha3-224 | `SHA3-224` | NIST CSOR | `java.hash.sha3` (SHA3) | `python.hash.sha3` (SHA3) |
| `2.16.840.1.101.3.4.2.8` | id-sha3-256 | `SHA3-256` | NIST CSOR | `java.hash.sha3` (SHA3) | `python.hash.sha3` (SHA3) |
| `2.16.840.1.101.3.4.2.9` | id-sha3-384 | `SHA3-384` | NIST CSOR | `java.hash.sha3` (SHA3) | `python.hash.sha3` (SHA3) |
| `2.16.840.1.101.3.4.2.10` | id-sha3-512 | `SHA3-512` | NIST CSOR | `java.hash.sha3` (SHA3) | `python.hash.sha3` (SHA3) |
| `1.2.840.113549.2.7` | id-hmacWithSHA1 | `HmacSHA1` | RFC 8018 | `java.mac.hmac` (HMAC) | `python.mac.hmac` (HMAC) |
| `1.2.840.113549.2.8` | id-hmacWithSHA224 | `HmacSHA224` | RFC 8018 | `java.mac.hmac` (HMAC) | `python.mac.hmac` (HMAC) |
| `1.2.840.113549.2.9` | id-hmacWithSHA256 | `HmacSHA256` | RFC 8018 | `java.mac.hmac` (HMAC) | `python.mac.hmac` (HMAC) |
| `1.2.840.113549.2.10` | id-hmacWithSHA384 | `HmacSHA384` | RFC 8018 | `java.mac.hmac` (HMAC) | `python.mac.hmac` (HMAC) |
| `1.2.840.113549.2.11` | id-hmacWithSHA512 | `HmacSHA512` | RFC 8018 | `java.mac.hmac` (HMAC) | `python.mac.hmac` (HMAC) |
| `1.2.840.113549.2.12` | id-hmacWithSHA512-224 | `HmacSHA512/224` | RFC 8018 | `java.mac.hmac` (HMAC) | `python.mac.hmac` (HMAC) |
| `1.2.840.113549.2.13` | id-hmacWithSHA512-256 | `HmacSHA512/256` | RFC 8018 | `java.mac.hmac` (HMAC) | `python.mac.hmac` (HMAC) |
| `2.16.840.1.101.3.4.2.13` | id-hmacWithSHA3-224 | `HmacSHA3-224` | NIST CSOR | `java.mac.hmac` (HMAC) | `python.mac.hmac` (HMAC) |
| `2.16.840.1.101.3.4.2.14` | id-hmacWithSHA3-256 | `HmacSHA3-256` | NIST CSOR | `java.mac.hmac` (HMAC) | `python.mac.hmac` (HMAC) |
| `2.16.840.1.101.3.4.2.15` | id-hmacWithSHA3-384 | `HmacSHA3-384` | NIST CSOR | `java.mac.hmac` (HMAC) | `python.mac.hmac` (HMAC) |
| `2.16.840.1.101.3.4.2.16` | id-hmacWithSHA3-512 | `HmacSHA3-512` | NIST CSOR | `java.mac.hmac` (HMAC) | `python.mac.hmac` (HMAC) |
| `2.16.840.1.101.3.4.1.1` | aes128-ECB | `AES_128/ECB/NoPadding` | NIST CSOR | `java.sym.aes.ecb` (AES / ECB) | `python.sym.aes.ecb` (AES / ECB) |
| `2.16.840.1.101.3.4.1.2` | aes128-CBC | `AES_128/CBC/NoPadding` | RFC 3565 | `java.sym.aes.cbc` (AES / CBC) | `python.sym.aes.cbc` (AES / CBC) |
| `2.16.840.1.101.3.4.1.3` | aes128-OFB | `AES_128/OFB/NoPadding` | NIST CSOR | `java.sym.aes.ofb` (AES / OFB) | `python.sym.aes.ofb` (AES / OFB) |
| `2.16.840.1.101.3.4.1.4` | aes128-CFB | `AES_128/CFB/NoPadding` | NIST CSOR | `java.sym.aes.cfb` (AES / CFB) | `python.sym.aes.cfb` (AES / CFB) |
| `2.16.840.1.101.3.4.1.5` | id-aes128-wrap | `AES_128/KW/NoPadding` | RFC 3394 | `java.sym.aes.kw` (AES) | `python.sym.aes.keywrap` (AES / KW) |
| `2.16.840.1.101.3.4.1.6` | id-aes128-GCM | `AES_128/GCM/NoPadding` | RFC 5084 | `java.sym.aes.gcm` (AES / GCM) | `python.sym.aes.gcm` (AES / GCM) |
| `2.16.840.1.101.3.4.1.7` | id-aes128-CCM | `AES_128/CCM/NoPadding` | RFC 5084 | `java.sym.aes.ccm` (AES / CCM) | `python.sym.aes.ccm` (AES / CCM) |
| `2.16.840.1.101.3.4.1.8` | id-aes128-wrap-pad | `AES_128/KWP/NoPadding` | RFC 5649 | `java.sym.aes.kw` (AES) | `python.sym.aes.keywrap` (AES / KW) |
| `2.16.840.1.101.3.4.1.21` | aes192-ECB | `AES_192/ECB/NoPadding` | NIST CSOR | `java.sym.aes.ecb` (AES / ECB) | `python.sym.aes.ecb` (AES / ECB) |
| `2.16.840.1.101.3.4.1.22` | aes192-CBC | `AES_192/CBC/NoPadding` | RFC 3565 | `java.sym.aes.cbc` (AES / CBC) | `python.sym.aes.cbc` (AES / CBC) |
| `2.16.840.1.101.3.4.1.23` | aes192-OFB | `AES_192/OFB/NoPadding` | NIST CSOR | `java.sym.aes.ofb` (AES / OFB) | `python.sym.aes.ofb` (AES / OFB) |
| `2.16.840.1.101.3.4.1.24` | aes192-CFB | `AES_192/CFB/NoPadding` | NIST CSOR | `java.sym.aes.cfb` (AES / CFB) | `python.sym.aes.cfb` (AES / CFB) |
| `2.16.840.1.101.3.4.1.25` | id-aes192-wrap | `AES_192/KW/NoPadding` | RFC 3394 | `java.sym.aes.kw` (AES) | `python.sym.aes.keywrap` (AES / KW) |
| `2.16.840.1.101.3.4.1.26` | id-aes192-GCM | `AES_192/GCM/NoPadding` | RFC 5084 | `java.sym.aes.gcm` (AES / GCM) | `python.sym.aes.gcm` (AES / GCM) |
| `2.16.840.1.101.3.4.1.27` | id-aes192-CCM | `AES_192/CCM/NoPadding` | RFC 5084 | `java.sym.aes.ccm` (AES / CCM) | `python.sym.aes.ccm` (AES / CCM) |
| `2.16.840.1.101.3.4.1.28` | id-aes192-wrap-pad | `AES_192/KWP/NoPadding` | RFC 5649 | `java.sym.aes.kw` (AES) | `python.sym.aes.keywrap` (AES / KW) |
| `2.16.840.1.101.3.4.1.41` | aes256-ECB | `AES_256/ECB/NoPadding` | NIST CSOR | `java.sym.aes.ecb` (AES / ECB) | `python.sym.aes.ecb` (AES / ECB) |
| `2.16.840.1.101.3.4.1.42` | aes256-CBC | `AES_256/CBC/NoPadding` | RFC 3565 | `java.sym.aes.cbc` (AES / CBC) | `python.sym.aes.cbc` (AES / CBC) |
| `2.16.840.1.101.3.4.1.43` | aes256-OFB | `AES_256/OFB/NoPadding` | NIST CSOR | `java.sym.aes.ofb` (AES / OFB) | `python.sym.aes.ofb` (AES / OFB) |
| `2.16.840.1.101.3.4.1.44` | aes256-CFB | `AES_256/CFB/NoPadding` | NIST CSOR | `java.sym.aes.cfb` (AES / CFB) | `python.sym.aes.cfb` (AES / CFB) |
| `2.16.840.1.101.3.4.1.45` | id-aes256-wrap | `AES_256/KW/NoPadding` | RFC 3394 | `java.sym.aes.kw` (AES) | `python.sym.aes.keywrap` (AES / KW) |
| `2.16.840.1.101.3.4.1.46` | id-aes256-GCM | `AES_256/GCM/NoPadding` | RFC 5084 | `java.sym.aes.gcm` (AES / GCM) | `python.sym.aes.gcm` (AES / GCM) |
| `2.16.840.1.101.3.4.1.47` | id-aes256-CCM | `AES_256/CCM/NoPadding` | RFC 5084 | `java.sym.aes.ccm` (AES / CCM) | `python.sym.aes.ccm` (AES / CCM) |
| `2.16.840.1.101.3.4.1.48` | id-aes256-wrap-pad | `AES_256/KWP/NoPadding` | RFC 5649 | `java.sym.aes.kw` (AES) | `python.sym.aes.keywrap` (AES / KW) |
| `1.2.840.113549.3.7` | des-ede3-cbc | `DESede/CBC/NoPadding` | RFC 8018 | `java.sym.3des` (3DES) | `python.sym.3des` (3DES) |
| `1.3.14.3.2.7` | desCBC | `DES/CBC/NoPadding` | RFC 8018 | `java.sym.des` (DES) | `python.sym.des` (DES) |
| `1.2.840.113549.3.2` | rc2CBC | `RC2/CBC/NoPadding` | RFC 8018 | `java.sym.rc2` (RC2) | `python.sym.rc2` (RC2) |
| `1.2.840.113549.1.5.12` | id-PBKDF2 | `PBKDF2` | RFC 8018 | `java.kdf.pbkdf2` (PBKDF2) | `python.kdf.pbkdf2` (PBKDF2) |
| `1.2.840.113549.1.5.13` | id-PBES2 | `PBES2` | RFC 8018 | `java.kdf.pbe` (PBE) | — |
| `1.3.6.1.4.1.11591.4.11` | id-scrypt | `SCRYPT` | RFC 7914 | `java.kdf.scrypt` (scrypt) | `python.kdf.scrypt` (scrypt) |
| `2.16.840.1.101.3.4.4.1` | id-alg-ml-kem-512 | `ML-KEM-512` | FIPS 203 / NIST CSOR | `java.pqc.mlkem` (ML-KEM) | `python.pqc.mlkem` (ML-KEM), param *(B-P-PQ)* |
| `2.16.840.1.101.3.4.4.2` | id-alg-ml-kem-768 | `ML-KEM-768` | FIPS 203 / NIST CSOR | `java.pqc.mlkem` (ML-KEM) | `python.pqc.mlkem` (ML-KEM), param *(B-P-PQ)* |
| `2.16.840.1.101.3.4.4.3` | id-alg-ml-kem-1024 | `ML-KEM-1024` | FIPS 203 / NIST CSOR | `java.pqc.mlkem` (ML-KEM) | `python.pqc.mlkem` (ML-KEM), param *(B-P-PQ)* |
| `2.16.840.1.101.3.4.3.17` | id-ml-dsa-44 | `ML-DSA-44` | FIPS 204 / NIST CSOR | `java.pqc.mldsa` (ML-DSA) | `python.pqc.mldsa` (ML-DSA), param *(B-P-PQ)* |
| `2.16.840.1.101.3.4.3.18` | id-ml-dsa-65 | `ML-DSA-65` | FIPS 204 / NIST CSOR | `java.pqc.mldsa` (ML-DSA) | `python.pqc.mldsa` (ML-DSA), param *(B-P-PQ)* |
| `2.16.840.1.101.3.4.3.19` | id-ml-dsa-87 | `ML-DSA-87` | FIPS 204 / NIST CSOR | `java.pqc.mldsa` (ML-DSA) | `python.pqc.mldsa` (ML-DSA), param *(B-P-PQ)* |
| `2.16.840.1.101.3.4.3.20` | id-slh-dsa-sha2-128s | `SLH-DSA-SHA2-128s` | FIPS 205 / NIST CSOR | `java.pqc.slhdsa` (SLH-DSA) | — |
| `2.16.840.1.101.3.4.3.21` | id-slh-dsa-sha2-128f | `SLH-DSA-SHA2-128f` | FIPS 205 / NIST CSOR | `java.pqc.slhdsa` (SLH-DSA) | — |
| `2.16.840.1.101.3.4.3.22` | id-slh-dsa-sha2-192s | `SLH-DSA-SHA2-192s` | FIPS 205 / NIST CSOR | `java.pqc.slhdsa` (SLH-DSA) | — |
| `2.16.840.1.101.3.4.3.23` | id-slh-dsa-sha2-192f | `SLH-DSA-SHA2-192f` | FIPS 205 / NIST CSOR | `java.pqc.slhdsa` (SLH-DSA) | — |
| `2.16.840.1.101.3.4.3.24` | id-slh-dsa-sha2-256s | `SLH-DSA-SHA2-256s` | FIPS 205 / NIST CSOR | `java.pqc.slhdsa` (SLH-DSA) | — |
| `2.16.840.1.101.3.4.3.25` | id-slh-dsa-sha2-256f | `SLH-DSA-SHA2-256f` | FIPS 205 / NIST CSOR | `java.pqc.slhdsa` (SLH-DSA) | — |
| `2.16.840.1.101.3.4.3.26` | id-slh-dsa-shake-128s | `SLH-DSA-SHAKE-128s` | FIPS 205 / NIST CSOR | `java.pqc.slhdsa` (SLH-DSA) | — |
| `2.16.840.1.101.3.4.3.27` | id-slh-dsa-shake-128f | `SLH-DSA-SHAKE-128f` | FIPS 205 / NIST CSOR | `java.pqc.slhdsa` (SLH-DSA) | — |
| `2.16.840.1.101.3.4.3.28` | id-slh-dsa-shake-192s | `SLH-DSA-SHAKE-192s` | FIPS 205 / NIST CSOR | `java.pqc.slhdsa` (SLH-DSA) | — |
| `2.16.840.1.101.3.4.3.29` | id-slh-dsa-shake-192f | `SLH-DSA-SHAKE-192f` | FIPS 205 / NIST CSOR | `java.pqc.slhdsa` (SLH-DSA) | — |
| `2.16.840.1.101.3.4.3.30` | id-slh-dsa-shake-256s | `SLH-DSA-SHAKE-256s` | FIPS 205 / NIST CSOR | `java.pqc.slhdsa` (SLH-DSA) | — |
| `2.16.840.1.101.3.4.3.31` | id-slh-dsa-shake-256f | `SLH-DSA-SHAKE-256f` | FIPS 205 / NIST CSOR | `java.pqc.slhdsa` (SLH-DSA) | — |
| `2.16.840.1.101.3.4.2.11` | id-shake128 | `SHAKE128` | NIST CSOR | `java.hash.sha3` | `python.hash.sha3` |
| `2.16.840.1.101.3.4.2.12` | id-shake256 | `SHAKE256` | NIST CSOR | `java.hash.sha3` | `python.hash.sha3` |
| `1.2.840.113549.1.1.3` | md4WithRSAEncryption | `MD4withRSA` | RFC 3279 | `java.asym.rsa` | `python.asym.rsa.pkcs1v15.sign` |
| `1.3.14.3.2.29` | sha1WithRSASignature (OIW) | `SHA1withRSA` | RFC 3279 | `java.asym.rsa` | `python.asym.rsa.pkcs1v15.sign` |
| `1.3.132.1.13` | id-ecMQV | `ECMQV` | RFC 5480 | `java.asym.ecdh` | `python.asym.ecdh` |
| `1.3.132.0.1` | sect163k1 | `sect163k1` | RFC 5480 / SEC 2 | `java.asym.ec`, param | `python.asym.ec`, param |
| `1.3.132.0.15` | sect163r2 | `sect163r2` | RFC 5480 / SEC 2 | `java.asym.ec`, param | `python.asym.ec`, param |
| `1.3.132.0.26` | sect233k1 | `sect233k1` | RFC 5480 / SEC 2 | `java.asym.ec`, param | `python.asym.ec`, param |
| `1.3.132.0.27` | sect233r1 | `sect233r1` | RFC 5480 / SEC 2 | `java.asym.ec`, param | `python.asym.ec`, param |
| `1.3.132.0.16` | sect283k1 | `sect283k1` | RFC 5480 / SEC 2 | `java.asym.ec`, param | `python.asym.ec`, param |
| `1.3.132.0.17` | sect283r1 | `sect283r1` | RFC 5480 / SEC 2 | `java.asym.ec`, param | `python.asym.ec`, param |
| `1.3.132.0.36` | sect409k1 | `sect409k1` | RFC 5480 / SEC 2 | `java.asym.ec`, param | `python.asym.ec`, param |
| `1.3.132.0.37` | sect409r1 | `sect409r1` | RFC 5480 / SEC 2 | `java.asym.ec`, param | `python.asym.ec`, param |
| `1.3.132.0.38` | sect571k1 | `sect571k1` | RFC 5480 / SEC 2 | `java.asym.ec`, param | `python.asym.ec`, param |
| `1.3.132.0.39` | sect571r1 | `sect571r1` | RFC 5480 / SEC 2 | `java.asym.ec`, param | `python.asym.ec`, param |
| `1.3.36.3.2.1` | ripemd160 | `RIPEMD160` | TeleTrusT (ISO/IEC 10118-3) | `java.hash.rmd160` | `python.hash.ripemd160` |
| `1.3.6.1.5.5.8.1.1` | hmac-md5 | `HmacMD5` | RFC 3370 | `java.mac.hmac` | `python.mac.hmac` |
| `1.3.6.1.5.5.8.1.2` | hmac-sha1 | `HmacSHA1` | RFC 3370 | `java.mac.hmac` | `python.mac.hmac` |
| `1.2.840.113549.3.4` | rc4 | `RC4` | RSA Data Security (PKCS #5 v1.5 era, RFC 8018 lists the arc) | `java.sym.rc4` | `python.sym.rc4` |
| `1.2.840.113549.1.5.3` | pbeWithMD5AndDES-CBC | `PBEWithMD5AndDES` | RFC 8018 | `java.kdf.pbe` | — |
| `1.2.840.113549.1.5.10` | pbeWithSHA1AndDES-CBC | `PBEWithSHA1AndDES` | RFC 8018 | `java.kdf.pbe` | — |
| `1.2.840.113549.1.12.1.3` | pbeWithSHAAnd3-KeyTripleDES-CBC | `PBEWithSHA1AndDESede` | RFC 7292 | `java.kdf.pbe` | — |
| `1.2.840.113549.1.12.1.6` | pbeWithSHAAnd40BitRC2-CBC | `PBEWithSHA1AndRC2_40` | RFC 7292 | `java.kdf.pbe` | — |
| `1.2.840.113549.1.9.16.3.18` | id-alg-AEADChaCha20Poly1305 | `ChaCha20-Poly1305` | RFC 8103 | `java.sym.chacha20` | `python.sym.chacha20poly1305` |
| `1.2.840.113549.1.9.16.3.28` | id-alg-hkdf-with-sha256 | `HKDF-SHA256` | RFC 8619 | `java.kdf.hkdf` | `python.kdf.hkdf` |
| `1.2.840.113549.1.9.16.3.29` | id-alg-hkdf-with-sha384 | `HKDF-SHA384` | RFC 8619 | `java.kdf.hkdf` | `python.kdf.hkdf` |
| `1.2.840.113549.1.9.16.3.30` | id-alg-hkdf-with-sha512 | `HKDF-SHA512` | RFC 8619 | `java.kdf.hkdf` | `python.kdf.hkdf` |
| `1.2.840.113549.1.9.16.3.6` | id-alg-CMS3DESwrap | `DESedeWrap` | RFC 3370 | `java.sym.3des` | `python.sym.3des` |
| `1.3.6.1.4.1.1722.12.2.1.8` | id-blake2b256 | `BLAKE2B-256` | RFC 7693 | `java.hash.blake2` | `python.hash.blake2` |
| `1.3.6.1.4.1.1722.12.2.1.16` | id-blake2b512 | `BLAKE2B-512` | RFC 7693 | `java.hash.blake2` | `python.hash.blake2` |
| `1.3.6.1.4.1.1722.12.2.2.8` | id-blake2s256 | `BLAKE2S-256` | RFC 7693 | `java.hash.blake2` | `python.hash.blake2` |
| `1.2.156.10197.1.401` | sm3 | `SM3` | GM/T 0006 | — | `python.hash.sm3` |
| `1.2.156.10197.1.104.2` | sm4-cbc | `SM4/CBC/NoPadding` | GM/T 0006 | `java.sym.sm4` | `python.sym.sm4` |
| `1.2.392.200011.61.1.1.1.2` | camellia128-cbc | `Camellia/CBC/NoPadding` | RFC 3657 | `java.sym.camellia` | `python.sym.camellia` |
| `1.3.6.1.4.1.188.7.1.1.2` | idea-cbc | `IDEA/CBC/NoPadding` | RFC 3058 | `java.sym.idea` | `python.sym.idea` |

---

## 6. Parsing

### 6.1 Parser

Source files are parsed with tree-sitter through **jtreesitter 0.26.1** (Maven
`io.github.tree-sitter:jtreesitter:0.26.1`) using the grammars **tree-sitter-java 0.23.5**,
**tree-sitter-python 0.25.0** and **tree-sitter-go 0.25.0** (section 17). Packaging of the native libraries is specified in
section 15.3.

The decoded text (4.4) is passed to `Parser.parse(String)` (it returns `Optional<Tree>`;
an empty result is a failure of that file, section 13), which converts it to UTF-8.
All byte offsets in this specification are offsets into that UTF-8 encoding; source texts
of nodes ("the text of a node") are the corresponding substrings of the decoded text.
Rows reported by tree-sitter count LF characters and are used for line numbers
(row + 1).

A `Parser` instance is not thread-safe; use one per worker thread *(advice)*. Trees MUST be
closed after the file has been analysed; retaining trees across files is not allowed for
memory reasons (but see 7.4.5 for the cross-file constant cache).

### 6.2 Error tolerance

tree-sitter always returns a tree; syntax errors appear as `ERROR` or `MISSING` nodes.
Analysis runs on the whole tree, including the children of `ERROR` nodes: every node of an
expected type is analysed wherever it appears. A file with syntax errors therefore still
yields the findings of its well-formed parts (conformance cases `java/syntax-error`,
`python/fork-fixtures/broken/*`). Python 2 files are analysed the same way.

### 6.3 Traversal

All tree walks MUST be iterative (explicit stack) or otherwise safe for deeply nested
trees: the conformance suite contains a Python expression nested 3 000 levels deep and a
Java string concatenation of 4 000 operands. Recursive evaluators (constant resolution,
symbol collection) have explicit depth limits, given where they are defined. In particular,
for Python: `resolveDotted` follows at most **64** attribute levels (deeper → no
candidates), `resolveName` follows at most **16** binding-chain steps, and `strings()` descends
at most **12** levels of nested parentheses/lists/tuples in an argument (like Java `value`).
Exceeding a limit yields "unresolved" for that expression, never an error, so results do not
depend on the thread stack size. For `resolveName` "unresolved" means *no candidates*: a name
whose binding chain needs more than 16 steps has no candidates, and neither has any name that
is resolved through it (step 1 of 8.4.1); the fallback of step 3 (the name itself, star
modules) does not apply to such names *(DECISIONS O4)*. A 20-step alias chain from
`import hashlib` therefore gives no call name, not the name 16 steps up.

"Pre-order" means: a node before its children, children left to right.

The node types and field names the analysis relies on are listed in Appendix C.

---

## 7. Java source analysis

### 7.1 Overview

For each Java file:

1. Build the **file context** (7.3): package, imports, declared classes, fields, reassigned
   names.
2. Enumerate **events** (7.2) in pre-order.
3. For each event, look up candidate rules in the Java rule index (7.5), evaluate their
   patterns (7.6) and select the reported rules (7.7.1).
4. Drop nested duplicates (7.7.2).
5. Emit one finding per remaining (event, rule) pair (7.8).

### 7.2 Events

| Event kind | Node | Name | Receiver | Line |
|---|---|---|---|---|
| `call` | `method_invocation` with a `name` field | text of `name` | see below | start row of the node + 1 |
| `new` | `object_creation_expression` with a `type` field | last `.`-segment of the type text *T* | *T* | start row + 1 |
| `field` | `field_access` with `object` and `field`, **unless** it is the `object` of its parent `method_invocation` | text of `field` | `object` text | start row + 1 |
| `decl` | `method_declaration` with a `name` field | text of `name` | – | row of the `name` node + 1 (so a leading annotation does not shift the line) |

Texts used as receivers and type names are the node text with **all whitespace removed**.
For `new`, generic arguments are removed from *T* as well: repeatedly delete every innermost
`<…>` group that contains no `<` or `>` until none is left (`java.util.HashMap<String,
List<X>>` → `java.util.HashMap`; `HashMap<>` → `HashMap`).

**Receivers of `call` events.**

* If the `object` field is present and is an `identifier`, `field_access` or
  `scoped_identifier`, the receiver is its text (whitespace removed), e.g. `Cipher`,
  `javax.crypto.Cipher`, `Argon2Parameters.Builder`, `this.md`, `kpg`.
* If the `object` field is present but of another type (a call `a.b().c()`, `this`,
  `super`, a parenthesised expression, an array access, …), the event has **no receiver and
  no static candidates**; it can only match `method` patterns.
* If there is no `object` (an unqualified call `m(…)`), the event's **static candidates**
  are: the class of the single-static import of `m` if there is one (7.3.1); otherwise all
  classes imported with static wildcard imports, in import order.

**Arguments.** The named children of the `arguments` node, excluding `line_comment` and
`block_comment`. `field` and `decl` events have no arguments.

**Display name.** Used as the component name when no string was matched (7.8):

* `call` with receiver: (last `.`-segment of the receiver) + `.` + name, e.g.
  `MessageDigest.getInstance`, `DigestUtils.md5Hex`;
* `call` without object and with exactly one static candidate: (simple name of that class)
  + `.` + name, e.g. `DigestUtils.sha256Hex`;
* any other `call`: the method name;
* `new`: *T* with its leading segments removed while more than one segment is left and the
  first one does not start with an upper-case letter: `org.bouncycastle.crypto.params.Argon2Parameters.Builder`
  → `Argon2Parameters.Builder`, `AESEngine` → `AESEngine`;
* `field`: (last segment of the receiver) + `.` + name, e.g. `SignatureAlgorithm.RS256`;
* `decl`: the method name.

### 7.3 File context

#### 7.3.1 Collected declarations

One walk over the whole tree (all depths, including inside `ERROR` nodes) collects:

* **package**: the text (whitespace removed) of the `scoped_identifier` or `identifier`
  child of `package_declaration`; empty if there is none.
* **imports** (`import_declaration`; *name* = text of its `scoped_identifier`/`identifier`
  child, whitespace removed; *static* = has a `static` child; *wildcard* = has an
  `asterisk` child):
  * single-type import `import a.b.C;` → `imports[C] = a.b.C` (a later import of the same
    simple name replaces an earlier one);
  * type-import-on-demand `import a.b.*;` → append `a.b` to *wildcards*;
  * single-static import `import static a.b.C.m;` → `staticImports[m] = a.b.C`;
  * static-import-on-demand `import static a.b.C.*;` → append `a.b.C` to *staticWildcards*.
* **local classes**: the `name` of every `class_declaration`, `interface_declaration`,
  `enum_declaration`, `record_declaration` and `annotation_type_declaration` in the file,
  at any nesting depth (simple names).
* **fields**: for every `field_declaration` and `constant_declaration`, for each
  `variable_declarator` child that has both `name` and `value`: append *(value node,
  final)* to `fields[name]`, in walk order. *final* is true for a `constant_declaration`,
  for a declaration whose `modifiers` contain the word `final`, and for any declaration
  whose parent is an `interface_body`. Fields of all classes of the file share one table
  (keyed by simple field name).
* **reassigned names**: for every `assignment_expression` (any operator, `=` or compound):
  if `left` is an `identifier`, its text; if `left` is a `field_access`, the text of its
  `field`. Increments (`++`, `--`) do not count.

#### 7.3.2 Does a class reference denote a class?

`denotes(ref, C)` decides whether a class reference as written in the source (`ref`, e.g.
`Cipher`, `javax.crypto.Cipher`, `Argon2Parameters.Builder`) denotes the class with the
fully-qualified name `C`:

1. Remove whitespace and generic arguments from `ref`. If `ref` is empty, false.
2. If `ref == C`, true.
3. Split `ref` into its first segment *F* and the rest *R* (possibly empty). If *F* is a
   key of `imports`: true iff `imports[F]` (followed by `.R` if *R* is non-empty) equals `C`.
4. If *F* is a local class, false. (A class declared in the file hides the API class.)
5. If the first character of *F* is not an upper-case letter (`Character.isUpperCase`),
   false. (A variable, or a package path that is not exactly `C`.)
6. Otherwise, if `C` does not end with `.` + `ref`, false. Let *E* be `C` without that suffix
   (the qualifier of `ref` within `C`). If the last segment of *E* starts with an upper-case
   letter, `ref` names a member type below the enclosing class *E* (`Inner` for
   `a.b.Outer.Inner`, `Digest256` for `…digest.SHA3.Digest256`); such a name is in scope only
   through an import, so the result is true iff *E* is in *wildcards* or *staticWildcards*, or
   `staticImports[F]` is *E* *(DECISIONS E7/E8)*. Otherwise true. (A top-level class, or a
   member type written with its enclosing class (`Outer.Inner`), is assumed to come from a
   wildcard import, the same package or `java.lang`.)

### 7.4 Constant resolution

#### 7.4.1 Values

`value(e, ctx, d)` evaluates an expression node `e`, read in file context `ctx`, to a
string or to *unresolved*. `d` is the depth, starting at 0; when `d > 12` the result is
unresolved. Each rule below that evaluates a sub-expression does so at depth `d + 1`.

| Node | Value |
|---|---|
| `string_literal` | the decoded literal (7.4.2) |
| `decimal_integer_literal` | its text without a trailing `l`/`L` (`256`, `1_000` stays `1_000`) |
| `character_literal` | its text with all leading and trailing `'` removed |
| `parenthesized_expression` | value of its first named child |
| `binary_expression` with operator `+` | value(left) concatenated with value(right); unresolved if either is unresolved. Other operators: unresolved |
| `method_invocation` with an `object` and a name in {`getName`, `toString`, `name`, `trim`, `intern`, `getId`} | value of the object (unchanged; `trim` does not trim; `getId` of an `ASN1ObjectIdentifier` constant is its OID, *DECISIONS B-J-JP2*) |
| `method_invocation` without `object` and without arguments *(DECISIONS B-J-JP1)* | if the file declares exactly one method of that name, it has no formal parameters and its body is the single statement `return e;`: `value(e)` in the file's context (as a field initialiser: identifiers use the fallback of 7.4.3); else unresolved |
| `method_invocation` `x.getAlgorithm()` without arguments *(DECISIONS B-J-JP5)* | if `x` is (or looks up, 7.4.3, to) an `object_creation_expression` of a type whose last segment is `SecretKeySpec`: the value of its last argument (the algorithm in every `SecretKeySpec` constructor); else unresolved |
| `identifier` | look the name up (7.4.3); if it yields *(initialiser, ctx′)* → `value(initialiser, ctx′)`; a constants-table hit yields its string |
| `field_access` | look the access up (7.4.4), then as for `identifier` |
| anything else | unresolved (ternaries, other calls, `String.format`, array access, …) |

Integer literals in hexadecimal, octal or binary notation and all other literal kinds are
unresolved.

#### 7.4.2 String literals

For an ordinary literal `"…"`: concatenate, in order, the texts of the `string_fragment`
children and the decoded `escape_sequence` children; ignore the quote tokens.

Escape sequences are decoded as in the JLS: `\b \t \n \f \r \s \" \' \\`, octal escapes
`\0`–`\377`, and Unicode escapes `\uXXXX` (one or more `u`). An unknown escape keeps its
text.

**Text blocks** (literal starts with `"""`) are decoded per JLS §3.10.6 *(Appendix A, D4)*:
take the raw text between the delimiters; drop everything up to and including the first
line terminator; normalise `\r\n` and `\r` to `\n`; split into lines; the *incidental
indentation* is the minimum count of leading whitespace characters over all non-blank
lines, plus the last line if it consists only of whitespace (closing delimiter on its own
line); remove that many leading characters from each non-blank line, remove trailing
whitespace from every line, make blank lines empty; join with `\n`; then decode escape
sequences (a `\` immediately before a line terminator removes both). Example:
`"""⏎            DESede"""` → `DESede`.

#### 7.4.3 Identifier lookup

To look up identifier `N` at node `X` in context `ctx`, walk from `X` towards the root,
keeping the child `c` through which the walk arrived at the current node `p`:

* If `p` is a `block`, `switch_block_statement_group` or `constructor_body`: among the named
  children of `p` that start before `c` starts, consider every `local_variable_declaration`
  and its `variable_declarator`s named `N`; if there is any, use the **last** one:
  * no initialiser → *(DECISIONS B-J-JP3)* the plain assignments `N = v` (operator `=`) inside `p` that
    start after the declaration: none, a compound assignment or an increment / decrement of `N` there, or
    an unresolved `v` → unresolved; all values equal → *(that `v`, ctx)*; different values → unresolved,
    with the values as **alternatives** (7.7.1);
  * the declaration is not `final` (its `modifiers` do not contain the word `final`) and `N`
    is a reassigned name of `ctx` → unresolved;
  * otherwise the result is *(its initialiser, ctx)*. Stop.
* If `p` is a `method_declaration`, `constructor_declaration` or `lambda_expression` that has
  a `parameters` field whose text contains `N` as a whole word (not preceded or followed by
  `[A-Za-z0-9_]`) → unresolved (parameters shadow fields). Stop.
* If `p` is an `enhanced_for_statement` whose `name` field text is `N` → unresolved. Stop.

If the walk reaches the root without stopping:

1. field lookup of `N` in `ctx` (7.4.4.1); if it yields an initialiser, that is the result;
2. else, if `N` is a key of `ctx.staticImports` → static field (`staticImports[N]`, `N`)
   (7.4.5);
3. else, for each class of `ctx.staticWildcards` in order → static field (class, `N`); the
   first that yields a result.

Otherwise unresolved. (Reassignment is file-global and by simple name: a variable that is
assigned anywhere in the file is not resolved unless it is declared `final`.)

#### 7.4.4 Field-access lookup

To look up `O.F` (a `field_access` with object `O` and field `F`) in `ctx`, let *Q* be the
text of `O` without whitespace and *S* its last `.`-segment:

1. if the constants table (5.10) has *S*.*F* → that string;
2. if `O` is `this`, or *S* is a local class of `ctx` → field lookup of `F` in `ctx`;
3. if *S* starts with an upper-case letter:
   * if the first segment *G* of *Q* is a key of `ctx.imports` → static field
     (`imports[G]` + the rest of *Q* after *G*, `F`);
   * else if *Q* contains no `.` → try static field (`package.Q`, `F`) (only if the package
     is non-empty), then static field (`w.Q`, `F`) for each wildcard import `w` in order;
     the first that yields a result;
   * else (*Q* is dotted) → static field (*Q*, `F`), *Q* taken as fully qualified;
4. otherwise unresolved.

##### 7.4.4.1 Field lookup in one file

`fields[N]` of the context: no entry → no result. If there are several entries and their
initialiser texts are not all identical → no result. Otherwise take the first entry; if it
is not final and `N` is a reassigned name of that context → no result; else *(initialiser,
that context)*.

#### 7.4.5 Static fields and cross-file constants

static field (`C`, `F`), evaluated on behalf of context `ctx`:

1. if the constants table has (simple name of `C`).`F` → that string;
2. locate the declaring file: the **source root** *R* is the directory of `ctx`'s file with
   as many trailing directories removed as `ctx`'s package has segments (for the default
   package, the file's own directory). If *R* is not the scan root or inside it, there is no
   result *(Appendix A, D5)*. Split `C` into segments *s1 … sk*; for *i* = *k* down to 1, the
   candidate is *R*/*s1*/…/*s(i−1)*/*si*`.java` (this finds nested classes: `a.b.Outer.Inner`
   is looked for in `a/b/Outer/Inner.java`, then `a/b/Outer.java`). The first candidate that
   is `ctx`'s own file, or an existing regular file (≤ 10 MiB) that can be read and parsed,
   is the declaring file; candidates that do not exist or fail to read are skipped;
3. field lookup of `F` in the declaring file's context.

Cross-file lookup reads files regardless of `--exclude`, `--exclude-tests` and their
classification, as long as they are inside the scan root. Contexts of other files are built
on demand and cached for the whole scan, keyed by canonical path, including negative
results. The cache MUST be safe for concurrent use; the result of a lookup MUST NOT depend
on the order in which files are analysed.

*(advice)* Do not keep tree-sitter trees in the cache. When a file context is built,
convert each field initialiser into a small immutable expression form (string literal value,
integer text, character text, `+` of two forms, parenthesis, identifier reference with its
lookup position, field-access reference, accepted method call on a receiver form, array
initialiser of forms, "other"), keep the import tables, local classes, fields and
reassigned names, and close the tree. The rules of 7.4 can be evaluated on that form;
identifier lookups inside a field initialiser always go to step 1 of 7.4.3's fallback,
because field initialisers are not inside blocks.

#### 7.4.6 String list of an event

The string list of a `call` or `new` event is built from its arguments, in order:

* an `array_creation_expression` with an `array_initializer` contributes the elements of
  the initialiser; one without an initialiser contributes nothing;
* an `array_initializer` contributes its elements;
* an `identifier` or `field_access` whose lookup (7.4.3/7.4.4) yields an initialiser that is
  an `array_initializer`, or an `array_creation_expression` with one, contributes that
  initialiser's elements, evaluated in the declaring context *(Appendix A, D3)*;
* any other argument contributes itself.

Array elements that are integer literals (any notation), character literals, or
`unary_expression` / `cast_expression` nodes are not contributed: a byte or char array is
data, not a list of names *(Appendix A, D9)*. Each contributed element (and each non-array
argument) is evaluated with `value`; resolved values are appended, unresolved ones are
skipped. Hence the "first string" is the first *resolvable* argument, not
necessarily argument 0: in `Cipher.getInstance(alg, "BC")` with unresolved `alg` it is
`"BC"`. `field` and `decl` events have an empty string list. Finally every element that is a
table OID is replaced by its name and remembers the OID (5.11) *(DECISIONS E15)*.

#### 7.4.7 Constant bytes

`isConst(e, ctx, d, viaVar)` (start with `d = 0`, `viaVar = false`; false when `d > 12`):

| Node | Result |
|---|---|
| constants-table hit | true |
| `string_literal` | true |
| `array_initializer` | true iff every named child other than a comment (`line_comment`, `block_comment`) has a type that ends with `literal` or is `cast_expression` or `unary_expression` (an empty initialiser is constant; `{1, /* x */ 2}` is constant, DECISIONS O3) |
| `array_creation_expression` | with an initialiser: `isConst(initialiser)`; without: true iff `viaVar` is false and it has a `dimensions_expr` child (an inline `new byte[16]` is an all-zero constant; through a variable it is usually filled later) |
| `parenthesized_expression`, `cast_expression` | `isConst` of the last named child |
| `method_invocation` whose name is a *decoder* | true iff its object's `value` is resolved, or its first argument's `value` is resolved |
| `identifier`, `field_access` | look up; if it yields *(initialiser, ctx′)* → `isConst(initialiser, ctx′, d+1, viaVar = true)` |
| anything else | false |

Decoders: `getBytes`, `toCharArray`, `decode`, `decodeHex`, `decodeBase64`,
`parseHexBinary`, `parseBase64Binary`, `fromHexString`, `hexStringToByteArray`,
`hexToBytes`, `fromHex`.

### 7.5 Rule index

Each pattern of each Java rule is indexed under a key:

| Anchor | Key |
|---|---|
| `call: C.m` | (`call`, `m`) |
| `new: C` | (`new`, last segment of `C`) |
| `method: m` | (`call`, `m`) |
| `field: C.F` | (`field`, `F`) |
| `override: m` | (`decl`, `m`) |
| `anyCall` | every `call` event whose name is not excluded (5.5) |

A key whose name ends with `*` is a prefix key. The candidate patterns of an event of kind
*k* and name *n* are those under (*k*, *n*) and under every prefix key (*k*, *p*`*`) with *n*
starting with *p*. Candidates are grouped by rule; within a rule, patterns keep their
file order.

### 7.6 Pattern evaluation

**Anchors.**

* `call: C.m` holds for a `call` event whose name equals `m` (or starts with it, for `m*`)
  and: if the event has a receiver, `denotes(receiver, C)`; otherwise `C` is one of the
  event's static candidates (exact string equality).
* `new: C` holds for a `new` event with `denotes(T, C)`.
* `method: m` holds for a `call` event whose name equals `m` (or starts with it).
* `field: C.F` holds for a `field` event whose name equals `F` (or starts with it) and
  `denotes(receiver, C)`.
* `override: m` holds for a `decl` event whose name equals `m` (or starts with it).
* `anyCall` holds for a `call` event whose name is not excluded (5.5).

**Conditions** are evaluated as defined in 5.5, on the event's string list (7.4.6) and
argument texts. In addition:

* `inType`: find the nearest ancestor of the method declaration that is a `class_body` or
  `enum_body` (an `interface_body` is passed over, so a method of an interface nested in a
  class looks at that class); let *P* be that body's parent. If *P* is an `object_creation_expression`
  (anonymous class), the *owner text* is the text of *P*'s `type` field; otherwise it is the
  text of *P*'s `superclass` field and of its `interfaces` field, joined by a space (missing
  fields are empty; no such ancestor → empty). The condition
  holds iff some listed name occurs in the owner text as a whole word.
* `body`: take the text of the declaration's `body` field (false if absent, e.g. abstract);
  first replace every `/* … */` (shortest match, spanning lines), then every `//` up to (not
  including) the end of the line, by one space — textually, without regard to string literals; replace every
  whitespace run by one space; trim; then `find` the regex. Example: the body
  `{ /* nothing */ }` becomes `{ }`.

### 7.7 Selection

#### 7.7.1 Specificity

For each event and each candidate rule: evaluate the rule's candidate patterns other than `anyCall`
patterns; only if no such pattern of any rule holds, evaluate the `anyCall` patterns instead (5.5). If none
holds, the rule does not match. Otherwise the rule's specificity is the highest specificity
(5.5) among the holding patterns, and its **chosen pattern** is the first holding pattern
(in file order) with that specificity.

The **matched string** of the chosen pattern is: if it has `firstString`, the first string;
else if it has `stringContains`, the first string of the list that contains a needle; else if
it has `anyString`, the first string of the list that matches; else none.

Then group the matching rules by asset `type`; in each group, keep only the rules whose
specificity equals the group's maximum.

**Alternatives** *(DECISIONS B-J-JP3)*: if an argument of a `call` or `new` event is an identifier with
alternatives (7.4.3), the selection is made once per alternative value (that argument contributing the
value to the string list); if every alternative selects the same rules (in the same order), those rules are
reported, each with its matched string and oid only if they are the same for every alternative (else none:
the display name); otherwise the selection without the argument stands. `if (a) alg = "SHA256withRSA";
else alg = "SHA1withRSA"; Signature.getInstance(alg)` is RSA. All kept rules are reported. Consequences:

* the `java.jca.*.unresolved` fallbacks (bare `call` patterns) are reported only when no
  specific algorithm rule of the same asset type matches the call;
* `new SecretKeySpec(KEY, "AES")` yields both AES (`algorithm`) and a hard-coded key
  (`key-material`): different asset types;
* `setEnabledProtocols(new String[] {"TLSv1.1", "TLSv1.3"})` yields both TLS 1.1 and
  TLS 1.3.

#### 7.7.2 Nested duplicates

After all events of the file have been selected, a selected (event, rule) pair is
**dropped** if the rule has a `family` and some *expression ancestor* of the event's node
has a selected rule with the same asset `type` and the same `family` (string equality).
The expression ancestors of a node are its parent, the parent's parent, and so on, as long
as each is one of: `argument_list`, `object_creation_expression`, `method_invocation`,
`parenthesized_expression`, `cast_expression`, `array_initializer`,
`array_creation_expression`, `binary_expression`; the chain ends at the first other node.
Comparison is against selections *before* dropping.

Examples: `new GCMBlockCipher(new AESEngine())` → AES-GCM only (the inner AES has family
AES); `new HMac(new SHA256Digest())` → HMAC and SHA-2.

### 7.8 Java findings

Each kept (event, rule) pair yields one finding:

| Field | Value |
|---|---|
| line | per 7.2 |
| name | the matched string of the chosen pattern if there is one, else the display name |
| symbol | `call`: `C` + `.` + the event's method name; `new`: `C`; `method`: the method name; `field`: `C` + `.` + the event's field name; `override`: the method name (`C` from the chosen pattern) |
| snippet | the node text; for `decl` events, the text up to (not including) the first `{`, trimmed; at most 500 code points |
| param | if the chosen pattern has `param.index` *i*: the `value` of argument *i*, if resolved, mapped through the OID table (5.11); else none |
| oid | the OID the matched string was given as (5.11), if any |

---

## 8. Python source analysis

### 8.1 Overview

For each Python file:

1. One pre-order walk over the tree collects, with the scope each node belongs to (8.3):
   import statements (8.2; their subtrees are not walked further), simple assignments,
   function parameters, `call` nodes, bare-reference candidates (8.6.1), and attribute
   assignments.
2. Calls and bare references are matched in pre-order (8.6, 8.6.1).
3. Attribute assignments are matched in pre-order (8.9).

Within one file, at most one finding is emitted per (rule, line) (calls and assignments
share this set).

### 8.2 Imports

The import table maps a *local name* to a list of *targets* (insertion order, no
duplicates); a second list holds *star modules*. Imports are collected from the whole file
regardless of position (module level, inside functions, all branches of `try`/`except`
and `if`).

* `import a.b.c` (`dotted_name` child) → local `a`, target `a`.
* `import a.b as x` (`aliased_import` with `name` and `alias`) → local `x`, target `a.b`.
* `from M import …` (`import_from_statement`): *M* is the text of the `module_name` field;
  if `module_name` is a `relative_import`, *M* is empty.
  * with a `wildcard_import` child: if *M* is non-empty, append it to the star modules;
  * for each `name` field child: a `dotted_name` *n* → local = last segment of *n*,
    target = *M*`.`*n* (just *n* if *M* is empty); an `aliased_import` (*n* as *x*) → local
    *x*, target *M*`.`*n*.

Relative imports therefore stay unqualified (`from .local import md5` maps `md5` to `md5`).

**Import alternatives** *(DECISIONS F2)*. The *try context* of an import statement is found by
walking up from it, stopping (no context) at a `function_definition`, `lambda`,
`class_definition` or `module`: the first `block` that is the `body` of a `try_statement` *T*
gives the context "body of *T*"; the first `block` of an `except_clause` *E* (parent *T*) gives
"handler of *T*" if *E* has no `value` (a bare `except:`) or the text of one of its `value`s
contains one of the words `ImportError`, `ModuleNotFoundError`, `Exception`, `BaseException`,
and no context otherwise; the first `block` of an `else_clause` or `finally_clause` gives no
context. After the whole file has been collected, a (local name, target) pair of an import in
the context "handler of *T*" is **not** entered into the table if an import in the context
"body of *T*" has the same local name: the handler runs only when that import failed, so its
binding is the alternative, not an additional one. All other pairs are entered in collection
order. Star modules are not affected.

### 8.3 Scopes and bindings

The module has a scope. Every `function_definition` and every `lambda` opens a new scope
whose parent is the scope it appears in; the node's whole subtree (parameters, default
values, body) belongs to the new scope. Class bodies and comprehensions do not open scopes.

* **Assignments.** For every `assignment` node (not `augmented_assignment`) whose `left` is
  an `identifier` and which has a `right`: append the `right` node to the binding list of
  that name in the current scope (pre-order). Annotated assignments `x: T = v` count; tuple
  targets do not.
* **Parameters** *(Appendix A, D2)*. The parameter names of a `function_definition`
  (`parameters` field) and of a `lambda` (`parameters` field) are bound in the new scope:
  an `identifier` child; the `name` of a `default_parameter` or `typed_default_parameter`;
  the `identifier` child of a `typed_parameter`, `list_splat_pattern` or
  `dictionary_splat_pattern`.

`bindings(N, s)`: starting at scope `s` and moving to the parents, find the first scope that
binds `N` by assignment or as a parameter; return the list of right-hand sides assigned to
`N` in *that* scope (possibly empty, e.g. for a parameter that is never assigned), each with
that scope. If no scope binds `N`, the list is empty. Resolution is flow-insensitive: all
assignments of the scope count, wherever they are.

### 8.4 Name resolution

#### 8.4.1 Names

`resolveName(N, s)` returns a list of candidate fully-qualified names (at most 8):

1. for each *(rhs, s′)* in `bindings(N, s)` where *rhs* is an `identifier` or `attribute`:
   add `resolveDotted(rhs, s′)` (an alias such as `H = hashlib.sha1`);
2. add the import targets of `N`;
3. if nothing was added: `N` itself, then *M*`.`*N* for each star module *M*.

Duplicates are removed keeping the first occurrence; the list is truncated to 8 entries.
If step 1 reached the binding-step limit (6.3), the result is the empty list instead
*(DECISIONS O4)*.
Cycle guard: if `resolveName(N, s)` is called while the same (*s*, `N`) is already being
resolved, step 1 is skipped for that inner call; steps 2 and 3 still apply (so in `a = b;
b = a` without imports, `resolveName(a)` yields `[a]`: the inner call falls back to `a`
itself).

`resolveDotted(e, s)`: for an `identifier`, `resolveName`; for an `attribute` with object
*O* and attribute *a*: `[b + "." + a for b in resolveDotted(O, s)]` truncated to 8, or
nothing if *O* has no candidates; for any other node, nothing.

`boundCalls(N, s)`: for each *(rhs, s′)* in `bindings(N, s)` where *rhs* is a `call`, add
`callNames(rhs, s′)` (8.4.2); with its own cycle guard. (Example: `algo =
algorithms.AES(k)` → `boundCalls(algo)` contains
`cryptography.hazmat.primitives.ciphers.algorithms.AES`.)

`constantValues(N, s)`: for each *rhs* in `bindings(N, s)`: its string value or integer
value (8.5.1), if any; duplicates removed, in order.

#### 8.4.2 Call names

For a `call` with `function` *F*: `callNames = resolveDotted(F)`. If that is empty and *F*
is an `attribute`, `callNames = [shape(F)]`, where

* `shape(identifier)` = first element of `resolveName`;
* `shape(attribute)` = (`shape(object)`, or `<expr>` if that is none) + `.` + attribute;
* `shape(call)` = (`shape(function)`, or `<expr>`) + `()`;
* `shape` of anything else, or beyond nesting depth 8, is none.

So `priv.public_key().encrypt(…)` is named `priv.public_key().encrypt` and
`random.SystemRandom().random()` is named `random.SystemRandom().random`. A call without
call names (e.g. `handlers[k](…)`) is not analysed.

#### 8.4.3 Method name

If *F* is an `attribute`, the method name is the text of its `attribute`; otherwise it is the
text of *F* (trimmed).

### 8.5 Argument analysis

Argument analysis is performed only for calls that have at least one candidate pattern
(8.6).

The **arguments** are the named children of the call's `arguments` node: `keyword_argument`
nodes are keyword arguments (name = `name` field text, value = `value` field);
`list_splat`, `dictionary_splat` and `comment` children are ignored; all others are
positional. If `arguments` is a `generator_expression`, there are no positional or keyword
arguments, the string list is empty and the symbol set is collected from the generator
expression.

#### 8.5.1 Literal values and the string list

* **String value** of a `string` node: if the text of its first child (`string_start`, which
  includes the prefix) contains `b` or `f` (case-insensitive), none. If it has an
  `interpolation` child, none. Otherwise the concatenation of the texts of its
  `string_content` children. Escape sequences are **not** interpreted (the raw text is
  used). A `concatenated_string` has a value iff all its parts have one: the concatenation.
* **Integer value** of an `integer` node: its text with `_` removed.

`strings(e)`: a string value → that string; an `identifier` → its `constantValues` that do
not consist of decimal digits only; a `list`, `tuple`, `set` or `parenthesized_expression` →
`strings` of its named children, concatenated; anything else → nothing.

The **string list** of a call is `strings` of each positional argument in order, followed by
`strings` of each keyword-argument value in order; then every element that is a table OID is
replaced by its name and remembers the OID (5.11) *(DECISIONS E15)*.

#### 8.5.2 Symbol set

`collect(e, d)` adds symbols to the call's set; it stops when `d > 6`:

* `identifier`: add `resolveDotted(e)` and `boundCalls(name)`;
* `attribute`: add `resolveDotted(e)`; if its object is neither an `identifier` nor an
  `attribute`, `collect(object, d+1)`;
* `call`: add its `callNames`; if its function is neither `identifier` nor `attribute`,
  `collect(function, d+1)`; `collect(arguments node, d+1)`;
* `lambda`, `string`, `integer`, `float`, `comment`: nothing;
* anything else: `collect(child, d+1)` for each named child.

The symbol set is the union of `collect(a, 0)` over the positional arguments and keyword
values. Example: `AES.new(k, AES.MODE_GCM)` with `from Crypto.Cipher import AES` has the
symbols `k`, `Crypto.Cipher.AES.MODE_GCM`; `Cipher(algo, modes.GCM(iv))` with `algo =
algorithms.AES(k)` has `algo`, `…algorithms.AES`, `…modes.GCM`, `iv`.

#### 8.5.3 Value texts

The value texts of an expression *e* are, in order: the text of *e*; its string value (if
any); if *e* is an `identifier`, its `constantValues`; if *e* is an `identifier` or
`attribute`, `resolveDotted(e)`; if *e* is a `call`, its `callNames`. A string value or
constant value that is a table OID is directly followed by its name (5.11).

### 8.6 Matching calls

Calls are processed in pre-order. For a call with call names *names* (8.4.2) and method name
*m*:

**Candidates.** The candidate patterns, in this order, each pattern at most once:

1. for each name *n* of *names* in order, for each prefix of *n* made of its first *k*
   `.`-separated segments, *k* from the number of segments down to 1: the patterns whose
   `call` equals the prefix (rules in id order, patterns in file order). The *name used* is
   *n*;
2. the patterns without `call` whose `method` contains *m* (rule order, file order); name
   used: *names*[0] — but if the pattern has `anySymbol`, the first entry of its `anySymbol`
   list (in list order) that hits the symbol set: the receiver of a method-only pattern is
   unknown, so the finding is named after the API that identified it
   (`cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15`, not `key.sign`)
   *(DECISIONS E13/E17)*;
3. if at least one `anyCall` pattern requires a keyword (in `kwargs`) that the call has: all
   `anyCall` patterns (rule order, file order); name used: *names*[0].

4. *(DECISIONS B-P-RX, feature `python-reexports`)* if steps 1–3 found nothing: for each name *n* of
   *names* that has at least three segments and does not start with `cryptography.`, the `call` patterns that
   may fire on references (8.6.1) and whose value starts with `cryptography.hazmat.primitives.` and ends with
   the same last two segments as *n* (a pyca class re-exported by another package:
   `jwt.algorithms.hashes.SHA256`); name used: *n*. Bare references (8.6.1) take the `ref` and `call`
   patterns of the same kind. The pre-filter (14) requires only those two segments for them.

If there are no candidates, the call is skipped without argument analysis.

**Hits.** Go through the candidates in order; skip a candidate whose rule already has a hit
on this call; otherwise evaluate its conditions (5.6; a `method` key on a `call` pattern is
also checked). A holding pattern gives the hit *(rule, name used, pattern)*.

**Refinement.** The *identity* of a rule is (asset type, primitive, family, protocol,
subtype); a rule is *refined* if it has a `variant` or a `version`. Drop every hit whose rule
is not refined if another hit's rule is refined and has the same identity.
(`Cipher(algorithms.AES(k), modes.GCM(iv))` → AES-GCM, not also AES.)

**Fallbacks** *(DECISIONS B-P-U1)*: a hit of a rule whose id ends in `.unresolved` is dropped if the call
has a hit of another rule with the same asset type and — when the fallback rule has a primitive — the same
primitive (the Python counterpart of the Java specificity rule, 7.7.1). The bundled fallbacks are
`python.hash.unresolved` (`hashlib.new`, `getattr` on a hash module, pyca `hashes.Hash` and `hmac.HMAC`
and the stdlib `hmac` functions whose hash is not one of the known hash APIs) and
`python.cipher.unresolved` (pyca `Cipher` without one of pyca's algorithm classes among its symbols),
both under the feature `python-unresolved` (3.1).

**Emission.** For each remaining hit, in hit order:

1. *Nesting.* If the call node lies completely inside a recorded argument range of the same
   rule, drop the hit (`bcrypt.hashpw(pw, bcrypt.gensalt())` and
   `ec.generate_private_key(⏎ ec.SECP256R1())` are one finding each, even across lines).
2. Record the byte range of the call's `arguments` node for the rule.
3. *Report node*: if the pattern has `reportAt`, the enclosing operation call (8.7), if any;
   otherwise the call itself.
4. *Line*: if the report node's `function` is an `attribute`, the row of that attribute's
   `attribute` identifier + 1 (the line of `encrypt` in `a.b().encrypt(`); otherwise the
   report node's start row + 1.
5. If (rule, line) was already emitted in this file, drop the hit; otherwise emit:

| Field | Value |
|---|---|
| line | from step 4 |
| name, symbol | the name used |
| snippet | text of the report node, at most 500 code points |
| param | 8.8 |
| oid | 5.11 |

### 8.6.1 Bare references *(DECISIONS E1)*

Libraries that define their algorithm suites declaratively name an algorithm without calling
it: in tables (`MACS = ((b"hmac-sha1", sha1),)`), as class attributes (`SHA256 =
hashes.SHA256`), as arguments (`hmac_oneshot(k, m, digest=hashlib.sha256)`) or as enum
members (`Mechanism.SHA256_RSA_PKCS`). Such a *bare reference* is an `identifier` or an
`attribute` node that is neither the `object` of an `attribute` nor the `function` of a
`call`. Its *names* are `resolveDotted` of the node (8.4.1); a reference without names is not
analysed.

**Candidates**: for each name *n* in order, the patterns that may fire on references whose value
equals *n* exactly (no prefix match), rules in id order, patterns in file order, each at most
once; name used: *n*. Patterns that may fire on references are the `ref` patterns and the `call`
patterns without any of `method`, `firstString`, `stringContains`, `anySymbol`, `allSymbols`,
`kwargs`, `dictItems`, `notInside` (a reference has no arguments). `param` and `reportAt` do not
prevent it.

**Position.** Walk from the reference *x* to its parent *p*, upwards:

* `parenthesized_expression` and `conditional_expression` are passed through;
* `list`, `tuple`, `set`, `expression_list`, `dictionary` and `pair` (key or value) are passed
  through and mark the reference as a *container element*;
* `argument_list`: a value position iff its parent is a `call` whose method name (8.4.3) is not
  `isinstance`, `issubclass`, `cast`, `TypeVar` or `NewType` (class bases are not positions);
* `keyword_argument`: a value position iff *x* is its `value` and the keyword argument belongs
  to the `argument_list` of such a call;
* `assignment`: a value position iff *x* is its `right`;
* any other node: a value position iff *x* is a container element and the node is not a type or
  test context: `comparison_operator`, `except_clause`, `subscript`, `type`, `generic_type`,
  `union_type`, `constrained_type`, `member_type`, `splat_type`, `type_alias_statement`,
  `type_parameter`.

**Key-type tests** *(DECISIONS B-P-ISI, feature `python-isinstance-keys`; relaxes E1)*: in a call
`isinstance(x, K)` with two positional arguments, the identifier and attribute references of `K` (a name or the
elements of a tuple) whose resolved name ends in a key-class name (`PrivateKey`, `PublicKey`, `…Key`,
`SigningKey`, `VerifyKey`) are matched against the reference patterns (exactly, or as re-exports, 8.6 step 4);
if all their hits belong to rules of exactly one family, each hit is reported at its reference (one per rule
and line, as always): `isinstance(key, rsa.RSAPrivateKey)` dispatches on RSA. With hits of two families
(`(rsa.RSAPublicKey, ec.EllipticCurvePublicKey)`) nothing is reported. The bundled rules gain pyca's key
interfaces `rsa.RSAPrivateKey`/`RSAPublicKey`, `ec.EllipticCurvePrivateKey`/`PublicKey`, `dsa.DSA…Key`,
`dh.DH…Key` as `call` patterns (value positions) under the same feature.

A `call` pattern fires only in a value position. A `ref` pattern fires in any *expression
position*: the same walk in which `binary_operator`, `unary_operator`, `boolean_operator`,
`not_operator` and `await` are passed through as well and every reference counts as a container
element (`Q = P + ecc.GENERATOR * k`, `return Mechanism.ECDSA`). Default values of parameters are
not positions (8.3: they belong to the function's scope, Appendix B).

**Hits, refinement, emission** as in 8.6, with these differences: there are no conditions; no
argument range is recorded; the nesting check of step 1 applies (a reference inside the recorded
arguments of a call with a hit of the same rule is dropped: `hmac.new(k, m, hashlib.sha256)` is
one SHA-2 finding, at `hmac.new`); the report node is the reference, or with `reportAt` the
operation call of 8.7 started at the reference; the line is the row of an `attribute`'s
`attribute` identifier (of the report node, or of the report call's `function`) + 1, otherwise
the start row + 1; the snippet is the report node's text; param: `{value: s}` → *s*,
`{self: true}` → as in 8.8, otherwise none.

### 8.7 Operation-call attribution (`reportAt`)

Starting at the matched call *c*: let *x* = *c* and *p* = parent of *x*. While *p* is one of
`argument_list`, `keyword_argument`, `call`, `parenthesized_expression`, `list`, `tuple`,
`conditional_expression`:

* if *p* is a `call`: if *x* is not inside *p*'s `arguments` node, stop with no result (the
  walk came up through the callee or receiver); if *p*'s method name is in the `reportAt`
  list, the result is *p*;
* *x* = *p*, *p* = parent of *p*.

No result if the loop ends. So `key.sign(m, padding.PSS(mgf=padding.MGF1(hashes.SHA256())),
hashes.SHA256())` reports PSS and SHA-2 once each, at the line of `sign`; a padding object
stored in a variable first (`pad = padding.OAEP(…)`) stays at its own line.

### 8.8 Parameter extraction (`param`)

* `{value: s}`: *s*.
* `{self: true}`: the last `.`-segment of the name used, if it contains a `.`; else none
  (`ec.SECP256R1()` → `SECP256R1`).
* Otherwise the argument node is: the value of keyword argument `keyword` if the call has
  it; else positional argument `index` if given and present; else none. Its param is:
  1. its integer value, else its string value, if any;
  2. if it is an `identifier`: its first `constantValues` entry if there is one; otherwise
     the candidates are `boundCalls`, or if that is empty, the `resolveName` candidates other
     than the identifier itself;
     if it is a `call`: its `callNames`; if it is an `attribute`: `resolveDotted`;
     otherwise no candidates;
  3. the last `.`-segment of the first candidate that contains a `.`; else none.

A param that is a table OID is replaced by its name (5.11).

Examples: `key_size=2048` → `2048`; `key_size=KEY_BITS` with `KEY_BITS = 3072` → `3072`;
`ec.generate_private_key(ec.SECP384R1())` → `SECP384R1`; `ECC.generate(curve="P-256")` →
`P-256`; a parameter passed through (`curve`) → none.

### 8.9 Attribute assignments

For every `assignment` or `augmented_assignment` whose `left` is an `attribute`, in
pre-order: the field is the text of the left side's `attribute`; the value texts are those
of `right` (8.5.3). For each rule (id order) that has `assign` patterns: the rule hits if
one of its `assign` patterns names this field and its `value` / `valueContains` conditions
hold. A hit is emitted with line = the assignment's start row + 1, unless (rule, line) was
already emitted; name and symbol = the field name; snippet = the assignment text.

---

## 9. Dependency manifests

Every manifest yields a set of *entries* (package key, version or none). An entry is
reported iff its key matches the dependency rule of its ecosystem (5.9). Within one
manifest, an entry key appears at most once. If a package is declared several times, a
declaration with a resolved version beats one without; among declarations of the same kind,
the **last** one (in the order defined per format below) determines the version. For Maven
this means that a version from the same POM's `<dependencyManagement>` (or `<properties>`)
applies to an unversioned dependency; parent POMs and BOM imports are not followed, and a
dependency whose version stays unresolved is reported without version.
A manifest that cannot be parsed (malformed XML/TOML/JSON) is skipped with a warning; it
yields no entries.

| Format | Ecosystem | Manifest label (11.4) |
|---|---|---|
| `pom.xml` | maven | `pom` |
| `build.gradle`, `build.gradle.kts` | maven | `gradle` |
| `*.versions.toml` | maven | `gradle-catalog` |
| `requirements*.txt`, `requirements/*.txt` | pypi | `requirements` |
| `pyproject.toml` | pypi | `pyproject` |
| `Pipfile` | pypi | `pipfile` |
| `Pipfile.lock` | pypi | `pipfile-lock` |
| `poetry.lock` | pypi | `poetry-lock` |
| `setup.cfg` | pypi | `setup-cfg` |
| `setup.py` (Python source, 9.8) | pypi | `setup-py` |
| `go.mod` (17.10) | golang | `go-mod` |
| `go.sum` (17.10) | golang | `go-sum` |

### 9.1 Package keys and versions

* **Maven**: key `groupId:artifactId` as written (case preserved; rule matching is
  case-insensitive).
* **PyPI**: the PEP 503 normalised name: lower-case, every run of `-`, `_`, `.` replaced by
  one `-` (`PyJWT` → `pyjwt`, `argon2_cffi` → `argon2-cffi`).
* A **version** is a non-empty string with surrounding whitespace removed, or none. Version
  ranges are never reported as versions (a lower bound is not a version).

### 9.2 Python requirements files

Lines are processed in order. A line ending in `\` is joined with the next line first.
Then: remove a comment that starts with `#` at the beginning of the line or after
whitespace; trim. Skip the line if it is empty, starts with `-` (options such as `-r`,
`-e`, `--hash`, `-c`, `--index-url`), or contains `://`. Otherwise parse the start of the
line as a PEP 508 requirement:

```
^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(?:\(?\s*(===|==|~=|>=|<=|!=|>|<)\s*([^\s;,)]+))?
```

Group 1 is the name. If the operator (group 3) is `==` or `===` and the version (group 4)
contains no `*`, the version is group 4; otherwise none. Text after the first specifier
(further specifiers, environment markers, `--hash` options) is ignored. Lines that do not
match are skipped. Included files (`-r other.txt`) are not followed; they are scanned on
their own if they are classified as requirements files.

### 9.3 pyproject.toml

Parsed as TOML 1.0. Entries are taken from, in this order:

1. `project.dependencies` (array of PEP 508 strings);
2. `project.optional-dependencies.*` (tables in document order; arrays of PEP 508 strings);
3. `dependency-groups.*` (PEP 735; string elements only; `{include-group = …}` tables are
   ignored) *(Appendix A, D7)*;
4. `tool.poetry.dependencies`, `tool.poetry.dev-dependencies`, then
   `tool.poetry.group.*.dependencies` (groups in document order).

PEP 508 strings are parsed as in 9.2 (without comment handling); as there, a string that
contains `://` (a direct reference such as `pkg @ https://…`) is skipped *(DECISIONS O5)*. In Poetry tables, the key is
the name (`python` is skipped) and the value is either a version-constraint string or a
table with a `version` string (other forms: no version). The constraint is an exact version
iff, after trimming, it matches `^=?=?\s*(\d[^\s,*]*)$`; the version is group 1 (`"1.5.0"`,
`"==2.14.2"`). Carets, tildes, ranges and wildcards give no version.

### 9.4 Pipfile, Pipfile.lock and poetry.lock

* **Pipfile** (TOML, *DECISIONS B-G2*): the tables `packages`, then `dev-packages`; each key is a name
  (`python` is skipped) and the value is a version-specifier string or a table with a `version`
  string, read like a Poetry table (9.3): only an exact pin (`"==3.20.0"`) gives a version
  (https://pipenv.pypa.io/en/latest/pipfile.html). Other tables (`source`, `requires`) are ignored.
* **Lock files are transitive** *(DECISIONS B-G2)*: `Pipfile.lock`, `poetry.lock` (and Go's `go.sum`,
  17.10) list every resolved package, the dependencies of dependencies included. By default they
  yield no findings (they are still counted as scanned manifests); the project's direct requirements
  come from `Pipfile`, `pyproject.toml` and `go.mod`. With `--transitive-deps` (3.1) they are read as
  below.
* **Pipfile.lock** (JSON): the objects `default`, then `develop`; each key is a name; the
  version is the entry's `version` string with all leading `=` removed (`"==4.9"` → `4.9`);
  no `version` → none.
* **poetry.lock** (TOML): every `[[package]]` table with a string `name`; version = its
  `version` string *(Appendix A, D7)*.

### 9.5 pom.xml

Parsed as XML with namespace-unaware local names (the POM namespace is optional). The parser
MUST NOT resolve DTDs or external entities (disable DOCTYPE declarations; treat any
DOCTYPE as a parse error) *(security)*.

* Every `dependency` element anywhere in the document (`dependencies`,
  `dependencyManagement`, plugin `dependencies`, `profiles`, …), in document order, whose
  direct children `groupId` and `artifactId` have non-empty trimmed text, is an entry.
  Elements inside XML comments are not elements and are ignored.
* The version is the trimmed text of the direct child `version`, with property references
  `${name}` substituted (repeatedly, at most 10 rounds) from:
  * the direct children of the root's `properties` element (name = element name, value =
    trimmed text);
  * `project.version` and `version` → the root's `version`, or else `parent/version`;
    `project.groupId` → the root's `groupId`, or else `parent/groupId`;
    `project.parent.version` → `parent/version`.

  If a `${…}` remains after substitution, or there is no `version` child, the version is
  none. Parent POMs, imported BOMs and profiles' properties are not consulted.
* `scope`, `optional`, `type`, `classifier` are ignored (test-scoped dependencies are
  reported).

### 9.6 Gradle build scripts

Gradle scripts are not evaluated; they are scanned textually:

1. Remove comments: `//` to the end of the line and `/* … */`, except inside string
   literals (single-quoted, double-quoted and triple-quoted strings are recognised so that
   `"http://…"` is kept).
2. Collect **string variables**: `(val|var|def)\s+NAME(\s*:\s*String)?\s*=\s*"…"` or `'…'`,
   and `ext.NAME = "…"` / `'…'` (the literal must not contain `$`). Later definitions
   replace earlier ones.
3. **Coordinate strings.** For every single- or double-quoted string literal (not
   triple-quoted), substitute `${NAME}` and `$NAME` from the string variables (an unknown
   name stays). If the result matches
   `^([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)(?::([^:@\s]+))?(?::[^:@\s]+)?(?:@[A-Za-z0-9]+)?$`,
   it is an entry with key `group1:group2` and version group 3, or none if group 3 is absent
   or contains `$`. Strings whose group or artifact still contain `$` are not entries.
4. **Map notation.** Every match of
   `group\s*[:=]\s*(['"])(.+?)\1\s*,\s*name\s*[:=]\s*(['"])(.+?)\3(?:\s*,\s*version\s*[:=]\s*(['"])(.+?)\5)?`
   (Groovy `group: 'g', name: 'a', version: 'v'`, Kotlin `group = "g", name = "a",
   version = "v"`) is an entry, with the same variable substitution.

Entries are ordered by their start offset in the comment-free text. Catalog accessors
(`libs.jose4j`) are not resolved in the script; the catalog itself is scanned (9.7).

### 9.7 Gradle version catalogs

Parsed as TOML. `[versions]`: name → string, or a table from which `strictly`, then
`require`, then `prefer` is taken. `[libraries]` (in document order): each value is

* a string `"g:a:v"` or `"g:a"` (parsed like 9.6 step 3), or
* a table with `module = "g:a"`, or with `group` and `name`; and a version given as
  `version = "v"`, `version.ref = "name"` (looked up in `[versions]`), or a `version` table
  with `ref`, `strictly`, `require` or `prefer`.

Missing or unresolvable versions are none. `[bundles]` and `[plugins]` are ignored.

### 9.8 setup.py and setup.cfg *(DECISIONS E10)*

Nothing is evaluated; only literal requirement strings are read.

* **setup.py** is Python source (4.5) and is analysed as such; if its text contains
  `install_requires` or `extras_require`, it is parsed even when the pre-filter (14) would skip
  it, and it also yields dependency findings (manifest label `setup-py`; the file counts as a
  Python file, 11.2.1). The *module bindings* are the `assignment`s directly below the module
  (`expression_statement` children of `module`) with an `identifier` on the left. For every
  `call` (pre-order) whose `function` is the identifier `setup` or an attribute `setup` of
  `setuptools` or `distutils.core` (text without whitespace), take, in this order, the value of
  its keyword argument `install_requires`, then each pair value of its `extras_require` value
  (a `dictionary`, or an identifier whose module bindings are dictionaries, in order). A value
  contributes its requirement strings: a string with a value (8.5.1) is a PEP 508 string (9.2,
  `://` skipped); a `list`, `tuple` or `parenthesized_expression` contributes its elements'
  strings (12 levels at most); an identifier at the top contributes the strings of each of its
  module bindings (`rsa_require = ['cryptography>=3']`; one level). Anything else contributes
  nothing.
* **setup.cfg** is read line by line (LF; a trailing CR is removed). Blank lines and lines whose
  first non-blank character is `#` or `;` are skipped. A non-indented line `[name]` starts a
  section (name trimmed, lower case). A non-indented line with `=` or `:` (the first one
  separates) is a key (trimmed, lower case, `-` → `_`) and its value. Requirements are the key
  `install_requires` of section `options` and every key of section `options.extras_require`:
  the value on the key's line, if any, and each following indented line, one requirement per
  line, comments removed as in 9.2, parsed as PEP 508 (9.2); values starting with `file:` or
  `attr:` are not followed, values containing `://` are skipped.

Entries are de-duplicated per file as in the introduction of section 9.

### 9.9 Contents of the bundled library lists *(DECISIONS F3)*

A package (Maven artifact, PyPI distribution, Go module) is on the bundled list of its ecosystem
if its own documentation states as its purpose one of:

* (a) implementing or binding cryptographic primitives (ciphers, hashes, MACs, signatures, KEMs,
  key agreement, KDFs, password hashing, CSPRNGs);
* (b) implementing a cryptographic protocol or message format (TLS/DTLS, SSH, Noise, WireGuard,
  HPKE, OpenPGP, JOSE/JWT, CMS/PKCS #7, PKCS #8/#12, XML signature/encryption, age);
* (c) cryptographic key management or cryptographic operations in a key-management service or a
  hardware module: the key clients of cloud KMSs (AWS KMS, Google Cloud KMS, Azure Key Vault
  keys), PKCS #11, PIV smart cards, TPMs;
* (d) creating or verifying digital signatures, certificates or time-stamps for artefacts:
  signing libraries (Sigstore), certificate authorities, RFC 3161 time-stamping.

Not listed: SDK cores, transport and HTTP libraries that only use TLS; secret stores that hold
opaque values (Azure Key Vault secrets, cloud secret managers); general clients of platforms that
offer cryptographic services among others (a cloud SDK as a whole); data-model, schema and protobuf
packages; transparency logs and supply-chain frameworks that use signatures as one part of a broader
model (TUF, in-toto). **Exceptions by owner decision** *(DECISIONS B-G4, reversing these parts of
F3)*: the Go modules `github.com/hashicorp/vault/api` (Vault's transit and PKI engines are reached
through it), `github.com/sigstore/protobuf-specs` (Sigstore's key-type and hash-algorithm data model)
and `github.com/sigstore/rekor` (Sigstore transparency log) are listed. `certifi` (a CA bundle,
none of a–d) is no longer listed *(DECISIONS B-P1)*; `commons-codec` is reported only where the
project uses its digest package *(DECISIONS B-J4, 5.9 `usedIf`)*.
A `*` glob is used where a project publishes several modules or major versions under one prefix.

---

## 10. Normalisation: findings to components

### 10.1 Component identity

| Asset type (rule) | Component key |
|---|---|
| `algorithm` | (rule id, name, param, oid) |
| `protocol` | (rule id) |
| `certificate` | (rule id) |
| `related-crypto-material`, `key-material` | (rule id) |
| `library` | (ecosystem, package key, version) |

All findings with the same key form one component. Different algorithm strings behind the
same API call are different components (`Cipher.getInstance("AES/GCM/NoPadding")` and
`Cipher.getInstance("AES/GCM/PKCS5Padding")`), and so are different calls of one rule in
Python (`hashlib.md5` and `hashlib.new` with `"md5"`). Findings are never merged across
rules.

### 10.2 Component name

| Asset type | Name |
|---|---|
| `algorithm` | the finding's name: Java — the matched algorithm string (`AES/GCM/NoPadding`, `SHA-256`) or the display name (`GCMBlockCipher`, `Cipher.getInstance`); Python — the resolved call name (`cryptography.hazmat.primitives.ciphers.Cipher`, `hashlib.new`); Go — the import path and member (`crypto/aes.NewCipher`, 17.8) |
| `protocol` | upper-case protocol, then a space and the version if the rule has one: `TLS 1.2`, `SSL 3.0`, `TLS`, `SSH` |
| others | the rule's `name` |
| `library` | Maven: the artifactId (the groupId goes to `group`); PyPI: the normalised name; Go: the module path |

### 10.3 Occurrences

Each finding becomes an occurrence of its component. Within a component, occurrences with
the same (path, line) — for libraries, the same path — are one occurrence: sort them by
(symbol, snippet, `via` chain — absent first, 18.7) in code-point order and keep the first. (A
propagated finding never shares a line with a finding of phase 3 of the same family key, 18.7.)

---

## 11. CBOM output

### 11.1 Library choice

CipherSift writes the JSON itself with Jackson's streaming `JsonGenerator` (fixed key order,
two-space indentation, `\n` line ends, UTF-8 without BOM, a final newline). It does **not**
use `org.cyclonedx:cyclonedx-core-java` for writing, because (a) byte-stable output needs
full control over key order, number formatting and escaping, (b) only a small subset of the
model is needed, and (c) the library adds dependencies to the fat jar. `cyclonedx-core-java`
13.2.0 is used **in tests only**, to validate every produced document against the CycloneDX
1.7 JSON schema (`JsonParser#validate(…, Version.VERSION_17)`; `VERSION_16` for
`--cyclonedx-version 1.6`). The tests also validate against the schemas of the CycloneDX
specification release 1.7.2 (`bom-1.7.schema.json`, `bom-1.6.schema.json`,
`cryptography-defs.schema.json`, `spdx.schema.json`, `jsf-0.82.schema.json`), vendored in
`src/test/resources/cyclonedx/`, with json-schema-validator. 13.2.0 bundles the same
`bom-1.7.schema.json` and `cryptography-defs.schema.json` byte for byte.

### 11.2 Document

```
bomFormat      "CycloneDX"
specVersion    "1.7" (or "1.6" with --cyclonedx-version 1.6)
serialNumber   "urn:uuid:<uuid>"           (11.6)
version        1
metadata       (11.2.1)
components     [ … ]                       (11.3, 11.6; always present, possibly empty)
dependencies   [ … ]                       (only if there is at least one library component)
```

#### 11.2.1 Metadata

```
timestamp   only if the environment variable SOURCE_DATE_EPOCH is a non-negative integer:
            that instant, ISO-8601 UTC with seconds precision ("2026-01-01T00:00:00Z")
tools       {"components": [{"type": "application", "name": "ciphersift", "version": "<version>"}]}
component   {"type": "application", "bom-ref": "root", "name": "<last segment of the scan root>"}
properties  ciphersift:rulesDigest   "sha256:<hex>" over the rule set (11.6)
            ciphersift:testFiles     "included" | "excluded"
            ciphersift:filesScanned  decimal count of files analysed (source + manifests)
            ciphersift:filesSkipped  decimal count of files skipped (too large, binary, unreadable, failed)
            ciphersift:weaknessIndicators  "included", only with --weakness-indicators (3.1)
            ciphersift:pythonThinWrappers  "included", only with --python-thin-wrappers (3.1, 18)
            ciphersift:features      the feature switches that differ from their defaults (3.1), as
                                     "id=on|off" joined by "," in code-point order of the ids; only if any
```

### 11.3 Components

Common shape of a cryptographic component:

```
type              "cryptographic-asset"
bom-ref           "<assetType>:<16 hex digits>"            (11.6)
name              (10.2)
cryptoProperties  { assetType, <type-specific properties>, oid (only if the component has one, 5.11) }
properties        [ {name, value}, … ]                     (11.3.4)
evidence          { occurrences: [ … ] }                   (11.4)
```

#### 11.3.1 Algorithms

`cryptoProperties.assetType` = `algorithm`; `algorithmProperties` with, in this order and
only when they have a value:

| Key | Value |
|---|---|
| `primitive` | the rule's `primitive`, or `unknown` |
| `algorithmFamily` | 1.7 only: the registry family of table 11.3.1a |
| `parameterSetIdentifier` | the param |
| `ellipticCurve` | 1.7 only: the registry curve of table 11.3.1b |
| `mode` | from the variant (case-insensitive): `ECB`→`ecb`, `CBC`→`cbc`, `CCM`→`ccm`, `GCM`→`gcm`, `CFB`→`cfb`, `OFB`→`ofb`, `CTR`→`ctr`; `EAX`, `OCB`, `SIV`, `GCM-SIV`, `XTS`, `KW` → `other`; otherwise absent |
| `padding` | `OAEP`→`oaep`, `PKCS1v15`→`pkcs1v15`, `PSS`→`other`; or `pkcs1v15` when the rule subtype is `pkcs1-v1_5-encrypt`; otherwise absent |
| `classicalSecurityLevel` | the rule's `securityLevel` |

CycloneDX 1.6 has no field for the algorithm family; it is a property (11.3.4). CycloneDX 1.7
adds `algorithmFamily` and `ellipticCurve`, whose values must come from the CycloneDX
cryptography registry (`cryptography-defs.schema.json`, enums `algorithmFamiliesEnum` and
`ellipticCurvesEnum`). In 1.7 output CipherSift writes them **in addition to** the
`ciphersift:family` property (which stays, unchanged, in both versions), and only where the
rule determines the value; otherwise the field is absent *(DECISIONS C1)*.

**Table 11.3.1a: rule family → `algorithmFamily`.** A family that is not in the table gets no
`algorithmFamily`. Exact string comparison on the rule's `family`, `primitive`, `variant` (case-insensitive)
and `subtype`:

| Rule family | `algorithmFamily` |
|---|---|
| `3DES`, `AES`, `Argon2`, `bcrypt`, `Blowfish`, `CAST5`, `ChaCha20`, `CMAC`, `DES`, `DSA`, `ElGamal`, `HKDF`, `HMAC`, `IDEA`, `MD2`, `MD4`, `MD5`, `ML-DSA`, `ML-KEM`, `PBKDF2`, `Poly1305`, `RC2`, `RC4`, `Salsa20`, `scrypt`, `SEED`, `Serpent`, `SLH-DSA`, `SM3`, `SM4`, `Twofish` | the same name |
| `Camellia` | `CAMELLIA` |
| `SHA1` / `SHA2` | `SHA-1` / `SHA-2` |
| `SHA3` | `SHA-3`; none if the component name contains `keccak` (case-insensitive; pre-standard Keccak, which the SHA3 rules also list) |
| `BLAKE2` | `BLAKE2`; `BLAKE3` if the component name contains `blake3` (the BLAKE2 rule also lists the BLAKE3 classes) |
| `RIPEMD160` | `RIPEMD` |
| `XSalsa20` | `Salsa20` (XSalsa20 is the extended-nonce Salsa20) |
| `KBKDF` | `SP800-108` |
| `DH` | `FFDH` |
| `Ed25519`, `Ed448` | `EdDSA` |
| `EC` | primitive `signature` → `ECDSA`; `key-agree` → `ECDH`; otherwise none. This follows the primitive the rule declares and the CBOM already states: `python.asym.ec` (EC key generation and use) declares `key-agree`, so its components get `ECDH` (to be revisited with the rules) |
| `Curve25519`, `Curve448` | primitive `key-agree` → `ECDH` (X25519 / X448); otherwise none |
| `RSA` | variant `OAEP` → `RSAES-OAEP`; `PSS` → `RSASSA-PSS`; subtype `pkcs1-v1_5-encrypt`, or variant `PKCS1v15` with primitive `pke` → `RSAES-PKCS1`; variant `PKCS1v15` with primitive `signature` → `RSASSA-PKCS1`; otherwise none (the registry has no family for RSA without a scheme) |
| `ConcatKDF`, `X963KDF` | none (no registry family) |
| `PBE` | none (PBES1 or PBES2; the rule does not say which) |

A unit test checks that every value of the table is in the vendored registry and that every
family of the bundled rules is in the table.

**Table 11.3.1b: `ellipticCurve`.** For family `EC`: the param, if it equals the name of a
registry curve in the namespaces `secg`, `x962`, `nist` or `brainpool` without the namespace
prefix, compared case-insensitively (`SECP256R1` → `secg/secp256r1`, `prime256v1` →
`x962/prime256v1`, `P-256` → `nist/P-256`, `BrainpoolP256R1` → `brainpool/brainpoolP256r1`);
otherwise none. Families `Curve25519`, `Curve448`, `Ed25519`, `Ed448` → `other/Curve25519`,
`other/Curve448`, `other/Ed25519`, `other/Ed448`. No other family gets a curve. Synonyms are
not resolved: `secp256r1`, `prime256v1` and `P-256` stay three registry names, as the
registry lists them.

Not used from 1.7: the `key-wrap` primitive (the rules record key wrapping inconsistently —
the Python AES-KW rule as variant `KW`, the Java one not at all — and the comparison takes the
primitive from the rule, so key wrapping stays `block-cipher` with mode `other`); the new
protocol types (`dtls`, `quic`, …; no rule detects them); `relatedCryptographicAssets`,
certificate and related-material fields (CipherSift has no values for them); the deprecated
`curve` is not written. Evidence occurrences are unchanged in 1.7.

#### 11.3.2 Protocols

`assetType` = `protocol`; `protocolProperties` = `{"type": <protocol>, "version": <version>}`
(`version` only if the rule has one).

#### 11.3.3 Certificates and related material

* `certificate` rules: `assetType` = `certificate`, no further crypto properties.
* `related-crypto-material` and `key-material` rules: `assetType` =
  `related-crypto-material` and `relatedCryptoMaterialProperties` = `{"type": T}` with T from
  the subtype: `hardcoded-key` → `secret-key`; `static-iv` → `initialization-vector`;
  `hardcoded-password` → `password`; `jwt-none-algorithm` → `token`; `private-key` →
  `private-key`; `public-key` → `public-key`; `cms-signed-data` → `signature`;
  `cms-enveloped-data` → `ciphertext`; every other subtype or none → `other`. The rule's
  original asset type and subtype are properties.

#### 11.3.4 Component properties

In this order, each only if it has a value:

| Name | Value |
|---|---|
| `ciphersift:ruleId` | rule id (all components of one key share it) |
| `ciphersift:language` | `java` / `python` / `go` |
| `ciphersift:assetType` | the rule's asset type when it differs from the CycloneDX one (`key-material`) |
| `ciphersift:primitive` | the rule's primitive (absent if unknown) |
| `ciphersift:family` | the rule's family |
| `ciphersift:variant` | the rule's variant |
| `ciphersift:subtype` | the rule's subtype |
| `ciphersift:indicator` | the rule's `indicator` (5.3), e.g. `weakness` (only with `--weakness-indicators`, DECISIONS E2) |
| `ciphersift:testOnly` | `true` if every occurrence is in a test file |

#### 11.3.5 Libraries

```
type        "library"
bom-ref     the purl
group       Maven groupId (Maven only)
name        (10.2)
version     only if known
purl        pkg:maven/<groupId>/<artifactId>[@<version>], pkg:pypi/<name>[@<version>] or
            pkg:golang/<module path>[@<version>] (17.10)
            (percent-encode every character outside A-Z a-z 0-9 . - _ ~ in each part; for Go each
            /-separated segment of the module path is a part)
properties  ciphersift:ruleId, ciphersift:ecosystem ("maven" / "pypi" / "golang"), ciphersift:testOnly (if so)
evidence    { occurrences: [ … ] }
```

`dependencies` = `[{"ref": "root", "dependsOn": [<library bom-refs in component order>]}]`.

### 11.4 Occurrences

```
location           relative path (always "/"-separated)
line               1-based line (absent for dependency findings: file-level)
symbol             the finding's symbol (absent for dependency findings)
additionalContext  a string holding compact JSON (no whitespace) with keys in this order:
                   "ruleId"    rule id                                  (always)
                   "snippet"   the snippet (dependencies: the coordinate, "g:a:v" / "name==v" / "name" /
                               "path@version", 17.10)
                   "param"     the param, if any
                   "manifest"  manifest label (9), dependency findings only
                   "via"       wrapper propagation only (18.7): array of the wrapper chain,
                               "<path>:<line> <display name>", the called wrapper first
                   "origin"    wrapper propagation only: "<path>:<line>" of the body finding
                   "test"      true, only for findings in test files
```

The `additionalContext` JSON is serialised like the document (11.6) but without
indentation. A normaliser therefore needs only `location`, `line` and
`JSON.parse(additionalContext).ruleId` per occurrence, plus the component's properties.

### 11.5 Example

Input (scan root `demo/`):

```
demo/pom.xml                                 bcprov-jdk18on 1.78.1
demo/src/main/java/demo/Crypto.java
   7:  Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
   8:  MessageDigest md = MessageDigest.getInstance(alg);
   9:  SecretKeySpec k = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
  10:  SSLContext ctx = SSLContext.getInstance("TLSv1.2");
demo/tools/test_sign.py
   4:  key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
```

Output (`serialNumber` and `rulesDigest` shortened for the example; all other values are
exact):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:5c1f0d7e-…",
  "version": 1,
  "metadata": {
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "ciphersift",
          "version": "1.0.0"
        }
      ]
    },
    "component": {
      "type": "application",
      "bom-ref": "root",
      "name": "demo"
    },
    "properties": [
      {"name": "ciphersift:rulesDigest", "value": "sha256:9e4…"},
      {"name": "ciphersift:testFiles", "value": "included"},
      {"name": "ciphersift:filesScanned", "value": "3"},
      {"name": "ciphersift:filesSkipped", "value": "0"}
    ]
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "bom-ref": "algorithm:caf89428cf58e2f1",
      "name": "MessageDigest.getInstance",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {"primitive": "hash"}
      },
      "properties": [
        {"name": "ciphersift:ruleId", "value": "java.jca.messagedigest.unresolved"},
        {"name": "ciphersift:language", "value": "java"},
        {"name": "ciphersift:primitive", "value": "hash"}
      ],
      "evidence": {
        "occurrences": [
          {
            "location": "src/main/java/demo/Crypto.java",
            "line": 8,
            "symbol": "java.security.MessageDigest.getInstance",
            "additionalContext": "{\"ruleId\":\"java.jca.messagedigest.unresolved\",\"snippet\":\"MessageDigest.getInstance(alg)\"}"
          }
        ]
      }
    },
    {
      "type": "cryptographic-asset",
      "bom-ref": "related-crypto-material:0cc7bc8e6739667a",
      "name": "Hard-coded symmetric key in Java",
      "cryptoProperties": {
        "assetType": "related-crypto-material",
        "relatedCryptoMaterialProperties": {"type": "secret-key"}
      },
      "properties": [
        {"name": "ciphersift:ruleId", "value": "java.key.hardcoded"},
        {"name": "ciphersift:language", "value": "java"},
        {"name": "ciphersift:assetType", "value": "key-material"},
        {"name": "ciphersift:subtype", "value": "hardcoded-key"}
      ],
      "evidence": {
        "occurrences": [
          {
            "location": "src/main/java/demo/Crypto.java",
            "line": 9,
            "symbol": "javax.crypto.spec.SecretKeySpec",
            "additionalContext": "{\"ruleId\":\"java.key.hardcoded\",\"snippet\":\"new SecretKeySpec(\\\"0123456789abcdef\\\".getBytes(), \\\"AES\\\")\"}"
          }
        ]
      }
    },
    {
      "type": "cryptographic-asset",
      "bom-ref": "protocol:f9c01d353de6ce03",
      "name": "TLS 1.2",
      "cryptoProperties": {
        "assetType": "protocol",
        "protocolProperties": {"type": "tls", "version": "1.2"}
      },
      "properties": [
        {"name": "ciphersift:ruleId", "value": "java.prot.tls.v1_2"},
        {"name": "ciphersift:language", "value": "java"}
      ],
      "evidence": {
        "occurrences": [
          {
            "location": "src/main/java/demo/Crypto.java",
            "line": 10,
            "symbol": "javax.net.ssl.SSLContext.getInstance",
            "additionalContext": "{\"ruleId\":\"java.prot.tls.v1_2\",\"snippet\":\"SSLContext.getInstance(\\\"TLSv1.2\\\")\"}"
          }
        ]
      }
    },
    {
      "type": "cryptographic-asset",
      "bom-ref": "algorithm:ad387c99838b1bb7",
      "name": "AES",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {"primitive": "block-cipher", "algorithmFamily": "AES"}
      },
      "properties": [
        {"name": "ciphersift:ruleId", "value": "java.sym.aes"},
        {"name": "ciphersift:language", "value": "java"},
        {"name": "ciphersift:primitive", "value": "block-cipher"},
        {"name": "ciphersift:family", "value": "AES"}
      ],
      "evidence": {
        "occurrences": [
          {
            "location": "src/main/java/demo/Crypto.java",
            "line": 9,
            "symbol": "javax.crypto.spec.SecretKeySpec",
            "additionalContext": "{\"ruleId\":\"java.sym.aes\",\"snippet\":\"new SecretKeySpec(\\\"0123456789abcdef\\\".getBytes(), \\\"AES\\\")\"}"
          }
        ]
      }
    },
    {
      "type": "cryptographic-asset",
      "bom-ref": "algorithm:310d0bda93ac2b84",
      "name": "AES/GCM/NoPadding",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {"primitive": "block-cipher", "algorithmFamily": "AES", "mode": "gcm"}
      },
      "properties": [
        {"name": "ciphersift:ruleId", "value": "java.sym.aes.gcm"},
        {"name": "ciphersift:language", "value": "java"},
        {"name": "ciphersift:primitive", "value": "block-cipher"},
        {"name": "ciphersift:family", "value": "AES"},
        {"name": "ciphersift:variant", "value": "GCM"}
      ],
      "evidence": {
        "occurrences": [
          {
            "location": "src/main/java/demo/Crypto.java",
            "line": 7,
            "symbol": "javax.crypto.Cipher.getInstance",
            "additionalContext": "{\"ruleId\":\"java.sym.aes.gcm\",\"snippet\":\"Cipher.getInstance(\\\"AES/GCM/NoPadding\\\")\"}"
          }
        ]
      }
    },
    {
      "type": "cryptographic-asset",
      "bom-ref": "algorithm:4a7c8a2e3b5f84f9",
      "name": "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {"primitive": "signature", "parameterSetIdentifier": "2048"}
      },
      "properties": [
        {"name": "ciphersift:ruleId", "value": "python.asym.rsa"},
        {"name": "ciphersift:language", "value": "python"},
        {"name": "ciphersift:primitive", "value": "signature"},
        {"name": "ciphersift:family", "value": "RSA"},
        {"name": "ciphersift:testOnly", "value": "true"}
      ],
      "evidence": {
        "occurrences": [
          {
            "location": "tools/test_sign.py",
            "line": 4,
            "symbol": "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key",
            "additionalContext": "{\"ruleId\":\"python.asym.rsa\",\"snippet\":\"rsa.generate_private_key(public_exponent=65537, key_size=2048)\",\"param\":\"2048\",\"test\":true}"
          }
        ]
      }
    },
    {
      "type": "library",
      "bom-ref": "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1",
      "group": "org.bouncycastle",
      "name": "bcprov-jdk18on",
      "version": "1.78.1",
      "purl": "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1",
      "properties": [
        {"name": "ciphersift:ruleId", "value": "dep.maven"},
        {"name": "ciphersift:ecosystem", "value": "maven"}
      ],
      "evidence": {
        "occurrences": [
          {
            "location": "pom.xml",
            "additionalContext": "{\"ruleId\":\"dep.maven\",\"snippet\":\"org.bouncycastle:bcprov-jdk18on:1.78.1\",\"manifest\":\"pom\"}"
          }
        ]
      }
    }
  ],
  "dependencies": [
    {"ref": "root", "dependsOn": ["pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1"]}
  ]
}
```

(The example is printed with some objects on one line for brevity; real output indents every
object and array element on its own line, 11.6. With `--cyclonedx-version 1.6` the document is
the same except `"specVersion": "1.6"`, no `algorithmFamily` / `ellipticCurve`, and therefore
another `serialNumber`. The RSA component has no `algorithmFamily`: its rule names no scheme.)

### 11.6 Ordering, references and serialisation

* **Components**: all cryptographic components first, sorted by (rule id, name, param, oid —
  none sorts before any value); then library components sorted by (ecosystem, package key,
  version — none first). All string comparisons in this document are by Unicode code points.
* **Occurrences**: sorted by (location, line — absent first, symbol, snippet, then the `via` chain of 18.7 — absent first, then element-wise).
* **Properties**: in the order of the tables above.
* **bom-ref** of a cryptographic component: the CycloneDX asset type, `:`, and the first 16
  lower-case hex digits of SHA-256 over the UTF-8 bytes of the compact JSON array
  `["algorithm",<rule id>,<name>,<param or "">]` — with the oid as a fifth element if the
  component has one (5.11) — or `[<assetType>,<rule id>]` for the
  other asset types (`<assetType>` being the CycloneDX value, so `key-material` rules use
  `related-crypto-material`). If two components of one document would get the same bom-ref,
  both use all 64 hex digits instead. Libraries use their purl.
* **serialNumber**: serialise the document with `serialNumber` omitted; take the SHA-256 of
  those bytes; use the first 16 bytes as a UUID, set the version nibble to 8
  (`byte[6] = (byte[6] & 0x0f) | 0x80`) and the variant bits to `10`
  (`byte[8] = (byte[8] & 0x3f) | 0x80`); write it as `urn:uuid:` + the lower-case 8-4-4-4-12
  form. Then serialise again with `serialNumber` in its place (after `specVersion`).
* **rulesDigest**: SHA-256 over, for each rule file in code-point order of its path relative
  to the rule directory: the path, a NUL byte, the file's bytes, a NUL byte.
* **JSON**: two-space indentation, one key/value or array element per line, `": "` after
  keys, no trailing spaces, `\n` line ends, final newline; strings escape `"`, `\` and
  control characters (`\b \f \n \r \t`, others as `\u00XX`); `/` and non-ASCII characters
  are not escaped; integers in decimal; `true`/`false`. Lone surrogates cannot occur (input
  is decoded with replacement).

---

## 12. Determinism

For the same scan root contents, rule set, options and CipherSift version, the output MUST
be byte-identical, independent of: thread count, file-system enumeration order, file
timestamps, the working directory, locale, default charset, time zone and the absolute
location of the scan root (only its last path segment appears, as `metadata.component.name`).
In particular: no random UUIDs, no timestamps unless `SOURCE_DATE_EPOCH` is set, no
`HashMap` iteration order leaking into output (sort as in 11.6), no locale-sensitive case
conversion (use `Locale.ROOT`).

**File names** are decoded as UTF-8 (malformed bytes → U+FFFD) whatever the locale
*(DECISIONS O1)*. The JVM decodes them with `sun.jnu.encoding`, which follows the locale and
cannot be overridden; when that charset is not UTF-8, an implementation obtains the raw bytes
of names with non-ASCII characters from `Path.toUri()` (which percent-encodes them) and
decodes those. This covers the walk (4.1), the scan root's name, cross-file lookups (7.4.5)
and rule paths. **Command-line arguments**, however, are decoded by the JVM with the
locale's charset before CipherSift sees them; under a non-UTF-8 locale an argument with
non-ASCII bytes (a scan root, `-o` file or `--exclude` glob) cannot be decoded, and
CipherSift then prints a warning. The launcher and the Docker image therefore run the JVM
with `LC_ALL=C.UTF-8` when the current locale is not UTF-8.

---

## 13. Error handling

| Situation | Behaviour |
|---|---|
| File cannot be read (permissions, vanished, I/O error) | warning, file skipped, counted as skipped |
| File larger than 10 MiB | debug message, skipped, counted |
| Binary source file (4.6) | debug message, skipped, counted |
| Invalid UTF-8 | replacement characters (4.4); analysis continues |
| Syntax errors | best-effort analysis (6.2); debug message |
| Exception or stack overflow while analysing one file | warning naming the file, the file's findings are discarded, counted as skipped (`failed`), scan continues |
| Internal failure of wrapper propagation (18) | warning; the propagated findings are omitted, all findings of phase 3 are written |
| Malformed manifest | warning, no entries |
| Cross-file constant file unreadable or unparseable | treated as absent (7.4.5), no warning |
| Native library cannot be loaded | error, exit 1 |
| Java runtime older than 23 | one-line error, exit 6 (section 3) |
| Rule file invalid | error naming file and pointer, exit 4 |
| Output not writable | error, exit 5, no partial file |
| Interrupt (SIGINT) | no output file is written; exit 130 is acceptable |

A finding is never emitted from a file whose analysis failed. If parsing or indexing a file
for wrapper propagation (18.2) fails, the file contributes no definitions and no call sites
(debug message); its findings of phase 3 are kept.

---

## 14. Performance

* **Guideline (non-binding).** Throughput of roughly **9 000 source lines per second** with
  `--threads 1` on a current x86-64 machine, with a maximum heap of 2 GiB, is sufficient: the
  largest benchmark projects (about 1 M lines) then take about 2 minutes. Speed is not an
  acceptance criterion; correctness and determinism come first. There are no targets for
  multi-threaded wall-clock time or start-up time.
* **Design properties** (advice that keeps the guideline easy to meet).
  * Every file is parsed once (cross-file constant files at most once more, then cached).
  * Rules are indexed (7.5, 8.6); per event, only candidate rules are evaluated. Most events
    and calls have no candidates; for them no string list, symbol set or value is computed.
  * Regexes are compiled once at rule loading.
  * String lists, symbol sets and resolution results are computed lazily and at most once
    per event *(advice: memoise per file)*.
  * Trees are closed after each file; only the compact constant contexts (7.4.5) are kept.
  * Workers process files independently; the results are merged and sorted at the end.
  * *(DECISIONS follow-up F3)* A source file in whose text no pattern can fire need not be parsed: every
    anchor compares node texts with literal names of the pattern (the member, the simple class
    name, Python call-name parts, keywords, attribute names), so if, for every pattern, one
    of its required names does not occur in the file's text as a substring, the file's
    findings are empty by construction. Such a file still counts as scanned (11.2.1). The
    output is identical with and without this check. (Bare references, 8.6.1, resolve like
    call names; `kwargs` keywords and `dictItems` keys occur in the text; a member type
    `a.Outer.Inner` is referred to only with `Outer` in the reference or in an import, 7.3.2.)
    A `setup.py` that declares requirements is always parsed (9.8).
    An enabled Java `anyCall` pattern (5.5) has no required name — its strings may be constants of
    other files — so with `java-any-call` on every Java file is parsed *(DECISIONS B-J-SNx)*.
  * *(DECISIONS T9)* Wrapper propagation (18) parses, in addition, only the files that phase 3
    skipped and whose text contains the name of a crypto callable; it keeps per file only the
    definitions and call sites (not the tree), and reads the text of a file again only to cut the
    snippets of its reported calls. Measured cost: section "Wrapper propagation" of
    `IMPLEMENTATION-NOTES.md`.
* **Reference points** (informational). The conformance suite (59 cases, about 140 input files)
  takes about half a second of JVM start-up and scan per case (2026-10-17: about 35 s for all
  cases with `spec/tools/conformance.py`, one JVM per case, on a shared 32-core machine).

---

## 15. Build, packaging and licensing

### 15.1 Project layout

```
pom.xml
LICENSE  NOTICE
bin/ciphersift                         launcher script
Dockerfile
native/
  build-natives.sh                     builds the native libraries (15.3)
  sources.lock                         pinned source URLs + SHA-256
  vendor/                              downloaded, unpacked grammar/core sources (committed)
src/main/java/...                      implementation
src/main/resources/
  META-INF/services/io.github.treesitter.jtreesitter.NativeLibraryLookup
                                       (the repository's rules/ is added as a resource with
                                       target path rules/; there is no copy in src/)
src/test/java/...                      unit tests + conformance runner
target/native/<platform>/*.so|*.dylib|*.dll  built by native/build-natives.sh (15.3), not committed;
                                       packaged into the jar under /native/<platform>/
rules/  spec/                          as delivered
```

### 15.2 Maven build

* Java: `maven.compiler.release` = **23**. jtreesitter 0.26.1 is compiled for Java 23 and
  uses the Foreign Function & Memory API; the minimum runtime is therefore Java 23 (not
  22). Build and test with JDK 25 (`/usr/lib/jvm/jdk-25.0.1` on the reference machine).
* Coordinates: `groupId` **`ch.unibe.seg`**, `artifactId` `ciphersift`, version
  `1.0.0-SNAPSHOT`. Java root package **`ch.unibe.seg.ciphersift`**. All versions below are
  pinned exactly, for a reproducible build.
* Runtime dependencies (all Apache-2.0 or MIT):
  `io.github.tree-sitter:jtreesitter:0.26.1`,
  `com.fasterxml.jackson.core:jackson-databind` and
  `com.fasterxml.jackson.dataformat:jackson-dataformat-yaml` and
  `jackson-dataformat-toml` (all **2.22.3**, managed with `jackson-bom:2.22.3`),
  `info.picocli:picocli:4.7.7` (CLI),
  `com.networknt:json-schema-validator:2.0.4` (rule validation against the schema; the same
  version cyclonedx-core-java 13.2.0 uses, so there is no API clash on the test classpath),
  `org.slf4j:slf4j-api:2.0.17` (declared explicitly, already a dependency of
  json-schema-validator, so that a silent logging provider can be registered).
* Test dependencies: `org.junit.jupiter:junit-jupiter:6.1.3`,
  `org.cyclonedx:cyclonedx-core-java:13.2.0` (output schema validation only; validates
  CycloneDX 1.6 and 1.7 with json-schema-validator 2.0.4, the runtime version above).
* Plugins: `maven-resources-plugin` copies `rules/` and `spec/rule-schema.json` into the jar;
  `exec-maven-plugin` runs `native/build-natives.sh` in `generate-resources` when the
  libraries for the build platform are missing from `target/native/`, and in
  `process-classes` validates the bundled rules in full and records their digest (5.8,
  DECISIONS follow-up F2); `maven-compiler-plugin` compiles the entry-point class for Java 8 (section 3)
  and everything else for Java 23;
  `maven-surefire-plugin` with `--enable-native-access=ALL-UNNAMED`;
  `maven-shade-plugin` produces `target/ciphersift-<version>-all.jar` with manifest entries
  `Main-Class` and `Enable-Native-Access: ALL-UNNAMED`, merging `META-INF/services`;
  `license-maven-plugin` (com.mycila) checks headers (15.5).
* `mvn verify` runs the unit tests and the conformance suite (16).

### 15.3 Native libraries (tree-sitter core and grammars)

jtreesitter does not ship native code. Four shared libraries are needed per platform:

| Library | Source | Exported entry point |
|---|---|---|
| `libtree-sitter` | tree-sitter core **v0.26.10** — the `core` submodule of the `v0.26.1` tag of `tree-sitter/java-tree-sitter` points to commit `3fc4cd2` ("release v0.26.10"). ABI range 13–15 (`TREE_SITTER_MIN_COMPATIBLE_LANGUAGE_VERSION` 13, `TREE_SITTER_LANGUAGE_VERSION` 15). | `ts_*` API |
| `libtree-sitter-java` | `tree-sitter/tree-sitter-java` tag `v0.23.5` (ABI 14) | `tree_sitter_java` |
| `libtree-sitter-python` | `tree-sitter/tree-sitter-python` tag `v0.25.0` (ABI 15) | `tree_sitter_python` |
| `libtree-sitter-go` | `tree-sitter/tree-sitter-go` tag `v0.25.0` (ABI 15; section 17) | `tree_sitter_go` |

**Sources.** `native/sources.lock` lists, for each, the GitHub release tarball URL
(`https://github.com/tree-sitter/<repo>/archive/refs/tags/<tag>.tar.gz`) and its SHA-256.
`native/build-natives.sh fetch` downloads and verifies them and unpacks into
`native/vendor/<repo>/` (e.g. `native/vendor/tree-sitter-java/`; the tag is recorded in
`sources.lock`); the unpacked `src/` directories (core `lib/`) and the MIT
licence files are committed, so a normal build needs no network.

**Compilation** (Linux x86-64, gcc 12; the default and required platform):

```sh
CFLAGS="-O2 -fPIC -std=c11 -fvisibility=hidden -D_DEFAULT_SOURCE"
gcc $CFLAGS -Ivendor/tree-sitter/lib/include -Ivendor/tree-sitter/lib/src \
    -fvisibility=default -shared -o libtree-sitter.so vendor/tree-sitter/lib/src/lib.c
for g in java python go; do
  srcs=vendor/tree-sitter-$g/src/parser.c
  [ -f vendor/tree-sitter-$g/src/scanner.c ] && srcs="$srcs vendor/tree-sitter-$g/src/scanner.c"
  gcc $CFLAGS -fvisibility=default -Ivendor/tree-sitter-$g/src -shared -o libtree-sitter-$g.so $srcs
done
strip --strip-unneeded *.so
```

Output: `target/native/linux-x86_64/` with the four files and a `SHA256SUMS` file; they
are copied into the jar under `/native/linux-x86_64/`. Further platforms (`linux-aarch64`,
`darwin-aarch64`, `darwin-x86_64`, `windows-x86_64`) MAY be added by cross-compiling (e.g.
`zig cc -target …`) in CI and placing the results in `target/native/<platform>/` before
packaging; the fat jar then contains all of them. Platform id: `os.name` mapped to `linux`,
`darwin`, `windows`; `os.arch` mapped `amd64`/`x86_64` → `x86_64`, `aarch64`/`arm64` →
`aarch64`.

**Loading at run time.**

1. Determine the platform id; if the jar has no `/native/<platform>/`, fail with exit 1
   and a message listing the supported platforms.
2. Extract the four files to `$XDG_CACHE_HOME/ciphersift/native/<sha256 of SHA256SUMS>/`
   (default `~/.cache/…`), or, if that is not writable, to a fresh temporary directory
   deleted on exit. Write to a temporary name and rename atomically; verify each file
   against `SHA256SUMS` before use (also when already present).
3. Provide the core library to jtreesitter through its service-provider interface
   `io.github.treesitter.jtreesitter.NativeLibraryLookup` (method
   `SymbolLookup get(Arena arena)`), returning
   `SymbolLookup.libraryLookup(<extracted libtree-sitter path>, arena)`; register it in
   `META-INF/services/io.github.treesitter.jtreesitter.NativeLibraryLookup`.
4. Load each grammar with
   `Language.load(SymbolLookup.libraryLookup(<path>, Arena.global()), "tree_sitter_java")`
   (resp. `tree_sitter_python`, `tree_sitter_go`). The arena must never be closed.
5. Native access must be enabled: the jar manifest's `Enable-Native-Access: ALL-UNNAMED`
   covers `java -jar`; the launcher also passes `--enable-native-access=ALL-UNNAMED`.

`ciphersift --version` prints the CipherSift version, the jtreesitter version, and the ABI
versions of the grammars (`Language.getAbiVersion()`).

### 15.4 Docker

```dockerfile
# syntax=docker/dockerfile:1
FROM maven:3.9-eclipse-temurin-25 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN mvn -B -ntp verify

FROM eclipse-temurin:25-jre
RUN useradd --create-home --uid 10001 ciphersift
COPY --from=build /src/target/ciphersift-*-all.jar /opt/ciphersift/ciphersift.jar
USER ciphersift
ENV XDG_CACHE_HOME=/tmp/ciphersift-cache \
    LC_ALL=C.UTF-8
WORKDIR /scan
ENTRYPOINT ["java", "--enable-native-access=ALL-UNNAMED", "-jar", "/opt/ciphersift/ciphersift.jar"]
CMD ["--help"]
```

Usage: `docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/scan:ro" -v "$PWD/out:/out" ciphersift scan /scan -o /out/cbom.cdx.json`
*(DECISIONS O7)*. `--user` lets the container write into the host's `out/` directory (the
image's own user, uid 10001, usually cannot); the output file gets the permissions of the
umask, so the host user can read it. `LC_ALL=C.UTF-8` keeps non-ASCII command-line
arguments decodable (section 12).

### 15.5 Licensing

* CipherSift is licensed under Apache-2.0; the repository root has `LICENSE` (the licence
  text) and `NOTICE`.
* Every source file (Java, shell, YAML rules, JSON schema, Python tools, Dockerfile, POM)
  starts with:

  ```
  SPDX-License-Identifier: Apache-2.0
  Copyright 2026 The CipherSift Authors
  ```

  in the file type's comment syntax (JSON files carry it in a `description` or `$comment`
  member, or are exempted in the licence-plugin configuration). Conformance input files
  under `spec/conformance/cases/*/input/` are test data and MUST NOT get headers (that would
  shift line numbers); they are excluded from the header check.
* `NOTICE` lists the bundled third-party components and their licences: tree-sitter core,
  tree-sitter-java, tree-sitter-python and tree-sitter-go (MIT; their copyright lines are reproduced),
  jtreesitter (MIT), Jackson, picocli, json-schema-validator (Apache-2.0), SnakeYAML
  (Apache-2.0, via jackson-dataformat-yaml), JSpecify (Apache-2.0, a runtime dependency of
  jtreesitter), and every further transitive dependency that the shade plugin puts into the
  fat jar (check with `mvn dependency:tree`).

---

## 16. Testing and conformance

* **Unit tests** cover at least: glob matching (4.2), test-file detection (4.7), binary
  detection (4.6), text-block decoding (7.4.2), PEP 508 parsing (9.2), purl encoding, bom-ref
  and serial-number computation (11.6), rule-schema validation of every bundled rule.
* **Conformance suite** (`spec/conformance/`, see its README): for each case, run
  `ciphersift scan <case>/input -o <tmp>` with the case's options, convert the CBOM to the
  normalised finding list with the procedure of the README (the reference implementation is
  `spec/tools/conformance.py`), and compare it with `expected.json`. All cases MUST pass.
  The JUnit conformance runner SHOULD implement the same comparison in Java.
* **Schema validation**: every CBOM produced by the conformance runner is validated against
  the CycloneDX 1.7 schema; the runner repeats every case with `--cyclonedx-version 1.6`,
  which MUST give the same normalised findings and a valid CycloneDX 1.6 document (11.1).
* **Determinism test**: scan the conformance cases (also with `--cyclonedx-version 1.6`) with `--threads 1` and `--threads 8`, and
  from two different absolute locations whose last path segment is the same (it is
  `metadata.component.name`); outputs MUST be byte-identical.
* **Wrapper propagation** (18): unit tests of the tokeniser and alias list, the resolution of each
  language, levels and cycles, collisions, folding and the test-file rule; conformance cases
  `java/wrappers`, `python/wrappers`, `python/thin-wrappers` (with the option), `go/wrappers`,
  `go/api-ag`; the determinism test covers them.
* **Rule regex parity**: `spec/tools/regex_parity.py` (optional in CI; requires Python).

---

## 17. Go source analysis *(DECISIONS G1–G16)*

Go support was added after version 1.0 of this specification; it reuses the rule format
(section 5), the normalisation (10) and the CBOM mapping (11) unchanged and adds only what Go
needs. Section numbers 1–16 apply to Go files as to Java and Python files unless this section
says otherwise.

### 17.1 Files

* **Go source**: extension `.go` (4.5, before `pom.xml`). Binary detection (4.6), the size limit
  (4.3) and the pre-filter (14) apply as for the other languages.
* **Test files** (4.7): the directory rule applies unchanged (it already contains Go's
  `testdata`); in addition a file whose base name ends with `_test.go` (case-sensitive, the
  `go test` convention) is a test file *(DECISIONS G12)*.
* **Vendored code**: `vendor/` directories are scanned like any other directory; use
  `--exclude vendor` to skip them (the default is the same as for Java and Python,
  *DECISIONS G13*).
* **Manifests**: `go.mod` and `go.sum` (section 17.10).

### 17.2 Parser

tree-sitter-go **v0.25.0** (ABI 15), built and loaded like the other grammars (15.3; entry
point `tree_sitter_go`, library `libtree-sitter-go`). Error tolerance (6.2) and iterative
traversal (6.3) apply. The node types and fields used are listed in Appendix C.

### 17.3 Go patterns *(DECISIONS G2, G3)*

A Go pattern names Go API members by **import path** and member, written
`<import path>.<Member>` and split at the **last** `.`: `crypto/aes.NewCipher`,
`golang.org/x/crypto/chacha20poly1305.New`, `crypto.SHA256` (package `crypto`). It has exactly
one anchor:

| Anchor | Value | Fires on |
|---|---|---|
| `call` | `path.Member`; the member may end with `*` (prefix), and `path.*` names every member | A call event (17.5) whose name (17.4) equals the value (or starts with it, for `*`). A `call` pattern **without** `anySymbol` also fires on a reference event with such a name: `hmac.New(sha256.New, key)` uses SHA-256 *(DECISIONS G5)*. |
| `ref` | as `call` | A reference event (17.5) only: a constant, variable or function used as a value (`tls.VersionTLS12`, `crypto.SHA256`, `rand.Reader`). |
| `composite` | `path.Type` (no `*`) | A composite-literal event (17.5): `tls.Config{…}`, `&rsa.PSSOptions{…}`, `new(tls.Config)`. |
| `assign` | a field name | A field-assignment event (17.5): the keyed element `InsecureSkipVerify: true` of any composite literal, or the assignment `cfg.InsecureSkipVerify = true`. |
| `method` | `path.Type.Method` (split at the last two `.`; no `*`) | A method event (17.12): a call `r.Method(…)` whose receiver `r` has the known type `path.Type` *(DECISIONS B-G-B1a)*. Takes no `anySymbol` and no `param: {self}`; `param: {index}` and `{value}` work as for `call`. |

Conditions:

| Key | Value | Allowed with | Holds when |
|---|---|---|---|
| `anySymbol` | list of `path.Member` names (no `*`) | call, composite | Some listed name equals a name of the event's symbol set (17.7). |
| `value` | regex | assign | The regex is found (`find`, case-insensitive) in one of the value texts (17.7) of the assigned expression. |
| `valueContains` | list | assign | Some value text contains some listed string (case-insensitive). |
| `param` | `{index: i}` (call, method), `{self: true}` (not method) or `{value: s}` | call, ref, composite, method | *Not a filter.* The finding's param (17.8). |

A pattern with `anySymbol`, `value` or `valueContains` is **specific** (specificity 2); every
other pattern is **bare** (1). `*` prefixes are allowed only in `call` and `ref` anchors.

The rule schema has a `goPattern` branch for `language: go`; source-rule ids start with `go.`.
Semantic check (5.8) in addition to the schema: the import path before the last `.` is not
empty. The bundled rules live in `rules/go/`; there is no Go constants document (Go constants are
resolved from the source only, 17.6).

### 17.4 Imports and names *(DECISIONS G4)*

One walk over the whole tree collects the `import_spec`s of the file (in any position, also
inside `ERROR` nodes). The **path** of a spec is the content of its `path` string literal,
without the quotes and without interpreting escape sequences (import paths are plain ASCII in
practice; a path written with escapes is not recognised). The spec's **local name** is:

* the text of its `name` field if that is a `package_identifier`;
* for `name` `.` (dot import): no local name; the path is appended to the file's *dot paths*;
* for `name` `_` (blank import): nothing (the import has no effect on names);
* without `name`: the last `/`-segment of the path; if that segment is a major-version suffix
  `v2`, `v3`, … (`^v[0-9]+$`) and there is a segment before it, that previous segment
  (`math/rand/v2` → `rand`, `github.com/golang-jwt/jwt/v5` → `jwt`); a trailing `.vN` of the
  segment is removed (`gopkg.in/yaml.v3` → `yaml`). (Go takes the name from the package clause
  of the imported package, which a scanner cannot see; these are the naming conventions of
  every package the bundled rules name.)

A later spec with the same local name replaces an earlier one. The **declared names** of the
file are the texts of every `identifier` that is the `name` of a `function_declaration`,
`var_spec`, `const_spec`, `parameter_declaration` or `variadic_parameter_declaration`, every
`identifier` in the `left` list of a `short_var_declaration` or `range_clause`, and every
`type_identifier` that is the `name` of a `type_spec` or `type_alias`.

**Name of a qualified selector.** A `selector_expression` whose `operand` is an `identifier`
*X* that is a local name of an import with path *P* has the single name *P*`.`*F*, *F* being
the text of its `field`. (A local variable cannot shadow an import that the same scope uses,
so no scope check is made.)

**Name of an unqualified identifier.** An `identifier` *N* that starts with an upper-case letter
(only exported names are visible through a dot import), is not a declared name of the file and
is not a local name of an import has, for each dot path *P* in order, the name *P*`.`*N*; without
dot imports it has no name. (Declared names are file-wide: a local variable named like a member of
a dot-imported package hides that member in the whole file.)

**Type names.** A `qualified_type` (`package` *X*, `name` *T*) has the name *P*`.`*T* if *X* is
a local name of path *P*; a `type_identifier` *T* gets dot-import names like an identifier.

### 17.5 Events

One pre-order walk enumerates the events of the file (import declarations are not walked):

| Event | Node | Names | Line | Snippet |
|---|---|---|---|---|
| call | `call_expression` whose `function` is a qualified selector or an unqualified identifier with names (17.4) | the function's names | row of the selector's `field` + 1, else start row + 1 | the call text |
| composite | `composite_literal` whose `type` is a `qualified_type` or `type_identifier` with names; and a call of the identifier `new` (not a declared name) whose single argument is a `qualified_type`, or a qualified selector, with names | the type's names | start row + 1 | the node text |
| reference | a qualified selector, or an unqualified identifier with names, that is not the `function` of a `call_expression`, not the type argument of a `new` composite event, not the expression of the `key` of a `keyed_element` (a struct field name or a map key), and not in a *test position* | its names | row of the `field` + 1 for a selector, else start row + 1 | the node text |
| assign | a `keyed_element` whose `key` is a `literal_element` holding a single `identifier` (the field name); an `assignment_statement` with operator `=` for each position *i* whose left element is a `selector_expression` (field name = its `field`), when left and right have the same number of elements (value = right element *i*) | – | start row + 1 | the node text |

**Test positions** *(DECISIONS G6)*: walking up from the reference through
`parenthesized_expression` and `unary_expression`, the walk reaches the `left` or `right` of a
`binary_expression` whose operator is `==`, `!=`, `<`, `<=`, `>` or `>=`, or an
`expression_list` that is the `value` of an `expression_case`. Such a reference compares a
value obtained elsewhere (`if state.Version == tls.VersionTLS10`, `case tls.VersionTLS12:` in a
version-name table); it does not choose an algorithm.

Snippets are truncated to 500 code points.

### 17.6 Constant resolution *(DECISIONS G7)*

**Scopes and bindings.** The *function scopes* are the `function_declaration`,
`method_declaration` and `func_literal` nodes; the file is the outermost scope. Block scopes inside a function are not
distinguished; resolution is flow-insensitive within a function.

*Declarations* bind in the innermost function scope that contains them:

* `const_spec` and `var_spec`: each `name` *nᵢ*; its value is element *i* of the `value`
  list if the list has as many elements as there are names, the single element if the list has
  one element (a multi-value call), and none otherwise (also without a value list, and for the
  implicit repetition of a `const` group);
* `short_var_declaration`: each `identifier` *nᵢ* of `left`, with the value paired from `right`
  in the same way;
* an identifier in the `left` of a `range_clause` with `:=`, and every parameter, receiver and
  named result (`parameter_declaration` / `variadic_parameter_declaration` names of the
  scope's `parameters`, `receiver`, `result`): a binding without value.

*Assignments* — an `assignment_statement` with operator `=` (each `identifier` of `left`, value
paired from `right` as above), one with another operator, an `inc_statement` /
`dec_statement` of an identifier and a `range_clause` with `=` (bindings without value) — bind
the variable where it is declared: in the innermost scope, from the assignment's function
scope outwards, that has a declaration of the name, else in the file scope. So `bits = 4096`
inside `init()` makes the package variable `bits` non-constant.

`bindings(N, x)`: starting at the innermost function scope of node *x* and moving outwards, the
bindings of `N` in the first scope that has any.

**Values.** `value(e, d)` (string or unresolved; unresolved when `d > 12`):

| Node | Value |
|---|---|
| `interpreted_string_literal` | its content with escapes decoded (`\a \b \f \n \r \t \v \\ \' \"`, `\xHH`, `\ooo`, `\uHHHH`, `\UHHHHHHHH`; an invalid escape keeps its text); a string |
| `raw_string_literal` | its content without carriage returns; a string |
| `int_literal` | decimal notation only (`[1-9][0-9_]*` or `0`): the text without `_`; a number |
| `true`, `false` | the text |
| `parenthesized_expression` | value of its expression |
| `binary_expression` `+` | both operands resolve **to strings**: their concatenation; otherwise unresolved |
| `identifier` | `bindings(N, e)`: if there is at least one and every binding has a value and all of these values resolve to the same result, that result; otherwise unresolved |
| anything else | unresolved (other packages' constants, `iota`, conversions, calls, …) |

So a `const`, or a variable assigned exactly once, is resolved; a variable assigned twice with
different values, a parameter, or a variable without initialiser is not.

**Bound names.** `boundNames(N, x, d)` (empty when `d > 12`; cycle guard as in 8.4.1): for each
binding of `bindings(N, x)` with a value *v*: the names of *v* if it is a call event's call
(its function's names), a qualified selector or an unqualified identifier with names, or a
composite literal or `&` of one (its type's names); `boundNames` of *v* if it is another
identifier. Example: `block, err := aes.NewCipher(key)` gives `block` (and `err`) the bound
name `crypto/aes.NewCipher`.

### 17.7 Symbol sets and value texts

`collect(e, d)` (stops when `d > 6`):

* qualified selector: add its name; any other `selector_expression`: `collect(operand)`;
* `identifier`: add its names (dot imports) and `boundNames`;
* `call_expression`: add the function's names; `collect` the function if it is neither a
  qualified selector nor an identifier; `collect` every argument;
* `composite_literal`: add the type's names; `collect` the body;
* `func_literal`, string and number literals, comments: nothing;
* anything else: `collect` every named child.

The **symbol set** of a call event is the union of `collect(a, 0)` over its arguments; of a
composite event, `collect(body, 0)`. Example: `cipher.NewGCM(block)` after the binding above has
the symbols `crypto/aes.NewCipher` (from `block`).

The **value texts** of an assigned expression *e*: its text; its value (17.6), if resolved; its
names if it is a qualified selector or identifier, the function's names if it is a call.

### 17.8 Selection, nesting and findings

For each event: the candidate patterns are those whose anchor fires on the event (17.3); a rule
matches if one of its candidate patterns holds (all conditions). Selection is that of Java
(7.7.1): the rule's specificity is the highest of its holding patterns, its chosen pattern the
first holding one with that specificity; per asset `type`, only the rules with the group's
maximum specificity are kept. Then nested duplicates are dropped as in 7.7.2, with the Go
expression ancestors `argument_list`, `call_expression`, `parenthesized_expression`,
`unary_expression`, `composite_literal`, `literal_value`, `literal_element`, `keyed_element`
*(DECISIONS G8)*: `ecdsa.GenerateKey(elliptic.P256(), rand.Reader)` is one ECDSA finding (the
inner EC curve has the same family) plus the CSPRNG (no family); `cipher.NewGCM(` … `aes.NewCipher(k)` … `)`
written inline is AES-GCM only.

Each kept (event, rule) pair yields one finding:

| Field | Value |
|---|---|
| line, snippet | 17.5 |
| name, symbol | the first name of the event (in the order of 17.4) that made the chosen pattern's anchor fire; assign events: the field name |
| param | 17.9 |

The component name of an algorithm finding is therefore the qualified name of the API
(`crypto/aes.NewCipher`, `crypto/tls.VersionTLS12`), as for Python (10.2).

### 17.9 Parameters *(DECISIONS G9)*

* `{value: s}`: *s*.
* `{self: true}`: the member of the name used (`crypto/elliptic.P256` → `P256`), mapped as below.
* `{index: i}` (call events): argument *i*, if present: its value (17.6) if resolved;
  otherwise its *candidates* — the names of a qualified selector, identifier (dot imports) or
  call; the bound names of an identifier; the type names of a composite literal or `&` of one —
  and the param is the mapped member of the first candidate.

*Mapping a member through the rules*: if some Go pattern of the loaded rule set
has a `call` or `ref` anchor equal to the candidate's full name and a `param: {value: v}`, the
param is *v* (the first such pattern in rule-id and file order); otherwise it is the member.
The curve functions carry their standard names this way: `call: crypto/elliptic.P256` has
`param: {value: P-256}`, so `ecdsa.GenerateKey(elliptic.P256(), rand.Reader)` reports `P-256`,
which table 11.3.1b maps to `nist/P-256`. A param that is a table OID is replaced by its name
(5.11).

### 17.10 Go module manifests *(DECISIONS G10, G11)*

Ecosystem **`golang`**; the package key is the module path as written (case preserved; rule
matching is case-insensitive, 5.9). Manifest labels `go-mod` and `go-sum`.

* **go.mod**: lines (LF; a trailing CR removed); `//` starts a comment to the end of the line.
  A line `require PATH VERSION`, or each line `PATH VERSION` inside a `require (` … `)` block,
  is an entry. An entry whose comment is `indirect` (after `//`, blanks allowed, then the end of the
  line or `;` and more text) is **transitive**: since Go 1.17 the go command lists in `go.mod` every
  module the build needs, and marks with `// indirect` those that no package of the main module imports
  (https://go.dev/ref/mod#go-mod-file-require). Transitive entries are not reported unless
  `--transitive-deps` is given (3.1) *(DECISIONS B-G1)*; within one file the last entry of a path
  decides, its marker included. `PATH` may be quoted with `"…"` or `` `…` ``. All other directives and blocks
  (`module`, `go`, `toolchain`, `replace`, `exclude`, `retract`, `tool`, `godebug`, …) are
  ignored; replacements are not applied.
* **go.sum** (a lock file, read only with `--transitive-deps`, *DECISIONS B-G2*): each line `PATH VERSION HASH` is an entry, except lines whose `VERSION` ends with
  `/go.mod` (only the module's `go.mod` was needed by version selection; the module's code is not
  part of the build).

Within one file the last entry of a path determines the version (section 9). Snippet:
`PATH@VERSION`. Library components (11.3.5): `name` = the module path, no `group`, `version`,
`purl` = `pkg:golang/` + the `/`-separated segments of the path, each percent-encoded as in
11.3.5, joined by `/`, + `@` + the encoded version; properties `ciphersift:ruleId`,
`ciphersift:ecosystem` (`golang`). The bundled rule `rules/dependencies/dep.golang.yaml` lists
Go cryptographic modules (`golang.org/x/crypto`, `filippo.io/age`, `github.com/cloudflare/circl`,
…).

### 17.12 Methods on receivers of a known type *(DECISIONS B-G-B1a, benchmark-informed)*

Go code calls most cryptographic operations as methods of key, curve, certificate and signer values
(`priv.Sign(…)`, `pool.AddCert(c)`, `curve.ScalarMult(…)`). Where the receiver's type can be read from
the file, such a call is a **method event**; `method` patterns (17.3) match it. Feature
`go-typed-methods` (3.1, default on).

* **Method event.** A `call_expression` whose `function` is a `selector_expression` that is not a
  qualified selector (17.4); its names are `T.M` for the receiver type `T` (below) and the `field` `M`.
  If the type is a struct type declared in the file (`#S` below) that has no method `M` declared in the
  file, the names are `E.M` for each embedded field of `S` whose type is a qualified type `E` (one level
  of promotion). Line: the row of the `field` + 1; snippet: the call text. Selection, nesting (17.8),
  findings and params are those of call events; the name used is `path.Type.Method`.
* **Type names**: a `qualified_type` `p.T` (pointer, parentheses and type arguments removed) whose package
  `p` is a local import name of path *P* has the name *P*`.T`; a `type_identifier` that names a struct
  type declared in the file has the name `#T`; other types have none.
* **Receiver type** of an expression (depth limit 12, cycle guard as in 17.6):
  * parentheses, `&x` and `*x`: the type of `x`;
  * a `type_assertion_expression` `x.(T)`, a composite literal `T{…}`: `T`;
  * a call: `new(T)` → `T`; a qualified function or a method event listed in the **result-type table**
    (below) → its result type at the position asked for (0 unless several names take the results of one
    call, `pub, priv, err := ed25519.GenerateKey(nil)`);
  * a selector `x.f` that is not qualified: if `x` has a struct type `#S` of the file with a field `f`,
    the type of that field;
  * an identifier `x`: if it is the alias of a `type_switch_statement` and lies inside a `type_case` that
    lists exactly one type, that type; otherwise its bindings (17.6) — the declared type of a parameter,
    receiver or `var`, else the receiver type of the bound value at its result position — which must all
    give the same type; a binding without either (a range variable, `x = nil`, a call not in the table)
    gives none.
* **Result-type table** (from the pkg.go.dev documentation; `lang/go/GoResultTypes.java`): `crypto/rsa`
  `GenerateKey`, `GenerateMultiPrimeKey` → `PrivateKey`; `crypto/ecdsa` `GenerateKey`,
  `ParseRawPrivateKey` → `PrivateKey`, `ParseUncompressedPublicKey` → `PublicKey`, `PrivateKey.ECDH` /
  `PublicKey.ECDH` → `crypto/ecdh` keys; `crypto/ed25519` (and `golang.org/x/crypto/ed25519`)
  `GenerateKey` → (`PublicKey`, `PrivateKey`), `NewKeyFromSeed` → `PrivateKey`; `crypto/elliptic`
  `P224`…`P521` → `Curve`; `crypto/ecdh` `P256`, `P384`, `P521`, `X25519` → `Curve`, `Curve.GenerateKey`,
  `Curve.NewPrivateKey` → `PrivateKey`, `Curve.NewPublicKey`, `PrivateKey.PublicKey` → `PublicKey`;
  `crypto/mlkem` `GenerateKey768/1024`, `NewDecapsulationKey768/1024` → `DecapsulationKey768/1024`,
  `NewEncapsulationKey768/1024`, `DecapsulationKey…EncapsulationKey` → `EncapsulationKey768/1024`;
  `crypto/x509` `ParseCertificate` → `Certificate`, `ParseCertificateRequest`, `ParseRevocationList`,
  `NewCertPool`, `SystemCertPool` → `CertPool`, `ParsePKCS1PrivateKey` / `ParsePKCS1PublicKey` → `crypto/rsa`
  keys, `ParseECPrivateKey` → `crypto/ecdsa.PrivateKey`; `golang.org/x/crypto/ssh` `NewSignerFromKey`,
  `NewSignerFromSigner`, `ParsePrivateKey[WithPassphrase]` → `Signer`, `ParsePublicKey`, `NewPublicKey`,
  `ParseAuthorizedKey`, `Signer.PublicKey` → `PublicKey`; sigstore `signature.GetAlgorithmDetails` →
  `AlgorithmDetails`.
* **Bundled method anchors**: `crypto/rsa.PrivateKey` `Sign`, `Decrypt`, `Precompute`, `Validate`, `Public`
  (RSA); `crypto/ecdsa.PrivateKey` `Sign`, `Public`, `ECDH` and `PublicKey.ECDH` (ECDSA); `crypto/ed25519`
  (also x/crypto) `PrivateKey` `Sign`, `Public`, `Seed` (Ed25519); `crypto/elliptic.Curve` `ScalarMult`,
  `ScalarBaseMult`, `Add`, `Double`, `IsOnCurve` (EC); `crypto/ecdh.PrivateKey.ECDH` (ECDH),
  `Curve.NewPublicKey`, `PrivateKey.PublicKey` (public key), `Curve.NewPrivateKey`, `Curve.GenerateKey`
  (private key); `crypto/mlkem` `DecapsulationKey768/1024` `Decapsulate`, `EncapsulationKey` and
  `EncapsulationKey768/1024.Encapsulate` (ML-KEM, parameter set); `crypto/x509` `Certificate` `Verify`,
  `CheckSignature`, `CheckSignatureFrom`, `CheckCRLSignature`, `VerifyHostname`,
  `CertificateRequest.CheckSignature`, `CertPool` `AddCert`, `AppendCertsFromPEM`,
  `RevocationList.CheckSignatureFrom` (X.509); `golang.org/x/crypto/ssh` `Signer.Sign`, `PublicKey.Verify`,
  `AlgorithmSigner` / `MultiAlgorithmSigner` `SignWithAlgorithm`, `CertChecker` `Authenticate`,
  `CheckHostKey`, `CheckCert`, `Certificate.SignCert`, `ServerConfig.AddHostKey` (SSH). Accessors
  (`Params`, `Equal`, `Size`, `BlockSize`, `Overhead`, `NonceSize`, `HashFunc`, `String`, …) are not anchors.
* Not covered: types of other files (a struct declared elsewhere in the package), interfaces satisfied
  implicitly, generic instantiation, chained promotion over more than one level, method values
  (`f := k.Sign`).

### 17.11 Go coverage of the bundled rules *(DECISIONS G14, G15)*

`rules/go/` (70 source rules; `go.pqc.slhdsa` added by DECISIONS B-G-B2) covers the Go standard library `crypto/...` packages
(`aes`, `cipher` modes, `des`, `rc4`, `rsa`, `dsa`, `ecdsa`, `ecdh`, `elliptic`, `ed25519`,
`hmac`, `md5`, `sha1`, `sha256`, `sha512`, `sha3`, `hkdf`, `pbkdf2`, `mlkem`, `rand`, `tls`,
`x509`, the `crypto.Hash` constants; Go 1.25 `ecdsa.ParseRawPrivateKey` /
`ParseUncompressedPublicKey`, Go 1.26 `rsa.EncryptOAEPWithOptions` and `hpke`, Go 1.27 `mldsa`
and the `tls.MLDSA*` signature schemes *(DECISIONS F4–F6)*) and `golang.org/x/crypto` (`chacha20`, `chacha20poly1305`,
`poly1305`, `salsa20`, `nacl/box`, `nacl/secretbox`, `nacl/sign`, `nacl/auth`, `curve25519`,
`ed25519`, `scrypt`, `argon2`, `bcrypt`, `hkdf`, `pbkdf2`, `sha3`, `blake2b`, `blake2s`, `md4`,
`ripemd160`, `blowfish`, `cast5`, `twofish`, `xts`, `pkcs12`, `ssh`), and `math/rand` /
`math/rand/v2` as a weakness indicator. Not covered: `golang.org/x/crypto/openpgp` (deprecated;
no fitting CycloneDX asset), third-party APIs (JWT, JOSE, age, circl — their modules are reported
through `go.mod`; the exception is `filippo.io/hpke`, whose API is that of `crypto/hpke`), method calls on values whose type is not known (`key.Sign(…)`, `aead.Seal(…)`;
receiver types are not inferred), and algorithm names in strings (`ssh.Config{Ciphers: […]}`).

**Third-party APIs** *(DECISIONS T11, benchmark-informed)*: package functions and values of
selected libraries, written from their pkg.go.dev documentation and filed under the existing rules
(two new rules, `go.asym.ed448` and `go.asym.x448`, mirror the Python ones):

| Package | Members | Rule |
|---|---|---|
| `filippo.io/age` | `Encrypt`, `EncryptReader`, `Decrypt`, `DecryptReaderAt` (the format's payload AEAD) | `go.sym.chacha20poly1305` |
| | `NewScryptIdentity`, `NewScryptRecipient` | `go.kdf.scrypt` |
| | `GenerateX25519Identity`, `ParseX25519Identity`, `ParseX25519Recipient` | `go.asym.x25519` |
| | `GenerateHybridIdentity`, `ParseHybridIdentity`, `ParseHybridRecipient` (ML-KEM-768 + X25519) | `go.pqc.mlkem` (ML-KEM-768) |
| `filippo.io/age/agessh` | `NewEd25519Identity`, `NewEd25519Recipient` / `NewRSAIdentity`, `NewRSARecipient` / `ParseIdentity`, `NewEncryptedSSHIdentity` / `ParseRecipient` | `go.asym.ed25519` / `go.asym.rsa` / `go.key.load.private` / `go.key.load.public` |
| `github.com/sigstore/sigstore/pkg/cryptoutils` | certificate PEM functions, `ParseCSR` / PEM key (un)marshalling / `GeneratePEMEncodedECDSAKeyPair` (curve as parameter), `GeneratePEMEncodedRSAKeyPair` (bits) / `SKID` | `go.cert.x509` / `go.key.load.*` / `go.asym.ecdsa`, `go.asym.rsa` / `go.hash.sha1` |
| `crypto/x509` | `MarshalPKCS1PrivateKey`, `MarshalPKCS8PrivateKey`, `MarshalECPrivateKey` / `MarshalPKIXPublicKey`, `MarshalPKCS1PublicKey` | `go.key.load.private` / `go.key.load.public` |
| `github.com/secure-systems-lab/go-securesystemslib/encrypted` | `Encrypt`, `Decrypt`, `Marshal`, `Unmarshal` and the `…WithCustomKDFParameters` variants (scrypt + NaCl secretbox) | `go.kdf.scrypt` and `go.sym.nacl.secretbox` |
| `github.com/google/go-containerregistry/pkg/v1` | `SHA256` | `go.hash.sha2` |
| `github.com/cloudflare/circl` (call anchors only) | `sign/mldsa/mldsa44/65/87`, `kem/mlkem/mlkem512/768/1024` (parameter set), `sign/ed25519`, `sign/ed448`, `dh/x25519`, `dh/x448` package functions | `go.pqc.mldsa`, `go.pqc.mlkem`, `go.asym.ed25519`, `go.asym.ed448`, `go.asym.x25519`, `go.asym.x448` |
| `github.com/flynn/noise` (values) | `CipherAESGCM` / `CipherChaChaPoly` / `DH25519` / `HashSHA256`, `HashSHA512` / `HashBLAKE2b`, `HashBLAKE2s` | `go.sym.aes.gcm` / `go.sym.chacha20poly1305` / `go.asym.x25519` / `go.hash.sha2` / `go.hash.blake2` |
| `github.com/miekg/pkcs11` | `CKM_ECDSA*` | `go.asym.ecdsa` |
| `…/keyvault/azkeys` | `EncryptionAlgorithmRSA15` / `RSAOAEP`, `RSAOAEP256` / `SignatureAlgorithmRS*` / `PS*` / `KeyTypeRSA`, `KeyTypeRSAHSM` | `go.asym.rsa.pkcs1v15.encrypt` / `go.asym.rsa.oaep` / `go.asym.rsa.pkcs1v15.sign` / `go.asym.rsa.pss` / `go.asym.rsa` |
| `github.com/sigstore/protobuf-specs/gen/pb-go/common/v1` (values; *DECISIONS B-G-B2*) | `PublicKeyDetails_PKIX_ECDSA_*` (curve as param) / `…RSA_PKCS1V5`, `…RSA_PKCS1V15_*` / `…RSA_PSS*` / `…PKIX_ED25519[_PH]` / `…ML_DSA_44/65/87` / `HashAlgorithm_SHA2_*` / `HashAlgorithm_SHA3_*` | `go.asym.ecdsa` / `go.asym.rsa.pkcs1v15.sign` / `go.asym.rsa.pss` / `go.asym.ed25519` / `go.pqc.mldsa` / `go.hash.sha2` / `go.hash.sha3` |
| `github.com/sigstore/sigstore/pkg/signature[/options]` (B-G-B2) | `options.WithED25519ph` / methods `AlgorithmDetails.GetECDSACurve` / `GetRSAKeySize` (17.12) | `go.asym.ed25519` / `go.asym.ec` / `go.asym.rsa` |
| `github.com/go-piv/piv-go[/v2]/piv` (B-G-B2) | `AlgorithmEC256`, `AlgorithmEC384` (curve) / `AlgorithmRSA1024…4096` (bits) / `AlgorithmEd25519` / `AlgorithmX25519` / `Verify` (attestation certificate chain) | `go.asym.ec` / `go.asym.rsa` / `go.asym.ed25519` / `go.asym.x25519` / `go.cert.x509` |
| `github.com/cloudflare/circl/sign/slhdsa` (B-G-B2) | the twelve FIPS 205 parameter-set identifiers `SHA2_128s` … `SHAKE_256f` (param `SLH-DSA-…`), `GenerateKey` (param from argument 1) | `go.pqc.slhdsa` (new rule) |

The `go-containerregistry` package is named `v1`; it is recognised only when imported with that
explicit name (17.4 skips a `vN` segment); the same holds for protobuf-specs' `common/v1` package (any
explicit import name works). Methods of these libraries' types (`identity.Unwrap`,
`scheme.Sign`) are not anchors (receiver types are not inferred).

**Key construction** *(DECISIONS F4)*: as the Java `*KeySpec` constructors and the Python
`*Numbers` classes are reported, the Go key types are reported where a key is built from its
parts: the composites `rsa.PrivateKey`, `rsa.PublicKey`, `ecdsa.PrivateKey`, `ecdsa.PublicKey`
(also `new(…)`) in the RSA and ECDSA rules, `elliptic.CurveParams` (a curve defined by its
parameters) in `go.asym.ec`, and the conversions `ed25519.PublicKey(b)` / `ed25519.PrivateKey(b)`
(call events, 17.5) in `go.asym.ed25519`. Types in declarations, type assertions and type
switches are not events.

**HPKE** *(DECISIONS F5)*: `crypto/hpke` and `filippo.io/hpke` are reported through their KEM,
KDF and AEAD identifiers, which name the algorithms: `DHKEM(curve)` as ECDH (with the curve as
parameter) or X25519 (`anySymbol` of the curve), `MLKEM768…`/`MLKEM1024…` as ML-KEM with the
parameter set (the hybrid KEMs under ML-KEM only, like the TLS hybrid groups), `HKDFSHA*` as HKDF
and SHA-2, `SHAKE128`/`SHAKE256` as SHA-3, `AES128GCM`/`AES256GCM` as AES-GCM, `ChaCha20Poly1305`
as ChaCha20-Poly1305. `Seal`, `Open`, `NewSender`, `NewRecipient` and the key wrappers take these
identifiers or keys as arguments and are not anchors; `ExportOnly` and the `New*(id)` lookups name
no algorithm.

**Primitive of EC keys** *(DECISIONS F1)*: the rules for EC key generation, construction and
curves (`java.asym.ec`, `python.asym.ec`, `python.asym.secp256k1`, `go.asym.ec`) declare no
primitive: a key or curve is used for signatures and key agreement alike. ECDSA and ECDH are
reported by the rules for those operations.

---

## 18. Wrapper propagation *(DECISIONS T1–T14, benchmark-informed)*

A project often reaches a cryptographic API through its own small functions (`Hash.sha3(x)`,
`sha256(x)`, `hmacSha512(k, d)`, `newAESGCM(k)`). Sections 7, 8 and 17 report the API call inside
such a function once; its call sites are not reported. *Wrapper propagation* reports them: a
project function whose body already yields a finding, and which is a *crypto callable* by the
criteria below, makes each call that resolves to it an occurrence of the body finding's component,
with the wrapper chain recorded in the occurrence (11.4).

It is a separate pass after extraction (phase 3) and before normalisation (phase 4), with this
contract: **input** the findings of phase 3 and the syntax trees of the project's source files;
**output** additional source findings, each saying "this call reaches callable *X*, which carries
family *F*; evidence: the chain *X* → … → the finding at *path:line*". It never removes or changes a
finding of phase 3. It works within one language (a Java call never reaches a Python function) and
only within the scan root.

| Component | Java | Python | Go |
|---|---|---|---|
| Name-consistent wrappers (W7, 18.5) | on | on | on |
| Thin wrappers (W6, 18.5) | on (12 lines) | off; on with `--python-thin-wrappers` | on, 12 lines, with the fallback-getter guard *(DECISIONS B-G-E; T14 had it off)* |

### 18.1 Terms

* **Family key** of a finding: the rule's `family` if it has one, else its `subtype` (e.g. `x509`),
  else the rule id. Two findings have the same family key if the strings are equal.
* **Propagatable finding**: a finding of phase 3 that is in the output (after the weakness-indicator
  filter of 3.1), whose rule has no `indicator`, and whose rule's subtype is not `prng-secure` (a
  random-number call in a helper does not make the helper a cryptographic algorithm) — except in Java,
  where `prng-secure` findings are propagatable *(DECISIONS B-J-D; not with
  `--feature java-propagate-random=off`)*: a Java helper that only returns a `SecureRandom` is a thin
  wrapper of the CSPRNG; a helper with a CSPRNG and another family is no longer a thin wrapper.
* **Definition**: a function or method declaration of the project (18.2). Its **span** is the
  lines from the row of its name to its last row, inclusive; its **body findings** are the
  propagatable findings whose file is the definition's file and whose line lies in the span, and for
  which this definition is the innermost one (the one with the greatest start line; equal start
  lines: the more deeply nested declaration).
* **Name families** of a definition: the family keys its name names by the tokeniser (18.6).

### 18.2 Definition index

Every source file of the language that is scanned contributes its definitions:

| Language | Definition | Owner | Addressable as |
|---|---|---|---|
| Java | `method_declaration` (with a name; with or without body) | the chain of enclosing `class_declaration`, `interface_declaration`, `enum_declaration`, `record_declaration` names; package from `package_declaration` | `pkg.Outer.Inner#m/arity` — not for methods of anonymous classes or of classes declared inside a method body |
| Python | `function_definition` (also inside `decorated_definition`) | the module (relative path without `.py`, `/` → `.`, a trailing `.__init__` removed) and, for a method, the enclosing `class_definition` | module-level functions; methods of module-level classes — not nested functions |
| Go | `function_declaration`, `method_declaration` | the package: (directory of the file, package name of its `package_clause`); for a method also the receiver's type name (pointer and type arguments removed) | always |

Constructors (Java `constructor_declaration`, Python classes and `__init__`, Go composite literals)
are not definitions. Arity of a Java method: the number of formal parameters; a method with a
variable-arity parameter accepts any number ≥ arity − 1.

**Files read for the index.** The source files parsed by phase 3 contribute directly. A file that
phase 3 did not parse (pre-filter, 14) contributes if its text contains an identifier (a maximal run
of `[A-Za-z0-9_$]` not starting with a digit) equal to the name of a crypto callable found so far;
or, for Java, equal to the simple name of a class enclosing such a callable; it is then parsed and
indexed, and the computation of 18.5 is repeated until no new name appears. Every call of a
callable and every other definition with the same name contains that name, a same-named class that
could shadow the callable's class contains the class name, and Python module names are known for
all files; so the result equals that of indexing every file *(DECISIONS T9)*.

### 18.3 Call sites

| Language | Call site | Line | Symbol |
|---|---|---|---|
| Java | `method_invocation` without object, with object `this`, or with an `identifier`, `field_access` or `scoped_identifier` object | row of `name` + 1 | object text (whitespace removed) + `.` + name, or the name |
| Python | `call` whose `function` is an `identifier` or an `attribute` chain of identifiers (`a.b.f`) | row of the last `attribute` identifier + 1, else start row + 1 | the function text without whitespace |
| Go | `call_expression` whose `function` is an `identifier`, or a `selector_expression` whose operand is an `identifier` or a `selector_expression` of an `identifier` (`x.f.M`) | row of the selector's `field` + 1, else start row + 1 | the function text without whitespace |

The snippet is the text of the call node (at most 500 code points). A call site belongs to the
innermost definition whose span contains its line (its *caller*), or to none.

### 18.4 Resolution

A call site resolves to a set of candidate definitions; the caller itself is removed from it (a
same-named overload is the more likely target than recursion). Then:

* **empty**: the call is not a project call; nothing happens;
* **name collision**: the candidates have more than one owner (two classes, modules, packages or
  receiver types): the call is **skipped and counted** (debug line, 18.7);
* otherwise the candidates form one **group** (overloads, redefinitions, build-tag variants of one
  owner).

Definitions in test files (4.7) are candidates only for call sites in test files.

**Java** (call with name *m*, *n* arguments; enclosing classes C1 innermost … Ck):

1. No object or `this`: the first class among C1 … Ck (for `this`: C1 only) that declares a method
   named *m*; else the class of a single-static import of *m* (`import static p.C.m;`); else all
   classes imported with static on-demand imports (`import static p.C.*;`).
2. Object text *Q*: if *Q* has a `.` and its first segment starts with a lower-case letter, *Q* is a
   fully qualified class name. Otherwise its first segment *S* must start with an upper-case letter
   and is resolved, in this order: a class named *S* declared in the file (at any nesting); the
   single-type import of *S*; the same package (a class `p.S` of the calling file's package `p` declared in the
   project, or a file `S.java` in the calling file's directory);
   the on-demand imports `p.*` (`p.S` declared in the project). Further segments name member
   classes. A *Q* that starts with a lower-case letter and has no `.` is a variable: not resolved.
3. Candidates: the methods named *m* declared in the body of the resolved project class (not
   inherited) whose arity accepts *n*.

**Python** (call in module *M*):

* `f(…)`: if *f* is a parameter or an assigned name of the caller, not resolved; else the import
  binding of *f* in the file (any `import` or `from … import` statement of the file); else a
  module-level function *f* of *M*.
* `self.f(…)`, `cls.f(…)` in a method of a module-level class *K*: the methods *f* of *K*.
* `X.f(…)`, `a.b.f(…)`: *X* (or the root *a*) bound by an import: the target module (a function
  *f*) or class (a method *f*); *X* a module-level class of *M*: its methods *f*.
* Import targets: `import a.b` binds `a`; `import a.b as x` binds `x` to `a.b`; `from a import b`
  binds `b` to the module `a.b` if it exists, else to the member `b` of `a`; relative imports
  (`from .m import f`, `from .. import m`) resolve against the package of *M*. A dotted module name
  *D* denotes the project module *D*, else the single project module whose name ends with `.D`
  (source roots such as `src/` are not known); several → not resolved. A member `b` of module *K* is
  *K*'s module-level function or class `b`, else, if *K* imports `b`, that binding's target (re-export,
  at most 4 hops). A local name with import bindings to different targets is not resolved.

**Go** (call in package *P* = (dir, name)):

* `F(…)`: if *F* is a parameter, receiver or variable of the caller, not resolved; else the
  functions *F* of *P*.
* `x.F(…)`: if *x* is a variable of the caller with a **declared type** *T*: the methods *F* with
  receiver type *T* (in *P*, or for `p.T` in the imported project package); else if *x* is the
  local name of an import (17.4) of a project package: its functions *F*.
* `x.f.M(…)`: *x* with declared type *T*, *T* a struct type declared in the same file with a field
  *f* of type *U*: the methods *M* with receiver type *U*.
* Declared types of a function's names: the receiver (`r *T`), parameters (`a T`, `b *p.U`),
  `var v T`, and `v := T{…}`, `v := &T{…}`, `v := new(T)` (also `p.T`); generic arguments removed.
  A name with two different declared types in one function is not typed.
* Project packages: an import path resolves through the `go.mod` files under the scan root (module
  path → directory; the longest matching module path wins; the rest of the import path is the
  subdirectory) or, failing that, to `vendor/<path>` below such a module directory; the package is
  that directory's package whose name does not end in `_test`. (Below a module directory, the one of
  the calling file's nearest enclosing `go.mod`.)

### 18.5 Crypto callables

A **crypto callable** is a definition together with the family keys it **carries**; for each
carried key it records its **depth** (1–4: the number of definitions on its chain), its
**evidence** (the body finding at the end of the chain) and its **chain** (the definitions from it
to the one holding the evidence). The callables are computed by levels, repeated until a level adds
nothing; level *k* sees only what levels below *k* produced, so the result does not depend on the
order in which definitions are visited, and cycles (recursion, mutual recursion) cannot add anything:

* **Level 1, W7 (name-consistent)**: a definition carries every family key that is both one of its
  name families and the family key of one of its body findings. Evidence: the first such body
  finding (by line, then rule id) whose rule id has a `.`-segment equal to a token of the definition's
  name (18.6), else the first such body finding *(DECISIONS B-P-B5, feature `wrapper-evidence-by-name`;
  `_ecdh_recipient` reports the ECDH finding of its body, not the earlier EC key generation)*.
* **Level 1, W6 (thin)**, where enabled: a definition whose span has at most *L* lines (*L* = 12 for Java,
  *DECISIONS B-J-G*, 8 with `--feature java-thin-12=off`; 8 for Python; 12 for Go, *DECISIONS B-G-E*) and whose body
  findings have exactly one family key carries that key (whatever its name). Evidence as above.
* **Level *k* ≥ 2, W7**: a definition that does not yet carry a key *F* carries *F* if *F* is one of
  its name families and a call site of its body resolves to a group carrying *F* below level *k*.
* **Fallback-getter guard (Go W6)** *(DECISIONS B-G-E)*: in a Go definition with at least two
  `return_statement`s of its own (not of a function literal inside it), a return statement that lies
  inside an `if_statement` of the definition is a *conditional return*. Body findings and call sites on
  the lines of a conditional return do not count for the W6 tests (here and at level *k*): a getter
  `if c.DefaultHash == 0 { return crypto.SHA256 }; return c.DefaultHash` returns a configured value with
  a default, it does not wrap SHA-256. W7 is not affected.
* **Level *k* ≥ 2, W6**, where enabled: a definition of at most *L* lines that carries nothing yet
  carries *F* if the family keys of its body findings together with the keys carried (below level
  *k*) by the groups its call sites resolve to are exactly {*F*} (a thin wrapper of a wrapper; the
  test is made once, at the first level where it holds).
* In both, evidence and chain are those of the group's **representative** for *F* with the definition
  prepended (of several such calls, the one whose representative has the smallest depth, then the
  first call); no carry is made whose chain would have more than 4 definitions *(DECISIONS B-C; 3 with
  `--feature wrapper-depth-4=off`)*.

A **group carries** *F* if every definition of the group carries *F*; its representative for *F* is
the member with the smallest depth for *F* (then path, then line).

### 18.6 Name tokeniser and aliases

A name is split into tokens at `_` and `$`, between a lower-case letter or digit and an upper-case
letter, and between two upper-case letters when the second is followed by a lower-case letter
(`hmacSha512` → `hmac`, `sha512`; `HMACSha256` → `HMAC`, `Sha256`; `sha3_256` → `sha3`, `256`;
`newAESGCM` → `new`, `AESGCM`). Letters and digits stay together (`x509`, `ed25519`, `p256`). Tokens
are lower-cased (`Locale.ROOT`). Each pair of adjacent tokens is also tried joined (`sha_256` → also
`sha256`, `KeyStore` → also `keystore`, `tripleDES` → also `tripledes`).

A token of at most 128 characters **names** the family keys of the aliases it consists of, if it decomposes completely: it
starts with an alias (the longest alias wins at each position), and every alias is followed by the
end of the token, another alias, a neutral part (`with`, `and`, `gcm`, `ccm`, `cbc`, `ctr`, `ecb`,
`cfb`, `ofb`, `siv`, `xts`, `kw`, `pss`, `oaep`, `d`, `sum`, `hex`; and, *DECISIONS B-A1*, `pkcs1`, `v15`,
`mgf1`, `p1363`, `ssa`, `es`) or a run of digits; after a digit
run, or an alias ending in a digit, the same holds, or at most two characters end the token (`aesgcm`
→ AES, `sha256withrsa` → SHA2 and RSA, `sha256d` → SHA2, `md5sum` → MD5, `blake2b` → BLAKE2,
`aes256gcm` → AES, `chacha20poly1305` → ChaCha20 and Poly1305, `secp256k1` → EC;
`rsassa` → RSA, `des3` → 3DES; `aesthetic`, `ecb`, `description`, `section` → nothing). The alias list
*(DECISIONS T5; the rows marked V1 and V2: DECISIONS B-A1, B-A2)*:

| Family key | Aliases |
|---|---|
| SHA1 | `sha1` |
| SHA2 | `sha2`, `sha224`, `sha256`, `sha384`, `sha512` |
| SHA3 | `sha3`, `keccak`, `shake` |
| MD5, MD4, MD2 | `md5`; `md4`; `md2` |
| RIPEMD160 | `ripemd`, `rmd160` |
| BLAKE2 | `blake2` |
| SM3 | `sm3` |
| HMAC | `hmac` |
| CMAC | `cmac` |
| Poly1305 | `poly1305` |
| AES | `aes`, `rijndael` |
| DES | `des` |
| 3DES | `3des`, `desede`, `tripledes` |
| ChaCha20 | `chacha`, `xchacha` |
| Salsa20, XSalsa20 | `salsa20`; `xsalsa20` |
| RC4, RC2 | `rc4`, `arcfour`; `rc2` |
| Blowfish, Twofish, Camellia, CAST5, Serpent, SM4 | `blowfish`; `twofish`; `camellia`; `cast5`; `serpent`; `sm4` |
| RSA | `rsa` |
| DSA | `dsa` |
| DH | `dh` |
| EC | `ec`, `ecc`, `ecdsa`, `ecdh`, `ecdhe`, `ecies`, `secp`, `prime256v1`, `p256`, `p384`, `p521`, `brainpool` |
| Ed25519, Ed448 | `ed25519`, `eddsa`; `ed448` |
| Curve25519, Curve448 | `x25519`, `curve25519`; `x448`, `curve448` |
| ML-KEM, ML-DSA, SLH-DSA | `mlkem`, `kyber`; `mldsa`, `dilithium`; `slhdsa`, `sphincs` |
| PBKDF2, HKDF, scrypt, Argon2, bcrypt | `pbkdf2`; `hkdf`; `scrypt`; `argon2`; `bcrypt` |
| x509 (subtype) | `x509` |
| `java.cert.keystore` (rule id) | `keystore`, `truststore` |
| HMAC, RSA, EC, AES (V1, IANA JOSE) | `hs256`, `hs384`, `hs512`; `rs256`, `rs384`, `rs512`, `ps256`, `ps384`, `ps512`; `es256`, `es384`, `es512`; `a128`, `a192`, `a256` |
| EC (V1, IANA TLS groups / SSH, JCA, RFC 5480) | `sect`, `nistp`, `p192`, `p224`, `ecmqv`, `x962` |
| DH (V1, JCA, IANA TLS / SSH) | `diffie`, `diffiehellman`, `ffdhe`, `dhe`, `dhkem` |
| DSA, 3DES (V1, IANA SSH, NIST SP 800-67) | `dss`; `tdea`, `tdes`, `des3` |
| IDEA, SEED, CAST5, PBE (V1) | `idea`; `seed`; `cast128`; `pbe`, `pbes2` |
| ConcatKDF, KBKDF, X963KDF, ElGamal (V1) | `concatkdf`; `kbkdf`; `x963kdf`; `elgamal` |
| x509 (V2) | `cert`, `certificate` |
| `private-key`, `public-key` (subtypes, V2) | `privatekey`, `privkey`; `publickey`, `pubkey` |
| `<lang>.prot.tls.context`, `<lang>.prot.ssh` (rule ids, V2) | `tls`, `ssl`; `ssh` (`<lang>` is the definition's language: `java`, `python`, `go`) |
| RIPEMD160 (V2, Bitcoin's HASH160) | `hash160` |
| `python.hash.unresolved` (rule id; Python only, U1W) | `hash`, `digest` (feature `python-hash-wrappers`, *DECISIONS B-P-U1W*) |

The V2 aliases name what a key, certificate or protocol helper returns rather than an algorithm; they
are on by default and can be switched off with `--feature wrapper-aliases-v2=off` (3.1). As for every
alias, the body check makes a false name match harmless: a definition carries a key only if a body
finding (or a called wrapper) has it.

### 18.7 Reporting, folding and interactions

For each call site (any scanned file of the language, test files included) that resolves to a group
carrying at least one key: for each carried key *F*, in code-point order, one finding with the
call's file, line, symbol, snippet and test flag and the evidence's rule, name, param and oid. Its
occurrence records the chain (11.4): `via` = the group representative and the definitions after it,
each as `<path>:<line of the name> <display name>` (Java `Outer.Inner.m`, Python `module.f` or
`module.Class.m`, Go `pkg.F` or `pkg.Type.M`), and `origin` = `<path>:<line>` of the evidence.

* **Folding of nested duplicates**: a propagated finding is dropped if a finding of phase 3 at the
  same (file, line) has the same family key (the direct finding is more specific); of several
  propagated findings with the same (file, line, family key) only the one of the leftmost call is
  kept (`sha256(sha256(x))` is one occurrence). Calls nested across lines are not folded.
* **Components**: a propagated finding belongs to the component of its evidence (same key, 10.1);
  it never creates a component of its own, but it can make a component that was test-only a
  non-test one (11.3.4).
* **Test files**: wrappers defined in test files serve only call sites in test files; call sites in
  test files are reported and marked like every test occurrence; `--exclude-tests` removes both.
* **Vendored code** (`vendor/`, copied libraries) is project code: it defines callables and holds
  call sites like any other directory; `--exclude` removes it from both sides.
* **Partial scans**: only files under the scan root take part. Scanning a subdirectory therefore may
  give fewer propagated findings (wrappers defined outside it are unknown; Go `pkg.F` calls need the
  `go.mod` under the scan root) and may resolve differently (a Python module name is matched by
  suffix, a collision partner outside the root is not seen). The output of one scan root is
  deterministic.
* **Name collisions**: as 18.4; such calls are skipped and counted.
* With `--verbose` the pass ends with one debug line:
  `wrapper propagation: <c> callables, <n> occurrences, <a> ambiguous calls skipped`.
* Determinism (12): the index, the levels and the folding depend only on the file contents; files
  are visited in relative-path order, definitions in (path, line) order.

### 18.8 Go package-name consistency *(DECISIONS B-G-B3L, benchmark-informed)*

Go projects often put an algorithm into a package of its own and name the package after it (`sops/aes`,
`smallstep/x25519`, `go-crypto/openpgp/ed448`); its callers write `aes.NewCipher()` or `c.Encrypt(…)` on a
value of the package's type. When Go wrappers (W7) are on and the feature `go-package-names` is on (3.1,
default):

* A **package-name package** is a directory of the scan root whose non-test Go files (as indexed, 18.2)
  have exactly one package name *N* (not ending in `_test`) such that *N* names family keys by the
  tokeniser (18.6, with the V2 aliases if they are on) and the package has a non-test propagatable finding
  of such a key. Its **evidence** for key *F* is its first such finding of *F* (by path, line, rule id).
* A **package-name call** is a Go call site (18.3) `x.M(…)` whose resolution is not ambiguous (18.4), whose
  member `M` does not contain (case-insensitively) `length`, `size`, `encode`, `decode`, `fields`, `find`,
  `name`, `string`, `params`, `oid` or `info` (sizes, encodings and look-ups name nothing), and where `x`
  is either the local name of an import (not a parameter or variable of the caller) of a project package
  (18.4) or a name of the caller with the declared type `p.T` (18.4) where `p` imports such a package,
  the package being a package-name package other than the caller's own directory.
* Each package-name call yields, for each evidence key *F* in code-point order, a propagated finding
  like 18.7 (folding included; after the callables of 18.5, so a callable's chain wins on the same line
  and key) whose `via` is the single element `<dir>: package <N>` and whose `origin` is the evidence.
* To index the files that make such calls (18.2), the package names and the last segments of the
  directories of package-name packages count as callable names.
* Not covered: the type of a call's result (`c := aes.NewCipher(); c.Encrypt()`), struct fields,
  external modules (B2p, rejected).

---

## Appendix A. Intentional differences from the reference tool

The expected findings of the conformance suite were produced by running the reference tool
and then applying the following differences (`spec/conformance/deviations.yaml`). Each is a
bug or gap in the reference tool that CipherSift fixes on purpose.

| Id | Behaviour in CipherSift | Reference tool | Section |
|---|---|---|---|
| D1 | `setup.py` is analysed as Python source. | Classified only as a manifest, never analysed. | 4.5 |
| D2 | Function and lambda parameters shadow outer bindings in Python constant/alias resolution. | A parameter named like a module constant resolved to the constant (`def f(ALG): hashlib.new(ALG)` reported MD5). | 8.3 |
| D3 | Java array initialisers reached through a constant (`static final String[] P = {…}; s.setEnabledProtocols(P)`) contribute their elements to the string list. | Only inline arrays were flattened. | 7.4.6 |
| D4 | Java text blocks are decoded per the JLS (incidental indentation and the opening line break removed). | The raw content, including the leading line break and indentation, was used, so no regex matched. | 7.4.2 |
| D5 | Binary files are skipped; cross-file constant lookup never leaves the scan root. | Binary `.py` files were parsed; the derived source root could lie outside the scan root. | 4.6, 7.4.5 |
| D6 | `--exclude-tests` and test-file marking. | No test-file detection. | 4.7 |
| D7 | PyPI manifests: `requirements*.txt`, `requirements/*.txt`, `poetry.lock`, PEP 735 `[dependency-groups]`. | Only files named exactly `requirements.txt`; no Poetry lock, no dependency groups. | 9 |
| D8 | Maven and Gradle manifests with the CipherSift crypto-library list; versions from `<properties>`; dependencies without version are reported. | Different (third-party) pom support, not carried over. | 9.5–9.7 |
| D9 | Integer and character elements of array arguments are not part of the Java string list, so `new SecretKeySpec(new byte[] {1, 2, …}, "DES")` has the first string `"DES"`. | The array's numbers became strings (`"1"`, `"2"`, …), so `firstString` saw `"1"` and the DES pattern did not match. | 7.4.6 |
| D10 | Python bare references in value position (table elements, class attributes, arguments, alias definitions) are matched by `call` patterns; `ref` patterns *(DECISIONS E1)*. | Only calls were matched. | 8.6.1 |
| D11 | `verify=False` / `ssl=False` disable certificate validation only on `requests`, `httpx`, `aiohttp` calls and HTTP-client method names *(DECISIONS E14)*. | Any call with such a keyword. | 8.6 (rule) |
| D12 | A PSS / OAEP padding object in a variable is attributed to the operation call like PKCS1v15; method-only patterns with `anySymbol` are named after the symbol *(DECISIONS E13, E17)*. | PSS/OAEP stayed at their own line; names were built from the receiver (`key.sign`). | 8.6 |
| D13 | `setup.py` `install_requires` / `extras_require` and `setup.cfg` are dependency manifests *(DECISIONS E10)*. | Not read. | 9.8 |
| D14 | `SecureRandom.getInstance(alg)` reports `alg` as parameter *(DECISIONS E17)*. | No parameter. | rule |
| D15 | Weakness indicators (insecure PRNGs) are reported only with `--weakness-indicators` *(DECISIONS E2)*; `common/test-files` drops its `random.random()` finding, the fork-fixture cases pass the option. | Always reported. | 3.1, 5.3 |

CBOM layout and component grouping (sections 10 and 11) are new designs and are not
comparable with the reference tool's components (which, for example, merge Java algorithm
names case-insensitively, key Python algorithms by call name and asset properties rather
than by rule, and group related-crypto-material per file). The conformance suite therefore
compares occurrences, not components.

Smaller differences that no conformance case exercises: snippets are truncated to 500 code
points for Java too; Java escape decoding follows the JLS exactly (`\s`); symbolic links are
never followed; directories `.git`, `.hg`, `.svn` are skipped; requirement lines ending in
`\` are joined.

## Appendix B. Known limitations (by design)

* No data flow beyond constants. Java algorithms from parameters, configuration,
  `String.format`, `StringBuilder` or ternaries give a `java.jca.*.unresolved` component;
  Python attributes (`self.mode`), return values and cross-module constants are not
  resolved, so `hashlib.new(name)` with unknown `name` gives nothing.
* Java: a local declared without initialiser and assigned later (`final String alg; if (c) alg = "A";
  else alg = "B";`) resolves only if its values agree (7.4.3, 7.7.1, *DECISIONS B-J-JP3*, which replaces
  the E15 limitation; with `--feature java-deferred-locals=off` it is unresolved as before). OID strings
  are mapped through the table of 5.11 only when they are literal or resolved constants; OIDs held in
  library constants other than the Bouncy Castle constants of the constants document (5.10) and OIDs
  missing from the table are not mapped.
* Receiver types are not inferred: `method` patterns are heuristics
  (`setEnabledProtocols`, `cipherSuites`, Python `sign`/`encrypt` with `padding.*`,
  `ecdsa_sign`, `verify=False` on HTTP-client method names such as `get` or `send`).
  Attribute *reads* are not anchors: asn1crypto certificate fingerprints (`cert.sha256`) are
  not reported *(DECISIONS E3)*.
* Python parameter default values are not value positions (8.6.1): `def h(v,
  f=hashlib.sha256)` reports nothing, at the definition or at the call `f(v)` (D6 of the
  evaluation, by design).
* Python import alternatives: only the import-failure handler of the same `try` is recognised
  (8.2, *DECISIONS F2*); alternatives chosen by `if` (version checks, `sys.platform`), by
  handlers of other exceptions or in another `try` statement are all bindings, so
  `if PY2: from md5 import md5 else: from hashlib import md5` binds both.
* Java simple names that are neither imported nor declared are assumed to be the API class
  (7.3.2 step 6); a same-named class from the same package or a wildcard import is
  mis-attributed. Reassignment is tracked by simple name across the whole file.
* Java constants of a nested class in the same package written as `Outer.Inner.X` without
  import are not resolved (the dotted qualifier is taken as fully qualified).
* Java "first string" is the first *resolvable* string argument (7.4.6).
* Python string literals are used raw (escape sequences are not interpreted); bytes and
  f-strings are never strings.
* Python resolution is flow-insensitive: all assignments of a scope count, and the first
  one supplies the first string (`alg = "md5"; alg = "sha256"; hashlib.new(alg)` → MD5).
* Python operation attribution (`reportAt`) only works when the padding / hash object is written
  inside the operation call's arguments; a padding object in a variable is reported at its own
  line and, through the symbol set (flow-insensitively: every padding the variable is ever bound
  to), at the operation call.
* One algorithm per signature identifier in Java (`SHA1withRSA` → RSA only).
* Dependency versions: no parent-POM, BOM or Gradle-plugin resolution; ranges give no
  version.
* Kotlin, Groovy and Scala sources are not analysed.
* Test detection is path-based: library code that lives in directories named like tests
  (e.g. `django/test/`, `numpy/testing/`) is marked as test code.
* Source files are recognised by extension, and extensionless Python scripts by their
  interpreter line (4.5, *DECISIONS F7*); a script with an extension other than `.py`
  (`tool.sh` holding Python), a relative interpreter (`#!python`) or an interpreter line beyond
  the first 256 bytes is not scanned *(DECISIONS E18)*.
* Go (section 17, *DECISIONS G1–G16*): receiver types are not inferred, so method calls on values
  (`key.Sign(…)`, `aead.Seal(…)`, `curve.GenerateKey(…)`) are not anchors; constants are resolved
  within the file only (not from other files of the package or from other packages); resolution
  is flow-insensitive within a function and block scopes are not distinguished; local names of
  imports without explicit name follow the naming conventions of 17.4 (a package whose name
  differs from its last path segment is not recognised without an alias); an `assign` pattern
  fires on a field of that name in any struct literal or selector (the type of the struct is
  not checked); cgo, `//go:build` constraints and generated code are not treated specially;
  `replace` directives of `go.mod` are not applied.
* Go: a block cipher created in another function (a constructor that stores it in a struct
  field, a helper that returns it, a function parameter such as go-jose's
  `newBlockCipher func([]byte) (cipher.Block, error)`) does not reach the mode call: symbol sets
  follow bindings within one function only (17.6/17.7), as Python and Java do not follow return
  values, parameters or fields (D2, D5 of the evaluation). The mode is then reported by its
  cipher-agnostic fallback (`go.sym.mode.*`, no family) *(DECISIONS F8)*.
* Go: a nested-duplicate fold (17.8) of a curve function into an enclosing key construction
  (`ecdsa.PublicKey{Curve: elliptic.P256(), …}`) drops the curve's finding and its parameter;
  the construction (a composite) has no parameter *(DECISIONS F4)*.
* Wrapper propagation (18) is name- and declaration-based, not typed: Java calls on variables
  (`key.sign(h)`), inherited methods, interface calls and constructors; Python calls on
  attributes other than `self`/`cls` (`self._key.sign`), on parameters, and through
  `getattr`; Go calls through interfaces or on values whose type is not declared in the function
  (`x := pkg.New()`; `x.M()`) are not resolved. A wrapper whose name names no family is a callable
  only as a thin wrapper (W6; Python only with `--python-thin-wrappers`). Calls nested across lines
  are not folded.
  Overloads of one Java class with the same arity are one group (reported only if all of them carry
  the family). Java "same package" also counts a file `S.java` in the calling file's directory (a class of that
  package that the index did not read).
  *(DECISIONS T1–T14)*
* tree-sitter-java 0.23.5 rejects some valid literals (a binary literal with a double
  underscore, `0b1000__0000`); the rest of the file is analysed (6.2) *(DECISIONS E18)*.

## Appendix C. Tree-sitter node types and fields used

**Java (tree-sitter-java 0.23.5).** `program`; `package_declaration`; `import_declaration`
(children `static`, `asterisk`, `scoped_identifier`, `identifier`); `class_declaration`,
`interface_declaration`, `enum_declaration`, `record_declaration`,
`annotation_type_declaration` (field `name`; class: `superclass`, `interfaces`; enum:
`interfaces`); `class_body`, `interface_body`, `enum_body`; `field_declaration`,
`constant_declaration`, `local_variable_declaration` (child `modifiers`, children
`variable_declarator` with fields `name`, `value`); `method_declaration` (fields `name`,
`parameters`, `body`); `constructor_declaration` (`parameters`); `constructor_body`;
`lambda_expression` (`parameters`); `enhanced_for_statement` (`name`); `block`;
`switch_block_statement_group`; `method_invocation` (fields `object`, `name`, `arguments`);
`object_creation_expression` (fields `type`, `arguments`; optional `class_body` child);
`field_access` (fields `object`, `field`); `argument_list`; `assignment_expression` (field
`left`); `binary_expression` (fields `left`, `operator`, `right`);
`parenthesized_expression`; `cast_expression`; `unary_expression`; `array_initializer`;
`array_creation_expression` (children `dimensions_expr`, `array_initializer`);
`string_literal` (children `string_fragment`, `multiline_string_fragment`,
`escape_sequence`); `decimal_integer_literal`; `character_literal`; `identifier`;
`scoped_identifier`; `this`; `line_comment`; `block_comment`.

**Python (tree-sitter-python 0.25.0).** `module`; `import_statement` (children
`dotted_name`, `aliased_import` with fields `name`, `alias`); `import_from_statement`
(fields `module_name` — `dotted_name` or `relative_import` — and `name`; child
`wildcard_import`); `function_definition` (field `parameters`); `lambda` (field
`parameters`); `parameters`, `lambda_parameters`, `default_parameter`,
`typed_parameter`, `typed_default_parameter`, `list_splat_pattern`,
`dictionary_splat_pattern`; `assignment` and `augmented_assignment` (fields `left`,
`right`); `call` (fields `function`, `arguments`); `attribute` (fields `object`,
`attribute`); `argument_list`; `generator_expression`; `keyword_argument` (fields `name`,
`value`); `list_splat`; `dictionary_splat`; `string` (children `string_start`,
`string_content`, `interpolation`); `concatenated_string`; `integer`; `float`; `list`;
`tuple`; `set`; `parenthesized_expression`; `conditional_expression`; `identifier`;
`comment`; for bare references (8.6.1) and setup.py (9.8) also `dictionary`, `pair` (fields
`key`, `value`), `expression_list`, `expression_statement`, `binary_operator`,
`unary_operator`, `boolean_operator`, `not_operator`, `return_statement`, `await`,
`comparison_operator`, `except_clause`, `subscript`, `type`, `generic_type`, `union_type`,
`constrained_type`, `member_type`, `splat_type`, `type_alias_statement`, `type_parameter`.

**Go (tree-sitter-go 0.25.0, section 17).** `source_file`; `import_declaration`, `import_spec`
(fields `name` — `package_identifier`, `dot`, `blank_identifier` — and `path`),
`interpreted_string_literal`, `raw_string_literal`; `function_declaration` (fields `name`,
`parameters`, `result`), `method_declaration` (`receiver`, `parameters`, `result`), `func_literal`
(`parameters`, `result`); `parameter_list`, `parameter_declaration`,
`variadic_parameter_declaration` (field `name`); `const_spec`, `var_spec` (fields `name`,
`value`); `short_var_declaration`, `assignment_statement` (fields `left`, `operator`, `right`),
`range_clause` (field `left`; child `:=`), `inc_statement`, `dec_statement`; `expression_list`;
`type_spec`, `type_alias` (field `name`); `call_expression` (fields `function`, `arguments`);
`argument_list`; `selector_expression` (fields `operand`, `field`); `identifier`;
`composite_literal` (fields `type`, `body`); `qualified_type` (fields `package`, `name`);
`type_identifier`; `literal_value`, `keyed_element` (fields `key`, `value`), `literal_element`;
`binary_expression` (fields `left`, `operator`, `right`); `unary_expression` (field `operand`);
`parenthesized_expression`; `expression_case` (field `value`); `int_literal`, `true`, `false`;
`comment`.

An implementation SHOULD verify at start-up (or in a unit test) that every field name listed
here exists in the loaded grammar (`Language.getFieldIdForName` returns non-zero), so that a
grammar upgrade that renames a field fails loudly.

## Appendix D. Roadmap: deep mode (potentially later, not implemented) *(DECISIONS T13)*

Recorded from the assessment of more radical designs (2026-10-17) so that a later round can start
from it. Nothing of this appendix is implemented or specified as behaviour.

* **Build-free typed call graph, as a separate optional component** (a "deep mode", off by
  default, its own option): receivers and interface implementations resolved from the declared
  types of the project's own sources and a class-hierarchy analysis, with the crypto summaries of
  section 18 propagated along the typed edges; owner-name consistency (the class, type or package
  name names the family, as Go's `ecdsa`, `x25519`, sops' `aes.Cipher`, bitcoinj's `ECKey`);
  KMS/HSM SDK anchors gated by the file's imports. No build, no network, deterministic.
* **Order: Java first** (a project symbol table from declared types), **then Go** through
  `go/types` over the project packages and the standard library from source (external modules
  as empty packages, type errors ignored), behind a clear helper boundary: a separate helper
  process with a versioned JSON interface (call edges with the resolution kind), so that the
  JVM tool does not link a Go toolchain. **Python only with a fast resolver** (pyright or an own
  module/attribute resolver); jedi was too slow (about 0.5 kLOC/s) and depends on the installed
  packages.
* **A `confidence` field per finding** (high / medium / low), fed by the resolution kind, depth,
  name consistency and a return-flow filter; the deep mode's broad tier (direct wrappers of any
  name) would ship only as low confidence.
* **Java virtual constants** (an overriding method that returns an algorithm literal used by a
  `getInstance(m())` of an ancestor makes each `new Subclass()` a finding) and **small
  partial-evaluation rules** (`getattr(hashlib, f"sha…")`, `hashes.Hash(var)`, typed algorithm
  literals and enums); these are cheap and could also enter the default mode.
* **Rejected options**: CodeQL or Joern as front-end (rules would become queries; CodeQL's CLI
  licence, Joern's runtime and memory), bytecode or binary analysis (needs build artefacts, loses
  source constants), and an LLM pass inside the CBOM (not deterministic, not reproducible, network;
  at most a separate triage tool outside the CBOM).
* **Engineering debt to plan for**: a polyglot helper (Go, perhaps Node for pyright) with its own
  build, licences and release; toolchain pinning (the result must not change with the installed
  Go or Python version; go1.19 lacked `crypto/ecdh`); a growing test matrix (languages × modes ×
  helper versions); blow-ups on large repositories (call-graph size, class-hierarchy fan-out,
  memory), which need explicit limits and a documented "limit reached" outcome.
