<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 The CipherSift Authors -->

# CipherSift 1.0 — implementation notes

Implemented clean-room from `spec/SPEC.md`, `spec/DECISIONS.md`, `spec/REVIEW.md`,
`spec/rule-schema.json`, `spec/conformance/`, `spec/tools/` and `rules/` only.

## Result in one paragraph

*(State of the first implementation. For the current numbers — 379 tests, 28/28 conformance
cases with 573 findings, start-up and throughput — see "Follow-up" below.)*

`mvn -q verify` is green: 288 unit tests (surefire) and 60 integration tests (failsafe,
against the fat jar). The conformance suite passes **25/25 cases, 562/562 findings** (the 23
delivered cases plus the two that DECISIONS.md asked for), both with the JUnit runner and with
`spec/tools/conformance.py`. Every CBOM the suite produces validates against the CycloneDX 1.6
schema (cyclonedx-core-java 13.2.0). Output is byte-identical across `--threads 1/8`, two scan
root locations, working directories, locale, time zone and default charset. The bom-refs of the
SPEC 11.5 example are reproduced exactly.

## Build and run

```sh
export JAVA_HOME=/usr/lib/jvm/jdk-25.0.1
mvn verify                                   # natives (if missing), tests, conformance, headers
java -jar target/ciphersift-1.0.0-SNAPSHOT-all.jar scan <dir> -o out.cdx.json
bin/ciphersift scan <dir> -o out.cdx.json    # launcher (adds --enable-native-access)
python3 spec/tools/conformance.py --cmd "java -jar target/ciphersift-1.0.0-SNAPSHOT-all.jar"
```

In this sandbox Maven was run with `-Dmaven.repo.local=$PWD/.m2` and a settings file in
`$TMPDIR` (proxy + `repo1.maven.org` mirror). The Java HTTP client was refused by the proxy for
most jar downloads although `curl` worked, so missing artifacts were fetched into `.m2/` with
`curl` (a helper loop outside the repository); nothing in the project depends on that. The
working `.m2/` is ignored by git. `/tmp` is read-only here: the scanner then extracts the
natives to `~/.cache/ciphersift/native/<digest>/`, or, if that is not writable either, to a
temporary directory in `java.io.tmpdir` or `$TMPDIR`.

## Architecture

Root package `ch.unibe.seg.ciphersift` (groupId `ch.unibe.seg`, artifactId `ciphersift`).

| Package / class | Role (SPEC section) |
|---|---|
| `Main`, `CipherSift` | entry point, version info (`version.properties`, filtered by Maven) |
| `cli.Main`, `ScanCommand`, `RulesCommand`, `ExitCodes`, `Log` | picocli commands, exit-code mapping, `ciphersift: <level>: …` logging (3) |
| `cli.SilentLoggingProvider` | SLF4J provider that discards json-schema-validator's log events (keeps stderr clean) |
| `natives.Platform`, `NativeLibraries`, `TreeSitterLibraryLookup`, `Grammars` | platform id, extraction + SHA-256 verification, jtreesitter `NativeLibraryLookup` SPI, grammar loading and Appendix C field check (15.3) |
| `syntax.SyntaxTrees`, `SyntaxNode` | parse with `Parser.parse(String)`, copy the tree into immutable Java nodes with one iterative `TreeCursor` walk, close the native tree (6) |
| `rules.RuleLoader`, `RuleSet`, `SourceRule`, `JavaPattern`, `PythonPattern`, `DependencyRule`, `Asset` | YAML/JSON loading, JSON-schema + semantic validation, compiled patterns, rules digest (5, 11.6) |
| `files.FileCollector`, `Glob`, `FileClass`, `TestFiles`, `SourceText` | walk, excludes, classification, test files, size/binary checks, UTF-8 decoding (4) |
| `lang.java.JavaAnalyzer` | events, rule index lookup, pattern evaluation, specificity selection, nested duplicates, findings (7.2, 7.5–7.8) |
| `lang.java.JavaContext`, `JExpr`, `JavaResolver`, `JavaStrings`, `JavaContexts`, `JavaRuleIndex` | file context, compact expression form, `value` / lookups / string lists / `isConst`, literal and text-block decoding, cross-file context cache (7.3, 7.4) |
| `lang.python.PythonAnalyzer`, `PythonRuleIndex` | collection walk, scopes and bindings, name resolution, argument analysis, matching of calls and bare references, attribution, params, attribute assignments (8) |
| `deps.DependencyScanner`, `PythonManifests`, `MavenManifests`, `SetupManifests`, `ManifestEntry` | all manifest formats (`setup.py` from its syntax tree, `setup.cfg`), per-manifest de-duplication, rule matching (9) |
| `model.*` | source and dependency findings (2.1) |
| `cbom.Normaliser`, `Component`, `CbomWriter`, `Purl` | components and occurrences, ordering, bom-refs, serial number, JSON (10, 11) |
| `scan.Scanner` | phases 1–4, worker pool, per-thread parsers, per-file error handling (2, 13, 14) |

Other files: `native/build-natives.sh` (+ `sources.lock`, `vendor/` with the unpacked
`src/`/`lib/` trees and MIT licences), `bin/ciphersift`, `Dockerfile` (+ `.dockerignore`),
`NOTICE`, `README.md`, `CHANGELOG.md`, `.gitignore`.

## How the spec is implemented (by section)

* **3 CLI.** picocli; `--include-tests/--exclude-tests` and `--quiet/--verbose` are exclusive
  arg groups (both given → usage error 2). `--threads 0` → 2. Order of checks: usage, scan root
  (3), output directory exists (5), rules (4), natives (1), scan, write (5). Output goes to a
  temporary file in the target directory and is renamed atomically; a shutdown hook deletes the
  temporary file on SIGINT (exit 130 from the JVM).
* **4 Files.** Directory entries sorted by code points; `.git/.hg/.svn` skipped; links and special
  files skipped (debug); excludes on directories prune the subtree. Classification by name, then
  test detection, then (with `--exclude-tests`) dropping. Size, binary and read checks happen in
  the worker; such files are counted as skipped.
* **5 Rules.** Bundled rules are read from the jar's `rules/` (or `target/classes/rules`), every
  document validated with networknt 2.0.4 against `rule-schema.json` (bundled as
  `schema/rule-schema.json`), then the 5.8 semantic checks. Regexes compiled once
  (`CASE_INSENSITIVE | UNICODE_CASE` where the spec says case-insensitive).
* **6 Parsing.** One `Parser` per worker thread (ThreadLocal), trees copied and closed immediately;
  all walks iterative. The copy includes anonymous nodes and field names; offsets are mapped
  from UTF-8 bytes to `String` indices; rows are computed from LF positions (same as
  tree-sitter rows, SPEC 1.3).
* **7 Java.** Implemented as specified; the analysed file's expressions are converted on demand
  into `JExpr` forms that keep identifier positions (for 7.4.3 local lookup); field initialisers
  are converted without positions. Cross-file contexts are built on demand, frozen (no syntax
  nodes kept) and cached in a `ConcurrentHashMap` (including negative results).
* **8 Python.** One collection walk with a scope stack, then calls in pre-order, then attribute
  assignments. `resolveName` results are memoised per (scope, name) only when the computation
  never hit the cycle guard or a depth limit, together with the number of binding steps used,
  so memoisation never changes a result.
* **9 Manifests.** DOM parser with DOCTYPE disallowed and external entities off; Jackson TOML and
  JSON; Gradle scanned textually. A manifest keeps one entry per key: a versioned declaration
  beats an unversioned one, otherwise the last wins (DECISIONS M2).
* **10/11 Output.** Jackson `JsonGenerator` with a configured `DefaultPrettyPrinter` (two spaces,
  `": "`, `[]`/`{}` for empty containers, `\n`, final newline). The document is serialised once
  without `serialNumber`, hashed, then again with it.
* **12 Determinism.** No hash-order leaks (all output sorted by code points), `Locale.ROOT`
  everywhere, file results merged in collection order, the scan root's last segment only.
* **13 Errors.** Any `RuntimeException` or `StackOverflowError` while analysing a file → warning,
  its findings discarded, counted as skipped. Malformed manifest → warning, no entries.

## Interpretations of unclear points (please review)

1. **Field initialisers always use the fallback lookup** (REVIEW m2, SPEC 7.4.5 advice made
   normative): identifiers inside field initialisers — also of local/anonymous classes inside
   methods — resolve via fields / static imports only, never via enclosing blocks. Same result
   for the analysed file and for cached cross-file contexts.
2. ~~**`param` counts as a condition key for Java specificity**~~ — superseded by DECISIONS O2
   (follow-up): `param` does not make a pattern specific. No bundled Java rule uses `param`.
3. **"Whitespace"** in receivers, `argsText`, `body` and Python method names means the
   `java.util.regex` `\s` set (space, TAB, LF, VT, FF, CR). Text-block indentation uses
   `Character.isWhitespace` (JLS).
4. **Comments** are named nodes in tree-sitter. They are excluded from Java argument lists (as
   specified), from array elements contributed to string lists and — since DECISIONS O3
   (follow-up) — from the `isConst` check of an `array_initializer`, so `{1, /* x */ 2}` is
   constant.
5. **Depth limits (DECISIONS M4).** `resolveName` beyond 16 binding steps: since DECISIONS O4
   (follow-up) the name and every name resolved through it have no candidates (no fallback to the
   name 16 steps up; before, a 20-step chain resolved to that name). `resolveDotted` with more than 64 attribute levels gives no
   candidates. `strings()` counts its argument as level 0: a string nested in 12 parentheses is
   still found, 13 is not (`python/deep-call-args` encodes exactly this). `shape` starts at depth
   0 for *F* (REVIEW m15).
6. **Cross-file candidates** (REVIEW m7): a candidate that is a symbolic link, or lies below a
   symbolically linked directory, is absent; the 10 MiB limit and the binary check (4.6) apply.
7. **Version ranges (9.1)** are never versions in Maven-ecosystem manifests either: a version that
   starts with `[`/`(`, ends with `]`/`)`, contains `,`, ends with `+` or starts with `latest.` is
   reported as no version (POM, Gradle, catalogs).
8. **Gradle** (REVIEW m6): `NAME` is `[A-Za-z_][A-Za-z0-9_]*`; each comment is replaced by one
   space; variable definitions are applied in order of their offset (later ones win); a map
   notation entry whose group/name still contains `$` after substitution is dropped, a version
   containing `$` becomes no version.
9. **pyproject PEP 508 strings** are parsed with the 9.2 regex; since DECISIONS O5 (follow-up) a
   string containing `://` (`pkg @ https://…`) is skipped as in requirements files.
10. **Dependency snippets**: Maven `g:a:v` / `g:a`; PyPI `<normalised name>==v` / `<name>`.
11. **rulesDigest** covers rule documents (`.yaml`, `.yml`, `.json`) with their paths relative to
    the rule directory; the bundled set and `rules/` (or an unchanged `rules export`) give the
    same digest. The `9e4…` prefix in the SPEC 11.5 example does not match (ours is `9e7f…`); I
    tried the obvious alternative definitions and none gives `9e4`, so I take the example value as
    illustrative.
12. **Counts**: `filesScanned` includes malformed manifests (they were analysed, 13 does not list
    them as skipped). The "findings" number of the final info line is the number of occurrences
    in the CBOM.
13. **`rules validate`** prints `source java: 88`, `source python: 79`, `constants java: 1`,
    `dependency maven: 1`, `dependency pypi: 1` on standard output (3.2's "nothing but the CBOM"
    is read as applying to `scan`). `rules export` failures exit with 5.
14. **YAML 1.2 (REVIEW m1)**: Jackson YAML with `PARSE_BOOLEAN_LIKE_WORDS_AS_STRINGS`, so
    `yes/no/on/off` are strings; duplicate keys and multi-document files are rejected. Other
    1.1-vs-1.2 differences (e.g. `010` as octal) are not special-cased.
15. **Schema messages**: a document whose `kind` is known is validated against that branch of the
    top-level `oneOf` only (equivalent, but the messages name the real problem). Semantic checks run
    after a document passes the schema.
16. **Test-file names**: `Test.java` and `IT.java` themselves match `*Test.java` / `*IT.java`.
17. **Python `kwargs` with a repeated keyword**: any occurrence of the keyword may satisfy the regex.
18. **Padding mapping** (11.3.1) is matched case-insensitively, like the mode mapping.
19. **Natives**: `-fvisibility=hidden` was dropped from the recipe (REVIEW m11: it was overridden by
    `-fvisibility=default` anyway; the resulting flags are identical). Maven calls
    `build-natives.sh ensure`, which builds only when `target/native/<platform>/` is incomplete
    (instead of a profile). `src/main/resources/rules/` is not a copied directory: the POM adds the
    repository's `rules/` as a resource with target path `rules/` (same jar layout).
20. **Temporary directory fallback** for native extraction also tries `$TMPDIR` when
    `java.io.tmpdir` is not writable.
21. **Licence header check**: com.mycila `license-maven-plugin` 4.6 in lenient mode
    (`strictCheck=false`), because the generated rule files continue the header comment with a
    "Generated by" line; `spec/tools/RegexParity.java` is mapped to `//` style. JSON, Markdown,
    vendored sources and conformance inputs are not checked.
22. **Extra dependency**: `org.slf4j:slf4j-api:2.0.17` is declared explicitly (it is already a
    transitive dependency of json-schema-validator) so that the silent provider can be
    registered; otherwise SLF4J prints a warning on every run.

No conformance difference remains, so there is no open spec question from the suite.

## Conformance cases added (DECISIONS.md)

* `deps/maven-managed-version` (2 POMs, 3 findings): `bcprov` versioned only in
  `<dependencyManagement>` via `${bc.version}` and unversioned in `<dependencies>` → `1.78.1`;
  the same with the managed declaration *after* the unversioned one → still versioned;
  `jjwt-api` without any version → no version.
* `python/deep-call-args` (1 file, 3 findings): `hashlib.new(` + 3 000 / 13 parentheses → no
  finding; 12 and 5 parentheses → MD5; a later `hashlib.md5()` is still found (no crash).
* `spec/conformance/README.md` lists both (25 cases, 562 findings) and says their expectations
  are hand-written.

## Tests

| Suite | Tests | What |
|---|---|---|
| `files.FilesTest` | 63 | globs (28 cases), classification, test files (31 cases), binary detection, decoding, walk (VCS dirs, links, excludes, `--exclude-tests`) |
| `rules.RuleLoaderTest` | 176 | bundled set (counts, order, digest = `rules/`), each of the 170 bundled documents validated on its own, schema/semantic errors with pointers, YAML 1.2 booleans, package patterns |
| `lang.java.JavaAnalysisTest` | 8 | escapes, text blocks, generics, `denotes`, SPEC example, nested duplicates, cross-file inside/outside scan root, 4 000-operand depth limit, overrides/body |
| `lang.python.PythonAnalysisTest` | 9 | imports/aliases, cycle guard, parameter shadowing, params, all three depth limits, (rule, line) rule, attribute assignment |
| `deps.ManifestsTest` | 18 | PEP 508 (10 cases), requirements, pyproject order, locks, POM properties/managed/ranges/comments, DOCTYPE rejected, Gradle, catalogs, normalisation |
| `cbom.CbomTest` | 8 | the six bom-refs of SPEC 11.5, collisions → 64 digits, serial-number UUID, purls, JSON layout and escaping, occurrence dedup, names/mode/padding |
| `natives.NativesTest` | 6 | platform ids, extraction, ABI 14/15, Appendix C field names, offsets/rows/fields of the copy, syntax-error flag, 5 000-level nesting |
| `ConformanceIT` | 51 | 25 cases through the jar, 25 CycloneDX 1.6 schema validations, suite totals / no empty components |
| `DeterminismIT` | 4 | byte-identical CBOMs for three option sets (threads 1 vs 8, other location/cwd/locale/TZ/charset), `SOURCE_DATE_EPOCH` |
| `CliIT` | 5 | relative paths from another cwd, `-o -`, exit codes 2/3/4/5/0, `rules validate/export`, `--version`, `--help` |

Total: 288 unit + 60 integration = **348 tests**, all passing. `mvn verify` takes about one minute.

## Timings

Machine: 32 cores, JDK 25.0.1, `-Xmx2g`, wall-clock including JVM start-up. (Before the
follow-up; see "Follow-up" below for the current numbers.)

| Input | Files | Lines | `--threads 1` | lines/s | `--threads 8` |
|---|---|---|---|---|---|
| Synthetic tree (conformance inputs ×134, renamed paths) | 10 000 (3 463 Java, 4 402 Python, rest manifests; 134 binary skipped) | 198 k | 19.3 s | ~10 k | 11.3 s (4 threads) |
| JDK 25 `lib/src.zip` | 15 020 Java | 5.10 M | 68 s | ~75 k | 41 s |
| Python 3.11 stdlib `/usr/lib/python3.11` | 1 715 Python | 838 k | 18 s | ~47 k | 9.8 s |

The synthetic tree is slow per line because every copy contains the pathological inputs of the
suite (a 4 000-operand Java concatenation and two 3 000-level Python nestings: deep trees cost
tree-sitter far more per line). On real code the non-binding guideline of ~9 000 lines/s is
exceeded several times. Start-up (`rules validate`) takes about 1.3 s, most of it rule-schema
validation of 170 documents. Both real code bases scanned without a single warning or failed
file; the outputs are byte-identical across thread counts.

The only performance change made after measuring was cheap: rows are computed from LF offsets
instead of calling `Node.getStartPoint()` per node (which allocates native memory). The remaining
overhead is jtreesitter creating one `Node` (with an automatic arena) per visited node during the
tree copy; avoiding it would need private API or own FFM bindings, which was not worth the
complexity under the relaxed SPEC 14. That per-node arena (a `Cleaner` registration) is also why
more threads help only about 1.7–2×: the JDK's single reference-handler/cleaner threads become
the bottleneck.

## Follow-up (2026-10-16): start-up, throughput, review items

Same clean-room rules as above. Decisions O1–O7 and F1–F3 are in `spec/DECISIONS.md`; SPEC.md
was updated where it describes the behaviour.

**Measurements** (same machine: 32 cores, JDK 25.0.1, `-Xmx2g`, wall clock including JVM start;
start-up is the median of 11 runs, throughput a single run each). Outputs are byte-identical
before/after, for every thread count, and with/without the pre-filter.

| | before | after |
|---|---|---|
| `scan` of a 2-file repository (natives cached) | 1.27 s | **0.53 s** (launcher 0.56 s) |
| same, no writable cache (natives extracted every run, as in this sandbox) | 1.27 s | 0.65 s |
| `rules validate` | 0.95 s | 0.30 s |
| `scan` with an optional JDK AOT cache (README) | – | 0.37 s |

| Input (lines) | threads | before | lines/s | after | lines/s | after, pre-filter off |
|---|---|---|---|---|---|---|
| JDK 25 `lib/src.zip`, 15 020 files (5.10 M) | 1 | 66.6 s | 77 k | **24.8 s** | 206 k | 63.0 s |
| | 4 | 38.0 s | 134 k | 11.5 s | 444 k | 33.2 s |
| | 8 | 41.2 s | 124 k | 10.8 s | 472 k | 32.4 s |
| Python 3.11 stdlib, 1 717 files (0.84 M) | 1 | 19.6 s | 43 k | **11.4 s** | 74 k | – |
| | 4 | 10.2 s | 82 k | 6.0 s | 140 k | – |
| | 8 | 10.4 s | 81 k | 5.9 s | 143 k | – |

**Where the time went (profiles).** JFR and per-phase timers on `java.base` (single thread):
native parsing 58 %, copying the tree into `SyntaxNode`s 36 %, analysis 5 %. Every visited node
makes jtreesitter create a `Node` whose constructor calls `Arena.ofAuto()`, i.e. registers a
`PhantomCleanable` with the JDK's single common `Cleaner`. With 8 threads 60 % of all samples
were in `CleanerImpl$CleanableList.insert` / `Cleaner.register` (one lock), and the
Common-Cleaner and Reference Handler threads were the busiest threads; this, not the analysis,
is why more threads helped so little. There is no public jtreesitter API that yields node data
without a `Node` (cursor, children, queries all create them), and own FFM bindings would bypass
jtreesitter (SPEC 6.1), so the per-node cost stays. What was done instead:

* **Pre-filter (F3)**, `scan/AnchorPrefilter`: one Aho–Corasick pass over the decoded text checks
  whether, for some pattern, all names it requires occur as substrings (Java: member and simple
  class name, Python: the identifier parts of `call` values, method names, keywords, attribute
  names, `anySymbol`/`allSymbols` parts). The soundness argument is in the class comment; a unit
  test checks on every conformance input that a rejected file really has no findings, and
  `DeterminismIT` compares the suite's CBOM with and without the filter
  (`-Dciphersift.noPrefilter=true`). JDK: 2 892 of 15 020 files (32 % of the text) pass; Python
  stdlib: 453 of 1 717 (65 % of the text — short names such as `sha`/`new` match often).
  Rejected files count as scanned; in `--verbose` they give no "syntax errors" debug line.
* **Tree copy**: one shared child stack instead of an `ArrayList` per node, the line-start table
  and the ASCII check in one pass, rows found incrementally (pre-order offsets only grow), and at
  most two threads copying at once (`Semaphore`), which removes most of the cleaner-lock
  contention (8 threads without pre-filter: 41.2 s → 32.4 s; 1, 2 and 3 permits were measured,
  2 was best). Parsers stay per thread, the scratch allocator per file.
* **Start-up (F2)**: `BundledRulesCheck` runs in `process-classes`, validates `target/classes/rules`
  in full (schema + 5.8), writes the parsed documents as one JSON array
  (`bundled-rules.json`), checks that the streaming `TreeReader` and that array reproduce the
  object mapper's trees exactly, and records a digest over rule files, schema and array
  (`bundled-rules.validated`); any problem fails the build. `loadBundled()` uses the array only
  if the digest of the jar's rule files, schema and array matches, else it validates in full.
  This removes the networknt validator, the `ObjectMapper` and the YAML parser from the start-up
  path (they are loaded lazily for `--rules`). The bundled rules are loaded on a background
  thread while picocli parses the command line (picocli's constructor alone takes ~0.2 s), and the
  native libraries and grammars — plus one throw-away parse per grammar to link the downcalls — on
  another one, early if the libraries are already in the cache (nothing is written then),
  otherwise after the scan root and output checks. Errors still surface in the specified order.
  The SHA-256 verification of the cached libraries is kept (SPEC 15.3 requires it on every run);
  regex compilation is negligible (~ms).
* **Java check (F1)**: `ch.unibe.seg.ciphersift.Main` is compiled with `--release 8` (second
  `maven-compiler-plugin` execution) and calls `cli.Main` reflectively after the version check;
  the launcher reads the runtime's `release` file (no extra JVM start) or falls back to
  `java -version`. Tested with JDK 8, 11, 21 (exit 6) and 25.
* **O1**: `files/FileNames` decodes names with non-ASCII characters from `Path.toUri()`'s raw
  bytes when `sun.jnu.encoding` is not UTF-8 (walk, scan-root name, rule paths) and resolves
  cross-file candidates by listing the directory in that case. Verified: identical CBOMs under
  `LC_ALL=C` and `C.UTF-8` for `café.py`, an undecodable name and a cross-file constant in
  `Ä.java` (before: `caf��.py`, and the constant was not found under C).

**Tests** now: 310 unit + 69 integration = 379 (new: pre-filter soundness and unit tests,
trusted-load equivalence and tamper detection, streaming reader vs mapper, `new: X*`, `param`
specificity, symbolic links in rule directories, binding-step limit O4, pyproject direct
references, Java version parsing, launcher selection with fake runtimes, pre-filter on/off and
non-ASCII names under a C locale in `DeterminismIT`). Conformance: 28/28 cases, 573/573
findings (JUnit runner and `spec/tools/conformance.py`); the three new cases fail on the
pre-follow-up jar, as intended.

## Known limitations and possible issues

* Natives are built and bundled for linux-x86_64 only (other platforms: cross-compile into
  `target/native/<platform>/`, as the spec allows).
* Memory: frozen cross-file contexts keep every field initialiser of a looked-up file (bounded by
  depth 16, but wide array initialisers are kept in full).
* The JVM's own exit code 130 is relied on for SIGINT; no CBOM is written in that case.
* `Parser` objects of worker threads are closed from the main thread at the end of a scan
  (exceptions ignored); the JVM exits right after in the CLI anyway.
* The design limitations of SPEC Appendix B apply unchanged.

## Evaluation fixes (2026-10-17)

Work list `ciphersift-eval/ISSUES.md`; decisions E1–E18 in `spec/DECISIONS.md`; SPEC.md updated.
What changed in the implementation:

* **Bare references (SPEC 8.6.1).** The collection walk of `PythonAnalyzer` also records
  `identifier` / `attribute` nodes whose parent can make them a value or expression position
  (cheap parent check), in the same pre-order list as the calls, so the per-rule nesting check
  (`hmac.new(k, m, hashlib.sha256)` → one SHA-2) works unchanged. `matchReference` resolves the
  node with `resolveDotted` (memoised as before), looks the names up in `PythonRuleIndex.byRef`
  (exact names of `ref` patterns and of condition-free `call` patterns), and only then walks up to
  decide the position (`valuePosition(node, operands)`). No argument analysis, no ranges.
* **New Python conditions**: `dictItems` (`dictItemsHold`: dictionary displays among the arguments,
  or names bound to one), `notInside` (the existing 8.7 walk), `param: {value}`; method-only
  `anySymbol` hits are named after the first hitting listed symbol.
* **Weakness indicators**: `SourceRule.indicator()`; `CbomWriter` writes `ciphersift:indicator` and
  the metadata property `ciphersift:weaknessIndicators`; `Scanner` drops indicator findings after
  extraction (`Options.weaknessIndicators`), so selection and folding of the other findings are
  untouched. (Since the owner decisions below, indicators are opt-in with `--weakness-indicators`.)
* **`setup.py` / `setup.cfg`**: `FileClass.SETUP_CFG`; `Scanner.process` parses a `setup.py` whose text
  contains `install_requires` or `extras_require` even when the pre-filter rejects it, runs the Python
  analysis as usual and adds `DependencyScanner.setupPy` findings (the file stays a Python file in the
  counts). `SetupManifests` reads literal requirement lists from the tree and `setup.cfg` line by line.
* **Java member types (SPEC 7.3.2 step 6)**: `JavaAnalyzer.denotes` accepts an unqualified member-type
  name only when its enclosing class is imported on demand or statically.
* **Pre-filter**: `call`/`method` patterns also require their `kwargs` keywords and `dictItems` keys;
  Java class names of member types also require the top-level class name; `ref` patterns their
  identifier parts. Without these, `method: [get, post, …]` (E14) and `new: …ConnectionSpec.Builder`
  (E7) let most files through: the Python stdlib took 21.5 s instead of 11.8 s single-threaded in the
  first build of the fixes. The soundness test (`AnchorPrefilterTest`) covers the new cases.
* **Grammar field check** (Appendix C): Python field `key` (of `pair`) added.
* **Tests**: 326 unit + 100 integration = 426 (new: rule-key loading, indicator property and metadata,
  `--no-weakness-indicators` through the jar, `setup.cfg`, related-material types, member-type
  pre-filter; Python analysis tests now include the alias-definition references). Conformance: 43/43
  cases, 736/736 findings, with the JUnit runner and `spec/tools/conformance.py`;
  `spec/tools/regex_parity.py`: 69 300 probes, no mismatch (it now also checks `dictItems` values).
* **Rule generation**: the rule edits were applied with a small script (outside the repository) and
  then hand-adjusted; generated files that were changed say so in their header.
* **Speed** (same machine, now shared with other load — load average 5–6, which is why the 1.0
  jar is slower than in the follow-up table above; both jars measured interleaved, two runs each,
  wall clock incl. JVM start, `-Xmx2g`):

  | Input | threads | 1.0 follow-up jar | with the fixes |
  |---|---|---|---|
  | JDK 25 `lib/src.zip` (15 020 files) | 1 | 28.9 s, 28.9 s | 18.0 s, 17.2 s |
  | | 8 | 11.1 s, 11.1 s | 6.4 s, 6.2 s |
  | Python 3.11 stdlib (1 715 files) | 1 | 14.2 s, 14.7 s | 14.5 s, 15.2 s |
  | | 8 | 5.8 s, 5.3 s | 5.8 s, 5.6 s |

  The JDK scan got faster because the member-type rule of the pre-filter now also applies to the
  existing nested-class patterns (`KeyStore.Builder`, `Argon2Parameters.Builder`), which let every
  file mentioning `Builder` through; no JDK finding of the earlier version is lost (175 added). The
  Python stdlib stays within ~5 % (bare-reference resolution; 68 findings added). Output is
  byte-identical for 1 and 8 threads (DeterminismIT and spot checks on the evaluation projects).

## Owner decisions (2026-10-17)

Decisions in `spec/DECISIONS.md` ("Owner decisions"); SPEC.md, README, CHANGELOG, rules and the
conformance suite updated.

* **E2, indicators opt-in.** `ScanCommand` has `--weakness-indicators` instead of
  `--no-weakness-indicators`; `Scanner.Options` and `CbomWriter.Metadata` default to *off*; the
  metadata property is now `ciphersift:weaknessIndicators=included` with the option (absent by
  default). Extraction is unchanged (indicator findings are still computed and then dropped), so
  the other findings stay byte-identical with and without the option.
* **E15, OID table.** `lang/OidTable` holds the 128 rows of SPEC 5.11 (one source; `OidTableTest`
  compares it with the SPEC table row by row). `JavaAnalyzer.strings` maps the resolved string list
  once per event and keeps a parallel list of OIDs; `matchedIndex` replaces `matchedString`, so the
  `Selected` pair carries the matched string and its OID; `param` values go through
  `OidTable.map`. `PythonAnalyzer.Args.strings` does the same; `valueTexts` appends the name after
  an OID string or constant; `matchedOid` finds the OID for `firstString`, `stringContains` and the
  first `dictItems` entry. `SourceFinding` and `Component.Crypto` gained `oid` (old constructors
  kept); the normaliser key and component order include it; `CbomWriter` writes
  `cryptoProperties.oid` and appends the OID to the bom-ref array only when present, so every
  other bom-ref is unchanged. `lookup` rejects anything that does not start with a digit or `o`/`O`
  before running the regex (it runs for every string-list element).
* **Rules for E15** were generated by a script outside the repository from the same table
  (`new ASN1ObjectIdentifier` patterns in 39 Java rules; four Python OID constructors in 33 Python
  rules; the asn1crypto `algos.*` regexes of 20 rules extended with the names). `java.kdf.pbkdf2`
  accepts `PBKDF2` in `SecretKeyFactory.getInstance`.
* **E16, Shiro.** Ten rules `java.lib.shiro.*` (hand-written from Shiro's public API, both package
  generations) and Shiro's `ALGORITHM_NAME` / `DEFAULT_ALGORITHM_NAME` constants in
  `_constants.yaml`. `setHashAlgorithmName` / `setDefaultAlgorithmName` are `method` patterns (the
  receiver is a variable), filtered by an algorithm-name `firstString`.
* **Tests**: 340 unit + 106 integration = 446, all passing (new: `OidTableTest`, CBOM `oid`
  output and bom-ref, `--weakness-indicators` through the jar and rejection of the old option).
  Conformance: 46/46 cases, 1021/1021 findings (JUnit runner and `spec/tools/conformance.py`);
  `spec/tools/regex_parity.py`: 106 722 probes, no mismatch; `spec/tools/check_rules.py`: 103 Java,
  87 Python rules valid.
* **Speed** (same machine, load average 3–7; interleaved with the 1.0 follow-up jar as reference,
  two runs each, wall clock incl. JVM start, `-Xmx2g`):

  | Input | threads | 1.0 follow-up jar | with the owner decisions |
  |---|---|---|---|
  | JDK 25 `lib/src.zip` (15 020 files) | 1 | 23.2 s, 24.1 s | 13.5 s, 16.7 s |
  | | 8 | 11.0 s, 11.1 s | 6.3 s, 6.2 s |
  | Python 3.11 stdlib (1 715 files) | 1 | 14.2 s, 13.7 s | 13.9 s, 14.5 s |
  | | 8 | 5.8 s, 5.5 s | 5.5 s, 6.0 s |

  Same ratios as with the evaluation fixes: the OID lookup (a first-character check before the
  regex) and the ten Shiro rules cost nothing measurable. Against the evaluation-fix outputs the
  default scan only lost the insecure-PRNG findings (JDK 63, stdlib 350); no other finding changed,
  and none was added (neither corpus passes OID literals to an anchored API). Output for 1 and 8
  threads is byte-identical on both corpora.
