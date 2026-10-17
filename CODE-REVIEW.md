<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 The CipherSift Authors -->

# CipherSift 1.0 — code review

Reviewed: the implementation in this directory against `spec/SPEC.md` (with `spec/DECISIONS.md`
and `spec/REVIEW.md`), the rule schema, the conformance suite, the rules and the delivered
documentation. Clean-room rules were respected (nothing outside this directory was read).
All fixes were made in the working tree before the first commit of the implementation (062f8c3).

## Verdict

**Ready for benchmarking: yes**, with the fixes below applied. Conformance stays at
**25/25 cases, 562/562 findings** (JUnit runner and `spec/tools/conformance.py`), every CBOM
validates against CycloneDX 1.6, output is byte-identical across thread counts and locations.
One blocker (whole-scan crash on non-ASCII file names under a non-UTF-8 locale) and six major
issues were found and fixed. What remains open are owner decisions with no or very rare effect
on detection results (see "Open items").

Run the benchmark through `bin/ciphersift` or the Docker image (both now force a UTF-8 locale),
or set `LC_ALL=C.UTF-8` when calling `java -jar` directly (open item O1).

| Severity | Found | Fixed | Open |
|---|---|---|---|
| Blocker | 1 | 1 | 0 |
| Major | 6 | 5 | 1 (O1, mitigated) |
| Minor | 14 | 8 | 6 |
| Nit | 8 | 5 | 3 |

Tests: before 288 unit + 60 integration = **348**; after **298 unit + 60 integration = 358**
(new: map-notation fuzz/linearity, undecodable file names, bounded no-follow reads, private
native cache, log sanitising, `SOURCE_DATE_EPOCH`, lone surrogates (2), Python nesting ranges,
Java local-declaration lookup). `mvn verify` green, licence-header check green, the jar is
reproducible (identical SHA-256 for two clean builds, natives included).

## Findings

Line numbers refer to the files after the fixes.

### Blocker

**B1 — Non-ASCII or undecodable file names abort the scan or are silently lost** — fixed
`src/main/java/ch/unibe/seg/ciphersift/files/FileCollector.java:57`.
The walk rebuilt every path from its decoded name (`dir.resolve(name)`, `root.resolve(relDir)`).
Under a non-UTF-8 locale (C/POSIX — common in CI, cron, minimal containers) any non-ASCII file
name made `resolve` throw `InvalidPathException`, which escaped as an internal error: **exit 1,
no CBOM for the whole repository**. Under a UTF-8 locale, names with invalid UTF-8 bytes were
re-encoded to a different file, logged as "cannot read attributes" and dropped.
*Fix:* the walk keeps the `Path` objects from the `DirectoryStream` and uses the decoded name
only for sorting, globbing, classification and output. Test
`FilesTest.undecodableFileNamesStayReachable`.

### Major

**M1 — Gradle map-notation regex backtracks catastrophically (hang)** — fixed
`deps/MavenManifests.java:268`, new `deps/MapNotation.java`.
The SPEC 9.6 step 4 regex `group\s*[:=]\s*(['"])(.+?)\1\s*,\s*name…` rescans the rest of the
line for every `group:'…'` without a following `name`. A 1.8 MB one-line `build.gradle`
(`group:'a'` × 200 000) ran for more than 5 minutes (killed); a 10 MiB file would take hours.
Untrusted repositories can stall the benchmark.
*Fix:* `MapNotation` computes exactly the matches and groups of `Matcher.find()` with that regex
in O(n log n) (the three lazy groups are resolved with sorted quote/line-terminator offsets; the
rest of the pattern is deterministic). The regex stays as the reference. Tests:
`ManifestsTest.mapNotationEqualsRegex` (60 000 random inputs, 1 731 matches, compared with the
regex group by group), `mapNotationIsLinear`.

**M2 — Python nesting check is quadratic in the number of findings** — fixed
`lang/python/PythonAnalyzer.java:874`.
Every emitted hit scanned all argument ranges recorded so far for its rule. One 3.6 MB file with
200 000 `hashlib.md5(…)` calls took **174 s**. *Fix:* calls arrive in pre-order (non-decreasing
start offsets), so ranges ending at or before the current call can never contain it or a later
call and are dropped; the list stays at nesting depth. Same file now 7.7 s; same results.
Test `PythonAnalysisTest.nestingRangesAcrossSiblingsAndLines`.

**M3 — Fat jar / Docker image shipped without the required licence texts** — fixed
`pom.xml` (resources), `NOTICE`, new `src/main/resources/META-INF/ciphersift/licenses/`.
MIT requires the copyright and permission notice "in all copies". The jar (and therefore the
Docker image, which contains only the jar) had no licence text for tree-sitter, tree-sitter-java,
tree-sitter-python, jtreesitter, SLF4J (its `META-INF/LICENSE.txt` is removed by the shade
`ApacheLicenseResourceTransformer`), nor CipherSift's own `LICENSE`/`NOTICE`. NOTICE did not
mention the ICU headers compiled into `libtree-sitter` (Unicode licence, `lib/src/unicode/`),
gave a generic jtreesitter copyright line and a wrong SLF4J year.
*Fix:* the jar now contains `META-INF/ciphersift/{LICENSE,NOTICE}` and
`META-INF/ciphersift/licenses/<component>/LICENSE` (copied from `native/vendor/`, plus the
jtreesitter v0.26.1 and SLF4J 2.0.17 texts); NOTICE lists ICU and the exact copyright lines.
The vendored sources were checked against the pinned tarballs (SHA-256 OK, `src/`, `lib/` and
LICENSE files identical).

**M4 — Native libraries are verified and then loaded from a directory others may control** — fixed
`natives/NativeLibraries.java:189`.
The SHA-256 check happens before `dlopen` by path, but the cache directory was used without
any ownership or permission check. With `XDG_CACHE_HOME` under a shared `/tmp` (as in the
Dockerfile), a pre-created or group-writable directory (umask 002 is the Debian/Ubuntu default
for users) lets another user swap a library between verification and loading — code execution as
the scanning user. *Fix:* cache directories are created with mode 0700; the digest directory and
its two parents must be real directories owned by the current user (or root) and not group- or
world-writable (own directories created group-writable earlier are tightened); otherwise the
fresh private temporary directory is used. Residual risk (a writable `$XDG_CACHE_HOME` itself)
is documented in the code. Test `NativesTest.cacheDirectoryMustBePrivate`.

**M5 — Reported paths depend on the locale (SPEC 12)** — mitigated, open as **O1**
`bin/ciphersift`, `Dockerfile`, `README.md`.
The JVM decodes file names with `sun.jnu.encoding`, which follows the locale and cannot be
overridden (`-Dsun.jnu.encoding=UTF-8` is ignored, verified). After B1, `café.py` is reported as
`café.py` under a UTF-8 locale but as `caf��.py` under `LC_ALL=C`. *Fix:* the launcher
sets `LC_ALL=C.UTF-8` on Linux when the current charset is not UTF-8, the Dockerfile sets
`LC_ALL=C.UTF-8`, README states the caveat. Plain `java -jar` remains locale-dependent for
non-ASCII names (owner decision, see O1). `DeterminismIT` passes the ineffective
`-Dsun.jnu.encoding` flag and the suite has only ASCII paths, so it cannot catch this.

**M6 — Documented Docker command cannot write its output; output files were mode 0600** — fixed
`cli/ScanCommand.java:211`, `README.md`.
The image runs as uid 10001; `-v "$PWD/out:/out"` is owned by the host user, so the documented
`docker run … -o /out/cbom.cdx.json` exits 5. And because the temporary file came from
`Files.createTempFile` (always 0600), every CBOM was readable only by its creator — a CBOM written
by the container into a mounted directory would not be readable by the host user.
*Fix:* the temporary file is created with `Files.createFile` (umask-respecting, as a plain write
would be) under a random name, then renamed atomically as before; README's Docker line adds
`--user "$(id -u):$(id -g)"`. SPEC 15.4 shows the old command (owner: update the spec text).

### Minor

| # | Location | Problem | Fix / recommendation | Status |
|---|---|---|---|---|
| m1 | `lang/java/JavaResolver.java:174` | 7.4.3 local lookup rescanned all earlier statements of each enclosing block for every identifier: 100 000 lookups in one method took 66 s (quadratic; generated code with big static initialisers). | Per-block index of local declarations by name, binary search for the last one before the use; 5.3 s, identical results. Test `localDeclarationLookup`. | fixed |
| m2 | `cli/Log.java:56` | Log lines contain file names from the untrusted repository verbatim: ESC sequences reach the terminal, newlines forge extra `ciphersift: …` lines. | Control characters (C0, DEL, C1) are written as `\uXXXX`. Test `CliUnitTest`. | fixed |
| m3 | `lang/java/JavaStrings.java:192` | Unicode escapes (`"AES/GCM/NoPadding\uD800"`) produce lone surrogates that became component names and bom-ref input; Jackson writes them as `\uD800`, ill-formed Unicode that strict consumers reject (SPEC 11.6 says this cannot occur). | Unpaired surrogates in decoded literals become U+FFFD. Tests in `JavaAnalysisTest`. | fixed |
| m4 | `files/SourceText.java:42`, `scan/Scanner.java:170`, `lang/java/JavaContexts.java:75` | `Files.readAllBytes` follows a symbolic link that replaced a collected file (TOCTOU; could read files outside the scan root into snippets) and reads a file that grew past 10 MiB completely before checking. | `readBounded`: `NOFOLLOW_LINKS`, at most 10 MiB + 1 byte. Test `boundedReadsDoNotFollowLinks`. | fixed |
| m5 | `cli/ScanCommand.java:173` | `SOURCE_DATE_EPOCH` above `Instant.MAX` (e.g. `99999999999999999`) made `Instant.ofEpochSecond` throw: exit 1. | Values an `Instant` cannot hold are ignored like other invalid values. Test. | fixed |
| m6 | `scan/Scanner.java:91` | `--threads 100000` created 100 000 threads. | Pool size capped at the number of files (output unchanged). | fixed |
| m7 | `syntax/SyntaxTrees.java:50` | The offset map was built between `parse` and the try-with-resources that closes the tree: an `OutOfMemoryError` there leaked the native tree. | Built before parsing. | fixed |
| m8 | `lang/java/JavaResolver.java:297` | A qualifier that is no valid file name (broken source) would make `Path.resolve` throw and fail the whole file. | Such a candidate is treated as absent (defensive; not reproduced with tree-sitter's error recovery). | fixed |
| m9 | `rules/RuleLoader.java:451` | `new: a.B*` passes the schema (`javaQualifiedName` allows `*`) although SPEC 5.5 says "No `*`"; it then acts as a prefix index key with an exact `denotes`, i.e. half a prefix. | Add a 5.8 semantic check (owner/spec decision). | open |
| m10 | `rules/RuleLoader.java:124` | `--rules DIR` follows symbolic links to files (`Files::isRegularFile`), unlike the scan walk (4.1). Only the user's own rule directory is affected. | Decide whether links in rule directories are allowed; if not, use `NOFOLLOW_LINKS`. | open |
| m11 | `deps/MavenManifests.java:151` | `FEATURE_SECURE_PROCESSING` sets `jdk.xml.maxElementDepth` to 100: a POM nested deeper is skipped as malformed (with a warning). Real POMs are far shallower; deep XML bombs are rejected cleanly (tested, as are 200 000-deep TOML/JSON: Jackson's nesting limit 1 000). | Keep; mention in Appendix B if desired. | open (informational) |
| m12 | `lang/java/JavaContexts.java:57` | The cross-file context cache is unbounded for the whole scan (every looked-up file's field initialisers). Fine for the benchmark sizes measured by the implementer (5 M lines). | Consider a size bound if memory becomes an issue. | open (informational) |
| m13 | `scan/Scanner.java` | No parse timeout for tree-sitter (jtreesitter 0.26 supports progress callbacks). Deeply nested input (100 000 levels, 4.5 MB of nested `def`s) parsed quickly in tests. | Optional per-file timeout. | open (informational) |
| m14 | `src/test/.../DeterminismIT.java:62` | The locale part of the determinism test cannot fail: `-Dsun.jnu.encoding` is ignored by the JDK, `tr_TR.ISO-8859-9` may not be installed, and all suite paths are ASCII. | Add a non-ASCII path case once O1 is decided. | open |

### Nits

| # | Location | Problem | Status |
|---|---|---|---|
| n1 | `files/Glob.java:73` | Dead `if/else` with identical branches and a comment describing code that did not exist. | fixed |
| n2 | `.dockerignore` | The tool directory `.claude/` went into the Docker build context. | fixed |
| n3 | several | `JsonNode.fields()` is deprecated in Jackson 2.22 (7 compiler warnings). Replaced by `properties().iterator()` (same order). | fixed |
| n4 | `natives/NativeLibraries.java` | `allPresent(dir)` only checked that the directory exists. Replaced by `privateDirectory` (M4). | fixed |
| n5 | `NOTICE` | jtreesitter copyright line was a placeholder. | fixed (M3) |
| n6 | `bin/ciphersift` | With a Java < 23 on `PATH` the launcher fails with a raw `UnsupportedClassVersionError`; a version check with a clear message would help. | open |
| n7 | `IMPLEMENTATION-NOTES.md` | Test counts and the "temporary directory if not writable" wording describe the state before this review. | open (historical document) |
| n8 | `rules/**/*.yaml` line 3 | Generated headers say "Generated by spec/tools/convert_rules.py from the BF-CBOM rule src.java….yaml". That is the documented provenance (PROVENANCE.md), not a leak, but the upstream rule ids remain visible in every published rule. | open (owner: keep or shorten) |

### Checked and found correct

* **Spec sections 4, 5, 7, 8, 9, 10, 11, 12, 13** were read against the code. Highlights that are
  correct but easy to get wrong: first-holding pattern of maximal specificity (with a sound early
  skip), grouping by rule asset type (so `key-material` and `algorithm` coexist), nested-duplicate
  check against pre-drop selections, `denotes` steps 1–6, decl line from the `name` node, 7.4.3
  walk including parameter/enhanced-for shadowing, cross-file candidates `a/b/Outer/Inner.java`
  then `a/b/Outer.java`, D3/D9 array handling, JLS text blocks, Python scope/parameter binding,
  cycle guard skipping only step 1, memoisation of `resolveName` (only untainted results, with
  their step height — the soundness argument holds: any cached result reused under a larger
  guard set would imply a cycle that tainted it), candidate order, refinement, `reportAt` walk,
  `(rule, line)` set shared with assignments, M2 de-duplication, POM property rounds, purl
  encoding, bom-ref collision handling, serial number, code-point ordering everywhere,
  `Locale.ROOT` everywhere, no hash-order leaks into output.
* **Targeted probes** (all as specified): static imports, cross-file and nested-class
  constants, `this.F`, final vs reassigned locals, parameters, enhanced-for, lambdas, text
  blocks, alias chains, parameter shadowing in functions and lambdas, `reportAt` across lines,
  `verify=False`, attribute assignments, class-body names.
* **Stack safety:** 100 000-deep parentheses and lists, 100 000-level attribute chains,
  200 000-operand concatenations, 50 000 nested Java blocks, 3 000 nested anonymous classes,
  20 000 nested lambdas, 3 000 nested `def`s, a 5 000-step alias chain — no failure, results as
  the depth limits prescribe.
* **XML/TOML/JSON:** DOCTYPE and entities rejected (XXE/billion laughs impossible), deep nesting
  rejected with a warning. **Binary files** skipped. **Symbolic links** never followed in the walk
  or in cross-file lookup. No zip/jar input is read.
* **Thread safety:** shared state is immutable (rules, indexes) or concurrent (context cache,
  symbol tables); per-file state is thread-confined; frozen contexts are published after
  freezing. **Resources:** trees, cursors and arenas closed by try-with-resources; parsers closed
  at the end of a scan.
* **Build:** versions pinned as in 15.2 / M3 (Jackson 2.22.3 via BOM, networknt 2.0.4, picocli
  4.7.7, JUnit 6.1.3, jtreesitter 0.26.1; all plugins pinned); `release 23`; jar reproducible;
  runs from any working directory; every documented command in README works (`rules
  validate/export`, `--rules`, `--version`, `-o -`, `conformance.py --cmd/--show`). Docker could
  not be run here (no access to the Docker daemon); the Dockerfile was reviewed statically: it
  builds with network access (Maven downloads), copies only the jar, runs as an unprivileged user.
* **Provenance:** no occurrence of "crypsy", "crypistry", "cryben", "Näther" or "Hirsch", and no
  absolute local path, in code, tests, README, CHANGELOG, NOTICE or IMPLEMENTATION-NOTES. The
  only hits are in the delivered `spec/` documents (PROVENANCE, REVIEW, conformance README,
  `make_expected.py`, `convert_rules.py`), where they document provenance as intended, and the
  rule headers (n8). All source files carry the SPDX header.
* **Tests** assert behaviour (exact finding lists, bytes, exit codes), not just execution.

## The 22 interpretations (IMPLEMENTATION-NOTES.md)

| # | Topic | Verdict | Detection impact |
|---|---|---|---|
| 1 | Field initialisers use the fallback lookup only | Sound; matches the 7.4.5 advice and REVIEW m2. Differs from a literal 7.4.3 reading only for fields of local/anonymous classes inside methods that reference enclosing locals. | rare |
| 2 | `param` counts as a condition (specificity 2) | Questionable: SPEC 1.3 defines a condition as restricting the anchor, and 5.5 calls `param` "not a filter". I would make it bare. **Owner decision** (O2). | none today (no bundled Java rule uses `param`) |
| 3 | Whitespace = `\s` set; text blocks use `Character.isWhitespace` | Sound. | none |
| 4 | Comments in array initialisers make `isConst` false | Literal reading of 7.4.7 (comments are named nodes), but it contradicts the intent (comments are excluded from arguments and string lists elsewhere): `new byte[] {1, /* x */ 2}` is no hard-coded key. **Owner decision** (O3); I recommend ignoring comments. | rare false negatives |
| 5 | Depth limits (M4) | Sound and consistent with Java `value` (a string in 12 parentheses is found, 13 is not). Beyond 16 binding steps the chain resolves to the name 16 steps up rather than "no candidates"; defensible reading of "unresolved for that expression", but worth confirming (O4). | only alias chains > 16 |
| 6 | Cross-file candidates: links absent, binary check applies | Sound (REVIEW m7 recommendation). | negligible |
| 7 | Version ranges never versions in Maven manifests | Sound (9.1 applies to all formats). | library versions only |
| 8 | Gradle details | Sound. | none |
| 9 | pyproject PEP 508 without the requirements skip rules | Reasonable, but makes `pkg @ https://…` a finding in pyproject while the same line is skipped in requirements files. **Owner decision** (O5). | rare extra library findings |
| 10 | Dependency snippets | Sound (matches 11.4). | none |
| 11 | rulesDigest, `9e4…` example | Sound; the example value is illustrative. | none |
| 12 | Counts (`filesScanned` includes malformed manifests) | Sound. | metadata only |
| 13 | `rules validate` on stdout; export failures exit 5 | Sound. | none |
| 14 | YAML 1.2 booleans only | Acceptable (REVIEW m1); 1.1 octal/sexagesimal integers are not special-cased, no bundled rule is affected. | none |
| 15 | Schema branch per `kind` | Sound (equivalent to the `oneOf`). | none |
| 16 | `Test.java`, `IT.java` are tests | Sound (`*` matches the empty string). | test flag only |
| 17 | Repeated Python keyword | Sound (a syntax error in Python anyway). | none |
| 18 | Padding mapping case-insensitive | Sound; no bundled variant differs by case. | none |
| 19 | Native build details, rules as resource | Sound; flags identical, jar layout identical. | none |
| 20 | `$TMPDIR` fallback | Sound. | none |
| 21 | Lenient licence-header check | Acceptable (generated rule headers have a third line). | none |
| 22 | Explicit `slf4j-api` 2.0.17 | Sound: the same version networknt 2.0.4 uses; listed in NOTICE. | none |

## Open items needing an owner decision

* **O1 (M5)** — Locale and file names: require a UTF-8 locale for `java -jar` (document in SPEC
  12/15), or keep the launcher/Docker mitigation as the supported way. For the benchmark: run via
  `bin/ciphersift`/Docker or set `LC_ALL=C.UTF-8`.
* **O2 (interp. 2)** — Is `param` a condition for Java specificity? Recommendation: no.
* **O3 (interp. 4)** — Ignore comments in `isConst` array initialisers? Recommendation: yes.
* **O4 (interp. 5)** — `resolveName` beyond 16 steps: "name at the limit" (current) or no
  candidates.
* **O5 (interp. 9)** — Apply the `://` skip rule to pyproject PEP 508 strings?
* **O6 (m9, m10)** — Reject `new: …*` at load time; allow symbolic links in `--rules` directories?
* **O7 (M6)** — Update SPEC 15.4's usage line (`--user`) and Dockerfile (`LC_ALL`) to match.

## Effects on benchmark results

* **B1** changes results for any repository with non-ASCII file names when run under a
  non-UTF-8 locale: before, the whole scan failed (exit 1, no CBOM); now it is scanned. Under a
  UTF-8 locale, files whose names are not valid UTF-8 are now scanned instead of dropped.
* **m3** changes the component name of matches whose string contains a lone-surrogate escape
  (U+FFFD instead of the surrogate); practically never seen.
* **M1, M2, m1** change only run time (no result changes; M1 verified against the regex on
  60 000 inputs, M2/m1 by the conformance suite and new tests). Before the fix, a crafted or
  generated Gradle file could stall a benchmark run indefinitely.
* Open interpretations O2–O5 can change findings only in rare corner cases (none in the
  conformance suite).

## Follow-up (2026-10-16)

The open items O1–O7 were decided by the follow-up per the recommendations above and recorded in
`spec/DECISIONS.md` (with SPEC.md updated); n6 (launcher version check) and m14 (a determinism
test with non-ASCII paths under a C locale) were done as well. Note on m9: the schema's
`if`/`then` branch for `new` already rejected `new: X*`, only with a bare regex message; the
loader now reports it in words.

## Go extension (2026-10-17)

Self-review of the Go support (SPEC section 17, DECISIONS G1–G16) by its implementer, done as a
strict re-read of the whole diff (code, rules, schema, tests, conformance cases, documents) against
the new spec section, before the evaluation on the BF-CBOM corpora. Clean-room rules respected: no
Crypsy material and no other scanner's Go rules or code were read (`spec/PROVENANCE.md`).

**Verdict: ready for evaluation.** `mvn verify` green (430 unit + 181 integration tests), the
conformance suite passes 55/55 cases, 1178/1178 findings (JUnit runner and
`spec/tools/conformance.py`), every CBOM validates against CycloneDX 1.7 and 1.6, determinism
(threads, locations) holds for the Go cases too, `check_rules.py` and `regex_parity.py` pass
(106 920 probes). Java and Python CBOMs of micro-java, micro-python and the 46 earlier conformance
inputs are byte-identical to those of 88936e3 apart from `rulesDigest` and the derived
`serialNumber`.

| Severity | Found | Fixed | Open |
|---|---|---|---|
| Major | 2 | 2 | 0 |
| Minor | 4 | 4 | 0 |
| By design (documented) | 5 | – | 5 |

### Major

**GM1 — Plain assignments in another function did not make a package variable non-constant** — fixed
`lang/go/GoAnalyzer.java` (`declarations`, `Assignment`). Bindings were stored in the innermost
function scope of the *statement*, so `var bits = 1024; func init() { bits = 2048 }` left `bits`
resolved to 1024 in every other function, and a closure assigning an outer variable was invisible
to its enclosing function. *Fix:* declarations bind where they are; plain, compound and `++`/`--`
assignments and `range … =` are attached after the walk to the innermost scope that declares the
name (else the file). Spec 17.6 updated; cases `go/constants` (`twice`), unit test
`plainAssignmentsBindWhereDeclared`.

**GM2 — Dot imports gave names to unexported identifiers** — fixed `dotNames`. With
`import . "math/rand"` every lower-case identifier (`len`, `_`, local names in other files) got
the name `math/rand.<id>` and matched the `math/rand.*` prefix rule. Only exported (upper-case)
identifiers are visible through a dot import; spec 17.4 says so now. Unit test
`weaknessIndicatorPrefixAndExportedDotNames`.

### Minor

* **Gm1** `\uD800`-style escapes produced lone surrogates (SPEC 11.6 excludes them from the
  output; Go rejects them as well) — such an escape now keeps its text. Test `interpretedStrings`.
* **Gm2** The param-candidate walk recursed through unary operators (`^^^…x`, 3 000 deep) — now an
  iterative loop over parentheses and unary operators. Test `deepNestingDoesNotCrash`.
* **Gm3** `require(` without a space in `go.mod` was not recognised as a block — normalised.
* **Gm4** A redundant always-true bounds test in the octal-escape branch obscured the logic —
  removed (behaviour unchanged).

### By design (documented in SPEC Appendix B / 17, README)

* **GD1** No shadowing check for qualified selectors: a local variable named like an imported
  package (legal when that scope does not use the package) is taken as the package; only names
  that a rule lists can produce a finding, and such collisions are unlikely.
* **GD2** `assign` patterns check the field name, not the struct type: `InsecureSkipVerify: true`
  in a project's own config struct is reported too (the field name is specific enough; Python's
  `assign` behaves the same).
* **GD3** Declared names for dot imports are file-wide, resolution is flow-insensitive within a
  function and block scopes are not distinguished (as in Python).
* **GD4** Constants are resolved within the file only (no package-wide lookup across files, no
  other packages' constants).
* **GD5** A write to a package variable (`rand.Reader = fake` in a test) is a reference like a read.

Checked without findings: thread safety (the analyzer holds only the immutable index; all state
is per file), determinism (no hash-order output; candidate lists sorted by rule order and pattern
position; `LinkedHashSet`s for bound names and symbols), the pre-filter's soundness argument (the
import path occurs literally in the import spec because escapes in import paths are not
interpreted; the member is the selector field, the dot-imported identifier or the type name; the
existing soundness test now also runs over the Go inputs and rejects `go/names/pkg/plain.go`),
the CycloneDX mapping of every Go family (`CycloneDx17Test`), the licence (MIT text in the jar
under `META-INF/ciphersift/licenses/tree-sitter-go/`, `NOTICE`), the checksum pin (fetching
reproduces the committed Java/Python vendor trees byte for byte), header checks (Go conformance
inputs are excluded like the others).

## Fix round F1–F8 (2026-10-17, self-review of the diff)

Scope: `PythonAnalyzer` (import alternatives), `FileClass` / `FileCollector` (interpreter
lines), 16 rule files (+ `go.pqc.mldsa`), the three dependency lists, SPEC 4.5 / 8.2 / 9.9 /
17.11 / Appendix B, four conformance cases, 36 changed expectations (primitive only), unit tests.
`mvn verify` green (436 unit + 193 integration tests, 59 conformance cases × {1.7, 1.6, determinism}).

Checked:

* **F2 ordering.** Imports are now entered after the collection walk instead of during it. Nothing
  reads the import table during the walk (`maybeReference` uses only the rule index), so the order
  of targets per local name is the collection order as before; the conformance cases with
  `try`/`except ImportError` (`python/name-resolution`, `python/fork-fixtures`) are unchanged.
  The try context stops at function, lambda, class and module boundaries and at `else` /
  `finally`; an `if` or `with` block inside a `try` body still belongs to the body. The word test
  `\b(ImportError|…|Exception|BaseException)\b` does not match `MyException` (no word boundary)
  but does match a qualified `builtins.Exception`; both are acceptable. Star imports unchanged
  (documented).
* **F7 cost and scope.** Only regular, non-excluded, unclassified files without `.` in their name
  are opened, and only 256 bytes are read; read errors give a debug line, not a warning (the file
  would have been ignored before). The file then goes through binary detection, the size limit and
  the pre-filter like any `.py` file. `.py` name rules of 4.7 do not apply to scripts (directory
  rule only), as specified. Hidden files (`.bashrc`) contain a `.` and are never opened.
* **F1** changes only asset fields: no selection, nesting or naming logic reads the primitive
  (only `CbomWriter` / `CryptoRegistry`). Diffed the evaluation CBOMs: Java/Python changes are the
  EC primitive and three library entries.
* **F4 composites.** A composite `rsa.PublicKey{…}` nested in `rsa.PrivateKey{…}` folds (same
  family); a curve call inside `ecdsa.PublicKey{Curve: elliptic.P256()}` folds too and loses its
  parameter — 11 such curve findings in go-jose/nebula tests and code moved to the enclosing
  construction line (documented in Appendix B; not worth a special case). Type assertions and type
  switches are not events (unit test). `ed25519.PublicKey(b)` conversions are call events by 17.5;
  a conversion and a separate `.Public()` call on one line give two findings (different names).
* **F5/F6** use only existing families; `CycloneDx17Test` (every family mapped / registry values)
  passes. The hybrid HPKE KEMs follow the `tls.X25519MLKEM768` precedent (ML-KEM only).
* **F3** globs: `github.com/sigstore/sigstore*` also covers `sigstore-go` and the `signature/kms/*`
  modules (intended, policy (c)/(d)); `golang.zx2c4.com/wireguard` is exact (a first draft with `*`
  also matched the `wireguard/windows` client module, removed).
* Rule counts in `RuleLoaderTest`, `CliIT` and the conformance total in `ConformanceIT` updated.

No findings left open.
