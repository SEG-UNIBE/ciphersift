# Decisions on the spec review (2026-10-16)

Decided by A. Boll (project owner) on the open items of `REVIEW.md`. `SPEC.md` has been updated accordingly.

| item | decision | where in SPEC.md |
|---|---|---|
| D1–D9 (Appendix A) | All nine accepted as specified. | Appendix A |
| M1 test files | Location counts (directory rule, case-insensitive, unchanged). File-name rules are case-sensitive, as in the Surefire/pytest conventions. Library code in test-named directories counts as test code (documented limitation). | 4.7, Appendix B |
| M2 Maven versions | Resolve within the same manifest: a declaration with a resolved version beats one without, so `<dependencyManagement>` / `<properties>` of the same POM apply. Otherwise report without version. No parent POMs, no BOM imports. | 9 |
| M3 dependency versions | All versions pinned exactly. Jackson 2.22.3 (via `jackson-bom`), json-schema-validator 2.0.4 (same as cyclonedx-core-java 13.2.0), picocli 4.7.7, JUnit 6.1.3. | 15.2 |
| M4 recursion limits | Python `resolveDotted` 64 attribute levels, `resolveName` 16 binding steps, `strings()` 12 nesting levels; exceeding a limit gives "unresolved", never an error. | 6.3 |
| Q1 Java target | `release 23`; build, test and ship on JDK 25. | 15.2 |
| Q2 tree-sitter core | v0.26.10 (`3fc4cd2`, ABI 13–15), as written in by the reviewer. | 6 |
| Q3 coordinates | groupId `ch.unibe.seg`, artifactId `ciphersift`, root package `ch.unibe.seg.ciphersift`. | 15.2 |
| Performance (14) | De-emphasised: a non-binding guideline of ~9 kLOC/s single-threaded; no MUST targets, no thread or start-up targets. Correctness and determinism come first. | 14 |
| Q4 Python naming | Keep naming Python components by call for 1.0. | 10 |

For the implementer: add two conformance cases that the review asked for and that follow from these decisions:
- `deps/maven-managed-version`: `bcprov` versioned only in `<dependencyManagement>` via a property, unversioned in `<dependencies>` → reported with the managed version.
- `python/deep-call-args`: `hashlib.new(((((…"md5"…)))))` nested 3 000 levels deep → no finding, no crash; the same at 5 levels → MD5.

Expected findings for these two are written by hand from the spec (the reference tool behaves differently by design).

# Follow-up decisions on the code review (2026-10-16)

The owner delegated the open items O1–O7 of `CODE-REVIEW.md` to the follow-up; each was decided by follow-up per reviewer recommendation (none was found to need a different outcome). F1–F3 record behaviour introduced by the follow-up's start-up and speed work. `SPEC.md` has been updated accordingly.

| item | decision | where in SPEC.md |
|---|---|---|
| O1 locale and file names | Decided by follow-up per reviewer recommendation, going one step further than the launcher/Docker mitigation: file names are decoded as UTF-8 whatever the locale (raw bytes via `Path.toUri()` when `sun.jnu.encoding` is not UTF-8) — in the walk, the scan root's name, cross-file lookups and rule paths — so plain `java -jar` gives the same CBOM under any locale. Command-line arguments cannot be recovered that way (the JVM decodes them with the locale's charset); an argument that arrives with U+FFFD under a non-UTF-8 locale gives a warning. Launcher and Docker keep `LC_ALL=C.UTF-8`. | 12, 15.4 |
| O2 `param` and Java specificity | Decided by follow-up per reviewer recommendation: `param` is not a filter and does not make a Java pattern specific (a pattern with only anchor and `param` is bare). No bundled Java rule uses `param`, so no bundled result changes. | 5.5 |
| O3 comments in byte-array initialisers | Decided by follow-up per reviewer recommendation: comments are ignored by the `isConst` check of an `array_initializer` (`new byte[] {1, /* x */ 2}` is constant bytes). New conformance case `java/array-comments`. | 7.4.7 |
| O4 alias chains longer than 16 steps | Decided by follow-up per reviewer recommendation, consistent with M4 ("exceeding a limit gives unresolved"): a name whose binding chain needs more than 16 steps has no candidates, and neither has any name resolved through it; the fallback to the name itself does not apply. New conformance case `python/alias-chain-limit`. | 6.3, 8.4.1 |
| O5 direct references in `pyproject.toml` | Decided by follow-up per reviewer recommendation: a PEP 508 string containing `://` (`pkg @ https://…`) is skipped, as in requirements files. New conformance case `deps/pyproject-direct-reference`. No existing expectation changes. | 9.3 |
| O6 rule-file details | Decided by follow-up per reviewer recommendation: `new: X*` is rejected at load time (rule error, exit 4) with the message "a new anchor names a class; "*" is not allowed" — the schema's `if`/`then` branch for `new` already rejected it (contrary to the review's m9), but only with a bare regex message; a semantic check backs it up; symbolic links inside a `--rules` directory are not followed and are rule errors (the directory argument itself may be a link). | 5.8 |
| O7 Docker usage in the spec | Decided by follow-up per reviewer recommendation: SPEC 15.4 shows `LC_ALL=C.UTF-8` in the Dockerfile and `--user "$(id -u):$(id -g)"` in the usage line, as delivered. | 15.4 |
| F1 Java version check | The launcher picks `CIPHERSIFT_JAVA`, else `JAVA_HOME`, else `java` on `PATH`; falls back only to a further explicitly configured runtime; never searches the file system. A runtime older than 23 gives a one-line error and the new exit code 6, also for `java -jar` on Java 8–22 (the entry point is compiled for Java 8). | 3, 3.3, 13, 15.2 |
| F2 bundled rules validated at build time | The build validates the bundled rules in full and fails on any problem; it records a digest of the rule files, the schema and a pre-parsed copy of the documents. At run time the schema validation (and YAML parsing) of the bundled set is skipped only if that digest matches; `--rules` directories and `rules validate --rules` are always validated in full. | 5.8, 15.2 |
| F3 textual pre-filter | A source file in which no pattern's required names occur (as substrings) is not parsed; it counts as scanned and has no findings — exactly what the analysis would give. Output is byte-identical with and without the filter (tested). | 14 |
