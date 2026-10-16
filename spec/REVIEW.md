<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 The CipherSift Authors -->

# Review of the CipherSift specification package

Reviewed: `spec/SPEC.md`, `spec/rule-schema.json`, `spec/PROVENANCE.md`, `spec/tools/`,
`spec/conformance/` (23 cases, 556 findings), `rules/`, `LICENSE`. Date: 2026-10-16.

## Verdict

**Ready for implementation: yes, with conditions.** Sections 6–8 (parsing, Java and Python
analysis) are precise and match the reference tool's parsers feature by feature. The
conformance expectations follow from the spec. The rule conversion is lossless. The native
toolchain was built and loaded end to end. Four design decisions should be taken first,
because they change observable behaviour or the build: **M1** (test-file name matching),
**M2** (Maven version when a POM declares a dependency twice), **M3** (dependency versions
that conflict with cyclonedx-core-java) and **M4** (depth limits). None of them blocks work on
the analysis core, so implementation can start in parallel.

Counts: blocker 0 · major 6 (2 fixed, 4 open) · minor 32 (17 fixed, 15 open).

## What was checked

| Check | Result |
|---|---|
| `check_rules.py rules` (schema + semantic checks) | pass: 88 Java, 79 Python, 1 constants, 2 dependency documents |
| `regex_parity.py rules` (JDK 25.0.1) | 48 894 checks, 0 mismatches |
| `convert_rules.py` re-run against the fork | output identical to `rules/` (except the two hand-written files) |
| Lossless conversion, **all** 167 rules / 1 276 patterns mapped back to the fork's originals | identical anchors, conditions, ids, names, descriptions and asset properties |
| `make_expected.py` re-run with the reference bundle | all 23 `expected.json` byte-identical (before and after the fixes below) |
| Hand checks of `java/string-resolution`, `java/selection`, `java/cross-file`, `python/constants`, `python/attribution`, `python/arguments`, `deps/pypi`, `deps/maven`, `common/*` against SPEC.md | consistent; README counts (files, findings) correct |
| `conformance.py --show` on the SPEC 11.5 example | normalises as documented; all six example bom-refs recomputed and exact |
| jtreesitter 0.26.1 from Maven Central | POM `maven.compiler.release` 23, class file version 67, manifest `Java-Version: 23`; `Parser.parse(String)` uses UTF-8; `NativeLibraryLookup` SPI via `ServiceLoader` |
| Core / grammar versions | `java-tree-sitter` tag v0.26.1 → `core` submodule `3fc4cd2` = tree-sitter **v0.26.10** (ABI 13–15). tree-sitter-java v0.23.5: `LANGUAGE_VERSION 14`, no `scanner.c`. tree-sitter-python v0.25.0: `LANGUAGE_VERSION 15`, has `scanner.c` |
| Native build (SPEC 15.3 recipe, gcc 12.2.0, linux-x86_64) and loading on JDK 25.0.1 through the SPI | builds without warnings; ABI 14/15 reported; every Appendix C field name has a non-zero id; text blocks give `multiline_string_fragment`, `A` gives `escape_sequence` |
| Clean room: byte-identical files and 9-word shingles vs. the third-party original | no copied file (only an empty `__init__.py`), no shared prose; the only overlap is `make_expected.py`'s `from crypsy… import …` lines (it runs the tool and copies nothing) |
| Third-party rules | none carried over: upstream has no Java/Python source rules; no Go/Ruby/config/artifact/assessment rule, upstream schema, `dep.java.pom_xml` or Cryben content in the package. Exceptions are listed under P1–P3 |

Tarball SHA-256 values for `native/sources.lock`, from `github.com/tree-sitter/<repo>/archive/refs/tags/<tag>.tar.gz` on 2026-10-16:
tree-sitter v0.26.10 `450cb85fd1af34111eb162e931e0e9e4d4dbf23fc09b9cb56f6299a1a80483b6`,
tree-sitter-java v0.23.5 `cb199e0faae4b2c08425f88cbb51c1a9319612e7b96315a174a624db9bf3d9f0`,
tree-sitter-python v0.25.0 `4609a3665a620e117acf795ff01b9e965880f81745f287a16336f4ca86cf270c`
(see m11 on the stability of archive tarballs).

## Findings

### Major

**M1. Java test-file name patterns are case-insensitive, so ordinary classes count as tests (decided, see DECISIONS.md).**
SPEC 4.7 rule 2 (and `make_expected.is_test_file`). "Matching is case-insensitive" also
applies to `*Test.java`, `*Tests.java`, `*TestCase.java` and `Test*.java`. So
`Latest.java`, `Contest.java`, `Greatest.java`, `Attest.java` and `Protest.java` are test
files. With `--exclude-tests` they are not scanned; otherwise they are marked `test: true`.
The directory rule has a similar effect: framework code such as `django/test/` or
`numpy/testing/` is classified as test code. That one is probably acceptable as a heuristic.
*Recommendation:* make the Java file-name patterns case-sensitive (this is the Surefire
convention: `Test*`, `*Test`, `*Tests`, `*TestCase`, `*IT`). Keep the directory rule
case-insensitive. Mention the library-code effect in Appendix B. Update `is_test_file` the
same way; no current expectation changes.

**M2. Maven "last declaration wins" loses managed versions (decided, see DECISIONS.md).** SPEC 9 / 9.5. A POM
that has `bcprov ${bc.version}` in `dependencyManagement` and an unversioned `bcprov` in
`dependencies` is very common. With "last declaration wins" it reports **no** version,
although the version is in the same file. *Recommendation:* within one manifest, a
declaration with a resolved version beats one without (otherwise the last one wins).
Alternatively, apply the same POM's `dependencyManagement` versions to its unversioned
dependencies. Add a `deps/maven` case for it.

**M3. Runtime dependency versions conflict with the test-only cyclonedx-core-java 13.2.0 (decided, see DECISIONS.md).**
SPEC 15.2. cyclonedx-core-java 13.2.0 depends on `com.networknt:json-schema-validator`
**2.0.4** and Jackson **2.22.2**. The spec pins the runtime to json-schema-validator
**1.5.x** and Jackson **2.18.x**. Maven's nearest-wins rule puts the runtime versions on the
test classpath as well. networknt 2.x is an API break, so the CBOM schema validation that
section 16 requires will most likely fail with `NoSuchMethodError` or
`ClassNotFoundException`. *Recommendation:* either use json-schema-validator 2.0.4 and
Jackson 2.22.x at runtime as well, or drop cyclonedx-core-java and validate CBOMs in tests
with networknt directly against a vendored `bom-1.6.schema.json` (plus its `spdx` and `jsf`
sub-schemas). Also pin exact versions everywhere instead of `2.18.x`, `1.5.x` and `5.11.x`,
so that the build is reproducible.

**M4. Recursion depth is unbounded in several Python evaluators (decided, see DECISIONS.md).** SPEC 6.3 says that
"recursive evaluators … have explicit depth limits", but there is none for `resolveName` /
`resolveDotted` / `boundCalls` (alias chains, long attribute chains `a.b.c…`) or for
`strings()` (nested parentheses, lists and tuples in an argument; 8.5.1). The reference tool
hits `RecursionError` at about 1 000 levels and skips the file. A Java implementation either
throws `StackOverflowError`, which depends on the thread stack size and makes the output
machine-dependent, or recurses successfully and then reports findings the reference never
produced. The existing `python/deep-nesting` case does not exercise this: its 3 000-level
expression is not a call argument. *Recommendation:* define limits, for example
`resolveDotted` attribute depth 64 → no candidates, `resolveName` binding-chain depth 16,
`strings` depth 12 (like Java `value`), and add a case with
`hashlib.new(((((…"md5"…)))))` 3 000 levels deep.

**P1. Third-party rule id in a shipped rule (fixed).** `rules/java/java.rand.prng.insecure.yaml`
had the description sentence "Same asset_properties as src.go.rand.prng.insecure …". That is
an upstream rule id plus an upstream format key. *Fix:* the sentence is replaced. Because the
file is generated, the rewrite lives in `convert_rules.py` (`DESCRIPTION_REWRITES`), and the
converter now refuses descriptions that mention `src.go.`, `src.ruby.`, `asset_properties`
or `rule_identifier`. A re-run reproduces `rules/` exactly.

**P2. PROVENANCE misattributed the PyPI seed list (fixed).** PROVENANCE called the fork's
`dep.python.*.yaml` "BF-CBOM Python dependency rules". `dep.python.requirements` is an
upstream rule with six packages (cryptography, pyopenssl, pyjwt, bcrypt, argon2-cffi,
paramiko), and `dep.pypi.yaml` still starts with exactly those six in upstream order.
*Fix:* the table row now states the origin, and that only package names (facts) are used.
*Optional:* sort `packages` alphabetically so that no trace of the upstream order remains.

### Minor — fixed

| # | Location | Problem | Fix |
|---|---|---|---|
| P3 | PROVENANCE "Written new" | The rule format was presented as entirely new. Five pattern concepts are renamed upstream keys (`call`, `args_matches_regex`, `args_contains_string`, `field_assign`, `value_contains`). The id taxonomy, 8 subtypes (`rc4-cipher`, `prng-insecure`, …) and the name pattern "X usage in <Lang>" (59 of 167 names) follow upstream Go/Ruby conventions; no descriptions are shared (checked: 0 of 167). | Documented. *Open option:* rename the "… usage in Java/Python" names if maximum distance is wanted (see m14) |
| P4 | PROVENANCE | The PEP 508 regex (9.2) and the Poetry exact-version regex (9.3) are taken verbatim from the fork's dependency extractor (BF-CBOM code), but the table said "No code". | Added a row |
| P5 | PROVENANCE "Reproducing" | Absolute local paths (`/home/lanpirot/…`) in a document meant for publication. | Replaced with placeholders |
| F1 | `convert_rules.py` docstring/comment | Named `rules/dependencies/pypi.yaml`, `maven.yaml`, `rules/dependencies/pypi-extra.yaml`. | `dep.pypi.yaml`, `dep.maven.yaml`, `spec/tools/pypi-extra.yaml` |
| F2 | `rule-schema.json` `$defs.regex` | Referred to SPEC 5.6 (should be 5.7). | Fixed |
| F3 | `RegexParity.java` header | "Modes as in SPEC.md 5.6". | 5.7 |
| F4 | `rules/java/_constants.yaml` header | Referred to a section title that does not exist. | "SPEC.md 5.10 and 7.4" |
| F5 | SPEC 7.6 `body` | The order of block- and line-comment removal was unspecified, and the results differ (`// a /* b` … `*/`). | Block comments first, then line comments (as in the reference tool) |
| F6 | SPEC 8.4.1 cycle guard | The spec said a re-entered (scope, name) "contributes nothing". The reference skips only the bindings step; imports and the fallback still apply. For `a = b; b = a` this gives `a`, not `b`. This was an undeclared deviation. | Text aligned with the reference; expectations unaffected |
| F7 | SPEC 15.1 vs 15.3 | The layout put natives in `src/main/resources/native/`, while 15.2/15.3 build into `target/native/`. | 15.1 now says `target/native/<platform>/` |
| F8 | SPEC 15.3 | `fetch` unpacked to `native/vendor/<repo>-<tag>/`, but the compile script uses `vendor/tree-sitter-java/`. | Unpack to `native/vendor/<repo>/`; the tag is recorded in `sources.lock` |
| F9 | SPEC 15.3 | The core version was left to the implementer to look up. | Filled in: v0.26.10, commit `3fc4cd2`, ABI 13–15 (verified) |
| F10 | SPEC 15.5 NOTICE | JSpecify (Apache-2.0, a compile-scope dependency of jtreesitter, so it lands in the fat jar) and other shaded transitive dependencies were missing. | Added |
| F11 | SPEC Appendix A | D9 was listed before D8. The component grouping is a new design and is not comparable with the reference tool's (it merges Java names case-insensitively, keys Python components by call plus properties, groups related material per file); this was undeclared. | Reordered; a paragraph added |
| F12 | SPEC 16 | The determinism test "from two different absolute locations" can only be byte-identical if the last path segment is the same. | Clarified |
| F13 | `java/string-resolution` input line 21 | The comment says "unicode escape" but the literal had none, so no conformance case exercised Java escapes. | Line 21 now uses `"AES/CBC/…"`; regeneration gives an identical `expected.json` |
| F14 | SPEC 6.1 | `Parser.parse(String)` returns `Optional<Tree>`. | Noted, with an empty result treated as a file failure |

### Minor — open

| # | Location | Problem | Recommendation |
|---|---|---|---|
| m1 | SPEC 5.1 | "YAML 1.2 core schema" is required, but the prescribed `jackson-dataformat-yaml` uses SnakeYAML, which follows YAML 1.1. The bundled rules are unaffected (they validate under PyYAML, also 1.1). | Either name `snakeyaml-engine` (1.2), or require that values whose meaning differs between 1.1 and 1.2 be quoted and let validation enforce it |
| m2 | SPEC 7.4.5 *(advice)* | "Identifier lookups inside a field initialiser always go to the fallback" is not equivalent to 7.4.3 for fields of local or anonymous classes declared inside methods (the walk up would meet blocks and parameters). | Make one rule normative (the simplest: field initialisers always use the fallback) so that cached and live contexts agree |
| m3 | SPEC 7.5 / 7.4.3 fidelity | Two differences from the reference tool that no bundled rule triggers: (a) within a rule, the reference tries exact-key patterns before prefix patterns, not in file order (all bundled prefix patterns are bare, so there is no observable difference); (b) the reference detects `final` on locals by substring, not by word. | Keep the spec's definitions; mention them under "smaller differences" |
| m4 | `dep.maven.yaml` | Dead patterns: `com.google.crypto:*` (no such groupId on Central; Tink is `com.google.crypto.tink`, already listed), `org.openquantumsafe:*` (not on Central), `com.github.marschall:*pkcs11*` (no such artifact). Gaps: Spongy Castle `com.madgag.spongycastle:*`, Ganymed/Trilead SSH (`ch.ethz.ganymed:*`, `com.trilead:*`), `org.cryptomator:siv-mode`, `org.keyczar:keyczar`. All other coordinates were checked and exist. | Remove or replace the dead patterns; add the gaps |
| m5 | `dep.pypi.yaml` | All 60 names exist on PyPI. `certifi`, `truststore`, `itsdangerous`, `pyotp` and `asn1crypto` are ubiquitous transitive packages and add noise to library inventories. Missing: `gmssl` (SM2/3/4; the Python rules cover SM3/SM4), `pyaes`, `pysha3`, `tinyec`, `ecpy`. | Decide on the noise packages; add the gaps |
| m6 | SPEC 9.6, Appendix B | Gradle `NAME` syntax in step 2 is undefined. `gradle.properties`, `extra["x"]` and `ext { … }` blocks are not read. `setup.py`/`setup.cfg` `install_requires` and plain `Pipfile` are not parsed (nor were they by the reference). | Define `NAME` as `[A-Za-z_][A-Za-z0-9_]*`; list these under Appendix B |
| m7 | SPEC 7.4.5 | Cross-file candidates: it is unspecified whether symbolic links are followed (4.1 never follows them) and whether the binary check (4.6) applies. | Use NOFOLLOW_LINKS (a link is "absent"); apply the binary check |
| m8 | `check_rules.py` | Two 5.8 checks are missing (at most one constants document per language and one dependency rule per ecosystem; Java `param` has only `index`). It is also stricter than 5.1: "file name = id" is only a convention there. | Add the checks; make the name check a warning or a stated requirement |
| m9 | `conformance.py` | A component without occurrences goes unnoticed; temporary outputs are not cleaned up. Otherwise the comparison is sound (unordered set equality over all fields, a duplicate check, no tolerances needed). | Fail on empty `occurrences`; delete the temp dir |
| m10 | SPEC 5.7 | Regex parity is probe-based. `$` semantics differ before `\r` / U+2028 (Java treats these as line terminators, Python does not). The spec rightly makes Java semantics normative. | Informational; optionally add probes with trailing `\n` and `\r` |
| m11 | SPEC 15.3 | GitHub `archive/refs/tags/*.tar.gz` tarballs are not guaranteed to stay byte-stable, so pinned SHA-256 values can break. The CFLAGS pass `-fvisibility=hidden` and then `-fvisibility=default` (redundant). | Pin commit SHAs in `sources.lock` and verify the unpacked tree, or use release assets; drop the `hidden` flag |
| m12 | SPEC 14 | The Keycloak target (2 min single-threaded) is plausible but unverified. jtreesitter `Node` calls are FFM downcalls that allocate (`getType()` builds a `String`). | *(advice)* walk with `TreeCursor` and compare symbol or field ids instead of strings; measure early |
| m13 | SPEC 15.3 step 3 | jtreesitter's `ChainedLibraryLookup` queries the SPI when its bindings are initialised, so the natives must be extracted before any jtreesitter class is touched. | Add as advice |
| m14 | Rule names | 59 names follow the upstream "X usage in <Lang>" template (see P3). | Optional rename for maximum distance; the legal risk is low (functional phrases) |
| m15 | SPEC header / 8.4.2 | The header says "Status: ready for implementation" while decisions are open. `shape` "beyond nesting depth 8" leaves the starting depth unspecified (the reference starts at 0 for *F*). | Update the status after the decisions; say "depth 0 for *F*" |

### Fidelity summary

Compared feature by feature with `languages/java.py` and `languages/python.py`, and with
the PyPI parts of `dependency_extractor.py`. Java: events, receivers, display names,
`denotes`, the file context, `value`, identifier and field-access lookup, cross-file
lookup, constant bytes, string list, index, specificity selection, nested-duplicate
suppression, line and snippet. Python: imports, scopes, bindings, name resolution and
`shape`, call names, string list, symbol set, value texts, candidates (prefix order,
`method`, `anyCall` gating), refinement, nesting, `reportAt`, line attribution,
(rule, line) deduplication, `param`, attribute assignments. All of these agree with the
spec, except D1–D9, F6 (now fixed) and m3. The reference tool's normaliser (component
grouping) differs by design (F11).

## Answers to the author's open questions

1. **Java 23 target, build on JDK 25?** Yes. Keep `maven.compiler.release=23`: it is the
   floor that jtreesitter 0.26.1 imposes (verified: class version 67, `Java-Version: 23`).
   Build, test and ship the Docker image on JDK 25.0.1 LTS, and document "Java 23+
   supported, 25 LTS recommended". Do not raise the target to 25 unless a Java 25 API is
   needed; 23 and 24 are end-of-life, so CI on 23 is optional.
2. **Exact tree-sitter core version.** **v0.26.10** (commit `3fc4cd2`, the `core`
   submodule of the `v0.26.1` tag). ABI range 13–15 covers tree-sitter-java v0.23.5 (ABI 14)
   and tree-sitter-python v0.25.0 (ABI 15). Built with gcc 12.2.0 and loaded through the SPI
   on JDK 25.0.1. Now in SPEC 15.3.
3. **Maven groupId.** Maven Central requires a namespace that you can verify. `org.ciphersift`
   needs the domain `ciphersift.org`. If the project does not own it, use
   `io.github.<github-org>` (verified through GitHub, free), e.g. `io.github.bf-cbom` with
   artifactId `ciphersift`. Decide before the first release. Also fix the Java root package
   (SPEC does not name one) to the same namespace, so that the implementer does not have to
   rename later.
4. **Python component naming: by call or by resolved algorithm?** Keep naming by call for 1.0.
   It is the reference behaviour, the conformance names depend on it, and many Python APIs
   have no algorithm string (`hashlib.sha256()`, `hashes.SHA256()`). The asset properties
   already carry family and variant. Revisit in 1.1, for example by using the matched
   `firstString` value as the name when there is one (as Java does) and updating the
   conformance suite then.
5. **Do D1–D9 need sign-off?** Yes, a short explicit sign-off by the project owner. They are
   intentional divergences from the tool that BF-CBOM benchmarks, so they affect
   comparability and belong on record. On D8 specifically: accept reporting Maven
   dependencies without a version. The library's presence is the finding, and "no version"
   is honest where parents or BOMs are not resolved. Decide M2 (version from the same POM's
   `dependencyManagement`) together with it.

## Changed files (not committed)

`spec/SPEC.md`, `spec/PROVENANCE.md`, `spec/rule-schema.json`, `spec/tools/convert_rules.py`,
`spec/tools/RegexParity.java`, `rules/java/java.rand.prng.insecure.yaml`,
`rules/java/_constants.yaml`, `spec/conformance/cases/java/string-resolution/input/src/strings/Strings.java`,
new: `spec/REVIEW.md`. Re-run after the changes: `check_rules.py` passes, `make_expected.py`
reproduces all 23 `expected.json` files unchanged, and `convert_rules.py` reproduces `rules/`.
