<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 The CipherSift Authors -->

# CipherSift conformance suite

28 cases, 573 expected findings. A conforming implementation produces exactly the expected
findings for every case.

## Layout

```
cases/<group>/<case>/
  input/          the directory to scan (scan root); test data, never edited for headers
  options.json    optional: {"args": ["--exclude", "vendor/**", ...]} extra CLI arguments
  expected.json   expected findings (generated, see "Provenance of the expectations")
deviations.yaml   intentional differences from the reference tool, applied when generating
```

| Case | Files | Findings | What it checks |
|---|---|---|---|
| `java/fork-fixtures` | 8 | 105 | the BF-CBOM Java fork's own fixtures: JCA, BouncyCastle, libraries, TLS, key management, edge cases, a negative file |
| `java/regex-battery` | 1 | 134 | one `getInstance` call per line for ~130 algorithm strings over 12 JCA factories; exactly one rule per line, `*.unresolved` for unknown names |
| `java/name-resolution` | 2 | 12 | explicit, wildcard, static and static-wildcard imports; FQN use; a different imported class with the same simple name; a class declared in the file; nested classes; variable receivers; line of a multi-line call |
| `java/string-resolution` | 1 | 19 | escapes, `+` with ints and constants, parentheses, `this.f`, `C.F.toString()`, interface constants, finality and reassignment, ternary/parameter/format fallbacks, constants table, array arguments (inline and via constant, D3), text blocks (D4) |
| `java/cross-file` | 4 | 8 | constants in other files: imported class, static import, static wildcard import, nested class, same package, wildcard-imported package, chained constants across files, missing class |
| `java/constant-args` | 1 | 13 | `constantArg`: array literals, constant fields, `"…".getBytes()`, `Hex.decode("…")`, `toCharArray()`, inline vs. variable `new byte[n]` |
| `java/overrides` | 1 | 4 | `override` + `inType` + `body`: trust-all trust managers (incl. `X509ExtendedTrustManager`, comment-only body, `return;`), validating ones, non-TrustManager classes, anonymous `HostnameVerifier` |
| `java/selection` | 1 | 21 | specificity: every `*.unresolved` fallback, provider argument; nested-duplicate suppression (also across lines); different families kept; several protocol versions; two calls on one line |
| `java/array-comments` | 1 | 7 | comments inside byte-array initialisers are ignored by the constant-bytes check (DECISIONS O3): inline, via a constant field, line comments across lines; a non-literal element still prevents it |
| `java/syntax-error` | 1 | 2 | findings before and after a syntax error |
| `java/deep-nesting` | 1 | 2 | 4 000-operand concatenation: no crash, depth limit → fallback |
| `python/fork-fixtures` | 14 | 142 | the BF-CBOM Python fork's own fixtures: stdlib, pyca/cryptography (incl. operation attribution and curve objects), PyCryptodome/Cryptodome, libraries, negatives, broken/Python 2/binary-ish files, requirements/pyproject/Pipfile.lock |
| `python/name-resolution` | 3 | 10 | `import as`, dotted imports, `from … import … as`, relative imports, star imports, `try`/`except` alternatives, function and module aliases, bound calls, prefix vs. non-prefix names |
| `python/constants` | 1 | 7 | module and local constants, implicit concatenation, f-strings and bytes (not strings), parameter shadowing (D2), keyword strings, flow-insensitivity |
| `python/arguments` | 1 | 15 | `anyCall` + `kwargs`, `param` by keyword/index/constant/symbol/self, list strings in keywords, attribute assignments |
| `python/attribution` | 1 | 11 | `reportAt` (incl. multi-line calls), padding in a variable, nested same-rule folding, one finding per (rule, line) |
| `python/setup-py` | 1 | 1 | `setup.py` is source (D1) |
| `python/deep-nesting` | 1 | 1 | 3 000-level nested parentheses: no crash, later finding still reported |
| `python/deep-call-args` | 1 | 3 | `hashlib.new(((…"md5"…)))` nested 3 000, 13, 12 and 5 levels deep: `strings()` depth limit 12 (SPEC 6.3, DECISIONS M4); no crash |
| `python/alias-chain-limit` | 1 | 1 | an alias chain of exactly 16 binding steps resolves; 17 steps and a name whose own binding lies beyond the limit are unresolved, without fallback to the name at the limit (DECISIONS O4) |
| `deps/pypi` | 6 | 21 | PEP 508 lines (pins, ranges, extras, markers, options, URLs, comments), `requirements-dev.txt`, `requirements/base.txt`, pyproject (PEP 621, PEP 735, Poetry), `Pipfile.lock`, `poetry.lock` |
| `deps/maven-managed-version` | 2 | 3 | a version from the same POM's `<dependencyManagement>` (via `<properties>`) applies to an unversioned dependency, in either order; no version anywhere → reported without version (DECISIONS M2) |
| `deps/pyproject-direct-reference` | 1 | 3 | `pkg @ https://…`, `git+https://…`, `file:///…` direct references in `project.dependencies`, optional dependencies and dependency groups are skipped like in requirements files (DECISIONS O5) |
| `deps/maven` | 5 | 17 | `pom.xml` (properties, dependencyManagement, plugin dependencies, unmanaged version, unknown property, comments), Groovy and Kotlin Gradle scripts (strings, map notation, variables, comments), version catalog |
| `common/test-files` | 6 | 6 | test-file marking with the default `--include-tests` |
| `common/test-files-excluded` | 6 | 2 | the same input with `--exclude-tests` (D6) |
| `common/exclude` | 3 | 1 | `--exclude` with `dir/**` and `**/*_pb2.py` |
| `common/binary` | 3 | 2 | binary `.py` skipped (D5), Latin-1 byte + CRLF, UTF-8 BOM |

## Format of expected.json

```json
{"case": "java/selection", "findings": [
  {"file": "src/s/Selection.java", "line": 23, "rule": "java.jca.cipher.unresolved", "type": "algorithm",
   "subtype": null, "primitive": null, "family": null, "variant": null, "protocol": null,
   "version": null, "param": null, "name": "Cipher.getInstance"},
  ...
]}
```

One object per finding, one finding per line of the file, sorted by (file, line, rule, name,
param, package, version).

Source findings:

| Field | Meaning |
|---|---|
| `file` | relative path inside `input/`, `/`-separated |
| `line` | 1-based line (SPEC 7.2, 8.6) |
| `rule` | CipherSift rule id |
| `type` | the **rule's** asset type (`key-material` is kept, not mapped to `related-crypto-material`) |
| `subtype`, `primitive`, `family`, `variant`, `protocol`, `version` | from the rule's `asset` block (`null` if absent); `primitive` uses the CycloneDX spelling |
| `param` | parameter-set identifier (SPEC 8.8) or `null` |
| `name` | component name (SPEC 10.2) for `algorithm` findings, `null` for other types |
| `test` | present and `true` only for findings in test files (SPEC 4.7) |

Dependency findings: `file`, `line` (always `null`), `rule` (`dep.maven` / `dep.pypi`),
`type` (`library`), `ecosystem`, `package` (Maven `groupId:artifactId`, PyPI normalised
name), `version` (or `null`), and `test` as above.

Snippets, symbols, bom-refs and the CBOM layout are not part of the comparison; they are
covered by SPEC.md section 11 and by unit tests.

## How to compare

1. Run `ciphersift scan cases/<case>/input -o out.json <options.json args>` for each case.
2. Normalise the CBOM into findings: for every component and every occurrence of it, emit one
   finding with
   * `file` = occurrence `location`, `line` = occurrence `line` (or `null`),
   * `rule` = `ruleId` from the JSON in the occurrence's `additionalContext`,
   * `test` = `true` if that JSON has `"test": true`,
   * for libraries: `type` = `library`, `ecosystem` = property `ciphersift:ecosystem`,
     `package` = `group:name` (Maven) or `name` (PyPI), `version` = component `version`;
   * for cryptographic assets: `type` = property `ciphersift:assetType` if present, else
     `cryptoProperties.assetType`; `subtype`, `primitive`, `family`, `variant` = the
     properties `ciphersift:<field>`; `protocol`, `version` = `protocolProperties.type` /
     `.version`; `param` = `algorithmProperties.parameterSetIdentifier`; `name` = component
     `name` if `type` is `algorithm`.
3. Compare the *set* of normalised findings with the set in `expected.json` (all fields
   listed above take part; missing optional fields count as `null`). A case passes iff the
   sets are equal and the CBOM contains no duplicate occurrence.

`spec/tools/conformance.py` implements exactly this (Python 3 standard library only):

```sh
python3 spec/tools/conformance.py --cmd "java --enable-native-access=ALL-UNNAMED -jar target/ciphersift-1.0.0-all.jar"
python3 spec/tools/conformance.py --show out.json      # print a CBOM's normalised findings
```

## Provenance of the expectations

`expected.json` files are generated by `spec/tools/make_expected.py`, which runs the
reference tool (the BF-CBOM Python fork of Crypsy, see `../PROVENANCE.md`) on each `input/`,
records its raw findings (before its own component merging, which can hide occurrences),
maps rule ids (`src.java.X` → `java.X`, `src.python.X` → `python.X`, `dep.python.*` →
`dep.pypi`), takes the asset properties from the converted rules, adds the test-file flag
(SPEC 4.7), and finally applies `deviations.yaml`. The implementer does not need the
reference tool; the generated files are the contract.

The expectations of `deps/maven-managed-version` and `python/deep-call-args` (added with the
implementation, as requested in `../DECISIONS.md`) are hand-written from SPEC.md; the reference
tool behaves differently there by design. The same holds for `java/array-comments`,
`python/alias-chain-limit` and `deps/pyproject-direct-reference`, added with the follow-up
decisions O3, O4 and O5 (`../DECISIONS.md`); CipherSift before those decisions fails each of them
(3 missing hard-coded keys, 1 extra MD5, 4 extra libraries). No existing expectation changed.

Every finding was then checked by hand against the comment at the end of its source line
(inputs written for this suite carry the expected line number and result as a trailing
comment such as `// 21: AES-CBC` or `# 12: ...`; the two `fork-fixtures` cases equal, line
for line, the hand-written expectations of the forks' own unit tests). Where the comment
and the reference tool disagreed, either the comment was wrong (fixed) or the reference
tool's behaviour is a bug; the latter are the deviations below.

## Intentional deviations from the reference tool

Listed in `deviations.yaml` with reasons; summarised in SPEC.md Appendix A.

| Id | Case | Change |
|---|---|---|
| D1 | `python/setup-py` | + SHA-1 at `setup.py:7` (reference tool never analysed `setup.py`) |
| D2 | `python/constants` | − MD5 at `consts.py:23` (a parameter shadowed by a module constant) |
| D3 | `java/string-resolution` | + TLS 1.0 and TLS 1.3 at line 37 (array constant) |
| D4 | `java/string-resolution` | line 41: 3DES-ECB (`DESede` text block) instead of the unresolved fallback |
| D5 | `common/binary` | − `blob.py` (binary) |
| D6 | `common/test-files-excluded` | − the four test files |
| D7 | `python/alias-chain-limit` | 1 | 1 | an alias chain of exactly 16 binding steps resolves; 17 steps and a name whose own binding lies beyond the limit are unresolved, without fallback to the name at the limit (DECISIONS O4) |
| `deps/pypi` | + `requirements-dev.txt`, `requirements/base.txt`, `poetry.lock`, PEP 735 group |
| D8 | `deps/pyproject-direct-reference` | 1 | 3 | `pkg @ https://…`, `git+https://…`, `file:///…` direct references in `project.dependencies`, optional dependencies and dependency groups are skipped like in requirements files (DECISIONS O5) |
| `deps/maven` | all 17 findings (hand-written) |
| D9 | `java/constant-args` | + DES at `Keys.java:14` (byte-array numbers are not strings) |

Regenerating (needs the reference tool, maintainers only):

```sh
B=<reference tool bundle>
$B/venv/bin/python -I spec/tools/make_expected.py --registry $B/crypistry --rules rules \
    --cases spec/conformance/cases --deviations spec/conformance/deviations.yaml
```
