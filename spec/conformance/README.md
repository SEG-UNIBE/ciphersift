<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 The CipherSift Authors -->

# CipherSift conformance suite

64 cases, 1403 expected findings. A conforming implementation produces exactly the expected
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
| `java/fork-fixtures` | 8 | 105 | the BF-CBOM Java fork's own fixtures (with `--weakness-indicators`): JCA, BouncyCastle, libraries, TLS, key management, edge cases, a negative file |
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
| `python/fork-fixtures` | 14 | 143 | the BF-CBOM Python fork's own fixtures (with `--weakness-indicators`): stdlib, pyca/cryptography (incl. operation attribution and curve objects), PyCryptodome/Cryptodome, libraries, negatives, broken/Python 2/binary-ish files, requirements/pyproject/Pipfile.lock |
| `python/name-resolution` | 3 | 11 | `import as`, dotted imports, `from … import … as`, relative imports, star imports, `try`/`except` alternatives, function and module aliases, bound calls, prefix vs. non-prefix names |
| `python/constants` | 1 | 7 | module and local constants, implicit concatenation, f-strings and bytes (not strings), parameter shadowing (D2), keyword strings, flow-insensitivity |
| `python/arguments` | 1 | 14 | `anyCall` + `kwargs`, `param` by keyword/index/constant/symbol/self, list strings in keywords, attribute assignments |
| `python/attribution` | 1 | 12 | `reportAt` (incl. multi-line calls), padding in a variable, nested same-rule folding, one finding per (rule, line) |
| `python/setup-py` | 1 | 3 | `setup.py` is source (D1); its `install_requires` (D13) |
| `python/deep-nesting` | 1 | 1 | 3 000-level nested parentheses: no crash, later finding still reported |
| `python/deep-call-args` | 1 | 3 | `hashlib.new(((…"md5"…)))` nested 3 000, 13, 12 and 5 levels deep: `strings()` depth limit 12 (SPEC 6.3, DECISIONS M4); no crash |
| `python/alias-chain-limit` | 1 | 1 | an alias chain of exactly 16 binding steps resolves; 17 steps and a name whose own binding lies beyond the limit are unresolved, without fallback to the name at the limit (DECISIONS O4) |
| `deps/pypi` | 6 | 21 | PEP 508 lines (pins, ranges, extras, markers, options, URLs, comments), `requirements-dev.txt`, `requirements/base.txt`, pyproject (PEP 621, PEP 735, Poetry), `Pipfile.lock`, `poetry.lock` |
| `deps/maven-managed-version` | 2 | 3 | a version from the same POM's `<dependencyManagement>` (via `<properties>`) applies to an unversioned dependency, in either order; no version anywhere → reported without version (DECISIONS M2) |
| `deps/pyproject-direct-reference` | 1 | 3 | `pkg @ https://…`, `git+https://…`, `file:///…` direct references in `project.dependencies`, optional dependencies and dependency groups are skipped like in requirements files (DECISIONS O5) |
| `deps/maven` | 5 | 16 | `pom.xml` (properties, dependencyManagement, plugin dependencies, unmanaged version, unknown property, comments), Groovy and Kotlin Gradle scripts (strings, map notation, variables, comments), version catalog |
| `common/test-files` | 6 | 5 | test-file marking with the default `--include-tests` (the `conftest.py` file holds only a weakness indicator, not reported by default: D15) |
| `common/test-files-excluded` | 6 | 2 | the same input with `--exclude-tests` (D6) |
| `common/exclude` | 3 | 1 | `--exclude` with `dir/**` and `**/*_pb2.py` |
| `common/binary` | 3 | 2 | binary `.py` skipped (D5), Latin-1 byte + CRLF, UTF-8 BOM |
| `common/weakness-indicators` | 2 | 3 | insecure and secure PRNGs in Java and Python, default options: only the secure PRNGs, weakness indicators are off by default (E2) |
| `common/weakness-indicators-enabled` | 2 | 8 | the same input with `--weakness-indicators` (E2) |
| `python/references` | 1 | 19 | bare references (SPEC 8.6.1): tuple, dict key/value, class attribute, keyword and positional arguments, alias definition, conditional expression, `ref` operands; folded inside `hmac.new`; nothing for annotations, `isinstance`, `cast`, comparisons, `except`, `Union[…]`, class bases, defaults, attribute reads, modules (E1) |
| `python/asn1crypto` | 1 | 9 | `Certificate.load`, CRLs, `DigestAlgorithm` / `SignedDigestAlgorithm` / `EncryptionAlgorithm` / `KeyEncryptionAlgorithm` with `dictItems` (inline and through a name), `DigestAlgorithmId`; no fingerprints, no dynamic values (E3) |
| `python/key-loading` | 1 | 7 | pyca `load_*_private_key` / `_public_key` / `_parameters`, pyOpenSSL, a loader as reference; not `private_bytes` (E4) |
| `python/secp256k1-pyaes` | 1 | 10 | electrum_ecc / coincurve keys with the fixed parameter `secp256k1`, `GENERATOR` as operand and table element, `ecdsa_sign`/`ecdsa_verify`, pyaes modes (E5) |
| `python/misc-libs` | 1 | 20 | standalone `PKCS1v15()`, ConcatKDF, X9.63 KDF, PyJWT algorithms, python-pkcs11 mechanisms and key types, signxml enums and strings, PKCS1v15 inside `sign` (E12) |
| `python/padding-flow` | 1 | 14 | a padding variable bound to several paddings: all of them at the operation call, each object at its own line (E13) |
| `python/verify-false` | 1 | 5 | `verify=False` / `ssl=False` on requests, sessions, httpx, aiohttp, OAuth sessions; not on other functions or `asyncio.open_connection` (E14) |
| `java/pki-cms` | 1 | 11 | PKIX parameters, cert stores, trust anchors, BC certificate holders, CMS signed / enveloped data, time-stamp tokens, `KeyStore.getDefaultType` (E6) |
| `java/okhttp-tls` | 2 | 10 | OkHttp `ConnectionSpec`, `CipherSuite` and `TlsVersion` constants, string suites and versions; an unqualified member type without import is not the API class (SPEC 7.3.2, E7) |
| `java/bc-provider-digests` | 3 | 7 | BC JCA provider digest classes `Outer.Inner`, a member type imported by name or through its enclosing class, not through the package (E8) |
| `java/fallbacks` | 1 | 11 | `*.unresolved` for `SecretKeySpec`, `AlgorithmParameterGenerator`, `AlgorithmParameters`, `JcaContentSignerBuilder`; specific rules win when the name is known (E9) |
| `java/ec-mgf1` | 1 | 9 | `EllipticCurve`/`ECFieldFp` (folded), BC EC parameters, `SecP256K1Curve.q`, `MGF1ParameterSpec` names and constants (E11) |
| `java/oid-table` | 2 | 144 | every OID of the built-in table (SPEC 5.11) through BouncyCastle `ASN1ObjectIdentifier`; JCA factories with OIDs (literal, constant, `OID.` prefix); unknown and non-OID strings; deferred `final` local stays unresolved (E15) |
| `python/oid-table` | 2 | 120 | every table OID through pyca `x509.ObjectIdentifier` (none for OIDs without a Python rule); `x509.oid.ObjectIdentifier`, asn1crypto, pyasn1, a constant, a curve parameter, unknown OIDs (E15) |
| `java/shiro` | 2 | 22 | Apache Shiro 1.x and 2.x public crypto API: hash classes, `SimpleHash`, `HashedCredentialsMatcher` / `setHashAlgorithmName` (also via `ALGORITHM_NAME`), Argon2 / bcrypt, cipher services, `SecureRandomNumberGenerator`; a same-named class of another library (E16) |
| `go/api-battery` | 1 | 61 | one Go standard-library or `golang.org/x/crypto` API per line (SPEC 17.11): ciphers, AEADs, NaCl, RSA schemes, DSA, curves, ECDSA/ECDH/X25519/Ed25519, ML-KEM, MACs, hashes, KDFs, CSPRNG, keys, certificates, `crypto.Hash` and `x509` constants; non-algorithm members give nothing |
| `go/names` | 3 | 11 | import aliases, default names with `/vN`, blank imports, variables named like packages, a different package with the same name, dot imports (only undeclared exported names), a multi-line selector, a file the pre-filter skips (SPEC 17.4) |
| `go/constants` | 1 | 18 | `const` groups, variables assigned once / twice (also from `init`), parameters, `:=` pairs, `++`, hexadecimal, parentheses, closures, curves through variables and as function values (SPEC 17.6, 17.9) |
| `go/modes` | 1 | 14 | AES-GCM/CTR/CBC/OFB/XTS through variables, aliases and inline calls; mode fallbacks for parameters and DES; flow-insensitive bindings (SPEC 17.7, 17.8) |
| `go/references` | 1 | 14 | function values, `crypto.Hash` constants, TLS versions, cipher suites and groups; nothing in comparisons, switch cases and map keys (SPEC 17.5, DECISIONS G6) |
| `go/tls-x509-ssh` | 1 | 22 | `tls.Config` literals and `new(tls.Config)`, `InsecureSkipVerify` (literal, constant, variable, assignment), x509 templates and keys, `rsa.PSSOptions`, SSH configs and `InsecureIgnoreHostKey` |
| `go/test-files` | 4 | 4 | `_test.go` and `testdata/` marking; the file-name rule is case-sensitive (SPEC 17.1) |
| `go/syntax-error` | 1 | 2 | findings before and after a Go syntax error |
| `deps/golang` | 4 | 11 | `go.mod` (single and block `require`, quoted paths, `replace`/`exclude`/`retract` ignored, last declaration wins), `go.sum` (`/go.mod` lines skipped, last version wins), major-version module paths (SPEC 17.10) |
| `deps/setup-files` | 5 | 15 | `setup.py` `install_requires` / `extras_require` (inline, through names, URL skipped), `setuptools.setup`, `setup.cfg`, `org.apache.shiro.crypto:*`, `electrum-ecc`, `pyaes`, `pysha3` (E10); `certifi` is not listed (DECISIONS B-P1, 1 expectation removed) |
| `python/import-fallback` | 1 | 8 | import alternatives: a binding made in an import-failure handler (`ImportError`, `ModuleNotFoundError`, `Exception`, `BaseException`, bare `except`) of a `try` whose body imports the same local name is dropped; other handlers, other names and `finally` keep theirs (SPEC 8.2, DECISIONS F2) |
| `go/hpke-mldsa-keys` | 3 | 32 | `crypto/hpke` / `filippo.io/hpke` KEM, KDF and AEAD identifiers (DHKEM with its curve, hybrid ML-KEM), `crypto/mldsa` and the TLS ML-DSA schemes, key structs, `elliptic.CurveParams`, Ed25519 key conversions, `ecdsa.ParseRawPrivateKey` / `ParseUncompressedPublicKey`, `rsa.EncryptOAEPWithOptions` (DECISIONS F4–F6) |
| `common/shebang-scripts` | 8 | 4 | extensionless files with a Python interpreter line are Python source (`env`, `env -S`, versioned interpreter, CRLF, test directory); shell, other interpreters, no interpreter line and files with an extension are not (SPEC 4.5, DECISIONS F7) |
| `java/wrappers` | 6 | 30 | (with `--feature java-thin-12=off` and `--feature java-propagate-random=off`, so that its 10-line `checksum` and its CSPRNG helper stay non-callables) wrapper propagation (SPEC 18): `Class.m`, FQN, static import, enclosing-class calls, overload groups with the caller removed, depth 1–3 and the depth limit, mutual recursion, thin wrappers (two families, CSPRNG only: not), folding (two calls on a line, a direct finding on the line), a collision through two on-demand imports, a class of the file shadowing them, test-file wrappers |
| `python/wrappers` | 7 | 20 | absolute, aliased, relative and package imports, a re-export through `__init__.py`, `self` and class methods, a parameter shadowing a wrapper, an ambiguous module name, thin wrappers off by default, test files |
| `python/thin-wrappers` | 1 | 8 | `--python-thin-wrappers`: thin wrappers, a thin wrapper of a thin wrapper, two families, nine lines, CSPRNG only |
| `go/wrappers` | 8 | 17 | (with `--feature go-thin-wrappers=off`) `pkg.F` through `go.mod` and `vendor/`, same package, receiver / `&T{}` / `var` / struct-field types, build-tag variants as one group, a local variable shadowing a wrapper, an untyped value, test files, thin wrappers off for Go |
| `go/api-ag` | 1 | 85 | the third-party Go APIs of SPEC 17.11 (age, agessh, sigstore cryptoutils, `x509.Marshal*`, securesystemslib `encrypted`, CIRCL, flynn/noise, go-containerregistry `v1.SHA256`, pkcs11 `CKM_ECDSA*`, azkeys) and non-anchors (types, size constants, other members, a switch case) |
| `deps/crypto-services` | 3 | 24 | the list policy of SPEC 9.9 in all three ecosystems: cloud KMS key clients, HPKE, Noise, WireGuard, PIV, Sigstore signing and time-stamping are listed; storage, secret stores and general SDKs are not (DECISIONS F3); the Vault API client, Rekor and Sigstore's protobuf-specs are listed by owner decision (DECISIONS B-G4, 3 expectations added) |
| `deps/transitive` | 6 | 6 | default: `go.mod` `// indirect` entries (also `//indirect`, `// indirect; …`, not `// indirectly …`), `go.sum`, `poetry.lock` and `Pipfile.lock` give nothing; `Pipfile` `[packages]` / `[dev-packages]` and `pyproject.toml` do (DECISIONS B-G1, B-G2) |
| `deps/transitive-included` | 6 | 16 | the same input with `--transitive-deps` |
| `deps/commons-codec-used` | 3 | 3 | `commons-codec` is reported when a Java file names `org.apache.commons.codec.digest` (here fully qualified) (DECISIONS B-J4) |
| `deps/commons-codec-unused` | 3 | 1 | `commons-codec` used only for Base64 / Hex: not reported; other libraries unaffected (DECISIONS B-J4) |
| `common/wrapper-aliases` | 4 | 26 | V2 wrapper-name aliases in Java, Python and Go (`tls`, `ssh`, `cert`/`certificate`, `privkey`, `hash160`) and the V1 alias `des3` → 3DES, on definitions that are not thin wrappers (DECISIONS B-A1, B-A2) |
| `java/wrapper-depth` | 1 | 5 | name-consistent chains of 2, 3 and 4 definitions are reported, a chain of 5 is not (DECISIONS B-C) |
| `java/thin-12` | 1 | 3 | Java thin wrappers of 12 lines carry their family, 13 lines do not (DECISIONS B-J-G) |
| `java/propagate-random` | 1 | 4 | a Java helper returning a `SecureRandom` is a thin wrapper; one with a CSPRNG and AES is not (DECISIONS B-J-D) |
| `go/thin-wrappers` | 1 | 6 | Go thin wrappers: 3 and 12 lines (an early error return) carry, 14 lines do not; a fallback getter (`if … { return crypto.SHA256 }; return c.DefaultHash`) does not (DECISIONS B-G-E) |
| `go/typed-methods` | 1 | 26 | method anchors on typed receivers: parameters, results by position, type assertions, a single-type type-switch case (not two types), struct fields, one level of embedding (not when the file declares the method), `ecdh` / `mlkem` / `x509` / `ssh` result chains, composite and `new`, a reassigned variable, accessors (DECISIONS B-G-B1a) |
| `go/api-b2` | 1 | 19 | Sigstore protobuf-specs key and hash values (an aliased `common/v1` import), sigstore `WithED25519ph` and `AlgorithmDetails` methods, go-piv algorithms and `Verify`, CIRCL SLH-DSA parameter sets; LMS and other members give nothing (DECISIONS B-G-B2) |

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
| `oid` | the algorithm OID (`cryptoProperties.oid`, SPEC 5.11) or `null`; written only where it is non-null |
| `name` | component name (SPEC 10.2) for `algorithm` findings, `null` for other types |
| `via`, `origin` | for findings of wrapper propagation (SPEC 18.7): the `via` array and the `origin` string of the occurrence's `additionalContext`; absent (`null`) otherwise |
| `test` | present and `true` only for findings in test files (SPEC 4.7) |

Dependency findings: `file`, `line` (always `null`), `rule` (`dep.maven` / `dep.pypi` /
`dep.golang`), `type` (`library`), `ecosystem`, `package` (Maven `groupId:artifactId`, PyPI
normalised name, Go module path), `version` (or `null`), and `test` as above.

Snippets, symbols, bom-refs and the CBOM layout are not part of the comparison; they are
covered by SPEC.md section 11 and by unit tests.

## How to compare

1. Run `ciphersift scan cases/<case>/input -o out.json <options.json args>` for each case.
2. Normalise the CBOM into findings: for every component and every occurrence of it, emit one
   finding with
   * `file` = occurrence `location`, `line` = occurrence `line` (or `null`),
   * `rule` = `ruleId` from the JSON in the occurrence's `additionalContext`,
   * `test` = `true` if that JSON has `"test": true`; `via` and `origin` = the JSON's values if present,
   * for libraries: `type` = `library`, `ecosystem` = property `ciphersift:ecosystem`,
     `package` = `group:name` (Maven) or `name` (PyPI, Go), `version` = component `version`;
   * for cryptographic assets: `type` = property `ciphersift:assetType` if present, else
     `cryptoProperties.assetType`; `subtype`, `primitive`, `family`, `variant` = the
     properties `ciphersift:<field>`; `protocol`, `version` = `protocolProperties.type` /
     `.version`; `param` = `algorithmProperties.parameterSetIdentifier`; `oid` = `cryptoProperties.oid`; `name` = component
     `name` if `type` is `algorithm`.
3. Compare the *set* of normalised findings with the set in `expected.json` (all fields
   listed above take part; missing optional fields count as `null`). A case passes iff the
   sets are equal and the CBOM contains no duplicate occurrence.

`spec/tools/conformance.py` implements exactly this (Python 3 standard library only):

```sh
python3 spec/tools/conformance.py --cmd "java --enable-native-access=ALL-UNNAMED -jar target/ciphersift-1.0.0-SNAPSHOT-all.jar"
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

The fifteen cases added with the evaluation fixes (E1–E14, `../DECISIONS.md`) are hand-written
as well; each is built from the reproducer of its issue, and every expected finding was derived
from SPEC.md and the rules before the implementation was run on it. Seven findings of six
generated cases changed with those fixes; they are deviations D10–D14 below and are listed with
their justification in `../DECISIONS.md`.

With the owner decisions of 2026-10-17 (`../DECISIONS.md`, "Owner decisions"), weakness
indicators are off by default: `common/weakness-indicators` now expects the default scan (3 of
its 8 findings), `common/weakness-indicators-enabled` (formerly `-excluded`) passes
`--weakness-indicators`, both `fork-fixtures` cases pass it too, and `common/test-files` loses one
finding (D15). The new cases `java/oid-table`, `python/oid-table` (E15) and `java/shiro` (E16)
are hand-written; their per-OID lines are derived from the table of SPEC 5.11.

The nine Go cases (Go support, `../DECISIONS.md` G1–G16) are hand-written: every line of a Go input
that has findings ends with a `// want: <rule> <name or -> [<param>]` comment (several separated by
`|`), and `expected.json` was derived mechanically from those comments and the rules' asset blocks
(the test flag from SPEC 4.7 / 17.1); `deps/golang/expected.json` was written directly. The
comments were written from SPEC section 17 and the rules before the implementation was run on the
cases.

The four cases added with the fix round of 2026-10-17 (`../DECISIONS.md`, "Fix round", F2–F7) are
hand-written like the Go cases: every line with findings carries a trailing `want:` comment (`#` or
`//`), written from SPEC.md and the rules before the implementation was run, and `expected.json`
was derived from those comments and the rules' asset blocks (`deps/crypto-services` written
directly). The EC primitive fix (F1) changed the `primitive` of 36 expected findings of eight
cases (`python.asym.ec`, `python.asym.secp256k1`, `go.asym.ec`); the asset fields come from the
rules, so no deviation entry is needed.

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
| D7 | `deps/pypi` | + `requirements-dev.txt`, `requirements/base.txt`, `poetry.lock`, PEP 735 group |
| D8 | `deps/maven` | all 17 findings (hand-written; 16 since DECISIONS B-J4 removed commons-codec) |
| D9 | `java/constant-args` | + DES at `Keys.java:14` (byte-array numbers are not strings) |
| D10 | `python/fork-fixtures`, `python/name-resolution` | + SHA2 at `pycryptodome/legacy.py:23`, + SHA1 at `pkg/imports.py:14` (bare references) |
| D11 | `python/arguments` | − validation disabled at `args.py:15` (`verify=False` on a non-HTTP function) |
| D12 | `python/attribution`, `python/fork-fixtures` | + OAEP at `ops.py:17`; four method-only findings named after the matching symbol |
| D13 | `python/setup-py` | + `cryptography`, `pyjwt 2.8.0` from `install_requires` |
| D14 | `java/regex-battery` | `SecureRandom.getInstance` lines 137–139 report the algorithm as parameter |
| D15 | `common/test-files` | − `random.random()` in `conftest.py` (weakness indicators are off by default; the fork-fixture cases pass `--weakness-indicators`) |

Regenerating (needs the reference tool, maintainers only):

```sh
B=<reference tool bundle>
$B/venv/bin/python -I spec/tools/make_expected.py --registry $B/crypistry --rules rules \
    --cases spec/conformance/cases --deviations spec/conformance/deviations.yaml
```

The five cases of the recall extension (`../DECISIONS.md` T1–T14) are hand-written like the Go
cases, with an extended comment syntax for propagated findings:
`want: <rule> <name> [<param>] via=<label>,… origin=<label>`, where `@<label>=<Display>` marks a
definition's name line and `@<label>` an evidence line. The comments were written from SPEC section
18 and 17.11 before the implementation was run; `expected.json` was derived from them and the
rules' asset blocks. The direct findings of these inputs were checked against CipherSift 097290e
(phase 3 is unchanged); two comments were corrected that way (`hmac.new` also reports SHA-2; the
curve parameter is `SECP256K1`). Two later behaviour decisions changed expectations of these new
cases only: transitive thin wrappers (T3, + one `twice(x)` finding) and thin wrappers off for Go
(T14, − the `newBlock` call). No existing expectation changed.

