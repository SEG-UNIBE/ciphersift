<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 The CipherSift Authors -->

# Changelog

## 1.0.0 (unreleased)

Development steps of the unreleased 1.0.0, newest first.

### Python tuning, round t3 (DECISIONS P3-RET … P3-PL; benchmark-informed)

* **Value positions**: returned values and literal table look-ups (`python-return-values`), parameter default
  values resolved in the enclosing scope (`python-default-values`, reverses the evaluation's D6).
* **Class wrappers** (`python-class-wrappers`): classes named after a family whose span or bases reach a finding
  of it are callables; constructor calls and instance method calls are reported (shared wrapper code, Python only).
* **Rules**: TLS beyond context creation (ldap3 `Tls` / `Server(use_ssl=True)`, `ssl._create_unverified_context`,
  `wrap_socket`, `starttls`); IANA TLS cipher suites as literals; passlib `pbkdf2_hmac`; `dep.pypi` lists
  `tgcrypto-pyrofork` and `unicrypto`.
* Conformance: 100 cases, 1693 findings (1648 + 44 in seven new cases + 1 in `python/fork-fixtures`).

### Boosters, round t2 (DECISIONS B0–B-P-B5; benchmark-informed)

Every behaviour booster has a feature switch (`--feature ID=on|off`, SPEC 3.1; recorded as
`ciphersift:features`); all are on by default except `transitive-deps` and `skip-python-lock-files`.

* **Dependencies**: `go.mod` `// indirect` requirements and `go.sum` only with `--transitive-deps`
  (`poetry.lock` / `Pipfile.lock` stay reported unless `--feature skip-python-lock-files=on`, review fix); `Pipfile` is read; Vault API client, Sigstore
  protobuf-specs and Rekor listed (owner decision); `certifi` removed; `commons-codec` only where its
  digest package is used (new rule key `usedIf`).
* **All languages**: registry aliases (V1; fixes `des3` → DES) and certificate/key/protocol aliases
  (V2) in the wrapper-name tokeniser; wrapper chains of up to 4 definitions; W7 evidence by name
  token; JCA standard-name gaps; 35 more table OIDs.
* **Go**: thin wrappers on (12 lines, fallback-getter guard); method anchors on receivers of a known
  type (`method: path.Type.Method`, result-type table); package-name consistency for project
  packages; Sigstore protobuf-specs / signature, go-piv and CIRCL SLH-DSA (`go.pqc.slhdsa`).
* **Java**: `anyCall` anchor with registry names (SNx and short names SA) and JSR 105 constants;
  constant getters, deferred locals with agreeing values, `SecretKeySpec.getAlgorithm()`; Bouncy
  Castle OID constants as anchors and values; JDK / Bouncy Castle class lists; JWT constants; key
  loading rules `java.key.load.*`; thin wrappers of 12 lines; secure random through wrappers.
* **Python**: `python.hash.unresolved` / `python.cipher.unresolved` fallbacks; `hash`/`digest`
  wrapper names; re-exported pyca names; `isinstance` key dispatch; IANA names as literals
  (`literal` anchor); ML-KEM / ML-DSA rules; asn1crypto schemas and receiver folding.
* Conformance: 93 cases, 1648 findings (1624 + 3 of the Java review, + 6 of the Go review fix of the fallback-getter guard, + 15 and one case of the cross-language review); changed expectations are listed in DECISIONS (round t2 and its reviews).

### Recall extension, tier 1 (DECISIONS T1–T14, SPEC section 18; benchmark-informed)

* **Wrapper propagation** (new pass between extraction and normalisation): the call sites of the
  project's own crypto wrappers are reported as further occurrences of the wrapper body's component,
  with `via` (wrapper chain) and `origin` (body finding) in `additionalContext`.
  * Name-consistent wrappers (W7): the function's name names a family its body yields (tokeniser
    and alias list, SPEC 18.6); transitive up to a chain of 3; Java, Python, Go.
  * Thin wrappers (W6): at most 8 lines, one family, any name; transitive; on for Java; for Python
    only with the new option `--python-thin-wrappers` (metadata `ciphersift:pythonThinWrappers`);
    off for Go (owner decision rule, DECISIONS T14).
  * Declaration-based resolution per language (Java imports, same package, nested and enclosing
    classes, static imports, arity; Python absolute and relative imports, re-exports, same module,
    `self`/`cls`; Go `go.mod`/`vendor/` packages, same package, declared receiver/variable types,
    one struct-field hop); name collisions are skipped and counted (`--verbose`).
  * Folding: no propagated finding where a direct finding of the same family is on the line; one
    per (file, line, family). Test-file wrappers serve test call sites only.
  * Files skipped by the pre-filter are parsed only if they contain a callable's name (an
    identifier Bloom filter built in phase 3 avoids rereading the others); output identical with
    and without the pre-filter (tested).
* **Go API rules (AG, T11)**: `filippo.io/age` and `agessh`, sigstore `cryptoutils`, `crypto/x509`
  `Marshal*`, go-securesystemslib `encrypted`, go-containerregistry `v1.SHA256`, CIRCL (call anchors),
  flynn/noise, miekg/pkcs11 `CKM_ECDSA*`, azkeys RSA constants; new rules `go.asym.ed448`,
  `go.asym.x448` (69 Go rules).
* Considered and rejected (did not generalise): Go identifier constants (C1), asn1crypto attribute
  reads (A1) (T12).
* Recorded, not implemented: the deep-mode roadmap (SPEC Appendix D, T13).
* Conformance: five new cases (`java/wrappers`, `python/wrappers`, `python/thin-wrappers`,
  `go/wrappers`, `go/api-ag`; 64 cases, 1403 findings); the normalisation compares `via`/`origin`.
  No existing expectation changed. New unit tests `NameTokensTest`, `WrapperPropagationTest`.

### Fix round (DECISIONS F1–F8)

* **EC keys are not key agreement** (F1): `python.asym.ec`, `python.asym.secp256k1` and
  `go.asym.ec` declare no primitive, like `java.asym.ec`; their components no longer carry
  `algorithmFamily` `ECDH` / `ECDSA` or `ciphersift:primitive`.
* **Python import alternatives** (F2): a binding of an `except ImportError` (or
  `ModuleNotFoundError`, `Exception`, `BaseException`, bare `except`) handler is dropped when the
  `try` body imports the same name; the `secrets` / `random` fallback no longer reports both PRNGs.
* **Library lists** (F3): written list policy (SPEC 9.9); cloud KMS key clients, HPKE, Noise,
  WireGuard, PIV, TPM, PKCS #7, Sigstore signing and time-stamping modules in all three ecosystems
  (Go 14 new patterns, `github.com/sigstore/sigstore*` widened; PyPI 6; Maven 5).
* **Go** (F4–F6): key construction (`rsa`/`ecdsa` key structs, `elliptic.CurveParams`, Ed25519
  key conversions), Go 1.25 `ecdsa.ParseRawPrivateKey` / `ParseUncompressedPublicKey`, Go 1.26
  `rsa.EncryptOAEPWithOptions` and `crypto/hpke` (also `filippo.io/hpke`) identifiers, new rule
  `go.pqc.mldsa` for Go 1.27 `crypto/mldsa` and the TLS ML-DSA schemes (67 Go rules).
* **Extensionless Python scripts** (F7): files without `.` whose first line is a Python
  interpreter line are scanned as Python.
* Documented (F8): Go block ciphers created in another function stay a design limitation.
* Conformance: four new cases, 59 cases and 1243 findings; 36 expected findings changed their
  primitive (F1).

### Go support (DECISIONS G1–G16, SPEC section 17)

* New language **Go**: `.go` files are parsed with tree-sitter-go **v0.25.0** (ABI 15; pinned with
  its SHA-256 in `native/sources.lock`, built by `native/build-natives.sh`, MIT licence in
  `NOTICE`); `--version` also prints its ABI.
* Import paths, aliases, default package names (`/vN` suffixes), dot and blank imports; in-file
  constant resolution (consts, variables assigned once, function scopes, plain assignments bound
  where declared); bound names of local variables (`block, _ := aes.NewCipher(k)`); calls,
  references (function values, constants; not in comparisons, `switch` cases, map keys),
  composite literals and `new(T)`, field assignments; Java-style selection with nested-duplicate
  folding.
* Rule format: `language: go` with the anchors `call`, `ref`, `composite`, `assign` and the
  conditions `anySymbol`, `value`, `valueContains`, `param` (schema branch `goPattern`;
  additive, the rule format version stays 1).
* 66 bundled Go rules (`rules/go/`) for the standard library `crypto/...` and
  `golang.org/x/crypto`, including the Go 1.24 packages (`crypto/hkdf`, `crypto/pbkdf2`,
  `crypto/sha3`, `crypto/mlkem`), TLS versions, suites and groups, `InsecureSkipVerify`, x509,
  SSH; `math/rand` as weakness indicator (off by default).
* New ecosystem **`golang`**: `go.mod` (`require`) and `go.sum` (modules whose code is built)
  with the module list `rules/dependencies/dep.golang.yaml` (36 patterns); purl
  `pkg:golang/<module path>@<version>`.
* `*_test.go` files are test files (case-sensitive), like `testdata/` directories.
* The scan summary shows `go N` when Go files were scanned (unchanged
  otherwise); `rules validate` prints the Go and golang counts.
* Conformance: nine new cases (`go/*`, `deps/golang`; 157 findings), 55 cases and 1178
  findings in total. Java and Python results are unchanged (byte-identical CBOMs apart from the
  rule digest and the serial number derived from it).

### CycloneDX 1.7 output (DECISIONS C1)

* Output is CycloneDX **1.7** by default (`specVersion` `"1.7"`, schema of specification release
  1.7.2). `--cyclonedx-version 1.6` writes the former 1.6 document unchanged.
* New in 1.7 output: `algorithmProperties.algorithmFamily` with the registry name of the rule's
  family (`SHA2` → `SHA-2`, `DH` → `FFDH`, `EC` → `ECDSA` / `ECDH` by primitive, `RSA` by scheme,
  …; SPEC table 11.3.1a) and `algorithmProperties.ellipticCurve` for named curves
  (`secg/secp256r1`, `nist/P-256`, …; table 11.3.1b), only where the rule determines them.
* Nothing removed: `ciphersift:family` and all other properties stay; components, order and
  bom-refs are the same in both versions. Conformance expectations unchanged.
* Tests validate every conformance CBOM against 1.7 and, in a second pass with the option, against
  1.6 — with cyclonedx-core-java 13.2.0 (unchanged pin; it bundles the 1.7.2 schema) and with
  json-schema-validator against the schemas vendored in `src/test/resources/cyclonedx/`.

### Owner decisions (E2, E15, E16; 7.3.2 and setup files confirmed)

* **Weakness indicators off by default** (E2): findings of rules with `indicator: weakness`
  (`java.rand.prng.insecure`, `python.rand.prng.insecure`) are reported only with the new option
  `--weakness-indicators`, which replaces `--no-weakness-indicators` (removed; using it is a usage
  error). With the option the metadata has `ciphersift:weaknessIndicators=included`. **Default
  output changes**: these findings are gone. Conformance: `common/weakness-indicators` now expects
  the default (3 findings instead of 8), `common/weakness-indicators-excluded` is replaced by
  `common/weakness-indicators-enabled` (the option, 8 findings), the two `fork-fixtures` cases pass
  the option, `common/test-files` loses its `random.random()` finding (deviation D15).
* **Algorithm OIDs** (E15): built-in table of 128 OIDs (SPEC 5.11). Dotted OIDs (also `OID.…`) in
  string lists, Python value texts and params are treated like the algorithm name; new patterns for
  BouncyCastle `ASN1ObjectIdentifier`, pyca `ObjectIdentifier`, asn1crypto `core.ObjectIdentifier`,
  pyasn1 `univ.ObjectIdentifier`; asn1crypto `algos.*` accept OIDs. Output: `cryptoProperties.oid`;
  the OID is part of an algorithm component's key, sort order and bom-ref (unchanged for components
  without OID). `SecretKeyFactory` accepts `PBKDF2`. Deferred `final` locals stay unresolved.
* **Apache Shiro** (E16): ten rules `java.lib.shiro.*` (MD2, MD5, SHA-1, SHA-2, SHA-3, Argon2,
  bcrypt, AES, Blowfish, secure random) for Shiro's public 1.x/2.x API; Shiro hash-class constants
  in the constants table. The Maven list already had `org.apache.shiro:shiro-crypto*` and
  `org.apache.shiro.crypto:*`.
* Bundled rules: 103 Java, 87 Python. Conformance suite: 46 cases (new `java/oid-table`,
  `python/oid-table`, `java/shiro`), all passing.

### Evaluation fixes (10-project evaluation, `ciphersift-eval/ISSUES.md`)

* **Python bare references** (E1): a `call` pattern without conditions also matches the name used
  as a value without a call — in tuples/lists/dicts, as a class attribute, as an argument or keyword
  value, on the right-hand side of an assignment — but not in annotations, `isinstance`/`cast`,
  comparisons, `except` clauses, class bases or parameter defaults (SPEC 8.6.1). New anchor `ref:`
  for names that are only used as values (enum members, cipher classes); it also matches operands.
* **Weakness indicators** (E2, proposed): rule key `indicator: weakness` on the two insecure-PRNG
  rules; component property `ciphersift:indicator=weakness`; option `--no-weakness-indicators`
  (metadata `ciphersift:weaknessIndicators=excluded`). Default output unchanged apart from the
  new property.
* **New Python coverage**: asn1crypto certificates, CRLs and algorithm identifiers (new condition
  `dictItems`) (E3); pyca / pyOpenSSL key loading, rules `python.key.load.private/.public/.parameters`
  (E4); libsecp256k1 bindings (electrum_ecc, coincurve, secp256k1-py) with the fixed parameter
  `secp256k1` (new `param: {value: s}`), `ecdsa_sign`/`ecdsa_verify`, pyaes (E5); `padding.PKCS1v15()`
  outside an operation (new condition `notInside`), Concat KDF, X9.63 KDF, KBKDF, PyJWT algorithm
  classes, python-pkcs11 mechanisms and key types, signxml methods (E12).
* **New Java coverage**: PKIX parameters, trust anchors, cert stores, BC certificate holders, CMS
  signed / enveloped data and time-stamp tokens (`java.cert.cms.signed`, `java.cert.cms.enveloped`),
  `KeyStore.getDefaultType` (E6); OkHttp `ConnectionSpec` / `CipherSuite` / `TlsVersion` (E7);
  BouncyCastle JCA provider digest classes such as `Keccak.Digest256` (E8); `*.unresolved` fallbacks
  for `SecretKeySpec`, `AlgorithmParameterGenerator`, `AlgorithmParameters`, `JcaContentSignerBuilder`
  and more `AlgorithmParameters` names (E9); `EllipticCurve`, `ECFieldFp`, BC EC parameter classes,
  `SecP*Curve`, `MGF1ParameterSpec` (E11); `SecureRandom.getInstance` reports its algorithm (E17).
* **Member types** (SPEC 7.3.2): an unqualified member-type name (`Builder`, `Digest`) denotes an API
  class only when its enclosing class is imported on demand; `Outer.Inner` as before.
* **Fixes**: a padding variable bound to several paddings reports all of them at the operation call;
  method-only findings are named after the matching API symbol instead of the receiver (E13, E17);
  `verify=False` / `ssl=False` only on HTTP-client calls and methods (E14).
* **Dependencies** (E10): `setup.py` `install_requires` / `extras_require` (literal, also through
  module-level names) and `setup.cfg`; list entries `org.apache.shiro.crypto:*`, `electrum-ecc`,
  `pyaes`, `pysha3`, `safe-pysha3`.
* CycloneDX related-material types for the subtypes `private-key`, `public-key`, `cms-signed-data`,
  `cms-enveloped-data`.
* Pre-filter: also requires `kwargs` keywords, `dictItems` keys and, for member types, the
  top-level class name (keeps the JDK and Python-stdlib throughput in the earlier range).
* Bundled rules: 93 Java, 87 Python. Conformance suite: 43 cases (15 new), 736 findings, all passing;
  seven expectations of six generated cases changed (deviations D10–D14, DECISIONS.md).
* Not changed: E15 (deferred `final` locals, OIDs) and E16 (Shiro's own hash API, names of an
  evaluated project); D1–D8 by design. See `spec/DECISIONS.md`.

### Follow-up (code-review items, start-up and speed)

* Java version check: `bin/ciphersift` selects `CIPHERSIFT_JAVA`, `JAVA_HOME/bin/java` or `java`
  on `PATH`, falls back only to another explicitly configured runtime, and reports a runtime older
  than 23 in one line with the new exit code 6. The jar's entry point is compiled for Java 8, so
  `java -jar` on Java 8–22 gives the same message instead of `UnsupportedClassVersionError`.
* Start-up about 1.3 s → 0.5 s: the bundled rules are validated in full at build time (the build
  fails on invalid rules) and loaded from a pre-parsed, digest-verified copy without schema
  validation at run time (`--rules` directories are still validated in full); rules, native
  libraries and grammars are prepared on background threads while the command line is parsed.
* Throughput: source files in which no rule's names occur are not parsed (textual Aho–Corasick
  pre-filter; output unchanged); fewer allocations in the tree copy; at most two threads copy
  trees at once (jtreesitter's per-node cleaner registrations contend otherwise). JDK sources
  (5.1 M lines): 67 s → 24 s single-threaded, 41 s → 11 s with 8 threads.
* File names are decoded as UTF-8 under any locale, also with plain `java -jar` (DECISIONS O1);
  a warning names command-line arguments the locale cannot decode.
* Decisions O2–O7: `param` no longer makes a Java pattern specific; comments in byte-array
  initialisers are ignored by the constant-bytes check; alias chains longer than 16 steps are
  unresolved; `pkg @ https://…` in `pyproject.toml` is skipped; `new: X*` gives a clear rule
  error and symbolic links inside `--rules` directories are rule errors; SPEC 15.4 updated.
* Conformance suite: 28 cases (added `java/array-comments`, `python/alias-chain-limit`,
  `deps/pyproject-direct-reference`), 573 findings, all passing.

### First implementation

First implementation of the CipherSift specification 1.0 (rule format version 1).

* `scan`, `rules validate`, `rules export`, `--version`; exit codes 0–5 as specified.
* Java analysis: imports and class references, constant resolution (locals, fields, cross-file
  constants inside the scan root, constants table, text blocks, arrays), constant-bytes check,
  specificity-based rule selection, nested-duplicate suppression, `override` rules.
* Python analysis: imports, scopes with parameter shadowing, alias and bound-call resolution,
  string lists, symbol sets, `reportAt` attribution, refinement, attribute assignments; depth
  limits 64 / 16 / 12 (DECISIONS M4).
* Dependency manifests: `pom.xml` (properties, same-POM managed versions — DECISIONS M2),
  Gradle scripts and version catalogs, `requirements*.txt`, `requirements/*.txt`,
  `pyproject.toml` (PEP 621, PEP 735, Poetry), `Pipfile.lock`, `poetry.lock`.
* Deterministic CycloneDX 1.6 output with content-derived serial number and stable bom-refs.
* Bundled rules: 88 Java, 79 Python, constants table, Maven and PyPI library lists.
* Native tree-sitter core v0.26.10, tree-sitter-java v0.23.5, tree-sitter-python v0.25.0
  (linux-x86_64), built by `native/build-natives.sh`.
* Conformance suite: 25 cases (two added: `deps/maven-managed-version`,
  `python/deep-call-args`), 562 findings, all passing.
