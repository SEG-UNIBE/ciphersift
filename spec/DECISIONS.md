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

# Evaluation fixes (2026-10-17)

Work list: `ciphersift-eval/ISSUES.md` (10-project evaluation). Same clean-room rules as before. Unless marked otherwise, each item was decided by the implementer as the issue suggested. The rows that were proposed to the owner (E2, 7.3.2, E10 manifests) and the deferred items E15 and E16 were **decided by owner** on 2026-10-17; see "Owner decisions" below. `SPEC.md`, `rule-schema.json`, the bundled rules and the conformance suite were updated accordingly.

| item | decision | where in SPEC.md |
|---|---|---|
| E1 Python references without a call | A `call` pattern without filter conditions also fires on a *bare reference* in value position (container element, call argument / keyword value, right-hand side of an assignment) whose resolved name equals the value exactly; type contexts, type-test calls (`isinstance`, `cast`, …), `except` clauses, comparisons, class bases and parameter defaults are not positions. New anchor `ref:` for names that are only ever used as values (enum members, classes); it fires in any expression position (also operands). Rules: `ref:` for `ciphers.algorithms.*`, python-pkcs11 `Mechanism`/`KeyType`, signxml `SignatureMethod`/`DigestAlgorithm`, PyJWT `*Algorithm.SHA*`, `electrum_ecc.GENERATOR`. | 5.6, 8.1, 8.6.1, Appendix A D10 |
| E2 insecure-PRNG findings | **Decided by owner: weakness indicators are off by default.** Same rule ids `java.rand.prng.insecure` / `python.rand.prng.insecure`, both with the rule key `indicator: weakness` (the only bundled rules with it). Their findings are reported only with the option `--weakness-indicators` (it replaces `--no-weakness-indicators`, which no longer exists); they are dropped after extraction, so all other findings are byte-identical with and without the option. With the option the components carry `ciphersift:indicator=weakness` and the metadata `ciphersift:weaknessIndicators=included`. Not chosen: lower confidence by context, dropping them in test files (options b/c of the issue). | 3.1, 5.1, 5.3, 11.2.1, 11.3.4 |
| E3 asn1crypto | `asn1crypto.x509.Certificate`, `TbsCertificate`, `crl.CertificateList`, `csr.CertificationRequest` in `python.cert.x509`; `algos.{Digest,SignedDigest,Encryption,KeyEncryption,Kdf}Algorithm` with the new condition `dictItems: {algorithm: regex}` and their `…Id` classes with `firstString` in the hash, signature, cipher, key-wrap and PBKDF2 rules; `HmacAlgorithm` in HMAC. Certificate fingerprints (`cert.sha256`, an attribute read on an untyped receiver) are declined (Appendix B). `pem.unarmor` not added (decodes any PEM, keys as well). | 5.6, Appendix B |
| E4 pyca key loading | New rules `python.key.load.private` / `.public` / `.parameters` (related-crypto-material, subtypes `private-key`, `public-key`, `domain-parameters`; CycloneDX types `private-key`, `public-key`, `other`). No Java mirror. | 11.3.3 |
| E5 libsecp256k1, pyaes | New rule `python.asym.secp256k1` (electrum_ecc, coincurve, secp256k1-py; family EC, parameter `secp256k1` through the new `param: {value: s}`); `ecdsa_sign`/`ecdsa_sign_recoverable`/`ecdsa_verify` method names in `python.asym.ecdsa`; `pyaes.AESModeOfOperation{CBC,CTR,ECB,CFB,OFB}` and `pyaes.AES`. | 5.6, 8.8 |
| E6 Java PKI / CMS | `java.cert.x509`: `PKIXParameters`, `PKIXBuilderParameters`, `TrustAnchor`, `CertStore.getInstance`, BC `X509CertificateHolder`, `X509CRLHolder`, `JcaX509CertificateHolder`, `JcaX509CRLHolder`, `JcaCertStore`, …; `java.cert.keystore`: `KeyStore.getDefaultType`, `KeyStore.Builder.newInstance`. New rules `java.cert.cms.signed` (CMS SignedData, BC TSP; subtype `cms-signed-data` → CycloneDX `signature`) and `java.cert.cms.enveloped` (EnvelopedData; `cms-enveloped-data` → `ciphertext`). `new BouncyCastleProvider()` not added (a provider is not an asset). | 11.3.3 |
| E7 OkHttp TLS | `java.prot.tls.context`: `new ConnectionSpec.Builder`, `ConnectionSpec.{MODERN,COMPATIBLE,RESTRICTED}_TLS`, `CipherSuite.TLS_*` / `SSL_*`, `forJavaName`, methods `cipherSuites` / `tlsVersions`; string arguments of these methods feed the RC4/NULL/EXPORT and version rules. Weak suites given as `CipherSuite` constants are reported as TLS only (a field anchor has only a trailing `*`). | — (rules) |
| E7/E8 member types (7.3.2) | **Decided by owner: accepted as implemented.** Needed for the nested-class patterns (`ConnectionSpec.Builder`, `SHA3.Digest256`): an unqualified member-type name (`Builder`, `Digest`) denotes the API class only if its enclosing class is imported on demand (or statically); before, step 6 assumed it, so `new Builder()` of any other class matched. The pre-filter requires the top-level class name for member types. No bundled result changed. | 7.3.2, 14 |
| E8 BC JCA provider digests | `new` patterns for `org.bouncycastle.jcajce.provider.digest.{SHA1,SHA224,SHA256,SHA384,SHA512,SHA3,Keccak,MD2,MD4,MD5,RIPEMD160,Blake2b,Blake2s,Blake3}.*` in the matching hash rules (Keccak under SHA3, as `KeccakDigest` already was). | — (rules) |
| E9 `*.unresolved` fallbacks | New fallbacks `java.jca.secretkeyspec.unresolved`, `java.jca.algorithmparametergenerator.unresolved`, `java.jca.algorithmparameters.unresolved`; `new JcaContentSignerBuilder` in `java.jca.signature.unresolved`. Audit: `AlgorithmParameters.getInstance` gained specific patterns for Blowfish, ChaCha20-Poly1305, DES, DESede, RC2, PBE/PBES2/PBEWith…; `JcaContentVerifierProviderBuilder` and `JcaDigestCalculatorProviderBuilder` take no algorithm (no fallback needed); `CertificateFactory`, `KeyStore`, `SSLContext`, `SecureRandom`, `TrustManagerFactory`, `KeyManagerFactory` are bare patterns already. | — (rules) |
| E10 dependencies | Lists: `org.apache.shiro.crypto:*` (Shiro 2.x crypto modules), `electrum-ecc`, `pyaes`, `pysha3`, `safe-pysha3` (the others named in the issue were listed already). New manifests (**decided by owner: accepted as implemented**): literal `install_requires` / `extras_require` of `setup()` in `setup.py` (also through module-level names) and `setup.cfg` `[options] install_requires` / `[options.extras_require]`. `setup.py` stays Python source (D1); it is parsed even if the pre-filter would skip it. | 1.1, 4.5, 9.8 |
| E11 EC / MGF1 classes | `java.asym.ec`: `EllipticCurve`, `ECFieldFp`, `ECFieldF2m`, `ECPoint` (JCA spec), BC `ECDomainParameters`, `ECNamedDomainParameters`, `ECKeyGenerationParameters`, `EC{Public,Private}KeyParameters`, `jce.spec.EC*Spec`, `ECCurve.Fp/F2m`, `SecP*Curve` constructors and their `q` fields. Hash rules: `new MGF1ParameterSpec(name)` and the `MGF1ParameterSpec.SHA*` fields. Not added: hash detail of `PSSParameterSpec` / `OAEPParameterSpec` (a specific hash pattern on the same constructor would suppress the bare RSA pattern, 7.7.1). | — (rules) |
| E12 smaller Python gaps | New rule `python.asym.rsa.pkcs1v15` for `padding.PKCS1v15()` outside sign/verify/encrypt/decrypt, with the new condition `notInside`; ConcatKDF, X9.63 KDF, KBKDF rules; python-pkcs11 mechanisms and key types, signxml methods (enums and the old string API), PyJWT algorithm classes. | 5.6 |
| E13 RSA padding attribution | Rule fix, no engine special case: `method: [sign, verify]` + `anySymbol: [padding.PSS]` and `method: [encrypt, decrypt]` + `anySymbol: [padding.OAEP]`, like PKCS1v15. A variable bound to several paddings now gives all of them at the operation call (flow-insensitive, the issue's acceptable outcome). Method-only patterns with `anySymbol` are named after the first listed symbol that hits (E17's receiver-named component). | 8.6, Appendix A D12, Appendix B |
| E14 `verify=False` | The `anyCall` patterns for `verify=False` and `ssl=False` are replaced by `call: requests / pip._vendor.requests / httpx` (`verify`), `call: aiohttp` (`ssl`) and the HTTP-client method names `get, post, put, patch, delete, head, options, request, send, stream, Session, Client, AsyncClient, ClientSession, TCPConnector, ws_connect` and the requests-oauthlib session methods `fetch_token, fetch_request_token, fetch_access_token, refresh_token` (both keywords). `cert_reqs`, `verify_ssl`, `assert_hostname`, `check_hostname` stay `anyCall` (their names are specific). The pre-filter now requires `kwargs` keywords of `call`/`method` patterns. | Appendix A D11, Appendix B, 14 |
| E15 deferred `final` locals, OIDs | **Decided by owner.** OIDs: built-in algorithm OID table (128 OIDs; RFC 8017, 3279, 5480, 5758, 8410, 5639, 3565, 5084, 3394, 5649, 8018, 7914, PKCS #3, NIST CSOR, FIPS 203/204/205); a dotted OID literal or resolved constant (optionally `OID.`-prefixed) in a string list, value text or param is treated like the table's algorithm name; new patterns for BouncyCastle `ASN1ObjectIdentifier`, pyca / asn1crypto / pyasn1 `ObjectIdentifier`; asn1crypto `algos.*` accept OIDs; the OID is reported as `cryptoProperties.oid` and is part of an algorithm component's key; unknown OIDs give no finding. Deferred `final` locals: unchanged and documented (a declarator without initialiser stays unresolved, 7.4.3). | 5.11, 7.4.6, 7.8, 8.5, 8.8, 10.1, 11.3, 11.6, Appendix B |
| E16 Shiro hash API | **Decided by owner: add Shiro library rules.** Ten rules `java.lib.shiro.{hash.md2,hash.md5,hash.sha1,hash.sha2,hash.sha3,hash.argon2,hash.bcrypt,sym.aes,sym.blowfish,rand.secure}` built from Shiro's documented public API, 1.x and 2.x package names (not from the evaluated project's internal use): hash classes `Md2/Md5/Sha1/Sha256/Sha384/Sha512Hash` (constructors and `from*` factories) and their `*CredentialsMatcher`s; `SimpleHash`, `SimpleHashRequest`, `HashedCredentialsMatcher` and `setHashAlgorithmName` with an algorithm name; Shiro 2 `Argon2Hash`, `Argon2HashProvider`, `BCryptHash`, `BCryptProvider` and `setDefaultAlgorithmName` with `argon2*`/`bcrypt*`; `AesCipherService`, `BlowfishCipherService`, `DefaultBlockCipherService` with `AES`/`Blowfish`; `SecureRandomNumberGenerator`. The constants table gained the classes' `ALGORITHM_NAME` / `DEFAULT_ALGORITHM_NAME`. The Maven list already covered `org.apache.shiro:shiro-crypto*` and `org.apache.shiro.crypto:*`. | 5.1, 5.10 |
| E17 small details | `SecureRandom.getInstance` reports its algorithm as `param` (the first bundled Java rule with `param`); PKCS1v15 components are named after the padding API (E13); the import-fallback double report is flow-insensitivity (Appendix B, not changed); `certifi` / `commons-codec` stay on the lists (documented as debatable in the README); XChaCha20 and the PSS/OAEP hash detail not changed. | 5.5, Appendix A D14 |
| E18 robustness / docs | Documented in Appendix B and the README (binary literal with `__`; extensionless scripts). No grammar update (pinned by SPEC 6.1). | Appendix B |
| D1–D8 | Not changed (by design). E1 deliberately excludes parameter default values, so D6 stays as it is. | Appendix B |
| Rule format | Additive keys only (`indicator`, Python `ref`, `dictItems`, `notInside`, `param.value`); rule format version stays 1; a 1.0 rule set loads unchanged. The relatedCryptoMaterial type mapping (11.3.3) gained four subtypes. | 5, 11.3.3 |
| Generated rule files | Files changed by hand carry a second header line; `spec/tools/convert_rules.py` no longer reproduces them (the BF-CBOM sources are not available in this round). | — |

**Changed conformance expectations** (each recorded in `conformance/deviations.yaml`, so that a regeneration reproduces them; inputs unchanged, so the trailing comments of these lines still describe the earlier behaviour):

| case | change | justification |
|---|---|---|
| `python/fork-fixtures` | + SHA2 at `pycryptodome/legacy.py:23` (`HMAC.new(key, digestmod=SHA256)`) | E1/D10: the module `Crypto.Hash.SHA256` is passed as the hash, a bare reference matched by `call: Crypto.Hash.SHA256`. |
| `python/fork-fixtures` | names of `misc/libs.py:33` (`OpenSSL.crypto.TYPE_RSA` for `pk.generate_key`), `pyca/ciphers.py:34`, `:35`, `pyca/operations.py:30` (`cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15` for `priv.sign`, `priv.public_key().encrypt`, `rsa_key.public_key().verify`) | E13/E17/D12: method-only patterns are named after the matching symbol, not the receiver. |
| `python/name-resolution` | + SHA1 at `pkg/imports.py:14` (`H = hl.sha1`) | E1/D10: alias definition is a bare reference. |
| `python/arguments` | − validation disabled at `args.py:15` (`some_helper(url, verify=False)`) | E14/D11: not an HTTP client. |
| `python/attribution` | + OAEP at `ops.py:17` (`key.decrypt(msg, pad)`, `pad = padding.OAEP(…)`) | E13/D12: padding object in a variable attributed to the operation call. |
| `python/setup-py` | + `cryptography`, `pyjwt 2.8.0` from `setup.py` | E10/D13: `install_requires` is read. |
| `java/regex-battery` | `param` of `SecureRandom.getInstance` at lines 137–139: `SHA1PRNG`, `DRBG`, `NativePRNG` | E17/D14. |

**New conformance cases** (hand-written expectations, derived from SPEC.md and the rules; each built from the issue's reproducer): `python/references` (E1), `common/weakness-indicators` and `common/weakness-indicators-excluded` (E2; the latter renamed `-enabled` with the owner decisions below), `python/asn1crypto` (E3), `python/key-loading` (E4), `python/secp256k1-pyaes` (E5), `java/pki-cms` (E6), `java/okhttp-tls` (E7, also 7.3.2), `java/bc-provider-digests` (E8, also 7.3.2), `java/fallbacks` (E9), `deps/setup-files` (E10), `java/ec-mgf1` (E11), `python/misc-libs` (E12), `python/padding-flow` (E13), `python/verify-false` (E14).

# Owner decisions (2026-10-17)

Decided by A. Boll (project owner) on the items left open by the evaluation fixes. The rows above
(E2, 7.3.2, E10, E15, E16) are updated; `SPEC.md`, the README, the CHANGELOG, the rules and the
conformance suite follow them.

| item | decision | where in SPEC.md |
|---|---|---|
| E2 weakness indicators | Decided by owner: off by default; opt in with `--weakness-indicators` (replaces `--no-weakness-indicators`). Rules and the `ciphersift:indicator=weakness` property stay. | 3.1, 5.1, 5.3, 11.2.1, 11.3.4 |
| 7.3.2 member types | Decided by owner: accepted as implemented. | 7.3.2 |
| E10 `setup.py` / `setup.cfg` manifests | Decided by owner: accepted as implemented. | 9.8 |
| E15 OID table | Decided by owner: built-in, documented OID table; OIDs treated like algorithm names; `cryptoProperties.oid`; unknown OIDs give nothing; deferred `final` locals stay unresolved (documented). | 5.11, Appendix B |
| E16 Apache Shiro | Decided by owner: `java.lib.shiro.*` rules for Shiro's public crypto API. | 5.1, 5.10 |

**Changed conformance expectations** (E2, by design — the default output no longer contains
weakness indicators; every case that expected insecure-PRNG findings was checked):

| case | change | justification |
|---|---|---|
| `common/weakness-indicators` | now a default scan: − the five insecure-PRNG findings (8 → 3) | the case checks the default; E2 makes indicators opt-in |
| `common/weakness-indicators-excluded` → `common/weakness-indicators-enabled` | renamed; `options.json` now passes `--weakness-indicators` instead of `--no-weakness-indicators`; expectation = the former default one (8 findings) | the case is about indicators, so it enables them; the former option no longer exists |
| `java/fork-fixtures`, `python/fork-fixtures` | `options.json` with `--weakness-indicators`; expectations unchanged | they are the forks' own fixtures and the only coverage of the insecure-PRNG patterns (`ThreadLocalRandom`, `SplittableRandom`, `random.random`, …) |
| `common/test-files` | − `app/conftest.py:2` `random.random()` (`python.rand.prng.insecure`), deviation D15 | the case is about test-file marking, not indicators; `conftest.py` marking stays covered by `FilesTest` |
| `common/test-files-excluded` | unchanged | its conftest finding was already removed (`--exclude-tests`) |

No other case expected insecure-PRNG findings (checked with a search of all `expected.json`
files). The OID mapping (E15) and the Shiro rules (E16) change no existing expectation.

**New conformance cases** (hand-written expectations; the per-OID lines are derived from the table
of SPEC 5.11 and the rules' asset blocks, the other lines from the rules and SPEC 7.7 / 8.6, before
the implementation was run on them): `java/oid-table` (every table OID through
`ASN1ObjectIdentifier`; JCA `Signature`, `KeyFactory`, `AlgorithmParameters`, `MessageDigest`,
`Mac`, `Cipher`, `SecretKeyFactory` with OIDs, through a constant and with the `OID.` prefix;
unknown and non-OID strings; a deferred `final` local), `python/oid-table` (every table OID through
`x509.ObjectIdentifier`, no finding for OIDs without a Python rule; `x509.oid.ObjectIdentifier`,
asn1crypto `core.ObjectIdentifier`, `algos.*Id` and `algos.*Algorithm` dicts, pyasn1, a constant, a
curve parameter, unknown OIDs), `java/shiro` (E16 reproducer and the 1.x / 2.x API).
