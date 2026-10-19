<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 The CipherSift Authors -->

# CipherSift

CipherSift is a clean-room reimplementation of the approach of **Crypsy** by Christian Näther and
Eduard Hirsch ([*Hidden Ciphers and Where to Find Them: Static Discovery and Assessment of
Cryptographic Assets in Software*](https://arxiv.org/abs/2608.04857), arXiv 2608.04857), which
scans Go and Ruby. CipherSift covers Java, Python and Go. It was written from a behavioural
specification, without Crypsy's source code (the Go support as well: its rules were written from the
Go API documentation, without Crypsy's Go rules); the process is documented in
[`spec/PROVENANCE.md`](spec/PROVENANCE.md).

CipherSift is a static scanner that finds cryptographic assets (algorithms, protocols,
certificates, keys and related material, crypto libraries) in **Java**, **Python** and **Go** source
code and in **Maven/Gradle**, **PyPI** and **Go module** (`go.mod`, `go.sum`) dependency manifests. It writes a **CycloneDX 1.7**
Cryptography Bill of Materials (CBOM) as JSON (CycloneDX 1.6 on request). Detection is rule-driven: the cryptographic
knowledge lives in YAML rule files, and the scanner provides the language analysis (name
resolution, constant resolution, argument analysis).

The behaviour is specified in [`spec/SPEC.md`](spec/SPEC.md); this README is the user guide.
Licence: Apache-2.0 (see `LICENSE` and `NOTICE`).

## Build

Requirements: JDK 25 (the code targets Java 23, the minimum runtime), Maven 3.9, and gcc on
Linux x86-64 for the native tree-sitter libraries.

```sh
mvn verify            # natives if missing, bundled-rule validation, unit tests, conformance suite, licence headers
ls target/ciphersift-1.2.0-all.jar
```

`native/build-natives.sh` compiles the tree-sitter core and the Java, Python and Go grammars from
the sources vendored under `native/vendor/` (`build-natives.sh fetch` re-downloads them from the
URLs and SHA-256 sums pinned in `native/sources.lock`). Maven runs it automatically in
`generate-resources` when `target/native/<platform>/` is missing. The libraries are packaged
into the jar and extracted at run time to `$XDG_CACHE_HOME/ciphersift/native/<digest>/`
(default `~/.cache/…`), or to a fresh private temporary directory if that directory cannot be
created or could be modified by other users (group- or world-writable, owned by someone else).

Docker: `docker build -t ciphersift .`, then
`docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/scan:ro" -v "$PWD/out:/out" ciphersift scan /scan -o /out/cbom.cdx.json`
(`--user` lets the container write into your `out/` directory; without it the image's own user
needs write permission there).

## Usage

```
ciphersift scan <dir> -o <out.cdx.json> [--exclude GLOB]... [--include-tests | --exclude-tests]
                [--threads N] [--rules DIR] [--weakness-indicators] [--python-thin-wrappers]
                [--transitive-deps] [--feature ID=on|off]... [--cyclonedx-version V] [--quiet | --verbose]
ciphersift rules validate [--rules DIR]
ciphersift rules export <dir>
ciphersift --version
ciphersift --help | ciphersift <command> --help
```

Run it with `java -jar target/ciphersift-1.2.0-all.jar …` (the jar manifest enables
native access) or with the launcher `bin/ciphersift`.

**Java runtime.** CipherSift needs Java 23 or newer. The launcher uses `$CIPHERSIFT_JAVA` (path
of a `java` executable) if set, else `$JAVA_HOME/bin/java`, else `java` on `PATH`. If the chosen
runtime is too old and another one is configured explicitly (`CIPHERSIFT_JAVA` too old →
`JAVA_HOME`), that one is used; the launcher never searches the file system. Otherwise it stops
with one line and exit code 6:

```
ciphersift: error: CipherSift needs Java 23 or newer; found 21.0.2 (/usr/lib/jvm/jdk-21.0.2/bin/java); set CIPHERSIFT_JAVA or JAVA_HOME
```

`java -jar` on Java 8–22 prints the same message (without the path) and exits with 6 too.
Extra JVM options can be passed in `CIPHERSIFT_JAVA_OPTS` (e.g. `-Xmx4g`).

| Option | Meaning |
|---|---|
| `-o FILE` | Output file (required); `-` writes the CBOM to standard output. Written atomically. |
| `--exclude GLOB` | Skip files/directories. `*`, `?`, `[a-z]`, `[!x]`; `**` matches whole segments. A glob without `/` matches the base name anywhere (`*_pb2.py`, `node_modules`); one with `/` matches the relative path (`vendor/**`, `**/gen/*.py`). A trailing `/` restricts it to directories. |
| `--include-tests` / `--exclude-tests` | Test files are scanned and marked (default), or skipped. Test files: a directory named `test`, `tests`, `testing`, `__tests__`, `testdata`, `test-data`, `testfixtures`, `test-fixtures`, `integrationtest`, `integration-test(s)` or `src/it` (case-insensitive); Java `*Test.java`, `*Tests.java`, `*TestCase.java`, `*IT.java`, `Test*.java` followed by an upper-case letter (`TestUtils.java`); Python `test_*.py`, `*_test.py`, `tests.py`, `conftest.py`; Go `*_test.go` (case-sensitive). |
| `--threads N` | Worker threads (default: processors, at most 8). The output does not depend on it. |
| `--rules DIR` | Use the rules under `DIR` instead of the bundled ones (`rules export` gives you a copy to edit). |
| `--weakness-indicators` | Also report *weakness indicators* (see below), e.g. non-cryptographic random generators. Off by default; all other findings are exactly those of a default scan. |
| `--python-thin-wrappers` | Also treat thin Python functions (at most 8 lines, one family, any name) as crypto wrappers whose call sites are reported (see "Wrapper propagation"). Off by default; the metadata records it as `ciphersift:pythonThinWrappers=included`. |
| `--transitive-deps` | Also report transitive dependencies: `go.mod` requirements marked `// indirect` and `go.sum`. Off by default (direct requirements come from `go.mod`). The Python lock files `poetry.lock` and `Pipfile.lock` are reported by default; `--feature skip-python-lock-files=on` skips them too. |
| `--feature ID=on\|off` | Switch one detection booster of round t2 on or off (repeatable). Ids and defaults: SPEC 3.1; every booster is on by default except `transitive-deps` and `skip-python-lock-files`. Non-default settings are recorded in the metadata (`ciphersift:features`). |
| `--cyclonedx-version V` | `1.7` (default) or `1.6`. The 1.6 document is the former output format: the same components, bom-refs and properties, without the 1.7 registry fields `algorithmFamily` and `ellipticCurve`. |
| `--quiet`, `--verbose` | Only errors / also debug messages (one line per skipped file) on standard error. |

Exit codes: `0` success (unreadable or unparsable files are skipped with a warning), `1` internal
error or native libraries not loadable, `2` usage error, `3` bad scan root, `4` invalid rules,
`5` output not writable, `6` no Java 23+ runtime.

Scanned inputs: `*.java`, `*.py` (including `setup.py`, whose literal `install_requires` /
`extras_require` are also read as dependencies), `*.go`, `pom.xml`, `build.gradle(.kts)`,
`*.versions.toml`, `requirements*.txt` and `requirements/*.txt`, `pyproject.toml`,
`Pipfile.lock`, `poetry.lock`, `setup.cfg`, `go.mod`, `go.sum`. Files without one of these names or extensions are
not scanned, except files without any `.` in their name whose first line is a Python interpreter
line (`#!/usr/bin/env python3`, `#!/usr/bin/python3.12`): they are scanned as Python (SPEC 4.5). `.git`, `.hg`, `.svn` and symbolic links are never followed; files
over 10 MiB and binary source files are skipped.

The output is byte-identical for identical inputs, regardless of thread count, file-system
order, locale, time zone or the location of the scan root. File names are always decoded as
UTF-8, also with plain `java -jar` under a C/POSIX locale. Only *command-line arguments* depend
on the locale (the JVM decodes them before CipherSift starts): under a non-UTF-8 locale a
non-ASCII scan root, output path or `--exclude` glob cannot be decoded, and CipherSift warns
about it. `bin/ciphersift` and the Docker image run the JVM with `LC_ALL=C.UTF-8` when the
current locale is not UTF-8. Set `SOURCE_DATE_EPOCH` to get a `metadata.timestamp`.

Start-up takes about half a second (measured 2026-10-17 on the 32-core development machine with
JDK 25.0.1, natives cached; bundled rules are validated when the jar is built, so they
are not re-validated at run time). Source files in which no rule's names occur at all are not
parsed; this changes nothing in the output, only the speed.

Optional, JDK 24 or newer: an AOT cache cuts start-up further (about 0.53 s → 0.37 s, measured
2026-10-16 on the same machine, before Go support).
It belongs to one JDK build and one jar file; create it once with a normal scan, then pass it on
every run (the directory must exist). Keep the JVM's own log quiet, since a mismatch warning would otherwise go to standard
output:

```sh
CIPHERSIFT_JAVA_OPTS="-XX:AOTCacheOutput=$HOME/.cache/ciphersift/app.aot" bin/ciphersift scan src/ -o /tmp/x.cdx.json
export CIPHERSIFT_JAVA_OPTS="-XX:AOTCache=$HOME/.cache/ciphersift/app.aot -Xlog:aot=off,cds=off"
```

## Output format (for consumers)

A CycloneDX 1.7 JSON document (1.6 with `--cyclonedx-version 1.6`) with `bomFormat`, `specVersion`, a content-derived
`serialNumber`, `version`, `metadata` (tool, root component named after the scan root,
properties `ciphersift:rulesDigest`, `ciphersift:testFiles`, `ciphersift:filesScanned`,
`ciphersift:filesSkipped`), `components` and, when libraries were found, `dependencies`.

**Cryptographic components** (`"type": "cryptographic-asset"`):

* one component per *(rule, name, parameter, OID)* for algorithms and per *rule* for protocols,
  certificates and related material;
* `name`: Java — the matched algorithm string (`AES/GCM/NoPadding`, `SHA-256`) or the API
  (`GCMBlockCipher`, `MessageDigest.getInstance`); Python — the resolved call
  (`cryptography.hazmat.primitives.ciphers.Cipher`, `hashlib.new`); Go — the import path and
  member of the API (`crypto/aes.NewCipher`, `crypto.SHA256`); protocols — `TLS 1.2`, `SSH`;
  other types — the rule name;
* `cryptoProperties`: `assetType` and `algorithmProperties` (`primitive`, `algorithmFamily`,
  `parameterSetIdentifier`, `ellipticCurve`, `mode`, `padding`, `classicalSecurityLevel`), `protocolProperties` (`type`, `version`) or
  `relatedCryptoMaterialProperties` (`type`); `oid` when the algorithm was given as an object
  identifier (see below);
* `properties`: `ciphersift:ruleId`, `ciphersift:language`, `ciphersift:assetType` (only for
  `key-material`), `ciphersift:primitive`, `ciphersift:family`, `ciphersift:variant`,
  `ciphersift:subtype`, `ciphersift:indicator`, `ciphersift:testOnly` — each only when it has a
  value;
* `evidence.occurrences`: `location` (path relative to the scan root, `/`-separated), `line`,
  `symbol` (the API, e.g. `javax.crypto.Cipher.getInstance`) and `additionalContext`, a string
  holding compact JSON `{"ruleId":…,"snippet":…,"param":…,"test":true}`; an occurrence found by
  wrapper propagation has the called function as `symbol` (`Hash.sha3`), the call as snippet, and
  `"via":[…],"origin":"<path>:<line>"` before `test`.

**CycloneDX 1.7 registry fields.** `algorithmFamily` and `ellipticCurve` use the names of the
CycloneDX cryptography registry (`cryptography-defs`): `SHA-2`, `SHA-3`, `RIPEMD`, `CAMELLIA`,
`FFDH` for DH, `EdDSA` for Ed25519/Ed448, `ECDSA` / `ECDH` for EC signatures / key agreement,
`RSAES-OAEP`, `RSASSA-PSS`, `RSAES-PKCS1`, `RSASSA-PKCS1` for RSA with a known scheme, and so on
(full table: SPEC 11.3.1a); curves as `secg/secp256r1`, `nist/P-256`, `brainpool/brainpoolP256r1`,
`other/Curve25519` (SPEC 11.3.1b). A field is absent where the rule does not determine it (plain
RSA key generation, EC key generation without a primitive, PBE, ConcatKDF, X9.63 KDF). The rule's
own family stays in the property `ciphersift:family`, in both versions.

**Library components** (`"type": "library"`): `bom-ref` = `purl`
(`pkg:maven/<group>/<artifact>[@<version>]`, `pkg:pypi/<name>[@<version>]`,
`pkg:golang/<module path>[@<version>]`), Maven `group`,
`name`, `version` (only if known), properties `ciphersift:ruleId`, `ciphersift:ecosystem`,
`ciphersift:testOnly`; occurrences have `location` and `additionalContext`
(`{"ruleId":…,"snippet":"g:a:v","manifest":"pom"}`; the snippet is `name==v` for PyPI and
`path@v` for Go, e.g. `"golang.org/x/crypto@v0.40.0"` with `"manifest":"go-mod"`), no line.

**Weakness indicators.** Some rules do not detect a cryptographic asset but a sign of a possible
weakness: today the non-cryptographic random generators (`java.util.Random`, `Math.random`,
`ThreadLocalRandom`, Python `random.*`, Go `math/rand`; rules `java.rand.prng.insecure`,
`python.rand.prng.insecure` and `go.rand.prng.insecure`). They would be reported wherever they occur, also for jitter,
shuffling or test data, so most of them are harmless; they are therefore **not reported by
default**. Scan with `--weakness-indicators` to get them: their components then carry the
property `ciphersift:indicator` = `weakness`, and the metadata has
`ciphersift:weaknessIndicators` = `included`. A rule becomes an indicator with the top-level key
`indicator: weakness`.

**Algorithm OIDs.** A dotted object identifier given where an algorithm name is expected
(`Signature.getInstance("1.2.840.10045.4.3.2")`, `KeyFactory.getInstance("1.2.840.113549.1.1.1")`,
BouncyCastle `new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1")`, pyca `x509.ObjectIdentifier(…)`,
asn1crypto and pyasn1 OIDs) is looked up in a built-in table of 128 algorithm OIDs (RSA, RSA-PSS,
RSA-OAEP, the `*WithRSAEncryption`, DSA and ECDSA signatures, EC public keys and named curves
including brainpool, X25519/X448/Ed25519/Ed448, DH, MD2, MD5, SHA-1, SHA-2, SHA-3, HMAC, AES in all
modes and key wrap, 3DES, DES, RC2, PBKDF2, PBES2, scrypt, ML-KEM, ML-DSA, SLH-DSA; SPEC 5.11) and
treated like the algorithm's name; the component gets `cryptoProperties.oid`. Unknown OIDs give no
finding.

**Apache Shiro.** The rules `java.lib.shiro.*` report Shiro's public crypto API (1.x and 2.x package
names): `Sha256Hash`/`Sha384Hash`/`Sha512Hash`/`Md5Hash`/`Sha1Hash`, `SimpleHash`,
`HashedCredentialsMatcher` and `setHashAlgorithmName` with an algorithm name (also
`Sha256Hash.ALGORITHM_NAME`), the Shiro 2 Argon2 and bcrypt hashes, `AesCipherService`,
`BlowfishCipherService`, `DefaultBlockCipherService` with `AES`/`Blowfish`, and
`SecureRandomNumberGenerator`.

**Go.** The rules `go.*` (SPEC section 17) cover the standard library `crypto/...` packages —
`aes` and the `cipher` modes (AES-GCM/CBC/CTR/CFB/OFB when the block comes from `aes.NewCipher`,
also through a variable; a mode-only component otherwise), `des`, `rc4`, `rsa` (key size as
parameter; OAEP, PKCS #1 v1.5, PSS), `dsa`, `ecdsa`, `ecdh`, `elliptic` (curves as `P-256` …),
`ed25519`, `hmac`, `md5`, `sha1`, `sha256`, `sha512`, `sha3`, `hkdf`, `pbkdf2`, `mlkem`, `rand`,
`tls` (configurations, versions, cipher suites, key-exchange groups, `InsecureSkipVerify: true`),
`x509` (certificates, templates, key parsing, signature algorithms) and the `crypto.Hash`
constants — and `golang.org/x/crypto` (`chacha20`, `chacha20poly1305`, `poly1305`, `salsa20`,
`nacl/box`, `nacl/secretbox`, `nacl/sign`, `nacl/auth`, `curve25519`, `ed25519`, `scrypt`,
`argon2`, `bcrypt`, `hkdf`, `pbkdf2`, `sha3`, `blake2b`, `blake2s`, `md4`, `ripemd160`,
`blowfish`, `cast5`, `twofish`, `xts`, `pkcs12`, `ssh`), and the newer `crypto/hpke` (also
`filippo.io/hpke`; reported through its KEM, KDF and AEAD identifiers), `crypto/mldsa`, the
Go 1.25 raw ECDSA key encodings and key construction (`rsa.PublicKey{…}`, `ed25519.PublicKey(b)`,
`elliptic.CurveParams{…}`). Functions passed as values count as uses
(`hmac.New(sha256.New, k)` reports HMAC and SHA-2); TLS constants in comparisons and `switch`
cases do not. `go.mod` reports the modules of `rules/dependencies/dep.golang.yaml`
(`golang.org/x/crypto`, `filippo.io/age`, `github.com/cloudflare/circl`, JWT/JOSE libraries, …);
`// indirect` requirements and `go.sum` only with `--transitive-deps`.
Method calls on values of a known type are reported too (SPEC 17.12): `priv.Sign(…)` on an
`*rsa.PrivateKey` parameter, `pool.AddCert(c)` after `x509.NewCertPool()`, `k.ECDH(…)`, typed by
declarations in the file, type assertions, single-type `case`s, struct fields and a table of
standard-library constructors. Calls into a project package named after an algorithm
(`aes.NewCipher()` of the project's own `aes` package) carry that package's finding (SPEC 18.8).
`vendor/` directories are scanned like any other; pass `--exclude vendor` to skip vendored modules.
Selected third-party Go APIs have rules too (SPEC 17.11, DECISIONS T11): `filippo.io/age` (and
`agessh`), sigstore `cryptoutils`, the `crypto/x509` `Marshal*` key encoders,
go-securesystemslib `encrypted` (scrypt + NaCl secretbox), go-containerregistry `v1.SHA256` (when
imported as `v1`), CIRCL (`mldsa`, `mlkem`, `ed25519`, `ed448`, `x25519`, `x448`), flynn/noise
cipher-suite values, miekg/pkcs11 `CKM_ECDSA*`, the azkeys RSA constants, Sigstore protobuf-specs
key/hash values and `AlgorithmDetails`, go-piv algorithms and CIRCL SLH-DSA (round t2).

**Wrapper propagation** (SPEC section 18, DECISIONS T1–T14). Projects often call their own small
crypto helpers (`Hash.sha3(x)`, `sha256(x)`, `hmacSha512(k, d)`, `newAESGCM(k)`). CipherSift reports
the API call inside such a helper anyway; it now also reports each *call* of the helper, as a
further occurrence of the same component, with the helper chain in the occurrence
(`additionalContext` keys `via` — the called helper first, `"<path>:<line> <name>"` — and `origin`,
the line of the API call). A function or method is such a *crypto callable* when

* its **name names a family** that a finding in its body has (`sha256`, `hmac_sha_512`,
  `createSecp256k1KeyPair`, `SignECDSA`; the tokeniser and alias list are in SPEC 18.6), also
  transitively through other callables, up to a chain of 4 functions (Java, Python, Go); besides the
  algorithm names, `cert`, `privkey`/`pubkey`, `tls`/`ssl`/`ssh` and `hash160` name the matching
  certificate, key and protocol findings, and in Python `hash`/`digest` name the hash fallback; or
* it is a **thin wrapper**: exactly one family in its body (or in the callables it calls), whatever
  its name, at most 12 lines (Java, Go) or 8 (Python). On for Java and Go (Go skips a getter that
  returns an algorithm only as a fallback default); off for Python (`--python-thin-wrappers`).

Calls are resolved from declarations, without type inference: Java `Class.m(…)` (imports, the same
package, nested classes), static imports and methods of the enclosing classes; Python imports
(also relative imports and re-exports through `__init__.py`), the same module and `self.m(…)`;
Go `pkg.F(…)` for project packages (through `go.mod`, also `vendor/`), the same package, and
methods of a receiver, parameter or variable whose type is declared in the function. A call whose
candidates belong to two different classes, modules or packages is skipped (`--verbose` prints the
count). Wrappers defined in test files serve only test call sites; calls in test files are marked
as test occurrences. Weakness indicators are not propagated, nor are cryptographically secure
random-number helpers outside Java. A call on a line that already has a finding of the same family is not reported
again. Only the scan root takes part, so scanning a subdirectory can give fewer propagated
occurrences than scanning the whole project.

**Which libraries are listed.** The lists follow a written policy (SPEC 9.9): packages whose
documented purpose is cryptographic primitives, a cryptographic protocol or format, key management
in a KMS or hardware module (AWS KMS, Google Cloud KMS, Azure Key Vault keys, PKCS #11, PIV, TPM),
or signing / certificates / time-stamping of artefacts (Sigstore). General SDKs, secret stores and
data-model packages are not listed; by owner decision the HashiCorp Vault API client, Sigstore's
protobuf-specs and Rekor are (DECISIONS B-G4).

**Conditional library entries.** `commons-codec` is reported only where a Java file of the project
names its digest package `org.apache.commons.codec.digest` (`usedIf` in the rule; it is often used
only for Base64); `certifi` (a CA bundle) is no longer listed.

To turn a CBOM into a flat finding list, read for every occurrence its `location`, `line` and
`JSON.parse(additionalContext).ruleId`, together with the component's properties;
`spec/tools/conformance.py --show out.cdx.json` does exactly that.

Components are sorted by (rule id, name, parameter, OID), libraries by (ecosystem, package, version);
occurrences by (location, line, symbol, snippet). `bom-ref`s of cryptographic components are
stable hashes of their identity, so they can be compared across scans.

## Writing rules

Rules are YAML (or JSON) documents, one per file, validated against
[`spec/rule-schema.json`](spec/rule-schema.json) (SPEC section 5). Start from the bundled set:

```sh
ciphersift rules export my-rules/
# edit or add files under my-rules/
ciphersift rules validate --rules my-rules/
ciphersift scan src/ -o out.cdx.json --rules my-rules/
```

A `--rules` directory is always validated in full. It may itself be a symbolic link, but must not
contain symbolic links (each one is reported as a rule error, exit 4).

A source rule:

```yaml
# SPDX-License-Identifier: Apache-2.0
id: java.sym.aes.gcm            # unique; starts with the language
kind: source
language: java                  # java | python | go
name: AES-GCM usage in Java
asset:                          # what a match denotes
  type: algorithm               # algorithm | protocol | certificate | related-crypto-material | key-material
  primitive: block-cipher
  family: AES
  variant: GCM
match:                          # a rule matches if any pattern matches
- call: javax.crypto.Cipher.getInstance       # anchor: class + method
  firstString: (AES(_(128|192|256))?|Rijndael)/GCM(/.*)?$
- new: javax.crypto.spec.GCMParameterSpec     # anchor: object creation
```

**Java anchors**: `call: pkg.Class.method` (receiver resolved through imports; trailing `*`
makes the method a prefix), `new: pkg.Class` (no `*`), `method: name` (any receiver), `field:
pkg.Class.FIELD`, `override: name` (method declarations), `anyCall: true` (any method call
except comparisons, logging, collection builders and `getInstance`; only where no other pattern
holds — used for registry algorithm names such as XML-Security URIs and `SHA256withECDSA` passed to
an unknown API). Any pattern may carry `feature: <id>` (used only while that feature is on).
**Java conditions**: `firstString`,
`anyString` (regex at the start of the first / any resolved string argument, case-insensitive),
`stringContains`, `argsText` (regex over the argument text), `argsTextContains`, `constantArg: i`
(argument *i* is constant bytes, e.g. a hard-coded key), `inType` and `body` (for `override`),
`param: {index: i}` (report argument *i* as parameter set; not a filter, so it does not make a
pattern specific). String arguments are resolved
through literals, `+`, local and field constants (also in other files of the scan), a table
of well-known library constants (`rules/java/_constants.yaml`: also the JSR 105 algorithm URIs and
Bouncy Castle OID constants), the file's only no-argument getter `return "…";`, locals assigned
later with agreeing values, and `new SecretKeySpec(k, alg).getAlgorithm()`.

**Python anchors**: `call: dotted.name` (matches the resolved call name or any name below it:
`Crypto.Hash.MD5` matches `Crypto.Hash.MD5.new`), `method: name | [names]`, `anyCall: true` (with
`kwargs`), `assign: attr` (attribute assignment `x.attr = value`). **Python conditions**:
`firstString`, `stringContains`, `anySymbol`/`allSymbols` (names referenced in the arguments),
`kwargs: {keyword: regex}`, `noSymbolPrefix`, `minArgs`, `dictItems: {key: regex}` (a dictionary argument such as
`{'algorithm': 'sha256'}`), `notInside: [method names]` (the call is not an argument of such a
call), `value`/`valueContains` (for `assign`); `param: {keyword, index}`, `{self: true}` or
`{value: fixed}` and `reportAt: [method names]` (attribute the finding to an enclosing operation call
such as `sign(…)`) are not filters. A `call` pattern without conditions also matches the name used
as a value without a call — in a table, as a class attribute, as an argument
(`digest=hashlib.sha256`) — but not in annotations, `isinstance`/`cast`, comparisons or `except`
clauses; `ref: dotted.name` matches only such uncalled references, also as an operand (enum
members like `pkcs11.Mechanism.SHA256_RSA_PKCS`, classes like `algorithms.AES`). A rule's top-level
`indicator: weakness` marks its findings as weakness indicators. `literal: [strings]` matches string
literals in value positions (IANA SSH / JOSE / TLS-group names); `*.unresolved` Python rules are
fallbacks reported only when no specific rule of the same type and primitive hits the call.

**Go anchors** (SPEC 17.3) name the API by import path and member, split at the last `.`:
`call: crypto/aes.NewCipher` (the import's local name, alias or dot import is resolved; a trailing
`*` makes the member a prefix, `math/rand.*` is every member), `ref: crypto/tls.VersionTLS12` (a
member used as a value), `composite: crypto/tls.Config` (`tls.Config{…}`, `&…{…}`, `new(…)`),
`assign: InsecureSkipVerify` (a field set in a composite literal or by assignment). **Go
conditions**: `anySymbol` (APIs referenced in the arguments, also through local variables:
`block, _ := aes.NewCipher(k); cipher.NewGCM(block)`), `value`/`valueContains` (for `assign`);
`param: {index: i}`, `{self: true}`, `{value: fixed}` are not filters. A `call` pattern without
`anySymbol` also matches the function used as a value. Go uses the Java selection below.

Selection: in Java (and Go), patterns with conditions beat bare patterns of the same asset type, so the
`java.jca.*.unresolved` fallbacks only appear when no specific rule matched; a match nested in
another match of the same family (`new GCMBlockCipher(new AESEngine())`) is reported once. In
Python, a rule with a `variant`/`version` replaces its unrefined sibling on the same call, and
each rule reports at most one finding per line.

Regexes must be valid in both `java.util.regex` and Python `re` (no `(?P<…>)`, `\Z`, possessive
quantifiers, `\p{…}`); `spec/tools/regex_parity.py` checks this. Dependency rules
(`kind: dependency`) list package patterns per ecosystem (`org.bouncycastle:*`, `pycryptodome`,
`golang.org/x/crypto`).

## Limitations

By design (SPEC Appendix B): attribute reads are not anchors (asn1crypto `cert.sha256`
fingerprints are not reported); Python parameter defaults (`def f(h=hashlib.sha256)`) are not
references; a Java local assigned different values after its declaration resolves only if all values
select the same rules, and OIDs held in library constants other than Bouncy Castle's, or missing from
the built-in table, are not mapped; a member type (`Builder`, `Digest`) counts as the API class only when it is
qualified (`ConnectionSpec.Builder`) or imported; no data flow beyond constants (values from parameters,
configuration, `String.format`, `StringBuilder` or ternaries give an `*.unresolved` component in
Java and nothing in Python); receiver types are not inferred, so `method:` patterns are
heuristics; unimported Java simple names are assumed to be the API class; reassignment is tracked
by simple name per file; Python resolution is flow-insensitive and does not follow attributes,
return values or other modules; one algorithm per Java signature string (`SHA1withRSA` → RSA);
dependency versions come from the manifest only (no parent POMs, BOMs, Gradle plugins; ranges give
no version); Kotlin, Groovy, Scala etc. are not analysed; Go: method calls on values whose type is
not visible in the file (`key.Sign(…)` on an interface from another file, `aead.Seal(…)`) are not anchors, constants are resolved within the file only,
algorithm names in strings (`ssh.Config{Ciphers: …}`) and `golang.org/x/crypto/openpgp` are not
covered, `go.mod` `replace` directives are not applied; wrapper propagation does not follow calls
on variables of unknown type, inherited methods, interfaces or constructors, and does not fold
calls nested across lines; test detection is path-based, so
library code in directories such as `django/test/` counts as test code. tree-sitter-java 0.23.5
reports a syntax error for some valid literals (a binary literal with a double underscore,
`0b1000__0000`); the rest of the file is still analysed. Native libraries are bundled for
linux-x86_64 only.

## Testing

`mvn verify` runs the unit tests (surefire) and, against the fat jar, the conformance suite in
`spec/conformance/` with CycloneDX 1.7 schema validation of every produced CBOM (and a second
pass with `--cyclonedx-version 1.6`, validated against 1.6, with the same findings), determinism
checks and CLI checks (failsafe). The Python reference comparator also works:
`python3 spec/tools/conformance.py --cmd "java -jar target/ciphersift-1.2.0-all.jar"`.

## Evaluating CipherSift

CipherSift's rules and heuristics were tuned on the repositories in [TUNING-REPOS.md](TUNING-REPOS.md). Results on
those repositories are in-sample; use other projects for any evaluation or tool comparison.
