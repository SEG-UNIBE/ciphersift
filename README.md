<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 The CipherSift Authors -->

# CipherSift

CipherSift is a clean-room reimplementation of the approach of **Crypsy** by Christian Näther and
Eduard Hirsch ([*Hidden Ciphers and Where to Find Them: Static Discovery and Assessment of
Cryptographic Assets in Software*](https://arxiv.org/abs/2608.04857), arXiv 2608.04857), which
scans Go and Ruby. CipherSift covers Java and Python instead. It was written from a behavioural
specification, without Crypsy's source code; the process is documented in
[`spec/PROVENANCE.md`](spec/PROVENANCE.md).

CipherSift is a static scanner that finds cryptographic assets (algorithms, protocols,
certificates, keys and related material, crypto libraries) in **Java** and **Python** source code
and in **Maven/Gradle** and **PyPI** dependency manifests. It writes a **CycloneDX 1.6**
Cryptography Bill of Materials (CBOM) as JSON. Detection is rule-driven: the cryptographic
knowledge lives in YAML rule files, and the scanner provides the language analysis (name
resolution, constant resolution, argument analysis).

The behaviour is specified in [`spec/SPEC.md`](spec/SPEC.md); this README is the user guide.
Licence: Apache-2.0 (see `LICENSE` and `NOTICE`).

## Build

Requirements: JDK 25 (the code targets Java 23, the minimum runtime), Maven 3.9, and gcc on
Linux x86-64 for the native tree-sitter libraries.

```sh
mvn verify            # natives if missing, bundled-rule validation, unit tests, conformance suite, licence headers
ls target/ciphersift-1.0.0-SNAPSHOT-all.jar
```

`native/build-natives.sh` compiles the tree-sitter core and the Java and Python grammars from
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
                [--threads N] [--rules DIR] [--weakness-indicators] [--quiet | --verbose]
ciphersift rules validate [--rules DIR]
ciphersift rules export <dir>
ciphersift --version
ciphersift --help | ciphersift <command> --help
```

Run it with `java -jar target/ciphersift-1.0.0-SNAPSHOT-all.jar …` (the jar manifest enables
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
| `--include-tests` / `--exclude-tests` | Test files are scanned and marked (default), or skipped. Test files: a directory named `test`, `tests`, `testing`, `__tests__`, `testdata`, `test-data`, `testfixtures`, `test-fixtures`, `integrationtest`, `integration-test(s)` or `src/it` (case-insensitive); Java `*Test.java`, `*Tests.java`, `*TestCase.java`, `*IT.java`, `Test*.java` followed by an upper-case letter (`TestUtils.java`); Python `test_*.py`, `*_test.py`, `tests.py`, `conftest.py` (case-sensitive). |
| `--threads N` | Worker threads (default: processors, at most 8). The output does not depend on it. |
| `--rules DIR` | Use the rules under `DIR` instead of the bundled ones (`rules export` gives you a copy to edit). |
| `--weakness-indicators` | Also report *weakness indicators* (see below), e.g. non-cryptographic random generators. Off by default; all other findings are exactly those of a default scan. |
| `--quiet`, `--verbose` | Only errors / also debug messages (one line per skipped file) on standard error. |

Exit codes: `0` success (unreadable or unparsable files are skipped with a warning), `1` internal
error or native libraries not loadable, `2` usage error, `3` bad scan root, `4` invalid rules,
`5` output not writable, `6` no Java 23+ runtime.

Scanned inputs: `*.java`, `*.py` (including `setup.py`, whose literal `install_requires` /
`extras_require` are also read as dependencies), `pom.xml`, `build.gradle(.kts)`,
`*.versions.toml`, `requirements*.txt` and `requirements/*.txt`, `pyproject.toml`,
`Pipfile.lock`, `poetry.lock`, `setup.cfg`. Files without one of these names or extensions are
not scanned, also executable scripts without extension (`#!/usr/bin/env python3`); pass them
through a copy with a `.py` name if they matter. `.git`, `.hg`, `.svn` and symbolic links are never followed; files
over 10 MiB and binary source files are skipped.

The output is byte-identical for identical inputs, regardless of thread count, file-system
order, locale, time zone or the location of the scan root. File names are always decoded as
UTF-8, also with plain `java -jar` under a C/POSIX locale. Only *command-line arguments* depend
on the locale (the JVM decodes them before CipherSift starts): under a non-UTF-8 locale a
non-ASCII scan root, output path or `--exclude` glob cannot be decoded, and CipherSift warns
about it. `bin/ciphersift` and the Docker image run the JVM with `LC_ALL=C.UTF-8` when the
current locale is not UTF-8. Set `SOURCE_DATE_EPOCH` to get a `metadata.timestamp`.

Start-up takes about half a second (bundled rules are validated when the jar is built, so they
are not re-validated at run time). Source files in which no rule's names occur at all are not
parsed; this changes nothing in the output, only the speed.

Optional, JDK 24 or newer: an AOT cache cuts start-up further (about 0.53 s → 0.37 s measured).
It belongs to one JDK build and one jar file; create it once with a normal scan, then pass it on
every run (the directory must exist). Keep the JVM's own log quiet, since a mismatch warning would otherwise go to standard
output:

```sh
CIPHERSIFT_JAVA_OPTS="-XX:AOTCacheOutput=$HOME/.cache/ciphersift/app.aot" bin/ciphersift scan src/ -o /tmp/x.cdx.json
export CIPHERSIFT_JAVA_OPTS="-XX:AOTCache=$HOME/.cache/ciphersift/app.aot -Xlog:aot=off,cds=off"
```

## Output format (for consumers)

A CycloneDX 1.6 JSON document with `bomFormat`, `specVersion`, a content-derived
`serialNumber`, `version`, `metadata` (tool, root component named after the scan root,
properties `ciphersift:rulesDigest`, `ciphersift:testFiles`, `ciphersift:filesScanned`,
`ciphersift:filesSkipped`), `components` and, when libraries were found, `dependencies`.

**Cryptographic components** (`"type": "cryptographic-asset"`):

* one component per *(rule, name, parameter, OID)* for algorithms and per *rule* for protocols,
  certificates and related material;
* `name`: Java — the matched algorithm string (`AES/GCM/NoPadding`, `SHA-256`) or the API
  (`GCMBlockCipher`, `MessageDigest.getInstance`); Python — the resolved call
  (`cryptography.hazmat.primitives.ciphers.Cipher`, `hashlib.new`); protocols — `TLS 1.2`, `SSH`;
  other types — the rule name;
* `cryptoProperties`: `assetType` and `algorithmProperties` (`primitive`, `parameterSetIdentifier`,
  `mode`, `padding`, `classicalSecurityLevel`), `protocolProperties` (`type`, `version`) or
  `relatedCryptoMaterialProperties` (`type`); `oid` when the algorithm was given as an object
  identifier (see below);
* `properties`: `ciphersift:ruleId`, `ciphersift:language`, `ciphersift:assetType` (only for
  `key-material`), `ciphersift:primitive`, `ciphersift:family`, `ciphersift:variant`,
  `ciphersift:subtype`, `ciphersift:indicator`, `ciphersift:testOnly` — each only when it has a
  value;
* `evidence.occurrences`: `location` (path relative to the scan root, `/`-separated), `line`,
  `symbol` (the API, e.g. `javax.crypto.Cipher.getInstance`) and `additionalContext`, a string
  holding compact JSON `{"ruleId":…,"snippet":…,"param":…,"test":true}`.

**Library components** (`"type": "library"`): `bom-ref` = `purl`
(`pkg:maven/<group>/<artifact>[@<version>]`, `pkg:pypi/<name>[@<version>]`), Maven `group`,
`name`, `version` (only if known), properties `ciphersift:ruleId`, `ciphersift:ecosystem`,
`ciphersift:testOnly`; occurrences have `location` and `additionalContext`
(`{"ruleId":…,"snippet":"g:a:v","manifest":"pom"}`), no line.

**Weakness indicators.** Some rules do not detect a cryptographic asset but a sign of a possible
weakness: today the non-cryptographic random generators (`java.util.Random`, `Math.random`,
`ThreadLocalRandom`, Python `random.*`; rules `java.rand.prng.insecure` and
`python.rand.prng.insecure`). They would be reported wherever they occur, also for jitter,
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

**Debatable library entries.** The dependency lists also contain packages that support
cryptography without implementing it, e.g. `certifi` (a CA bundle) and `commons-codec`
(`DigestUtils`, but often used only for Base64). Filter on the package if they are not wanted.

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
language: java                  # java | python
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
pkg.Class.FIELD`, `override: name` (method declarations). **Java conditions**: `firstString`,
`anyString` (regex at the start of the first / any resolved string argument, case-insensitive),
`stringContains`, `argsText` (regex over the argument text), `argsTextContains`, `constantArg: i`
(argument *i* is constant bytes, e.g. a hard-coded key), `inType` and `body` (for `override`),
`param: {index: i}` (report argument *i* as parameter set; not a filter, so it does not make a
pattern specific). String arguments are resolved
through literals, `+`, local and field constants (also in other files of the scan) and a table
of well-known library constants (`rules/java/_constants.yaml`).

**Python anchors**: `call: dotted.name` (matches the resolved call name or any name below it:
`Crypto.Hash.MD5` matches `Crypto.Hash.MD5.new`), `method: name | [names]`, `anyCall: true` (with
`kwargs`), `assign: attr` (attribute assignment `x.attr = value`). **Python conditions**:
`firstString`, `stringContains`, `anySymbol`/`allSymbols` (names referenced in the arguments),
`kwargs: {keyword: regex}`, `dictItems: {key: regex}` (a dictionary argument such as
`{'algorithm': 'sha256'}`), `notInside: [method names]` (the call is not an argument of such a
call), `value`/`valueContains` (for `assign`); `param: {keyword, index}`, `{self: true}` or
`{value: fixed}` and `reportAt: [method names]` (attribute the finding to an enclosing operation call
such as `sign(…)`) are not filters. A `call` pattern without conditions also matches the name used
as a value without a call — in a table, as a class attribute, as an argument
(`digest=hashlib.sha256`) — but not in annotations, `isinstance`/`cast`, comparisons or `except`
clauses; `ref: dotted.name` matches only such uncalled references, also as an operand (enum
members like `pkcs11.Mechanism.SHA256_RSA_PKCS`, classes like `algorithms.AES`). A rule's top-level
`indicator: weakness` marks its findings as weakness indicators.

Selection: in Java, patterns with conditions beat bare patterns of the same asset type, so the
`java.jca.*.unresolved` fallbacks only appear when no specific rule matched; a match nested in
another match of the same family (`new GCMBlockCipher(new AESEngine())`) is reported once. In
Python, a rule with a `variant`/`version` replaces its unrefined sibling on the same call, and
each rule reports at most one finding per line.

Regexes must be valid in both `java.util.regex` and Python `re` (no `(?P<…>)`, `\Z`, possessive
quantifiers, `\p{…}`); `spec/tools/regex_parity.py` checks this. Dependency rules
(`kind: dependency`) list package patterns per ecosystem (`org.bouncycastle:*`, `pycryptodome`).

## Limitations

By design (SPEC Appendix B): attribute reads are not anchors (asn1crypto `cert.sha256`
fingerprints are not reported); Python parameter defaults (`def f(h=hashlib.sha256)`) are not
references; a Java `final` local assigned after its declaration gives the `*.unresolved`
fallback, and OIDs held in library constants (`PKCSObjectIdentifiers.rsaEncryption`) or missing from
the built-in table are not mapped; a member type (`Builder`, `Digest`) counts as the API class only when it is
qualified (`ConnectionSpec.Builder`) or imported; no data flow beyond constants (values from parameters,
configuration, `String.format`, `StringBuilder` or ternaries give an `*.unresolved` component in
Java and nothing in Python); receiver types are not inferred, so `method:` patterns are
heuristics; unimported Java simple names are assumed to be the API class; reassignment is tracked
by simple name per file; Python resolution is flow-insensitive and does not follow attributes,
return values or other modules; one algorithm per Java signature string (`SHA1withRSA` → RSA);
dependency versions come from the manifest only (no parent POMs, BOMs, Gradle plugins; ranges give
no version); Kotlin, Groovy, Scala, Go etc. are not analysed; test detection is path-based, so
library code in directories such as `django/test/` counts as test code. tree-sitter-java 0.23.5
reports a syntax error for some valid literals (a binary literal with a double underscore,
`0b1000__0000`); the rest of the file is still analysed. Native libraries are bundled for
linux-x86_64 only.

## Testing

`mvn verify` runs the unit tests (surefire) and, against the fat jar, the conformance suite in
`spec/conformance/` with CycloneDX 1.6 schema validation of every produced CBOM, determinism
checks and CLI checks (failsafe). The Python reference comparator also works:
`python3 spec/tools/conformance.py --cmd "java -jar target/ciphersift-1.0.0-SNAPSHOT-all.jar"`.
