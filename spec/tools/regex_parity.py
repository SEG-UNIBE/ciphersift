#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The CipherSift Authors
"""Check that every rule regex behaves the same in Python re and java.util.regex.

Writes <tmp>/regex-cases.tsv (mode, flags, regex, probe, python-result) and runs
RegexParity.java with the JDK given by $JAVA (default: java) to compare.
Usage: JAVA=/usr/lib/jvm/jdk-25.0.1/bin/java python3 regex_parity.py [rules dir]
Needs PyYAML.
"""
import base64
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parents[1] / "rules"

# probe strings: algorithm names, protocol names, assigned values, keyword values, bodies
PROBES = """AES AES/ECB/PKCS5Padding AES_256/GCM/NoPadding aes/gcm/nopadding AES/CBC/PKCS5Padding AES/CTR/NoPadding
AES/CFB8/NoPadding AES/OFB/NoPadding AES/CCM/NoPadding AESWrap AES/KW/NoPadding AES/KWP/NoPadding AES/CTS/NoPadding
AES/GCM-SIV/NoPadding Rijndael DES DES/CBC/PKCS5Padding DESede DESede/ECB/PKCS5Padding DESede/CBC/NoPadding
TripleDES/CBC/PKCS5Padding DESedeWrap RC4 ARCFOUR ChaCha20-Poly1305 ChaCha20 Blowfish RC2 IDEA Camellia Twofish
Serpent CAST5 SM4 Salsa20 XSalsa20 RSA RSA/ECB/PKCS1Padding RSA/ECB/OAEPWithSHA-256AndMGF1Padding RSA/NONE/NoPadding
PBEWithMD5AndDES PBEWithHmacSHA256AndAES_256 MD5 MD2 MD4 SHA SHA-1 SHA1 SHA-224 SHA-256 SHA256 SHA-512/256 SHA3-256
BLAKE2B-256 RIPEMD160 SM3 Whirlpool SHA256withRSA SHA256withRSA/PSS RSASSA-PSS SHA256withECDSA SHA256withPLAIN-ECDSA
SHA256withDSA Ed25519 EdDSA Ed448 ML-DSA-65 ML-KEM ML-KEM-768 SLH-DSA-SHA2-128s EC DSA DH DiffieHellman X25519 X448 XDH
ECDH ECMQV HmacSHA256 HmacMD5 HmacSHA1 HmacSHA3-256 AESCMAC AES-GMAC Poly1305 SipHash PBKDF2WithHmacSHA1 TLS TLSv1
TLSv1.1 TLSv1.2 TLSv1.3 SSLv3 SSLv2Hello SSL Default PKCS12 JKS SHA1PRNG DRBG NativePRNG X.509 TLS_RSA_WITH_RC4_128_SHA
TLS_RSA_WITH_NULL_SHA TLS_RSA_EXPORT_WITH_RC4_40_MD5 TLS_DH_anon_WITH_AES_128_CBC_SHA TLSv1,TLSv1.2 TLSv1.2,TLSv1.3
md5 sha1 sha256 sha512 sha3_256 blake2b sha224 SHA512 sm3 ripemd160 md4 HS256 RS256 ES256 PS256 EdDSA none None
False 0 True CERT_NONE ssl.CERT_NONE ssl.TLSVersion.TLSv1 ssl.TLSVersion.TLSv1_1 ssl.TLSVersion.TLSv1_2
ssl.TLSVersion.TLSv1_3 ssl.TLSVersion.SSLv3 ssl.PROTOCOL_TLSv1 ssl.PROTOCOL_TLSv1_1 ssl.PROTOCOL_TLSv1_2
ssl.PROTOCOL_SSLv3 ssl.PROTOCOL_SSLv23 PROTOCOL_TLS_CLIENT bcrypt md5_crypt sha256_crypt des_crypt argon2 pbkdf2_sha256
AES256_GCM AES128_GCM_RAW AES256_SIV CHACHA20_POLY1305 XCHACHA20_POLY1305 ECDSA_P256 ED25519 RSA_SSA_PKCS1_3072_SHA256_F4
HMAC_SHA256_128BITTAG""".split()
PROBES += ["{ }", "{}", "{ return; }", "{ return true; }", "{ return \"x\".equals(h); }",
           "((h, s) -> true)", "(ALLOW_ALL_HOSTNAME_VERIFIER)", "(x -> { return true; })", "(\"GCM\")", "(a, b)",
           "Algorithm.HMAC256(\"secret\")", "sha-256", "SHA-512/224", "Sha256", "İ", "ſ"]

RX_KEYS = {"firstString": "M", "anyString": "M", "argsText": "S", "body": "S", "value": "SI"}
cases = []
for f in sorted(ROOT.rglob("*.yaml")):
    doc = yaml.safe_load(f.read_text(encoding="utf-8"))
    for p in doc.get("match") or []:
        items = [(k, p[k]) for k in RX_KEYS if k in p] + [("kw", v) for v in (p.get("kwargs") or {}).values()]
        for k, rx in items:
            mode = {"firstString": "match-i", "anyString": "match-i", "argsText": "find",
                    "body": "find", "value": "find-i", "kw": "find-i"}[k]
            flags = re.IGNORECASE if mode.endswith("-i") else 0
            cre = re.compile(rx, flags)
            for s in PROBES:
                r = (cre.match(s) if mode.startswith("match") else cre.search(s)) is not None
                cases.append((mode, rx, s, r))

tmp = Path(tempfile.mkdtemp())
tsv = tmp / "regex-cases.tsv"
with tsv.open("w", encoding="utf-8") as out:
    for mode, rx, s, r in cases:
        b = lambda x: base64.b64encode(x.encode("utf-8")).decode()
        out.write(f"{mode}\t{b(rx)}\t{b(s)}\t{int(r)}\n")
java = os.environ.get("JAVA", "java")
res = subprocess.run([java, str(HERE / "RegexParity.java"), str(tsv)], capture_output=True, text=True)
print(res.stdout, end="")
print(res.stderr, end="", file=sys.stderr)
sys.exit(res.returncode)
