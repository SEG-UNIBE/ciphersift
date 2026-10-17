"""OIDs given to pyca, asn1crypto and pyasn1 (SPEC 5.11)."""
# Each call carries its line number and the expected result in a trailing comment.
from asn1crypto import algos, core
from cryptography.x509.oid import ObjectIdentifier
from pyasn1.type import univ

SHA256 = "2.16.840.1.101.3.4.2.1"
CN = "2.5.4.3"

ObjectIdentifier("1.2.840.10045.4.3.2")                          # 10: EC (ECDSA)
ObjectIdentifier(SHA256)                                         # 11: SHA2 through a constant
core.ObjectIdentifier("1.3.101.112")                             # 12: Ed25519
univ.ObjectIdentifier("1.2.840.113549.1.1.10")                   # 13: RSA-PSS
algos.DigestAlgorithmId("2.16.840.1.101.3.4.2.3")                # 14: SHA2 (asn1crypto id class)
algos.DigestAlgorithm({"algorithm": "1.3.14.3.2.26"})            # 15: SHA1 (asn1crypto dict)
algos.SignedDigestAlgorithm({"algorithm": "1.2.840.113549.1.1.11"})  # 16: RSA PKCS1v15 signature
algos.KeyEncryptionAlgorithm({"algorithm": "1.2.840.113549.1.1.1"})  # 17: RSA PKCS1v15 encryption
algos.EncryptionAlgorithm({"algorithm": "2.16.840.1.101.3.4.1.2"})   # 18: AES-CBC
algos.DigestAlgorithm({"algorithm": "sha256"})                   # 19: SHA2 by name: no OID
ObjectIdentifier(CN)                                             # 20: commonName: nothing
ObjectIdentifier("1.2.840.113549.1.1.99")                        # 21: unknown: nothing
ObjectIdentifier("OID.1.3.132.0.10")                             # 22: EC, parameter secp256k1
