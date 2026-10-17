"""Every OID of the table through pyca/cryptography (SPEC 5.11)."""
from cryptography import x509

x509.ObjectIdentifier("1.2.840.113549.1.1.1")  # 4: rsaEncryption -> RSA
x509.ObjectIdentifier("1.2.840.113549.1.1.7")  # 5: id-RSAES-OAEP -> OAEP
x509.ObjectIdentifier("1.2.840.113549.1.1.10")  # 6: id-RSASSA-PSS -> RSASSA-PSS
x509.ObjectIdentifier("1.2.840.113549.1.1.2")  # 7: md2WithRSAEncryption -> MD2withRSA
x509.ObjectIdentifier("1.2.840.113549.1.1.4")  # 8: md5WithRSAEncryption -> MD5withRSA
x509.ObjectIdentifier("1.2.840.113549.1.1.5")  # 9: sha1WithRSAEncryption -> SHA1withRSA
x509.ObjectIdentifier("1.2.840.113549.1.1.14")  # 10: sha224WithRSAEncryption -> SHA224withRSA
x509.ObjectIdentifier("1.2.840.113549.1.1.11")  # 11: sha256WithRSAEncryption -> SHA256withRSA
x509.ObjectIdentifier("1.2.840.113549.1.1.12")  # 12: sha384WithRSAEncryption -> SHA384withRSA
x509.ObjectIdentifier("1.2.840.113549.1.1.13")  # 13: sha512WithRSAEncryption -> SHA512withRSA
x509.ObjectIdentifier("1.2.840.113549.1.1.15")  # 14: sha512-224WithRSAEncryption -> SHA512/224withRSA
x509.ObjectIdentifier("1.2.840.113549.1.1.16")  # 15: sha512-256WithRSAEncryption -> SHA512/256withRSA
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.13")  # 16: id-rsassa-pkcs1-v1_5-with-sha3-224 -> SHA3-224withRSA
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.14")  # 17: id-rsassa-pkcs1-v1_5-with-sha3-256 -> SHA3-256withRSA
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.15")  # 18: id-rsassa-pkcs1-v1_5-with-sha3-384 -> SHA3-384withRSA
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.16")  # 19: id-rsassa-pkcs1-v1_5-with-sha3-512 -> SHA3-512withRSA
x509.ObjectIdentifier("1.2.840.10040.4.1")  # 20: id-dsa -> DSA
x509.ObjectIdentifier("1.2.840.10040.4.3")  # 21: id-dsa-with-sha1 -> SHA1withDSA
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.1")  # 22: id-dsa-with-sha224 -> SHA224withDSA
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.2")  # 23: id-dsa-with-sha256 -> SHA256withDSA
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.3")  # 24: id-dsa-with-sha384 -> SHA384withDSA
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.4")  # 25: id-dsa-with-sha512 -> SHA512withDSA
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.5")  # 26: id-dsa-with-sha3-224 -> SHA3-224withDSA
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.6")  # 27: id-dsa-with-sha3-256 -> SHA3-256withDSA
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.7")  # 28: id-dsa-with-sha3-384 -> SHA3-384withDSA
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.8")  # 29: id-dsa-with-sha3-512 -> SHA3-512withDSA
x509.ObjectIdentifier("1.2.840.10045.2.1")  # 30: id-ecPublicKey -> EC
x509.ObjectIdentifier("1.3.132.1.12")  # 31: id-ecDH -> ECDH
x509.ObjectIdentifier("1.2.840.10045.4.1")  # 32: ecdsa-with-SHA1 -> SHA1withECDSA
x509.ObjectIdentifier("1.2.840.10045.4.3.1")  # 33: ecdsa-with-SHA224 -> SHA224withECDSA
x509.ObjectIdentifier("1.2.840.10045.4.3.2")  # 34: ecdsa-with-SHA256 -> SHA256withECDSA
x509.ObjectIdentifier("1.2.840.10045.4.3.3")  # 35: ecdsa-with-SHA384 -> SHA384withECDSA
x509.ObjectIdentifier("1.2.840.10045.4.3.4")  # 36: ecdsa-with-SHA512 -> SHA512withECDSA
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.9")  # 37: id-ecdsa-with-sha3-224 -> SHA3-224withECDSA
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.10")  # 38: id-ecdsa-with-sha3-256 -> SHA3-256withECDSA
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.11")  # 39: id-ecdsa-with-sha3-384 -> SHA3-384withECDSA
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.12")  # 40: id-ecdsa-with-sha3-512 -> SHA3-512withECDSA
x509.ObjectIdentifier("1.2.840.10045.3.1.1")  # 41: prime192v1 -> secp192r1
x509.ObjectIdentifier("1.3.132.0.33")  # 42: secp224r1 -> secp224r1
x509.ObjectIdentifier("1.2.840.10045.3.1.7")  # 43: prime256v1 -> secp256r1
x509.ObjectIdentifier("1.3.132.0.34")  # 44: secp384r1 -> secp384r1
x509.ObjectIdentifier("1.3.132.0.35")  # 45: secp521r1 -> secp521r1
x509.ObjectIdentifier("1.3.132.0.10")  # 46: secp256k1 -> secp256k1
x509.ObjectIdentifier("1.3.36.3.3.2.8.1.1.1")  # 47: brainpoolP160r1 -> brainpoolP160r1
x509.ObjectIdentifier("1.3.36.3.3.2.8.1.1.3")  # 48: brainpoolP192r1 -> brainpoolP192r1
x509.ObjectIdentifier("1.3.36.3.3.2.8.1.1.5")  # 49: brainpoolP224r1 -> brainpoolP224r1
x509.ObjectIdentifier("1.3.36.3.3.2.8.1.1.7")  # 50: brainpoolP256r1 -> brainpoolP256r1
x509.ObjectIdentifier("1.3.36.3.3.2.8.1.1.9")  # 51: brainpoolP320r1 -> brainpoolP320r1
x509.ObjectIdentifier("1.3.36.3.3.2.8.1.1.11")  # 52: brainpoolP384r1 -> brainpoolP384r1
x509.ObjectIdentifier("1.3.36.3.3.2.8.1.1.13")  # 53: brainpoolP512r1 -> brainpoolP512r1
x509.ObjectIdentifier("1.3.101.110")  # 54: id-X25519 -> X25519
x509.ObjectIdentifier("1.3.101.111")  # 55: id-X448 -> X448
x509.ObjectIdentifier("1.3.101.112")  # 56: id-Ed25519 -> Ed25519
x509.ObjectIdentifier("1.3.101.113")  # 57: id-Ed448 -> Ed448
x509.ObjectIdentifier("1.2.840.113549.1.3.1")  # 58: dhKeyAgreement -> DH
x509.ObjectIdentifier("1.2.840.10046.2.1")  # 59: dhpublicnumber -> DH
x509.ObjectIdentifier("1.2.840.113549.2.2")  # 60: md2 -> MD2
x509.ObjectIdentifier("1.2.840.113549.2.5")  # 61: md5 -> MD5
x509.ObjectIdentifier("1.3.14.3.2.26")  # 62: id-sha1 -> SHA-1
x509.ObjectIdentifier("2.16.840.1.101.3.4.2.4")  # 63: id-sha224 -> SHA-224
x509.ObjectIdentifier("2.16.840.1.101.3.4.2.1")  # 64: id-sha256 -> SHA-256
x509.ObjectIdentifier("2.16.840.1.101.3.4.2.2")  # 65: id-sha384 -> SHA-384
x509.ObjectIdentifier("2.16.840.1.101.3.4.2.3")  # 66: id-sha512 -> SHA-512
x509.ObjectIdentifier("2.16.840.1.101.3.4.2.5")  # 67: id-sha512-224 -> SHA-512/224
x509.ObjectIdentifier("2.16.840.1.101.3.4.2.6")  # 68: id-sha512-256 -> SHA-512/256
x509.ObjectIdentifier("2.16.840.1.101.3.4.2.7")  # 69: id-sha3-224 -> SHA3-224
x509.ObjectIdentifier("2.16.840.1.101.3.4.2.8")  # 70: id-sha3-256 -> SHA3-256
x509.ObjectIdentifier("2.16.840.1.101.3.4.2.9")  # 71: id-sha3-384 -> SHA3-384
x509.ObjectIdentifier("2.16.840.1.101.3.4.2.10")  # 72: id-sha3-512 -> SHA3-512
x509.ObjectIdentifier("1.2.840.113549.2.7")  # 73: id-hmacWithSHA1 -> HmacSHA1
x509.ObjectIdentifier("1.2.840.113549.2.8")  # 74: id-hmacWithSHA224 -> HmacSHA224
x509.ObjectIdentifier("1.2.840.113549.2.9")  # 75: id-hmacWithSHA256 -> HmacSHA256
x509.ObjectIdentifier("1.2.840.113549.2.10")  # 76: id-hmacWithSHA384 -> HmacSHA384
x509.ObjectIdentifier("1.2.840.113549.2.11")  # 77: id-hmacWithSHA512 -> HmacSHA512
x509.ObjectIdentifier("1.2.840.113549.2.12")  # 78: id-hmacWithSHA512-224 -> HmacSHA512/224
x509.ObjectIdentifier("1.2.840.113549.2.13")  # 79: id-hmacWithSHA512-256 -> HmacSHA512/256
x509.ObjectIdentifier("2.16.840.1.101.3.4.2.13")  # 80: id-hmacWithSHA3-224 -> HmacSHA3-224
x509.ObjectIdentifier("2.16.840.1.101.3.4.2.14")  # 81: id-hmacWithSHA3-256 -> HmacSHA3-256
x509.ObjectIdentifier("2.16.840.1.101.3.4.2.15")  # 82: id-hmacWithSHA3-384 -> HmacSHA3-384
x509.ObjectIdentifier("2.16.840.1.101.3.4.2.16")  # 83: id-hmacWithSHA3-512 -> HmacSHA3-512
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.1")  # 84: aes128-ECB -> AES_128/ECB/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.2")  # 85: aes128-CBC -> AES_128/CBC/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.3")  # 86: aes128-OFB -> AES_128/OFB/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.4")  # 87: aes128-CFB -> AES_128/CFB/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.5")  # 88: id-aes128-wrap -> AES_128/KW/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.6")  # 89: id-aes128-GCM -> AES_128/GCM/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.7")  # 90: id-aes128-CCM -> AES_128/CCM/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.8")  # 91: id-aes128-wrap-pad -> AES_128/KWP/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.21")  # 92: aes192-ECB -> AES_192/ECB/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.22")  # 93: aes192-CBC -> AES_192/CBC/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.23")  # 94: aes192-OFB -> AES_192/OFB/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.24")  # 95: aes192-CFB -> AES_192/CFB/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.25")  # 96: id-aes192-wrap -> AES_192/KW/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.26")  # 97: id-aes192-GCM -> AES_192/GCM/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.27")  # 98: id-aes192-CCM -> AES_192/CCM/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.28")  # 99: id-aes192-wrap-pad -> AES_192/KWP/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.41")  # 100: aes256-ECB -> AES_256/ECB/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.42")  # 101: aes256-CBC -> AES_256/CBC/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.43")  # 102: aes256-OFB -> AES_256/OFB/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.44")  # 103: aes256-CFB -> AES_256/CFB/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.45")  # 104: id-aes256-wrap -> AES_256/KW/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.46")  # 105: id-aes256-GCM -> AES_256/GCM/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.47")  # 106: id-aes256-CCM -> AES_256/CCM/NoPadding
x509.ObjectIdentifier("2.16.840.1.101.3.4.1.48")  # 107: id-aes256-wrap-pad -> AES_256/KWP/NoPadding
x509.ObjectIdentifier("1.2.840.113549.3.7")  # 108: des-ede3-cbc -> DESede/CBC/NoPadding
x509.ObjectIdentifier("1.3.14.3.2.7")  # 109: desCBC -> DES/CBC/NoPadding
x509.ObjectIdentifier("1.2.840.113549.3.2")  # 110: rc2CBC -> RC2/CBC/NoPadding
x509.ObjectIdentifier("1.2.840.113549.1.5.12")  # 111: id-PBKDF2 -> PBKDF2
x509.ObjectIdentifier("1.2.840.113549.1.5.13")  # 112: id-PBES2: no Python rule, nothing
x509.ObjectIdentifier("1.3.6.1.4.1.11591.4.11")  # 113: id-scrypt -> SCRYPT
x509.ObjectIdentifier("2.16.840.1.101.3.4.4.1")  # 114: id-alg-ml-kem-512: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.4.2")  # 115: id-alg-ml-kem-768: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.4.3")  # 116: id-alg-ml-kem-1024: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.17")  # 117: id-ml-dsa-44: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.18")  # 118: id-ml-dsa-65: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.19")  # 119: id-ml-dsa-87: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.20")  # 120: id-slh-dsa-sha2-128s: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.21")  # 121: id-slh-dsa-sha2-128f: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.22")  # 122: id-slh-dsa-sha2-192s: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.23")  # 123: id-slh-dsa-sha2-192f: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.24")  # 124: id-slh-dsa-sha2-256s: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.25")  # 125: id-slh-dsa-sha2-256f: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.26")  # 126: id-slh-dsa-shake-128s: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.27")  # 127: id-slh-dsa-shake-128f: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.28")  # 128: id-slh-dsa-shake-192s: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.29")  # 129: id-slh-dsa-shake-192f: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.30")  # 130: id-slh-dsa-shake-256s: no Python rule, nothing
x509.ObjectIdentifier("2.16.840.1.101.3.4.3.31")  # 131: id-slh-dsa-shake-256f: no Python rule, nothing
