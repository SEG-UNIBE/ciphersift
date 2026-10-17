import electrum_ecc as ecc
import coincurve
import pyaes
k = ecc.ECPrivkey(b"\x01" * 32)                                 # 4: EC secp256k1
sig = k.ecdsa_sign(b"\x00" * 32)                                # 5: ECDSA (method name)
pub = ecc.ECPubkey(b"\x02" + b"\x01" * 32)                      # 6: EC secp256k1
Q = ecc.GENERATOR * 5                                           # 7: EC secp256k1 (ref patterns: any expression position)
P = [ecc.GENERATOR]                                             # 8: EC secp256k1 (reference)
c = coincurve.PrivateKey()                                      # 9: EC secp256k1
aes = pyaes.AESModeOfOperationCBC(b"k" * 16, iv=b"i" * 16)      # 10: AES-CBC
ctr = pyaes.AESModeOfOperationCTR(b"k" * 16)                    # 11: AES-CTR
blk = pyaes.AES(b"k" * 16)                                      # 12: AES
ok = pub.ecdsa_verify(sig, b"\x00" * 32)                        # 13: ECDSA (method name)
