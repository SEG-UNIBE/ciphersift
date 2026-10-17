from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
import jwt.algorithms as ja
from pkcs11 import Mechanism, KeyType
from signxml import XMLSigner, SignatureMethod, DigestAlgorithm
ALGS = [("RSA1_5", padding.PKCS1v15())]                               # 8: RSA PKCS1v15 (padding object outside an operation)
kdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=32, otherinfo=b"")  # 9: ConcatKDF and SHA2
x963 = X963KDF(algorithm=hashes.SHA384(), length=32, sharedinfo=None)  # 10: X9.63 KDF and SHA2
alg = ja.RSAAlgorithm(ja.RSAAlgorithm.SHA256)                         # 11: RSA PKCS1v15 signature and SHA2
pss = ja.RSAPSSAlgorithm(ja.RSAPSSAlgorithm.SHA512)                   # 12: RSA-PSS and SHA2
mech = Mechanism.SHA256_RSA_PKCS                                      # 13: RSA PKCS1v15 signature and SHA2
kt = (KeyType.EC, Mechanism.ECDSA_SHA384)                             # 14: EC, ECDSA and SHA2
signer = XMLSigner(signature_algorithm=SignatureMethod.ECDSA_SHA256,
                   digest_algorithm=DigestAlgorithm.SHA256)           # 15: ECDSA and SHA2 (reported at the references' lines: 15 and 16)
old = XMLSigner(signature_algorithm="rsa-sha256")                     # 17: RSA PKCS1v15 signature (signxml < 3 strings)
def sign(key, data):
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())        # 19: RSA PKCS1v15 signature and SHA2 (not the generic padding rule)
