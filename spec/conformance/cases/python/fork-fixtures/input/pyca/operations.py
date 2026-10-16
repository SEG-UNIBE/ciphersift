"""Merged-tool fixture: operation-call attribution (issue 1) and bare curve objects (issue 2)."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from Crypto.PublicKey import ECC


def oaep(rsa_key):
    return rsa_key.public_key().encrypt(                                     # 8: RSA-OAEP + SHA2
        b"data",
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def oaep_decrypt(rsa_key, ct):
    return rsa_key.decrypt(ct, padding.OAEP(mgf=padding.MGF1(hashes.SHA1()),  # 19: OAEP + SHA1
                                            algorithm=hashes.SHA1(), label=None))


def pss(rsa_key, msg):
    sig = rsa_key.sign(                                                      # 24: PSS + SHA2
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    rsa_key.public_key().verify(                                             # 30: PKCS1v15 sig + SHA2
        sig,
        msg,
        padding.PKCS1v15(),
        hashes.SHA512(),
    )
    return sig


def ecdsa(key, msg):
    return key.sign(                                                         # 40: ECDSA + SHA2
        msg,
        ec.ECDSA(hashes.SHA384()),
    )


def standalone_padding():
    pad = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)  # 47
    return pad


class Key:
    @classmethod
    def generate(cls, curve=ec.SECP256R1(), backend=None):                   # 53: EC P-256 (default arg)
        return ec.generate_private_key(curve, backend)                       # 54: EC keygen


def curves():
    curve = ec.SECP384R1()                                                   # 58: EC P-384
    k = ec.generate_private_key(ec.SECP521R1())                              # 59: one EC finding
    k2 = ec.generate_private_key(
        ec.BrainpoolP256R1(),                                                # folded into line 60
    )
    pk = ECC.EccKey(curve="P-256", d=1)                                      # 63: PyCryptodome EC
    return curve, k, k2, pk
