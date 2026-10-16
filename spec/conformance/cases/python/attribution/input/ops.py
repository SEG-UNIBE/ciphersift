import bcrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding


def run(key, priv, msg, pw):
    key.public_key().encrypt(msg, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))  # 7: OAEP + SHA2 once
    priv.sign(
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA384()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA384(),
    )                                                         # PSS + SHA2, reported at line 8 (the sign call)
    pad = padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)  # 16: OAEP + SHA1 at their own line
    key.decrypt(msg, pad)                                     # 17: nothing (padding in a variable)
    priv.sign(msg, ec.ECDSA(hashes.SHA256()))                 # 18: ECDSA + SHA2
    digest = hashes.Hash(
        hashes.SHA512())                                      # 20: SHA2 (hashes.Hash is not an anchor; SHA512() is)
    bcrypt.hashpw(pw,
                  bcrypt.gensalt(rounds=14))                  # bcrypt once, reported at line 21
    hashes.Hash(hashes.MD5()); hashes.Hash(hashes.MD5())      # 23: MD5 once per line
    return digest
