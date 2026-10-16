from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac, padding as sympadding
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, ed25519, x25519, dsa, dh
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
from cryptography import x509


def sym(key, iv, nonce):
    c1 = Cipher(algorithms.AES(key), modes.GCM(iv))        # AES-GCM
    c2 = Cipher(algorithms.AES(key), modes.CBC(iv))        # AES-CBC
    c3 = Cipher(algorithms.AES(key), modes.ECB())          # AES-ECB
    algo = algorithms.AES(key)
    mode = modes.CTR(nonce)
    c4 = Cipher(algo, mode)                                # AES-CTR via local variables
    c5 = Cipher(algorithms.TripleDES(key), modes.CBC(iv))  # 3DES
    c6 = Cipher(algorithms.ChaCha20(key, nonce), mode=None)  # ChaCha20
    a = AESGCM(AESGCM.generate_key(bit_length=256))        # AES-GCM (x2 calls, one asset per line)
    b = ChaCha20Poly1305(key)                              # ChaCha20-Poly1305
    f = Fernet(Fernet.generate_key())                      # Fernet
    return c1, c2, c3, c4, c5, c6, a, b, f


def asym(msg):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)   # RSA 2048
    ct = priv.public_key().encrypt(                                         # OAEP + SHA2 (reported here)
        msg,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),           # OAEP + SHA2
                     algorithm=hashes.SHA256(), label=None))                 # SHA2
    sig = priv.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),     # PSS + SHA2
                                     salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    legacy = priv.sign(msg, padding.PKCS1v15(), hashes.SHA1())               # PKCS1v15 sig + SHA1
    bad = priv.public_key().encrypt(msg, padding.PKCS1v15())                 # PKCS1v15 encrypt
    eck = ec.generate_private_key(ec.SECP256R1())                            # EC P-256
    esig = eck.sign(msg, ec.ECDSA(hashes.SHA384()))                          # ECDSA + SHA2
    edk = ed25519.Ed25519PrivateKey.generate()                               # Ed25519
    xk = x25519.X25519PrivateKey.generate()                                  # X25519
    dk = dsa.generate_private_key(key_size=1024)                             # DSA 1024
    params = dh.generate_parameters(generator=2, key_size=2048)              # DH 2048
    return ct, sig, legacy, bad, esig, edk, xk, dk, params


def macs_kdfs(key, salt, data):
    hm = hmac.HMAC(key, hashes.SHA256())                                     # HMAC + SHA2
    kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=32, salt=salt, iterations=1000)  # PBKDF2 + SHA1
    hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"x")   # HKDF + SHA2
    dg = hashes.Hash(hashes.MD5())                                           # MD5
    cert = x509.load_pem_x509_certificate(data)                              # x509
    return hm, kdf, hk, dg, cert
