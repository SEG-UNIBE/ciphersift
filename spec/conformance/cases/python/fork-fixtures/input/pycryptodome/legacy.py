from Crypto.Cipher import AES, DES, DES3, ARC4, PKCS1_OAEP, PKCS1_v1_5
from Crypto.Hash import SHA256, MD5, HMAC
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pss, pkcs1_15, DSS
from Crypto.Protocol.KDF import PBKDF2, scrypt
from Crypto.Random import get_random_bytes
import Crypto.Cipher.AES as AESMOD

MODE = AES.MODE_CBC


def go(key, data, iv):
    a = AES.new(key, AES.MODE_GCM)              # AES-GCM
    b = AES.new(key, AES.MODE_ECB)              # AES-ECB
    c = AES.new(key, mode=AES.MODE_CTR)         # AES-CTR (keyword)
    d = AES.new(key, MODE, iv)                  # AES-CBC via module constant
    e = AESMOD.new(key, AESMOD.MODE_EAX)        # AES-EAX (module alias)
    f = DES.new(key, DES.MODE_ECB)              # DES
    g = DES3.new(key, DES3.MODE_CBC, iv)        # 3DES
    r = ARC4.new(key)                           # RC4
    h1 = SHA256.new(data)                       # SHA2
    h2 = MD5.new(data)                          # MD5
    mac = HMAC.new(key, digestmod=SHA256)       # HMAC
    k = RSA.generate(1024)                      # RSA 1024
    oa = PKCS1_OAEP.new(k)                      # OAEP
    p15 = PKCS1_v1_5.new(k)                     # PKCS1v15 encrypt
    s1 = pss.new(k)                             # PSS
    s2 = pkcs1_15.new(k)                        # PKCS1v15 sig
    ek = ECC.generate(curve="P-256")            # EC P-256
    ds = DSS.new(ek, "fips-186-3")              # ECDSA
    kd = PBKDF2("pw", b"salt", 32, count=1000)  # PBKDF2
    sc = scrypt("pw", b"salt", 32, N=2**14, r=8, p=1)  # scrypt
    rnd = get_random_bytes(16)                  # secure PRNG
    return a, b, c, d, e, f, g, r, h1, h2, mac, k, oa, p15, s1, s2, ek, ds, kd, sc, rnd
