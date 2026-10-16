import ssl
import requests
import httpx
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from Crypto.PublicKey import RSA
from passlib.context import CryptContext

KEY_BITS = 3072


def run(url):
    requests.get(url, verify=False)                                   # 12: keyword condition -> validation disabled
    requests.get(url, verify=True)                                    # 13: nothing
    httpx.Client(verify=False)                                        # 14: validation disabled
    some_helper(url, verify=False)                                    # 15: any call with verify=False -> validation disabled
    rsa.generate_private_key(public_exponent=65537, key_size=4096)    # 16: RSA, param 4096 (keyword)
    rsa.generate_private_key(65537, 1024)                             # 17: RSA, param 1024 (positional)
    rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)  # 18: RSA, param 3072 (constant)
    RSA.generate(2048)                                                # 19: RSA, param 2048
    ec.generate_private_key(ec.SECP384R1())                           # 20: EC, param SECP384R1 (symbol)
    curve = ec.SECT571K1()                                            # 21: EC, param SECT571K1 (self)
    dsa.generate_private_key(key_size=2048)                           # 22: DSA, param 2048
    CryptContext(schemes=["sha256_crypt", "des_crypt"])               # 23: list of strings inside a keyword -> SHA2 (sha256_crypt; des_crypt has no rule)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)                     # 24: TLS context
    ctx.check_hostname = False                                        # 25: hostname verification disabled
    ctx.verify_mode = ssl.CERT_NONE                                   # 26: validation disabled
    ctx.minimum_version = ssl.TLSVersion.TLSv1_1                      # 27: TLS 1.1
    return curve
