from hashlib import sha1, sha256
import hashlib
import hmac
from typing import Union, cast
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import algorithms
MACS = ((b'hmac-sha1', sha1), (b'hmac-sha2-256', sha256))     # 9: SHA1 and SHA2 (tuple elements)
class Alg:
    SHA256 = hashes.SHA256                                    # 11: SHA2 (class attribute)
KEYS = {"Ed25519": Ed25519PrivateKey}                         # 12: Ed25519 (dict value)
CURVES = {"P-256": ec.SECP256R1}                              # 13: EC, param SECP256R1 (self)
NAMES = {hashes.SHA384: "sha384"}                             # 14: SHA2 (dict key)
def hkdf(key, msg, digest): pass
t = hkdf(b"k", b"m", digest=sha256)                           # 16: SHA2 (keyword value)
u = hkdf(b"k", b"m", hashlib.sha512)                          # 17: SHA2 (positional argument)
H = hashlib.sha1                                              # 18: SHA1 (alias definition)
mac = hmac.new(b"k", b"m",
               hashlib.sha256)                                # 19: SHA2 and HMAC once, at hmac.new (nested reference folded)
CIPHERS = [(b"aes128-ctr", algorithms.AES)]                   # 21: AES (ref pattern)
pick = sha1 if t else sha256                                  # 22: SHA1 and SHA2 (conditional expression)
def check(key: Ed25519PrivateKey) -> Ed25519PrivateKey:       # 23: nothing (annotations)
    if isinstance(key, Ed25519PrivateKey):                    # 24: nothing (type test)
        return cast(Ed25519PrivateKey, key)                   # 25: nothing (cast)
    if type(key) in (ec.SECP256R1, ec.SECP384R1):             # 26: nothing (membership test)
        return None
    try:
        return key
    except (ValueError, TypeError):                           # 30: nothing
        return None
KeyT = Union[Ed25519PrivateKey, ec.SECP256R1]                 # 32: nothing (subscript / typing)
class MyKey(Ed25519PrivateKey):                               # 33: nothing (base class)
    pass
def default(h=hashlib.sha256): return h                       # 35: nothing (default values are not value positions)
for alg in (hashes.SHA512, hashes.MD5):                       # 36: SHA2 and MD5 (tuple iterated)
    pass
x = hashlib.sha256.__name__                                   # 38: nothing (attribute of the function, not the function)
y = hashes                                                    # 39: nothing (a module)
z = [hashes.SHA256(), hashes.SHA256]                          # 40: SHA2 once per line
v = hashlib.sha256 or hashlib.md5                             # 41: nothing (operands: call patterns need a value position)
w = algorithms.TripleDES or algorithms.AES                    # 42: 3DES and AES (ref patterns: any expression position)
if algorithms.Blowfish == w:                                  # 43: nothing (comparison)
    pass
