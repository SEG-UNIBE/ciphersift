import hashlib
import hashlib as h
import hmac
from hashlib import sha256, md5 as weak_md5

DIGEST = "sha512"
LEGACY = "md5"


def digests(data, key):
    a = hashlib.md5(data)                     # MD5
    b = h.sha1(data)                          # SHA1
    c = sha256(data)                          # SHA2
    d = weak_md5(data)                        # MD5
    e = hashlib.new("md5", data)              # MD5
    f = hashlib.new("sha256")                 # SHA2
    g = hashlib.new(DIGEST)                   # SHA2 via module constant
    i = hashlib.sha3_256(data)                # SHA3
    j = hashlib.blake2b(data)                 # BLAKE2
    k = hmac.new(key, data, "sha512")         # HMAC + SHA2
    m = hmac.new(key, data, hashlib.md5)      # HMAC + MD5
    n = hmac.digest(key, data, digestmod=LEGACY)  # HMAC + MD5
    return a, b, c, d, e, f, g, i, j, k, m, n


def kdfs(pw, salt):
    x = hashlib.pbkdf2_hmac("sha256", pw, salt, 100000)   # PBKDF2 + SHA2
    y = hashlib.scrypt(pw, salt=salt, n=2**14, r=8, p=1)  # scrypt
    local = "sha1"
    z = hashlib.new(local)                                # SHA1 (function-local constant)
    return x, y, z
