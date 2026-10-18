import hashlib
from hashlib import sha1


# parameter defaults are value positions, resolved where the function is defined (DECISIONS P3-DEF)
def digest(data, hash_func=sha1):  # want: python.hash.sha1 hashlib.sha1
    return hash_func(data).hexdigest()


def jws(payload, alg="RS256"):  # want: python.asym.rsa RS256 | python.hash.sha2 RS256
    return alg


def shadow(hashlib=None, h=hashlib.sha256):  # want: python.hash.sha2 hashlib.sha256
    return h


lam = lambda h=hashlib.md5: h  # want: python.hash.md5 hashlib.md5


def plain(x, y=3, z="name", hashfunc=None):  # nothing
    return x
