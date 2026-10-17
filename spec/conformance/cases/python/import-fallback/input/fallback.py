# Import alternatives (SPEC 8.2, DECISIONS F2): a binding made in an import-failure handler of a try
# whose body imports the same local name is dropped; other bindings of the file stay.
try:
    from secrets import randbits
except ImportError:
    from random import getrandbits as randbits
nonce = randbits(64)                    # want: python.rand.prng.secure secrets.randbits

try:
    from hashlib import sha256 as H
except (ModuleNotFoundError, AttributeError):
    from hashlib import md5 as H
digest = H(b"x")                        # want: python.hash.sha2 hashlib.sha256

try:
    from hashlib import sha512 as K
except:
    from hashlib import md5 as K
k = K(b"x")                             # want: python.hash.sha2 hashlib.sha512

try:
    from hashlib import sha1 as G
except KeyError:
    from hashlib import md5 as G
g = G(b"x")                             # want: python.hash.sha1 hashlib.sha1 | python.hash.md5 hashlib.md5

try:
    from hashlib import sha384
except ImportError:
    from hashlib import md5
m = md5(b"x")                           # want: python.hash.md5 hashlib.md5


def local():
    try:
        import secrets as rnd
    except Exception:
        import random as rnd
    return rnd.randbits(8)              # want: python.rand.prng.secure secrets.randbits


try:
    pass
finally:
    from hashlib import md5 as F
f = F(b"x")                             # want: python.hash.md5 hashlib.md5
