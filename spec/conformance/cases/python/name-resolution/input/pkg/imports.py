import hashlib as hl
import cryptography.hazmat.primitives.hashes
import Crypto.Cipher.AES as CAES
from cryptography.hazmat.primitives.ciphers import Cipher as C, algorithms, modes
from Crypto.Hash import SHA256 as S256
from .local import md5
from . import sha1
from Crypto.Cipher import *
try:
    from Cryptodome.Hash import SHA512
except ImportError:
    from Crypto.Hash import SHA512

H = hl.sha1
Alias = algorithms


def run(key, iv, data):
    hl.md5(data)                                                       # 19: import as -> MD5
    cryptography.hazmat.primitives.hashes.SHA256()                     # 20: dotted import -> SHA2
    CAES.new(key, CAES.MODE_ECB)                                       # 21: import a.b.C as X -> AES-ECB
    C(algorithms.AES(key), modes.GCM(iv))                              # 22: from-import with alias -> AES-GCM
    S256.new(data)                                                     # 23: from-import alias -> SHA2
    md5(data)                                                          # 24: relative import -> nothing
    sha1.new()                                                         # 25: relative import -> nothing
    DES.new(key, DES.MODE_CBC)                                         # 26: star import -> DES
    SHA512.new(data)                                                   # 27: try/except alternatives -> SHA2
    H(data)                                                            # 28: alias of a function -> SHA1
    algo = Alias.TripleDES(key)
    C(algo, modes.CBC(iv))                                             # 30: alias of a module + bound call -> 3DES
    hl.sha3_512(data).hexdigest()                                      # 31: inner call only -> SHA3
    hl.sha256x(data)                                                   # 32: not a prefix match -> nothing
