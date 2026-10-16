import hashlib
import hmac
from Crypto.Cipher import AES

MODULE_ALG = "md5"
SPLIT = "sha" "256"
NUMBER = 512


def module_level(data):
    hashlib.new(MODULE_ALG)                         # 11: module constant -> MD5
    hashlib.new(SPLIT)                              # 12: implicit concatenation -> SHA2
    hashlib.new(f"sha{NUMBER}")                     # 13: f-string -> nothing
    hashlib.new(b"md5")                             # 14: bytes literal -> nothing


def local_constant(data):
    alg = "sha1"
    hashlib.new(alg)                                # 19: function-local constant -> SHA1


def parameter_shadows(MODULE_ALG):
    hashlib.new(MODULE_ALG)                         # 23: parameter shadows the module constant -> nothing (reference tool: MD5, see deviations)


def keyword_default(alg="sha512"):
    hashlib.new(alg)                                # 27: parameter (default not used) -> nothing


def lists(key, data):
    hmac.new(key, data, digestmod="sha384")         # 31: keyword string -> HMAC + SHA2
    AES.new(key, AES.MODE_CBC, iv=b"0" * 16)        # 32: AES-CBC


def rebound(data):
    alg = "md5"
    alg = "sha256"
    hashlib.new(alg)                                # 38: flow-insensitive; the first binding ("md5") is the first string -> MD5
