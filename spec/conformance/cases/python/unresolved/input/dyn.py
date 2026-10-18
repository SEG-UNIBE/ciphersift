import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as pyca_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Fallbacks for algorithms chosen at run time (DECISIONS B-P-U1)


def digest(name, data):
    h = hashlib.new(name)  # want: python.hash.unresolved hashlib.new
    h2 = hashlib.new("sha256")  # want: python.hash.sha2 hashlib.new
    return getattr(hashlib, name)(data)  # want: python.hash.unresolved getattr


def pyca(alg, key, data):
    hashes.Hash(alg)  # want: python.hash.unresolved cryptography.hazmat.primitives.hashes.Hash
    hashes.Hash(hashes.SHA256())  # want: python.hash.sha2 cryptography.hazmat.primitives.hashes.SHA256
    pyca_hmac.HMAC(key, alg)  # want: python.mac.hmac cryptography.hazmat.primitives.hmac.HMAC
    Cipher(alg, modes.CBC(b"0" * 16))  # want: python.cipher.unresolved cryptography.hazmat.primitives.ciphers.Cipher


def stdlib_hmac(key, msg, mod):
    hmac.new(key, msg, mod)  # want: python.mac.hmac hmac.new
    hmac.new(key, msg, digestmod=hashlib.sha256)  # want: python.mac.hmac hmac.new | python.hash.sha2 hmac.new
    hmac.new(key, msg, digestmod="sha512")  # want: python.mac.hmac hmac.new | python.hash.sha2 hmac.new


def constant_names(data):
    getattr(hashlib, "sha256")(data)  # a constant name (review): no fallback
    return getattr(hashlib, "scrypt", None)  # feature detection: nothing
