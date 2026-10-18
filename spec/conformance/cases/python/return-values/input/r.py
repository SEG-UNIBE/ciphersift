import hashlib
from typing import Dict
from cryptography.hazmat.primitives import hashes


# returned values and table look-ups are value positions (DECISIONS P3-RET)
def pick(name):
    if name == hashlib.md5:  # a comparison: nothing
        return hashlib.md5  # want: python.hash.md5 hashlib.md5
    return hashlib.sha256  # want: python.hash.sha2 hashlib.sha256


def table(name):
    return {"sha1": hashes.SHA1, "sha512": hashes.SHA512}[name]()  # want: python.hash.sha1 cryptography.hazmat.primitives.hashes.SHA1 | python.hash.sha2 cryptography.hazmat.primitives.hashes.SHA512


def ssh_name():
    return "ssh-ed25519"  # want: python.asym.ed25519 ssh-ed25519


FIRST = (hashlib.sha3_256, hashlib.blake2b)[0]  # want: python.hash.blake2 hashlib.blake2b | python.hash.sha3 hashlib.sha3_256


def nothing(d, k):
    x = d[hashlib.sha1]  # a subscript index: nothing
    y = hashlib.sha1.__name__  # an attribute of the function: nothing
    return hashlib  # a module: nothing


def typed() -> Dict[str, hashes.SHA256]:  # an annotation: nothing
    return None
