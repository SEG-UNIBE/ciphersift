import hashlib

from pkg.crypto import sha256


def sha3_hex(b):  # @pt=tests.test_crypto.sha3_hex
    return hashlib.sha3_256(b).hexdigest()  # @opt want: python.hash.sha3 hashlib.sha3_256


def test_it():
    assert sha256(b"")  # want: python.hash.sha2 hashlib.sha256 via=ps origin=ops
    assert sha3_hex(b"")  # want: python.hash.sha3 hashlib.sha3_256 via=pt origin=opt
