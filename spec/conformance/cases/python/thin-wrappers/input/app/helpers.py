"""Thin wrappers (SPEC 18.5, W6), enabled for Python with --python-thin-wrappers."""
import hashlib
import os


def digest(x):  # @td=app.helpers.digest
    # at most 8 lines, exactly one family: a crypto callable whatever its name
    return hashlib.sha1(x).digest()  # @otd want: python.hash.sha1 hashlib.sha1


def twice(x):  # @tt=app.helpers.twice
    # a thin wrapper of a thin wrapper (transitive W6)
    return digest(digest(x))  # want: python.hash.sha1 hashlib.sha1 via=td origin=otd


def two_families(x):
    hashlib.md5(x)  # want: python.hash.md5 hashlib.md5
    return hashlib.sha1(x)  # want: python.hash.sha1 hashlib.sha1


def long_one(x):
    h = hashlib.sha256()  # want: python.hash.sha2 hashlib.sha256
    h.update(x)
    h.update(x)
    h.update(x)
    h.update(x)
    h.update(x)
    h.update(x)
    return h.digest()


def random_bytes(n):
    return os.urandom(n)  # want: python.rand.prng.secure os.urandom


def main(x):
    digest(x)  # want: python.hash.sha1 hashlib.sha1 via=td origin=otd
    twice(x)  # want: python.hash.sha1 hashlib.sha1 via=tt,td origin=otd
    two_families(x)  # two families: not a thin wrapper
    long_one(x)  # nine lines: not a thin wrapper
    random_bytes(16)  # a CSPRNG only: not propagated
