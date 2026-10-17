import hashlib


def md5_hex(b):
    return hashlib.md5(b).hexdigest()  # want: python.hash.md5 hashlib.md5
