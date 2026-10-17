from ..crypto import sha256


def run(b):
    return sha256(b)  # want: python.hash.sha2 hashlib.sha256 via=ps origin=ops
