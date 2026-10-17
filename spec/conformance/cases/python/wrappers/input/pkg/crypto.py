"""Name-consistent wrappers (SPEC 18.5, W7)."""
import hashlib
import hmac as _hmac


def sha256(x):  # @ps=pkg.crypto.sha256
    if isinstance(x, str):
        x = x.encode()
    return hashlib.sha256(x).digest()  # @ops want: python.hash.sha2 hashlib.sha256


def sha256d(x):  # @psd=pkg.crypto.sha256d
    return sha256(sha256(x))  # want: python.hash.sha2 hashlib.sha256 via=ps origin=ops


def hmac_sha_512(key, msg):  # @phm=pkg.crypto.hmac_sha_512
    return _hmac.new(key, msg, hashlib.sha512).digest()  # @ophm want: python.mac.hmac hmac.new | python.hash.sha2 hmac.new


def digest(x):
    # thin, but W6 is off for Python by default
    return hashlib.sha1(x).digest()  # want: python.hash.sha1 hashlib.sha1


def shadowed(sha256):
    return sha256(b"x")  # a parameter: not resolved


class Keys:
    def ecdsa_key(self):  # @pk=pkg.crypto.Keys.ecdsa_key
        from cryptography.hazmat.primitives.asymmetric import ec
        return ec.generate_private_key(ec.SECP256K1())  # @opk want: python.asym.ec cryptography.hazmat.primitives.asymmetric.ec.generate_private_key SECP256K1

    def make(self):
        return self.ecdsa_key()  # want: python.asym.ec cryptography.hazmat.primitives.asymmetric.ec.generate_private_key SECP256K1 via=pk origin=opk

    @staticmethod
    def md5_hex(data):  # @pm=pkg.crypto.Keys.md5_hex
        return hashlib.md5(data).hexdigest()  # @opm want: python.hash.md5 hashlib.md5
