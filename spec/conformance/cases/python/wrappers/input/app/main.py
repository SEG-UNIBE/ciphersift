import pkg.crypto
import util
from pkg import crypto
from pkg import sha256d
from pkg.crypto import Keys, digest
from pkg.crypto import sha256 as h256


def main(b, k):
    h256(b)  # want: python.hash.sha2 hashlib.sha256 via=ps origin=ops
    crypto.hmac_sha_512(k, b)  # want: python.mac.hmac hmac.new via=phm origin=ophm | python.hash.sha2 hmac.new via=phm origin=ophm
    pkg.crypto.sha256(b)  # want: python.hash.sha2 hashlib.sha256 via=ps origin=ops
    sha256d(b)  # want: python.hash.sha2 hashlib.sha256 via=psd,ps origin=ops
    Keys.md5_hex(b)  # want: python.hash.md5 hashlib.md5 via=pm origin=opm
    digest(b)  # thin wrapper: off for Python by default
    util.md5_hex(b)  # util matches lib1.util and lib2.util: not resolved
    k.sha256(b)  # an unknown receiver: not resolved
