import hashlib

from cryptography.hazmat.primitives.asymmetric import ec

# U1W (DECISIONS B-P-U1W): hash / digest name the hash fallback; B5 (B-P-B5): evidence by name token


def compute_hash(alg, data):  # @h1=hw.util.compute_hash
    h = hashlib.new(alg)  # @oh1 want: python.hash.unresolved hashlib.new
    h.update(data)
    return h.digest()


def make_digest(alg, data):  # @h2=hw.util.make_digest
    return compute_hash(alg, data)  # want: python.hash.unresolved hashlib.new via=h1 origin=oh1


def checksum(alg, data):
    # the name names nothing: not a callable (Python thin wrappers are off)
    return hashlib.new(alg, data).digest()  # want: python.hash.unresolved hashlib.new


def _ecdh_shared(peer):  # @e1=hw.util._ecdh_shared
    key = ec.generate_private_key(ec.SECP256R1())  # want: python.asym.ec cryptography.hazmat.primitives.asymmetric.ec.generate_private_key SECP256R1
    return key.exchange(ec.ECDH(), peer)  # @oe1 want: python.asym.ecdh cryptography.hazmat.primitives.asymmetric.ec.ECDH


def use(data, peer):
    make_digest("x", data)  # want: python.hash.unresolved hashlib.new via=h2,h1 origin=oh1
    checksum("x", data)
    _ecdh_shared(peer)  # want: python.asym.ecdh cryptography.hazmat.primitives.asymmetric.ec.ECDH via=e1 origin=oe1
