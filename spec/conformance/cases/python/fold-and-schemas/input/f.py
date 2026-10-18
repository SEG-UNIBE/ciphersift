import electrum_ecc as ecc
from asn1crypto import core, x509

# a key object in the receiver of an ECDSA operation folds into it (DECISIONS B-P-B3)
ok = ecc.ECPubkey(b"\x02" + b"\x01" * 32).ecdsa_verify(b"s", b"h")  # want: python.asym.ecdsa electrum_ecc.ECPubkey().ecdsa_verify
pub = ecc.ECPubkey(b"\x02" + b"\x01" * 32)  # want: python.asym.secp256k1 electrum_ecc.ECPubkey secp256k1


# an asn1crypto schema declaration names types (DECISIONS B-P-B2)
class Recipient(core.Sequence):
    _fields = [("cert", x509.Certificate), ("rid", core.OctetString)]


CERT_TYPE = x509.Certificate  # want: python.cert.x509 asn1crypto.x509.Certificate
