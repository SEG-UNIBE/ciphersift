from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

# isinstance on key classes of one family (DECISIONS B-P-ISI)


def sign(key, data):
    if isinstance(key, rsa.RSAPrivateKey):  # want: python.asym.rsa cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
        return 1
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):  # want: python.asym.ed25519 cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey
        return 2
    if isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):  # two families: nothing
        return 3
    if isinstance(key, ec.SECP256R1):  # not a key class: nothing
        return 4
