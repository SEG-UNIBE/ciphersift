import hashlib

# IANA SSH / JOSE / TLS-group names as string literals in value positions (DECISIONS B-P-LIT)
KEX = ("curve25519-sha256", "diffie-hellman-group14-sha256")  # want: python.asym.dh diffie-hellman-group14-sha256 | python.asym.x25519 curve25519-sha256 | python.hash.sha2 curve25519-sha256
register_alg(b"ssh-ed25519", object)  # want: python.asym.ed25519 ssh-ed25519
ALG = "ES384"  # want: python.asym.ec ES384 | python.hash.sha2 ES384
if ALG == "RS256":  # a comparison: nothing
    pass
h = hashlib.sha256(b"ES512")  # want: python.hash.sha2 hashlib.sha256
f"{ALG}-ssh-rsa"  # an f-string: nothing
"""ssh-rsa"""  # a docstring-like statement: nothing
