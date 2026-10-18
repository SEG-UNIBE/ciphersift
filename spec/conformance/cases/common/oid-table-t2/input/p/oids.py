from cryptography import x509

# OID table entries added by DECISIONS B-A4 (SPEC 5.11)
A = x509.ObjectIdentifier("1.3.6.1.4.1.1722.12.2.1.8")  # want: python.hash.blake2 cryptography.x509.ObjectIdentifier oid=1.3.6.1.4.1.1722.12.2.1.8
B = x509.ObjectIdentifier("1.2.156.10197.1.401")  # want: python.hash.sm3 cryptography.x509.ObjectIdentifier oid=1.2.156.10197.1.401
C = x509.ObjectIdentifier("1.2.840.113549.3.4")  # want: python.sym.rc4 cryptography.x509.ObjectIdentifier oid=1.2.840.113549.3.4
D = x509.ObjectIdentifier("1.2.840.113549.1.12.1.3")  # no Python PBE rule: nothing
