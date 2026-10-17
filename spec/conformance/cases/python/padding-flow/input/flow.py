from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15, PSS, MGF1, OAEP
from cryptography.hazmat.primitives import hashes
def sign(key, data, mech):
    if mech == 'pkcs1':
        padding = PKCS1v15()                                       # 5: RSA PKCS1v15 (padding object of its own)
        return key.sign(data, padding, hashes.SHA256())            # 6: PKCS1v15 and PSS (flow-insensitive), SHA2
    padding = PSS(mgf=MGF1(hashes.SHA256()), salt_length=32)       # 7: PSS, SHA2
    return key.sign(data, padding, hashes.SHA256())                # 8: PKCS1v15 and PSS (flow-insensitive), SHA2
def decrypt(key, ct, legacy):
    pad = OAEP(mgf=MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)  # 10: OAEP, SHA1
    if legacy:
        pad = PKCS1v15()                                           # 12: RSA PKCS1v15
    return key.decrypt(ct, pad)                                    # 13: PKCS1v15 encryption and OAEP (flow-insensitive)
