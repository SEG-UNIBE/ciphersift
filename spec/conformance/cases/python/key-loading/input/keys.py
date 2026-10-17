from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_ssh_public_key
from OpenSSL import crypto
priv = serialization.load_pem_private_key(b"...", password=None)    # 4: private key
pub = load_pem_public_key(b"...")                                   # 5: public key
der = serialization.load_der_private_key(b"...", password=None)     # 6: private key
ssh = load_ssh_public_key(b"ssh-ed25519 AAAA")                      # 7: public key
dh = serialization.load_pem_parameters(b"...")                      # 8: domain parameters
ossl = crypto.load_privatekey(crypto.FILETYPE_PEM, b"...")          # 9: private key
LOADERS = [serialization.load_der_public_key]                       # 10: public key (reference)
out = priv.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8,
                         serialization.NoEncryption())              # 11: nothing (serialisation of a key object)
