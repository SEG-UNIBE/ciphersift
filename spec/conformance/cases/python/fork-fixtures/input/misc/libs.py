import bcrypt
import jwt
import nacl.secret
import nacl.utils
import paramiko
from nacl.public import PrivateKey, Box
from nacl.signing import SigningKey
from passlib.hash import pbkdf2_sha256, md5_crypt
from passlib.context import CryptContext
from argon2 import PasswordHasher
from OpenSSL import SSL, crypto


def go(pw, payload, key):
    h = bcrypt.hashpw(pw, bcrypt.gensalt())                # bcrypt (2 calls, one asset)
    t = jwt.encode(payload, key, algorithm="HS256")        # JWT HMAC
    n = jwt.encode(payload, None, algorithm="none")        # JWT none
    v = jwt.decode(t, options={"verify_signature": False})  # JWT unverified
    r = jwt.decode(t, key, algorithms=["RS256"])           # RSA PKCS1v15 sig
    box = nacl.secret.SecretBox(nacl.utils.random(32))     # SecretBox + secure PRNG
    sk = PrivateKey.generate()                             # NaCl box keypair
    sg = SigningKey.generate()                             # Ed25519
    p1 = pbkdf2_sha256.hash(pw)                            # PBKDF2
    p2 = md5_crypt.hash(pw)                                # MD5
    ctx = CryptContext(schemes=["bcrypt", "md5_crypt"])    # bcrypt + MD5
    ph = PasswordHasher()                                  # Argon2
    client = paramiko.SSHClient()                          # SSH
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # host key verification disabled
    rk = paramiko.RSAKey.generate(bits=2048)               # RSA 2048
    oc = SSL.Context(SSL.TLSv1_METHOD)                     # TLS 1.0
    oc.set_verify(SSL.VERIFY_NONE, None)                   # cert validation disabled
    pk = crypto.PKey()
    pk.generate_key(crypto.TYPE_RSA, 1024)                 # RSA 1024
    return h, t, n, v, r, box, sk, sg, p1, p2, ctx, ph, client, rk, oc, pk
