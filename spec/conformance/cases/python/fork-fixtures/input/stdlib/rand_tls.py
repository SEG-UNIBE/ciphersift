import os
import random
import secrets
import ssl
import socket
from random import randint
import requests


def tokens():
    a = random.random()                       # insecure PRNG
    b = randint(0, 10)                        # insecure PRNG
    c = secrets.token_hex(16)                 # secure PRNG
    d = os.urandom(16)                        # secure PRNG
    e = random.SystemRandom().random()        # secure PRNG (SystemRandom), outer call not matched
    return a, b, c, d, e


def tls():
    ctx = ssl.create_default_context()        # TLS context
    ctx.check_hostname = False                # hostname verification disabled
    ctx.verify_mode = ssl.CERT_NONE           # cert validation disabled
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2   # TLS 1.2
    old = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # TLS 1.0 (not generic context)
    s = ssl.wrap_socket(socket.socket(), ssl_version=ssl.PROTOCOL_SSLv3)  # SSL 3.0
    u = ssl._create_unverified_context()      # cert validation disabled
    r = requests.get("https://example.org", verify=False)  # cert validation disabled
    ctx.options |= ssl.OP_NO_TLSv1            # nothing
    return old, s, u, r
