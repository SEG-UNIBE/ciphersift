from Cryptodome.Cipher import AES
from Crypto.Hash import *

try:
    from Crypto.Cipher import Blowfish
except ImportError:
    from Cryptodome.Cipher import Blowfish


def go(key):
    a = AES.new(key, AES.MODE_OCB)     # AES-OCB (Cryptodome namespace)
    h = SHA1.new()                     # SHA1 via star import
    b = Blowfish.new(key, Blowfish.MODE_CBC)  # Blowfish (either namespace)
    return a, h, b
