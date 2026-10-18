from pkg.aes import AESCipher, Helper, RSAThing
from pkg import filters


# classes named after a family whose body has a finding of it are callables (DECISIONS P3-CLS)
def use(key, data):
    c = AESCipher(key)  # want: python.sym.aes.cbc Crypto.Cipher.AES.new
    out = c.encrypt(data)  # want: python.sym.aes.cbc Crypto.Cipher.AES.new
    c.pad(data)  # a method without the finding: nothing
    f = filters.StandardAESFilter()  # want: python.sym.aes.ecb Crypto.Cipher.AES.new
    f.decrypt(key, out)  # want: python.sym.aes.ecb Crypto.Cipher.AES.new
    Helper().run(key)  # the class name names no family: nothing
    RSAThing().run(key)  # the name names RSA, the body has AES: nothing
    d = AESCipher(key)  # want: python.sym.aes.cbc Crypto.Cipher.AES.new
    d = None
    d.encrypt(data)  # d is bound twice: nothing
    return out


def param(c, data):
    return c.encrypt(data)  # a parameter: nothing
