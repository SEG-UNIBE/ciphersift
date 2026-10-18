from Crypto.Cipher import AES  # an import: nothing


class AESCipher:
    def __init__(self, key):
        self.key = key

    def pad(self, data):
        return data + b"\0" * (16 - len(data) % 16)

    def encrypt(self, data):
        return AES.new(self.key, AES.MODE_CBC).encrypt(self.pad(data))  # want: python.sym.aes.cbc Crypto.Cipher.AES.new


class AESFilterMixin:
    def decrypt(self, key, data):
        return AES.new(key, AES.MODE_ECB).decrypt(data)  # want: python.sym.aes.ecb Crypto.Cipher.AES.new


class Helper:
    def run(self, key):
        return AES.new(key, AES.MODE_GCM)  # want: python.sym.aes.gcm Crypto.Cipher.AES.new


class RSAThing:
    def run(self, key):
        return AES.new(key, AES.MODE_GCM)  # want: python.sym.aes.gcm Crypto.Cipher.AES.new
