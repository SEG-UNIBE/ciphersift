import hashlib
import ssl

import paramiko
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def make_tls_context():  # @p1=py.wa.net.make_tls_context
    return ssl.create_default_context()  # @op1 want: python.prot.tls.context -


def ssh_client():  # @p2=py.wa.net.ssh_client
    return paramiko.SSHClient()  # @op2 want: python.prot.ssh -


def load_cert(data):  # @p3=py.wa.net.load_cert
    return x509.load_pem_x509_certificate(data)  # @op3 want: python.cert.x509 cryptography.x509.load_pem_x509_certificate


def load_privkey(data):  # @p4=py.wa.net.load_privkey
    return load_pem_private_key(data, None)  # @op4 want: python.key.load.private -


def hash160(b):  # @p5=py.wa.net.hash160
    # Bitcoin's HASH160: RIPEMD-160 of SHA-256; the name names RIPEMD160 only
    h = hashlib.sha256(b).digest()  # want: python.hash.sha2 hashlib.sha256
    return hashlib.new("ripemd160", h).digest()  # @op5 want: python.hash.ripemd160 hashlib.new


def use(b):
    make_tls_context()  # want: python.prot.tls.context - via=p1 origin=op1
    ssh_client()  # want: python.prot.ssh - via=p2 origin=op2
    load_cert(b)  # want: python.cert.x509 cryptography.x509.load_pem_x509_certificate via=p3 origin=op3
    load_privkey(b)  # want: python.key.load.private - via=p4 origin=op4
    hash160(b)  # want: python.hash.ripemd160 hashlib.new via=p5 origin=op5
