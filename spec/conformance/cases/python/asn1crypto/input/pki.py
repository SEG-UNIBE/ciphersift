from asn1crypto import x509, algos, crl
cert = x509.Certificate.load(b"...")                                   # 2: x509 certificate
fp = cert.sha256                                                       # 3: nothing (attribute read, receiver type unknown)
alg = algos.DigestAlgorithm({'algorithm': 'sha256'})                   # 4: SHA2 (dictionary argument)
sig = algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'})         # 5: RSA PKCS#1 v1.5 signature
pss = algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pss',
                                   'parameters': None})                # 6: RSA-PSS
params = {'algorithm': 'sha256_ecdsa'}
ec = algos.SignedDigestAlgorithm(params)                               # 9: ECDSA (dictionary bound to a name)
md = algos.DigestAlgorithmId('sha1')                                   # 10: SHA1 (string argument)
enc = algos.EncryptionAlgorithm({'algorithm': 'aes256_cbc', 'parameters': b"iv"})  # 11: AES-CBC
kek = algos.KeyEncryptionAlgorithm({'algorithm': 'rsaes_oaep'})        # 12: RSA-OAEP
crls = crl.CertificateList.load(b"...")                                # 13: x509 (CRL)
def dyn(name):
    return algos.DigestAlgorithm({'algorithm': name})                  # 15: nothing (dynamic value)
other = algos.DigestAlgorithm({'name': 'sha256'})                      # 16: nothing (other key)
