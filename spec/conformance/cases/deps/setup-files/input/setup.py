from setuptools import setup

rsa_require = ['cryptography>=3.0.0']
signed_require = ['cryptography>=3.0.0', 'pyjwt>=2.0.0,<3']

setup(
    name='demo',
    install_requires=['pyaes==1.6.1', 'requests', 'electrum_ecc>=0.0.4'],
    extras_require={
        'rsa': rsa_require,
        'signed': signed_require,
        'nacl': ['PyNaCl==1.5.0'],
        'url': ['tink @ https://example.org/tink.whl'],
    },
)
