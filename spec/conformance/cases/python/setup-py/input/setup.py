import hashlib
from setuptools import setup


def _checksum(path):
    with open(path, "rb") as fh:
        return hashlib.sha1(fh.read()).hexdigest()   # 7: SHA1 (setup.py is Python source too)


setup(name="demo", version="1.0", install_requires=["cryptography>=42", "pyjwt==2.8.0"])
