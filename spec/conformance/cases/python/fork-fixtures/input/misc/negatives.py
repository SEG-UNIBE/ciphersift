import numpy as np
from numpy import random
import hashlib


class AES:
    @staticmethod
    def new(key):
        return key


def md5(x):
    return x


def go(name):
    a = random.randint(0, 3)        # numpy.random — not stdlib random
    b = np.random.rand()            # numpy — not flagged
    c = AES.new("k")                # local class, not PyCryptodome
    d = md5("x")                    # local function, not hashlib
    e = hashlib.new(name)           # unknown algorithm — not reported
    f = hashlib.sha256(b"x").hexdigest()  # only the inner call is reported 
    return a, b, c, d, e, f
