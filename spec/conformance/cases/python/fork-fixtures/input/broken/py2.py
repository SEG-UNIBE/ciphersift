import md5
import sha
import random

print "hello"
digest = md5.new("data").hexdigest()     # MD5 (Python 2 md5 module)
s = sha.new("data")                      # SHA1
exec "x = 1"
r = random.random()                      # insecure PRNG
