import random
import secrets
delay = random.random() * 5                    # 3: insecure PRNG (weakness indicator)
token = "%032x" % random.getrandbits(128)      # 4: insecure PRNG (weakness indicator)
nonce = secrets.token_hex(16)                  # 5: secure PRNG
