from jwt.algorithms import hashes

import oauthlib_compat.primitives.serialization as ser

# pyca names re-exported by other packages (DECISIONS B-P-RX)
DIGESTS = {"SHA-1": hashes.SHA1}  # want: python.hash.sha1 jwt.algorithms.hashes.SHA1
h = hashes.SHA256()  # want: python.hash.sha2 jwt.algorithms.hashes.SHA256
ser.load_pem_private_key(b"", None)  # want: python.key.load.private oauthlib_compat.primitives.serialization.load_pem_private_key
