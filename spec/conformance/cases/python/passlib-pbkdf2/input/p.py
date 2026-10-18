from passlib.crypto.digest import pbkdf2_hmac
from passlib.crypto import digest

# passlib's PBKDF2 function (DECISIONS P3-PL)
a = pbkdf2_hmac("sha1", b"pw", b"salt", 1000)  # want: python.hash.sha1 passlib.crypto.digest.pbkdf2_hmac | python.kdf.pbkdf2 passlib.crypto.digest.pbkdf2_hmac
b = digest.pbkdf2_hmac("sha256", b"pw", b"salt", 1000, 32)  # want: python.hash.sha2 passlib.crypto.digest.pbkdf2_hmac | python.kdf.pbkdf2 passlib.crypto.digest.pbkdf2_hmac
c = digest.lookup_hash("sha256")  # another function: nothing
