import oqs
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM1024PrivateKey

# ML-KEM and ML-DSA (DECISIONS B-P-PQ)
dk = mlkem.MLKEM768PrivateKey.generate()  # want: python.pqc.mlkem cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey.generate ML-KEM-768
sk = mldsa.MLDSA65PrivateKey.generate()  # want: python.pqc.mldsa cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.generate ML-DSA-65
KEY_TYPES = (MLKEM1024PrivateKey,)  # want: python.pqc.mlkem cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PrivateKey ML-KEM-1024
kem = oqs.KeyEncapsulation("ML-KEM-512")  # want: python.pqc.mlkem oqs.KeyEncapsulation ML-KEM-512
sig = oqs.Signature("ML-DSA-87")  # want: python.pqc.mldsa oqs.Signature ML-DSA-87
