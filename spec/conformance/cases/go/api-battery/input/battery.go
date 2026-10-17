// One API per line; each line's expected findings are in its trailing "want:" comment
// (rule, component name or "-", optional parameter; several findings separated by "|").
package battery

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/md5"
	"crypto/mlkem"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/x509"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	xed "golang.org/x/crypto/ed25519"
	xhkdf "golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/nacl/auth"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/nacl/sign"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/scrypt"
	xsha3 "golang.org/x/crypto/sha3"
	"golang.org/x/crypto/twofish"
)

func battery(k, m []byte, pub *rsa.PublicKey, priv *rsa.PrivateKey, h crypto.Hash) {
	aes.NewCipher(k)                              // want: go.sym.aes crypto/aes.NewCipher
	des.NewCipher(k)                              // want: go.sym.des crypto/des.NewCipher
	des.NewTripleDESCipher(k)                     // want: go.sym.3des crypto/des.NewTripleDESCipher
	rc4.NewCipher(k)                              // want: go.sym.rc4 crypto/rc4.NewCipher
	blowfish.NewCipher(k)                         // want: go.sym.blowfish golang.org/x/crypto/blowfish.NewCipher
	cast5.NewCipher(k)                            // want: go.sym.cast5 golang.org/x/crypto/cast5.NewCipher
	twofish.NewCipher(k)                          // want: go.sym.twofish golang.org/x/crypto/twofish.NewCipher
	chacha20.NewUnauthenticatedCipher(k, m)       // want: go.sym.chacha20 golang.org/x/crypto/chacha20.NewUnauthenticatedCipher
	chacha20poly1305.NewX(k)                      // want: go.sym.chacha20poly1305 golang.org/x/crypto/chacha20poly1305.NewX
	salsa20.XORKeyStream(m, m, k, nil)            // want: go.sym.salsa20 golang.org/x/crypto/salsa20.XORKeyStream
	secretbox.Seal(nil, m, nil, nil)              // want: go.sym.nacl.secretbox golang.org/x/crypto/nacl/secretbox.Seal
	box.Open(nil, m, nil, nil, nil)               // want: go.asym.nacl.box golang.org/x/crypto/nacl/box.Open
	rsa.EncryptOAEP(h.New(), rand.Reader, pub, m, nil) // want: go.asym.rsa.oaep crypto/rsa.EncryptOAEP | go.rand.prng.secure crypto/rand.Reader
	rsa.DecryptPKCS1v15(nil, priv, m)             // want: go.asym.rsa.pkcs1v15.encrypt crypto/rsa.DecryptPKCS1v15
	rsa.SignPKCS1v15(nil, priv, h, m)             // want: go.asym.rsa.pkcs1v15.sign crypto/rsa.SignPKCS1v15
	rsa.VerifyPSS(pub, h, m, m, nil)              // want: go.asym.rsa.pss crypto/rsa.VerifyPSS
	rsa.GenerateMultiPrimeKey(nil, 3, 4096)       // want: go.asym.rsa crypto/rsa.GenerateMultiPrimeKey 4096
	dsa.GenerateParameters(nil, nil, dsa.L2048N256) // want: go.asym.dsa crypto/dsa.GenerateParameters
	elliptic.P384()                               // want: go.asym.ec crypto/elliptic.P384 P-384
	ecdsa.SignASN1(nil, nil, m)                   // want: go.asym.ecdsa crypto/ecdsa.SignASN1
	ecdh.P521()                                   // want: go.asym.ecdh crypto/ecdh.P521 P-521
	ecdh.X25519()                                 // want: go.asym.x25519 crypto/ecdh.X25519
	curve25519.X25519(k, curve25519.Basepoint)    // want: go.asym.x25519 golang.org/x/crypto/curve25519.X25519
	ed25519.NewKeyFromSeed(k)                     // want: go.asym.ed25519 crypto/ed25519.NewKeyFromSeed
	xed.Sign(nil, m)                              // want: go.asym.ed25519 golang.org/x/crypto/ed25519.Sign
	sign.Open(nil, m, nil)                        // want: go.asym.ed25519 golang.org/x/crypto/nacl/sign.Open
	mlkem.GenerateKey1024()                       // want: go.pqc.mlkem crypto/mlkem.GenerateKey1024 ML-KEM-1024
	hmac.New(nil, k)                              // want: go.mac.hmac crypto/hmac.New
	auth.Sum(m, nil)                              // want: go.mac.hmac golang.org/x/crypto/nacl/auth.Sum
	poly1305.Verify(nil, m, nil)                  // want: go.mac.poly1305 golang.org/x/crypto/poly1305.Verify
	md4.New()                                     // want: go.hash.md4 golang.org/x/crypto/md4.New
	md5.Sum(m)                                    // want: go.hash.md5 crypto/md5.Sum
	sha1.New()                                    // want: go.hash.sha1 crypto/sha1.New
	sha256.Sum224(m)                              // want: go.hash.sha2 crypto/sha256.Sum224
	sha512.New512_256()                           // want: go.hash.sha2 crypto/sha512.New512_256
	sha3.SumSHAKE256(m, 64)                       // want: go.hash.sha3 crypto/sha3.SumSHAKE256
	xsha3.NewLegacyKeccak256()                    // want: go.hash.sha3 golang.org/x/crypto/sha3.NewLegacyKeccak256
	blake2b.Sum512(m)                             // want: go.hash.blake2 golang.org/x/crypto/blake2b.Sum512
	blake2s.New256(k)                             // want: go.hash.blake2 golang.org/x/crypto/blake2s.New256
	ripemd160.New()                               // want: go.hash.ripemd160 golang.org/x/crypto/ripemd160.New
	argon2.IDKey(k, m, 1, 64*1024, 4, 32)         // want: go.hash.argon2 golang.org/x/crypto/argon2.IDKey
	bcrypt.GenerateFromPassword(k, 12)            // want: go.hash.bcrypt golang.org/x/crypto/bcrypt.GenerateFromPassword
	hkdf.Extract(nil, k, m)                       // want: go.kdf.hkdf crypto/hkdf.Extract
	xhkdf.Expand(nil, k, m)                       // want: go.kdf.hkdf golang.org/x/crypto/hkdf.Expand
	pbkdf2.Key(nil, "pw", m, 600000, 32)          // want: go.kdf.pbkdf2 crypto/pbkdf2.Key
	scrypt.Key(k, m, 32768, 8, 1, 32)             // want: go.kdf.scrypt golang.org/x/crypto/scrypt.Key
	rand.Read(k)                                  // want: go.rand.prng.secure crypto/rand.Read
	x509.ParsePKCS8PrivateKey(k)                  // want: go.key.load.private -
	x509.ParsePKIXPublicKey(k)                    // want: go.key.load.public -
	x509.ParseCertificate(k)                      // want: go.cert.x509 crypto/x509.ParseCertificate
	pkcs12.Decode(k, "pw")                        // want: go.cert.pkcs -
	_ = crypto.SHA512_256                         // want: go.hash.sha2 crypto.SHA512_256
	_ = crypto.SHA3_384                           // want: go.hash.sha3 crypto.SHA3_384
	_ = crypto.MD5                                // want: go.hash.md5 crypto.MD5
	_ = x509.SHA384WithRSAPSS                     // want: go.asym.rsa.pss crypto/x509.SHA384WithRSAPSS
	_ = x509.ECDSAWithSHA256                      // want: go.asym.ecdsa crypto/x509.ECDSAWithSHA256
	_ = x509.PureEd25519                          // want: go.asym.ed25519 crypto/x509.PureEd25519
	_ = x509.SHA1WithRSA                          // want: go.asym.rsa.pkcs1v15.sign crypto/x509.SHA1WithRSA
	_ = x509.DSAWithSHA256                        // want: go.asym.dsa crypto/x509.DSAWithSHA256
	_ = cipher.NewOFB(nil, k)                     // want: go.sym.mode.ofb crypto/cipher.NewOFB
	_ = sha512.Size                               // not an algorithm use: no finding
	_ = md5.BlockSize                             // no finding
	bcrypt.DefaultCost = 10                       // no finding
}
