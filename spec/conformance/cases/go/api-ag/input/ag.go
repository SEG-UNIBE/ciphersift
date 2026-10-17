// Third-party Go APIs of SPEC 17.11 (DECISIONS T11), one use per line.
package ag

import (
	"crypto/elliptic"
	"crypto/x509"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/cloudflare/circl/dh/x448"
	cx25519 "github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/ed448"
	ced25519 "github.com/cloudflare/circl/sign/ed25519"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/flynn/noise"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/miekg/pkcs11"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func ageUses(w, r, rs, ids, pw, s, pem, key interface{}) {
	age.Encrypt(w, rs) // want: go.sym.chacha20poly1305 filippo.io/age.Encrypt
	age.EncryptReader(r, rs) // want: go.sym.chacha20poly1305 filippo.io/age.EncryptReader
	age.Decrypt(r, ids) // want: go.sym.chacha20poly1305 filippo.io/age.Decrypt
	age.DecryptReaderAt(r, 0, ids) // want: go.sym.chacha20poly1305 filippo.io/age.DecryptReaderAt
	age.NewScryptIdentity(pw) // want: go.kdf.scrypt filippo.io/age.NewScryptIdentity
	age.NewScryptRecipient(pw) // want: go.kdf.scrypt filippo.io/age.NewScryptRecipient
	age.GenerateX25519Identity() // want: go.asym.x25519 filippo.io/age.GenerateX25519Identity
	age.ParseX25519Identity(s) // want: go.asym.x25519 filippo.io/age.ParseX25519Identity
	age.ParseX25519Recipient(s) // want: go.asym.x25519 filippo.io/age.ParseX25519Recipient
	age.GenerateHybridIdentity() // want: go.pqc.mlkem filippo.io/age.GenerateHybridIdentity ML-KEM-768
	age.ParseHybridIdentity(s) // want: go.pqc.mlkem filippo.io/age.ParseHybridIdentity ML-KEM-768
	age.ParseHybridRecipient(s) // want: go.pqc.mlkem filippo.io/age.ParseHybridRecipient ML-KEM-768
	age.ParseRecipients(r) // names no algorithm: nothing
	agessh.NewEd25519Identity(key) // want: go.asym.ed25519 filippo.io/age/agessh.NewEd25519Identity
	agessh.NewEd25519Recipient(key) // want: go.asym.ed25519 filippo.io/age/agessh.NewEd25519Recipient
	agessh.NewRSAIdentity(key) // want: go.asym.rsa filippo.io/age/agessh.NewRSAIdentity
	agessh.NewRSARecipient(key) // want: go.asym.rsa filippo.io/age/agessh.NewRSARecipient
	agessh.ParseIdentity(pem) // want: go.key.load.private -
	agessh.NewEncryptedSSHIdentity(key, pem, nil) // want: go.key.load.private -
	agessh.ParseRecipient(s) // want: go.key.load.public -
}

func sigstoreUses(pem, cert, certs, priv, pub, pf interface{}) {
	cryptoutils.UnmarshalCertificatesFromPEM(pem) // want: go.cert.x509 github.com/sigstore/sigstore/pkg/cryptoutils.UnmarshalCertificatesFromPEM
	cryptoutils.UnmarshalCertificatesFromPEMLimited(pem, 10) // want: go.cert.x509 github.com/sigstore/sigstore/pkg/cryptoutils.UnmarshalCertificatesFromPEMLimited
	cryptoutils.LoadCertificatesFromPEM(pem) // want: go.cert.x509 github.com/sigstore/sigstore/pkg/cryptoutils.LoadCertificatesFromPEM
	cryptoutils.MarshalCertificateToPEM(cert) // want: go.cert.x509 github.com/sigstore/sigstore/pkg/cryptoutils.MarshalCertificateToPEM
	cryptoutils.MarshalCertificatesToPEM(certs) // want: go.cert.x509 github.com/sigstore/sigstore/pkg/cryptoutils.MarshalCertificatesToPEM
	cryptoutils.ParseCSR(pem) // want: go.cert.x509 github.com/sigstore/sigstore/pkg/cryptoutils.ParseCSR
	cryptoutils.UnmarshalPEMToPrivateKey(pem, pf) // want: go.key.load.private -
	cryptoutils.MarshalPrivateKeyToPEM(priv) // want: go.key.load.private -
	cryptoutils.MarshalPrivateKeyToDER(priv) // want: go.key.load.private -
	cryptoutils.MarshalPrivateKeyToEncryptedDER(priv, pf) // want: go.key.load.private -
	cryptoutils.UnmarshalPEMToPublicKey(pem) // want: go.key.load.public -
	cryptoutils.MarshalPublicKeyToPEM(pub) // want: go.key.load.public -
	cryptoutils.MarshalPublicKeyToDER(pub) // want: go.key.load.public -
	cryptoutils.GeneratePEMEncodedECDSAKeyPair(elliptic.P384(), pf) // want: go.asym.ecdsa github.com/sigstore/sigstore/pkg/cryptoutils.GeneratePEMEncodedECDSAKeyPair P-384
	cryptoutils.GeneratePEMEncodedRSAKeyPair(3072, pf) // want: go.asym.rsa github.com/sigstore/sigstore/pkg/cryptoutils.GeneratePEMEncodedRSAKeyPair 3072
	cryptoutils.SKID(pub) // want: go.hash.sha1 github.com/sigstore/sigstore/pkg/cryptoutils.SKID
	cryptoutils.GetPasswordFromStdIn(false) // names no algorithm: nothing
}

func x509Uses(priv, pub interface{}) {
	x509.MarshalPKCS1PrivateKey(priv) // want: go.key.load.private -
	x509.MarshalPKCS8PrivateKey(priv) // want: go.key.load.private -
	x509.MarshalECPrivateKey(priv) // want: go.key.load.private -
	x509.MarshalPKIXPublicKey(pub) // want: go.key.load.public -
	x509.MarshalPKCS1PublicKey(pub) // want: go.key.load.public -
}

func sslibUses(pt, ct, pw, v interface{}) {
	encrypted.Encrypt(pt, pw) // want: go.kdf.scrypt github.com/secure-systems-lab/go-securesystemslib/encrypted.Encrypt | go.sym.nacl.secretbox github.com/secure-systems-lab/go-securesystemslib/encrypted.Encrypt
	encrypted.Decrypt(ct, pw) // want: go.kdf.scrypt github.com/secure-systems-lab/go-securesystemslib/encrypted.Decrypt | go.sym.nacl.secretbox github.com/secure-systems-lab/go-securesystemslib/encrypted.Decrypt
	encrypted.EncryptWithCustomKDFParameters(pt, pw, encrypted.OWASP) // want: go.kdf.scrypt github.com/secure-systems-lab/go-securesystemslib/encrypted.EncryptWithCustomKDFParameters | go.sym.nacl.secretbox github.com/secure-systems-lab/go-securesystemslib/encrypted.EncryptWithCustomKDFParameters
	encrypted.Marshal(v, pw) // want: go.kdf.scrypt github.com/secure-systems-lab/go-securesystemslib/encrypted.Marshal | go.sym.nacl.secretbox github.com/secure-systems-lab/go-securesystemslib/encrypted.Marshal
	encrypted.MarshalWithCustomKDFParameters(v, pw, encrypted.Legacy) // want: go.kdf.scrypt github.com/secure-systems-lab/go-securesystemslib/encrypted.MarshalWithCustomKDFParameters | go.sym.nacl.secretbox github.com/secure-systems-lab/go-securesystemslib/encrypted.MarshalWithCustomKDFParameters
	encrypted.Unmarshal(ct, v, pw) // want: go.kdf.scrypt github.com/secure-systems-lab/go-securesystemslib/encrypted.Unmarshal | go.sym.nacl.secretbox github.com/secure-systems-lab/go-securesystemslib/encrypted.Unmarshal
}

func circlUses(seed, sk, pk, msg, sig, ctx, out interface{}) {
	mldsa44.GenerateKey(nil) // want: go.pqc.mldsa github.com/cloudflare/circl/sign/mldsa/mldsa44.GenerateKey ML-DSA-44
	mldsa65.NewKeyFromSeed(seed) // want: go.pqc.mldsa github.com/cloudflare/circl/sign/mldsa/mldsa65.NewKeyFromSeed ML-DSA-65
	mldsa87.SignTo(sk, msg, ctx, false, sig) // want: go.pqc.mldsa github.com/cloudflare/circl/sign/mldsa/mldsa87.SignTo ML-DSA-87
	mldsa87.Verify(pk, msg, ctx, sig) // want: go.pqc.mldsa github.com/cloudflare/circl/sign/mldsa/mldsa87.Verify ML-DSA-87
	mldsa65.Scheme() // want: go.pqc.mldsa github.com/cloudflare/circl/sign/mldsa/mldsa65.Scheme ML-DSA-65
	mlkem512.GenerateKeyPair(nil) // want: go.pqc.mlkem github.com/cloudflare/circl/kem/mlkem/mlkem512.GenerateKeyPair ML-KEM-512
	mlkem768.NewKeyFromSeed(seed) // want: go.pqc.mlkem github.com/cloudflare/circl/kem/mlkem/mlkem768.NewKeyFromSeed ML-KEM-768
	mlkem1024.Scheme() // want: go.pqc.mlkem github.com/cloudflare/circl/kem/mlkem/mlkem1024.Scheme ML-KEM-1024
	ced25519.Sign(sk, msg) // want: go.asym.ed25519 github.com/cloudflare/circl/sign/ed25519.Sign
	ced25519.VerifyWithCtx(pk, msg, sig, "c") // want: go.asym.ed25519 github.com/cloudflare/circl/sign/ed25519.VerifyWithCtx
	ed448.GenerateKey(nil) // want: go.asym.ed448 github.com/cloudflare/circl/sign/ed448.GenerateKey
	ed448.SignPh(sk, msg, "") // want: go.asym.ed448 github.com/cloudflare/circl/sign/ed448.SignPh
	ed448.Verify(pk, msg, sig, "") // want: go.asym.ed448 github.com/cloudflare/circl/sign/ed448.Verify
	cx25519.KeyGen(out, sk) // want: go.asym.x25519 github.com/cloudflare/circl/dh/x25519.KeyGen
	cx25519.Shared(out, sk, pk) // want: go.asym.x25519 github.com/cloudflare/circl/dh/x25519.Shared
	x448.KeyGen(out, sk) // want: go.asym.x448 github.com/cloudflare/circl/dh/x448.KeyGen
	x448.Shared(out, sk, pk) // want: go.asym.x448 github.com/cloudflare/circl/dh/x448.Shared
	var k x448.Key // a type, not a call anchor: nothing
	_ = mldsa44.SeedSize // a size constant: nothing
	_ = k
}

func noiseUses() {
	noise.NewCipherSuite(
		noise.DH25519, // want: go.asym.x25519 github.com/flynn/noise.DH25519
		noise.CipherChaChaPoly, // want: go.sym.chacha20poly1305 github.com/flynn/noise.CipherChaChaPoly
		noise.HashBLAKE2s) // want: go.hash.blake2 github.com/flynn/noise.HashBLAKE2s
	_ = noise.CipherAESGCM // want: go.sym.aes.gcm github.com/flynn/noise.CipherAESGCM
	_ = noise.HashSHA256 // want: go.hash.sha2 github.com/flynn/noise.HashSHA256
	_ = noise.HashSHA512 // want: go.hash.sha2 github.com/flynn/noise.HashSHA512
	_ = noise.HashBLAKE2b // want: go.hash.blake2 github.com/flynn/noise.HashBLAKE2b
	_ = noise.HandshakeXX // names no algorithm: nothing
}

func miscUses(r interface{}) {
	v1.SHA256(r) // want: go.hash.sha2 github.com/google/go-containerregistry/pkg/v1.SHA256
	pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil) // want: go.asym.ecdsa github.com/miekg/pkcs11.CKM_ECDSA
	_ = pkcs11.CKM_ECDSA_SHA256 // want: go.asym.ecdsa github.com/miekg/pkcs11.CKM_ECDSA_SHA256
	_ = pkcs11.CKM_EC_KEY_PAIR_GEN // not listed (DECISIONS T11): nothing
	_ = azkeys.EncryptionAlgorithmRSA15 // want: go.asym.rsa.pkcs1v15.encrypt github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys.EncryptionAlgorithmRSA15
	_ = azkeys.EncryptionAlgorithmRSAOAEP // want: go.asym.rsa.oaep github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys.EncryptionAlgorithmRSAOAEP
	_ = azkeys.EncryptionAlgorithmRSAOAEP256 // want: go.asym.rsa.oaep github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys.EncryptionAlgorithmRSAOAEP256
	_ = azkeys.SignatureAlgorithmRS256 // want: go.asym.rsa.pkcs1v15.sign github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys.SignatureAlgorithmRS256
	_ = azkeys.SignatureAlgorithmPS384 // want: go.asym.rsa.pss github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys.SignatureAlgorithmPS384
	_ = azkeys.KeyTypeRSA // want: go.asym.rsa github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys.KeyTypeRSA
	_ = azkeys.SignatureAlgorithmES256 // not listed: nothing
	switch r {
	case azkeys.KeyTypeRSAHSM: // a switch case is a test position (G6): nothing
	}
}
