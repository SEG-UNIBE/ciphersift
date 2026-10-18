package m

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rsa"
	"crypto/x509"

	"golang.org/x/crypto/ssh"
)

// Methods of standard-library types on receivers of a known type (SPEC 17.12, DECISIONS B-G-B1a).

func params(k *rsa.PrivateKey, d []byte) {
	k.Sign(nil, d, nil) // want: go.asym.rsa crypto/rsa.PrivateKey.Sign
	k.Size()            // an accessor: nothing
}

func results(d []byte) {
	priv, err := rsa.GenerateKey(nil, 2048) // want: go.asym.rsa crypto/rsa.GenerateKey 2048
	_ = err
	priv.Precompute()                      // want: go.asym.rsa crypto/rsa.PrivateKey.Precompute
	pub, sk, _ := ed25519.GenerateKey(nil) // want: go.asym.ed25519 crypto/ed25519.GenerateKey
	sk.Public()                            // want: go.asym.ed25519 crypto/ed25519.PrivateKey.Public
	pub.Equal(nil)                         // PublicKey methods are not anchors: nothing
}

func assertions(key crypto.PrivateKey) {
	key.(*ecdsa.PrivateKey).Public() // want: go.asym.ecdsa crypto/ecdsa.PrivateKey.Public
	switch k := key.(type) {
	case *rsa.PrivateKey:
		k.Validate() // want: go.asym.rsa crypto/rsa.PrivateKey.Validate
	case ed25519.PrivateKey, *ecdsa.PrivateKey:
		k.Public() // two types in the case: not typed
	}
}

type signer struct {
	key   ed25519.PrivateKey
	curve elliptic.Curve
}

type wrapped struct {
	*rsa.PrivateKey
	name string
}

type own struct {
	*rsa.PrivateKey
}

func (o *own) Decrypt() {}

func fields(s *signer, w wrapped, o own, d []byte) {
	s.key.Sign(nil, d, nil)   // want: go.asym.ed25519 crypto/ed25519.PrivateKey.Sign
	s.curve.ScalarBaseMult(d) // want: go.asym.ec crypto/elliptic.Curve.ScalarBaseMult
	w.Decrypt(nil, d, nil)    // want: go.asym.rsa crypto/rsa.PrivateKey.Decrypt
	o.Decrypt()               // own.Decrypt is declared in this file: nothing
}

func values(d []byte) {
	c := ecdh.P256()                // want: go.asym.ecdh crypto/ecdh.P256 P-256
	k, _ := c.GenerateKey(nil)      // want: go.key.load.private crypto/ecdh.Curve.GenerateKey
	k.PublicKey()                   // want: go.key.load.public crypto/ecdh.PrivateKey.PublicKey
	k.ECDH(nil)                     // want: go.asym.ecdh crypto/ecdh.PrivateKey.ECDH
	pool := x509.NewCertPool()      // want: go.cert.x509 crypto/x509.NewCertPool
	pool.AppendCertsFromPEM(d)      // want: go.cert.x509 crypto/x509.CertPool.AppendCertsFromPEM
	dk, _ := mlkem.GenerateKey768() // want: go.pqc.mlkem crypto/mlkem.GenerateKey768 ML-KEM-768
	ek := dk.EncapsulationKey()     // want: go.pqc.mlkem crypto/mlkem.DecapsulationKey768.EncapsulationKey ML-KEM-768
	ek.Encapsulate()                // want: go.pqc.mlkem crypto/mlkem.EncapsulationKey768.Encapsulate ML-KEM-768
	rk := &rsa.PrivateKey{}         // want: go.asym.rsa crypto/rsa.PrivateKey
	rk.Public()                     // want: go.asym.rsa crypto/rsa.PrivateKey.Public
	var cv elliptic.Curve = elliptic.P384() // want: go.asym.ec crypto/elliptic.P384 P-384
	cv.IsOnCurve(nil, nil)          // want: go.asym.ec crypto/elliptic.Curve.IsOnCurve
	cv.Params()                     // an accessor: nothing
	z := new(rsa.PrivateKey)        // want: go.asym.rsa crypto/rsa.PrivateKey
	z = nil
	z.Public() // assigned another value as well: not typed
}

func sshKeys(b []byte) {
	signer, _ := ssh.ParsePrivateKey(b) // want: go.key.load.private -
	signer.Sign(nil, b)                 // want: go.prot.ssh -
}
