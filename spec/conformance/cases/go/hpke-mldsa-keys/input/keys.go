// Key construction (DECISIONS F4): key structs, curve parameters, key conversions, Go 1.25 raw
// encodings, Go 1.26 EncryptOAEPWithOptions.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
)

func build(n *big.Int, d []byte, seed []byte, raw []byte) {
	pub := &rsa.PublicKey{N: n, E: 65537}           // want: go.asym.rsa crypto/rsa.PublicKey
	priv := rsa.PrivateKey{                         // want: go.asym.rsa crypto/rsa.PrivateKey
		PublicKey: rsa.PublicKey{N: n, E: 3},       // nested, same family: folded
	}
	_ = new(rsa.PrivateKey)                         // want: go.asym.rsa crypto/rsa.PrivateKey
	_, _ = pub, priv
	ek := &ecdsa.PrivateKey{D: n}                   // want: go.asym.ecdsa crypto/ecdsa.PrivateKey
	_ = ek
	_, _ = ecdsa.ParseRawPrivateKey(elliptic.P384(), raw) // want: go.asym.ecdsa crypto/ecdsa.ParseRawPrivateKey P-384
	_, _ = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw) // want: go.asym.ecdsa crypto/ecdsa.ParseUncompressedPublicKey P-256
	params := &elliptic.CurveParams{Name: "brainpoolP256r1"} // want: go.asym.ec crypto/elliptic.CurveParams
	_ = params
	pk := ed25519.PublicKey(raw)                    // want: go.asym.ed25519 crypto/ed25519.PublicKey
	ok := ed25519.PublicKey(raw).Equal(ed25519.PrivateKey(seed).Public()) // want: go.asym.ed25519 crypto/ed25519.PublicKey | go.asym.ed25519 crypto/ed25519.PrivateKey
	_, _ = pk, ok
	_, _ = rsa.EncryptOAEPWithOptions(rand.Reader, pub, d, &rsa.OAEPOptions{Hash: crypto.SHA256}) // want: go.asym.rsa.oaep crypto/rsa.EncryptOAEPWithOptions | go.rand.prng.secure crypto/rand.Reader | go.hash.sha2 crypto.SHA256
}

func check(k crypto.PublicKey) bool {
	_, isRSA := k.(*rsa.PublicKey)                  // a type, not a construction: no finding
	return isRSA
}
