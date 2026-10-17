// Package crypto holds the project's wrappers (SPEC 18.5).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
)

// SHA256 is name-consistent (W7).
func SHA256(b []byte) []byte { // @g1=crypto.SHA256
	s := sha256.Sum256(b) // @og1 want: go.hash.sha2 crypto/sha256.Sum256
	return s[:]
}

// hashTwice calls the same-package wrapper twice on one line (one occurrence).
func hashTwice(b []byte) []byte {
	return SHA256(SHA256(b)) // want: go.hash.sha2 crypto/sha256.Sum256 via=g1 origin=og1
}

// Signer has a name-consistent method; its body's CSPRNG is not propagated.
type Signer struct {
	key *ecdsa.PrivateKey
}

func (s *Signer) SignECDSA(h []byte) ([]byte, error) { // @g2=crypto.Signer.SignECDSA
	return ecdsa.SignASN1(rand.Reader, s.key, h) // @og2 want: go.asym.ecdsa crypto/ecdsa.SignASN1 | go.rand.prng.secure crypto/rand.Reader
}

// New returns a Signer; values it returns are not typed (18.4).
func New() *Signer {
	return &Signer{}
}

// newBlock is a thin wrapper (W6), which is off for Go (DECISIONS T14): not a callable.
func newBlock(k []byte) (cipher.Block, error) {
	return aes.NewCipher(k) // want: go.sym.aes crypto/aes.NewCipher
}

func seal(k []byte) cipher.Block {
	b, _ := newBlock(k) // not reported: Go has no thin wrappers
	return b
}
