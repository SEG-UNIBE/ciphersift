package main

import (
	"github.com/lib/hashutil"

	c "example.com/app/crypto"
)

// Service has a field of a project type (one field hop, 18.4).
type Service struct {
	signer *c.Signer
}

func (sv *Service) Do(h []byte) {
	sv.signer.SignECDSA(h) // want: go.asym.ecdsa crypto/ecdsa.SignASN1 via=g2 origin=og2
}

func main() {
	b := []byte("x")
	_ = c.SHA256(b) // want: go.hash.sha2 crypto/sha256.Sum256 via=g1 origin=og1
	s := &c.Signer{}
	s.SignECDSA(b) // want: go.asym.ecdsa crypto/ecdsa.SignASN1 via=g2 origin=og2
	var s2 c.Signer
	s2.SignECDSA(b) // want: go.asym.ecdsa crypto/ecdsa.SignASN1 via=g2 origin=og2
	x := c.New()
	x.SignECDSA(b) // the type of x is not declared: not resolved
	_ = hashutil.Blake2b(b) // want: go.hash.blake2 golang.org/x/crypto/blake2b.Sum512 via=g6 origin=og6
}
