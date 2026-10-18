package f

import (
	"crypto/ecdh"
	"crypto/rand"
)

func keys(c ecdh.Curve, b []byte) {
	ecdh.X25519().GenerateKey(rand.Reader)
	ecdh.X25519().NewPrivateKey(b)
	c.GenerateKey(rand.Reader)
	k := ecdh.P256()
	k.GenerateKey(rand.Reader)
}
