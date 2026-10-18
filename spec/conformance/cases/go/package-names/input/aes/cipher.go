package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

// Cipher is a project type in a package named after AES.
type Cipher struct{ k []byte }

// NewCipher is longer than a thin wrapper and its name names nothing: only the package name links it to AES.
func NewCipher() *Cipher {
	return &Cipher{}
}

func (c *Cipher) Encrypt(p []byte) []byte {
	b, _ := aes.NewCipher(c.k) // @oa want: go.sym.aes crypto/aes.NewCipher
	g, _ := cipher.NewGCM(b)   // want: go.sym.aes.gcm crypto/cipher.NewGCM
	n := 0
	n++
	n++
	n++
	n++
	n++
	n++
	n++
	n++
	return g.Seal(nil, nil, p, nil)
}

func EncodedLength(n int) int { return n + 16 }
