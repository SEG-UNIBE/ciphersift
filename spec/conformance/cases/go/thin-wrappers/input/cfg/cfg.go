package cfg

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"hash"
)

// Go thin wrappers (SPEC 18.5, DECISIONS B-G-E): at most 12 lines, one family key, whatever the name.
func newBlock(k []byte) (cipher.Block, error) { // @g1=cfg.newBlock
	return aes.NewCipher(k) // @og1 want: go.sym.aes crypto/aes.NewCipher
}

// 12 lines, an early error return and a crypto call in the final return: a thin wrapper
func digestOf(b []byte) []byte { // @g2=cfg.digestOf
	if len(b) == 0 {
		return nil
	}
	h := sha256.New() // @og2 want: go.hash.sha2 crypto/sha256.New
	h.Write(b)
	n := 0
	n++
	n++
	n++
	return h.Sum(nil)
}

type Config struct {
	DefaultHash crypto.Hash
}

// a fallback getter: the only crypto value is a conditional default, another return gives the field
func (c *Config) Hash() crypto.Hash {
	if c.DefaultHash == 0 {
		return crypto.SHA256 // want: go.hash.sha2 crypto.SHA256
	}
	return c.DefaultHash
}

// 13 lines: not thin
func longHash() hash.Hash {
	n := 0
	n++
	n++
	n++
	n++
	n++
	n++
	n++
	n++
	n++
	return sha256.New() // want: go.hash.sha2 crypto/sha256.New
}

func use(c *Config, k []byte) {
	newBlock(k)  // want: go.sym.aes crypto/aes.NewCipher via=g1 origin=og1
	digestOf(k)  // want: go.hash.sha2 crypto/sha256.New via=g2 origin=og2
	_ = c.Hash() // a fallback getter: nothing
	longHash()   // not a callable
}
