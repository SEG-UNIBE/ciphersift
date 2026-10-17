package hashutil

import "golang.org/x/crypto/blake2b"

// Blake2b is vendored code: a definition like any other (18.7).
func Blake2b(b []byte) [64]byte { // @g6=hashutil.Blake2b
	return blake2b.Sum512(b) // @og6 want: go.hash.blake2 golang.org/x/crypto/blake2b.Sum512
}
