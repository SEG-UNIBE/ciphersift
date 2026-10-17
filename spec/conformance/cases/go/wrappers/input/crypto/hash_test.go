package crypto

import "crypto/sha1"

// sha1Hex is defined in a test file: it serves test call sites only.
func sha1Hex(b []byte) [20]byte { // @g5=crypto.sha1Hex
	return sha1.Sum(b) // @og5 want: go.hash.sha1 crypto/sha1.Sum
}

func useInTest(b []byte) {
	_ = SHA256(b) // want: go.hash.sha2 crypto/sha256.Sum256 via=g1 origin=og1
	_ = sha1Hex(b) // want: go.hash.sha1 crypto/sha1.Sum via=g5 origin=og5
}
