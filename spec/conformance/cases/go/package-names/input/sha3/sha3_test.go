package sha3

import "crypto/sha3"

// findings in test files are no evidence
func helper(b []byte) [32]byte { return sha3.Sum256(b) } // want: go.hash.sha3 crypto/sha3.Sum256
