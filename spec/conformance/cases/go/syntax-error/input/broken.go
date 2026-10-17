package broken

import "crypto/sha256"

func before(b []byte) { sha256.Sum256(b) } // want: go.hash.sha2 crypto/sha256.Sum256

func broken( {
	x := := 3
}

func after(b []byte) { sha256.Sum224(b) } // want: go.hash.sha2 crypto/sha256.Sum224
