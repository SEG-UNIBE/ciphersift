//go:build amd64

package crypto

import "crypto/md5"

// md5sum has a build-tag variant in sum_generic.go: one owner, one group (18.4).
func md5sum(b []byte) [16]byte { // @g4=crypto.md5sum
	return md5.Sum(b) // @og4 want: go.hash.md5 crypto/md5.Sum
}
