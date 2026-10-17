//go:build !amd64

package crypto

import "crypto/md5"

func md5sum(b []byte) [16]byte {
	return md5.Sum(b) // want: go.hash.md5 crypto/md5.Sum
}

func useSum(b []byte) [16]byte {
	return md5sum(b) // want: go.hash.md5 crypto/md5.Sum via=g4 origin=og4
}
