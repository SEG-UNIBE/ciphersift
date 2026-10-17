package pkg

import "crypto/md5"

func Sum(b []byte) [16]byte { return md5.Sum(b) } // want: go.hash.md5 crypto/md5.Sum
