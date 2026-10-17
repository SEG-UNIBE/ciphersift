package pkg

import "crypto/sha1"

// The test-file rule is case-sensitive: not a test file.
func Contest() { sha1.Sum(nil) } // want: go.hash.sha1 crypto/sha1.Sum
