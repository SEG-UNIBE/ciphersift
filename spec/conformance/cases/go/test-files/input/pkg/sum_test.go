package pkg

import (
	"crypto/sha1"
	"testing"
)

func TestSum(t *testing.T) { sha1.Sum(nil) } // want: go.hash.sha1 crypto/sha1.Sum
