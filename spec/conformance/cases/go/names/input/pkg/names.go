// Import names (SPEC 17.4): aliases, default names with major-version suffixes, blank imports,
// receivers that are not imports, a local package that shadows nothing.
package pkg

import (
	cr "crypto/rand"
	h256 "crypto/sha256"
	"crypto/sha1"
	_ "crypto/sha512"
	mrand "math/rand"
	"math/rand/v2"

	"example.com/local/md5"
)

type hasher struct{}

func (hasher) New() {}

func names(b []byte) {
	h256.Sum256(b)            // want: go.hash.sha2 crypto/sha256.Sum256
	cr.Read(b)                // want: go.rand.prng.secure crypto/rand.Read
	sha1.Sum(b)               // want: go.hash.sha1 crypto/sha1.Sum
	md5.Sum(b)                // a different package named md5: no finding
	var sha256 hasher
	sha256.New()              // a variable, not the import (crypto/sha256 is imported as h256): no finding
	_ = mrand.Intn(10)        // want: go.rand.prng.insecure -
	_ = rand.IntN(10)         // want: go.rand.prng.insecure -
	sha512 := hasher{}
	sha512.New()              // blank import gives no name: no finding
	f := h256.New             // want: go.hash.sha2 crypto/sha256.New
	_ = f
	h := sha1.
		New()                 // want: go.hash.sha1 crypto/sha1.New
	_ = h
}
