// Constant resolution (SPEC 17.6): consts, variables assigned once, reassigned variables,
// parameters, multi-assignment, concatenation, function scopes; parameters (SPEC 17.9).
package consts

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/ecdsa"
)

const keyBits = 4096

const (
	small, large = 2048, 8192
	sep          = "-"
)

var once = 3072

var twice = 1024

func init() { twice = 2048 }

func keys(param int) {
	rsa.GenerateKey(nil, keyBits)       // want: go.asym.rsa crypto/rsa.GenerateKey 4096
	rsa.GenerateKey(nil, large)         // want: go.asym.rsa crypto/rsa.GenerateKey 8192
	rsa.GenerateKey(nil, once)          // want: go.asym.rsa crypto/rsa.GenerateKey 3072
	rsa.GenerateKey(nil, twice)         // reassigned with another value: no param; want: go.asym.rsa crypto/rsa.GenerateKey
	rsa.GenerateKey(nil, param)         // a parameter: want: go.asym.rsa crypto/rsa.GenerateKey
	local := 1_536
	rsa.GenerateKey(nil, local)         // want: go.asym.rsa crypto/rsa.GenerateKey 1536
	hex := 0x800
	rsa.GenerateKey(nil, hex)           // hexadecimal is not resolved; want: go.asym.rsa crypto/rsa.GenerateKey
	a, b := 2048, small
	rsa.GenerateKey(nil, b)             // want: go.asym.rsa crypto/rsa.GenerateKey 2048
	_ = a
	n := 512
	n++
	rsa.GenerateKey(nil, n)             // incremented: want: go.asym.rsa crypto/rsa.GenerateKey
	rsa.GenerateKey(nil, (keyBits))     // want: go.asym.rsa crypto/rsa.GenerateKey 4096
	f := func() {
		inner := 2048
		rsa.GenerateKey(rand.Reader, inner) // want: go.asym.rsa crypto/rsa.GenerateKey 2048 | go.rand.prng.secure crypto/rand.Reader
	}
	f()
	curve := elliptic.P521()            // want: go.asym.ec crypto/elliptic.P521 P-521
	ecdsa.GenerateKey(curve, nil)       // the curve through a variable: want: go.asym.ecdsa crypto/ecdsa.GenerateKey P-521
	ecdsa.GenerateKey(elliptic.P224(), nil) // want: go.asym.ecdsa crypto/ecdsa.GenerateKey P-224
	c := elliptic.P256                  // want: go.asym.ec crypto/elliptic.P256 P-256
	ecdsa.GenerateKey(c(), nil)         // a call of a variable has no name: want: go.asym.ecdsa crypto/ecdsa.GenerateKey
	_ = c                               // (the line of c := ... has its own finding below)
}

var curveFn = elliptic.P384 // want: go.asym.ec crypto/elliptic.P384 P-384
