// References (SPEC 17.3, 17.5): function values, crypto.Hash constants, TLS constants; no finding
// in comparisons, switch cases and map keys (test positions).
package refs

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"

	"golang.org/x/crypto/pbkdf2"
)

var hashes = map[string]crypto.Hash{
	"sha256": crypto.SHA256,                // want: go.hash.sha2 crypto.SHA256
}

var names = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",            // a map key: no finding
}

func refs(pw, salt []byte, v uint16) {
	hmac.New(sha256.New, pw)                // want: go.mac.hmac crypto/hmac.New | go.hash.sha2 crypto/sha256.New
	pbkdf2.Key(pw, salt, 4096, 32, sha1.New) // want: go.kdf.pbkdf2 golang.org/x/crypto/pbkdf2.Key | go.hash.sha1 crypto/sha1.New
	h := crypto.SHA1.New()                  // want: go.hash.sha1 crypto.SHA1
	_ = h
	if v == tls.VersionTLS11 {              // a comparison: no finding
	}
	if tls.VersionTLS12 <= (v) {            // no finding
	}
	switch v {
	case tls.VersionSSL30, tls.VersionTLS13: // switch cases: no finding
	}
	min := tls.VersionTLS12                 // want: go.prot.tls.v1_2 -
	_ = min
	r := rand.Reader                        // want: go.rand.prng.secure crypto/rand.Reader
	_ = r
	suites := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,          // want: go.prot.tls.rc4 - | go.prot.tls.context -
		tls.TLS_AES_128_GCM_SHA256,            // want: go.prot.tls.context -
	}
	_ = suites
	groups := []tls.CurveID{tls.X25519MLKEM768, tls.CurveP384, tls.X25519} // want: go.pqc.mlkem crypto/tls.X25519MLKEM768 ML-KEM-768 | go.asym.ecdh crypto/tls.CurveP384 P-384 | go.asym.x25519 crypto/tls.X25519
	_ = groups
	_ = tls.VersionName(v)                  // no finding
}
