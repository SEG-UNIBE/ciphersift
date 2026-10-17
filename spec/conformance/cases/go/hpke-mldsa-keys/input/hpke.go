// HPKE identifiers (crypto/hpke, Go 1.26, and filippo.io/hpke), DECISIONS F5: KEMs, KDFs and AEADs are
// reported where they are chosen; the operations take them as arguments and are not anchors themselves.
package hpkeuse

import (
	"crypto/ecdh"
	"crypto/hpke"

	fhpke "filippo.io/hpke"
)

func seal(pk hpke.PublicKey, msg []byte) ([]byte, error) {
	kdf := hpke.HKDFSHA256()                        // want: go.kdf.hkdf crypto/hpke.HKDFSHA256 | go.hash.sha2 crypto/hpke.HKDFSHA256
	return hpke.Seal(pk, kdf, hpke.AES256GCM(), nil, msg) // want: go.sym.aes.gcm crypto/hpke.AES256GCM
}

func kems() {
	_ = hpke.DHKEM(ecdh.P256())                     // want: go.asym.ecdh crypto/hpke.DHKEM P-256
	curve := ecdh.X25519()                          // want: go.asym.x25519 crypto/ecdh.X25519
	_ = hpke.DHKEM(curve)                           // want: go.asym.x25519 crypto/hpke.DHKEM
	_ = hpke.MLKEM768X25519()                       // want: go.pqc.mlkem crypto/hpke.MLKEM768X25519 ML-KEM-768
	_ = hpke.MLKEM1024P384()                        // want: go.pqc.mlkem crypto/hpke.MLKEM1024P384 ML-KEM-1024
	_ = hpke.SHAKE256()                             // want: go.hash.sha3 crypto/hpke.SHAKE256
	_ = hpke.ExportOnly()                           // not an algorithm: no finding
	_, _ = hpke.NewKEM(0x0020)                      // dynamic identifier: no finding
}

func filippo(pk fhpke.PublicKey) {
	k, _ := fhpke.MLKEM768().GenerateKey()          // want: go.pqc.mlkem filippo.io/hpke.MLKEM768 ML-KEM-768
	_ = k
	_, _, _ = fhpke.NewSender(pk, fhpke.HKDFSHA384(), fhpke.ChaCha20Poly1305(), nil) // want: go.kdf.hkdf filippo.io/hpke.HKDFSHA384 | go.hash.sha2 filippo.io/hpke.HKDFSHA384 | go.sym.chacha20poly1305 filippo.io/hpke.ChaCha20Poly1305
}
