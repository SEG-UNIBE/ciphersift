package svc

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
)

// V2 aliases (DECISIONS B-A2): tls, cert, privkey name the TLS context, x509 and private-key keys.
// Each body has a second family, so none is a thin wrapper (W6): the names decide.
func newTLSConfig(b []byte) *tls.Config { // @g1=svc.newTLSConfig
	_ = sha256.Sum256(b)  // want: go.hash.sha2 crypto/sha256.Sum256
	return &tls.Config{} // @og1 want: go.prot.tls.context -
}

func parseCert(der []byte) (*x509.Certificate, error) { // @g2=svc.parseCert
	_ = sha256.Sum256(der)           // want: go.hash.sha2 crypto/sha256.Sum256
	return x509.ParseCertificate(der) // @og2 want: go.cert.x509 crypto/x509.ParseCertificate
}

func loadPrivKey(der []byte) (any, error) { // @g3=svc.loadPrivKey
	_ = sha256.Sum256(der)                // want: go.hash.sha2 crypto/sha256.Sum256
	return x509.ParsePKCS8PrivateKey(der) // @og3 want: go.key.load.private -
}

// The name names the TLS context, the body has none: nothing is carried.
func sslFingerprint(b []byte) [32]byte {
	_ = md5.Sum(b)          // want: go.hash.md5 crypto/md5.Sum
	return sha256.Sum256(b) // want: go.hash.sha2 crypto/sha256.Sum256
}

func use(b []byte) {
	newTLSConfig(b)   // want: go.prot.tls.context - via=g1 origin=og1
	parseCert(b)      // want: go.cert.x509 crypto/x509.ParseCertificate via=g2 origin=og2
	loadPrivKey(b)    // want: go.key.load.private - via=g3 origin=og3
	sslFingerprint(b) // a name match without body evidence: nothing
}
