package svc

import (
	"crypto/tls"
	"crypto/x509"
)

// V2 aliases (DECISIONS B-A2): tls, cert, privkey name the TLS context, x509 and private-key keys.
func newTLSConfig() *tls.Config { // @g1=svc.newTLSConfig
	return &tls.Config{} // @og1 want: go.prot.tls.context -
}

func parseCert(der []byte) (*x509.Certificate, error) { // @g2=svc.parseCert
	return x509.ParseCertificate(der) // @og2 want: go.cert.x509 crypto/x509.ParseCertificate
}

func loadPrivKey(der []byte) (any, error) { // @g3=svc.loadPrivKey
	return x509.ParsePKCS8PrivateKey(der) // @og3 want: go.key.load.private -
}

func use(b []byte) {
	newTLSConfig() // want: go.prot.tls.context - via=g1 origin=og1
	parseCert(b)   // want: go.cert.x509 crypto/x509.ParseCertificate via=g2 origin=og2
	loadPrivKey(b) // want: go.key.load.private - via=g3 origin=og3
}
