// Composite literals and field assignments (SPEC 17.5): TLS configurations, disabled certificate
// validation, x509 templates and keys, SSH.
package conf

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"golang.org/x/crypto/ssh"
)

const skip = true

func client(insecure bool) *http.Client {
	cfg := &tls.Config{                     // want: go.prot.tls.context -
		MinVersion:         tls.VersionTLS10, // want: go.prot.tls.v1_0 -
		InsecureSkipVerify: true,             // want: go.cert.validation.disabled -
	}
	other := tls.Config{InsecureSkipVerify: false} // want: go.prot.tls.context -
	_ = other
	third := tls.Config{InsecureSkipVerify: insecure} // not a constant: want: go.prot.tls.context -
	_ = third
	fourth := &tls.Config{InsecureSkipVerify: skip}  // want: go.prot.tls.context - | go.cert.validation.disabled -
	_ = fourth
	cfg.InsecureSkipVerify = true           // want: go.cert.validation.disabled -
	n := new(tls.Config)                    // want: go.prot.tls.context -
	n.MaxVersion = tls.VersionTLS13         // want: go.prot.tls.v1_3 -
	tr := &http.Transport{TLSClientConfig: cfg}
	return &http.Client{Transport: tr}
}

func pki(der []byte, pub *rsa.PublicKey, priv *rsa.PrivateKey) {
	tmpl := &x509.Certificate{SignatureAlgorithm: x509.SHA256WithRSA} // want: go.cert.x509 crypto/x509.Certificate | go.asym.rsa.pkcs1v15.sign crypto/x509.SHA256WithRSA
	x509.CreateCertificate(nil, tmpl, tmpl, pub, priv) // want: go.cert.x509 crypto/x509.CreateCertificate
	pool := x509.NewCertPool()              // want: go.cert.x509 crypto/x509.NewCertPool
	_ = pool
	x509.ParsePKCS1PrivateKey(der)          // want: go.key.load.private -
	tls.LoadX509KeyPair("c.pem", "k.pem")   // want: go.cert.x509 crypto/tls.LoadX509KeyPair
	_ = rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto} // want: go.asym.rsa.pss crypto/rsa.PSSOptions
}

func sshClient(signer ssh.Signer) {
	conf := &ssh.ClientConfig{               // want: go.prot.ssh -
		User:            "u",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)}, // want: go.prot.ssh -
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // want: go.prot.ssh.hostkey_verification.disabled -
	}
	ssh.Dial("tcp", "h:22", conf)           // want: go.prot.ssh -
	ssh.ParseAuthorizedKey(nil)             // want: go.key.load.public -
}
