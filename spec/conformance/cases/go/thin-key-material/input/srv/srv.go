package srv

import (
	"crypto/sha256"
	"crypto/x509"

	"golang.org/x/crypto/ssh"
)

type Server struct{ config *ssh.ServerConfig }

func (s *Server) SetHostKey(b []byte) error {
	private, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return err
	}
	s.config.AddHostKey(private)
	return nil
}

func LoadOnly(b []byte) (ssh.Signer, error) {
	return ssh.ParsePrivateKey(b)
}

func KeyID(der []byte) []byte {
	pub, _ := x509.ParsePKIXPublicKey(der)
	b, _ := x509.MarshalPKIXPublicKey(pub)
	h := sha256.Sum256(b)
	return h[:]
}
