package m

import (
	"crypto/rand"
	"crypto/x509"
	"io"
	"math/big"
)

func draw(n int64, buf []byte) {
	rand.Int(rand.Reader, big.NewInt(n))
	rand.Prime(rand.Reader, 64)
	io.ReadFull(rand.Reader, buf)
	rand.Read(buf)
	r := rand.Reader
	rand.Int(r,
		big.NewInt(n))
	rand.Int(
		rand.Reader, big.NewInt(n))
}

func verify(c *x509.Certificate) {
	c.Verify(x509.VerifyOptions{Roots: x509.NewCertPool()})
	c.Verify(x509.VerifyOptions{
		Roots: x509.NewCertPool(),
	})
}
