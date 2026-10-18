package c

import (
	"crypto/ecdh"
	"crypto/elliptic"

	"filippo.io/hpke"
)

func hybrid(k hpke.KEM) bool {
	return k.ID() == hpke.MLKEM768P256().ID()
}

func name(c elliptic.Curve) string {
	if c.Params().Name == elliptic.P384().Params().Name {
		return "p384"
	}
	switch c {
	case elliptic.P256():
		return "p256"
	}
	return ""
}

func gen() {
	ecdh.X25519().GenerateKey(nil)
	_ = hpke.MLKEM768P256().ID()
}
