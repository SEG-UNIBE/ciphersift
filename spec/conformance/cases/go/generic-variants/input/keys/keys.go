package keys

import "crypto/ecdh"

func Curve(n int) ecdh.Curve {
	switch n {
	case 384:
		return ecdh.P384()
	default:
		return ecdh.P256()
	}
}

func Fixed() ecdh.Curve {
	return ecdh.P256()
}
