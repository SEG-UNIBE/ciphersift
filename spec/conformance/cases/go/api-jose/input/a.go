package a

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

var algs = []jose.SignatureAlgorithm{jose.RS256, jose.ES384}

func f(alg jose.SignatureAlgorithm, k []byte) {
	if alg == jose.HS256 {
		return
	}
	switch alg {
	case jose.PS256:
		return
	}
	_ = jose.Recipient{Algorithm: jose.ECDH_ES_A256KW}
	_ = jose.A128GCM
	_ = jose.PBES2_HS256_A128KW
	_ = jose.DEFLATE
	_ = jose.DIRECT
	jwt.NewWithClaims(jwt.SigningMethodHS512, nil)
	jwt.ParseRSAPublicKeyFromPEM(k)
	jwt.ParseEdPrivateKeyFromPEM(k)
	_ = jwt.SigningMethodNone
}
