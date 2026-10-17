// crypto/mldsa (Go 1.27) and the crypto/tls ML-DSA signature schemes, DECISIONS F6.
package mldsause

import (
	"crypto/mldsa"
	"crypto/tls"
)

var GenerateKey = mldsa.GenerateKey                 // want: go.pqc.mldsa crypto/mldsa.GenerateKey

func sign(msg []byte) error {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())   // want: go.pqc.mldsa crypto/mldsa.GenerateKey ML-DSA-65
	if err != nil {
		return err
	}
	params := mldsa.MLDSA87()                       // want: go.pqc.mldsa crypto/mldsa.MLDSA87 ML-DSA-87
	pk, _ := mldsa.NewPublicKey(params, nil)        // want: go.pqc.mldsa crypto/mldsa.NewPublicKey ML-DSA-87
	sig, _ := sk.Sign(nil, msg, &mldsa.Options{})   // a method on a value: no anchor
	return mldsa.Verify(pk, msg, sig, nil)          // want: go.pqc.mldsa crypto/mldsa.Verify
}

var schemes = []tls.SignatureScheme{tls.MLDSA44, tls.Ed25519} // want: go.pqc.mldsa crypto/tls.MLDSA44 ML-DSA-44
