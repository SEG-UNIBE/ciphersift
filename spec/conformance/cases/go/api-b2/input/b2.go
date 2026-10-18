package b2

import (
	"crypto"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/go-piv/piv-go/v2/piv"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// Curated third-party APIs (SPEC 17.11, DECISIONS B-G-B2).

var allowed = []protocommon.PublicKeyDetails{
	protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,       // want: go.asym.ecdsa github.com/sigstore/protobuf-specs/gen/pb-go/common/v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256 P-256
	protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256, // want: go.asym.rsa.pkcs1v15.sign github.com/sigstore/protobuf-specs/gen/pb-go/common/v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256
	protocommon.PublicKeyDetails_PKIX_RSA_PSS_4096_SHA256,      // want: go.asym.rsa.pss github.com/sigstore/protobuf-specs/gen/pb-go/common/v1.PublicKeyDetails_PKIX_RSA_PSS_4096_SHA256
	protocommon.PublicKeyDetails_PKIX_ED25519_PH,               // want: go.asym.ed25519 github.com/sigstore/protobuf-specs/gen/pb-go/common/v1.PublicKeyDetails_PKIX_ED25519_PH
	protocommon.PublicKeyDetails_ML_DSA_65,                     // want: go.pqc.mldsa github.com/sigstore/protobuf-specs/gen/pb-go/common/v1.PublicKeyDetails_ML_DSA_65 ML-DSA-65
	protocommon.PublicKeyDetails_LMS_SHA256,                    // no rule for LMS: nothing
}

var hashes = []protocommon.HashAlgorithm{
	protocommon.HashAlgorithm_SHA2_384, // want: go.hash.sha2 github.com/sigstore/protobuf-specs/gen/pb-go/common/v1.HashAlgorithm_SHA2_384
	protocommon.HashAlgorithm_SHA3_256, // want: go.hash.sha3 github.com/sigstore/protobuf-specs/gen/pb-go/common/v1.HashAlgorithm_SHA3_256
}

func details() {
	ad, _ := signature.GetAlgorithmDetails(protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384) // want: go.asym.ecdsa github.com/sigstore/protobuf-specs/gen/pb-go/common/v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384 P-384
	ad.GetECDSACurve()                       // want: go.asym.ec github.com/sigstore/sigstore/pkg/signature.AlgorithmDetails.GetECDSACurve
	ad.GetRSAKeySize()                       // want: go.asym.rsa github.com/sigstore/sigstore/pkg/signature.AlgorithmDetails.GetRSAKeySize
	ad.GetHashType()                         // not an anchor: nothing
	_ = options.WithED25519ph()              // want: go.asym.ed25519 github.com/sigstore/sigstore/pkg/signature/options.WithED25519ph
	_ = crypto.SHA256                        // want: go.hash.sha2 crypto.SHA256
}

func pivKeys(dev, att []byte) {
	_ = piv.Key{Algorithm: piv.AlgorithmEC384} // want: go.asym.ec github.com/go-piv/piv-go/v2/piv.AlgorithmEC384 P-384
	_ = piv.AlgorithmRSA2048                   // want: go.asym.rsa github.com/go-piv/piv-go/v2/piv.AlgorithmRSA2048 2048
	_ = piv.AlgorithmEd25519                   // want: go.asym.ed25519 github.com/go-piv/piv-go/v2/piv.AlgorithmEd25519
	_ = piv.AlgorithmX25519                    // want: go.asym.x25519 github.com/go-piv/piv-go/v2/piv.AlgorithmX25519
	piv.Verify(nil, nil)                       // want: go.cert.x509 github.com/go-piv/piv-go/v2/piv.Verify
}

func slh() {
	slhdsa.GenerateKey(nil, slhdsa.SHAKE_128f) // want: go.pqc.slhdsa github.com/cloudflare/circl/sign/slhdsa.GenerateKey SLH-DSA-SHAKE-128f
	_ = slhdsa.SHA2_256s                       // want: go.pqc.slhdsa github.com/cloudflare/circl/sign/slhdsa.SHA2_256s SLH-DSA-SHA2-256s
}
