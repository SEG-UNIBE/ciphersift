package k

import (
	"crypto/rand"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/libp2p/go-libp2p/core/crypto"
)

func sign(b, h []byte) {
	priv, pub := btcec.PrivKeyFromBytes(b)
	_ = ecdsa.Sign(priv, h)
	_, _ = ecdsa.ParseDERSignature(b)
	_ = btcec.GenerateSharedSecret(priv, pub)
	_ = btcec.IsCompressedPubKey(b)
}

func p2p(b []byte) {
	_, _ = crypto.UnmarshalPrivateKey(b)
	_, _ = crypto.UnmarshalSecp256k1PrivateKey(b)
	_, _, _ = crypto.GenerateKeyPairWithReader(crypto.Ed25519, 0, rand.Reader)
	_, _, _ = crypto.GenerateRSAKeyPair(2048, rand.Reader)
	_ = crypto.ConfigEncodeKey(b)
}
