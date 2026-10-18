package eth

import (
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func sign(msg []byte, hexkey string) ([]byte, error) {
	key, err := ethcrypto.HexToECDSA(hexkey)
	if err != nil {
		return nil, err
	}
	h := ethcrypto.Keccak256(msg)
	sig, err := ethcrypto.Sign(h, key)
	pub, _ := ethcrypto.SigToPub(h, sig)
	_ = ethcrypto.FromECDSAPub(pub)
	_ = ethcrypto.VerifySignature(ethcrypto.CompressPubkey(pub), h, sig[:64])
	_ = ethcrypto.PubkeyToAddress(*pub)
	_ = ethcrypto.SignatureLength
	return sig, err
}

func store(dir string, a accounts.Account, h []byte) {
	ks := keystore.NewKeyStore(dir, keystore.StandardScryptN, keystore.StandardScryptP)
	ks.SignHash(a, h)
	ks.Accounts()
	priv, _ := ethcrypto.GenerateKey()
	_ = ethcrypto.FromECDSA(priv)
}
