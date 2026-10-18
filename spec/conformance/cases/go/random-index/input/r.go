package r

import (
	"crypto/rand"
	"math/big"
)

func pick(servers []string, limit *big.Int) {
	rand.Int(rand.Reader, big.NewInt(int64(len(servers))))
	rand.Int(rand.Reader, big.NewInt(len(servers)))
	rand.Int(rand.Reader, limit)
	rand.Int(rand.Reader, big.NewInt(1<<62))
	rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
