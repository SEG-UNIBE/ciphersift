package l

import (
	"crypto/sha256"
	"fmt"
)

type Config struct{ Cipher, Alg string }

var algs = map[string]bool{"RS256": true}

func setParam(k, v string) {}

func f(alg string) {
	setParam("cipher", "AES-256-GCM")
	setParam("tls-cipher", "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384")
	_ = Config{Alg: "ES256"}
	_ = []string{"ssh-ed25519", "TLS_AES_128_GCM_SHA256"}
	if alg == "HS256" {
		return
	}
	switch alg {
	case "PS256":
	}
	_ = sha256.Sum256([]byte("RS512"))
	fmt.Println("AES-128-CBC")
	_ = "aes-256-gcm"
}
