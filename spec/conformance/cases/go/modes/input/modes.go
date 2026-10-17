// Block-cipher modes (SPEC 17.7, 17.8): the AES-specific rule when the block comes from
// aes.NewCipher (through variables, also flow-insensitively), the mode fallback otherwise.
package modes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"

	"golang.org/x/crypto/xts"
)

func must(b cipher.Block, err error) cipher.Block { return b }

func gcm(key []byte) {
	block, err := aes.NewCipher(key) // want: go.sym.aes crypto/aes.NewCipher
	_ = err
	aead, _ := cipher.NewGCM(block)  // want: go.sym.aes.gcm crypto/cipher.NewGCM
	_ = aead
	b2 := block
	cipher.NewCTR(b2, nil)           // an alias of the variable: want: go.sym.aes.ctr crypto/cipher.NewCTR
	cipher.NewCBCEncrypter(must(aes.NewCipher(key)), nil) // inline: want: go.sym.aes.cbc crypto/cipher.NewCBCEncrypter
}

func given(b cipher.Block, iv []byte) {
	cipher.NewCBCDecrypter(b, iv)    // a parameter: want: go.sym.mode.cbc crypto/cipher.NewCBCDecrypter
	cipher.NewGCMWithTagSize(b, 12)  // want: go.sym.mode.gcm crypto/cipher.NewGCMWithTagSize
	cipher.NewCFBEncrypter(b, iv)    // want: go.sym.mode.cfb crypto/cipher.NewCFBEncrypter
}

func legacy(key []byte, des3 bool) {
	var block cipher.Block
	if des3 {
		block, _ = des.NewTripleDESCipher(key) // want: go.sym.3des crypto/des.NewTripleDESCipher
	} else {
		block, _ = aes.NewCipher(key)          // want: go.sym.aes crypto/aes.NewCipher
	}
	cipher.NewOFB(block, nil) // flow-insensitive: AES is one of the blocks; want: go.sym.aes.ofb crypto/cipher.NewOFB
	d, _ := des.NewCipher(key) // want: go.sym.des crypto/des.NewCipher
	cipher.NewCBCEncrypter(d, nil) // DES-CBC: the mode fallback; want: go.sym.mode.cbc crypto/cipher.NewCBCEncrypter
}

func disk(key []byte) {
	xts.NewCipher(aes.NewCipher, key) // want: go.sym.aes.xts golang.org/x/crypto/xts.NewCipher
	xts.NewCipher(nil, key)           // want: go.sym.mode.xts golang.org/x/crypto/xts.NewCipher
}
