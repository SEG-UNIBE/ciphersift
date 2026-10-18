package main

import (
	"example.com/pn/aes"
	"example.com/pn/ecdsa"
	"example.com/pn/sha3"
)

func main() {
	c := aes.NewCipher() // want: go.sym.aes crypto/aes.NewCipher via=pkg:aes:aes origin=oa
	c.Encrypt(nil)       // the type of a result is not declared: nothing
	var d *aes.Cipher
	d.Encrypt(nil)       // want: go.sym.aes crypto/aes.NewCipher via=pkg:aes:aes origin=oa
	aes.EncodedLength(3) // an excluded member name: nothing
	ecdsa.Sign(nil)      // no EC finding in package ecdsa: nothing
	sha3.Hash(nil)       // its only SHA3 finding is in a test file: nothing
}
