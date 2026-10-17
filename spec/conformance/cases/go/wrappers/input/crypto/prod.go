package crypto

func prod(b []byte) [20]byte {
	return sha1Hex(b) // sha1Hex is defined in a test file: not a candidate here
}

func shadow(b []byte) []byte {
	SHA256 := func(x []byte) []byte { return x }
	return SHA256(b) // a local variable: not resolved
}
