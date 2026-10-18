package cfg

import (
	"crypto/md5"
	"crypto/sha256"
	"hash"
)

// two families, one of them in a conditional return: the guard only removes evidence, so this is
// still a definition with two families and not a thin wrapper (SPEC 18.5)
func pick(legacy bool) hash.Hash {
	if legacy {
		return md5.New() // want: go.hash.md5 crypto/md5.New
	}
	return sha256.New() // want: go.hash.sha2 crypto/sha256.New
}

func md5Of() hash.Hash { // @p1=cfg.md5Of
	return md5.New() // @op1 want: go.hash.md5 crypto/md5.New
}

func sha256Of() hash.Hash { // @p2=cfg.sha256Of
	return sha256.New() // @op2 want: go.hash.sha2 crypto/sha256.New
}

// the same through calls: the guarded call carries another family, so not a thin wrapper either
func pickVia(legacy bool) hash.Hash {
	if legacy {
		return md5Of() // want: go.hash.md5 crypto/md5.New via=p1 origin=op1
	}
	return sha256Of() // want: go.hash.sha2 crypto/sha256.New via=p2 origin=op2
}

func usePick() {
	pick(false)    // two families: nothing
	pickVia(false) // two families below: nothing
}
