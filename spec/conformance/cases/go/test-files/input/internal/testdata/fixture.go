package fixture

import "crypto/rc4"

func F(k []byte) { rc4.NewCipher(k) } // want: go.sym.rc4 crypto/rc4.NewCipher
