// Dot imports (SPEC 17.4): unqualified names of a dot-imported package, unless declared in the file.
package dot

import (
	. "crypto/md5"
	. "crypto/tls"
	. "crypto/rand"
)

func Sum(b []byte) {}

func dots(b []byte) {
	New()                        // want: go.hash.md5 crypto/md5.New
	Sum(b)                       // declared in this file: no finding
	_ = &Config{MinVersion: VersionTLS13} // want: go.prot.tls.context - | go.prot.tls.v1_3 -
	_ = Reader                   // want: go.rand.prng.secure crypto/rand.Reader
	var Read = func([]byte) {}
	Read(b)                      // declared in this file: no finding
}
