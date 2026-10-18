module example.com/t2

go 1.24

require (
	golang.org/x/crypto v0.31.0
	filippo.io/age v1.2.1 // indirect
	github.com/cloudflare/circl v1.5.0 //indirect
	github.com/ProtonMail/go-crypto v1.1.0 // indirect; kept for the openpgp tests
	github.com/go-jose/go-jose/v4 v4.0.4 // indirectly needed, but not marked: reported
)

require filippo.io/edwards25519 v1.1.0 // indirect
