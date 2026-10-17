module example.com/app

go 1.23

toolchain go1.23.2

require golang.org/x/crypto v0.31.0

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	"filippo.io/age" v1.2.1 // indirect
	github.com/stretchr/testify v1.9.0
	github.com/cloudflare/circl v1.5.0 // indirect
)

replace github.com/cloudflare/circl => ../circl

exclude (
	go.step.sm/crypto v0.1.0
)

retract v0.9.0
