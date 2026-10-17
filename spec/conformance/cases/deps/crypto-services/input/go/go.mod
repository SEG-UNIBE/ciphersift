module example.com/svc

go 1.26

require (
	cloud.google.com/go/kms v1.32.0
	cloud.google.com/go/storage v1.50.0
	filippo.io/hpke v0.4.0
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys v1.5.0
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets v1.3.0
	github.com/aws/aws-sdk-go-v2/service/kms v1.54.1
	github.com/aws/aws-sdk-go-v2/service/s3 v1.80.0
	github.com/flynn/noise v1.1.0
	github.com/go-piv/piv-go/v2 v2.4.0
	github.com/hashicorp/vault/api v1.23.0
	github.com/sigstore/rekor v1.5.3
	github.com/sigstore/sigstore-go v1.2.2
	github.com/sigstore/sigstore/pkg/signature/kms/aws v1.10.0
	github.com/sigstore/protobuf-specs v0.5.1
	github.com/sigstore/timestamp-authority/v2 v2.0.0
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
)
