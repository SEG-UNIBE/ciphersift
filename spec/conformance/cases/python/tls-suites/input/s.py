# IANA TLS cipher suites as string literals (DECISIONS P3-SUITE)
SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",  # want: python.hash.sha2 TLS_AES_128_GCM_SHA256 | python.prot.tls.context | python.sym.aes TLS_AES_128_GCM_SHA256
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",  # want: python.hash.sha2 TLS_CHACHA20_POLY1305_SHA256 | python.mac.poly1305 TLS_CHACHA20_POLY1305_SHA256 | python.prot.tls.context | python.sym.chacha20 TLS_CHACHA20_POLY1305_SHA256
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",  # want: python.prot.tls.context
}
if name == "TLS_AES_256_GCM_SHA384":  # a comparison: nothing
    pass
KEY = "TLS_CA_FILE"  # not a suite: nothing
lower = "tls_aes_128_gcm_sha256"  # the registry spelling only: nothing
