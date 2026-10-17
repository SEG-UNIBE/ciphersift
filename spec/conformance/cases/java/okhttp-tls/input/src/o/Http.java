package o;

import okhttp3.CipherSuite;
import okhttp3.ConnectionSpec;
import okhttp3.TlsVersion;

class Http {
    // a chained call starts at the line of its receiver expression (SPEC 7.2)
    static final ConnectionSpec SPEC = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)   // 9: TLS (also cipherSuites/tlsVersions)
        .cipherSuites(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,                      // 10: TLS
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256)                                          // 11: TLS
        .tlsVersions(TlsVersion.TLS_1_2, TlsVersion.TLS_1_3)                                   // 12: TLS 1.2, TLS 1.3
        .build();
    static final ConnectionSpec OLD = new ConnectionSpec.Builder(ConnectionSpec.COMPATIBLE_TLS)  // 14: TLS, RC4 and NULL suites, TLS 1.0, TLS 1.1
        .cipherSuites("SSL_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_NULL_SHA256")                    // (reported at 14)
        .tlsVersions("TLSv1", "TLSv1.1")                                                        // (reported at 14)
        .build();
    Object spec() { return ConnectionSpec.CLEARTEXT; }                                         // 18: nothing
    static class Builder { }
    Object local() { return new Builder(); }                                                    // 20: nothing (a class of this file)
}
