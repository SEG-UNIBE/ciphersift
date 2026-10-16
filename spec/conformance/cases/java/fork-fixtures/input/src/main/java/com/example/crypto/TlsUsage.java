package com.example.crypto;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.KeyStore;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.http.conn.ssl.NoopHostnameVerifier;

public class TlsUsage {
    private static final String PROTO = "TLSv1.2";

    void ctx(SSLSocket sock) throws Exception {
        SSLContext a = SSLContext.getInstance("TLS");                        // L19 tls context
        SSLContext b = SSLContext.getInstance(PROTO);                        // L20 TLS 1.2
        SSLContext c = SSLContext.getInstance("TLSv1");                      // L21 TLS 1.0
        SSLContext d = SSLContext.getInstance("SSLv3");                      // L22 SSL 3.0
        sock.setEnabledProtocols(new String[] {"TLSv1.1", "TLSv1.3"});      // L23 TLS 1.1 + 1.3
        System.setProperty("https.protocols", "TLSv1,TLSv1.2");              // L24 TLS 1.0 + 1.2
        sock.setEnabledCipherSuites(new String[] {"TLS_RSA_WITH_RC4_128_SHA"}); // L25 rc4 suite
        CertificateFactory cf = CertificateFactory.getInstance("X.509");     // L26 x509
        KeyStore ks = KeyStore.getInstance("PKCS12");                        // L27 keystore
    }

    TrustManager[] trustAll = new TrustManager[] {
        new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) { } // L33 validation disabled
            public X509Certificate[] getAcceptedIssuers() { return null; }
        }
    };

    static class AllowAll implements HostnameVerifier {
        @Override
        public boolean verify(String host, SSLSession s) {                    // L40 hostname verification disabled
            return true;
        }
    }

    void hv() {
        HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);       // L46 hostname verification disabled
        Object v = NoopHostnameVerifier.INSTANCE;                           // L47 hostname verification disabled
    }
}
