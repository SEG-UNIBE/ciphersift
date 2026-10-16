package o;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

public class Trust {
    static class TrustAll extends X509ExtendedTrustManager {
        @Override public void checkClientTrusted(X509Certificate[] c, String a) {}
        @Override public void checkServerTrusted(X509Certificate[] c, String a) {}           // 15: validation disabled
        @Override public void checkServerTrusted(X509Certificate[] c, String a, Socket s) { /* nothing */ } // 16: validation disabled
        @Override public void checkServerTrusted(X509Certificate[] c, String a, SSLEngine e) {
            return;
        }                                                                                    // validation disabled, reported at line 17 (method name)
        @Override public void checkClientTrusted(X509Certificate[] c, String a, Socket s) {}
        @Override public void checkClientTrusted(X509Certificate[] c, String a, SSLEngine e) {}
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static class Pinning implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException {
            if (c.length == 0) { throw new CertificateException("empty"); }                  // not reported
        }
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }

    static class NotATrustManager {
        public void checkServerTrusted(X509Certificate[] c, String a) {}                      // not a TrustManager -> nothing
    }

    HostnameVerifier lax = new HostnameVerifier() {
        @Override
        public boolean verify(String host, SSLSession session) {                             // 39: hostname verification disabled
            return true;
        }
    };

    HostnameVerifier strict = new HostnameVerifier() {
        public boolean verify(String host, SSLSession session) {
            return "example.org".equals(host);                                               // not reported
        }
    };
}
