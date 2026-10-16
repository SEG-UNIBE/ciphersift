package com.example.crypto;

import android.security.keystore.KeyProperties;
import io.jsonwebtoken.Jwts;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.spec.NamedParameterSpec;
import javax.crypto.Cipher;
import javax.net.ssl.X509TrustManager;
import okhttp3.TlsVersion;

interface AlgNames {
    String SIG = "SHA384withECDSA";
}

public class EdgeCases {
    private static String mutable = "MD5";
    static { mutable = "SHA-256"; }

    void run(boolean flag, byte[] x) throws Exception {
        Cipher a = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_GCM + "/" + KeyProperties.ENCRYPTION_PADDING_NONE); // L22 AES GCM
        java.security.Signature s = java.security.Signature.getInstance(AlgNames.SIG);     // L23 ECDSA (interface const)
        MessageDigest m1 = MessageDigest.getInstance(mutable);                              // L24 reassigned -> fallback
        MessageDigest m2 = MessageDigest.getInstance(flag ? "MD5" : "SHA-1");              // L25 ternary -> fallback
        {
            String inner = "MD5";
        }
        String inner = "SHA-512";
        byte[] h = MessageDigest.getInstance(inner).digest(x);                              // L30 SHA2 (block scoping)
        Cipher b = Cipher
            .getInstance("DESede");                                                        // 3DES ECB, reported at L31 (start line of the call node)
        Object ed = NamedParameterSpec.X25519;                                              // L33 ECDH
        Object tv = TlsVersion.TLS_1_1;                                                     // L34 TLS 1.1
        Object hs = Jwts.SIG.HS256;                                                         // L35 HMAC
        java.util.function.Function<String, Object> f = alg -> {
            try { return MessageDigest.getInstance(alg); } catch (Exception e) { return null; } // L37 lambda param -> fallback
        };
        a.init(Cipher.ENCRYPT_MODE, null);                                                  // nothing
        java.util.Map<String, String> map = new java.util.HashMap<>();                      // nothing
    }

    static class TrustEverything implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] c, String t) {}
        @Override
        public void checkServerTrusted(X509Certificate[] c, String t) {
            // intentionally empty
        }                                                  // validation disabled, reported at L46 (method name)
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static class Validating implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] c, String t) {}
        public void checkServerTrusted(X509Certificate[] c, String t) throws java.security.cert.CertificateException {
            if (c == null) throw new java.security.cert.CertificateException("x");         // not reported
        }
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
}
