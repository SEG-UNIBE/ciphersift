package com.example.crypto;

import java.security.KeyStore;
import java.util.Random;
import java.util.SplittableRandom;
import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** Merged-tool fixture: JSSE key/trust managers (issue 3), non-crypto PRNGs (issue 4). */
public class TlsKeyManagement {
    SSLContext setup(KeyStore ks, char[] pw) throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");              // L16 TLS key management
        kmf.init(ks, pw);
        TrustManagerFactory tmf =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); // L19 TLS key management
        tmf.init(ks);
        SSLContext ctx = SSLContext.getInstance("TLS");                                // L21 tls context
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }

    int random() {
        int a = new Random(42).nextInt();                                              // L27 prng insecure
        int b = ThreadLocalRandom.current().nextInt(10);                               // L28 prng insecure
        long c = new SplittableRandom().nextLong();                                    // L29 prng insecure
        return a + b + (int) c;
    }

    void material() {
        SecretKeySpec k = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");    // L34 hardcoded key + AES
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);                        // L35 static IV
    }
}
