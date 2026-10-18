package r;

import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Constant getters (B-J-JP1), deferred locals (B-J-JP3), SecretKeySpec.getAlgorithm (B-J-JP5). */
class Res {
    String getJCAAlgorithm() {
        return "SHA256withRSAandMGF1";
    }

    String twice() {
        return "MD5";
    }

    String twice(int x) {
        return "SHA-1";
    }

    String withParam(String s) {
        return "SHA-1";
    }

    void getters() throws Exception {
        Signature.getInstance(getJCAAlgorithm()); // want: java.asym.rsa SHA256withRSAandMGF1
        MessageDigest.getInstance(twice()); // want: java.jca.messagedigest.unresolved MessageDigest.getInstance
        MessageDigest.getInstance(withParam("x")); // want: java.jca.messagedigest.unresolved MessageDigest.getInstance
    }

    void deferred(boolean c, String pki) throws Exception {
        final String one;
        if (c) {
            one = "SHA-256";
        } else {
            throw new IllegalStateException();
        }
        MessageDigest.getInstance(one); // want: java.hash.sha2 SHA-256
        String agree;
        if ("x509+sha256".equals(pki)) {
            agree = "SHA256withRSA";
        } else {
            agree = "SHA1withRSA";
        }
        Signature.getInstance(agree); // want: java.asym.rsa Signature.getInstance
        String differ;
        if (c) {
            differ = "SHA256withECDSA";
        } else {
            differ = "SHA256withRSA";
        }
        Signature.getInstance(differ); // want: java.jca.signature.unresolved Signature.getInstance
        String counted;
        counted = "MD5";
        counted += "x";
        MessageDigest.getInstance(counted); // want: java.jca.messagedigest.unresolved MessageDigest.getInstance
    }

    void keys(byte[] k) throws Exception {
        SecretKeySpec key = new SecretKeySpec(k, "HmacSHA512"); // want: java.mac.hmac HmacSHA512
        Mac.getInstance(key.getAlgorithm()); // want: java.mac.hmac HmacSHA512
    }

    void selfReference() throws Exception {
        String s;
        s = "SHA";
        s = s + "-256";
        MessageDigest.getInstance(s); // want: java.jca.messagedigest.unresolved MessageDigest.getInstance
        String a;
        String b;
        a = "MD5";
        b = a;
        a = b;
        MessageDigest.getInstance(a); // want: java.jca.messagedigest.unresolved MessageDigest.getInstance
    }
}
