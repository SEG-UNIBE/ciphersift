package com.x.ex;

import com.x.core.Algs;
import com.x.core.BaseDigest;
import com.x.dup.Twice;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Constants of other modules and inherited constants (t3 J-XMOD, J-INH); super(…) / this(…) calls (J-SUPER). */
public class ExDigest extends BaseDigest {
    public ExDigest(String secret) throws Exception {
        super(secret, HMAC_SHA_256); // want: java.mac.hmac HmacSHA256
    }

    public ExDigest(String secret, int n) throws Exception {
        this(secret, n, HMAC_SHA_512); // want: java.mac.hmac HmacSHA512
    }

    public ExDigest(String secret, int n, String alg) throws Exception {
        super(secret, alg); // a parameter: nothing
    }

    public ExDigest() throws Exception {
        super("nothing", "not an algorithm"); // nothing
    }

    void use(String secret) throws Exception {
        Mac.getInstance(HMAC_SHA_256); // want: java.mac.hmac HmacSHA256 (inherited from a class of another module)
        MessageDigest.getInstance(DIGEST); // want: java.hash.sha2 SHA-512 (interface of the superclass)
        Signature.getInstance(Algs.SIG); // want: java.asym.ecdsa SHA256withECDSA (imported class of another module)
        Mac.getInstance(ExDigest.HMAC_SHA_512); // want: java.mac.hmac HmacSHA512 (C.F declared in a supertype of C)
        MessageDigest.getInstance(Twice.ALG); // two files com/x/dup/Twice.java: want: java.jca.messagedigest.unresolved MessageDigest.getInstance
        new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256"); // want: java.mac.hmac HmacSHA256 (a charset argument is no constant key, J-GB)
        new SecretKeySpec("0123456789abcdef".getBytes("UTF-8"), "HmacSHA256"); // want: java.mac.hmac HmacSHA256 | java.key.hardcoded
    }

    void shadow(String DIGEST) throws Exception {
        MessageDigest.getInstance(DIGEST); // a parameter shadows the inherited constant: want: java.jca.messagedigest.unresolved MessageDigest.getInstance
    }
}
