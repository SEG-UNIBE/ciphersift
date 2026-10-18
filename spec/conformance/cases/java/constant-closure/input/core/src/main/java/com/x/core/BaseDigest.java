package com.x.core;

import javax.crypto.Mac;

/** A base class in another module (source root) than its subclasses (t3 J-XMOD, J-INH). */
public abstract class BaseDigest implements Names {
    public static final String HMAC_SHA_256 = "HmacSHA256";
    public static final String HMAC_SHA_512 = "HmacSHA512";

    protected BaseDigest(String secret, String alg) throws Exception {
        Mac.getInstance(alg); // want: java.jca.mac.unresolved Mac.getInstance
    }
}
