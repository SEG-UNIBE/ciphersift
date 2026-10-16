package com.acme.conf;

public final class CryptoConfig {
    public static final String DIGEST = "SHA-384";
    public static final String CIPHER = "AES" + "/" + Inner.MODE + "/NoPadding";
    public static final String DELEGATED = Algorithms.HMAC;

    public static final class Inner {
        public static final String MODE = "CBC";
        public static final String KDF = "PBKDF2WithHmacSHA512";
    }

    private CryptoConfig() {}
}
