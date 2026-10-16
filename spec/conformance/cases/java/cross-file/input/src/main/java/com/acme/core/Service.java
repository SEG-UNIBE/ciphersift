package com.acme.core;

import static com.acme.conf.Algorithms.SIGNATURE;
import static com.acme.conf.CryptoConfig.*;
import com.acme.conf.CryptoConfig;
import com.acme.conf.*;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;

public class Service {
    void run() throws Exception {
        MessageDigest.getInstance(CryptoConfig.DIGEST);                // 16: imported class constant -> SHA2
        Cipher.getInstance(CryptoConfig.CIPHER);                       // 17: constant built from a nested-class constant -> AES-CBC
        Signature.getInstance(SIGNATURE);                              // 18: static import -> ECDSA
        Mac.getInstance(DELEGATED);                                    // 19: static wildcard import, constant referencing another file -> HMAC
        SecretKeyFactory.getInstance(CryptoConfig.Inner.KDF);          // 20: nested class -> PBKDF2
        KeyPairGenerator.getInstance(Local.KEYPAIR);                   // 21: same package, not imported -> EC
        Mac.getInstance(Algorithms.HMAC);                              // 22: wildcard-imported package -> HMAC
        MessageDigest.getInstance(Missing.VALUE);                      // 23: class not in the tree -> fallback
    }
}
