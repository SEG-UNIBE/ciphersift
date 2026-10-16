package org.acme.app;

import javax.crypto.*;
import java.security.MessageDigest;
import org.acme.own.Signature;
import static org.apache.commons.codec.digest.DigestUtils.md5Hex;
import static org.apache.commons.codec.digest.DigestUtils.*;
import org.bouncycastle.crypto.params.Argon2Parameters;

public class Imports {
    static class KeyAgreement { static Object getInstance(String s) { return null; } }

    void run(Object md, String data) throws Exception {
        Cipher.getInstance("AES/GCM/NoPadding");                 // 14: wildcard import javax.crypto.* -> AES-GCM
        MessageDigest.getInstance("SHA-256");                    // 15: explicit import -> SHA2
        java.security.MessageDigest.getInstance("MD5");          // 16: fully qualified -> MD5
        Signature.getInstance("SHA256withRSA");                  // 17: explicit import of another Signature -> nothing
        KeyAgreement.getInstance("ECDH");                        // 18: class declared in this file -> nothing
        Mac.getInstance("HmacSHA256");                           // 19: wildcard import -> HMAC
        md5Hex(data);                                            // 20: static import -> MD5
        sha1Hex(data);                                           // 21: static wildcard import -> SHA1
        new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id); // 22: nested class via import of outer -> Argon2
        new org.bouncycastle.crypto.engines.AESEngine();         // 23: fully qualified creation -> AES
        SecretKeyFactory
            .getInstance("PBKDF2WithHmacSHA256");                // PBKDF2, reported at line 24 (start of the call node)
        KeyGenerator kg = KeyGenerator.getInstance("AES");       // 26: AES
        kg.getProvider();                                        // 27: method on variable -> nothing
        md.getClass();                                           // 28: nothing
        KeyPairGenerator.getInstance("RSA");                     // 29: simple name, not imported (java.security) -> RSA (assumed)
        MessageDigest.getInstance("SHA-512").digest(new byte[0]); // 30: chained call -> SHA2
    }
}
