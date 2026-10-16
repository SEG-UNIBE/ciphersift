package s;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.net.ssl.SSLParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;

public class Selection {
    void fallbacks(String a) throws Exception {
        Cipher.getInstance(a);                     // 23: java.jca.cipher.unresolved
        MessageDigest.getInstance(a);              // 24: java.jca.messagedigest.unresolved
        Signature.getInstance(a);                  // 25: java.jca.signature.unresolved
        KeyPairGenerator.getInstance(a);           // 26: java.jca.keypairgenerator.unresolved
        KeyFactory.getInstance(a);                 // 27: java.jca.keyfactory.unresolved
        KeyAgreement.getInstance(a);               // 28: java.jca.keyagreement.unresolved
        KeyGenerator.getInstance(a);               // 29: java.jca.keygenerator.unresolved
        Mac.getInstance(a);                        // 30: java.jca.mac.unresolved
        SecretKeyFactory.getInstance(a);           // 31: java.jca.secretkeyfactory.unresolved
        Cipher.getInstance("AES/GCM/NoPadding", "BC"); // 32: provider argument ignored -> AES-GCM only
    }

    void nesting(SSLParameters p) {
        new GCMBlockCipher(new AESEngine());                         // 36: AES-GCM only (inner AES suppressed)
        new GCMBlockCipher(
            new AESEngine());                                        // AES-GCM only (reported at 37), also across lines
        CBCBlockCipher.newInstance(new AESEngine());                 // 39: AES-CBC only
        new HMac(new SHA256Digest());                                // 40: HMAC + SHA2 (different families)
        new HMacDSAKCalculator(new SHA512Digest());                  // 41: SHA2 (+ whatever the calculator matches)
        p.setProtocols(new String[] {"TLSv1.2", "TLSv1.3"});         // 42: TLS 1.2 + TLS 1.3
        MessageDigest.getInstance("MD5"); MessageDigest.getInstance("SHA-1"); // 43: MD5 + SHA1 on one line
        MessageDigest.getInstance("MD5"); MessageDigest.getInstance("MD5");   // 44: MD5 once (same component, same line)
    }
}
