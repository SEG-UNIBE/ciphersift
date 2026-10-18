package g;

import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.SecretKeyFactory;

/** JCA standard names that had no specific rule (DECISIONS B-A3). */
class Gaps {
    void names() throws Exception {
        Signature.getInstance("SHA256withECDSAinP1363Format"); // want: java.asym.ecdsa SHA256withECDSAinP1363Format
        Signature.getInstance("SHA3-256withDSAinP1363Format"); // want: java.asym.dsa SHA3-256withDSAinP1363Format
        MessageDigest.getInstance("SHAKE256-512"); // want: java.hash.sha3 SHAKE256-512
        SecretKeyFactory.getInstance("ARCFOUR"); // want: java.sym.rc4 ARCFOUR
        SecretKeyFactory.getInstance("ChaCha20"); // want: java.sym.chacha20 ChaCha20
        KEM.getInstance("DHKEM"); // want: java.asym.ecdh DHKEM
        Cipher.getInstance("ECIES"); // want: java.asym.ec ECIES
    }
}
