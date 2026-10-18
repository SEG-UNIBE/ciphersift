package r;

import java.security.SecureRandom;
import javax.crypto.KeyGenerator;

/** Secure-random findings are propagated in Java (SPEC 18.1, DECISIONS B-J-D). */
public class Rand {
    static SecureRandom rng() throws Exception { // @r1=Rand.rng
        return SecureRandom.getInstanceStrong(); // @or1 want: java.rand.prng.secure SecureRandom.getInstanceStrong
    }

    // a secure random next to AES does not count: a thin wrapper of AES (DECISIONS B-J-D review)
    static byte[] newKey() throws Exception { // @r2=Rand.newKey
        KeyGenerator kg = KeyGenerator.getInstance("AES"); // @or2 want: java.sym.aes AES
        kg.init(256, new SecureRandom()); // want: java.rand.prng.secure SecureRandom
        return kg.generateKey().getEncoded();
    }

    void use() throws Exception {
        rng(); // want: java.rand.prng.secure SecureRandom.getInstanceStrong via=r1 origin=or1
        newKey(); // want: java.sym.aes AES via=r2 origin=or2
    }
}
