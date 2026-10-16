package k;

import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Hex;

public class Keys {
    static final byte[] FIXED = {0x01, 0x02, 0x03, 0x04};
    static final String SECRET = "s3cr3t-s3cr3t-16";

    void run(byte[] key, char[] pw, byte[] salt, SecureRandom rnd) {
        new SecretKeySpec(new byte[] {1, 2, 3, 4, 5, 6, 7, 8}, "DES");        // 14: DES + hard-coded key (array literal; reference tool: key only, see deviations)
        new SecretKeySpec(FIXED, "AES");                                     // 15: AES + hard-coded key (constant field)
        new SecretKeySpec(SECRET.getBytes(), "AES");                         // 16: AES + hard-coded key (constant.getBytes())
        new SecretKeySpec(Hex.decode("00112233445566778899aabbccddeeff"), "AES"); // 17: AES + hard-coded key (decode literal)
        new SecretKeySpec(key, "AES");                                       // 18: AES only
        byte[] iv = new byte[16];
        rnd.nextBytes(iv);
        new IvParameterSpec(iv);                                             // 21: nothing (zero array via variable)
        new IvParameterSpec(new byte[12]);                                   // 22: static IV (inline zero array)
        new IvParameterSpec("abcdefghijklmnop".getBytes());                  // 23: static IV (literal)
        new PBEKeySpec("changeit".toCharArray());                            // 24: hard-coded password
        new PBEKeySpec(pw, salt, 310000, 256);                               // 25: PBKDF2
    }
}
