package k;

import javax.crypto.spec.SecretKeySpec;

public class Commented {
    static final byte[] KEY = {0x01, /* second */ 0x02, 0x03, 0x04};

    void run(byte[] key) {
        new SecretKeySpec(new byte[] {1, /* x */ 2, 3, 4, 5, 6, 7, 8}, "DES");   // 9: DES + hard-coded key (comment ignored, O3)
        new SecretKeySpec(KEY, "AES");                                          // 10: AES + hard-coded key (constant field with a comment)
        new SecretKeySpec(new byte[] {                                          // 11: AES + hard-coded key (line comments)
            0x10, 0x11, // first half
            0x12, 0x13  // second half
        }, "AES");
        new SecretKeySpec(new byte[] {1, /* x */ key[0]}, "AES");               // 15: AES only (an element is not a literal)
    }
}
