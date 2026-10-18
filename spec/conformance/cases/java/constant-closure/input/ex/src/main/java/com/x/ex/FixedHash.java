package com.x.ex;

import com.x.core.BaseHash;
import java.security.MessageDigest;

/** Uses the inherited initialiser without assigning it (t3 J-INH). */
public class FixedHash extends BaseHash {
    byte[] digest(byte[] b) throws Exception {
        return MessageDigest.getInstance(algorithm).digest(b); // want: java.hash.sha2 SHA-256
    }
}
