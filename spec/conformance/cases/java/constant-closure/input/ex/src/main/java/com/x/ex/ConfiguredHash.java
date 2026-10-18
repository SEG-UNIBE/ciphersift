package com.x.ex;

import com.x.core.BaseHash;
import java.security.MessageDigest;

/** Assigns the inherited non-final field: its initialiser is no constant here (review3 R3-J-INH1). */
public class ConfiguredHash extends BaseHash {
    public ConfiguredHash(String a) {
        this.algorithm = a;
    }

    byte[] digest(byte[] b) throws Exception {
        return MessageDigest.getInstance(algorithm).digest(b); // want: java.jca.messagedigest.unresolved MessageDigest.getInstance
    }
}
