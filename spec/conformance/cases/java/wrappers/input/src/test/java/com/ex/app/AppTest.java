package com.ex.app;

import com.ex.crypto.Hash;
import java.security.MessageDigest;

class AppTest {
    // a wrapper defined in a test file serves test call sites only (18.4)
    static byte[] sha3(byte[] d) throws Exception { // @t3=AppTest.sha3
        return MessageDigest.getInstance("SHA3-256").digest(d); // @ot3 want: java.hash.sha3 SHA3-256
    }

    void test() throws Exception {
        Hash.sha256(new byte[0]); // want: java.hash.sha2 SHA-256 via=hb origin=ohb
        sha3(new byte[0]); // want: java.hash.sha3 SHA3-256 via=t3 origin=ot3
    }
}
