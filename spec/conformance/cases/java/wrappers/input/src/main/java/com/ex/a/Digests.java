package com.ex.a;

import java.security.MessageDigest;

public final class Digests {
    public static byte[] sha1(byte[] d) throws Exception { // @da=Digests.sha1
        return MessageDigest.getInstance("SHA-1").digest(d); // @oda want: java.hash.sha1 SHA-1
    }

    static byte[] twice(byte[] d) throws Exception {
        return sha1(sha1(d)); // want: java.hash.sha1 SHA-1 via=da origin=oda
    }
}
