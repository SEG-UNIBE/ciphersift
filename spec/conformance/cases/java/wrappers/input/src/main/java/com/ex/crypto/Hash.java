package com.ex.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Name-consistent wrappers (SPEC 18.5, W7), overloads, depth, cycles. */
public final class Hash {
    private Hash() {
    }

    public static byte[] sha256(byte[] data) { // @hb=Hash.sha256
        try {
            return MessageDigest.getInstance("SHA-256").digest(data); // @ohb want: java.hash.sha2 SHA-256
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } finally {
            count();
        }
    }

    // same arity as sha256(byte[]): the caller is removed from its own candidates, so this is level 2
    public static byte[] sha256(String s) { // @hs=Hash.sha256
        return sha256(s.getBytes()); // want: java.hash.sha2 SHA-256 via=hb origin=ohb
    }

    // two calls on one line are one occurrence (18.7); the group {sha256(byte[]), sha256(String)} carries SHA2
    public static byte[] sha256Twice(byte[] d) { // @h2=Hash.sha256Twice
        return sha256(sha256(d)); // want: java.hash.sha2 SHA-256 via=hb origin=ohb
    }

    // depth chain: sha512 (1) <- sha512Hex (2) <- sha512Base64 (3) <- sha512Wrapped (4: not a callable)
    public static byte[] sha512(byte[] d) throws NoSuchAlgorithmException { // @h5=Hash.sha512
        MessageDigest md = MessageDigest.getInstance("SHA-512"); // @oh5 want: java.hash.sha2 SHA-512
        md.update(d);
        count();
        count();
        count();
        count();
        count();
        return md.digest();
    }

    public static String sha512Hex(byte[] d) throws NoSuchAlgorithmException { // @h5h=Hash.sha512Hex
        return hex(sha512(d)); // want: java.hash.sha2 SHA-512 via=h5 origin=oh5
    }

    public static String sha512Base64(byte[] d) throws NoSuchAlgorithmException { // @h5b=Hash.sha512Base64
        return "b64:" + sha512Hex(d); // want: java.hash.sha2 SHA-512 via=h5h,h5 origin=oh5
    }

    public static String sha512Wrapped(byte[] d) throws NoSuchAlgorithmException {
        return "[" + sha512Base64(d) + "]"; // want: java.hash.sha2 SHA-512 via=h5b,h5h,h5 origin=oh5
    }

    // mutual recursion between two name-consistent methods: nothing beyond the direct finding
    public static byte[] md5A(byte[] d, int n) throws NoSuchAlgorithmException { // @ma=Hash.md5A
        if (n > 0) {
            return md5B(d, n - 1); // want: java.hash.md5 MD5 via=mb origin=omb
        }
        return d;
    }

    public static byte[] md5B(byte[] d, int n) throws NoSuchAlgorithmException { // @mb=Hash.md5B
        if (n > 0) {
            return md5A(d, n - 1); // want: java.hash.md5 MD5 via=ma,mb origin=omb
        }
        return MessageDigest.getInstance("MD5").digest(d); // @omb want: java.hash.md5 MD5
    }

    // the name names no family of the body and the body is long: not a callable
    public static byte[] checksum(byte[] d) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1"); // want: java.hash.sha1 SHA-1
        md.update(d);
        count();
        count();
        count();
        count();
        count();
        return md.digest();
    }

    // the name names AES, the body yields SHA-1: not name-consistent, and too long for W6
    public static byte[] aesKey(byte[] d) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1"); // want: java.hash.sha1 SHA-1
        md.update(d);
        count();
        count();
        count();
        count();
        count();
        return md.digest();
    }

    // thin (W6): at most 8 lines, exactly one family, any name
    public static MessageDigest digester() throws NoSuchAlgorithmException { // @dg=Hash.digester
        return MessageDigest.getInstance("SHA-384"); // @odg want: java.hash.sha2 SHA-384
    }

    // thin but two families: not W6
    public static byte[] both(byte[] d) throws NoSuchAlgorithmException {
        MessageDigest.getInstance("MD5").digest(d); // want: java.hash.md5 MD5
        return MessageDigest.getInstance("SHA-1").digest(d); // want: java.hash.sha1 SHA-1
    }

    // thin and only a secure random: not propagated (18.1)
    public static java.security.SecureRandom random() {
        return new java.security.SecureRandom(); // want: java.rand.prng.secure SecureRandom
    }

    /** A nested class calls the enclosing class's method unqualified. */
    public static final class Inner {
        public byte[] run(byte[] d) {
            return sha256(d); // want: java.hash.sha2 SHA-256 via=hb origin=ohb
        }
    }

    // a direct finding of the same family on the call's line wins (folding, 18.7)
    public static byte[] folded(byte[] d) throws NoSuchAlgorithmException {
        return sha256(MessageDigest.getInstance("SHA-256").digest(d)); // want: java.hash.sha2 SHA-256
    }

    private static void count() {
    }

    private static String hex(byte[] b) {
        return String.valueOf(b.length);
    }
}
