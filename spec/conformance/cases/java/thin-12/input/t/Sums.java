package t;

import java.security.MessageDigest;

/** Java thin wrappers of up to 12 lines (SPEC 18.5, DECISIONS B-J-G). */
public class Sums {
    static void count() {
    }

    // 12 lines from the name row to the last row: thin, carries SHA1 whatever its name
    static byte[] checksum(byte[] d) throws Exception { // @c1=Sums.checksum
        MessageDigest md = MessageDigest.getInstance("SHA-1"); // @oc1 want: java.hash.sha1 SHA-1
        md.update(d);
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        return md.digest();
    }

    // 13 lines: not thin
    static byte[] fingerprint(byte[] d) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5"); // want: java.hash.md5 MD5
        md.update(d);
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        return md.digest();
    }

    void use(byte[] d) throws Exception {
        checksum(d); // want: java.hash.sha1 SHA-1 via=c1 origin=oc1
        fingerprint(d); // not a callable
    }
}
