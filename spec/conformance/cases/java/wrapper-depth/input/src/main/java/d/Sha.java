package d;

import java.security.MessageDigest;

/** Chains of up to four definitions (SPEC 18.5, DECISIONS B-C); bodies longer than 12 lines are not thin. */
public class Sha {
    static void count() {
    }

    static byte[] sha384(byte[] b) throws Exception { // @s1=Sha.sha384
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        return MessageDigest.getInstance("SHA-384").digest(b); // @os1 want: java.hash.sha2 SHA-384
    }

    static byte[] sha384Hex(byte[] b) throws Exception { // @s2=Sha.sha384Hex
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        return sha384(b); // want: java.hash.sha2 SHA-384 via=s1 origin=os1
    }

    static byte[] sha384B64(byte[] b) throws Exception { // @s3=Sha.sha384B64
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        return sha384Hex(b); // want: java.hash.sha2 SHA-384 via=s2,s1 origin=os1
    }

    static byte[] sha384Wrapped(byte[] b) throws Exception { // @s4=Sha.sha384Wrapped
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        return sha384B64(b); // want: java.hash.sha2 SHA-384 via=s3,s2,s1 origin=os1
    }

    static byte[] sha384Boxed(byte[] b) throws Exception {
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        count();
        return sha384Wrapped(b); // want: java.hash.sha2 SHA-384 via=s4,s3,s2,s1 origin=os1
    }

    void use(byte[] b) throws Exception {
        sha384Boxed(b); // a chain of five definitions: nothing
    }
}
