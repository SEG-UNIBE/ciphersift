package app;

// a fully qualified use of the digest package counts like an import (DECISIONS B-J4)
public class Digests {
    String sha(byte[] b) {
        return org.apache.commons.codec.digest.DigestUtils.sha256Hex(b); // want: java.hash.sha2 DigestUtils.sha256Hex
    }
}
