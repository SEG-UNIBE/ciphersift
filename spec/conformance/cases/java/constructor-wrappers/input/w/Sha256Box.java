package w;

import java.security.MessageDigest;

/** A constructor as a wrapper definition, new C(…) as its call site (t3 J-CTOR). */
public class Sha256Box {
    private final MessageDigest md;

    public Sha256Box() throws Exception {
        md = MessageDigest.getInstance("SHA-256"); // want: java.hash.sha2 SHA-256
    }

    public Sha256Box(String other) {
        md = null; // an overload without crypto: the group of arity 1 carries nothing
    }
}

class Plain {
    Plain() {
    }
}

class Use {
    void run() throws Exception {
        new Sha256Box(); // want: java.hash.sha2 SHA-256 via w/Sha256Box.java:9 Sha256Box.Sha256Box
        new Sha256Box("x"); // nothing
        new Plain(); // nothing
        new Sha256Box() { }; // an anonymous subclass: nothing
    }
}
