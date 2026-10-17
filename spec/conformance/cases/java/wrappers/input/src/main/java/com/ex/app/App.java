package com.ex.app;

import static com.ex.crypto.Hash.sha512Hex;

import com.ex.a.*;
import com.ex.b.*;
import com.ex.crypto.Hash;

/** Call sites of the wrappers in com.ex.crypto (SPEC 18.4). */
public class App {
    private final Hash h = null;

    byte[] qualified(byte[] d) {
        return Hash.sha256(d); // want: java.hash.sha2 SHA-256 via=hb origin=ohb
    }

    byte[] fullyQualified(byte[] d) {
        return com.ex.crypto.Hash.sha256(d); // want: java.hash.sha2 SHA-256 via=hb origin=ohb
    }

    String staticImport(byte[] d) throws Exception {
        return sha512Hex(d); // want: java.hash.sha2 SHA-512 via=h5h,h5 origin=oh5
    }

    Object thin() throws Exception {
        return Hash.digester(); // want: java.hash.sha2 SHA-384 via=dg origin=odg
    }

    byte[] multiLine(byte[] d) {
        return Hash
                .sha256( // want: java.hash.sha2 SHA-256 via=hb origin=ohb
                        d);
    }

    void notResolved(byte[] d) throws Exception {
        h.sha256(d); // a variable receiver: not resolved
        Hash.sha256(d, 1); // no overload with two parameters
        Hash.checksum(d); // not a callable
        Hash.random(); // a CSPRNG helper is not propagated
        Hash.both(d); // two families: not a thin wrapper
        Digests.sha1(d); // Digests exists in com.ex.a and com.ex.b (both imported on demand): collision, skipped
        Local.sha1(d); // a class declared in this file wins over the on-demand imports
    }

    static final class Local {
        static byte[] sha1(byte[] d) {
            return d;
        }
    }
}
