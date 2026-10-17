package d;

import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jcajce.provider.digest.Blake2b;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.jcajce.provider.digest.RIPEMD160.Digest;

class Digests {
    byte[] k(byte[] in) { return new Keccak.Digest256().digest(in); }      // 10: SHA3 (Keccak-256)
    byte[] b(byte[] in) { return new Blake2b.Blake2b256().digest(in); }    // 11: BLAKE2
    byte[] s(byte[] in) { return new SHA3.Digest256().digest(in); }        // 12: SHA3
    byte[] t(byte[] in) { return new SHA256.Digest().digest(in); }         // 13: SHA2
    byte[] r(byte[] in) { return new Digest().digest(in); }                // 14: RIPEMD160 (member type imported by name)
}
