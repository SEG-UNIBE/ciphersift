package w;

import java.security.SecureRandom;
import java.util.Random;

class Rand {
    long jitter() { return new Random().nextLong(); }                 // 7: insecure PRNG (weakness indicator)
    double d() { return Math.random(); }                              // 8: insecure PRNG (weakness indicator)
    byte[] key() { byte[] k = new byte[16]; new SecureRandom().nextBytes(k); return k; }  // 9: secure PRNG
    Random seeded() { return new Random(new SecureRandom().nextLong()); }  // 10: both
}
