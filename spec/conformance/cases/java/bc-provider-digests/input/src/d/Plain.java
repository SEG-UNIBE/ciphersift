package d;

import org.bouncycastle.jcajce.provider.digest.*;

class Plain {
    Object a() { return new Digest256(); }                                 // 6: nothing (Digest256 is a member type of Keccak or SHA3: needs an import)
    Object b() { return new Keccak.Digest512(); }                          // 7: SHA3 (Keccak via the package import)
}
