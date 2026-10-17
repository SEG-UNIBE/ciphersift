package d;

import org.bouncycastle.jcajce.provider.digest.SHA3.*;

class Wild {
    Object a() { return new Digest512(); }                                 // 6: SHA3 (enclosing class imported on demand)
}
