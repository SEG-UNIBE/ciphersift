package e;

import java.math.BigInteger;
import java.security.spec.*;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

class EcSpec {
    void a(BigInteger p, BigInteger x, BigInteger y, org.bouncycastle.math.ec.ECCurve c, org.bouncycastle.math.ec.ECPoint g, BigInteger n) {
        EllipticCurve curve = new EllipticCurve(new ECFieldFp(p), x, y);         // 13: EC once (nested ECFieldFp folded)
        ECDomainParameters d = new ECDomainParameters(c, g, n);                   // 14: EC
        MGF1ParameterSpec m = new MGF1ParameterSpec("SHA-384");                   // 15: SHA2
        ECPrivateKeyParameters k = new ECPrivateKeyParameters(n, d);              // 16: EC
        BigInteger q = SecP256K1Curve.q;                                          // 17: EC (curve prime)
        Object o = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);  // 18: RSA-OAEP and SHA2
        ECPoint w = new ECPoint(x, y);                                            // 19: EC
        MGF1ParameterSpec s3 = new MGF1ParameterSpec("SHA3-256");                 // 20: SHA3
    }
}
