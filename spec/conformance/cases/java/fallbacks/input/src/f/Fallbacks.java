package f;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

class Fallbacks {
    Object a(byte[] key, String alg) throws Exception { return new SecretKeySpec(key, alg); }               // 9: SecretKeySpec unresolved
    Object b(String alg) throws Exception { return AlgorithmParameterGenerator.getInstance(alg); }          // 10: AlgorithmParameterGenerator unresolved
    Object c(java.security.cert.X509Certificate cert) { return new JcaContentSignerBuilder(cert.getSigAlgName()); }  // 11: Signature unresolved
    Object d(String alg) throws Exception { return AlgorithmParameters.getInstance(alg); }                  // 12: AlgorithmParameters unresolved
    Object e(byte[] key) { return new SecretKeySpec(key, "AES"); }                                         // 13: AES only
    Object f() throws Exception { return AlgorithmParameters.getInstance("DESede"); }                       // 14: 3DES
    Object g() throws Exception { return AlgorithmParameters.getInstance("PBEWithHmacSHA256AndAES_128"); }  // 15: PBE
    Object h() throws Exception { return AlgorithmParameterGenerator.getInstance("DH"); }                    // 16: DH
    Object i() { return new JcaContentSignerBuilder("SHA256withECDSA"); }                                  // 17: ECDSA only
    Object j(byte[] key) { return new SecretKeySpec(key, "Unknown-Alg"); }                                 // 18: SecretKeySpec unresolved (no rule for the name)
    Object k() throws Exception { return AlgorithmParameters.getInstance("ChaCha20-Poly1305"); }            // 19: ChaCha20-Poly1305
}
