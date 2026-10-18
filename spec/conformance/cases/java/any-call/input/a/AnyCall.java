package a;

import java.security.Signature;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.HMACParameterSpec;

/** Registry names as arguments of any call (SPEC 5.5 anyCall, DECISIONS B-J-SNx) and JSR 105 constants (B-J-XD2). */
class AnyCall {
    static final String DIGEST = "http://www.w3.org/2001/04/xmlenc#sha256";
    static final Logger LOG = Logger.getLogger("a");
    final Map<String, String> uris = new HashMap<>();

    void register(String name) {
    }

    void names(XMLSignatureFactory fac, String alg) throws Exception {
        register("SHA3-256"); // want: java.hash.sha3 SHA3-256
        uris.put(DIGEST, "x"); // want: java.hash.sha2 http://www.w3.org/2001/04/xmlenc#sha256
        fac.newDigestMethod(DigestMethod.SHA512, null); // want: java.hash.sha2 http://www.w3.org/2001/04/xmlenc#sha512
        fac.newSignatureMethod(SignatureMethod.HMAC_SHA256, null); // want: java.mac.hmac http://www.w3.org/2001/04/xmldsig-more#hmac-sha256
        new HMACParameterSpec(128); // want: java.mac.hmac HMACParameterSpec
        register("Signature.SHA256withECDSA"); // want: java.asym.ecdsa Signature.SHA256withECDSA | java.hash.sha2 Signature.SHA256withECDSA
        register("AES"); // want: java.sym.aes AES
        register("SHA-256 is fine"); // not a whole name: nothing
    }

    void excluded(String alg) throws Exception {
        if ("SHA-256".equals(alg)) { // a comparison: nothing
            LOG.info("SHA-256"); // logging: nothing
        }
        List.of("SHA-256", "SHA-512"); // a collection builder: nothing
        Signature.getInstance("SHA256withECDSA"); // want: java.asym.ecdsa SHA256withECDSA
        uris.containsKey("SHA-1"); // nothing
    }
}
