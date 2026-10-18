package a;

import java.security.cert.CertificateFactory;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;

/** t3 rule additions: J-CF, J-XSIG, J-I2P, J-CONST. */
class ApiT3 {
    void certs(CertificateFactory cf, java.io.InputStream in) throws Exception {
        cf.generateCertificate(in); // want: java.cert.x509 cf.generateCertificate
        cf.generateCRL(in); // want: java.cert.x509 cf.generateCRL
    }

    void xml(java.util.List<String> l, java.security.KeyStore ks) throws Exception {
        XMLSignatureFactory.getInstance("DOM"); // want: java.jca.signature.unresolved XMLSignatureFactory.getInstance
        Signer.signObject(null); // want: java.jca.signature.unresolved Signer.signObject
        new KeyStoreCredentialResolver(ks, null); // want: java.cert.keystore
        l.remove(SignatureConstants.ALGO_ID_DIGEST_SHA512); // want: java.hash.sha2 http://www.w3.org/2001/04/xmlenc#sha512
    }

    void jose(JsonWebSignature jws) {
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256); // want: java.asym.rsa RS256 | java.hash.sha2 RS256
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.NONE); // "none" is not in the constants table: nothing
    }

    void eddsa() throws Exception {
        new EdDSAEngine(); // want: java.asym.ed25519 EdDSAEngine
        EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519); // want: java.asym.ed25519 EdDSANamedCurveTable.getByName
    }
}
