package p;

import java.security.KeyStore;
import java.security.cert.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TimeStampToken;

class Pki {
    void a(KeyStore ks, byte[] der, java.util.List<Certificate> l, X509Certificate c) throws Exception {
        PKIXParameters p = new PKIXParameters(ks);                                           // 14: x509
        CertStore s = CertStore.getInstance("Collection", new CollectionCertStoreParameters(l));  // 15: x509
        X509CertificateHolder h = new X509CertificateHolder(der);                            // 16: x509
        CMSSignedData sd = new CMSSignedData(der);                                           // 17: CMS signed data
        CMSSignedDataGenerator g = new CMSSignedDataGenerator();                             // 18: CMS signed data
        String t = KeyStore.getDefaultType();                                                // 19: keystore
        TimeStampToken tst = new TimeStampToken(sd);                                         // 20: CMS signed data (time-stamp)
        CMSEnvelopedData ed = new CMSEnvelopedData(der);                                     // 21: CMS enveloped data
        Object v = new JcaSimpleSignerInfoVerifierBuilder().build(c);                        // 22: CMS signed data
        TrustAnchor ta = new TrustAnchor(c, null);                                           // 23: x509
        PKIXBuilderParameters b = new PKIXBuilderParameters(ks, new X509CertSelector());     // 24: x509
    }
}
