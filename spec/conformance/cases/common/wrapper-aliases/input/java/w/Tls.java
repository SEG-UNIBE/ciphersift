package w;

import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import javax.crypto.Cipher;
import javax.net.ssl.SSLContext;

public class Tls {
    // two family keys in each body: not thin wrappers; the names decide (V2, V1)
    static SSLContext tlsContext() throws Exception { // @j1=Tls.tlsContext
        MessageDigest.getInstance("SHA-256"); // want: java.hash.sha2 SHA-256
        return SSLContext.getInstance("TLS"); // @oj1 want: java.prot.tls.context -
    }

    static Object loadCertificate(byte[] b) throws Exception { // @j2=Tls.loadCertificate
        MessageDigest.getInstance("SHA-1"); // want: java.hash.sha1 SHA-1
        return CertificateFactory.getInstance("X.509"); // @oj2 want: java.cert.x509 CertificateFactory.getInstance
    }

    static Cipher des3Cipher() throws Exception { // @j3=Tls.des3Cipher
        MessageDigest.getInstance("MD5"); // want: java.hash.md5 MD5
        return Cipher.getInstance("DESede/CBC/PKCS5Padding"); // @oj3 want: java.sym.3des DESede/CBC/PKCS5Padding
    }

    void use(byte[] b) throws Exception {
        tlsContext(); // want: java.prot.tls.context - via=j1 origin=oj1
        loadCertificate(b); // want: java.cert.x509 CertificateFactory.getInstance via=j2 origin=oj2
        des3Cipher(); // want: java.sym.3des DESede/CBC/PKCS5Padding via=j3 origin=oj3
    }
}
