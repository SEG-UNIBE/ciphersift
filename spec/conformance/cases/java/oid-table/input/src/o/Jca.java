package o;

import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/** OIDs given to JCA factories and BouncyCastle (SPEC 5.11). */
class Jca {
    static final String ECDSA_SHA256 = "1.2.840.10045.4.3.2";
    static final String CN = "2.5.4.3";

    void jca() throws Exception {
        Signature.getInstance("1.2.840.10045.4.3.2");          // 18: EC (ECDSA) SHA256withECDSA
        Signature.getInstance(ECDSA_SHA256);                  // 19: the same through a constant
        Signature.getInstance("OID.1.2.840.113549.1.1.11");    // 20: RSA SHA256withRSA (JCA alias prefix)
        KeyFactory.getInstance("1.2.840.10045.2.1");           // 21: EC
        KeyFactory.getInstance("1.2.840.113549.1.1.1");        // 22: RSA
        AlgorithmParameters.getInstance("1.2.840.10045.2.1");  // 23: EC
        MessageDigest.getInstance("2.16.840.1.101.3.4.2.1");   // 24: SHA2 SHA-256
        Mac.getInstance("1.2.840.113549.2.9");                 // 25: HMAC HmacSHA256
        Cipher.getInstance("2.16.840.1.101.3.4.1.42");         // 26: AES-CBC AES_256/CBC/NoPadding
        Cipher.getInstance("1.2.840.113549.3.2");              // 27: RC2 RC2/CBC/NoPadding
        SecretKeyFactory.getInstance("1.2.840.113549.1.5.12"); // 28: PBKDF2
        Cipher.getInstance("1.2.3.4.5");                       // 29: unknown OID: only the Cipher fallback
        MessageDigest.getInstance("2.16.840.1.101.3.4.2.1.1"); // 30: not in the table: only the fallback
        MessageDigest.getInstance("SHA-256");                  // 31: by name: no OID
    }

    void bc() {
        new ASN1ObjectIdentifier(CN);                           // 35: commonName is not in the table: nothing
        new ASN1ObjectIdentifier("1.2.840.113549.1.1.99");      // 36: unknown: nothing
        new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.101.112"); // 37: Ed25519 (qualified)
        new ASN1ObjectIdentifier(" 1.3.101.112");               // 38: not exactly an OID: nothing
    }

    Signature deferred(boolean c) throws Exception {
        final String alg;
        if (c) alg = "1.2.840.113549.1.1.11"; else alg = "1.2.840.113549.1.1.5";
        return Signature.getInstance(alg);                     // 44: deferred final local stays unresolved (7.4.3)
    }
}
