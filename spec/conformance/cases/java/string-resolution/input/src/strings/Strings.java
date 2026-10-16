package strings;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.net.ssl.SSLSocket;
import org.apache.commons.codec.digest.HmacAlgorithms;
import javax.crypto.Mac;

interface Names {
    String SIG = "SHA384withECDSA";
}

public class Strings {
    private static final String MODE = "GCM";
    private static String counter = "MD5";
    private String twice = "SHA-1";
    private final String fin = "SHA-224";
    static final String[] PROTOCOLS = {"TLSv1", "TLSv1.3"};

    void run(SSLSocket s, String userAlg, boolean flag) throws Exception {
        Cipher.getInstance("\u0041ES/CBC/PKCS5Padding");           // 21: unicode escape -> AES-CBC
        Cipher.getInstance("AES_" + 256 + "/" + MODE + "/NoPadding");        // 22: concat with int and field -> AES-GCM
        Cipher.getInstance(("AES/CTR/NoPadding"));                           // 23: parentheses -> AES-CTR
        MessageDigest.getInstance(counter);                                  // 24: field reassigned below -> fallback
        MessageDigest.getInstance(this.fin);                                 // 25: this.field (final) -> SHA2
        MessageDigest.getInstance(Strings.MODE.toString());                  // 26: Cls.FIELD.toString() -> "GCM" -> fallback
        java.security.Signature.getInstance(Names.SIG);                      // 27: interface constant -> ECDSA
        String local = "SHA3-256";
        MessageDigest.getInstance(local);                                    // 29: effectively final local -> SHA3
        String changed = "MD5";
        changed = "SHA-256";
        MessageDigest.getInstance(changed);                                  // 32: reassigned local -> fallback
        MessageDigest.getInstance(flag ? "MD5" : "SHA-1");                   // 33: ternary -> fallback
        MessageDigest.getInstance(userAlg);                                  // 34: parameter -> fallback
        MessageDigest.getInstance(String.format("SHA-%d", 256));             // 35: format -> fallback
        Mac.getInstance(HmacAlgorithms.HMAC_SHA_256.getName());              // 36: known constant table -> HMAC
        s.setEnabledProtocols(PROTOCOLS);                                    // 37: array constant -> TLS 1.0 + TLS 1.3 (reference tool: nothing, see deviations)
        s.setEnabledProtocols(new String[] {"SSLv3", "TLSv1.2"});            // 38: array literal -> SSL 3.0 + TLS 1.2
        String block = """
            DESede""";
        Cipher.getInstance(block);                                           // 41: text block -> 3DES ECB (reference tool: fallback, see deviations)
        MessageDigest.getInstance(twice);                                    // 42: field (not final, not reassigned) -> SHA1
    }

    void later() { counter = "SHA-256"; }
}
