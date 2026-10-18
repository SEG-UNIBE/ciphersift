package b;

import java.security.MessageDigest;
import javax.crypto.KeyGenerator;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/** Bouncy Castle OID constants as anchors (DECISIONS B-J-BCOID) and as OID values (B-J-JP2). */
class Oids {
    void a() throws Exception {
        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256); // want: java.hash.sha2 NISTObjectIdentifiers.id_sha256
        MessageDigest.getInstance(NISTObjectIdentifiers.id_sha384.getId()); // want: java.hash.sha2 SHA-384 oid=2.16.840.1.101.3.4.2.2
        KeyGenerator.getInstance(PKCSObjectIdentifiers.RC2_CBC.getId()); // want: java.sym.rc2 RC2/CBC/NoPadding oid=1.2.840.113549.3.2
    }
}
