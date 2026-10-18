package x;

import java.io.InputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SealedObject;
import javax.crypto.spec.PBEParameterSpec;
import org.bouncycastle.crypto.digests.Blake2bpDigest;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;

/** Java SE and Bouncy Castle class anchors (DECISIONS B-J-JDK, B-J-BC2). */
class Additions {
    void jdk(InputStream in, Cipher c, java.io.Serializable o) throws Exception {
        new CipherInputStream(in, c); // want: java.jca.cipher.unresolved CipherInputStream
        new SealedObject(o, c); // want: java.jca.cipher.unresolved SealedObject
        new PBEParameterSpec(new byte[8], 1000); // want: java.kdf.pbe PBEParameterSpec
    }

    void bc() {
        new Blake2bpDigest(); // want: java.hash.blake2 Blake2bpDigest
        new MLKEMKeyPairGenerator(); // want: java.pqc.mlkem MLKEMKeyPairGenerator
        new ScryptKeySpec(new char[0], new byte[0], 1024, 8, 1, 256); // want: java.kdf.scrypt ScryptKeySpec
    }
}
