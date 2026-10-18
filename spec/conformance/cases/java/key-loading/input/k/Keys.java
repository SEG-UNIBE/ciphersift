package k;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.crypto.util.PublicKeyFactory;

/** Java key loading (DECISIONS B-J-KL, mirror of the Python rules of E4). */
class Keys {
    PublicKey pub(KeyFactory kf, byte[] der) throws Exception {
        return kf.generatePublic(new X509EncodedKeySpec(der)); // want: java.key.load.public -
    }

    PrivateKey priv(byte[] der) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC"); // want: java.asym.ec EC
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der); // want: java.key.load.private -
        return kf.generatePrivate(spec); // want: java.key.load.private -
    }

    Object bc(byte[] der) throws Exception {
        return PublicKeyFactory.createKey(der); // want: java.key.load.public -
    }
}
