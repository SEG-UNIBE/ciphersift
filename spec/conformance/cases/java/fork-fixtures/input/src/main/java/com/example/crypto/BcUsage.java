package com.example.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;

public class BcUsage {
    void run(byte[] k, byte[] pw, byte[] salt) {
        GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());                        // L21 AES GCM (inner AES suppressed)
        AESEngine plain = new AESEngine();                                               // L22 AES
        AESWrapEngine wrap = new AESWrapEngine();                                        // L23 AES (KW)
        PaddedBufferedBlockCipher cbc =
            new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(AESEngine.newInstance())); // L25 AES CBC
        DESedeEngine tdes = new DESedeEngine();                                          // L26 3DES
        SHA256Digest d = new SHA256Digest();                                             // L27 SHA2
        HMac hmac = new HMac(new SHA256Digest());                                        // L28 HMAC + SHA2
        MD5Digest md5 = new MD5Digest();                                                 // L29 MD5
        byte[] s = SCrypt.generate(pw, salt, 16384, 8, 1, 32);                           // L30 scrypt
        Argon2Parameters p = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).build(); // L31 Argon2
        Argon2BytesGenerator g = new Argon2BytesGenerator();                             // L32 Argon2
        Ed25519Signer ed = new Ed25519Signer();                                          // L33 Ed25519
        ECDSASigner ecdsa = new ECDSASigner();                                           // L34 ECDSA
        KeyParameter kp = new KeyParameter(new byte[] {1, 2, 3, 4});                     // L35 hardcoded key
    }
}
