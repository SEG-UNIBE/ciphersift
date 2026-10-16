package com.example.crypto;

import static com.example.crypto.Constants.MODE;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class JcaUsage {
    private static final String HASH_ALG = "SHA-256";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String DES_PREFIX = "DESede";
    private static final byte[] KEY = "0123456789abcdef".getBytes();

    byte[] hash(byte[] in) throws Exception {
        MessageDigest md = MessageDigest.getInstance(HASH_ALG);            // L29 SHA2
        MessageDigest md5 = MessageDigest.getInstance("MD5");              // L30 MD5
        MessageDigest sha1 = java.security.MessageDigest.getInstance("SHA-1"); // L31 SHA1 (FQN)
        MessageDigest other = MessageDigest.getInstance(Constants.HASH_ALG);   // L32 SHA2 (cross-file)
        return md.digest(in);
    }

    void ciphers(byte[] key, String userAlg) throws Exception {
        Cipher gcm = Cipher.getInstance(TRANSFORMATION);                   // L37 AES GCM
        Cipher ecb = Cipher.getInstance("AES");                            // L38 AES ECB (default)
        final String local = "AES/CBC/PKCS5Padding";
        Cipher cbc = Cipher.getInstance(local);                            // L40 AES CBC (local final)
        Cipher tdes = Cipher.getInstance(DES_PREFIX + "/CBC/PKCS5Padding"); // L41 3DES (concat)
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");          // L42 RSA pkcs1
        Cipher oaep = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"); // L43 RSA OAEP
        Cipher unknown = Cipher.getInstance(userAlg);                      // L44 unresolved fallback
        Cipher viaImport = Cipher.getInstance(Constants.CIPHER_ALG + "/" + MODE + "/NoPadding"); // L45 AES CBC
        SecretKeySpec spec = new SecretKeySpec(key, "AES");                // L46 AES
        SecretKeySpec hard = new SecretKeySpec(KEY, "AES");                // L47 AES + hardcoded key
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);            // L48 static IV
        GCMParameterSpec gp = new GCMParameterSpec(128, key);              // L49 AES GCM
        KeyGenerator kg = KeyGenerator.getInstance("AES");                 // L50 AES
        KeyGenerator hk = KeyGenerator.getInstance("HmacSHA256");          // L51 HMAC
        Mac mac = Mac.getInstance("HmacSHA512");                           // L52 HMAC
        Cipher chacha = Cipher.getInstance("ChaCha20-Poly1305");           // L53 ChaCha20-Poly1305
        Cipher rc4 = Cipher.getInstance("ARCFOUR");                        // L54 RC4
        Cipher des = Cipher.getInstance("DES/ECB/PKCS5Padding");           // L55 DES ECB
    }

    void asym() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");        // L59 RSA
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");          // L60 EC
        ec.initialize(new ECGenParameterSpec("secp256r1"));                // L61 EC
        Signature s1 = Signature.getInstance("SHA256withECDSA");           // L62 ECDSA
        Signature s2 = Signature.getInstance("SHA1withRSA");               // L63 RSA
        Signature s3 = Signature.getInstance("Ed25519");                   // L64 Ed25519
        KeyAgreement ka = KeyAgreement.getInstance("X25519");              // L65 ECDH
        KeyAgreement dh = KeyAgreement.getInstance("DH");                  // L66 DH
        KeyFactory kf = KeyFactory.getInstance("DSA");                     // L67 DSA
        KeyPairGenerator mlkem = KeyPairGenerator.getInstance("ML-KEM-768"); // L68 ML-KEM
    }

    void kdf(char[] pw, byte[] salt) throws Exception {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); // L72 PBKDF2
        PBEKeySpec ks = new PBEKeySpec(pw, salt, 600000, 256);                     // L73 PBKDF2
        PBEKeySpec hard = new PBEKeySpec("hunter2".toCharArray(), salt, 1000, 128); // L74 PBKDF2 + hardcoded pw
        SecretKeyFactory p = SecretKeyFactory.getInstance("PBEWithMD5AndDES");      // L75 PBE
    }

    void rnd() throws Exception {
        SecureRandom sr = new SecureRandom();                              // L79 prng secure
        SecureRandom strong = SecureRandom.getInstanceStrong();            // L80 prng secure
        Random r = new Random();                                           // L81 prng insecure
        double d = Math.random();                                          // L82 prng insecure
    }

    void shadowed(String HASH_ALG) throws Exception {
        MessageDigest md = MessageDigest.getInstance(HASH_ALG);            // L86 parameter shadows field -> unresolved fallback
    }
}
