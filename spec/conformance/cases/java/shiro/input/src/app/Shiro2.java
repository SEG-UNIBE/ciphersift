package app;

import org.apache.shiro.crypto.cipher.AesCipherService;
import org.apache.shiro.crypto.cipher.BlowfishCipherService;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.Sha384Hash;
import org.apache.shiro.crypto.support.hashes.argon2.Argon2Hash;
import org.apache.shiro.crypto.support.hashes.argon2.Argon2HashProvider;
import org.apache.shiro.crypto.support.hashes.bcrypt.BCryptHash;
import org.apache.shiro.crypto.support.hashes.bcrypt.BCryptProvider;

/** Shiro 2.x package names (DECISIONS E16). */
class Shiro2 {
    Object a() { return new AesCipherService(); }                             // 14: AES
    Object b() { return new BlowfishCipherService(); }                        // 15: Blowfish
    Object s(String pw) { return new Sha384Hash(pw); }                        // 16: SHA2
    Object argon(char[] pw) { return Argon2Hash.generate(pw); }               // 17: Argon2
    Object argonProvider() { return new Argon2HashProvider(); }               // 18: Argon2
    Object bcrypt(byte[] pw) { return BCryptHash.generate(null); }            // 19: bcrypt
    Object bcryptProvider() { return new BCryptProvider(); }                  // 20: bcrypt

    Object service() {
        DefaultHashService hs = new DefaultHashService();                     // 23: nothing
        hs.setDefaultAlgorithmName("argon2id");                               // 24: Argon2
        hs.setDefaultAlgorithmName(BCryptHash.DEFAULT_ALGORITHM_NAME);        // 25: bcrypt via the constants table
        return hs;
    }
}

/** A class of the same simple name from another library is not Shiro's. */
class Other {
    Object o() { return new com.example.Sha256Hash(new byte[32]); }           // 32: nothing
}
