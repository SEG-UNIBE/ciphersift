package app;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authc.credential.Md5CredentialsMatcher;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.crypto.BlowfishCipherService;
import org.apache.shiro.crypto.DefaultBlockCipherService;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.crypto.hash.Sha1Hash;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.crypto.hash.SimpleHash;

/** Shiro 1.x public crypto API (DECISIONS E16). Trailing comments: line and expected result. */
class Shiro1 {
    String h(String pw) { return new Sha256Hash(pw).toHex(); }                 // 16: SHA2 Sha256Hash
    String md5(String pw, String salt) { return new Md5Hash(pw, salt, 1024).toBase64(); } // 17: MD5
    Object sha1(String hex) { return Sha1Hash.fromHexString(hex); }           // 18: SHA1 Sha1Hash.fromHexString
    String simple(String pw) { return new SimpleHash("SHA-512", pw).toHex(); } // 19: SHA2 SHA-512
    String simpleSha3(String pw) { return new SimpleHash("SHA3-256", pw).toHex(); } // 20: SHA3 SHA3-256

    Object matcher() {
        HashedCredentialsMatcher m = new HashedCredentialsMatcher();         // 23: nothing (no algorithm)
        m.setHashAlgorithmName("SHA-256");                                    // 24: SHA2 SHA-256
        m.setHashAlgorithmName(Sha256Hash.ALGORITHM_NAME);                    // 25: SHA2 via the constants table
        return new HashedCredentialsMatcher(Md5Hash.ALGORITHM_NAME);          // 26: MD5 via the constants table
    }

    Object oldMatcher() { return new Md5CredentialsMatcher(); }                // 29: MD5 Md5CredentialsMatcher

    Object ciphers() {
        new AesCipherService();                                               // 32: AES
        new BlowfishCipherService();                                          // 33: Blowfish
        new DefaultBlockCipherService("AES");                                 // 34: AES
        return new DefaultBlockCipherService("Twofish");                      // 35: nothing (no Shiro Twofish rule)
    }

    Object random() { return new SecureRandomNumberGenerator().nextBytes(); }  // 38: secure PRNG
}
