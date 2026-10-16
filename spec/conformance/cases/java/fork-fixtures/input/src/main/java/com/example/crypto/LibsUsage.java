package com.example.crypto;

import static org.apache.commons.codec.digest.DigestUtils.sha256Hex;

import com.auth0.jwt.algorithms.Algorithm;
import com.google.common.hash.Hashing;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.encrypt.Encryptors;

public class LibsUsage {
    void run(String pw, String data) throws Exception {
        String a = DigestUtils.md5Hex(data);                                     // L18 MD5
        String b = sha256Hex(data);                                              // L19 SHA2 (static import)
        byte[] c = new DigestUtils(MessageDigestAlgorithms.SHA3_256).digest(data); // L20 SHA3 (known constant)
        String d = Hashing.sha1().hashString(data, null).toString();             // L21 SHA1
        String h = BCrypt.hashpw(pw, BCrypt.gensalt(12));                        // L22 bcrypt (outer + inner gensalt)
        BCryptPasswordEncoder enc = new BCryptPasswordEncoder();                 // L23 bcrypt
        Object e = Encryptors.stronger(pw, "deadbeef");                         // L24 AES GCM
        KeysetHandle k = KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM")); // L25 AES GCM
        Algorithm none = Algorithm.none();                                       // L26 jwt none
        Algorithm hs = Algorithm.HMAC256("secret");                              // L27 HMAC + hardcoded key
        SignatureAlgorithm rs = SignatureAlgorithm.RS256;                        // L28 RSA
    }
}
