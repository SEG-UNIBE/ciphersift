package j;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import io.jsonwebtoken.Jwts;

/** JWT library algorithm constants (DECISIONS B-J-JWT). */
class Jwt {
    Object[] algs() {
        return new Object[] {
            JWEAlgorithm.RSA_OAEP_256, // want: java.asym.rsa JWEAlgorithm.RSA_OAEP_256
            JWEAlgorithm.ECDH_ES, // want: java.asym.ecdh JWEAlgorithm.ECDH_ES
            Jwts.ENC.A256GCM, // want: java.sym.aes ENC.A256GCM
            JWSAlgorithm.Ed448, // want: java.asym.ed25519 JWSAlgorithm.Ed448
        };
    }
}
