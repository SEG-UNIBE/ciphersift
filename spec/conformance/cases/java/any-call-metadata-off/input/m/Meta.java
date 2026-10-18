package m;

import java.util.HashMap;
import java.util.Map;

/** anyCall on metadata (SPEC 5.5, DECISIONS R3-X-A1), with java-any-call-metadata off and composite JOSE names (DECISIONS R3-X-JOSE). */
class Meta {
    static final String DEFAULT_ALG = "PS256";
    final Map<String, String> config = new HashMap<>();
    final Map<String, String> algs = new HashMap<>();
    Key key = new Key();
    Logger logger = new Logger();
    Logger log = logger;

    void metadata() {
        key.setType("EC"); // want: java.asym.ec EC
        key.setKeyType("RSA"); // want: java.asym.rsa RSA
        logger.tracev("fall back to {0}", DEFAULT_ALG); // want: java.asym.rsa PS256 | java.hash.sha2 PS256
        logger.debugf("using %s", "RS256"); // want: java.asym.rsa RS256 | java.hash.sha2 RS256
        log.record("HS256"); // want: java.mac.hmac HS256 | java.hash.sha2 HS256
        config.put("algorithm", "RS256"); // want: java.asym.rsa RS256 | java.hash.sha2 RS256
        config.putIfAbsent("alg", DEFAULT_ALG); // want: java.asym.rsa PS256 | java.hash.sha2 PS256
    }

    void kept() {
        algs.put("RS256", "SHA256withRSA"); // want: java.asym.rsa SHA256withRSA | java.hash.sha2 SHA256withRSA
        algs.put("HS384", "HmacSHA384"); // want: java.mac.hmac HmacSHA384 | java.hash.sha2 HS384
        key.setAlgorithm("ES512"); // want: java.asym.ecdsa ES512 | java.hash.sha2 ES512
        register("A128CBC-HS256"); // want: java.sym.aes A128CBC-HS256 | java.mac.hmac A128CBC-HS256 | java.hash.sha2 A128CBC-HS256
        register("RSA-OAEP"); // want: java.asym.rsa RSA-OAEP
        register("EdDSA"); // want: java.asym.ed25519 EdDSA
    }

    void register(String name) {
    }

    static class Key {
        void setType(String t) {
        }

        void setKeyType(String t) {
        }

        void setAlgorithm(String a) {
        }
    }

    static class Logger {
        void tracev(String f, Object... a) {
        }

        void debugf(String f, Object... a) {
        }

        void record(String s) {
        }
    }
}
