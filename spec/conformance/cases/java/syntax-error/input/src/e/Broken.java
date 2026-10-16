package e;

import java.security.MessageDigest;

public class Broken {
    void ok() throws Exception {
        MessageDigest.getInstance("MD5");          // 7: MD5, before the error
    }

    void broken( {
        int x = ;
    }

    void after() throws Exception {
        MessageDigest.getInstance("SHA-256");      // 15: SHA2, after the error (best effort)
    }
}
