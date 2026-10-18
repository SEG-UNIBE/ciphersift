package app;

import org.apache.commons.codec.binary.Base64;

public class Encode {
    String b64(byte[] b) {
        return Base64.encodeBase64String(b);
    }
}
