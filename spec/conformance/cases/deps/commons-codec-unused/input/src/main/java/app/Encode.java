package app;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

// commons-codec is used only for Base64 and Hex: not reported (DECISIONS B-J4)
public class Encode {
    String b64(byte[] b) {
        return Base64.encodeBase64String(b);
    }

    String hex(byte[] b) {
        return Hex.encodeHexString(b);
    }
}
