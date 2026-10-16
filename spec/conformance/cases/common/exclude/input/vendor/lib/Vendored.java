package lib;

class Vendored {
    Object md() throws Exception { return java.security.MessageDigest.getInstance("MD5"); } // excluded by --exclude
}
