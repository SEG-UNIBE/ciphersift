package com.example.crypto;

import com.example.other.Cipher;

// Nothing in this file should be reported.
public class Negative {
    static class MessageDigest { static Object getInstance(String s) { return null; } }

    void run(Object cipher) {
        Cipher.getInstance("AES/CBC/PKCS5Padding");   // own Cipher class (explicit import)
        MessageDigest.getInstance("MD5");              // own nested class
        String s = "Cipher.getInstance(\"DES\")";      // string, not a call
        // MessageDigest.getInstance("MD5");  comment
        cipher.toString();
        java.util.List<String> l = new java.util.ArrayList<>();
    }
}
