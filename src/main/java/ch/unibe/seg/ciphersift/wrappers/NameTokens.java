/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.wrappers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The name tokeniser and alias list of SPEC 18.6 (DECISIONS T5): which family keys a function or
 * method name names.
 */
public final class NameTokens {
    private NameTokens() {}

    /** Alias → family key (SPEC 18.6 table). */
    static final Map<String, String> ALIASES = new LinkedHashMap<>();
    /** Parts that may follow or separate aliases inside one token (SPEC 18.6). */
    static final List<String> NEUTRAL = List.of("with", "and", "gcm", "ccm", "cbc", "ctr", "ecb", "cfb", "ofb", "siv",
            "xts", "kw", "pss", "oaep", "d", "sum", "hex");

    private static void alias(String key, String... aliases) {
        for (String a : aliases) {
            if (ALIASES.put(a, key) != null) {
                throw new IllegalStateException("duplicate alias " + a);
            }
        }
    }

    static {
        alias("SHA1", "sha1");
        alias("SHA2", "sha2", "sha224", "sha256", "sha384", "sha512");
        alias("SHA3", "sha3", "keccak", "shake");
        alias("MD5", "md5");
        alias("MD4", "md4");
        alias("MD2", "md2");
        alias("RIPEMD160", "ripemd", "rmd160");
        alias("BLAKE2", "blake2");
        alias("SM3", "sm3");
        alias("HMAC", "hmac");
        alias("CMAC", "cmac");
        alias("Poly1305", "poly1305");
        alias("AES", "aes", "rijndael");
        alias("DES", "des");
        alias("3DES", "3des", "desede", "tripledes");
        alias("ChaCha20", "chacha", "xchacha");
        alias("Salsa20", "salsa20");
        alias("XSalsa20", "xsalsa20");
        alias("RC4", "rc4", "arcfour");
        alias("RC2", "rc2");
        alias("Blowfish", "blowfish");
        alias("Twofish", "twofish");
        alias("Camellia", "camellia");
        alias("CAST5", "cast5");
        alias("Serpent", "serpent");
        alias("SM4", "sm4");
        alias("RSA", "rsa");
        alias("DSA", "dsa");
        alias("DH", "dh");
        alias("EC", "ec", "ecc", "ecdsa", "ecdh", "ecdhe", "ecies", "secp", "prime256v1", "p256", "p384", "p521",
                "brainpool");
        alias("Ed25519", "ed25519", "eddsa");
        alias("Ed448", "ed448");
        alias("Curve25519", "x25519", "curve25519");
        alias("Curve448", "x448", "curve448");
        alias("ML-KEM", "mlkem", "kyber");
        alias("ML-DSA", "mldsa", "dilithium");
        alias("SLH-DSA", "slhdsa", "sphincs");
        alias("PBKDF2", "pbkdf2");
        alias("HKDF", "hkdf");
        alias("scrypt", "scrypt");
        alias("Argon2", "argon2");
        alias("bcrypt", "bcrypt");
        alias("x509", "x509");
        alias("java.cert.keystore", "keystore", "truststore");
    }

    /**
     * Splits a name into lower-case tokens (SPEC 18.6): at {@code _} and {@code $}, between a
     * lower-case letter or digit and an upper-case letter, and between two upper-case letters when
     * the second is followed by a lower-case letter. Letters and digits stay together.
     */
    public static List<String> tokens(String name) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        int n = name.length();
        for (int i = 0; i < n; i++) {
            char c = name.charAt(i);
            if (c == '_' || c == '$') {
                flush(cur, out);
                continue;
            }
            if (cur.length() > 0 && Character.isUpperCase(c)) {
                char p = name.charAt(i - 1);
                boolean lowerOrDigitBefore = Character.isLowerCase(p) || Character.isDigit(p);
                boolean upperRun = Character.isUpperCase(p) && i + 1 < n && Character.isLowerCase(name.charAt(i + 1));
                if (lowerOrDigitBefore || upperRun) {
                    flush(cur, out);
                }
            }
            cur.append(c);
        }
        flush(cur, out);
        return out;
    }

    private static void flush(StringBuilder cur, List<String> out) {
        if (cur.length() > 0) {
            out.add(cur.toString().toLowerCase(Locale.ROOT));
            cur.setLength(0);
        }
    }

    /** The family keys a name names (SPEC 18.6), in code-point order. */
    public static Set<String> families(String name) {
        List<String> toks = tokens(name);
        Set<String> out = new TreeSet<>();
        for (int i = 0; i < toks.size(); i++) {
            String t = toks.get(i);
            tokenFamilies(t, out);
            if (i + 1 < toks.size()) {
                tokenFamilies(t + toks.get(i + 1), out); // sha_256, KeyStore, tripleDES
            }
        }
        return out;
    }


    /** Tokens longer than this name nothing (bounds the work on pathological identifiers). */
    static final int MAX_TOKEN = 128;

    /** Adds the families of one token if it decomposes completely (SPEC 18.6). */
    private static void tokenFamilies(String t, Set<String> out) {
        if (t.length() > MAX_TOKEN) {
            return;
        }
        Set<String> found = new TreeSet<>();
        if (decompose(t, 0, found, false, new boolean[t.length() + 1])) {
            out.addAll(found);
        }
    }

    /**
     * Whether {@code t} from {@code pos} consists of aliases, neutral parts and digit runs (a digit run
     * may end the token with at most two more characters, as in {@code secp256k1}); the first part
     * must be an alias. The longest alias wins at each position. {@code failed} memoises positions
     * from which (after an alias) no decomposition exists.
     */
    private static boolean decompose(String t, int pos, Set<String> found, boolean afterAlias, boolean[] failed) {
        if (afterAlias && failed[pos]) {
            return false;
        }
        boolean ok = decompose0(t, pos, found, afterAlias, failed);
        if (!ok && afterAlias) {
            failed[pos] = true;
        }
        return ok;
    }

    private static boolean decompose0(String t, int pos, Set<String> found, boolean afterAlias, boolean[] failed) {
        if (pos == t.length()) {
            return afterAlias;
        }
        if (afterAlias && Character.isDigit(t.charAt(pos))) {
            int p = pos;
            while (p < t.length() && Character.isDigit(t.charAt(p))) {
                p++;
            }
            // a digit run, then the end, at most two more characters (secp256k1), or more parts
            return t.length() - p <= 2 || decompose(t, p, found, true, failed);
        }
        String best = null;
        for (String a : ALIASES.keySet()) {
            if (t.startsWith(a, pos) && (best == null || a.length() > best.length())) {
                best = a;
            }
        }
        if (best != null) {
            Set<String> sub = new TreeSet<>();
            int end = pos + best.length();
            // an alias ending in a digit is like a digit run: at most two characters may end the token (blake2b)
            boolean shortTail = Character.isDigit(best.charAt(best.length() - 1)) && t.length() - end <= 2;
            if (shortTail || decompose(t, end, sub, true, failed)) {
                found.add(ALIASES.get(best));
                found.addAll(sub);
                return true;
            }
        }
        if (afterAlias) {
            for (String nPart : NEUTRAL) {
                if (t.startsWith(nPart, pos)) {
                    Set<String> sub = new TreeSet<>();
                    if (decompose(t, pos + nPart.length(), sub, true, failed)) {
                        found.addAll(sub);
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
