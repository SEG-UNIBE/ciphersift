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

    /** Alias → family key (SPEC 18.6 table, with the registry aliases V1 of DECISIONS B-A1). */
    static final Map<String, String> ALIASES = new LinkedHashMap<>();
    /**
     * The aliases of DECISIONS B-A2 (V2: certificates, keys, protocols): alias → family key, where a key
     * starting with {@code *} is a rule id without its language prefix ({@code *.prot.tls.context} →
     * {@code java.prot.tls.context}, {@code python.…}, {@code go.…}).
     */
    static final Map<String, String> ALIASES_V2 = new LinkedHashMap<>();
    /** Base and V2 aliases together. */
    static final Map<String, String> ALL_ALIASES = new LinkedHashMap<>();
    /** Python's hash-fallback aliases (DECISIONS B-P-U1W): {@code hash}, {@code digest} → the fallback rule id. */
    static final Map<String, String> ALIASES_U1W = Map.of("hash", "*.hash.unresolved", "digest", "*.hash.unresolved");
    /** Base (resp. base and V2) aliases with the U1W aliases, built once. */
    private static final Map<String, String> ALIASES_WITH_U1W = new LinkedHashMap<>();
    private static final Map<String, String> ALL_ALIASES_WITH_U1W = new LinkedHashMap<>();
    /** Parts that may follow or separate aliases inside one token (SPEC 18.6; the last six: DECISIONS B-A1). */
    static final List<String> NEUTRAL = List.of("with", "and", "gcm", "ccm", "cbc", "ctr", "ecb", "cfb", "ofb", "siv",
            "xts", "kw", "pss", "oaep", "d", "sum", "hex", "pkcs1", "v15", "mgf1", "p1363", "ssa", "es");

    private static void alias(String key, String... aliases) {
        for (String a : aliases) {
            if (ALIASES.put(a, key) != null) {
                throw new IllegalStateException("duplicate alias " + a);
            }
        }
    }

    private static void aliasV2(String key, String... aliases) {
        for (String a : aliases) {
            if (ALIASES.containsKey(a) || ALIASES_V2.put(a, key) != null) {
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
        // DECISIONS B-A1 (V1): algorithm names of the public registries (IANA JOSE "alg"/"enc", IANA TLS supported
        // groups, IANA SSH algorithm names, Oracle JCA standard names, NIST SP 800-67 / SP 800-131A), each mapped to
        // the family the bundled rules use; sources in PROVENANCE.md
        alias("HMAC", "hs256", "hs384", "hs512");
        alias("RSA", "rs256", "rs384", "rs512", "ps256", "ps384", "ps512");
        alias("EC", "es256", "es384", "es512", "sect", "nistp", "p192", "p224", "ecmqv", "x962");
        alias("AES", "a128", "a192", "a256");
        alias("DH", "diffie", "diffiehellman", "ffdhe", "dhe", "dhkem");
        alias("DSA", "dss");
        alias("3DES", "tdea", "tdes", "des3");
        alias("IDEA", "idea");
        alias("SEED", "seed");
        alias("CAST5", "cast128");
        alias("PBE", "pbe", "pbes2");
        alias("ConcatKDF", "concatkdf");
        alias("KBKDF", "kbkdf");
        alias("X963KDF", "x963kdf");
        alias("ElGamal", "elgamal");
        // DECISIONS B-A2 (V2): certificates, keys, protocols, Bitcoin's HASH160 (RIPEMD-160 of SHA-256)
        aliasV2("x509", "cert", "certificate");
        aliasV2("private-key", "privatekey", "privkey");
        aliasV2("public-key", "publickey", "pubkey");
        aliasV2("*.prot.tls.context", "tls", "ssl");
        aliasV2("*.prot.ssh", "ssh");
        aliasV2("RIPEMD160", "hash160");
        ALL_ALIASES.putAll(ALIASES);
        ALL_ALIASES.putAll(ALIASES_V2);
        ALIASES_WITH_U1W.putAll(ALIASES);
        ALIASES_WITH_U1W.putAll(ALIASES_U1W);
        ALL_ALIASES_WITH_U1W.putAll(ALL_ALIASES);
        ALL_ALIASES_WITH_U1W.putAll(ALIASES_U1W);
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

    /** The family keys a name names (SPEC 18.6) with the base aliases only, in code-point order. */
    public static Set<String> families(String name) {
        return families(name, null, false);
    }

    /**
     * The family keys a name names (SPEC 18.6), in code-point order; with {@code v2} also through the V2
     * aliases (DECISIONS B-A2), whose rule-id keys are completed with {@code lang} ({@code java},
     * {@code python}, {@code go}; with a null language they name nothing).
     */
    public static Set<String> families(String name, String lang, boolean v2) {
        return families(name, lang, v2, false);
    }

    /** As {@link #families(String, String, boolean)}, with the U1W aliases if {@code u1w} (DECISIONS B-P-U1W). */
    public static Set<String> families(String name, String lang, boolean v2, boolean u1w) {
        Map<String, String> aliases = u1w ? (v2 ? ALL_ALIASES_WITH_U1W : ALIASES_WITH_U1W) : (v2 ? ALL_ALIASES : ALIASES);
        List<String> toks = tokens(name);
        Set<String> out = new TreeSet<>();
        for (int i = 0; i < toks.size(); i++) {
            String t = toks.get(i);
            tokenFamilies(t, aliases, out);
            if (i + 1 < toks.size()) {
                tokenFamilies(t + toks.get(i + 1), aliases, out); // sha_256, KeyStore, tripleDES
            }
        }
        if (v2 || u1w) {
            Set<String> r = new TreeSet<>();
            for (String k : out) {
                if (k.startsWith("*")) {
                    if (lang != null) {
                        r.add(lang + k.substring(1));
                    }
                } else {
                    r.add(k);
                }
            }
            return r;
        }
        return out;
    }


    /** Tokens longer than this name nothing (bounds the work on pathological identifiers). */
    static final int MAX_TOKEN = 128;

    /** Adds the families of one token if it decomposes completely (SPEC 18.6). */
    private static void tokenFamilies(String t, Map<String, String> aliases, Set<String> out) {
        if (t.length() > MAX_TOKEN) {
            return;
        }
        Set<String> found = new TreeSet<>();
        if (decompose(t, 0, found, false, new boolean[t.length() + 1], aliases)) {
            out.addAll(found);
        }
    }

    /**
     * Whether {@code t} from {@code pos} consists of aliases, neutral parts and digit runs (a digit run
     * may end the token with at most two more characters, as in {@code secp256k1}); the first part
     * must be an alias. The longest alias wins at each position. {@code failed} memoises positions
     * from which (after an alias) no decomposition exists.
     */
    private static boolean decompose(String t, int pos, Set<String> found, boolean afterAlias, boolean[] failed,
            Map<String, String> aliases) {
        if (afterAlias && failed[pos]) {
            return false;
        }
        boolean ok = decompose0(t, pos, found, afterAlias, failed, aliases);
        if (!ok && afterAlias) {
            failed[pos] = true;
        }
        return ok;
    }

    private static boolean decompose0(String t, int pos, Set<String> found, boolean afterAlias, boolean[] failed,
            Map<String, String> aliases) {
        if (pos == t.length()) {
            return afterAlias;
        }
        if (afterAlias && Character.isDigit(t.charAt(pos))) {
            int p = pos;
            while (p < t.length() && Character.isDigit(t.charAt(p))) {
                p++;
            }
            // a digit run, then the end, at most two more characters (secp256k1), or more parts
            return t.length() - p <= 2 || decompose(t, p, found, true, failed, aliases);
        }
        String best = null;
        for (String a : aliases.keySet()) {
            if (t.startsWith(a, pos) && (best == null || a.length() > best.length())) {
                best = a;
            }
        }
        if (best != null) {
            Set<String> sub = new TreeSet<>();
            int end = pos + best.length();
            // an alias ending in a digit is like a digit run: at most two characters may end the token (blake2b)
            boolean shortTail = Character.isDigit(best.charAt(best.length() - 1)) && t.length() - end <= 2;
            if (shortTail || decompose(t, end, sub, true, failed, aliases)) {
                found.add(aliases.get(best));
                found.addAll(sub);
                return true;
            }
        }
        if (afterAlias) {
            for (String nPart : NEUTRAL) {
                if (t.startsWith(nPart, pos)) {
                    Set<String> sub = new TreeSet<>();
                    if (decompose(t, pos + nPart.length(), sub, true, failed, aliases)) {
                        found.addAll(sub);
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
