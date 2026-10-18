/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The built-in table of algorithm object identifiers (SPEC 5.11, DECISIONS E15). A resolved string
 * that is a dotted OID listed here is treated like the algorithm name it maps to; unknown OIDs stay as
 * they are (and match no bundled pattern).
 */
public final class OidTable {
    /**
     * One table row.
     *
     * @param oid the dotted OID
     * @param name the algorithm name it is treated as (the JCA standard name where there is one)
     * @param asn1Name the ASN.1 name in its defining standard
     */
    public record Entry(String oid, String name, String asn1Name) {}

    /** A dotted OID, optionally with the JCA alias prefix {@code OID.} (any case). */
    private static final Pattern DOTTED = Pattern.compile("(?:[Oo][Ii][Dd]\\.)?([0-2](?:\\.(?:0|[1-9][0-9]*))+)");

    private static final List<Entry> ENTRIES = List.of(
            e("1.2.840.113549.1.1.1", "RSA", "rsaEncryption"),
            e("1.2.840.113549.1.1.7", "OAEP", "id-RSAES-OAEP"),
            e("1.2.840.113549.1.1.10", "RSASSA-PSS", "id-RSASSA-PSS"),
            e("1.2.840.113549.1.1.2", "MD2withRSA", "md2WithRSAEncryption"),
            e("1.2.840.113549.1.1.4", "MD5withRSA", "md5WithRSAEncryption"),
            e("1.2.840.113549.1.1.5", "SHA1withRSA", "sha1WithRSAEncryption"),
            e("1.2.840.113549.1.1.14", "SHA224withRSA", "sha224WithRSAEncryption"),
            e("1.2.840.113549.1.1.11", "SHA256withRSA", "sha256WithRSAEncryption"),
            e("1.2.840.113549.1.1.12", "SHA384withRSA", "sha384WithRSAEncryption"),
            e("1.2.840.113549.1.1.13", "SHA512withRSA", "sha512WithRSAEncryption"),
            e("1.2.840.113549.1.1.15", "SHA512/224withRSA", "sha512-224WithRSAEncryption"),
            e("1.2.840.113549.1.1.16", "SHA512/256withRSA", "sha512-256WithRSAEncryption"),
            e("2.16.840.1.101.3.4.3.13", "SHA3-224withRSA", "id-rsassa-pkcs1-v1_5-with-sha3-224"),
            e("2.16.840.1.101.3.4.3.14", "SHA3-256withRSA", "id-rsassa-pkcs1-v1_5-with-sha3-256"),
            e("2.16.840.1.101.3.4.3.15", "SHA3-384withRSA", "id-rsassa-pkcs1-v1_5-with-sha3-384"),
            e("2.16.840.1.101.3.4.3.16", "SHA3-512withRSA", "id-rsassa-pkcs1-v1_5-with-sha3-512"),
            e("1.2.840.10040.4.1", "DSA", "id-dsa"),
            e("1.2.840.10040.4.3", "SHA1withDSA", "id-dsa-with-sha1"),
            e("2.16.840.1.101.3.4.3.1", "SHA224withDSA", "id-dsa-with-sha224"),
            e("2.16.840.1.101.3.4.3.2", "SHA256withDSA", "id-dsa-with-sha256"),
            e("2.16.840.1.101.3.4.3.3", "SHA384withDSA", "id-dsa-with-sha384"),
            e("2.16.840.1.101.3.4.3.4", "SHA512withDSA", "id-dsa-with-sha512"),
            e("2.16.840.1.101.3.4.3.5", "SHA3-224withDSA", "id-dsa-with-sha3-224"),
            e("2.16.840.1.101.3.4.3.6", "SHA3-256withDSA", "id-dsa-with-sha3-256"),
            e("2.16.840.1.101.3.4.3.7", "SHA3-384withDSA", "id-dsa-with-sha3-384"),
            e("2.16.840.1.101.3.4.3.8", "SHA3-512withDSA", "id-dsa-with-sha3-512"),
            e("1.2.840.10045.2.1", "EC", "id-ecPublicKey"),
            e("1.3.132.1.12", "ECDH", "id-ecDH"),
            e("1.2.840.10045.4.1", "SHA1withECDSA", "ecdsa-with-SHA1"),
            e("1.2.840.10045.4.3.1", "SHA224withECDSA", "ecdsa-with-SHA224"),
            e("1.2.840.10045.4.3.2", "SHA256withECDSA", "ecdsa-with-SHA256"),
            e("1.2.840.10045.4.3.3", "SHA384withECDSA", "ecdsa-with-SHA384"),
            e("1.2.840.10045.4.3.4", "SHA512withECDSA", "ecdsa-with-SHA512"),
            e("2.16.840.1.101.3.4.3.9", "SHA3-224withECDSA", "id-ecdsa-with-sha3-224"),
            e("2.16.840.1.101.3.4.3.10", "SHA3-256withECDSA", "id-ecdsa-with-sha3-256"),
            e("2.16.840.1.101.3.4.3.11", "SHA3-384withECDSA", "id-ecdsa-with-sha3-384"),
            e("2.16.840.1.101.3.4.3.12", "SHA3-512withECDSA", "id-ecdsa-with-sha3-512"),
            e("1.2.840.10045.3.1.1", "secp192r1", "prime192v1"),
            e("1.3.132.0.33", "secp224r1", "secp224r1"),
            e("1.2.840.10045.3.1.7", "secp256r1", "prime256v1"),
            e("1.3.132.0.34", "secp384r1", "secp384r1"),
            e("1.3.132.0.35", "secp521r1", "secp521r1"),
            e("1.3.132.0.10", "secp256k1", "secp256k1"),
            e("1.3.36.3.3.2.8.1.1.1", "brainpoolP160r1", "brainpoolP160r1"),
            e("1.3.36.3.3.2.8.1.1.3", "brainpoolP192r1", "brainpoolP192r1"),
            e("1.3.36.3.3.2.8.1.1.5", "brainpoolP224r1", "brainpoolP224r1"),
            e("1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1", "brainpoolP256r1"),
            e("1.3.36.3.3.2.8.1.1.9", "brainpoolP320r1", "brainpoolP320r1"),
            e("1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1", "brainpoolP384r1"),
            e("1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1", "brainpoolP512r1"),
            e("1.3.101.110", "X25519", "id-X25519"),
            e("1.3.101.111", "X448", "id-X448"),
            e("1.3.101.112", "Ed25519", "id-Ed25519"),
            e("1.3.101.113", "Ed448", "id-Ed448"),
            e("1.2.840.113549.1.3.1", "DH", "dhKeyAgreement"),
            e("1.2.840.10046.2.1", "DH", "dhpublicnumber"),
            e("1.2.840.113549.2.2", "MD2", "md2"),
            e("1.2.840.113549.2.5", "MD5", "md5"),
            e("1.3.14.3.2.26", "SHA-1", "id-sha1"),
            e("2.16.840.1.101.3.4.2.4", "SHA-224", "id-sha224"),
            e("2.16.840.1.101.3.4.2.1", "SHA-256", "id-sha256"),
            e("2.16.840.1.101.3.4.2.2", "SHA-384", "id-sha384"),
            e("2.16.840.1.101.3.4.2.3", "SHA-512", "id-sha512"),
            e("2.16.840.1.101.3.4.2.5", "SHA-512/224", "id-sha512-224"),
            e("2.16.840.1.101.3.4.2.6", "SHA-512/256", "id-sha512-256"),
            e("2.16.840.1.101.3.4.2.7", "SHA3-224", "id-sha3-224"),
            e("2.16.840.1.101.3.4.2.8", "SHA3-256", "id-sha3-256"),
            e("2.16.840.1.101.3.4.2.9", "SHA3-384", "id-sha3-384"),
            e("2.16.840.1.101.3.4.2.10", "SHA3-512", "id-sha3-512"),
            e("1.2.840.113549.2.7", "HmacSHA1", "id-hmacWithSHA1"),
            e("1.2.840.113549.2.8", "HmacSHA224", "id-hmacWithSHA224"),
            e("1.2.840.113549.2.9", "HmacSHA256", "id-hmacWithSHA256"),
            e("1.2.840.113549.2.10", "HmacSHA384", "id-hmacWithSHA384"),
            e("1.2.840.113549.2.11", "HmacSHA512", "id-hmacWithSHA512"),
            e("1.2.840.113549.2.12", "HmacSHA512/224", "id-hmacWithSHA512-224"),
            e("1.2.840.113549.2.13", "HmacSHA512/256", "id-hmacWithSHA512-256"),
            e("2.16.840.1.101.3.4.2.13", "HmacSHA3-224", "id-hmacWithSHA3-224"),
            e("2.16.840.1.101.3.4.2.14", "HmacSHA3-256", "id-hmacWithSHA3-256"),
            e("2.16.840.1.101.3.4.2.15", "HmacSHA3-384", "id-hmacWithSHA3-384"),
            e("2.16.840.1.101.3.4.2.16", "HmacSHA3-512", "id-hmacWithSHA3-512"),
            e("2.16.840.1.101.3.4.1.1", "AES_128/ECB/NoPadding", "aes128-ECB"),
            e("2.16.840.1.101.3.4.1.2", "AES_128/CBC/NoPadding", "aes128-CBC"),
            e("2.16.840.1.101.3.4.1.3", "AES_128/OFB/NoPadding", "aes128-OFB"),
            e("2.16.840.1.101.3.4.1.4", "AES_128/CFB/NoPadding", "aes128-CFB"),
            e("2.16.840.1.101.3.4.1.5", "AES_128/KW/NoPadding", "id-aes128-wrap"),
            e("2.16.840.1.101.3.4.1.6", "AES_128/GCM/NoPadding", "id-aes128-GCM"),
            e("2.16.840.1.101.3.4.1.7", "AES_128/CCM/NoPadding", "id-aes128-CCM"),
            e("2.16.840.1.101.3.4.1.8", "AES_128/KWP/NoPadding", "id-aes128-wrap-pad"),
            e("2.16.840.1.101.3.4.1.21", "AES_192/ECB/NoPadding", "aes192-ECB"),
            e("2.16.840.1.101.3.4.1.22", "AES_192/CBC/NoPadding", "aes192-CBC"),
            e("2.16.840.1.101.3.4.1.23", "AES_192/OFB/NoPadding", "aes192-OFB"),
            e("2.16.840.1.101.3.4.1.24", "AES_192/CFB/NoPadding", "aes192-CFB"),
            e("2.16.840.1.101.3.4.1.25", "AES_192/KW/NoPadding", "id-aes192-wrap"),
            e("2.16.840.1.101.3.4.1.26", "AES_192/GCM/NoPadding", "id-aes192-GCM"),
            e("2.16.840.1.101.3.4.1.27", "AES_192/CCM/NoPadding", "id-aes192-CCM"),
            e("2.16.840.1.101.3.4.1.28", "AES_192/KWP/NoPadding", "id-aes192-wrap-pad"),
            e("2.16.840.1.101.3.4.1.41", "AES_256/ECB/NoPadding", "aes256-ECB"),
            e("2.16.840.1.101.3.4.1.42", "AES_256/CBC/NoPadding", "aes256-CBC"),
            e("2.16.840.1.101.3.4.1.43", "AES_256/OFB/NoPadding", "aes256-OFB"),
            e("2.16.840.1.101.3.4.1.44", "AES_256/CFB/NoPadding", "aes256-CFB"),
            e("2.16.840.1.101.3.4.1.45", "AES_256/KW/NoPadding", "id-aes256-wrap"),
            e("2.16.840.1.101.3.4.1.46", "AES_256/GCM/NoPadding", "id-aes256-GCM"),
            e("2.16.840.1.101.3.4.1.47", "AES_256/CCM/NoPadding", "id-aes256-CCM"),
            e("2.16.840.1.101.3.4.1.48", "AES_256/KWP/NoPadding", "id-aes256-wrap-pad"),
            e("1.2.840.113549.3.7", "DESede/CBC/NoPadding", "des-ede3-cbc"),
            e("1.3.14.3.2.7", "DES/CBC/NoPadding", "desCBC"),
            e("1.2.840.113549.3.2", "RC2/CBC/NoPadding", "rc2CBC"),
            e("1.2.840.113549.1.5.12", "PBKDF2", "id-PBKDF2"),
            e("1.2.840.113549.1.5.13", "PBES2", "id-PBES2"),
            e("1.3.6.1.4.1.11591.4.11", "SCRYPT", "id-scrypt"),
            e("2.16.840.1.101.3.4.4.1", "ML-KEM-512", "id-alg-ml-kem-512"),
            e("2.16.840.1.101.3.4.4.2", "ML-KEM-768", "id-alg-ml-kem-768"),
            e("2.16.840.1.101.3.4.4.3", "ML-KEM-1024", "id-alg-ml-kem-1024"),
            e("2.16.840.1.101.3.4.3.17", "ML-DSA-44", "id-ml-dsa-44"),
            e("2.16.840.1.101.3.4.3.18", "ML-DSA-65", "id-ml-dsa-65"),
            e("2.16.840.1.101.3.4.3.19", "ML-DSA-87", "id-ml-dsa-87"),
            e("2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s", "id-slh-dsa-sha2-128s"),
            e("2.16.840.1.101.3.4.3.21", "SLH-DSA-SHA2-128f", "id-slh-dsa-sha2-128f"),
            e("2.16.840.1.101.3.4.3.22", "SLH-DSA-SHA2-192s", "id-slh-dsa-sha2-192s"),
            e("2.16.840.1.101.3.4.3.23", "SLH-DSA-SHA2-192f", "id-slh-dsa-sha2-192f"),
            e("2.16.840.1.101.3.4.3.24", "SLH-DSA-SHA2-256s", "id-slh-dsa-sha2-256s"),
            e("2.16.840.1.101.3.4.3.25", "SLH-DSA-SHA2-256f", "id-slh-dsa-sha2-256f"),
            e("2.16.840.1.101.3.4.3.26", "SLH-DSA-SHAKE-128s", "id-slh-dsa-shake-128s"),
            e("2.16.840.1.101.3.4.3.27", "SLH-DSA-SHAKE-128f", "id-slh-dsa-shake-128f"),
            e("2.16.840.1.101.3.4.3.28", "SLH-DSA-SHAKE-192s", "id-slh-dsa-shake-192s"),
            e("2.16.840.1.101.3.4.3.29", "SLH-DSA-SHAKE-192f", "id-slh-dsa-shake-192f"),
            e("2.16.840.1.101.3.4.3.30", "SLH-DSA-SHAKE-256s", "id-slh-dsa-shake-256s"),
            e("2.16.840.1.101.3.4.3.31", "SLH-DSA-SHAKE-256f", "id-slh-dsa-shake-256f"),
            // DECISIONS B-A4: completion from the public registries (SPEC 5.11)
            e("2.16.840.1.101.3.4.2.11", "SHAKE128", "id-shake128"),
            e("2.16.840.1.101.3.4.2.12", "SHAKE256", "id-shake256"),
            e("1.2.840.113549.1.1.3", "MD4withRSA", "md4WithRSAEncryption"),
            e("1.3.14.3.2.29", "SHA1withRSA", "sha1WithRSASignature (OIW)"),
            e("1.3.132.1.13", "ECMQV", "id-ecMQV"),
            e("1.3.132.0.1", "sect163k1", "sect163k1"),
            e("1.3.132.0.15", "sect163r2", "sect163r2"),
            e("1.3.132.0.26", "sect233k1", "sect233k1"),
            e("1.3.132.0.27", "sect233r1", "sect233r1"),
            e("1.3.132.0.16", "sect283k1", "sect283k1"),
            e("1.3.132.0.17", "sect283r1", "sect283r1"),
            e("1.3.132.0.36", "sect409k1", "sect409k1"),
            e("1.3.132.0.37", "sect409r1", "sect409r1"),
            e("1.3.132.0.38", "sect571k1", "sect571k1"),
            e("1.3.132.0.39", "sect571r1", "sect571r1"),
            e("1.3.36.3.2.1", "RIPEMD160", "ripemd160"),
            e("1.3.6.1.5.5.8.1.1", "HmacMD5", "hmac-md5"),
            e("1.3.6.1.5.5.8.1.2", "HmacSHA1", "hmac-sha1"),
            e("1.2.840.113549.3.4", "RC4", "rc4"),
            e("1.2.840.113549.1.5.3", "PBEWithMD5AndDES", "pbeWithMD5AndDES-CBC"),
            e("1.2.840.113549.1.5.10", "PBEWithSHA1AndDES", "pbeWithSHA1AndDES-CBC"),
            e("1.2.840.113549.1.12.1.3", "PBEWithSHA1AndDESede", "pbeWithSHAAnd3-KeyTripleDES-CBC"),
            e("1.2.840.113549.1.12.1.6", "PBEWithSHA1AndRC2_40", "pbeWithSHAAnd40BitRC2-CBC"),
            e("1.2.840.113549.1.9.16.3.18", "ChaCha20-Poly1305", "id-alg-AEADChaCha20Poly1305"),
            e("1.2.840.113549.1.9.16.3.28", "HKDF-SHA256", "id-alg-hkdf-with-sha256"),
            e("1.2.840.113549.1.9.16.3.29", "HKDF-SHA384", "id-alg-hkdf-with-sha384"),
            e("1.2.840.113549.1.9.16.3.30", "HKDF-SHA512", "id-alg-hkdf-with-sha512"),
            e("1.2.840.113549.1.9.16.3.6", "DESedeWrap", "id-alg-CMS3DESwrap"),
            e("1.3.6.1.4.1.1722.12.2.1.8", "BLAKE2B-256", "id-blake2b256"),
            e("1.3.6.1.4.1.1722.12.2.1.16", "BLAKE2B-512", "id-blake2b512"),
            e("1.3.6.1.4.1.1722.12.2.2.8", "BLAKE2S-256", "id-blake2s256"),
            e("1.2.156.10197.1.401", "SM3", "sm3"),
            e("1.2.156.10197.1.104.2", "SM4/CBC/NoPadding", "sm4-cbc"),
            e("1.2.392.200011.61.1.1.1.2", "Camellia/CBC/NoPadding", "camellia128-cbc"),
            e("1.3.6.1.4.1.188.7.1.1.2", "IDEA/CBC/NoPadding", "idea-cbc"));

    private static final Map<String, Entry> BY_OID = new LinkedHashMap<>();

    static {
        for (Entry x : ENTRIES) {
            if (BY_OID.put(x.oid(), x) != null) {
                throw new IllegalStateException("duplicate OID " + x.oid());
            }
        }
    }

    private OidTable() {}

    private static Entry e(String oid, String name, String asn1Name) {
        return new Entry(oid, name, asn1Name);
    }

    /** All rows, in table order. */
    public static List<Entry> entries() {
        return ENTRIES;
    }

    /**
     * The row for {@code s} if {@code s} is exactly a dotted OID of the table (optionally prefixed with
     * {@code OID.}), else {@code null}.
     */
    public static Entry lookup(String s) {
        if (s == null || s.isEmpty() || s.length() > 64) {
            return null;
        }
        char c = s.charAt(0);
        if (c != '0' && c != '1' && c != '2' && c != 'O' && c != 'o') {
            return null;
        }
        java.util.regex.Matcher m = DOTTED.matcher(s);
        return m.matches() ? BY_OID.get(m.group(1)) : null;
    }

    /** {@code s} mapped through the table: the row's name for a listed OID, else {@code s} itself. */
    public static String map(String s) {
        Entry x = lookup(s);
        return x == null ? s : x.name();
    }
}
