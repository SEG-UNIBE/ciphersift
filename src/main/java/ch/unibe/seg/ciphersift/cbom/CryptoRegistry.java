/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.cbom;

import ch.unibe.seg.ciphersift.rules.Asset;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Maps rule assets to the CycloneDX 1.7 cryptography registry ({@code cryptography-defs.schema.json},
 * CycloneDX specification 1.7.2): {@code algorithmProperties.algorithmFamily} and
 * {@code algorithmProperties.ellipticCurve} (SPEC 11.3.1, table 11.3.1a/b). A value is written only
 * where the rule determines it unambiguously; otherwise the field is absent and only the
 * {@code ciphersift:family} property remains.
 */
public final class CryptoRegistry {
    private CryptoRegistry() {}

    /** Rule family to registry family, where the family alone decides (SPEC table 11.3.1a). */
    private static final Map<String, String> FAMILY = Map.ofEntries(
            Map.entry("3DES", "3DES"),
            Map.entry("AES", "AES"),
            Map.entry("Argon2", "Argon2"),
            Map.entry("bcrypt", "bcrypt"),
            Map.entry("BLAKE2", "BLAKE2"),
            Map.entry("Blowfish", "Blowfish"),
            Map.entry("Camellia", "CAMELLIA"),
            Map.entry("CAST5", "CAST5"),
            Map.entry("ChaCha20", "ChaCha20"),
            Map.entry("CMAC", "CMAC"),
            Map.entry("DES", "DES"),
            Map.entry("DH", "FFDH"),
            Map.entry("DSA", "DSA"),
            Map.entry("Ed25519", "EdDSA"),
            Map.entry("Ed448", "EdDSA"),
            Map.entry("ElGamal", "ElGamal"),
            Map.entry("HKDF", "HKDF"),
            Map.entry("HMAC", "HMAC"),
            Map.entry("IDEA", "IDEA"),
            Map.entry("KBKDF", "SP800-108"),
            Map.entry("MD2", "MD2"),
            Map.entry("MD4", "MD4"),
            Map.entry("MD5", "MD5"),
            Map.entry("ML-DSA", "ML-DSA"),
            Map.entry("ML-KEM", "ML-KEM"),
            Map.entry("PBKDF2", "PBKDF2"),
            Map.entry("Poly1305", "Poly1305"),
            Map.entry("RC2", "RC2"),
            Map.entry("RC4", "RC4"),
            Map.entry("RIPEMD160", "RIPEMD"),
            Map.entry("Salsa20", "Salsa20"),
            Map.entry("XSalsa20", "Salsa20"),
            Map.entry("scrypt", "scrypt"),
            Map.entry("SEED", "SEED"),
            Map.entry("Serpent", "Serpent"),
            Map.entry("SHA1", "SHA-1"),
            Map.entry("SHA2", "SHA-2"),
            Map.entry("SHA3", "SHA-3"),
            Map.entry("SLH-DSA", "SLH-DSA"),
            Map.entry("SM3", "SM3"),
            Map.entry("SM4", "SM4"),
            Map.entry("Twofish", "Twofish"));

    /**
     * Rule families deliberately without a registry family: the registry has no entry
     * (ConcatKDF, X963KDF), or the family covers several registry families and the rule does not say
     * which (PBE: PBES1 or PBES2). EC, RSA, Curve25519 and Curve448 are decided by primitive / variant.
     */
    static final java.util.Set<String> UNMAPPED = java.util.Set.of("ConcatKDF", "X963KDF", "PBE");

    /** The registry family of a component, or null (SPEC table 11.3.1a). */
    public static String algorithmFamily(Asset a, String componentName) {
        String f = a.family();
        if (f == null) {
            return null;
        }
        String prim = a.primitive();
        String variant = a.variant() == null ? null : a.variant().toUpperCase(Locale.ROOT);
        String name = componentName == null ? "" : componentName.toLowerCase(Locale.ROOT);
        switch (f) {
            case "EC" -> {
                return "signature".equals(prim) ? "ECDSA" : "key-agree".equals(prim) ? "ECDH" : null;
            }
            case "Curve25519", "Curve448" -> {
                return "key-agree".equals(prim) ? "ECDH" : null;
            }
            case "RSA" -> {
                if ("OAEP".equals(variant)) {
                    return "RSAES-OAEP";
                }
                if ("PSS".equals(variant)) {
                    return "RSASSA-PSS";
                }
                if ("pkcs1-v1_5-encrypt".equals(a.subtype()) || "PKCS1V15".equals(variant) && "pke".equals(prim)) {
                    return "RSAES-PKCS1";
                }
                if ("PKCS1V15".equals(variant) && "signature".equals(prim)) {
                    return "RSASSA-PKCS1";
                }
                return null;
            }
            case "BLAKE2" -> {
                // the BLAKE2 rules also list BLAKE3 classes
                return name.contains("blake3") ? "BLAKE3" : "BLAKE2";
            }
            case "SHA3" -> {
                // the SHA3 rules also list Keccak (pre-standard padding), which is not FIPS 202 SHA-3
                return name.contains("keccak") ? null : "SHA-3";
            }
            default -> {
                return FAMILY.get(f);
            }
        }
    }

    /** The registry names of the curves CipherSift can name (SPEC table 11.3.1b). */
    static final java.util.List<String> CURVES = java.util.List.of(
            "brainpool/brainpoolP160r1", "brainpool/brainpoolP160t1", "brainpool/brainpoolP192r1",
            "brainpool/brainpoolP192t1", "brainpool/brainpoolP224r1", "brainpool/brainpoolP224t1",
            "brainpool/brainpoolP256r1", "brainpool/brainpoolP256t1", "brainpool/brainpoolP320r1",
            "brainpool/brainpoolP320t1", "brainpool/brainpoolP384r1", "brainpool/brainpoolP384t1",
            "brainpool/brainpoolP512r1", "brainpool/brainpoolP512t1", "nist/B-163", "nist/B-233", "nist/B-283",
            "nist/B-409", "nist/B-571", "nist/K-163", "nist/K-233", "nist/K-283", "nist/K-409", "nist/K-571",
            "nist/P-192", "nist/P-224", "nist/P-256", "nist/P-384", "nist/P-521", "secg/secp112r1",
            "secg/secp112r2", "secg/secp128r1", "secg/secp128r2", "secg/secp160k1", "secg/secp160r1",
            "secg/secp160r2", "secg/secp192k1", "secg/secp192r1", "secg/secp224k1", "secg/secp224r1",
            "secg/secp256k1", "secg/secp256r1", "secg/secp384r1", "secg/secp521r1", "secg/sect113r1",
            "secg/sect113r2", "secg/sect131r1", "secg/sect131r2", "secg/sect163k1", "secg/sect163r1",
            "secg/sect163r2", "secg/sect193r1", "secg/sect193r2", "secg/sect233k1", "secg/sect233r1",
            "secg/sect239k1", "secg/sect283k1", "secg/sect283r1", "secg/sect409k1", "secg/sect409r1",
            "secg/sect571k1", "secg/sect571r1", "x962/c2onb191v4", "x962/c2onb191v5", "x962/c2onb239v4",
            "x962/c2onb239v5", "x962/c2pnb163v1", "x962/c2pnb163v2", "x962/c2pnb163v3", "x962/c2pnb176w1",
            "x962/c2pnb208w1", "x962/c2pnb272w1", "x962/c2pnb304w1", "x962/c2pnb368w1", "x962/c2tnb191v1",
            "x962/c2tnb191v2", "x962/c2tnb191v3", "x962/c2tnb239v1", "x962/c2tnb239v2", "x962/c2tnb239v3",
            "x962/c2tnb359v1", "x962/c2tnb431r1", "x962/prime192v1", "x962/prime192v2", "x962/prime192v3",
            "x962/prime239v1", "x962/prime239v2", "x962/prime239v3", "x962/prime256v1", "other/Curve25519",
            "other/Curve448", "other/Ed25519", "other/Ed448"
    );

    private static final Map<String, String> CURVE_BY_NAME = new HashMap<>();

    static {
        for (String c : CURVES) {
            CURVE_BY_NAME.put(c.substring(c.indexOf('/') + 1).toLowerCase(Locale.ROOT), c);
        }
    }

    /**
     * The registry curve of a component, or null: for family EC the param, if it names a curve of the
     * registry (case-insensitive, without the registry's namespace prefix); for the families
     * Curve25519, Curve448, Ed25519 and Ed448 the curve the family names.
     */
    public static String ellipticCurve(Asset a, String param) {
        String f = a.family();
        if (f == null) {
            return null;
        }
        return switch (f) {
            case "EC" -> param == null ? null : CURVE_BY_NAME.get(param.toLowerCase(Locale.ROOT));
            case "Curve25519", "Curve448", "Ed25519", "Ed448" -> CURVE_BY_NAME.get(f.toLowerCase(Locale.ROOT));
            default -> null;
        };
    }
}
