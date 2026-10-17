/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.cbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.unibe.seg.ciphersift.CycloneDxSchemas;
import ch.unibe.seg.ciphersift.TestSupport;
import ch.unibe.seg.ciphersift.rules.Asset;
import ch.unibe.seg.ciphersift.rules.RuleLoader;
import ch.unibe.seg.ciphersift.rules.RuleSet;
import ch.unibe.seg.ciphersift.rules.SourceRule;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** CycloneDX 1.7 output (SPEC 11.1–11.3): registry fields, version option, schema validity of every rule. */
class CycloneDx17Test {
    static RuleSet rules;
    static Set<String> families;
    static Set<String> curves;

    @BeforeAll
    static void load() throws Exception {
        rules = RuleLoader.loadBundled();
        JsonNode defs = TestSupport.JSON.readTree(
                CycloneDx17Test.class.getResourceAsStream("/cyclonedx/cryptography-defs.schema.json"));
        families = strings(defs.at("/definitions/algorithmFamiliesEnum/enum"));
        curves = strings(defs.at("/definitions/ellipticCurvesEnum/enum"));
    }

    private static Set<String> strings(JsonNode arr) {
        Set<String> s = new HashSet<>();
        arr.forEach(n -> s.add(n.asText()));
        assertFalse(s.isEmpty());
        return s;
    }

    private static List<SourceRule> sourceRules() {
        List<SourceRule> all = new ArrayList<>(rules.javaRules());
        all.addAll(rules.pythonRules());
        all.addAll(rules.goRules());
        return all;
    }

    private static Asset asset(String family, String primitive, String variant, String subtype) {
        return new Asset("algorithm", subtype, primitive, family, variant, null, null, null);
    }

    @Test
    void everyMappedValueIsInTheRegistry() {
        for (String c : CryptoRegistry.CURVES) {
            assertTrue(curves.contains(c), c);
        }
        for (SourceRule r : sourceRules()) {
            String f = CryptoRegistry.algorithmFamily(r.asset(), r.name());
            assertTrue(f == null || families.contains(f), r.id() + " -> " + f);
        }
    }

    /** A new rule family must be added to the mapping table (or to the documented exceptions). */
    @Test
    void everyBundledFamilyIsMappedOrListed() {
        Set<String> unmapped = new TreeSet<>();
        for (SourceRule r : sourceRules()) {
            Asset a = r.asset();
            if (a.family() == null || CryptoRegistry.UNMAPPED.contains(a.family())) {
                continue;
            }
            boolean decided = Set.of("EC", "RSA", "Curve25519", "Curve448").contains(a.family());
            if (!decided && CryptoRegistry.algorithmFamily(a, r.name()) == null) {
                unmapped.add(a.family());
            }
        }
        assertEquals(Set.of(), unmapped);
    }

    @Test
    void familyTable() {
        assertEquals("AES", CryptoRegistry.algorithmFamily(asset("AES", "block-cipher", "GCM", null), "AES"));
        assertEquals("SHA-2", CryptoRegistry.algorithmFamily(asset("SHA2", "hash", null, null), "SHA-256"));
        assertEquals("SHA-3", CryptoRegistry.algorithmFamily(asset("SHA3", "hash", null, null), "SHA3-256"));
        assertNull(CryptoRegistry.algorithmFamily(asset("SHA3", "hash", null, null), "KeccakDigest"));
        assertEquals("BLAKE3", CryptoRegistry.algorithmFamily(asset("BLAKE2", "hash", null, null), "Blake3Digest"));
        assertEquals("CAMELLIA", CryptoRegistry.algorithmFamily(asset("Camellia", "block-cipher", null, null), "x"));
        assertEquals("RIPEMD", CryptoRegistry.algorithmFamily(asset("RIPEMD160", "hash", null, null), "x"));
        assertEquals("FFDH", CryptoRegistry.algorithmFamily(asset("DH", "key-agree", null, null), "x"));
        assertEquals("EdDSA", CryptoRegistry.algorithmFamily(asset("Ed25519", "signature", null, null), "x"));
        assertEquals("ECDSA", CryptoRegistry.algorithmFamily(asset("EC", "signature", null, null), "x"));
        assertEquals("ECDH", CryptoRegistry.algorithmFamily(asset("EC", "key-agree", null, null), "x"));
        assertNull(CryptoRegistry.algorithmFamily(asset("EC", null, null, null), "x"));
        assertEquals("ECDH", CryptoRegistry.algorithmFamily(asset("Curve25519", "key-agree", null, null), "x"));
        assertEquals("SP800-108", CryptoRegistry.algorithmFamily(asset("KBKDF", "kdf", null, null), "x"));
        assertEquals("Salsa20", CryptoRegistry.algorithmFamily(asset("XSalsa20", "stream-cipher", null, null), "x"));
        assertEquals("RSAES-OAEP", CryptoRegistry.algorithmFamily(asset("RSA", "pke", "OAEP", null), "x"));
        assertEquals("RSASSA-PSS", CryptoRegistry.algorithmFamily(asset("RSA", "signature", "PSS", null), "x"));
        assertEquals("RSASSA-PKCS1", CryptoRegistry.algorithmFamily(asset("RSA", "signature", "PKCS1v15", null), "x"));
        assertEquals("RSAES-PKCS1", CryptoRegistry.algorithmFamily(asset("RSA", "pke", null, "pkcs1-v1_5-encrypt"), "x"));
        assertNull(CryptoRegistry.algorithmFamily(asset("RSA", "signature", null, null), "x"), "scheme unknown");
        assertNull(CryptoRegistry.algorithmFamily(asset("RSA", null, "PKCS1v15", null), "x"));
        assertNull(CryptoRegistry.algorithmFamily(asset("PBE", "kdf", null, null), "x"));
        assertNull(CryptoRegistry.algorithmFamily(asset("ConcatKDF", "kdf", null, null), "x"));
        assertNull(CryptoRegistry.algorithmFamily(asset(null, "hash", null, null), "x"));
    }

    @Test
    void curveTable() {
        assertEquals("secg/secp256r1", CryptoRegistry.ellipticCurve(asset("EC", "key-agree", null, null), "SECP256R1"));
        assertEquals("secg/secp256k1", CryptoRegistry.ellipticCurve(asset("EC", "signature", null, null), "secp256k1"));
        assertEquals("secg/sect571k1", CryptoRegistry.ellipticCurve(asset("EC", "key-agree", null, null), "SECT571K1"));
        assertEquals("nist/P-256", CryptoRegistry.ellipticCurve(asset("EC", "key-agree", null, null), "P-256"));
        assertEquals("x962/prime256v1", CryptoRegistry.ellipticCurve(asset("EC", null, null, null), "prime256v1"));
        assertEquals("brainpool/brainpoolP256r1",
                CryptoRegistry.ellipticCurve(asset("EC", "key-agree", null, null), "BrainpoolP256R1"));
        assertNull(CryptoRegistry.ellipticCurve(asset("EC", "key-agree", null, null), "curve"));
        assertNull(CryptoRegistry.ellipticCurve(asset("EC", "key-agree", null, null), null));
        assertNull(CryptoRegistry.ellipticCurve(asset("RSA", "signature", null, null), "2048"));
        assertNull(CryptoRegistry.ellipticCurve(asset("DH", "key-agree", null, null), "P-256"), "only family EC");
        assertEquals("other/Curve25519", CryptoRegistry.ellipticCurve(asset("Curve25519", "key-agree", null, null), null));
        assertEquals("other/Ed448", CryptoRegistry.ellipticCurve(asset("Ed448", "signature", null, null), null));
    }

    /** One component per bundled rule (EC rules with a curve param): valid 1.7 and, with the option, valid 1.6. */
    @Test
    void everyBundledRuleGivesValidDocumentsInBothVersions() throws Exception {
        List<Component> comps = new ArrayList<>();
        int i = 0;
        for (SourceRule r : sourceRules()) {
            String param = "EC".equals(r.asset().family()) ? "secp384r1" : null;
            comps.add(new Component.Crypto(r, r.name(), param, List.of(
                    new Component.Occurrence("F" + i++ + ".java", 1, "s", r.id(), "x", param, null, false))));
        }
        for (CycloneDxVersion v : CycloneDxVersion.values()) {
            byte[] doc = CbomWriter.write(new CbomWriter.Metadata("1", "r", "sha256:0", true, 1, 0, null, true, v),
                    comps);
            List<String> errors = CycloneDxSchemas.validate(doc, v);
            assertTrue(errors.isEmpty(), v + ": " + errors);
            String s = new String(doc, StandardCharsets.UTF_8);
            assertEquals(v == CycloneDxVersion.V1_7, s.contains("\"algorithmFamily\""), v.spec());
            assertEquals(v == CycloneDxVersion.V1_7, s.contains("\"ellipticCurve\": \"secg/secp384r1\""), v.spec());
            assertTrue(s.contains("\"specVersion\": \"" + v.spec() + "\""));
        }
    }

    /** The validators are not vacuous: a value outside the registry, or a 1.7 field in 1.6, is rejected. */
    @Test
    void validatorsRejectInvalidDocuments() throws Exception {
        SourceRule aes = sourceRules().stream().filter(r -> r.id().equals("java.sym.aes")).findFirst().orElseThrow();
        List<Component> comps = List.of(new Component.Crypto(aes, "AES", null,
                List.of(new Component.Occurrence("A.java", 1, "s", aes.id(), "x", null, null, false))));
        String s17 = new String(CbomWriter.write(new CbomWriter.Metadata("1", "r", "sha256:0", true, 1, 0, null), comps),
                StandardCharsets.UTF_8);
        assertTrue(s17.contains("\"primitive\": \"block-cipher\",\n          \"algorithmFamily\": \"AES\""), s17);
        assertTrue(CycloneDxSchemas.validate(s17.getBytes(StandardCharsets.UTF_8), CycloneDxVersion.V1_7).isEmpty());
        byte[] bad = s17.replace("\"algorithmFamily\": \"AES\"", "\"algorithmFamily\": \"NotAFamily\"")
                .getBytes(StandardCharsets.UTF_8);
        assertFalse(CycloneDxSchemas.validate(bad, CycloneDxVersion.V1_7).isEmpty());
        byte[] as16 = s17.replace("\"specVersion\": \"1.7\"", "\"specVersion\": \"1.6\"").getBytes(StandardCharsets.UTF_8);
        assertFalse(CycloneDxSchemas.validate(as16, CycloneDxVersion.V1_6).isEmpty(), "algorithmFamily is not 1.6");
    }

    /** 1.6 output is the pre-1.7 format: no registry fields, only the specVersion of the option. */
    @Test
    void version16HasNoRegistryFields() {
        SourceRule ec = sourceRules().stream().filter(r -> "EC".equals(r.asset().family())
                && "key-agree".equals(r.asset().primitive())).findFirst().orElseThrow();
        List<Component> comps = List.of(new Component.Crypto(ec, "EC", "secp256r1",
                List.of(new Component.Occurrence("A.java", 1, "s", ec.id(), "x", "secp256r1", null, false))));
        String s16 = new String(CbomWriter.write(new CbomWriter.Metadata("1", "r", "sha256:0", true, 1, 0, null, false,
                CycloneDxVersion.V1_6), comps), StandardCharsets.UTF_8);
        String s17 = new String(CbomWriter.write(new CbomWriter.Metadata("1", "r", "sha256:0", true, 1, 0, null, false,
                CycloneDxVersion.V1_7), comps), StandardCharsets.UTF_8);
        assertFalse(s16.contains("algorithmFamily") || s16.contains("ellipticCurve"), s16);
        assertTrue(s17.contains("\"algorithmFamily\": \"ECDH\",\n          \"parameterSetIdentifier\": \"secp256r1\",\n"
                + "          \"ellipticCurve\": \"secg/secp256r1\""), s17);
        // the family property stays for consumers of the 1.6 format
        assertTrue(s17.contains("\"name\": \"ciphersift:family\",\n          \"value\": \"EC\""), s17);
    }
}
