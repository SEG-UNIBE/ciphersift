/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.cbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.unibe.seg.ciphersift.model.DependencyFinding;
import ch.unibe.seg.ciphersift.model.SourceFinding;
import ch.unibe.seg.ciphersift.rules.RuleLoader;
import ch.unibe.seg.ciphersift.rules.RuleSet;
import ch.unibe.seg.ciphersift.rules.SourceRule;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Normalisation (SPEC 10) and CBOM output (SPEC 11): references, serial number, purl, JSON format. */
class CbomTest {
    static RuleSet rules;

    @BeforeAll
    static void load() throws Exception {
        rules = RuleLoader.loadBundled();
    }

    static SourceRule rule(String id) {
        for (SourceRule r : rules.javaRules()) {
            if (r.id().equals(id)) {
                return r;
            }
        }
        for (SourceRule r : rules.pythonRules()) {
            if (r.id().equals(id)) {
                return r;
            }
        }
        throw new IllegalArgumentException(id);
    }

    @Test
    void bomRefsOfTheSpecExample() {
        assertEquals("algorithm:caf89428cf58e2f1", shortRef(new Component.Crypto(
                rule("java.jca.messagedigest.unresolved"), "MessageDigest.getInstance", null, List.of())));
        assertEquals("related-crypto-material:0cc7bc8e6739667a", shortRef(new Component.Crypto(
                rule("java.key.hardcoded"), "Hard-coded symmetric key in Java", null, List.of())));
        assertEquals("protocol:f9c01d353de6ce03", shortRef(new Component.Crypto(
                rule("java.prot.tls.v1_2"), "TLS 1.2", null, List.of())));
        assertEquals("algorithm:ad387c99838b1bb7", shortRef(new Component.Crypto(
                rule("java.sym.aes"), "AES", null, List.of())));
        assertEquals("algorithm:310d0bda93ac2b84", shortRef(new Component.Crypto(
                rule("java.sym.aes.gcm"), "AES/GCM/NoPadding", null, List.of())));
        assertEquals("algorithm:4a7c8a2e3b5f84f9", shortRef(new Component.Crypto(rule("python.asym.rsa"),
                "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key", "2048", List.of())));
    }

    private static String shortRef(Component.Crypto c) {
        String f = CbomWriter.fullRef(c);
        return f.substring(0, f.lastIndexOf(':') + 17);
    }

    @Test
    void collidingRefsUseAllDigits() {
        Component.Crypto a = new Component.Crypto(rule("java.sym.aes"), "AES", null, List.of());
        Component.Crypto b = new Component.Crypto(rule("java.sym.aes"), "AES", null, List.of());
        var refs = CbomWriter.bomRefs(List.of(a, b));
        assertEquals(64 + "algorithm:".length(), refs.get(a).length());
        assertEquals(refs.get(a), refs.get(b));
    }

    @Test
    void serialNumberIsVersion8Uuid() {
        String s = CbomWriter.serialNumber("x".getBytes(StandardCharsets.UTF_8));
        assertTrue(Pattern.matches("urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", s), s);
        // SHA-256("x") = 2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881
        assertEquals("urn:uuid:2d711642-b726-8044-8162-7ca9fbac32f5", s);
    }

    @Test
    void purls() {
        assertEquals("pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1",
                Purl.maven("org.bouncycastle", "bcprov-jdk18on", "1.78.1"));
        assertEquals("pkg:pypi/argon2-cffi", Purl.pypi("argon2-cffi", null));
        assertEquals("pkg:maven/a/b@1.0%2Bbuild%20x%C3%A9", Purl.maven("a", "b", "1.0+build xé"));
    }

    @Test
    void jsonFormatAndEscaping() {
        SourceFinding f = new SourceFinding("dir/über.java", 3, rule("java.sym.aes"), "AES", "sym",
                "a\"b\\c/d\te\nf\u0001é", null, true);
        DependencyFinding d = new DependencyFinding("pom.xml", rules.dependencyRule("maven"), "maven",
                "org.bouncycastle:bcprov", null, "pom", "org.bouncycastle:bcprov", false);
        List<Component> comps = Normaliser.normalise(List.of(f), List.of(d));
        byte[] doc = CbomWriter.write(new CbomWriter.Metadata("1.0.0", "root", "sha256:00", true, 2, 0, null), comps);
        String s = new String(doc, StandardCharsets.UTF_8);
        assertTrue(s.endsWith("}\n"));
        assertFalse(s.contains("\r"));
        assertFalse(s.contains(" \n"), "trailing spaces");
        assertTrue(s.contains("\"location\": \"dir/über.java\""), "non-ASCII and / unescaped");
        assertTrue(s.contains("a\\\\\\\"b\\\\\\\\c/d\\\\te\\\\nf\\\\u0001é"), s);
        assertTrue(s.contains("{\\\"ruleId\\\":\\\"java.sym.aes\\\",\\\"snippet\\\":"), s);
        assertTrue(s.contains("\\\"test\\\":true}"), s);
        assertTrue(s.contains("\"name\": \"ciphersift:testOnly\""));
        assertTrue(s.contains("\"dependsOn\": [\n        \"pkg:maven/org.bouncycastle/bcprov\"\n      ]"), s);
        assertFalse(s.contains("timestamp"));
        // empty component list
        String empty = new String(CbomWriter.write(new CbomWriter.Metadata("1", "r", "sha256:0", false, 0, 0, 0L),
                List.of()), StandardCharsets.UTF_8);
        assertTrue(empty.contains("\"components\": []"), empty);
        assertFalse(empty.contains("dependencies"));
        assertTrue(empty.contains("\"timestamp\": \"1970-01-01T00:00:00Z\""));
    }

    @Test
    void additionalContextEscapes() {
        Component.Occurrence o = new Component.Occurrence("a", 1, "s", "r", "x\b\f\r\u001f", "p", null, false);
        assertEquals("{\"ruleId\":\"r\",\"snippet\":\"x\\b\\f\\r\\u001F\",\"param\":\"p\"}",
                CbomWriter.additionalContext(o).replace("\\u001f", "\\u001F"));
    }

    @Test
    void occurrenceDeduplication() {
        SourceRule r = rule("java.sym.aes");
        SourceFinding a = new SourceFinding("A.java", 3, r, "AES", "z.sym", "snippet2", null, false);
        SourceFinding b = new SourceFinding("A.java", 3, r, "AES", "a.sym", "snippet1", null, false);
        SourceFinding c = new SourceFinding("A.java", 4, r, "AES", "a.sym", "snippet1", null, false);
        List<Component> comps = Normaliser.normalise(List.of(a, b, c), List.of());
        assertEquals(1, comps.size());
        assertEquals(2, comps.get(0).occurrences().size());
        assertEquals("a.sym", comps.get(0).occurrences().get(0).symbol());
        // different names behind the same rule are different components, sorted by name
        SourceFinding d = new SourceFinding("A.java", 5, r, "AES_128", "x", "y", null, false);
        assertEquals(List.of("AES", "AES_128"), Normaliser.normalise(List.of(d, a), List.of()).stream()
                .map(x -> ((Component.Crypto) x).name()).toList());
    }

    @Test
    void componentNames() {
        assertEquals("TLS 1.2", Normaliser.componentName(rule("java.prot.tls.v1_2"), "TLSv1.2"));
        assertEquals("Hard-coded symmetric key in Java", Normaliser.componentName(rule("java.key.hardcoded"), "x"));
        assertEquals("gcm", CbomWriter.mode("GCM"));
        assertEquals("other", CbomWriter.mode("GCM-SIV"));
        assertEquals(null, CbomWriter.mode("Poly1305"));
        assertEquals("secret-key", CbomWriter.relatedType("hardcoded-key"));
        assertEquals("other", CbomWriter.relatedType(null));
        assertEquals("private-key", CbomWriter.relatedType("private-key"));
        assertEquals("public-key", CbomWriter.relatedType("public-key"));
        assertEquals("signature", CbomWriter.relatedType("cms-signed-data"));
        assertEquals("ciphertext", CbomWriter.relatedType("cms-enveloped-data"));
        assertEquals("other", CbomWriter.relatedType("domain-parameters"));
    }

    /** Weakness indicators (SPEC 11.3.4, 11.2.1; DECISIONS E2). */
    @Test
    void weaknessIndicatorProperty() {
        SourceFinding prng = new SourceFinding("A.java", 3, rule("java.rand.prng.insecure"), "x", "java.util.Random",
                "new Random()", null, false);
        SourceFinding aes = new SourceFinding("A.java", 4, rule("java.sym.aes"), "AES", "s", "s", null, false);
        List<Component> comps = Normaliser.normalise(List.of(prng, aes), List.of());
        String s = new String(CbomWriter.write(new CbomWriter.Metadata("1", "r", "sha256:0", true, 1, 0, null), comps),
                StandardCharsets.UTF_8);
        assertTrue(s.contains("\"name\": \"ciphersift:subtype\",\n          \"value\": \"prng-insecure\"\n        },\n"
                + "        {\n          \"name\": \"ciphersift:indicator\",\n          \"value\": \"weakness\""), s);
        assertEquals(1, s.split("ciphersift:indicator", -1).length - 1, "only the indicator rule's component");
        assertFalse(s.contains("ciphersift:weaknessIndicators"), "absent in a default scan");
        String included = new String(CbomWriter.write(new CbomWriter.Metadata("1", "r", "sha256:0", true, 1, 0, null,
                true), List.of()), StandardCharsets.UTF_8);
        assertTrue(included.contains("\"name\": \"ciphersift:weaknessIndicators\",\n        \"value\": \"included\""),
                included);
    }

    /** An OID (SPEC 5.11): {@code cryptoProperties.oid}, part of the key; bom-refs without OID unchanged. */
    @Test
    void oidIsWrittenAndSeparatesComponents() {
        SourceFinding byName = new SourceFinding("A.java", 3, rule("java.hash.sha2"), "SHA-256", "s", "s", null, false);
        SourceFinding byOid = new SourceFinding("A.java", 4, rule("java.hash.sha2"), "SHA-256", "s", "s", null,
                "2.16.840.1.101.3.4.2.1", false);
        List<Component> comps = Normaliser.normalise(List.of(byOid, byName), List.of());
        assertEquals(2, comps.size());
        assertNull(((Component.Crypto) comps.get(0)).oid(), "no OID sorts first");
        String s = new String(CbomWriter.write(new CbomWriter.Metadata("1", "r", "sha256:0", true, 1, 0, null), comps),
                StandardCharsets.UTF_8);
        assertTrue(s.contains("\"primitive\": \"hash\"\n        },\n        \"oid\": \"2.16.840.1.101.3.4.2.1\"\n      }"), s);
        assertEquals(1, s.split("\"oid\"", -1).length - 1);
        String plain = CbomWriter.fullRef((Component.Crypto) comps.get(0));
        assertEquals("algorithm:" + CbomWriter.sha256Hex(CbomWriter.compactArray("algorithm", "java.hash.sha2", "SHA-256", "")
                .getBytes(StandardCharsets.UTF_8)), plain);
        assertEquals("algorithm:" + CbomWriter.sha256Hex(CbomWriter.compactArray("algorithm", "java.hash.sha2", "SHA-256", "",
                "2.16.840.1.101.3.4.2.1").getBytes(StandardCharsets.UTF_8)), CbomWriter.fullRef((Component.Crypto) comps.get(1)));
    }
}
