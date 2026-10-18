/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.rules;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.unibe.seg.ciphersift.TestSupport;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/** Rule loading and validation (SPEC 5, 5.8). */
class RuleLoaderTest {
    private static final String HEAD = "id: java.t.x\nkind: source\nlanguage: java\nname: t\nasset: {type: algorithm}\n";

    private static RuleException fail(String path, String yaml) {
        return assertThrows(RuleException.class, () -> RuleLoader.load(List.of(
                new RuleLoader.RuleFile(path, yaml.getBytes(StandardCharsets.UTF_8)))));
    }

    @Test
    void bundledRuleSet() throws Exception {
        RuleSet r = RuleLoader.loadBundled();
        assertEquals(105, r.javaRules().size()); // + java.key.load.public, .private (DECISIONS B-J-KL)
        assertEquals(89, r.pythonRules().size()); // + python.hash.unresolved, python.cipher.unresolved (B-P-U1)
        assertEquals(70, r.goRules().size()); // DECISIONS T11: + go.asym.ed448, go.asym.x448; B-G-B2: + go.pqc.slhdsa
        assertNotNull(r.dependencyRule("golang"));
        assertTrue(r.dependencyRule("golang").matches("github.com/golang-jwt/jwt/v5"));
        assertFalse(r.dependencyRule("golang").matches("golang.org/x/crypto/ssh"), "a pattern covers the whole key");
        // DECISIONS F3: crypto services are listed, general platform clients and data-model modules are not
        assertTrue(r.dependencyRule("golang").matches("github.com/aws/aws-sdk-go-v2/service/kms"));
        // DECISIONS B-G4 (owner decision): these two exceptions are listed now
        assertTrue(r.dependencyRule("golang").matches("github.com/hashicorp/vault/api"));
        assertTrue(r.dependencyRule("golang").matches("github.com/sigstore/protobuf-specs"));
        assertFalse(r.dependencyRule("golang").matches("github.com/hashicorp/vault/sdk"));
        // DECISIONS B-J4: commons-codec only where its digest package is used
        assertEquals(java.util.List.of("org.apache.commons.codec.digest"),
                r.dependencyRule("maven").usedIf("commons-codec:commons-codec"));
        assertEquals(java.util.List.of(), r.dependencyRule("maven").usedIf("org.bouncycastle:bcprov-jdk18on"));
        for (int i = 1; i < r.goRules().size(); i++) {
            assertTrue(r.goRules().get(i - 1).id().compareTo(r.goRules().get(i).id()) < 0, "id order");
        }
        assertEquals(1, r.constantsDocuments());
        assertNotNull(r.dependencyRule("maven"));
        assertNotNull(r.dependencyRule("pypi"));
        assertEquals("SHA-256", r.javaConstant("MessageDigestAlgorithms", "SHA_256"));
        for (int i = 1; i < r.javaRules().size(); i++) {
            assertTrue(r.javaRules().get(i - 1).id().compareTo(r.javaRules().get(i).id()) < 0, "id order");
        }
        assertTrue(r.dependencyRule("maven").matches("ORG.BOUNCYCASTLE:bcprov-jdk18on"));
        assertFalse(r.dependencyRule("maven").matches("com.google.guava:guava"));
        // the bundled set equals the repository's rules/ directory
        RuleSet dir = RuleLoader.loadDirectory(TestSupport.baseDir().resolve("rules"));
        assertEquals(r.digest(), dir.digest());
    }

    /** Every bundled rule document validates on its own against the schema and the semantic checks. */
    @TestFactory
    Stream<DynamicTest> everyBundledRuleValidates() throws Exception {
        List<DynamicTest> tests = new ArrayList<>();
        for (RuleLoader.RuleFile f : RuleLoader.bundledFiles()) {
            tests.add(DynamicTest.dynamicTest(f.path(), () -> RuleLoader.load(List.of(f))));
        }
        assertEquals(268, tests.size()); // + go.pqc.slhdsa (B-G-B2), java.key.load.* (B-J-KL), python.*.unresolved (B-P-U1)
        return tests.stream();
    }

    /** The keys added with the evaluation fixes (SPEC 5.3, 5.6): indicator, ref, dictItems, notInside, param.value. */
    @Test
    void evaluationFixKeys() throws Exception {
        String py = "id: python.t.x\nkind: source\nlanguage: python\nname: t\nasset: {type: algorithm}\n";
        RuleSet ok = RuleLoader.load(List.of(new RuleLoader.RuleFile("ok.yaml", (py.replace("asset:", "indicator: weakness\nasset:")
                + "match:\n- ref: a.B.C\n  param: {value: x}\n- ref: a.B.D\n  param: {self: true}\n"
                + "- call: a.f\n  dictItems: {algorithm: '^sha'}\n- call: a.g\n  notInside: [sign]\n")
                .getBytes(StandardCharsets.UTF_8))));
        SourceRule r = ok.pythonRules().get(0);
        assertEquals("weakness", r.indicator());
        assertEquals("a.B.C", r.pythonPatterns().get(0).ref);
        assertEquals("x", r.pythonPatterns().get(0).paramValue);
        assertTrue(r.pythonPatterns().get(0).matchesReferences());
        assertFalse(r.pythonPatterns().get(2).matchesReferences(), "a filtered call pattern needs arguments");
        assertTrue(fail("i.yaml", py.replace("asset:", "indicator: maybe\nasset:") + "match:\n- call: a.b\n").getMessage()
                .contains("i.yaml: /indicator"));
        assertTrue(fail("r.yaml", py + "match:\n- ref: a.b\n  firstString: x\n").getMessage().contains("r.yaml: /match/0"));
        assertTrue(fail("k.yaml", py + "match:\n- ref: a.b\n  param: {keyword: k}\n").getMessage().contains("k.yaml: /match/0"));
        assertTrue(fail("c.yaml", py + "match:\n- ref: a.b\n  call: a.c\n").getMessage().contains("c.yaml: /match/0"));
        assertTrue(fail("v.yaml", py + "match:\n- call: a.b\n  param: {value: x, index: 0}\n").getMessage()
                .contains("v.yaml: /match/0/param"));
        assertTrue(fail("j.yaml", HEAD + "match:\n- call: a.B.c\n  param: {value: x}\n").getMessage()
                .contains("only contain \"index\""));
    }

    @Test
    void schemaErrorsNameFileAndPointer() {
        RuleException e = fail("a.yaml", HEAD + "match:\n- call: a.B.c\n  bogus: 1\n");
        assertTrue(e.getMessage().contains("a.yaml: /match/0:"), e.getMessage());
        assertTrue(e.getMessage().contains("bogus"), e.getMessage());
        RuleException proto = fail("p.yaml", "id: java.t.p\nkind: source\nlanguage: java\nname: t\n"
                + "asset: {type: protocol}\nmatch:\n- method: x\n");
        assertTrue(proto.getMessage().contains("p.yaml: /asset:"), proto.getMessage());
    }

    @Test
    void semanticChecks() {
        assertTrue(fail("r.yaml", HEAD + "match:\n- call: a.B.c\n  firstString: \"((\"\n").getMessage()
                .contains("r.yaml: /match/0/firstString: invalid regular expression"));
        assertTrue(fail("p.yaml", HEAD + "match:\n- call: a.B.c\n  param: {keyword: k}\n").getMessage()
                .contains("/match/0/param/keyword"));
        RuleException dup = assertThrows(RuleException.class, () -> RuleLoader.load(List.of(
                new RuleLoader.RuleFile("a.yaml", (HEAD + "match:\n- method: x\n").getBytes(StandardCharsets.UTF_8)),
                new RuleLoader.RuleFile("b.yaml", (HEAD + "match:\n- method: y\n").getBytes(StandardCharsets.UTF_8)))));
        assertTrue(dup.getMessage().contains("duplicate rule id java.t.x"), dup.getMessage());
        String consts = "kind: constants\nlanguage: java\nconstants: {A: {B: c}}\n";
        RuleException two = assertThrows(RuleException.class, () -> RuleLoader.load(List.of(
                new RuleLoader.RuleFile("a.yaml", ("id: java.c1\n" + consts).getBytes(StandardCharsets.UTF_8)),
                new RuleLoader.RuleFile("b.yaml", ("id: java.c2\n" + consts).getBytes(StandardCharsets.UTF_8)))));
        assertTrue(two.getMessage().contains("second constants document"), two.getMessage());
        assertTrue(fail("m.yaml", HEAD + "---\n" + HEAD).getMessage().contains("exactly one document"));
        assertTrue(fail("e.yaml", "").getMessage().contains("e.yaml"));
        assertTrue(fail("j.json", "{\"id\": 1").getMessage().contains("j.json"));
    }

    @Test
    void yaml12Booleans() throws Exception {
        // "yes" / "on" are strings in YAML 1.2: valid as a method name and a regex
        RuleSet r = RuleLoader.load(List.of(new RuleLoader.RuleFile("y.yaml",
                (HEAD + "match:\n- method: on\n  firstString: yes\n").getBytes(StandardCharsets.UTF_8))));
        JavaPattern p = r.javaRules().get(0).javaPatterns().get(0);
        assertEquals("on", p.member);
        assertEquals("yes", p.firstString.pattern());
        assertEquals(2, p.specificity);
    }

    @Test
    void directoryLoadingIgnoresOtherFiles() throws Exception {
        Path d = Files.createTempDirectory("rules");
        Files.createDirectories(d.resolve("sub"));
        Files.writeString(d.resolve("sub/x.yml"), HEAD + "match:\n- method: x\n");
        Files.writeString(d.resolve("README.md"), "not a rule");
        RuleSet r = RuleLoader.loadDirectory(d);
        assertEquals(1, r.javaRules().size());
        assertEquals("sub/x.yml", r.javaRules().get(0).file());
    }

    @Test
    void packagePatterns() {
        DependencyRule r = new DependencyRule("dep.x", "maven", "x", List.of(
                DependencyRule.compilePackage("org.bouncycastle:*"), DependencyRule.compilePackage("a.b:c*d")));
        assertTrue(r.matches("org.bouncycastle:bcprov"));
        assertTrue(r.matches("a.b:c-x.y-d"));
        assertFalse(r.matches("a.bx:cd"));
        assertFalse(r.matches("org.bouncycastle"));
    }

    /** DECISIONS O6: {@code new: X*} is rejected at load time. */
    @Test
    void newAnchorWithStarRejected() {
        RuleException e = fail("n.yaml", HEAD + "match:\n- new: a.b.C*\n");
        assertTrue(e.getMessage().contains("n.yaml: /match/0/new"), e.getMessage());
        assertTrue(e.getMessage().contains("\"*\" is not allowed"), e.getMessage());
    }

    /** DECISIONS O2: {@code param} does not make a Java pattern specific. */
    @Test
    void paramIsNotACondition() throws Exception {
        RuleSet r = RuleLoader.load(List.of(new RuleLoader.RuleFile("p.yaml", (HEAD
                + "match:\n- call: a.B.c\n  param: {index: 0}\n- call: a.B.d\n  param: {index: 0}\n  anyString: x\n"
                + "- call: a.B.e\n").getBytes(StandardCharsets.UTF_8))));
        List<JavaPattern> ps = r.javaRules().get(0).javaPatterns();
        assertEquals(1, ps.get(0).specificity, "anchor + param is bare");
        assertEquals(2, ps.get(1).specificity, "a real condition is specific");
        assertEquals(1, ps.get(2).specificity);
    }

    /** DECISIONS O6: symbolic links inside a rule directory are rule errors; the directory itself may be a link. */
    @Test
    void symbolicLinksInRuleDirectories(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path dir = Files.createDirectories(tmp.resolve("rules/java"));
        Files.writeString(dir.resolve("a.yaml"), HEAD + "match:\n- call: a.B.c\n");
        Path outside = Files.writeString(tmp.resolve("outside.yaml"),
                HEAD.replace("java.t.x", "java.t.y") + "match:\n- call: a.B.c\n");
        Path dirLink = tmp.resolve("linked-rules");
        try {
            Files.createSymbolicLink(dirLink, tmp.resolve("rules"));
        } catch (UnsupportedOperationException | java.io.IOException ex) {
            return; // no symbolic links here
        }
        assertEquals(1, RuleLoader.loadDirectory(dirLink).javaRules().size(), "the directory argument may be a link");
        Files.createSymbolicLink(dir.resolve("b.yaml"), outside);
        RuleException e = assertThrows(RuleException.class, () -> RuleLoader.loadDirectory(tmp.resolve("rules")));
        assertEquals(List.of("java/b.yaml: (document): symbolic links are not allowed in a rule directory"),
                e.problems());
    }

    /**
     * DECISIONS follow-up F2: the bundled set is loaded without schema validation only when it is the set that the
     * build validated; the result equals a full validation.
     */
    @Test
    void trustedBundledLoadEqualsFullValidation() throws Exception {
        List<RuleLoader.RuleFile> files = RuleLoader.bundledFiles();
        byte[] schema = RuleLoader.resourceBytes("schema/rule-schema.json");
        byte[] bundle = RuleLoader.resourceBytes(RuleLoader.BUNDLE_RESOURCE);
        assertNotNull(bundle, "the build step wrote the pre-parsed bundle");
        String marker = new String(RuleLoader.resourceBytes(RuleLoader.VALIDATED_RESOURCE), StandardCharsets.UTF_8).strip();
        assertEquals(marker, RuleLoader.validationKey(files, schema, bundle));
        RuleSet trusted = RuleLoader.loadTrusted(files, bundle);
        RuleSet full = RuleLoader.load(files);
        assertNotNull(trusted);
        assertEquals(full.digest(), trusted.digest());
        assertEquals(ids(full), ids(trusted));
        // any change to a file or the bundle changes the key, so the full validation runs instead
        List<RuleLoader.RuleFile> changed = new ArrayList<>(files);
        RuleLoader.RuleFile f0 = changed.get(0);
        changed.set(0, new RuleLoader.RuleFile(f0.path(), (new String(f0.bytes(), StandardCharsets.UTF_8) + "\n")
                .getBytes(StandardCharsets.UTF_8)));
        assertFalse(marker.equals(RuleLoader.validationKey(changed, schema, bundle)));
        byte[] otherBundle = bundle.clone();
        otherBundle[otherBundle.length - 1] = ' ';
        assertFalse(marker.equals(RuleLoader.validationKey(files, schema, otherBundle)));
        // a bundle that does not fit the files is refused
        assertEquals(null, RuleLoader.loadTrusted(files.subList(1, files.size()), bundle));
        assertEquals(null, RuleLoader.loadTrusted(files, "[]".getBytes(StandardCharsets.UTF_8)));
    }

    /** The streaming reader gives the same trees as the object mapper (also for unusual scalars). */
    @Test
    void streamingReaderEqualsMapper() throws Exception {
        String yaml = "a: 1\nb: 12345678901\nc: 123456789012345678901234567890\nd: 1.5\ne: true\nf: yes\n"
                + "g: null\nh: [1, [2, {x: y}], []]\ni: {}\nj: 'it''s'\nk: ~\n";
        RuleLoader.RuleFile f = new RuleLoader.RuleFile("t.yaml", yaml.getBytes(StandardCharsets.UTF_8));
        assertEquals(RuleLoader.parse(f), TreeReader.read(f.path(), f.bytes()));
        RuleLoader.RuleFile j = new RuleLoader.RuleFile("t.json",
                "{\"a\": [1, 2.5, \"x\", null, false, {\"b\": {}}]}".getBytes(StandardCharsets.UTF_8));
        assertEquals(RuleLoader.parse(j), TreeReader.read(j.path(), j.bytes()));
        assertThrows(java.io.IOException.class, () -> TreeReader.read("d.yaml",
                "a: 1\na: 2\n".getBytes(StandardCharsets.UTF_8)), "duplicate keys");
        assertThrows(java.io.IOException.class, () -> TreeReader.read("m.yaml",
                "a: 1\n---\nb: 2\n".getBytes(StandardCharsets.UTF_8)), "two documents");
    }

    /** Go patterns (SPEC 17.3): anchors, conditions per anchor, the import path. */
    @Test
    void goPatterns() throws Exception {
        String go = "id: go.t.x\nkind: source\nlanguage: go\nname: t\nasset: {type: algorithm}\n";
        RuleSet ok = RuleLoader.load(List.of(new RuleLoader.RuleFile("r.yaml", (go + "match:\n"
                + "- call: crypto/cipher.NewGCM\n  anySymbol: [crypto/aes.NewCipher]\n"
                + "- call: 'math/rand.*'\n- ref: 'crypto/tls.TLS_*'\n- composite: crypto/tls.Config\n"
                + "- assign: InsecureSkipVerify\n  value: ^true$\n- call: crypto.SHA256\n  param: {value: x}\n"
                + "- call: golang.org/x/crypto/sha3.New256\n  param: {index: 0}\n")
                .getBytes(StandardCharsets.UTF_8))));
        var ps = ok.goRules().get(0).goPatterns();
        assertEquals("crypto/cipher", ps.get(0).path);
        assertEquals(2, ps.get(0).specificity);
        assertFalse(ps.get(0).matchesReferences(), "a call pattern with anySymbol needs arguments");
        assertTrue(ps.get(1).prefix);
        assertEquals("math/rand", ps.get(1).path);
        assertEquals("", ps.get(1).member());
        assertTrue(ps.get(1).nameMatches("math/rand.Intn"));
        assertFalse(ps.get(1).nameMatches("math/rand/v2.IntN"));
        assertEquals("TLS_", ps.get(2).member());
        assertEquals(2, ps.get(4).specificity);
        assertEquals("crypto", ps.get(5).path);
        assertEquals("golang.org/x/crypto/sha3", ps.get(6).path);
        fail("r.yaml", go + "match:\n- ref: crypto/tls.VersionTLS12\n  anySymbol: [crypto/aes.NewCipher]\n");
        fail("r.yaml", go + "match:\n- call: crypto/aes.NewCipher\n  value: x\n");
        fail("r.yaml", go + "match:\n- ref: crypto/rand.Reader\n  param: {index: 0}\n");
        fail("r.yaml", go + "match:\n- composite: 'crypto/tls.Conf*'\n");
        fail("r.yaml", go + "match:\n- call: NewCipher\n");
        fail("r.yaml", go + "match:\n- call: crypto/aes.NewCipher\n  kwargs: {a: b}\n");
        fail("r.yaml", "id: python.t.x\nkind: source\nlanguage: go\nname: t\nasset: {type: algorithm}\n"
                + "match:\n- call: crypto/aes.NewCipher\n");
    }

    private static List<String> ids(RuleSet r) {
        List<String> l = new ArrayList<>();
        r.javaRules().forEach(x -> l.add(x.id() + "/" + x.javaPatterns().size()));
        r.pythonRules().forEach(x -> l.add(x.id() + "/" + x.pythonPatterns().size()));
        r.goRules().forEach(x -> l.add(x.id() + "/" + x.goPatterns().size()));
        return l;
    }
}
