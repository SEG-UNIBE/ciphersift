/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.unibe.seg.ciphersift.TestSupport;
import ch.unibe.seg.ciphersift.files.SourceText;
import ch.unibe.seg.ciphersift.lang.java.JavaAnalyzer;
import ch.unibe.seg.ciphersift.lang.java.JavaContexts;
import ch.unibe.seg.ciphersift.lang.python.PythonAnalyzer;
import ch.unibe.seg.ciphersift.natives.Grammars;
import ch.unibe.seg.ciphersift.rules.RuleLoader;
import ch.unibe.seg.ciphersift.rules.RuleSet;
import ch.unibe.seg.ciphersift.syntax.SyntaxTrees;
import io.github.treesitter.jtreesitter.Parser;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/** The textual pre-filter (DECISIONS follow-up F3) never rejects a file that has findings. */
class AnchorPrefilterTest {
    private static RuleSet rules(String yaml) throws Exception {
        return RuleLoader.load(List.of(new RuleLoader.RuleFile("r.yaml", yaml.getBytes(StandardCharsets.UTF_8))));
    }

    private static final String JAVA = "id: java.t.x\nkind: source\nlanguage: java\nname: t\nasset: {type: algorithm}\n";
    private static final String PY = "id: python.t.x\nkind: source\nlanguage: python\nname: t\nasset: {type: algorithm}\n";

    @Test
    void javaNamesAreRequired() throws Exception {
        AnchorPrefilter f = AnchorPrefilter.java(rules(JAVA + "match:\n- call: javax.crypto.Cipher.getInstance\n"
                + "- new: a.b.Outer.Inner\n- method: setProtocols\n- call: x.y.Util.sha256*\n").javaRules());
        assertFalse(f.mayMatch("class A { void f() { getInstance(); } }"), "member without the class name");
        assertTrue(f.mayMatch("import javax.crypto.Cipher; class A { Object o = Cipher.getInstance(\"AES\"); }"));
        assertFalse(f.mayMatch("x = new Inner();"), "a member type needs its top-level class (SPEC 7.3.2)");
        assertTrue(f.mayMatch("import a.b.Outer.*; class A { Object x = new Inner(); }"));
        assertTrue(f.mayMatch("x = new Outer.Inner();"));
        assertFalse(f.mayMatch("x = new Outer();"));
        assertTrue(f.mayMatch("s.setProtocols(p);"));
        assertTrue(f.mayMatch("Util.sha256Hex(x)"), "prefix member");
        assertFalse(f.mayMatch("Util.sha25(x)"));
        assertTrue(f.mayMatch("// Cipher and getInstance in a comment"), "substrings anywhere: errs towards analysing");
        assertFalse(f.mayMatch("Ciphér.getInstance()"));
        assertFalse(f.mayMatch(""));
    }

    @Test
    void javaAnyCallAcceptsEverythingWhileItsFeatureIsOn() throws Exception {
        List<ch.unibe.seg.ciphersift.rules.SourceRule> r = rules(JAVA + "match:\n- method: setProtocols\n"
                + "- anyCall: true\n  anyString: 'SHA-256$'\n  feature: java-any-call\n").javaRules();
        assertTrue(AnchorPrefilter.java(r).mayMatch("class A {}"), "DECISIONS B-J-SNx: no required name");
        AnchorPrefilter off = AnchorPrefilter.java(r, Features.DEFAULTS.with(Features.JAVA_ANY_CALL, false));
        assertFalse(off.mayMatch("class A {}"));
        assertTrue(off.mayMatch("s.setProtocols(p);"));
    }

    @Test
    void pythonNamesAreRequired() throws Exception {
        AnchorPrefilter f = AnchorPrefilter.python(rules(PY + "match:\n- call: hashlib.md5\n"
                + "- method: [sign, verify]\n  anySymbol: [cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15]\n"
                + "- anyCall: true\n  kwargs: {verify: '^False$'}\n- assign: check_hostname\n").pythonRules());
        assertTrue(f.mayMatch("import hashlib as h\nh.md5()"));
        assertFalse(f.mayMatch("from x import md5\nmd5()"), "every part of the call value is required");
        assertFalse(f.mayMatch("key.sign(m)"), "a symbol condition adds its names");
        assertTrue(f.mayMatch("from cryptography.hazmat.primitives.asymmetric import padding\nk.sign(m, padding.PKCS1v15())"));
        assertTrue(f.mayMatch("requests.get(u, verify=False)"));
        assertTrue(f.mayMatch("ctx.check_hostname = False"));
        assertFalse(f.mayMatch("print('hello')"));
    }

    @Test
    void goNamesAreRequired() throws Exception {
        AnchorPrefilter f = AnchorPrefilter.go(rules("id: go.t.x\nkind: source\nlanguage: go\nname: t\n"
                + "asset: {type: algorithm}\nmatch:\n- call: crypto/aes.NewCipher\n- ref: 'crypto/tls.TLS_*'\n"
                + "- assign: InsecureSkipVerify\n").goRules());
        assertTrue(f.mayMatch("import \"crypto/aes\"\nfunc f() { aes.NewCipher(k) }"));
        assertTrue(f.mayMatch("import x \"crypto/aes\"\nfunc f() { x.NewCipher(k) }"));
        assertFalse(f.mayMatch("func f() { aes.NewCipher(k) }"), "the import path is required");
        assertFalse(f.mayMatch("import \"crypto/aes\"\nfunc f() { aes.NewGCM(k) }"));
        assertTrue(f.mayMatch("import \"crypto/tls\"\nvar s = tls.TLS_AES_128_GCM_SHA256"));
        assertTrue(f.mayMatch("c.InsecureSkipVerify = true"));
    }

    @Test
    void identifierParts() throws Exception {
        assertTrue(AnchorPrefilter.ALL.mayMatch("nothing"));
        assertFalse(AnchorPrefilter.python(List.of()).mayMatch("import hashlib"), "no rules: nothing can fire");
        assertEquals(List.of("random", "SystemRandom", "random"), AnchorPrefilter.identifierParts(
                "random.SystemRandom().random"));
        assertEquals(List.of("encrypt"), AnchorPrefilter.identifierParts("<expr>.encrypt"));
    }

    /** Soundness on the whole conformance suite: a rejected file has no findings. */
    @Test
    void rejectedConformanceFilesHaveNoFindings() throws Exception {
        RuleSet rules = RuleLoader.loadBundled();
        AnchorPrefilter jf = AnchorPrefilter.java(rules.javaRules());
        AnchorPrefilter pf = AnchorPrefilter.python(rules.pythonRules());
        AnchorPrefilter gf = AnchorPrefilter.go(rules.goRules());
        Grammars g = Grammars.get();
        List<Path> files = new ArrayList<>();
        try (Stream<Path> s = Files.walk(TestSupport.casesDir())) {
            s.filter(Files::isRegularFile).filter(p -> p.toString().endsWith(".java") || p.toString().endsWith(".py")
                    || p.toString().endsWith(".go"))
                    .sorted().forEach(files::add);
        }
        int rejected = 0;
        try (Parser jp = new Parser(g.java()); Parser pp = new Parser(g.python()); Parser gp = new Parser(g.go())) {
            JavaContexts ctx = new JavaContexts(TestSupport.casesDir().toRealPath(), g.java(), () -> jp);
            JavaAnalyzer ja = new JavaAnalyzer(rules, ctx);
            PythonAnalyzer pa = new PythonAnalyzer(rules);
            ch.unibe.seg.ciphersift.lang.go.GoAnalyzer ga = new ch.unibe.seg.ciphersift.lang.go.GoAnalyzer(rules);
            for (Path p : files) {
                byte[] bytes = Files.readAllBytes(p);
                if (SourceText.isBinary(bytes)) {
                    continue;
                }
                String text = SourceText.decode(bytes);
                boolean java = p.toString().endsWith(".java");
                boolean go = p.toString().endsWith(".go");
                if ((java ? jf : go ? gf : pf).mayMatch(text)) {
                    continue;
                }
                rejected++;
                var found = java
                        ? ja.analyze(SyntaxTrees.parse(jp, g.java(), text), p.toRealPath(), p.toString(), false)
                        : go ? ga.analyze(SyntaxTrees.parse(gp, g.go(), text), p.toString(), false)
                        : pa.analyze(SyntaxTrees.parse(pp, g.python(), text), p.toString(), false);
                assertTrue(found.isEmpty(), p + ": rejected by the pre-filter but has findings " + found);
            }
        }
        assertTrue(rejected > 0, "some files are rejected");
    }
}
