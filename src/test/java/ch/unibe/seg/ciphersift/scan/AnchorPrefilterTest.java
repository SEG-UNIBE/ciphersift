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

/** The textual pre-filter (DECISIONS F3) never rejects a file that has findings. */
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
        assertTrue(f.mayMatch("x = new Inner();"));
        assertFalse(f.mayMatch("x = new Outer();"));
        assertTrue(f.mayMatch("s.setProtocols(p);"));
        assertTrue(f.mayMatch("Util.sha256Hex(x)"), "prefix member");
        assertFalse(f.mayMatch("Util.sha25(x)"));
        assertTrue(f.mayMatch("// Cipher and getInstance in a comment"), "substrings anywhere: errs towards analysing");
        assertFalse(f.mayMatch("Ciphér.getInstance()"));
        assertFalse(f.mayMatch(""));
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
        Grammars g = Grammars.get();
        List<Path> files = new ArrayList<>();
        try (Stream<Path> s = Files.walk(TestSupport.casesDir())) {
            s.filter(Files::isRegularFile).filter(p -> p.toString().endsWith(".java") || p.toString().endsWith(".py"))
                    .sorted().forEach(files::add);
        }
        int rejected = 0;
        try (Parser jp = new Parser(g.java()); Parser pp = new Parser(g.python())) {
            JavaContexts ctx = new JavaContexts(TestSupport.casesDir().toRealPath(), g.java(), () -> jp);
            JavaAnalyzer ja = new JavaAnalyzer(rules, ctx);
            PythonAnalyzer pa = new PythonAnalyzer(rules);
            for (Path p : files) {
                byte[] bytes = Files.readAllBytes(p);
                if (SourceText.isBinary(bytes)) {
                    continue;
                }
                String text = SourceText.decode(bytes);
                boolean java = p.toString().endsWith(".java");
                if ((java ? jf : pf).mayMatch(text)) {
                    continue;
                }
                rejected++;
                var found = java
                        ? ja.analyze(SyntaxTrees.parse(jp, g.java(), text), p.toRealPath(), p.toString(), false)
                        : pa.analyze(SyntaxTrees.parse(pp, g.python(), text), p.toString(), false);
                assertTrue(found.isEmpty(), p + ": rejected by the pre-filter but has findings " + found);
            }
        }
        assertTrue(rejected > 0, "some files are rejected");
    }
}
