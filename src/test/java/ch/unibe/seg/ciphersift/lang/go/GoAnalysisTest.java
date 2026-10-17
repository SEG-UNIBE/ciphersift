/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang.go;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.unibe.seg.ciphersift.model.SourceFinding;
import ch.unibe.seg.ciphersift.natives.Grammars;
import ch.unibe.seg.ciphersift.rules.RuleLoader;
import ch.unibe.seg.ciphersift.rules.RuleSet;
import ch.unibe.seg.ciphersift.syntax.SyntaxTrees;
import io.github.treesitter.jtreesitter.Parser;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Go analysis (SPEC 17). */
class GoAnalysisTest {
    static RuleSet rules;
    static Parser parser;
    static GoAnalyzer analyzer;

    @BeforeAll
    static void setUp() throws Exception {
        rules = RuleLoader.loadBundled();
        parser = new Parser(Grammars.get().go());
        analyzer = new GoAnalyzer(rules);
    }

    @AfterAll
    static void tearDown() {
        parser.close();
    }

    private static List<SourceFinding> analyze(String src) {
        return analyzer.analyze(SyntaxTrees.parse(parser, Grammars.get().go(), src), "x.go", false);
    }

    private static String summary(String src) {
        return analyze(src).stream().map(f -> f.line() + ":" + f.rule().id() + ":" + f.name()
                + (f.param() == null ? "" : "[" + f.param() + "]")).sorted().collect(Collectors.joining(" "));
    }

    private static String file(String imports, String body) {
        return "package p\n" + imports + "\n\nfunc f(k []byte, n int) {\n" + body + "\n}\n";
    }

    @Test
    void defaultLocalNames() {
        assertEquals("aes", GoAnalyzer.defaultLocalName("crypto/aes"));
        assertEquals("rand", GoAnalyzer.defaultLocalName("math/rand/v2"));
        assertEquals("jwt", GoAnalyzer.defaultLocalName("github.com/golang-jwt/jwt/v5"));
        assertEquals("yaml", GoAnalyzer.defaultLocalName("gopkg.in/yaml.v3"));
        assertEquals("v2", GoAnalyzer.defaultLocalName("v2"));
        assertEquals("crypto", GoAnalyzer.defaultLocalName("crypto"));
    }

    @Test
    void interpretedStrings() {
        assertEquals("a\"b\\c\n\t", GoAnalyzer.decodeInterpreted("a\\\"b\\\\c\\n\\t"));
        assertEquals("AES", GoAnalyzer.decodeInterpreted("\\x41\\u0045\\123"));
        assertEquals("😀", GoAnalyzer.decodeInterpreted("\\U0001F600"));
        assertEquals("\\q\\x4", GoAnalyzer.decodeInterpreted("\\q\\x4"), "invalid escapes keep their text");
        assertEquals("\\uD800x", GoAnalyzer.decodeInterpreted("\\uD800x"), "no lone surrogates");
    }

    @Test
    void stringConstantsAndConcatenation() {
        // the analysis has no string-valued Go rule; values are visible through assign value texts
        String src = "package p\nimport \"crypto/tls\"\nconst on = \"tr\" + `ue`\nconst no = 1 + 2\n"
                + "func f(c *tls.Config) {\n c.InsecureSkipVerify = on\n c.InsecureSkipVerify = no == 3\n}\n"
                + "var a = tls.Config{InsecureSkipVerify: (true)}\n";
        assertEquals("6:go.cert.validation.disabled:InsecureSkipVerify 9:go.cert.validation.disabled:InsecureSkipVerify "
                + "9:go.prot.tls.context:crypto/tls.Config", summary(src),
                "a string concatenation and a parenthesised literal are constants; a comparison is not");
    }

    @Test
    void linesAndSnippets() {
        List<SourceFinding> f = analyze(file("import \"crypto/sha256\"", " _ = sha256.\n  Sum256(k)"));
        assertEquals(1, f.size());
        assertEquals(6, f.get(0).line(), "the line of the selector's field");
        assertEquals("sha256.\n  Sum256(k)", f.get(0).snippet());
        assertEquals("crypto/sha256.Sum256", f.get(0).symbol());
        String longCall = " rsa.GenerateKey(nil, " + "1+".repeat(400) + "1)";
        SourceFinding g = analyze(file("import \"crypto/rsa\"", longCall)).get(0);
        assertEquals(500, g.snippet().codePointCount(0, g.snippet().length()));
    }

    @Test
    void deepNestingDoesNotCrash() {
        String deep = "(".repeat(3000) + "2048" + ")".repeat(3000);
        assertEquals("5:go.asym.rsa:crypto/rsa.GenerateKey", summary(file("import \"crypto/rsa\"",
                " rsa.GenerateKey(nil, " + deep + ")")), "beyond the depth limit: unresolved");
        assertEquals("5:go.asym.rsa:crypto/rsa.GenerateKey[2048]", summary(file("import \"crypto/rsa\"",
                " rsa.GenerateKey(nil, ((2048)))")));
        String neg = "^".repeat(3000) + "x";
        assertEquals("5:go.asym.ecdsa:crypto/ecdsa.GenerateKey", summary(file("import \"crypto/ecdsa\"",
                " ecdsa.GenerateKey(" + neg + ", nil)")));
    }

    @Test
    void cyclesAreGuarded() {
        String src = file("import (\"crypto/rsa\"; \"crypto/cipher\")",
                " a := b\n b := a\n rsa.GenerateKey(nil, a)\n cipher.NewGCM(b)");
        assertEquals("7:go.asym.rsa:crypto/rsa.GenerateKey 8:go.sym.mode.gcm:crypto/cipher.NewGCM", summary(src));
    }

    @Test
    void scopesAndShadowing() {
        // a parameter n shadows the package constant n; a closure sees the outer variable
        String src = "package p\nimport \"crypto/rsa\"\nconst n = 1024\nconst m = 4096\n"
                + "func f(n int) { rsa.GenerateKey(nil, n) }\n"
                + "func g() { x := m; func() { rsa.GenerateKey(nil, x) }() }\n"
                + "func h() { rsa.GenerateKey(nil, n) }\n";
        assertEquals("5:go.asym.rsa:crypto/rsa.GenerateKey 6:go.asym.rsa:crypto/rsa.GenerateKey[4096] "
                + "7:go.asym.rsa:crypto/rsa.GenerateKey[1024]", summary(src));
    }

    @Test
    void plainAssignmentsBindWhereDeclared() {
        String src = "package p\nimport \"crypto/rsa\"\nvar bits = 2048\nfunc set() { bits = 4096 }\n"
                + "func f() { rsa.GenerateKey(nil, bits) }\n"
                + "func g() { b := 2048; func() { b = 1024 }(); rsa.GenerateKey(nil, b) }\n";
        assertEquals("5:go.asym.rsa:crypto/rsa.GenerateKey 6:go.asym.rsa:crypto/rsa.GenerateKey", summary(src));
    }

    @Test
    void weaknessIndicatorPrefixAndExportedDotNames() {
        assertEquals("5:go.rand.prng.insecure:math/rand.Intn", summary(file("import \"math/rand\"", " rand.Intn(n)")));
        // with a dot import of math/rand, only exported (upper-case) identifiers get names
        assertEquals("5:go.rand.prng.insecure:math/rand.Intn", summary(file("import . \"math/rand\"",
                " _ = len(k); Intn(n); _ = n")));
    }

    @Test
    void selectionAndNesting() {
        // HMAC and SHA-256 are different families: both; P256 inside GenerateKey has the family EC: folded
        assertEquals("5:go.hash.sha2:crypto/sha256.New 5:go.mac.hmac:crypto/hmac.New",
                summary(file("import (\"crypto/hmac\"; \"crypto/sha256\")", " hmac.New(sha256.New, k)")));
        assertEquals("5:go.asym.ecdsa:crypto/ecdsa.GenerateKey[P-256]",
                summary(file("import (\"crypto/ecdsa\"; \"crypto/elliptic\")", " ecdsa.GenerateKey(elliptic.P256(), nil)")));
        // on its own line the curve is a finding of its own
        assertEquals("5:go.asym.ec:crypto/elliptic.P256[P-256] 6:go.asym.ecdsa:crypto/ecdsa.GenerateKey[P-256]",
                summary(file("import (\"crypto/ecdsa\"; \"crypto/elliptic\")",
                        " c := elliptic.P256()\n ecdsa.GenerateKey(c, nil)")));
    }

    @Test
    void testFlag() {
        List<SourceFinding> f = analyzer.analyze(SyntaxTrees.parse(parser, Grammars.get().go(),
                file("import \"crypto/md5\"", " md5.Sum(k)")), "a_test.go", true);
        assertTrue(f.get(0).test());
    }

    @Test
    void noRulesNoFindings() throws Exception {
        RuleSet none = RuleLoader.load(List.of());
        GoAnalyzer a = new GoAnalyzer(none);
        assertEquals(List.of(), a.analyze(SyntaxTrees.parse(parser, Grammars.get().go(),
                file("import \"crypto/md5\"", " md5.Sum(k)")), "x.go", false));
    }
}
