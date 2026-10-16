/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang.python;

import static org.junit.jupiter.api.Assertions.assertEquals;

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

/** Python analysis (SPEC 8), including the depth limits of SPEC 6.3 / DECISIONS M4. */
class PythonAnalysisTest {
    static RuleSet rules;
    static Parser parser;
    static PythonAnalyzer analyzer;

    @BeforeAll
    static void setUp() throws Exception {
        rules = RuleLoader.loadBundled();
        parser = new Parser(Grammars.get().python());
        analyzer = new PythonAnalyzer(rules);
    }

    @AfterAll
    static void tearDown() {
        parser.close();
    }

    private static List<SourceFinding> analyze(String src) {
        return analyzer.analyze(SyntaxTrees.parse(parser, Grammars.get().python(), src), "x.py", false);
    }

    private static String summary(String src) {
        return analyze(src).stream().map(f -> f.line() + ":" + f.rule().id() + ":" + f.name()
                + (f.param() == null ? "" : "[" + f.param() + "]")).collect(Collectors.joining(" "));
    }

    @Test
    void importsAndAliases() {
        assertEquals("2:python.hash.sha1:hashlib.sha1", summary("import hashlib as h\nh.sha1()\n"));
        assertEquals("2:python.hash.md5:hashlib.md5", summary("from hashlib import md5 as m\nm()\n"));
        assertEquals("3:python.hash.md5:hashlib.md5", summary("import hashlib\nH = hashlib.md5\nH()\n"));
        assertEquals("", summary("from .local import md5\nmd5()\n"));
        assertEquals("", summary("import hashlib\nhashlib.sha1x()\n"));
    }

    @Test
    void cycleGuard() {
        // a = b; b = a: resolveName(a) yields [a] (SPEC 8.4.1); must terminate
        assertEquals("", summary("a = b\nb = a\na()\n"));
    }

    @Test
    void parametersShadowConstants() {
        assertEquals("", summary("import hashlib\nALG = 'md5'\ndef f(ALG):\n    hashlib.new(ALG)\n"));
        assertEquals("3:python.hash.md5:hashlib.new", summary("import hashlib\nALG = 'md5'\nhashlib.new(ALG)\n"));
    }

    @Test
    void paramExtraction() {
        assertEquals("2:python.asym.rsa:cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key[2048]",
                summary("from cryptography.hazmat.primitives.asymmetric import rsa\n"
                        + "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"));
        assertEquals("3:python.asym.rsa:cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key[3072]",
                summary("from cryptography.hazmat.primitives.asymmetric import rsa\nKEY_BITS = 3072\n"
                        + "rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)\n"));
    }

    @Test
    void stringsDepthLimit() {
        String twelve = "(".repeat(12) + "'md5'" + ")".repeat(12);
        String thirteen = "(".repeat(13) + "'md5'" + ")".repeat(13);
        assertEquals("2:python.hash.md5:hashlib.new", summary("import hashlib\nhashlib.new(" + twelve + ")\n"));
        assertEquals("", summary("import hashlib\nhashlib.new(" + thirteen + ")\n"));
        String deep = "(".repeat(3000) + "'md5'" + ")".repeat(3000);
        assertEquals("3:python.hash.md5:hashlib.md5",
                summary("import hashlib\nhashlib.new(" + deep + ")\nhashlib.md5()\n"));
    }

    @Test
    void attributeDepthLimit() {
        // 63 attribute levels resolve, more than 64 give no candidates; nothing crashes
        String ok = "hashlib" + ".x".repeat(10) + ".md5";
        assertEquals("", summary("import hashlib\n" + ok + "()\n"));
        String deep = "a" + ".b".repeat(5000);
        assertEquals("", summary(deep + "()\n"));
    }

    @Test
    void bindingStepLimit() {
        // an alias chain of 20 assignments: resolution stops after 16 binding steps (no crash)
        StringBuilder b = new StringBuilder("import hashlib\nv0 = hashlib.md5\n");
        for (int i = 1; i <= 20; i++) {
            b.append("v").append(i).append(" = v").append(i - 1).append('\n');
        }
        b.append("v10()\n");
        b.append("v20()\n");
        assertEquals("23:python.hash.md5:hashlib.md5", summary(b.toString()));
    }

    /**
     * DECISIONS O4: a name whose binding chain exceeds 16 steps is unresolved (no candidates); the
     * fallback to the name reached at the limit does not apply. Within the limit it still does.
     */
    @Test
    void bindingStepLimitGivesUnresolved() {
        StringBuilder chain = new StringBuilder("u0 = md5\n");
        for (int i = 1; i <= 15; i++) {
            chain.append("u").append(i).append(" = u").append(i - 1).append('\n');
        }
        // md5 is reached at step 16 without own bindings: fallback md5, hashlib.md5 (star module)
        assertEquals("18:python.hash.md5:hashlib.md5", summary("from hashlib import *\n" + chain + "u15()\n"));
        // md5 has a binding of its own, which would be step 17: unresolved, no finding
        assertEquals("", summary("from hashlib import *\nmd5 = v\n" + chain + "u15()\n"));
    }

    @Test
    void oneFindingPerRuleAndLine() {
        assertEquals("2:python.hash.md5:hashlib.md5", summary("import hashlib\nhashlib.md5(); hashlib.md5()\n"));
    }

    @Test
    void attributeAssignment() {
        List<SourceFinding> fs = analyze("import ssl\nctx = ssl.SSLContext()\nctx.verify_mode = ssl.CERT_NONE\n");
        SourceFinding f = fs.stream().filter(x -> x.rule().id().equals("python.cert.validation.disabled"))
                .findFirst().orElseThrow();
        assertEquals(3, f.line());
        assertEquals("verify_mode", f.symbol());
        assertEquals("ctx.verify_mode = ssl.CERT_NONE", f.snippet());
    }

    /** SPEC 8.6 emission step 1: only calls inside a recorded argument range of the same rule are dropped. */
    @Test
    void nestingRangesAcrossSiblingsAndLines() {
        assertEquals("2:python.hash.bcrypt:bcrypt.hashpw 3:python.hash.bcrypt:bcrypt.gensalt "
                + "4:python.hash.bcrypt:bcrypt.hashpw 6:python.hash.bcrypt:bcrypt.gensalt",
                summary("import bcrypt\nbcrypt.hashpw(pw, bcrypt.gensalt())\nbcrypt.gensalt()\n"
                        + "bcrypt.hashpw(pw, f(bcrypt.gensalt(),\n    bcrypt.gensalt()))\nf(bcrypt.gensalt())\n"));
        // many findings in one file: the range bookkeeping must stay linear
        String many = "import hashlib\n" + "hashlib.md5(b'x')\n".repeat(50_000);
        long t0 = System.nanoTime();
        assertEquals(50_000, analyze(many).size());
        long ms = (System.nanoTime() - t0) / 1_000_000;
        org.junit.jupiter.api.Assertions.assertTrue(ms < 30_000, "took " + ms + " ms");
    }
}
