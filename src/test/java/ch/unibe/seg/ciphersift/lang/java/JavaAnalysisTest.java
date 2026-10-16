/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang.java;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.unibe.seg.ciphersift.model.SourceFinding;
import ch.unibe.seg.ciphersift.natives.Grammars;
import ch.unibe.seg.ciphersift.rules.RuleLoader;
import ch.unibe.seg.ciphersift.rules.RuleSet;
import ch.unibe.seg.ciphersift.syntax.SyntaxNode;
import ch.unibe.seg.ciphersift.syntax.SyntaxTrees;
import io.github.treesitter.jtreesitter.Parser;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Java analysis (SPEC 7): strings, denotes, resolution, selection, findings. */
class JavaAnalysisTest {
    static RuleSet rules;
    static Parser parser;

    @TempDir
    Path root;

    @BeforeAll
    static void setUp() throws Exception {
        rules = RuleLoader.loadBundled();
        parser = new Parser(Grammars.get().java());
    }

    @AfterAll
    static void tearDown() {
        parser.close();
    }

    private List<SourceFinding> analyze(String rel, String src) throws Exception {
        Path canonical = root.toRealPath();
        Path file = canonical.resolve(rel);
        Files.createDirectories(file.getParent());
        Files.writeString(file, src);
        JavaContexts ctx = new JavaContexts(canonical, Grammars.get().java(), () -> parser);
        SyntaxNode tree = SyntaxTrees.parse(parser, Grammars.get().java(), src);
        return new JavaAnalyzer(rules, ctx).analyze(tree, file, rel, false);
    }

    private static String summary(List<SourceFinding> fs) {
        return fs.stream().map(f -> f.line() + ":" + f.rule().id() + ":" + f.name())
                .sorted().collect(Collectors.joining(" "));
    }

    @Test
    void escapesAndTextBlocks() {
        assertEquals("A\t\n\"\\ x", JavaStrings.decodeEscapes("\\u0041\\t\\n\\\"\\\\\\sx", false));
        assertEquals("A", JavaStrings.decodeEscapes("\\uuu0041", false));
        assertEquals("A\0\377", JavaStrings.decodeEscapes("\\101\\0\\377", false));
        assertEquals("\\q", JavaStrings.decodeEscapes("\\q", false));
        assertEquals("DESede", JavaStrings.decodeTextBlock("\n            DESede"));
        assertEquals("a\n  b\n", JavaStrings.decodeTextBlock("   \n    a\n      b\n    "));
        assertEquals("a\n\nb", JavaStrings.decodeTextBlock("\r\n  a   \r\n\r\n  b"));
        assertEquals("ab\n", JavaStrings.decodeTextBlock("\n  a\\\n  b\n  "));
        assertEquals("x\ty", JavaStrings.decodeTextBlock("\n  x\\ty"));
        // Unicode escapes can produce unpaired surrogates; decoded values must stay well-formed (SPEC 11.6)
        assertEquals("AES\uFFFD", JavaStrings.replaceLoneSurrogates("AES\uD800"));
        assertEquals("\uFFFDx\uFFFD", JavaStrings.replaceLoneSurrogates("\uDC00x\uD800"));
        assertEquals("\uD83D\uDE00", JavaStrings.replaceLoneSurrogates("\uD83D\uDE00"));
    }

    @Test
    void loneSurrogateEscapesBecomeReplacementCharacters() throws Exception {
        List<SourceFinding> fs = analyze("S.java", "import javax.crypto.Cipher;\nclass S { void f() {\n"
                + "Cipher.getInstance(\"AES/GCM/NoPadding\\uD800\");\n}}\n");
        assertEquals("3:java.sym.aes.gcm:AES/GCM/NoPadding\uFFFD", summary(fs));
    }

    @Test
    void genericsAndDenotes() throws Exception {
        assertEquals("java.util.HashMap", JavaAnalyzer.removeGenerics("java.util.HashMap<String,List<X>>"));
        assertEquals("HashMap", JavaAnalyzer.removeGenerics("HashMap<>"));
        JavaContext ctx = JavaContext.build(root.resolve("A.java"), SyntaxTrees.parse(parser, Grammars.get().java(),
                "import javax.crypto.Cipher;\nimport org.x.Builder;\nclass Local {}\n"));
        assertTrue(JavaAnalyzer.denotes("Cipher", "javax.crypto.Cipher", ctx));
        assertTrue(JavaAnalyzer.denotes("javax.crypto.Cipher", "javax.crypto.Cipher", ctx));
        assertTrue(JavaAnalyzer.denotes("MessageDigest", "java.security.MessageDigest", ctx));
        assertFalse(JavaAnalyzer.denotes("Local", "x.Local", ctx));
        assertFalse(JavaAnalyzer.denotes("md", "java.security.md", ctx));
        assertFalse(JavaAnalyzer.denotes("other.pkg.Cipher", "javax.crypto.Cipher", ctx));
        assertTrue(JavaAnalyzer.denotes("Builder.Inner", "org.x.Builder.Inner", ctx));
        assertFalse(JavaAnalyzer.denotes("Builder", "org.y.Builder", ctx));
        assertFalse(JavaAnalyzer.denotes("", "a.B", ctx));
    }

    @Test
    void specExampleFindings() throws Exception {
        List<SourceFinding> fs = analyze("src/main/java/demo/Crypto.java", """
                package demo;
                import javax.crypto.Cipher;
                import java.security.MessageDigest;
                import javax.crypto.spec.SecretKeySpec;
                import javax.net.ssl.SSLContext;
                class Crypto { void f(String alg) throws Exception {
                  Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                  MessageDigest md = MessageDigest.getInstance(alg);
                  SecretKeySpec k = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
                  SSLContext ctx = SSLContext.getInstance("TLSv1.2");
                }}
                """);
        assertEquals("10:java.prot.tls.v1_2:TLSv1.2 7:java.sym.aes.gcm:AES/GCM/NoPadding"
                + " 8:java.jca.messagedigest.unresolved:MessageDigest.getInstance 9:java.key.hardcoded:SecretKeySpec"
                + " 9:java.sym.aes:AES", summary(fs));
        SourceFinding gcm = fs.stream().filter(f -> f.rule().id().equals("java.sym.aes.gcm")).findFirst().get();
        assertEquals("javax.crypto.Cipher.getInstance", gcm.symbol());
        assertEquals("Cipher.getInstance(\"AES/GCM/NoPadding\")", gcm.snippet());
        SourceFinding key = fs.stream().filter(f -> f.rule().id().equals("java.key.hardcoded")).findFirst().get();
        assertEquals("javax.crypto.spec.SecretKeySpec", key.symbol());
    }

    @Test
    void nestedDuplicatesAndDisplayNames() throws Exception {
        List<SourceFinding> fs = analyze("B.java", """
                import org.bouncycastle.crypto.modes.GCMBlockCipher;
                import org.bouncycastle.crypto.engines.AESEngine;
                import org.bouncycastle.crypto.macs.HMac;
                import org.bouncycastle.crypto.digests.SHA256Digest;
                class B { void f() {
                  new GCMBlockCipher(new AESEngine());
                  new HMac(new SHA256Digest());
                  new org.bouncycastle.crypto.engines.AESEngine();
                }}
                """);
        String s = summary(fs);
        assertFalse(s.contains("6:java.sym.aes:"), s);
        assertTrue(s.contains("6:java.sym.aes.gcm:GCMBlockCipher"), s);
        assertTrue(s.contains("7:java.mac.hmac:HMac"), s);
        assertTrue(s.contains("7:java.hash.sha2:SHA256Digest"), s);
        assertTrue(s.contains("8:java.sym.aes:AESEngine"), s);
    }

    @Test
    void crossFileConstantsStayInsideTheScanRoot() throws Exception {
        Path conf = root.toRealPath().resolve("src/com/acme/Conf.java");
        Files.createDirectories(conf.getParent());
        Files.writeString(conf, "package com.acme;\npublic class Conf { public static final String ALG = \"SHA-1\"; }\n");
        List<SourceFinding> fs = analyze("src/com/acme/app/App.java", """
                package com.acme.app;
                import com.acme.Conf;
                import java.security.MessageDigest;
                class App { void f() throws Exception { MessageDigest.getInstance(Conf.ALG); } }
                """);
        assertEquals("4:java.hash.sha1:SHA-1", summary(fs));
        // package deeper than the directory: the source root would be outside the scan root
        List<SourceFinding> outside = analyze("Top.java", """
                package a.b.c;
                import com.acme.Conf;
                import java.security.MessageDigest;
                class Top { void f() throws Exception { MessageDigest.getInstance(Conf.ALG); } }
                """);
        assertEquals("4:java.jca.messagedigest.unresolved:MessageDigest.getInstance", summary(outside));
    }

    @Test
    void depthLimitGivesFallback() throws Exception {
        StringBuilder b = new StringBuilder("\"SHA\"");
        for (int i = 0; i < 4000; i++) {
            b.append(" + \"\"");
        }
        List<SourceFinding> fs = analyze("D.java", "import java.security.MessageDigest;\nclass D { void f() {\n"
                + "MessageDigest.getInstance(" + b + ");\n"
                + "MessageDigest.getInstance(\"SHA\" + \"-\" + \"256\");\n}}\n");
        assertEquals("3:java.jca.messagedigest.unresolved:MessageDigest.getInstance 4:java.hash.sha2:SHA-256",
                summary(fs));
    }

    @Test
    void overrideWithBodyAndInType() throws Exception {
        List<SourceFinding> fs = analyze("T.java", """
                import javax.net.ssl.X509TrustManager;
                class T implements X509TrustManager {
                  @Override
                  public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) { /* trust */ }
                }
                class U { public void checkServerTrusted(Object c, String a) { } }
                """);
        assertEquals(1, fs.size(), summary(fs));
        assertEquals(4, fs.get(0).line());
        assertEquals("java.cert.validation.disabled", fs.get(0).rule().id());
        assertEquals("public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a)",
                fs.get(0).snippet().substring(fs.get(0).snippet().indexOf("public")));
        assertNull(fs.get(0).param());
    }

    @Test
    void bodyNormalisation() {
        assertEquals("{ }", JavaAnalyzer.normalisedBody("{ /* nothing */ }"));
        assertEquals("{ return; }", JavaAnalyzer.normalisedBody("{\n  // a\n  return;\n}"));
        // block comments are removed first, then line comments (SPEC 7.6)
        assertEquals("{", JavaAnalyzer.normalisedBody("{ // a /* b\n */ }"));
    }

    /** SPEC 7.4.3: only declarations before the use, the last one, in the nearest enclosing block. */
    @Test
    void localDeclarationLookup() throws Exception {
        List<SourceFinding> fs = analyze("L.java", """
                import java.security.MessageDigest;
                class L { void f() throws Exception {
                  MessageDigest.getInstance(a);
                  final String a = "MD5";
                  MessageDigest.getInstance(a);
                  { final String b = "SHA-1"; MessageDigest.getInstance(b); }
                  { final String b = "MD5", c = "SHA-1"; MessageDigest.getInstance(c); }
                  final String a = "SHA-1";
                  MessageDigest.getInstance(a);
                }}
                """);
        assertEquals("3:java.jca.messagedigest.unresolved:MessageDigest.getInstance 5:java.hash.md5:MD5"
                + " 6:java.hash.sha1:SHA-1 7:java.hash.sha1:SHA-1 9:java.hash.sha1:SHA-1", summary(fs));
    }
}
