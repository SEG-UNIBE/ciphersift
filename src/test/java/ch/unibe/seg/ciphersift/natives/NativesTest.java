/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.natives;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.unibe.seg.ciphersift.syntax.SyntaxNode;
import ch.unibe.seg.ciphersift.syntax.SyntaxTrees;
import io.github.treesitter.jtreesitter.Parser;
import java.nio.file.Files;
import org.junit.jupiter.api.Test;

/** Native libraries, grammars and the syntax-tree copy (SPEC 6, 15.3, Appendix C). */
class NativesTest {
    @Test
    void platformIds() {
        assertEquals("linux-x86_64", Platform.id("Linux", "amd64"));
        assertEquals("darwin-aarch64", Platform.id("Mac OS X", "aarch64"));
        assertEquals("windows-x86_64", Platform.id("Windows 11", "x86_64"));
        assertEquals("libtree-sitter-java.so", Platform.libraryFile("linux-x86_64", "tree-sitter-java"));
        assertEquals("libtree-sitter.dylib", Platform.libraryFile("darwin-aarch64", "tree-sitter"));
    }

    @Test
    void librariesAreExtractedAndVerified() throws Exception {
        NativeLibraries libs = NativeLibraries.get();
        for (String l : new String[] {NativeLibraries.CORE, NativeLibraries.JAVA, NativeLibraries.PYTHON,
                NativeLibraries.GO}) {
            assertTrue(Files.isRegularFile(libs.library(l)), l);
        }
        assertEquals(3, NativeLibraries.parseSums("aa  a.so\nbb *b.so\n\ncc c.so\n").size());
    }

    @Test
    void grammarsAndAppendixCFields() {
        Grammars g = Grammars.get();
        assertEquals(14, g.java().getAbiVersion());
        assertEquals(15, g.python().getAbiVersion());
        for (String f : Grammars.JAVA_FIELDS) {
            assertNotEquals(0, g.java().getFieldIdForName(f), f);
        }
        for (String f : Grammars.PYTHON_FIELDS) {
            assertNotEquals(0, g.python().getFieldIdForName(f), f);
        }
        assertEquals(15, g.go().getAbiVersion());
        for (String f : Grammars.GO_FIELDS) {
            assertNotEquals(0, g.go().getFieldIdForName(f), f);
        }
    }

    @Test
    void treeCopyKeepsOffsetsRowsAndFields() {
        try (Parser p = new Parser(Grammars.get().java())) {
            String src = "class A {\n  String s = \"ä😀x\"; // ü\r\n  void m() { foo(1); }\n}\n";
            SyntaxTrees.Parsed parsed = SyntaxTrees.parseChecked(p, Grammars.get().java(), src);
            assertTrue(!parsed.hasError());
            SyntaxNode root = parsed.root();
            SyntaxNode cls = root.child(0);
            assertEquals("class_declaration", cls.type());
            assertEquals("A", cls.field("name").text());
            SyntaxNode body = cls.field("body");
            SyntaxNode field = body.namedChildren().get(0);
            assertEquals("String s = \"ä😀x\";", field.text());
            SyntaxNode method = body.namedChildren().get(2);
            assertEquals("method_declaration", method.type());
            assertEquals(3, method.line(), "rows count LF only; CR does not start a line");
            assertEquals("m", method.field("name").text());
        }
    }

    @Test
    void syntaxErrorsAreReported() {
        try (Parser p = new Parser(Grammars.get().python())) {
            assertTrue(SyntaxTrees.parseChecked(p, Grammars.get().python(), "def f(:\n  x = 1\n").hasError());
        }
    }

    @Test
    void deepTreesDoNotOverflow() {
        try (Parser p = new Parser(Grammars.get().python())) {
            String deep = "x = " + "(".repeat(5000) + "1" + ")".repeat(5000) + "\n";
            SyntaxNode root = SyntaxTrees.parse(p, Grammars.get().python(), deep);
            assertEquals("module", root.type());
        }
    }

    /** The native cache must not be modifiable by others: a library is verified, then loaded by path. */
    @Test
    void cacheDirectoryMustBePrivate(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tmp) throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(tmp.getFileSystem().supportedFileAttributeViews().contains("unix"));
        java.nio.file.Path own = Files.createDirectory(tmp.resolve("own"));
        Files.setPosixFilePermissions(own, java.nio.file.attribute.PosixFilePermissions.fromString("rwxrwxrwx"));
        assertTrue(NativeLibraries.privateDirectory(own), "own directory is tightened and accepted");
        assertEquals("rwxr-xr-x", java.nio.file.attribute.PosixFilePermissions.toString(
                Files.getPosixFilePermissions(own)));
        java.nio.file.Path link = Files.createSymbolicLink(tmp.resolve("link"), own);
        org.junit.jupiter.api.Assertions.assertFalse(NativeLibraries.privateDirectory(link), "a link is rejected");
        java.nio.file.Path shared = java.nio.file.Path.of("/tmp");
        if (Files.isDirectory(shared, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            org.junit.jupiter.api.Assertions.assertFalse(NativeLibraries.privateDirectory(shared),
                    "a world-writable directory (sticky /tmp) is rejected");
        }
    }
}
