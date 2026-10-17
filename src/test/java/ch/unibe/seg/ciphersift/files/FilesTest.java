/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.files;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Glob matching (4.2), classification (4.5), binary detection (4.6), decoding (4.4), test files (4.7), walk (4.1). */
class FilesTest {
    @ParameterizedTest(name = "{0} ~ {1} (dir={2}) -> {3}")
    @CsvSource({
        "vendor/**, vendor/x.py, false, true",
        "vendor/**, vendor/a/b/c.java, false, true",
        "vendor/**, src/vendor/x.py, false, false",
        "vendor/**, vendorx/x.py, false, false",
        "**/gen/*.py, gen/x.py, false, true",
        "**/gen/*.py, a/b/gen/x.py, false, true",
        "**/gen/*.py, a/b/gen/sub/x.py, false, false",
        "*_pb2.py, x_pb2.py, false, true",
        "*_pb2.py, a/b/x_pb2.py, false, true",
        "*_pb2.py, a/b/x_pb2.pyc, false, false",
        "node_modules, a/node_modules, true, true",
        "node_modules, node_modules, true, true",
        "/src/*.py, src/a.py, false, true",
        "/src/*.py, x/src/a.py, false, false",
        "build/, build, true, true",
        "build/, build, false, false",
        "a?c.py, abc.py, false, true",
        "a?c.py, a/c.py, false, false",
        "[ab]*.py, b1.py, false, true",
        "[!ab]*.py, b1.py, false, false",
        "[!ab]*.py, c1.py, false, true",
        "[a-c]x.py, bx.py, false, true",
        "[a-c]x.py, dx.py, false, false",
        "Vendor/**, vendor/x.py, false, false",
        "src/*/A.java, src/a/A.java, false, true",
        "src/*/A.java, src/a/b/A.java, false, false",
        "a/**/b, a/b, true, true",
        "a/**/b, a/x/y/b, true, true",
    })
    void glob(String glob, String path, boolean dir, boolean expected) {
        assertEquals(expected, Glob.compile(glob).matches(path, dir));
    }

    @Test
    void classification() {
        assertEquals(FileClass.JAVA, FileClass.of("a/B.JAVA"));
        assertEquals(FileClass.PYTHON, FileClass.of("setup.py"));
        assertEquals(FileClass.GO, FileClass.of("cmd/main.go"));
        assertEquals(FileClass.GO, FileClass.of("x_test.GO"));
        assertEquals(FileClass.GO_MOD, FileClass.of("a/go.mod"));
        assertEquals(FileClass.GO_SUM, FileClass.of("go.sum"));
        assertEquals(FileClass.IGNORED, FileClass.of("go.work"));
        assertEquals("golang", FileClass.GO_MOD.ecosystem());
        assertEquals("go-sum", FileClass.GO_SUM.label());
        assertTrue(FileClass.GO.isSource());
        assertTrue(TestFiles.isTest("pkg/sum_test.go"));
        assertTrue(TestFiles.isTest("internal/testdata/fixture.go"));
        assertFalse(TestFiles.isTest("pkg/sum_Test.go"), "case-sensitive (SPEC 17.1)");
        assertFalse(TestFiles.isTest("pkg/test.go"));
        assertFalse(TestFiles.isTest("pkg/TestMain.go"), "the Java Test* rule does not apply to Go");
        assertEquals(FileClass.POM, FileClass.of("x/POM.xml"));
        assertEquals(FileClass.GRADLE, FileClass.of("build.gradle"));
        assertEquals(FileClass.GRADLE, FileClass.of("m/build.gradle.kts"));
        assertEquals(FileClass.GRADLE_CATALOG, FileClass.of("gradle/libs.versions.toml"));
        assertEquals(FileClass.REQUIREMENTS, FileClass.of("requirements.txt"));
        assertEquals(FileClass.REQUIREMENTS, FileClass.of("requirements-dev.txt"));
        assertEquals(FileClass.REQUIREMENTS, FileClass.of("requirements/base.txt"));
        assertEquals(FileClass.REQUIREMENTS, FileClass.of("x/Requirements/BASE.TXT"));
        assertEquals(FileClass.IGNORED, FileClass.of("notes.txt"));
        assertEquals(FileClass.IGNORED, FileClass.of("requirements.in"));
        assertEquals(FileClass.PYPROJECT, FileClass.of("pyproject.toml"));
        assertEquals(FileClass.PIPFILE_LOCK, FileClass.of("svc/Pipfile.lock"));
        assertEquals(FileClass.POETRY_LOCK, FileClass.of("poetry.lock"));
        assertEquals(FileClass.IGNORED, FileClass.of("Pipfile"));
        assertEquals("gradle-catalog", FileClass.GRADLE_CATALOG.label());
        assertEquals("pypi", FileClass.POETRY_LOCK.ecosystem());
    }

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource({
        "src/test/java/a/A.java, true",
        "src/TEST/java/a/A.java, true",
        "lib/Tests/x.py, true",
        "x/__tests__/a.py, true",
        "x/testdata/a.py, true",
        "x/test-fixtures/a.java, true",
        "x/integration-tests/a.java, true",
        "src/it/java/A.java, true",
        "it/java/A.java, false",
        "x/src/IT/A.java, true",
        "src/main/java/FooTest.java, true",
        "src/main/java/FooTests.java, true",
        "src/main/java/FooTestCase.java, true",
        "src/main/java/FooIT.java, true",
        "src/main/java/TestUtils.java, true",
        "src/main/java/Testament.java, false",
        "src/main/java/Latest.java, false",
        "src/main/java/Contest.java, false",
        "src/main/java/footest.java, false",
        "src/main/java/FOOTEST.java, false",
        "src/main/java/Test.java, true",
        "pkg/test_util.py, true",
        "pkg/util_test.py, true",
        "pkg/tests.py, true",
        "pkg/conftest.py, true",
        "pkg/Test_util.py, false",
        "pkg/latest.py, false",
        "pkg/contest.py, false",
        "test.py, false",
        "test/pom.xml, true",
        "tests, false",
    })
    void testFiles(String path, boolean expected) {
        assertEquals(expected, TestFiles.isTest(path));
    }

    @Test
    void binaryDetection() {
        assertFalse(SourceText.isBinary(new byte[0]));
        assertFalse(SourceText.isBinary("print('hi')\n\t\r\n".getBytes(StandardCharsets.US_ASCII)));
        byte[] b = new byte[100];
        for (int i = 0; i < 10; i++) {
            b[i] = 0x01; // 10 control bytes of 100: 10*10 > 100 is false
        }
        java.util.Arrays.fill(b, 10, 100, (byte) 'a');
        assertFalse(SourceText.isBinary(b));
        b[10] = 0x1F;
        assertTrue(SourceText.isBinary(b));
        byte[] esc = new byte[20];
        java.util.Arrays.fill(esc, (byte) 0x1B); // ESC is 0x1B, counted
        assertTrue(SourceText.isBinary(esc));
        byte[] cr = new byte[20];
        java.util.Arrays.fill(cr, (byte) 0x0C); // form feed is not counted
        assertFalse(SourceText.isBinary(cr));
        // only the first 8192 bytes count
        byte[] late = new byte[20000];
        java.util.Arrays.fill(late, (byte) 'x');
        java.util.Arrays.fill(late, 8192, 20000, (byte) 0);
        assertFalse(SourceText.isBinary(late));
    }

    @Test
    void decoding() {
        assertEquals("ab", SourceText.decode(new byte[] {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, 'a', 'b'}));
        assertEquals("a�b", SourceText.decode(new byte[] {'a', (byte) 0xE9, 'b'}));
        assertEquals("a�\nb", SourceText.decode(new byte[] {'a', (byte) 0xC3, '\n', 'b'}));
        assertEquals("é", SourceText.decode(new byte[] {(byte) 0xC3, (byte) 0xA9}));
    }

    @Test
    void walkSkipsVcsLinksExcludesAndTests(@TempDir Path root) throws Exception {
        Files.createDirectories(root.resolve(".git"));
        Files.writeString(root.resolve(".git/x.py"), "");
        Files.createDirectories(root.resolve("src/test"));
        Files.writeString(root.resolve("src/test/T.java"), "");
        Files.writeString(root.resolve("src/A.java"), "");
        Files.writeString(root.resolve("src/readme.md"), "");
        Files.createDirectories(root.resolve("vendor"));
        Files.writeString(root.resolve("vendor/V.java"), "");
        Files.writeString(root.resolve("pom.xml"), "");
        try {
            Files.createSymbolicLink(root.resolve("link.py"), root.resolve("src/A.java"));
            Files.createSymbolicLink(root.resolve("linkdir"), root.resolve("src"));
        } catch (UnsupportedOperationException | java.io.IOException ex) {
            // symbolic links unsupported here
        }
        var all = new FileCollector(root, List.of(Glob.compile("vendor")), false).collect();
        assertEquals(List.of("pom.xml", "src/A.java", "src/test/T.java"),
                all.stream().map(FileCollector.CollectedFile::relativePath).toList());
        assertTrue(all.get(2).test());
        var noTests = new FileCollector(root, List.of(), true).collect();
        assertEquals(List.of("pom.xml", "src/A.java", "vendor/V.java"),
                noTests.stream().map(FileCollector.CollectedFile::relativePath).toList());
    }

    /**
     * A file name that is not valid in the platform encoding (here: a 0xFF byte) is still collected and
     * readable; rebuilding the path from its decoded name used to lose it (or, under a C locale, abort
     * the scan with InvalidPathException).
     */
    @Test
    void undecodableFileNamesStayReachable(@TempDir Path root) throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(System.getProperty("os.name").startsWith("Linux"));
        Process p = new ProcessBuilder("sh", "-c", "mkdir -p \"$(printf 'd\\377')\" && printf x > \"$(printf 'd\\377/b\\377.py')\"")
                .directory(root.toFile()).inheritIO().start();
        assertEquals(0, p.waitFor());
        var all = new FileCollector(root, List.of(), false).collect();
        assertEquals(1, all.size());
        assertTrue(all.get(0).relativePath().endsWith(".py"), all.get(0).relativePath());
        assertEquals("x", new String(SourceText.readBounded(all.get(0).path()), StandardCharsets.UTF_8));
    }

    /** Reading never follows a link that replaced a collected file, and stops after 10 MiB + 1 byte. */
    @Test
    void boundedReadsDoNotFollowLinks(@TempDir Path root) throws Exception {
        Path target = Files.writeString(root.resolve("secret.txt"), "secret");
        Path link = root.resolve("a.py");
        try {
            Files.createSymbolicLink(link, target);
        } catch (UnsupportedOperationException | java.io.IOException ex) {
            return; // symbolic links unsupported here
        }
        org.junit.jupiter.api.Assertions.assertThrows(java.io.IOException.class, () -> SourceText.readBounded(link));
        Path big = root.resolve("big.py");
        try (var ch = java.nio.channels.FileChannel.open(big, java.nio.file.StandardOpenOption.CREATE_NEW,
                java.nio.file.StandardOpenOption.WRITE)) {
            ch.write(java.nio.ByteBuffer.wrap(new byte[] {1}), SourceText.MAX_SIZE); // sparse, MAX_SIZE + 1 bytes
        }
        org.junit.jupiter.api.Assertions.assertThrows(SourceText.TooLargeException.class,
                () -> SourceText.readBounded(big));
        Files.writeString(big, "ok", java.nio.file.StandardOpenOption.TRUNCATE_EXISTING);
        assertEquals("ok", new String(SourceText.readBounded(big), StandardCharsets.UTF_8));
    }
}
