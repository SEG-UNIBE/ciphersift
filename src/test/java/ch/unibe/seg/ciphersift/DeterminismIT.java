/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Determinism (SPEC 12, 16): the conformance inputs scanned with {@code --threads 1} and
 * {@code --threads 8}, from two absolute locations with the same last segment, from different
 * working directories and with a different locale, time zone and default charset give
 * byte-identical CBOMs.
 */
class DeterminismIT {
    @TempDir
    static Path tmp;
    static Path a;
    static Path b;

    @BeforeAll
    static void copy() throws Exception {
        a = tmp.resolve("a").resolve("cases");
        b = tmp.resolve("b").resolve("deeper").resolve("cases");
        TestSupport.copyTree(TestSupport.casesDir(), a);
        TestSupport.copyTree(TestSupport.casesDir(), b);
    }

    private static byte[] scan(Path root, Path cwd, List<String> jvm, Map<String, String> env, String threads,
            String options) throws Exception {
        Path out = tmp.resolve("out-" + System.nanoTime() + ".json");
        List<String> args = new ArrayList<>(List.of("scan", root.toString(), "-o", out.toString(), "--threads",
                threads));
        if (!options.isEmpty()) {
            args.addAll(List.of(options.split(" ")));
        }
        JarRunner.Run r = JarRunner.run(cwd, jvm, env, args.toArray(new String[0]));
        assertEquals(0, r.exit(), r.stderr());
        return Files.readAllBytes(out);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "--exclude-tests", "--exclude vendor/** --exclude **/*_pb2.py", "--cyclonedx-version 1.6"})
    void byteIdentical(String options) throws Exception {
        byte[] t1 = scan(a, tmp, List.of(), Map.of(), "1", options);
        byte[] t8 = scan(a, a, List.of(), Map.of(), "8", options);
        byte[] other = scan(b, b.getParent(), List.of("-Duser.language=tr", "-Duser.country=TR",
                "-Duser.timezone=Pacific/Kiritimati", "-Dfile.encoding=ISO-8859-1", "-Dsun.jnu.encoding=UTF-8"),
                Map.of("LC_ALL", "tr_TR.ISO-8859-9", "TZ", "Asia/Kathmandu"), "8", options);
        assertArrayEquals(t1, t8, "--threads 1 vs --threads 8");
        assertArrayEquals(t1, other, "different location, locale, time zone, charset");
        assertTrue(new String(t1, StandardCharsets.UTF_8).contains("\"name\": \"cases\""));
    }

    @Test
    void sourceDateEpoch() throws Exception {
        Map<String, String> env = Map.of("SOURCE_DATE_EPOCH", "1767225600");
        byte[] x = scan(a, tmp, List.of(), env, "2", "");
        byte[] y = scan(b, tmp, List.of(), env, "3", "");
        assertArrayEquals(x, y);
        assertTrue(new String(x, StandardCharsets.UTF_8).contains("\"timestamp\": \"2026-01-01T00:00:00Z\""));
        byte[] none = scan(a, tmp, List.of(), Map.of(), "2", "");
        assertTrue(!new String(none, StandardCharsets.UTF_8).contains("\"timestamp\""));
    }

    /** DECISIONS follow-up F3: the textual pre-filter does not change the output. */
    @Test
    void prefilterDoesNotChangeTheOutput() throws Exception {
        byte[] with = scan(a, tmp, List.of(), Map.of(), "4", "");
        byte[] without = scan(a, tmp, List.of("-Dciphersift.noPrefilter=true"), Map.of(), "4", "");
        assertArrayEquals(with, without);
    }

    /**
     * DECISIONS O1: non-ASCII and undecodable file names (walk, cross-file lookup, scan-root name)
     * are reported identically under a C and a UTF-8 locale with plain {@code java -jar}.
     */
    @Test
    void nonAsciiFileNamesIndependentOfLocale() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(System.getProperty("os.name").startsWith("Linux"));
        // this test JVM creates the non-ASCII names, which needs a UTF-8 file-name charset itself
        org.junit.jupiter.api.Assumptions.assumeTrue("UTF-8".equalsIgnoreCase(System.getProperty("sun.jnu.encoding")));
        Path root = tmp.resolve("ünï-root");
        Files.createDirectories(root.resolve("src/q"));
        Files.writeString(root.resolve("café.py"), "import hashlib\nhashlib.md5(b'x')\n");
        Files.writeString(root.resolve("src/q/Main.java"), "package q;\nimport javax.crypto.Cipher;\n"
                + "class Main { void f() throws Exception { Cipher.getInstance(Ä.ALG); } }\n");
        Files.writeString(root.resolve("src/q/Ä.java"), "package q;\nclass Ä { static final String ALG = \"DES\"; }\n");
        Process p = new ProcessBuilder("sh", "-c", "printf 'import hashlib\\nhashlib.sha1()\\n' > \"$(printf 'bad\\377.py')\"")
                .directory(root.toFile()).inheritIO().start();
        assertEquals(0, p.waitFor());
        // the scan root is passed as ASCII (a symbolic link), since arguments are decoded with the locale
        Path link = tmp.resolve("rootlink");
        Files.createSymbolicLink(link, root);
        byte[] utf8 = scan(link, tmp, List.of(), Map.of("LC_ALL", "C.UTF-8"), "2", "");
        byte[] c = scan(link, tmp, List.of(), Map.of("LC_ALL", "C"), "2", "");
        assertArrayEquals(utf8, c, "C vs UTF-8 locale");
        String doc = new String(utf8, StandardCharsets.UTF_8);
        assertTrue(doc.contains("\"location\": \"café.py\""), doc);
        assertTrue(doc.contains("\"location\": \"bad\uFFFD.py\""), doc);
        assertTrue(doc.contains("\"name\": \"DES\""), "cross-file constant in Ä.java");
        assertTrue(doc.contains("\"name\": \"ünï-root\""), "scan-root name");
    }
}
