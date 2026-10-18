/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Command-line behaviour of the fat jar: commands, standard streams and exit codes (SPEC 3). */
class CliIT {
    @TempDir
    Path tmp;

    private Path demo() throws Exception {
        Path d = tmp.resolve("demo");
        Files.createDirectories(d.resolve("src"));
        Files.writeString(d.resolve("src/A.java"),
                "import java.security.MessageDigest;\nclass A { void f() throws Exception {\n"
                        + "  MessageDigest.getInstance(\"SHA-256\");\n} }\n");
        return d;
    }

    @Test
    void scanFromAnyWorkingDirectoryWithRelativePaths() throws Exception {
        demo();
        Path cwd = tmp;
        JarRunner.Run r = JarRunner.run(cwd, List.of(), Map.of(), "scan", "demo", "-o", "out.cdx.json");
        assertEquals(0, r.exit(), r.stderr());
        assertEquals(0, r.stdout().length, "nothing but the CBOM on stdout");
        assertTrue(Files.exists(tmp.resolve("out.cdx.json")));
        assertTrue(r.stderr().matches("(?s)ciphersift: info: scanned 1 files \\(java 1, python 0, manifests 0\\) in "
                + "[0-9.]+ s; 1 findings, 1 components; 0 files skipped\\R"), r.stderr());
        try (Stream<Path> s = Files.list(tmp)) {
            assertFalse(s.anyMatch(p -> p.getFileName().toString().endsWith(".tmp")), "temporary file left");
        }
    }

    /**
     * Weakness indicators are off by default; {@code --weakness-indicators} adds them and leaves the rest unchanged
     * (SPEC 3.1, DECISIONS E2).
     */
    @Test
    void weaknessIndicatorsAreOptIn() throws Exception {
        Path d = demo();
        Files.writeString(d.resolve("src/R.java"), "import java.util.Random;\nclass R { long f() { return new Random().nextLong(); } }\n");
        JarRunner.Run def = JarRunner.run("scan", d.toString(), "-o", "-", "--quiet");
        JarRunner.Run all = JarRunner.run("scan", d.toString(), "-o", "-", "--quiet", "--weakness-indicators");
        assertEquals(0, def.exit(), def.stderr());
        assertEquals(0, all.exit(), all.stderr());
        assertFalse(def.out().contains("java.rand.prng.insecure"), def.out());
        assertFalse(def.out().contains("ciphersift:weaknessIndicators"));
        assertTrue(def.out().contains("java.hash.sha2"), "other findings stay");
        assertTrue(all.out().contains("java.rand.prng.insecure"), all.out());
        assertTrue(all.out().contains("\"value\": \"weakness\""), all.out());
        assertTrue(all.out().contains("\"name\": \"ciphersift:weaknessIndicators\",\n        \"value\": \"included\""),
                all.out());
        assertTrue(all.out().contains("java.hash.sha2"), "other findings stay");
        String help = JarRunner.run("scan", "--help").out();
        assertTrue(help.contains("--weakness-indicators"));
        assertFalse(help.contains("--no-weakness-indicators"));
        JarRunner.Run old = JarRunner.run("scan", d.toString(), "-o", "-", "--quiet", "--no-weakness-indicators");
        assertEquals(2, old.exit(), "the former option is gone: " + old.stderr());
    }

    @Test
    void stdoutOutputIsTheCbomOnly() throws Exception {
        Path d = demo();
        JarRunner.Run r = JarRunner.run("scan", d.toString(), "-o", "-", "--quiet");
        assertEquals(0, r.exit(), r.stderr());
        assertTrue(r.out().startsWith("{\n  \"bomFormat\": \"CycloneDX\","));
        assertTrue(r.out().endsWith("}\n"));
        assertEquals("", r.stderr());
    }

    @Test
    void exitCodes() throws Exception {
        Path d = demo();
        Path out = tmp.resolve("o.json");
        assertEquals(2, JarRunner.run("scan", d.toString()).exit(), "missing -o");
        assertEquals(2, JarRunner.run("scan", d.toString(), "-o", out.toString(), "--threads", "0").exit());
        assertEquals(2, JarRunner.run("scan", d.toString(), "-o", out.toString(), "--include-tests",
                "--exclude-tests").exit());
        assertEquals(2, JarRunner.run("scan", d.toString(), "-o", out.toString(), "--quiet", "--verbose").exit());
        assertEquals(2, JarRunner.run("scan", d.toString(), "-o", out.toString(), "--bogus").exit());
        assertEquals(2, JarRunner.run("scan", d.toString(), "-o", out.toString(), "--cyclonedx-version", "1.5").exit());
        assertEquals(2, JarRunner.run("scan", d.toString(), "-o", out.toString(), "--cyclonedx-version").exit());
        assertEquals(3, JarRunner.run("scan", tmp.resolve("missing").toString(), "-o", out.toString()).exit());
        assertEquals(3, JarRunner.run("scan", d.resolve("src/A.java").toString(), "-o", out.toString()).exit());
        Path badRules = tmp.resolve("rules");
        Files.createDirectories(badRules);
        Files.writeString(badRules.resolve("x.yaml"), "id: java.x\nkind: source\nlanguage: java\n");
        JarRunner.Run rr = JarRunner.run("scan", d.toString(), "-o", out.toString(), "--rules", badRules.toString());
        assertEquals(4, rr.exit());
        assertTrue(rr.stderr().contains("x.yaml"), rr.stderr());
        assertEquals(5, JarRunner.run("scan", d.toString(), "-o", tmp.resolve("no/such/dir/o.json").toString()).exit());
        assertFalse(Files.exists(out));
        assertEquals(0, JarRunner.run("scan", d.toString(), "-o", out.toString()).exit());
    }

    /** {@code --cyclonedx-version} (SPEC 3.1, 11.2): 1.7 by default, 1.6 on request; nothing else differs in kind. */
    @Test
    void cycloneDxVersionOption() throws Exception {
        Path d = demo();
        Path o17 = tmp.resolve("v17.json");
        Path o16 = tmp.resolve("v16.json");
        Path o17x = tmp.resolve("v17x.json");
        assertEquals(0, JarRunner.run("scan", d.toString(), "-o", o17.toString()).exit());
        assertEquals(0, JarRunner.run("scan", d.toString(), "-o", o16.toString(), "--cyclonedx-version", "1.6").exit());
        assertEquals(0, JarRunner.run("scan", d.toString(), "-o", o17x.toString(), "--cyclonedx-version", "1.7").exit());
        assertArrayEquals(Files.readAllBytes(o17), Files.readAllBytes(o17x), "1.7 is the default");
        var j17 = TestSupport.JSON.readTree(o17.toFile());
        var j16 = TestSupport.JSON.readTree(o16.toFile());
        assertEquals("1.7", j17.path("specVersion").asText());
        assertEquals("1.6", j16.path("specVersion").asText());
        assertEquals("SHA-2", j17.at("/components/0/cryptoProperties/algorithmProperties/algorithmFamily").asText());
        assertTrue(j16.at("/components/0/cryptoProperties/algorithmProperties/algorithmFamily").isMissingNode());
        assertTrue(CycloneDxSchemas.validate(Files.readAllBytes(o17), ch.unibe.seg.ciphersift.cbom.CycloneDxVersion.V1_7)
                .isEmpty());
        assertTrue(CycloneDxSchemas.validate(Files.readAllBytes(o16), ch.unibe.seg.ciphersift.cbom.CycloneDxVersion.V1_6)
                .isEmpty());
        assertEquals(TestSupport.normalise(Files.readAllBytes(o17)).size(),
                TestSupport.normalise(Files.readAllBytes(o16)).size());
        // same components and bom-refs in both versions
        assertEquals(j17.path("components").size(), j16.path("components").size());
        for (int i = 0; i < j17.path("components").size(); i++) {
            assertEquals(j17.path("components").get(i).path("bom-ref"), j16.path("components").get(i).path("bom-ref"));
        }
    }

    @Test
    void rulesValidateAndExport() throws Exception {
        JarRunner.Run v = JarRunner.run("rules", "validate");
        assertEquals(0, v.exit(), v.stderr());
        assertTrue(v.out().contains("source java: 105"), v.out());
        assertTrue(v.out().contains("source python: 91"), v.out());
        assertTrue(v.out().contains("source go: 70"), v.out());
        assertTrue(v.out().contains("dependency golang: 1"), v.out());
        Path exp = tmp.resolve("exported");
        JarRunner.Run e = JarRunner.run("rules", "export", exp.toString());
        assertEquals(0, e.exit(), e.stderr());
        assertTrue(Files.exists(exp.resolve("java/java.sym.aes.gcm.yaml")));
        assertTrue(Files.exists(exp.resolve("dependencies/dep.maven.yaml")));
        JarRunner.Run v2 = JarRunner.run("rules", "validate", "--rules", exp.toString());
        assertEquals(0, v2.exit(), v2.stderr());
        assertEquals(v.out(), v2.out());
        // an exported rule set gives the same CBOM (same rule digest)
        Path d = demo();
        JarRunner.Run s1 = JarRunner.run("scan", d.toString(), "-o", "-");
        JarRunner.Run s2 = JarRunner.run("scan", d.toString(), "-o", "-", "--rules", exp.toString());
        assertEquals(s1.out(), s2.out());
    }

    @Test
    void versionAndHelp() throws Exception {
        JarRunner.Run v = JarRunner.run("--version");
        assertEquals(0, v.exit());
        assertTrue(v.out().contains("ciphersift " + CipherSift.version()));
        assertTrue(v.out().contains("jtreesitter 0.26.1"));
        assertTrue(v.out().contains("tree-sitter-java ABI 14"));
        assertTrue(v.out().contains("tree-sitter-python ABI 15"));
        assertTrue(v.out().contains("tree-sitter-go ABI 15"));
        assertEquals(0, JarRunner.run("--help").exit());
        assertEquals(0, JarRunner.run("scan", "--help").exit());
    }

    /** Runs {@code bin/ciphersift} with the given environment (CIPHERSIFT_JAVA, JAVA_HOME and PATH are reset). */
    private JarRunner.Run launcher(Map<String, String> env, String... args) throws Exception {
        List<String> cmd = new java.util.ArrayList<>(List.of("sh", TestSupport.baseDir().resolve("bin/ciphersift").toString()));
        cmd.addAll(List.of(args));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().remove("CIPHERSIFT_JAVA");
        pb.environment().remove("JAVA_HOME");
        pb.environment().put("PATH", "/usr/bin:/bin");
        pb.environment().put("CIPHERSIFT_JAR", JarRunner.jar().toString());
        String tmpdir = System.getProperty("java.io.tmpdir");
        pb.environment().put("CIPHERSIFT_JAVA_OPTS", "-Djava.io.tmpdir=" + tmpdir);
        pb.environment().putAll(env);
        Path out = Files.createTempFile(tmp, "l", ".out");
        Path err = Files.createTempFile(tmp, "l", ".err");
        pb.redirectOutput(out.toFile());
        pb.redirectError(err.toFile());
        int code = pb.start().waitFor();
        return new JarRunner.Run(code, Files.readAllBytes(out), Files.readString(err));
    }

    /** A fake java executable that reports the given version (no release file next to it). */
    private Path fakeJava(String version) throws Exception {
        Path bin = Files.createDirectories(tmp.resolve("jdk-" + version).resolve("bin"));
        Path java = bin.resolve("java");
        Files.writeString(java, "#!/bin/sh\necho 'openjdk version \"" + version + "\" 2024-01-16' >&2\nexit 0\n");
        java.toFile().setExecutable(true);
        return java;
    }

    /** DECISIONS follow-up F1: the launcher's Java selection and the one-line error with exit code 6. */
    @Test
    void launcherChecksTheJavaVersion() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(System.getProperty("os.name").startsWith("Linux"));
        String current = Path.of(System.getProperty("java.home")).toString();
        Path old = fakeJava("21.0.2");
        JarRunner.Run r = launcher(Map.of("JAVA_HOME", old.getParent().getParent().toString()), "--version");
        assertEquals(6, r.exit(), r.stderr());
        assertEquals("ciphersift: error: CipherSift needs Java 23 or newer; found 21.0.2 (" + old
                + "); set CIPHERSIFT_JAVA or JAVA_HOME\n", r.stderr());
        // too old CIPHERSIFT_JAVA, explicitly configured JAVA_HOME: fall back to it
        r = launcher(Map.of("CIPHERSIFT_JAVA", old.toString(), "JAVA_HOME", current), "--version");
        assertEquals(0, r.exit(), r.stderr());
        assertTrue(r.out().startsWith("ciphersift " + CipherSift.version()), r.out());
        // CIPHERSIFT_JAVA wins over JAVA_HOME
        r = launcher(Map.of("CIPHERSIFT_JAVA", Path.of(current, "bin", "java").toString(), "JAVA_HOME",
                old.getParent().getParent().toString()), "--version");
        assertEquals(0, r.exit(), r.stderr());
        // java on PATH is used only when nothing is configured, and is never a fallback
        r = launcher(Map.of("PATH", old.getParent() + ":/usr/bin:/bin"), "--version");
        assertEquals(6, r.exit(), r.stderr());
        r = launcher(Map.of("PATH", old.getParent() + ":/usr/bin:/bin", "JAVA_HOME", current), "--version");
        assertEquals(0, r.exit(), r.stderr());
        r = launcher(Map.of("CIPHERSIFT_JAVA", tmp.resolve("missing/java").toString()), "--version");
        assertEquals(6, r.exit(), r.stderr());
        assertTrue(r.stderr().contains("found no executable"), r.stderr());
    }
}
