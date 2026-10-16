/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** Runs the built fat jar in a separate JVM (integration tests). */
public final class JarRunner {
    /** Result of one run. */
    public record Run(int exit, byte[] stdout, String stderr) {
        public String out() {
            return new String(stdout, StandardCharsets.UTF_8);
        }
    }

    private JarRunner() {}

    public static Path jar() {
        String p = System.getProperty("ciphersift.jar");
        Path jar = p != null ? Path.of(p)
                : TestSupport.baseDir().resolve("target/ciphersift-" + CipherSift.version() + "-all.jar");
        if (!Files.isRegularFile(jar)) {
            throw new IllegalStateException("fat jar not built: " + jar);
        }
        return jar;
    }

    public static Run run(Path cwd, List<String> jvmArgs, Map<String, String> env, String... args)
            throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>();
        cmd.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        cmd.add("--enable-native-access=ALL-UNNAMED");
        String tmp = System.getProperty("java.io.tmpdir");
        if (tmp != null) {
            cmd.add("-Djava.io.tmpdir=" + tmp);
        }
        cmd.addAll(jvmArgs);
        cmd.add("-jar");
        cmd.add(jar().toString());
        cmd.addAll(List.of(args));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        if (cwd != null) {
            pb.directory(cwd.toFile());
        }
        pb.environment().remove("SOURCE_DATE_EPOCH");
        if (env != null) {
            pb.environment().putAll(env);
        }
        Path out = Files.createTempFile("ciphersift-it-", ".out");
        Path err = Files.createTempFile("ciphersift-it-", ".err");
        try {
            pb.redirectOutput(out.toFile());
            pb.redirectError(err.toFile());
            Process proc = pb.start();
            if (!proc.waitFor(10, TimeUnit.MINUTES)) {
                proc.destroyForcibly();
                throw new IllegalStateException("timeout: " + cmd);
            }
            return new Run(proc.exitValue(), Files.readAllBytes(out), Files.readString(err, StandardCharsets.UTF_8));
        } finally {
            Files.deleteIfExists(out);
            Files.deleteIfExists(err);
        }
    }

    public static Run run(String... args) throws IOException, InterruptedException {
        return run(null, List.of(), Map.of(), args);
    }
}
