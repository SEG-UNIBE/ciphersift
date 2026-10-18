/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.cli;

import ch.unibe.seg.ciphersift.CipherSift;
import ch.unibe.seg.ciphersift.cbom.CbomWriter;
import ch.unibe.seg.ciphersift.cbom.CycloneDxVersion;
import ch.unibe.seg.ciphersift.cli.ExitCodes.ExitException;
import ch.unibe.seg.ciphersift.files.Glob;
import ch.unibe.seg.ciphersift.natives.NativeLoadException;
import ch.unibe.seg.ciphersift.rules.RuleSet;
import ch.unibe.seg.ciphersift.scan.Features;
import ch.unibe.seg.ciphersift.scan.Scanner;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

/** {@code ciphersift scan} (SPEC 3.1). */
@Command(name = "scan", mixinStandardHelpOptions = true, versionProvider = Main.VersionProvider.class,
        description = "Scan a directory and write a CycloneDX 1.7 (or 1.6) CBOM.",
        sortOptions = false)
public final class ScanCommand implements Callable<Integer> {
    @Spec
    CommandSpec spec;

    @Parameters(index = "0", paramLabel = "<dir>", description = "Scan root (an existing directory).")
    String dir;

    @Option(names = {"-o", "--output"}, required = true, paramLabel = "FILE",
            description = "Output file; '-' writes to standard output.")
    String output;

    @Option(names = "--exclude", paramLabel = "GLOB", description = "Exclude files and directories (repeatable).")
    List<String> excludes = new ArrayList<>();

    static final class TestMode {
        @Option(names = "--include-tests", description = "Scan test files and mark their occurrences (default).")
        boolean include;

        @Option(names = "--exclude-tests", description = "Do not scan test files.")
        boolean exclude;
    }

    @ArgGroup(exclusive = true, multiplicity = "0..1")
    TestMode testMode;

    @Option(names = "--threads", paramLabel = "N",
            description = "Worker threads (default: available processors, at most 8).")
    Integer threads;

    @Option(names = "--rules", paramLabel = "DIR", description = "Use the rule documents under DIR instead of the bundled rules.")
    String rulesDir;

    @Option(names = "--weakness-indicators",
            description = "Also report weakness indicators (rules with indicator: weakness, e.g. non-cryptographic random generators); off by default.")
    boolean weaknessIndicators;

    @Option(names = "--python-thin-wrappers",
            description = "Also treat thin Python functions (at most 8 lines, one family) as crypto wrappers whose call sites are reported; off by default (on for Java and Go).")
    boolean pythonThinWrappers;

    @Option(names = "--transitive-deps",
            description = "Also report transitive dependencies: go.mod requirements marked // indirect and the entries of lock files (go.sum, poetry.lock, Pipfile.lock); off by default.")
    boolean transitiveDeps;

    @Option(names = "--feature", paramLabel = "ID=on|off",
            description = "Switch a detection feature on or off (repeatable; see the README for the ids and defaults).")
    List<String> featureSpecs = new ArrayList<>();

    @Option(names = "--cyclonedx-version", paramLabel = "VERSION",
            description = "CycloneDX version of the output: 1.7 (default) or 1.6.")
    String cyclonedxVersion;

    static final class Verbosity {
        @Option(names = "--quiet", description = "Only errors on standard error.")
        boolean quiet;

        @Option(names = "--verbose", description = "Debug messages on standard error.")
        boolean verbose;
    }

    @ArgGroup(exclusive = true, multiplicity = "0..1")
    Verbosity verbosity;

    @Override
    public Integer call() throws Exception {
        if (verbosity != null) {
            Log.setThreshold(verbosity.quiet ? Log.Level.ERROR : Log.Level.DEBUG);
        }
        int n = threads == null ? Math.min(8, Math.max(1, Runtime.getRuntime().availableProcessors())) : threads;
        if (n < 1) {
            throw new CommandLine.ParameterException(spec.commandLine(), "--threads must be at least 1");
        }
        CycloneDxVersion cdx = cyclonedxVersion == null ? CycloneDxVersion.DEFAULT
                : CycloneDxVersion.of(cyclonedxVersion);
        if (cdx == null) {
            throw new CommandLine.ParameterException(spec.commandLine(),
                    "--cyclonedx-version must be 1.7 or 1.6, not '" + cyclonedxVersion + "'");
        }
        Features features;
        try {
            features = Features.parse(featureSpecs, transitiveDeps
                    ? Features.DEFAULTS.with(Features.TRANSITIVE_DEPS, true) : Features.DEFAULTS);
        } catch (IllegalArgumentException ex) {
            throw new CommandLine.ParameterException(spec.commandLine(), ex.getMessage());
        }
        boolean excludeTests = testMode != null && testMode.exclude;
        List<Glob> globs = new ArrayList<>();
        for (String g : excludes) {
            globs.add(Glob.compile(g));
        }

        long start = System.nanoTime();
        Path root = scanRoot(dir);
        Path out = "-".equals(output) ? null : outputPath(output);
        Scanner.prefetchNatives(); // overlaps native start-up with rule loading
        RuleSet rules = Main.loadRules(rulesDir);

        Scanner.Result result;
        try {
            result = new Scanner(new Scanner.Options(root, globs, excludeTests, n, rules, weaknessIndicators,
                    ch.unibe.seg.ciphersift.wrappers.WrapperOptions.defaults(pythonThinWrappers), features)).run();
        } catch (NativeLoadException ex) {
            throw new ExitException(ExitCodes.INTERNAL, ex.getMessage(), ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new ExitException(ExitCodes.INTERRUPTED, "interrupted");
        }
        String rootName = ch.unibe.seg.ciphersift.files.FileNames.name(root);
        CbomWriter.Metadata meta = new CbomWriter.Metadata(CipherSift.version(), rootName, rules.digest(),
                !excludeTests, result.scanned(), result.skipped(), sourceDateEpoch(), weaknessIndicators, cdx,
                pythonThinWrappers, features.describe());
        byte[] doc = CbomWriter.write(meta, result.components());
        write(out, doc);
        double secs = (System.nanoTime() - start) / 1e9;
        // "go N" only when Go files were scanned, so that the line of a Java/Python scan is unchanged
        Log.info(String.format(Locale.ROOT,
                "scanned %d files (java %d, python %d%s, manifests %d) in %.1f s; %d findings, %d components; %d files skipped",
                result.scanned(), result.javaFiles(), result.pythonFiles(),
                result.goFiles() == 0 ? "" : ", go " + result.goFiles(), result.manifests(), secs, result.findings(),
                result.components().size(), result.skipped()));
        return ExitCodes.OK;
    }

    static Path scanRoot(String dir) {
        Path p;
        try {
            p = Path.of(dir);
        } catch (InvalidPathException ex) {
            throw new ExitException(ExitCodes.SCAN_ROOT, "scan root " + dir + " is not a valid path");
        }
        if (!Files.exists(p)) {
            throw new ExitException(ExitCodes.SCAN_ROOT, "scan root " + dir + " does not exist");
        }
        if (!Files.isDirectory(p)) {
            throw new ExitException(ExitCodes.SCAN_ROOT, "scan root " + dir + " is not a directory");
        }
        if (!Files.isReadable(p)) {
            throw new ExitException(ExitCodes.SCAN_ROOT, "scan root " + dir + " cannot be read");
        }
        try {
            return p.toRealPath();
        } catch (IOException ex) {
            throw new ExitException(ExitCodes.SCAN_ROOT, "scan root " + dir + " cannot be resolved: " + ex.getMessage());
        }
    }

    private static Path outputPath(String output) {
        Path p;
        try {
            p = Path.of(output).toAbsolutePath();
        } catch (InvalidPathException ex) {
            throw new ExitException(ExitCodes.OUTPUT, "output " + output + " is not a valid path");
        }
        Path parent = p.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new ExitException(ExitCodes.OUTPUT, "cannot write " + output + ": directory "
                    + (parent == null ? "" : parent) + " does not exist");
        }
        if (Files.isDirectory(p)) {
            throw new ExitException(ExitCodes.OUTPUT, "cannot write " + output + ": is a directory");
        }
        return p;
    }

    private static Long sourceDateEpoch() {
        return parseSourceDateEpoch(System.getenv("SOURCE_DATE_EPOCH"));
    }

    /**
     * {@code SOURCE_DATE_EPOCH} as seconds, or null unless it is a non-negative decimal integer that
     * an {@link java.time.Instant} can represent (a larger value would make the timestamp
     * formatting fail).
     */
    static Long parseSourceDateEpoch(String s) {
        if (s == null || !s.matches("[0-9]+")) {
            return null;
        }
        try {
            long v = Long.parseLong(s);
            return v <= java.time.Instant.MAX.getEpochSecond() ? v : null;
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    /** Pending temporary output file, removed by the shutdown hook on interrupt. */
    static final AtomicReference<Path> PENDING = new AtomicReference<>();

    static {
        try {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                Path t = PENDING.getAndSet(null);
                if (t != null) {
                    try {
                        Files.deleteIfExists(t);
                    } catch (IOException ex) {
                        // nothing more to do
                    }
                }
            }, "ciphersift-cleanup"));
        } catch (IllegalStateException | SecurityException ex) {
            // shutting down already
        }
    }

    /**
     * Creates the temporary output file next to {@code out}. Unlike {@code Files.createTempFile}
     * (always mode 0600) the file gets the default permissions of the user's umask, as a plainly
     * written file would; the CBOM is not secret, and e.g. a container user writing to a mounted
     * directory must leave a file the host user can read.
     */
    private static Path createTemporary(Path out) throws IOException {
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        for (int attempt = 0; ; attempt++) {
            Path p = out.resolveSibling("." + out.getFileName() + "." + Long.toHexString(rnd.nextLong()) + ".tmp");
            try {
                return Files.createFile(p);
            } catch (java.nio.file.FileAlreadyExistsException ex) {
                if (attempt >= 100) {
                    throw ex;
                }
            }
        }
    }

    private static void write(Path out, byte[] doc) {
        if (out == null) {
            try {
                OutputStream o = System.out;
                o.write(doc);
                o.flush();
            } catch (IOException ex) {
                throw new ExitException(ExitCodes.OUTPUT, "cannot write to standard output: " + ex.getMessage());
            }
            return;
        }
        Path tmp = null;
        try {
            tmp = createTemporary(out);
            PENDING.set(tmp);
            Files.write(tmp, doc);
            try {
                Files.move(tmp, out, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException ex) {
                Files.move(tmp, out, StandardCopyOption.REPLACE_EXISTING);
            }
            PENDING.set(null);
        } catch (IOException | SecurityException ex) {
            if (tmp != null) {
                try {
                    Files.deleteIfExists(tmp);
                } catch (IOException ignored) {
                    // best effort
                }
                PENDING.set(null);
            }
            throw new ExitException(ExitCodes.OUTPUT, "cannot write " + out + ": " + ex.getMessage());
        }
    }
}
