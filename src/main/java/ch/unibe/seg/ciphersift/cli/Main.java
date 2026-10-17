/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.cli;

import ch.unibe.seg.ciphersift.CipherSift;
import ch.unibe.seg.ciphersift.cli.ExitCodes.ExitException;
import ch.unibe.seg.ciphersift.natives.Grammars;
import ch.unibe.seg.ciphersift.natives.NativeLoadException;
import ch.unibe.seg.ciphersift.rules.RuleException;
import ch.unibe.seg.ciphersift.rules.RuleLoader;
import ch.unibe.seg.ciphersift.rules.RuleSet;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import picocli.CommandLine;
import picocli.CommandLine.Command;

/** Command-line wiring (picocli) and exit-code mapping (SPEC 3.3). */
public final class Main {
    private Main() {}

    /** The root command {@code ciphersift}. */
    @Command(name = "ciphersift", mixinStandardHelpOptions = true, versionProvider = VersionProvider.class,
            description = "Finds cryptographic assets in Java and Python sources and dependency manifests "
                    + "and writes a CycloneDX 1.7 (or 1.6) CBOM.",
            subcommands = {ScanCommand.class, RulesCommand.class})
    public static final class Root implements Runnable {
        @picocli.CommandLine.Spec
        picocli.CommandLine.Model.CommandSpec spec;

        @Override
        public void run() {
            throw new CommandLine.ParameterException(spec.commandLine(), "missing command (scan, rules)");
        }
    }

    /** {@code --version}: CipherSift, jtreesitter and grammar ABI versions (SPEC 15.3). */
    public static final class VersionProvider implements CommandLine.IVersionProvider {
        @Override
        public String[] getVersion() {
            List<String> l = new ArrayList<>();
            l.add("ciphersift " + CipherSift.version());
            l.add("jtreesitter " + CipherSift.jtreesitterVersion());
            try {
                Grammars g = Grammars.get();
                l.add("tree-sitter-java ABI " + g.java().getAbiVersion());
                l.add("tree-sitter-python ABI " + g.python().getAbiVersion());
            } catch (NativeLoadException | LinkageError ex) {
                l.add("native libraries: not available (" + ex.getMessage() + ")");
            }
            return l.toArray(new String[0]);
        }
    }

    /**
     * Start-up optimisation: work without side effects that a {@code scan} or {@code rules validate}
     * will certainly need starts on background threads while picocli parses the command line —
     * the bundled rules (unless {@code --rules} is given) and, if they are already in the cache
     * (so that nothing is written), the native libraries. Errors surface later, in the specified
     * order of checks, when the results are used.
     */
    private static void prefetch(String[] args) {
        if (args.length == 0 || !("scan".equals(args[0]) || "rules".equals(args[0]))) {
            return;
        }
        boolean ownRules = false;
        for (String a : args) {
            if ("--rules".equals(a) || a.startsWith("--rules=")) {
                ownRules = true;
            }
        }
        if (!ownRules) {
            RuleLoader.prefetchBundled();
        }
        if ("scan".equals(args[0]) && ch.unibe.seg.ciphersift.natives.NativeLibraries.cachedAlready()) {
            ch.unibe.seg.ciphersift.scan.Scanner.prefetchNatives();
        }
    }

    /**
     * DECISIONS O1: file names are read as UTF-8 under any locale, but the JVM decodes the command
     * line with the locale's charset. Under a non-UTF-8 locale an argument with non-ASCII bytes
     * arrives with U+FFFD in it; say so instead of failing obscurely later.
     */
    private static void warnUndecodableArguments(String[] args) {
        if (ch.unibe.seg.ciphersift.files.FileNames.jvmUsesUtf8()) {
            return;
        }
        for (String a : args) {
            if (a.indexOf('\uFFFD') >= 0) {
                Log.warning("a command-line argument could not be decoded with the locale's character set ("
                        + System.getProperty("sun.jnu.encoding") + "): " + a
                        + "; run under a UTF-8 locale (e.g. LC_ALL=C.UTF-8) or through bin/ciphersift");
                return;
            }
        }
    }

    /** Loads the bundled rules or those of {@code dir}; exit 4 on failure. */
    static RuleSet loadRules(String dir) {
        try {
            if (dir == null) {
                return RuleLoader.loadBundled();
            }
            Path p;
            try {
                p = Path.of(dir);
            } catch (InvalidPathException ex) {
                throw new RuleException(dir + ": invalid path");
            }
            return RuleLoader.loadDirectory(p);
        } catch (RuleException ex) {
            for (String problem : ex.problems()) {
                Log.error("rule error: " + problem);
            }
            throw new ExitException(ExitCodes.RULES, null);
        }
    }

    public static int run(String[] args) {
        Log.setThreshold(Log.Level.INFO);
        prefetch(args);
        warnUndecodableArguments(args);
        CommandLine cl = new CommandLine(new Root());
        cl.setCaseInsensitiveEnumValuesAllowed(false);
        cl.setOut(new PrintWriter(new java.io.OutputStreamWriter(System.out, StandardCharsets.UTF_8), true));
        cl.setErr(new PrintWriter(new java.io.OutputStreamWriter(System.err, StandardCharsets.UTF_8), true));
        cl.setParameterExceptionHandler((ex, a) -> {
            Log.error(ex.getMessage());
            CommandLine c = ex.getCommandLine();
            c.getErr().println("Try '" + c.getCommandSpec().qualifiedName() + " --help' for more information.");
            c.getErr().flush();
            return ExitCodes.USAGE;
        });
        cl.setExecutionExceptionHandler((ex, c, parseResult) -> {
            if (ex instanceof ExitException ee) {
                if (ee.getMessage() != null) {
                    Log.error(ee.getMessage());
                }
                return ee.code();
            }
            if (ex instanceof CommandLine.ParameterException pe) {
                Log.error(pe.getMessage());
                return ExitCodes.USAGE;
            }
            if (ex instanceof NativeLoadException) {
                Log.error(ex.getMessage());
                return ExitCodes.INTERNAL;
            }
            Log.error("internal error: " + ex);
            if (Log.enabled(Log.Level.DEBUG)) {
                ex.printStackTrace(System.err);
            }
            return ExitCodes.INTERNAL;
        });
        try {
            return cl.execute(args);
        } catch (RuntimeException | LinkageError ex) {
            Log.error("internal error: " + ex);
            return ExitCodes.INTERNAL;
        }
    }
}
