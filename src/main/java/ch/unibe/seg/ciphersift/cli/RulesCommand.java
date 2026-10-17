/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.cli;

import ch.unibe.seg.ciphersift.cli.ExitCodes.ExitException;
import ch.unibe.seg.ciphersift.rules.RuleException;
import ch.unibe.seg.ciphersift.rules.RuleLoader;
import ch.unibe.seg.ciphersift.rules.RuleSet;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/** {@code ciphersift rules validate|export} (SPEC 3.1). */
@Command(name = "rules", mixinStandardHelpOptions = true, versionProvider = Main.VersionProvider.class,
        description = "Validate or export rules.",
        subcommands = {RulesCommand.Validate.class, RulesCommand.Export.class})
public final class RulesCommand implements Callable<Integer> {
    @picocli.CommandLine.Spec
    picocli.CommandLine.Model.CommandSpec spec;

    @Override
    public Integer call() {
        throw new picocli.CommandLine.ParameterException(spec.commandLine(), "missing subcommand: validate or export");
    }

    /** {@code rules validate [--rules DIR]}. */
    @Command(name = "validate", mixinStandardHelpOptions = true, versionProvider = Main.VersionProvider.class,
            description = "Load and validate the bundled rules (or --rules DIR) and print counts.")
    public static final class Validate implements Callable<Integer> {
        @Option(names = "--rules", paramLabel = "DIR", description = "Rule directory instead of the bundled rules.")
        String rulesDir;

        @Override
        public Integer call() {
            RuleSet r = Main.loadRules(rulesDir);
            PrintStream o = System.out;
            o.println("source java: " + r.javaRules().size());
            o.println("source python: " + r.pythonRules().size());
            o.println("source go: " + r.goRules().size());
            o.println("constants java: " + r.constantsDocuments());
            o.println("dependency maven: " + (r.dependencyRule("maven") == null ? 0 : 1));
            o.println("dependency pypi: " + (r.dependencyRule("pypi") == null ? 0 : 1));
            o.println("dependency golang: " + (r.dependencyRule("golang") == null ? 0 : 1));
            o.flush();
            return ExitCodes.OK;
        }
    }

    /** {@code rules export <dir>}. */
    @Command(name = "export", mixinStandardHelpOptions = true, versionProvider = Main.VersionProvider.class,
            description = "Write the bundled rule files into <dir>.")
    public static final class Export implements Callable<Integer> {
        @Parameters(index = "0", paramLabel = "<dir>", description = "Target directory (created if missing).")
        String dir;

        @Override
        public Integer call() {
            Path target;
            try {
                target = Path.of(dir);
            } catch (InvalidPathException ex) {
                throw new ExitException(ExitCodes.OUTPUT, "invalid directory " + dir);
            }
            try {
                for (RuleLoader.RuleFile f : RuleLoader.bundledFiles()) {
                    Path p = target.resolve(f.path());
                    Files.createDirectories(p.getParent());
                    Files.write(p, f.bytes());
                }
            } catch (RuleException ex) {
                throw new ExitException(ExitCodes.RULES, ex.getMessage());
            } catch (IOException | SecurityException ex) {
                throw new ExitException(ExitCodes.OUTPUT, "cannot write rules to " + dir + ": " + ex.getMessage());
            }
            return ExitCodes.OK;
        }
    }
}
