/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.scan;

import ch.unibe.seg.ciphersift.cbom.Component;
import ch.unibe.seg.ciphersift.cbom.Normaliser;
import ch.unibe.seg.ciphersift.cli.Log;
import ch.unibe.seg.ciphersift.deps.DependencyScanner;
import ch.unibe.seg.ciphersift.deps.SetupManifests;
import ch.unibe.seg.ciphersift.files.FileClass;
import ch.unibe.seg.ciphersift.files.FileCollector;
import ch.unibe.seg.ciphersift.files.FileCollector.CollectedFile;
import ch.unibe.seg.ciphersift.files.Glob;
import ch.unibe.seg.ciphersift.files.SourceText;
import ch.unibe.seg.ciphersift.lang.go.GoAnalyzer;
import ch.unibe.seg.ciphersift.lang.java.JavaAnalyzer;
import ch.unibe.seg.ciphersift.lang.java.JavaContexts;
import ch.unibe.seg.ciphersift.lang.python.PythonAnalyzer;
import ch.unibe.seg.ciphersift.model.DependencyFinding;
import ch.unibe.seg.ciphersift.model.FileFindings;
import ch.unibe.seg.ciphersift.model.SourceFinding;
import ch.unibe.seg.ciphersift.natives.Grammars;
import ch.unibe.seg.ciphersift.rules.RuleSet;
import ch.unibe.seg.ciphersift.syntax.SyntaxTrees;
import io.github.treesitter.jtreesitter.Language;
import io.github.treesitter.jtreesitter.Parser;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/** Runs phases 1–4 of a scan (SPEC 2): collection, classification, extraction, normalisation. */
public final class Scanner {
    /** Scan options. {@code root} must be the canonical scan root. */
    public record Options(Path root, List<Glob> excludes, boolean excludeTests, int threads, RuleSet rules,
            boolean weaknessIndicators) {
        /** Options of a scan without weakness indicators (the default, DECISIONS E2). */
        public Options(Path root, List<Glob> excludes, boolean excludeTests, int threads, RuleSet rules) {
            this(root, excludes, excludeTests, threads, rules, false);
        }
    }

    /** What happened to one file. */
    enum Outcome { JAVA, PYTHON, GO, MANIFEST, SKIPPED }

    private record FileResult(Outcome outcome, FileFindings findings) {}

    /** The result of a scan. */
    public record Result(List<Component> components, int javaFiles, int pythonFiles, int goFiles, int manifests,
            int skipped, int findings) {
        public int scanned() {
            return javaFiles + pythonFiles + goFiles + manifests;
        }
    }

    private final Options options;
    private final Language javaLanguage;
    private final Language pythonLanguage;
    private final Language goLanguage;
    private final List<Parser> parsers = Collections.synchronizedList(new ArrayList<>());
    private final ThreadLocal<Parser> javaParser;
    private final ThreadLocal<Parser> pythonParser;
    private final ThreadLocal<Parser> goParser;
    private final JavaAnalyzer javaAnalyzer;
    private final PythonAnalyzer pythonAnalyzer;
    private final GoAnalyzer goAnalyzer;
    private final DependencyScanner dependencyScanner;
    private final AnchorPrefilter javaFilter;
    private final AnchorPrefilter pythonFilter;
    private final AnchorPrefilter goFilter;

    /**
     * System property that disables the anchor pre-filter (every source file is parsed and analysed).
     * The output is the same either way; this exists for tests and measurements.
     */
    static final String NO_PREFILTER = "ciphersift.noPrefilter";

    public Scanner(Options options) {
        this.options = options;
        Grammars g = Grammars.get();
        this.javaLanguage = g.java();
        this.pythonLanguage = g.python();
        this.goLanguage = g.go();
        this.javaParser = ThreadLocal.withInitial(() -> newParser(javaLanguage));
        this.pythonParser = ThreadLocal.withInitial(() -> newParser(pythonLanguage));
        this.goParser = ThreadLocal.withInitial(() -> newParser(goLanguage));
        JavaContexts contexts = new JavaContexts(options.root(), javaLanguage, javaParser::get);
        this.javaAnalyzer = new JavaAnalyzer(options.rules(), contexts);
        this.pythonAnalyzer = new PythonAnalyzer(options.rules());
        this.goAnalyzer = new GoAnalyzer(options.rules());
        this.dependencyScanner = new DependencyScanner(options.rules());
        boolean filter = !Boolean.getBoolean(NO_PREFILTER);
        this.javaFilter = filter ? AnchorPrefilter.java(options.rules().javaRules()) : AnchorPrefilter.ALL;
        this.pythonFilter = filter ? AnchorPrefilter.python(options.rules().pythonRules()) : AnchorPrefilter.ALL;
        this.goFilter = filter ? AnchorPrefilter.go(options.rules().goRules()) : AnchorPrefilter.ALL;
    }

    /**
     * Starts loading the native libraries and grammars on a background thread (and makes a first,
     * throw-away parse with each grammar), so that this start-up work overlaps with loading the rules.
     * Purely an optimisation: failures are ignored here and surface, in the specified order of checks,
     * when {@link Scanner} needs the grammars.
     */
    public static void prefetchNatives() {
        if (!PREFETCH_STARTED.compareAndSet(false, true)) {
            return;
        }
        Thread t = new Thread(() -> {
            try {
                Grammars g = Grammars.get();
                SyntaxTrees.warmUp(g.java());
                SyntaxTrees.warmUp(g.python());
                SyntaxTrees.warmUp(g.go());
            } catch (RuntimeException | LinkageError ex) {
                // reported later by Grammars.get() on the scanning thread
            }
        }, "ciphersift-prefetch");
        t.setDaemon(true);
        t.start();
    }

    private static final java.util.concurrent.atomic.AtomicBoolean PREFETCH_STARTED =
            new java.util.concurrent.atomic.AtomicBoolean();

    private Parser newParser(Language l) {
        Parser p = new Parser(l);
        parsers.add(p);
        return p;
    }

    public Result run() throws InterruptedException {
        List<CollectedFile> files = new FileCollector(options.root(), options.excludes(), options.excludeTests())
                .collect();
        List<FileResult> results = new ArrayList<>(files.size());
        // never more workers than files (a huge --threads value must not create thousands of threads)
        int threads = Math.max(1, Math.min(options.threads(), files.size()));
        if (threads == 1) {
            for (CollectedFile f : files) {
                if (Thread.interrupted()) {
                    throw new InterruptedException();
                }
                results.add(process(f));
            }
        } else {
            AtomicInteger n = new AtomicInteger();
            ThreadFactory tf = r -> {
                Thread t = new Thread(r, "ciphersift-worker-" + n.incrementAndGet());
                t.setDaemon(true);
                return t;
            };
            ExecutorService pool = Executors.newFixedThreadPool(threads, tf);
            try {
                List<Future<FileResult>> futures = new ArrayList<>(files.size());
                for (CollectedFile f : files) {
                    futures.add(pool.submit(() -> process(f)));
                }
                for (Future<FileResult> fu : futures) {
                    try {
                        results.add(fu.get());
                    } catch (ExecutionException ex) {
                        // process() handles all per-file failures; anything else is internal
                        throw new IllegalStateException("internal error in worker", ex.getCause());
                    }
                }
            } finally {
                pool.shutdownNow();
            }
        }
        synchronized (parsers) {
            for (Parser p : parsers) {
                try {
                    p.close();
                } catch (RuntimeException ex) {
                    // ignore
                }
            }
            parsers.clear();
        }

        int java = 0;
        int python = 0;
        int go = 0;
        int manifests = 0;
        int skipped = 0;
        List<SourceFinding> source = new ArrayList<>();
        List<DependencyFinding> deps = new ArrayList<>();
        for (FileResult r : results) {
            switch (r.outcome()) {
                case JAVA -> java++;
                case PYTHON -> python++;
                case GO -> go++;
                case MANIFEST -> manifests++;
                case SKIPPED -> skipped++;
                default -> throw new IllegalStateException();
            }
            for (SourceFinding f : r.findings().source()) {
                // Findings of indicator rules are dropped after extraction unless --weakness-indicators is
                // given, so that every other finding is exactly the one of a scan with them (SPEC 3.1)
                if (options.weaknessIndicators() || f.rule().indicator() == null) {
                    source.add(f);
                }
            }
            deps.addAll(r.findings().dependencies());
        }
        List<Component> components = Normaliser.normalise(source, deps);
        int occurrences = 0;
        for (Component c : components) {
            occurrences += c.occurrences().size();
        }
        return new Result(components, java, python, go, manifests, skipped, occurrences);
    }

    private static final FileResult SKIP = new FileResult(Outcome.SKIPPED, FileFindings.EMPTY);

    private FileResult process(CollectedFile f) {
        String rel = f.relativePath();
        if (f.size() > SourceText.MAX_SIZE) {
            Log.debug("skipping " + rel + ": larger than 10 MiB");
            return SKIP;
        }
        byte[] bytes;
        try {
            bytes = SourceText.readBounded(f.path());
        } catch (SourceText.TooLargeException ex) {
            Log.debug("skipping " + rel + ": larger than 10 MiB");
            return SKIP;
        } catch (IOException | SecurityException | OutOfMemoryError ex) {
            Log.warning("cannot read " + rel + ": " + message(ex));
            return SKIP;
        }
        FileClass fc = f.fileClass();
        try {
            if (fc.isSource()) {
                if (SourceText.isBinary(bytes)) {
                    Log.debug("skipping " + rel + ": binary content");
                    return SKIP;
                }
                String text = SourceText.decode(bytes);
                if (fc == FileClass.GO) {
                    return goFile(text, rel, f.test());
                }
                boolean java = fc == FileClass.JAVA;
                // setup.py is Python source and may also declare requirements (SPEC 9.8)
                boolean setupPy = !java && SetupManifests.isSetupPy(rel) && SetupManifests.maybeDeclaresRequirements(text);
                if (!setupPy && !(java ? javaFilter : pythonFilter).mayMatch(text)) {
                    // no pattern can fire: the findings are empty without parsing (see AnchorPrefilter)
                    return new FileResult(java ? Outcome.JAVA : Outcome.PYTHON, FileFindings.EMPTY);
                }
                SyntaxTrees.Parsed parsed = SyntaxTrees.parseChecked(
                        java ? javaParser.get() : pythonParser.get(), java ? javaLanguage : pythonLanguage, text);
                if (parsed.hasError()) {
                    Log.debug("syntax errors in " + rel + "; analysing the well-formed parts");
                }
                List<SourceFinding> found;
                if (java) {
                    Path abs = f.path().toAbsolutePath().normalize();
                    found = javaAnalyzer.analyze(parsed.root(), abs, rel, f.test());
                } else {
                    found = pythonAnalyzer.analyze(parsed.root(), rel, f.test());
                }
                if (setupPy) {
                    return new FileResult(Outcome.PYTHON, new FileFindings(List.copyOf(found),
                            List.copyOf(dependencyScanner.setupPy(rel, parsed.root(), f.test()))));
                }
                return new FileResult(java ? Outcome.JAVA : Outcome.PYTHON, FileFindings.ofSource(found));
            }
            try {
                return new FileResult(Outcome.MANIFEST,
                        FileFindings.ofDependencies(dependencyScanner.scan(rel, fc, bytes, f.test())));
            } catch (DependencyScanner.MalformedManifestException ex) {
                Log.warning("cannot parse manifest " + rel + ": " + ex.getMessage());
                return new FileResult(Outcome.MANIFEST, FileFindings.EMPTY);
            }
        } catch (RuntimeException | StackOverflowError ex) {
            Log.warning("analysis of " + rel + " failed (" + message(ex) + "); file skipped");
            return SKIP;
        }
    }

    /** A Go source file (SPEC 17); failures are handled by the caller like for the other languages. */
    private FileResult goFile(String text, String rel, boolean test) {
        if (!goFilter.mayMatch(text)) {
            return new FileResult(Outcome.GO, FileFindings.EMPTY);
        }
        SyntaxTrees.Parsed parsed = SyntaxTrees.parseChecked(goParser.get(), goLanguage, text);
        if (parsed.hasError()) {
            Log.debug("syntax errors in " + rel + "; analysing the well-formed parts");
        }
        return new FileResult(Outcome.GO, FileFindings.ofSource(goAnalyzer.analyze(parsed.root(), rel, test)));
    }

    private static String message(Throwable ex) {
        return ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getClass().getSimpleName() + ": "
                + ex.getMessage();
    }
}
