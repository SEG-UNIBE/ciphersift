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
import ch.unibe.seg.ciphersift.rules.DependencyRule;
import ch.unibe.seg.ciphersift.rules.RuleSet;
import ch.unibe.seg.ciphersift.syntax.SyntaxNode;
import ch.unibe.seg.ciphersift.syntax.SyntaxTrees;
import ch.unibe.seg.ciphersift.util.Texts;
import ch.unibe.seg.ciphersift.wrappers.Outline;
import ch.unibe.seg.ciphersift.wrappers.Outlines;
import ch.unibe.seg.ciphersift.wrappers.WrapperOptions;
import ch.unibe.seg.ciphersift.wrappers.WrapperPass;
import io.github.treesitter.jtreesitter.Language;
import io.github.treesitter.jtreesitter.Parser;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Runs phases 1–4 of a scan (SPEC 2): collection, classification, extraction, normalisation. */
public final class Scanner {
    /** Scan options. {@code root} must be the canonical scan root. */
    public record Options(Path root, List<Glob> excludes, boolean excludeTests, int threads, RuleSet rules,
            boolean weaknessIndicators, WrapperOptions wrappers, Features features) {
        /** Options with the default feature switches (SPEC 3.1). */
        public Options(Path root, List<Glob> excludes, boolean excludeTests, int threads, RuleSet rules,
                boolean weaknessIndicators, WrapperOptions wrappers) {
            this(root, excludes, excludeTests, threads, rules, weaknessIndicators, wrappers, Features.DEFAULTS);
        }
    }

    /** What happened to one file. */
    enum Outcome { JAVA, PYTHON, GO, MANIFEST, SKIPPED }

    /**
     * @param outline the definitions and call sites for wrapper propagation (SPEC 18), or null
     * @param unparsed for a source file the pre-filter did not parse, the identifiers of its text (it may
     *        still be indexed, SPEC 18.2); else null
     */
    private record FileResult(Outcome outcome, FileFindings findings, Outline outline, IdentifierBloom unparsed) {
        FileResult(Outcome outcome, FileFindings findings) {
            this(outcome, findings, null, null);
        }
    }

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
    /** {@code usedIf} texts of the dependency rules, by source file class (SPEC 5.9, DECISIONS B-J4). */
    private final Map<FileClass, Set<String>> usedIfTexts = new EnumMap<>(FileClass.class);
    /** The {@code usedIf} texts found so far, as {@code <file class>:<text>} (thread-safe). */
    private final Set<String> usedIfFound = ConcurrentHashMap.newKeySet();

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
        this.javaAnalyzer = new JavaAnalyzer(options.rules(), contexts, options.features());
        this.pythonAnalyzer = new PythonAnalyzer(options.rules(), options.features());
        this.goAnalyzer = new GoAnalyzer(options.rules(), options.features());
        this.dependencyScanner = new DependencyScanner(options.rules(), options.features(), options.root());
        boolean filter = !Boolean.getBoolean(NO_PREFILTER);
        this.javaFilter = filter ? AnchorPrefilter.java(options.rules().javaRules(), options.features()) : AnchorPrefilter.ALL;
        this.pythonFilter = filter ? AnchorPrefilter.python(options.rules().pythonRules(), options.features()) : AnchorPrefilter.ALL;
        this.goFilter = filter ? AnchorPrefilter.go(options.rules().goRules(), options.features()) : AnchorPrefilter.ALL;
        for (DependencyRule r : options.rules().dependencyRules().values()) {
            FileClass lang = languageOf(r.ecosystem());
            if (lang != null && !r.usedIfTexts().isEmpty()) {
                usedIfTexts.computeIfAbsent(lang, k -> new TreeSet<>()).addAll(r.usedIfTexts());
            }
        }
    }

    /** The source language whose files decide {@code usedIf} entries of an ecosystem (SPEC 5.9). */
    static FileClass languageOf(String ecosystem) {
        return switch (ecosystem) {
            case "maven" -> FileClass.JAVA;
            case "pypi" -> FileClass.PYTHON;
            case "golang" -> FileClass.GO;
            default -> null;
        };
    }

    /** Records which {@code usedIf} texts of the file's language occur in its text. */
    private void noteUsedIf(FileClass fc, String text) {
        Set<String> ts = usedIfTexts.get(fc);
        if (ts != null) {
            for (String t : ts) {
                if (text.contains(t)) {
                    usedIfFound.add(fc + ":" + t);
                }
            }
        }
    }

    /** Whether a dependency finding passes its {@code usedIf} condition (SPEC 5.9, DECISIONS B-J4). */
    private boolean used(DependencyFinding d) {
        List<String> need = d.rule().usedIf(d.packageKey());
        if (need.isEmpty()) {
            return true;
        }
        FileClass lang = languageOf(d.ecosystem());
        for (String t : need) {
            if (usedIfFound.contains(lang + ":" + t)) {
                return true;
            }
        }
        return false;
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

    private static final AtomicBoolean PREFETCH_STARTED = new AtomicBoolean();

    private Parser newParser(Language l) {
        Parser p = new Parser(l);
        parsers.add(p);
        return p;
    }

    public Result run() throws InterruptedException {
        List<CollectedFile> files = new FileCollector(options.root(), options.excludes(), options.excludeTests())
                .collect();
        List<FileResult> results = parallel(files, this::process, "ciphersift-worker-");
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
            for (DependencyFinding d : r.findings().dependencies()) {
                if (used(d)) {
                    deps.add(d);
                }
            }
        }
        if (options.wrappers().any()) {
            try {
                source.addAll(propagate(files, results, source));
            } catch (RuntimeException | StackOverflowError | OutOfMemoryError ex) {
                // an internal failure of the pass must not cost the findings of phase 3 (SPEC 13)
                Log.warning("wrapper propagation failed (" + message(ex) + "); its findings are omitted");
            }
        }
        closeParsers();
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
                noteUsedIf(fc, text);
                return sourceFile(f, text);
            }
            try {
                List<DependencyFinding> deps = dependencyScanner.scan(rel, fc, bytes, f.test());
                if (options.excludeTests()) {
                    // test-scoped entries are test occurrences (t3 J-TSCOPE); --exclude-tests drops them
                    deps = deps.stream().filter(d -> !d.test()).toList();
                }
                return new FileResult(Outcome.MANIFEST, FileFindings.ofDependencies(deps));
            } catch (DependencyScanner.MalformedManifestException ex) {
                Log.warning("cannot parse manifest " + rel + ": " + ex.getMessage());
                return new FileResult(Outcome.MANIFEST, FileFindings.EMPTY);
            }
        } catch (RuntimeException | StackOverflowError ex) {
            Log.warning("analysis of " + rel + " failed (" + message(ex) + "); file skipped");
            return SKIP;
        }
    }

    /**
     * The findings and outline of a decoded Java, Python or Go source file (SPEC 7, 8, 17); failures are handled
     * by the caller.
     */
    private FileResult sourceFile(CollectedFile f, String text) {
        FileClass fc = f.fileClass();
        String rel = f.relativePath();
        Outcome outcome = switch (fc) {
            case JAVA -> Outcome.JAVA;
            case PYTHON -> Outcome.PYTHON;
            case GO -> Outcome.GO;
            default -> throw new IllegalArgumentException("not a source file: " + rel);
        };
        // setup.py is Python source and may also declare requirements (SPEC 9.8)
        boolean setupPy = fc == FileClass.PYTHON && SetupManifests.isSetupPy(rel)
                && SetupManifests.maybeDeclaresRequirements(text);
        if (!setupPy && !prefilter(fc).mayMatch(text)) {
            // no pattern can fire: the findings are empty without parsing (see AnchorPrefilter)
            return new FileResult(outcome, FileFindings.EMPTY, null, bloom(fc, text));
        }
        SyntaxTrees.Parsed parsed = SyntaxTrees.parseChecked(parser(fc), language(fc), text);
        if (parsed.hasError()) {
            Log.debug("syntax errors in " + rel + "; analysing the well-formed parts");
        }
        List<SourceFinding> found = switch (fc) {
            case JAVA -> javaAnalyzer.analyze(parsed.root(), f.path().toAbsolutePath().normalize(), rel, f.test());
            case PYTHON -> pythonAnalyzer.analyze(parsed.root(), rel, f.test());
            default -> goAnalyzer.analyze(parsed.root(), rel, f.test());
        };
        Outline outline = outline(fc, parsed.root(), rel, f.test());
        if (setupPy) {
            return new FileResult(Outcome.PYTHON, new FileFindings(List.copyOf(found),
                    List.copyOf(dependencyScanner.setupPy(rel, parsed.root(), f.test()))), outline, null);
        }
        return new FileResult(outcome, FileFindings.ofSource(found), outline, null);
    }

    /** The anchor pre-filter of a source language. */
    private AnchorPrefilter prefilter(FileClass fc) {
        return switch (fc) {
            case JAVA -> javaFilter;
            case PYTHON -> pythonFilter;
            case GO -> goFilter;
            default -> throw new IllegalArgumentException(fc.name());
        };
    }

    /** This thread's parser of a source language. */
    private Parser parser(FileClass fc) {
        return switch (fc) {
            case JAVA -> javaParser.get();
            case PYTHON -> pythonParser.get();
            case GO -> goParser.get();
            default -> throw new IllegalArgumentException(fc.name());
        };
    }

    /** The grammar of a source language. */
    private Language language(FileClass fc) {
        return switch (fc) {
            case JAVA -> javaLanguage;
            case PYTHON -> pythonLanguage;
            case GO -> goLanguage;
            default -> throw new IllegalArgumentException(fc.name());
        };
    }

    // ====================================================================== wrapper propagation (SPEC 18)

    private static Outline.Lang lang(FileClass fc) {
        return switch (fc) {
            case JAVA -> Outline.Lang.JAVA;
            case PYTHON -> Outline.Lang.PYTHON;
            case GO -> Outline.Lang.GO;
            default -> null;
        };
    }

    /** The identifiers of a file the pre-filter skipped, if propagation is on for its language. */
    private IdentifierBloom bloom(FileClass fc, String text) {
        Outline.Lang l = lang(fc);
        return l != null && options.wrappers().on(l) ? IdentifierBloom.of(text) : null;
    }

    /** The outline of a parsed file if propagation is on for its language; null if it fails (SPEC 13). */
    private Outline outline(FileClass fc, SyntaxNode root, String rel, boolean test) {
        Outline.Lang l = lang(fc);
        if (l == null || !options.wrappers().on(l)) {
            return null;
        }
        try {
            return Outlines.of(l, root, rel, test, options.features().on(Features.JAVA_CONSTRUCTOR_WRAPPERS));
        } catch (RuntimeException | StackOverflowError ex) {
            Log.debug("cannot index " + rel + " for wrapper propagation (" + message(ex) + ")");
            return null;
        }
    }

    /** Parses and outlines a file the pre-filter skipped (SPEC 18.2); null if it cannot be read or parsed. */
    private Outline outlineSkipped(CollectedFile f, String text) {
        try {
            FileClass fc = f.fileClass();
            return outline(fc, SyntaxTrees.parseChecked(parser(fc), language(fc), text).root(), f.relativePath(),
                    f.test());
        } catch (RuntimeException | StackOverflowError ex) {
            Log.debug("cannot index " + f.relativePath() + " for wrapper propagation (" + message(ex) + ")");
            return null;
        }
    }

    /** The decoded text of a source file, or null (unreadable, too large, binary). */
    private static String readText(CollectedFile f) {
        try {
            byte[] bytes = SourceText.readBounded(f.path());
            if (SourceText.isBinary(bytes)) {
                return null;
            }
            return SourceText.decode(bytes);
        } catch (IOException | SecurityException | OutOfMemoryError ex) {
            return null;
        }
    }

    /** Whether the text has an identifier (SPEC 18.2) in {@code names}. */
    static boolean hasIdentifier(String text, Set<String> names) {
        return new NameSet(names).occursIn(text);
    }

    /**
     * A set of identifiers that can be looked up while scanning a text, without creating a string
     * per identifier: open addressing on {@link String#hashCode()} values.
     */
    static final class NameSet {
        private final int[] hashes;
        private final String[] names;
        private final int mask;

        NameSet(Set<String> s) {
            int cap = Integer.highestOneBit(Math.max(4, s.size() * 4 - 1)) << 1;
            hashes = new int[cap];
            names = new String[cap];
            mask = cap - 1;
            for (String n : s) {
                int i = n.hashCode() & mask;
                while (names[i] != null) {
                    i = (i + 1) & mask;
                }
                names[i] = n;
                hashes[i] = n.hashCode();
            }
        }

        private boolean contains(String text, int from, int to, int h) {
            for (int i = h & mask; names[i] != null; i = (i + 1) & mask) {
                if (hashes[i] == h && names[i].length() == to - from && text.regionMatches(from, names[i], 0, to - from)) {
                    return true;
                }
            }
            return false;
        }

        boolean occursIn(String text) {
            int n = text.length();
            int i = 0;
            while (i < n) {
                char c = text.charAt(i);
                if (Character.isLetter(c) || c == '_' || c == '$') {
                    int s = i;
                    int h = 0;
                    while (i < n) {
                        char d = text.charAt(i);
                        if (!(Character.isLetterOrDigit(d) || d == '_' || d == '$')) {
                            break;
                        }
                        h = 31 * h + d;
                        i++;
                    }
                    if (contains(text, s, i, h)) {
                        return true;
                    }
                } else if (Character.isDigit(c)) {
                    while (i < n && (Character.isLetterOrDigit(text.charAt(i)) || text.charAt(i) == '_')) {
                        i++;
                    }
                } else {
                    i++;
                }
            }
            return false;
        }
    }

    private static final Pattern GO_MODULE = Pattern.compile("^\\s*module\\s+\"?([^\\s\"]+)\"?");

    /** The findings of wrapper propagation (SPEC 18). */
    private List<SourceFinding> propagate(List<CollectedFile> files, List<FileResult> results,
            List<SourceFinding> direct) throws InterruptedException {
        Map<String, Outline> outlines = new HashMap<>();
        List<CollectedFile> unparsed = new ArrayList<>();
        Map<CollectedFile, IdentifierBloom> blooms = new IdentityHashMap<>();
        Map<String, CollectedFile> byPath = new HashMap<>();
        for (int i = 0; i < files.size(); i++) {
            CollectedFile f = files.get(i);
            FileResult r = results.get(i);
            byPath.put(f.relativePath(), f);
            if (r.outline() != null) {
                outlines.put(f.relativePath(), r.outline());
            } else if (r.unparsed() != null) {
                unparsed.add(f);
                blooms.put(f, r.unparsed());
            }
        }
        WrapperPass pass = new WrapperPass(options.wrappers(), project(files, results));
        Map<Outline.Lang, Set<String>> checked = new HashMap<>();
        while (true) {
            pass.compute(outlines, direct);
            Map<Outline.Lang, Set<String>> fresh = freshNames(pass.callableNames(), checked);
            if (fresh.isEmpty() || unparsed.isEmpty()) {
                break;
            }
            List<CollectedFile> rest = outlineMentioning(fresh, unparsed, blooms, outlines);
            if (rest.size() == unparsed.size()) {
                break;
            }
            unparsed = rest;
        }
        WrapperPass.Result r = pass.report(path -> {
            CollectedFile f = byPath.get(path);
            return f == null ? null : readText(f);
        });
        Log.debug("wrapper propagation: " + r.callables() + " callables, " + r.findings().size() + " occurrences, "
                + r.ambiguous() + " ambiguous calls skipped");
        return r.findings();
    }

    /** The project facts of SPEC 18.4: Java files, Python modules, Go directories and the modules of go.mod files. */
    private static WrapperPass.Project project(List<CollectedFile> files, List<FileResult> results) {
        Set<String> javaFiles = new HashSet<>();
        Set<String> pythonModules = new HashSet<>();
        Set<String> goDirs = new HashSet<>();
        Map<String, String> goModules = new TreeMap<>(Texts.CODE_POINT_ORDER);
        for (int i = 0; i < files.size(); i++) {
            CollectedFile f = files.get(i);
            String rel = f.relativePath();
            switch (f.fileClass()) {
                case JAVA -> javaFiles.add(rel);
                case PYTHON -> pythonModules.add(WrapperPass.pythonModule(rel));
                case GO -> goDirs.add(WrapperPass.dirOf(rel));
                case GO_MOD -> {
                    String module = results.get(i).outcome() == Outcome.MANIFEST ? goModule(f) : null;
                    if (module != null) {
                        goModules.put(WrapperPass.dirOf(rel), module);
                    }
                }
                default -> {
                    // nothing
                }
            }
        }
        return new WrapperPass.Project(javaFiles, pythonModules, goDirs, goModules);
    }

    /** The module path of a go.mod file (its first {@code module} line), or null. */
    private static String goModule(CollectedFile f) {
        String t = readText(f);
        if (t != null) {
            for (String line : t.split("\n")) {
                Matcher m = GO_MODULE.matcher(line);
                if (m.find()) {
                    return m.group(1);
                }
            }
        }
        return null;
    }

    /** The callable names of each language that are not in {@code checked} yet; adds them all to {@code checked}. */
    private static Map<Outline.Lang, Set<String>> freshNames(Map<Outline.Lang, Set<String>> names,
            Map<Outline.Lang, Set<String>> checked) {
        Map<Outline.Lang, Set<String>> fresh = new HashMap<>();
        for (Map.Entry<Outline.Lang, Set<String>> e : names.entrySet()) {
            Set<String> s = new HashSet<>(e.getValue());
            s.removeAll(checked.getOrDefault(e.getKey(), Set.of()));
            if (!s.isEmpty()) {
                fresh.put(e.getKey(), s);
            }
            checked.computeIfAbsent(e.getKey(), k -> new HashSet<>()).addAll(e.getValue());
        }
        return fresh;
    }

    /**
     * Parses and outlines the files the pre-filter skipped that mention one of the {@code fresh} names (SPEC 18.2),
     * adding them to {@code outlines}; returns the files still not outlined, in their order.
     */
    private List<CollectedFile> outlineMentioning(Map<Outline.Lang, Set<String>> fresh, List<CollectedFile> unparsed,
            Map<CollectedFile, IdentifierBloom> blooms, Map<String, Outline> outlines) throws InterruptedException {
        Map<Outline.Lang, NameSet> sets = new HashMap<>();
        fresh.forEach((k, v) -> sets.put(k, new NameSet(v)));
        List<Outline> got = parallel(unparsed, f -> {
            NameSet s = sets.get(lang(f.fileClass()));
            if (s == null) {
                return null;
            }
            IdentifierBloom b = blooms.get(f);
            if (fresh.get(lang(f.fileClass())).stream().noneMatch(b::mightContain)) {
                return null;
            }
            String t = readText(f);
            return t != null && s.occursIn(t) ? outlineSkipped(f, t) : null;
        }, "ciphersift-index-");
        List<CollectedFile> rest = new ArrayList<>();
        for (int i = 0; i < unparsed.size(); i++) {
            Outline o = got.get(i);
            if (o != null) {
                outlines.put(unparsed.get(i).relativePath(), o);
            } else {
                rest.add(unparsed.get(i));
            }
        }
        return rest;
    }

    /**
     * Applies {@code fn} to every element on up to {@code --threads} daemon threads named {@code threadPrefix} and
     * a number; results in input order. {@code fn} handles its own per-element failures (SPEC 13): an exception
     * that escapes it is an internal error.
     */
    private <T, R> List<R> parallel(List<T> in, Function<T, R> fn, String threadPrefix) throws InterruptedException {
        List<R> out = new ArrayList<>(in.size());
        // never more workers than elements (a huge --threads value must not create thousands of threads)
        int threads = Math.max(1, Math.min(options.threads(), in.size()));
        if (threads == 1) {
            for (T t : in) {
                if (Thread.interrupted()) {
                    throw new InterruptedException();
                }
                out.add(fn.apply(t));
            }
            return out;
        }
        AtomicInteger n = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(threads, r -> {
            Thread t = new Thread(r, threadPrefix + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        });
        try {
            List<Future<R>> futures = new ArrayList<>(in.size());
            for (T t : in) {
                futures.add(pool.submit(() -> fn.apply(t)));
            }
            for (Future<R> fu : futures) {
                try {
                    out.add(fu.get());
                } catch (ExecutionException ex) {
                    throw new IllegalStateException("internal error in worker", ex.getCause());
                }
            }
        } finally {
            pool.shutdownNow();
        }
        return out;
    }

    private void closeParsers() {
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
    }

    private static String message(Throwable ex) {
        return ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getClass().getSimpleName() + ": "
                + ex.getMessage();
    }
}
