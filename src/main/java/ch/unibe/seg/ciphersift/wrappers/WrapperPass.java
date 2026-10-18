/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.wrappers;

import ch.unibe.seg.ciphersift.model.SourceFinding;
import ch.unibe.seg.ciphersift.rules.SourceRule;
import ch.unibe.seg.ciphersift.scan.Features;
import ch.unibe.seg.ciphersift.util.Texts;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Function;

/**
 * Wrapper propagation (SPEC 18): from the outlines of the project's source files and the findings of
 * phase 3, the crypto callables (18.5) and the propagated findings at their call sites (18.7).
 *
 * <p>Contract: {@link #compute} builds the definition index and the callables from scratch for the
 * current outlines; {@link #callableNames} tells the caller which further files to index (18.2);
 * {@link #report} then yields the additional findings. Nothing here depends on iteration order of
 * hash maps: outlines are visited in path order, definitions and calls in file order.
 */
public final class WrapperPass {
    /** SPEC 18.5: the longest chain, 4 definitions (DECISIONS B-C), 3 with {@code wrapper-depth-4=off}. */
    private final int maxDepth;
    /** Safety bound on the number of levels; the computation stops earlier when nothing changes. */
    static final int MAX_LEVELS = 1000;
    /** SPEC 18.5: the span limit of a thin wrapper, by language (DECISIONS T3, B-J-G, B-G-E). */
    private int thinLines(Outline.Lang l) {
        return switch (l) {
            case JAVA -> options.features().on(Features.JAVA_THIN_12) ? 12 : 8;
            case PYTHON -> 8;
            case GO -> 12;
        };
    }

    /**
     * Whether a line of definition {@code d} lies in one of its conditional returns (Go only: SPEC 18.5,
     * fallback-getter guard, DECISIONS B-G-E). Such findings and calls do not count for the thin-wrapper test.
     */
    private static boolean guarded(Outline o, int d, int line) {
        List<int[]> g = o.goGuards.get(d);
        if (g == null) {
            return false;
        }
        for (int[] r : g) {
            if (r[0] <= line && line <= r[1]) {
                return true;
            }
        }
        return false;
    }
    static final int MAX_REEXPORT_HOPS = 4;
    static final int SNIPPET_MAX = 500;

    /** Project facts beyond the outlines (SPEC 18.4). */
    /**
     * @param javaFiles relative paths of all Java files
     * @param pythonModules module names (SPEC 18.2) of all Python files
     * @param goDirs directories of all Go files
     * @param goModules directory → module path of every {@code go.mod}
     */
    public record Project(Set<String> javaFiles, Set<String> pythonModules, Set<String> goDirs,
            Map<String, String> goModules) {}

    /** The result of {@link #report}. */
    public record Result(List<SourceFinding> findings, int callables, int ambiguous) {}

    /** A Go package whose name names family keys, with its first non-test finding per such key (SPEC 18.8). */
    record GoPkg(String dir, String name, TreeMap<String, SourceFinding> evidence) {}

    /** Member names that a package-name call does not count for (SPEC 18.8): sizes, encodings, look-ups, names. */
    static final java.util.regex.Pattern GO_PKG_EXCLUDED = java.util.regex.Pattern.compile(
            "length|size|encode|decode|fields|find|name|string|params|oid|info", java.util.regex.Pattern.CASE_INSENSITIVE);

    /** A definition in the index, with its body findings and what it carries. */
    static final class Node {
        final Outline o;
        final Outline.Def d;
        final Set<String> nameFams;
        /** Family key → evidence (first body finding by line, then rule id). */
        final TreeMap<String, SourceFinding> direct = new TreeMap<>(Texts.CODE_POINT_ORDER);
        /** Family key → evidence for the thin-wrapper test: body findings outside guarded lines (SPEC 18.5). */
        final TreeMap<String, SourceFinding> thinDirect = new TreeMap<>(Texts.CODE_POINT_ORDER);
        /** Family key → carried evidence. */
        final TreeMap<String, Carry> carry = new TreeMap<>(Texts.CODE_POINT_ORDER);

        /** Family key → all body findings with that key, by line then rule id (for the B5 tie-break). */
        final TreeMap<String, List<SourceFinding>> bodyByKey = new TreeMap<>(Texts.CODE_POINT_ORDER);

        Node(Outline o, Outline.Def d, boolean v2, boolean u1w) {
            this.o = o;
            this.d = d;
            this.nameFams = NameTokens.families(d.name(), langPrefix(o.lang), v2,
                    u1w && o.lang == Outline.Lang.PYTHON);
        }

        String where() {
            return o.path + ":" + d.line() + " " + d.display();
        }
    }

    /** What a definition carries for one family key (SPEC 18.5). */
    record Carry(int depth, int level, SourceFinding evidence, List<Node> chain) {}

    /** Resolution of one call (SPEC 18.4). */
    private record Res(List<Node> group, List<Node> collision) {
        static final Res NONE = new Res(List.of(), List.of());

        boolean ambiguous() {
            return !collision.isEmpty();
        }
    }

    private static final Comparator<Node> NODE_ORDER = (a, b) -> {
        int c = Texts.compareCodePoints(a.o.path, b.o.path);
        return c != 0 ? c : Integer.compare(a.d.line(), b.d.line());
    };

    private final WrapperOptions options;
    private final Project project;

    // ---- state of the last compute()
    private final TreeMap<String, Outline> outlines = new TreeMap<>(Texts.CODE_POINT_ORDER);
    private final Map<Outline, List<Node>> nodes = new HashMap<>();
    private final Map<Outline, int[]> callers = new HashMap<>();
    private final Map<Outline, Res[]> resolutions = new HashMap<>();
    private List<SourceFinding> direct = List.of();

    // Java index
    private final Map<String, Outline> byPath = new HashMap<>();
    private final Map<String, Map<String, List<Node>>> javaMethods = new HashMap<>();
    // Python index
    private final Map<String, Outline> pyModules = new HashMap<>();
    private final Map<String, String> pyLookupCache = new HashMap<>();
    private final Map<String, Map<String, List<Node>>> pyFuncs = new HashMap<>();
    private final Map<String, Map<String, List<Node>>> pyMethods = new HashMap<>();
    // Go index
    /** Go package-name evidence (SPEC 18.8): package directory → (package name, family key → finding). */
    private final Map<String, GoPkg> goPkgs = new HashMap<>();
    private final Map<String, Map<String, List<Node>>> goFuncs = new HashMap<>();
    private final Map<String, Map<String, List<Node>>> goMethods = new HashMap<>();
    private final Map<String, Map<String, List<Node>>> goDirFuncs = new HashMap<>();
    private final Map<String, Map<String, List<Node>>> goDirMethods = new HashMap<>();

    public WrapperPass(WrapperOptions options, Project project) {
        this.options = options;
        this.project = project;
        this.maxDepth = options.features().on(Features.WRAPPER_DEPTH_4) ? 4 : 3;
    }

    /** The rule-id prefix of a language ({@code java}, {@code python}, {@code go}). */
    static String langPrefix(Outline.Lang l) {
        return switch (l) {
            case JAVA -> "java";
            case PYTHON -> "python";
            case GO -> "go";
        };
    }

    /** The Python module of a relative path (SPEC 18.2). */
    public static String pythonModule(String path) {
        return PythonOutliner.moduleOf(path);
    }

    /** The directory part of a relative path ("" for a file in the scan root). */
    public static String dirOf(String path) {
        return GoOutliner.dirOf(path);
    }

    /** The family key of a rule (SPEC 18.1): family, else subtype, else the rule id. */
    /** The family key of the CSPRNG findings (subtype {@code prng-secure}, SPEC 18.1). */
    static final String RANDOM_KEY = "prng-secure";

    /**
     * The keys that count for the thin-wrapper test (SPEC 18.5): a CSPRNG next to another key does not (a key
     * generator that draws from {@code SecureRandom} stays a thin wrapper of its algorithm; DECISIONS B-J-D review).
     */
    static Set<String> thinKeys(Set<String> keys) {
        if (keys.size() < 2 || !keys.contains(RANDOM_KEY)) {
            return keys;
        }
        Set<String> out = new TreeSet<>(Texts.CODE_POINT_ORDER);
        out.addAll(keys);
        out.remove(RANDOM_KEY);
        return out;
    }

    static String familyKey(SourceRule r) {
        if (r.asset().family() != null) {
            return r.asset().family();
        }
        if (r.asset().subtype() != null) {
            return r.asset().subtype();
        }
        return r.id();
    }

    /**
     * SPEC 18.1: weakness indicators are not propagated; CSPRNG findings only in Java (DECISIONS B-J-D, feature
     * {@code java-propagate-random}).
     */
    boolean propagatable(SourceFinding f) {
        if (f.rule().indicator() != null || f.via() != null) {
            return false;
        }
        if ("prng-secure".equals(f.rule().asset().subtype())) {
            return f.rule().id().startsWith("java.") && options.features().on(Features.JAVA_PROPAGATE_RANDOM);
        }
        return true;
    }

    // ======================================================================== compute

    /** Builds the index and the crypto callables for the given outlines and phase-3 findings. */
    public void compute(Map<String, Outline> all, List<SourceFinding> findings) {
        outlines.clear();
        nodes.clear();
        callers.clear();
        resolutions.clear();
        javaClassOwners.clear();
        byPath.clear();
        javaMethods.clear();
        pyModules.clear();
        pyLookupCache.clear();
        pyFuncs.clear();
        pyMethods.clear();
        goFuncs.clear();
        goMethods.clear();
        goDirFuncs.clear();
        goDirMethods.clear();
        goPkgs.clear();
        for (Outline o : all.values()) {
            if (options.on(o.lang)) {
                outlines.put(o.path, o);
            }
        }
        this.direct = findings;
        for (Outline o : outlines.values()) {
            byPath.put(o.path, o);
            List<Node> l = new ArrayList<>(o.defs.size());
            for (Outline.Def d : o.defs) {
                l.add(new Node(o, d, options.features().on(Features.WRAPPER_ALIASES_V2),
                        options.features().on(Features.PYTHON_HASH_WRAPPERS)));
            }
            nodes.put(o, l);
            index(o, l);
        }
        // callers of calls and body findings (SPEC 18.1, 18.3)
        Map<String, List<SourceFinding>> byFile = new HashMap<>();
        for (SourceFinding f : findings) {
            if (propagatable(f) && outlines.containsKey(f.path())) {
                byFile.computeIfAbsent(f.path(), k -> new ArrayList<>()).add(f);
            }
        }
        for (Outline o : outlines.values()) {
            List<Node> l = nodes.get(o);
            int[] cs = new int[o.calls.size()];
            for (int i = 0; i < cs.length; i++) {
                cs[i] = innermost(o, o.calls.get(i).line());
            }
            callers.put(o, cs);
            List<SourceFinding> fs = new ArrayList<>(byFile.getOrDefault(o.path, List.of()));
            fs.sort(Comparator.comparingInt(SourceFinding::line)
                    .thenComparing(f -> f.rule().id(), Texts.CODE_POINT_ORDER));
            for (SourceFinding f : fs) {
                int d = innermost(o, f.line());
                if (d >= 0) {
                    l.get(d).direct.putIfAbsent(familyKey(f.rule()), f);
                    l.get(d).bodyByKey.computeIfAbsent(familyKey(f.rule()), k -> new ArrayList<>()).add(f);
                    if (!guarded(o, d, f.line())) {
                        l.get(d).thinDirect.putIfAbsent(familyKey(f.rule()), f);
                    }
                }
            }
        }
        if (options.goNamed() && options.features().on(Features.GO_PACKAGE_NAMES)) {
            goPackages(byFile);
        }
        // resolutions (independent of the levels)
        for (Outline o : outlines.values()) {
            Res[] rs = new Res[o.calls.size()];
            for (int i = 0; i < rs.length; i++) {
                rs[i] = resolve(o, i);
            }
            resolutions.put(o, rs);
        }
        levels();
    }

    /**
     * The Go packages whose name names family keys and that have a non-test finding of such a key (SPEC 18.8):
     * per directory, the one package name of its non-test files (a directory with two is skipped), the first
     * finding per key by path, line and rule id.
     */
    private void goPackages(Map<String, List<SourceFinding>> byFile) {
        Map<String, Set<String>> names = new TreeMap<>(Texts.CODE_POINT_ORDER);
        for (Outline o : outlines.values()) {
            if (o.lang == Outline.Lang.GO && !o.test && !o.goPackage.isEmpty() && !o.goPackage.endsWith("_test")) {
                names.computeIfAbsent(o.goDir, k -> new TreeSet<>()).add(o.goPackage);
            }
        }
        for (Map.Entry<String, Set<String>> e : names.entrySet()) {
            if (e.getValue().size() != 1) {
                continue;
            }
            String name = e.getValue().iterator().next();
            // algorithm aliases only: a package named after a protocol or key kind (sshd, tlsutil, certs) holds much
            // more than that protocol's operations (rescore: nebula's sshd command API, DECISIONS B-G-B3L)
            Set<String> fams = NameTokens.families(name, "go", false);
            if (fams.isEmpty()) {
                continue;
            }
            TreeMap<String, SourceFinding> ev = new TreeMap<>(Texts.CODE_POINT_ORDER);
            for (Outline o : outlines.values()) { // path order
                if (o.lang != Outline.Lang.GO || o.test || !o.goDir.equals(e.getKey()) || !o.goPackage.equals(name)) {
                    continue;
                }
                List<SourceFinding> fs = new ArrayList<>(byFile.getOrDefault(o.path, List.of()));
                fs.sort(Comparator.comparingInt(SourceFinding::line)
                        .thenComparing(f -> f.rule().id(), Texts.CODE_POINT_ORDER));
                for (SourceFinding f : fs) {
                    String k = familyKey(f.rule());
                    if (fams.contains(k)) {
                        ev.putIfAbsent(k, f);
                    }
                }
            }
            if (!ev.isEmpty()) {
                goPkgs.put(e.getKey(), new GoPkg(e.getKey(), name, ev));
            }
        }
    }

    /**
     * The package-name package a Go call reaches (SPEC 18.8): {@code x.F(…)} with {@code x} an import of a
     * project package, or {@code x.M(…)} with {@code x} of declared type {@code p.T} of such a package; else null.
     */
    private GoPkg goPackageOf(Outline o, Outline.Call c, int caller) {
        if (goPkgs.isEmpty() || c.qualifier().size() != 1 || GO_PKG_EXCLUDED.matcher(c.name()).find()) {
            return null;
        }
        Outline.Def d = caller >= 0 ? o.defs.get(caller) : null;
        String x = c.qualifier().get(0);
        Outline.TypeRef t = d == null ? null : d.types().get(x);
        String path;
        if (t != null) {
            if (t == GoOutliner.CONFLICT || t.pkg() == null) {
                return null;
            }
            path = o.goImports.get(t.pkg());
        } else {
            if (d != null && d.locals().contains(x)) {
                return null;
            }
            path = o.goImports.get(x);
        }
        String dir = path == null ? null : importDir(path, o.goDir);
        return dir == null || dir.equals(o.goDir) ? null : goPkgs.get(dir);
    }

    /**
     * W7 evidence (SPEC 18.5, DECISIONS B-P-B5): the first body finding of key {@code f} whose rule id has a
     * segment equal to a token of the definition's name (`_ecdh_recipient` → `python.asym.ecdh` rather than the
     * earlier `python.asym.ec`), else {@code first}.
     */
    private SourceFinding byName(Node n, String f, SourceFinding first) {
        if (!options.features().on(Features.WRAPPER_EVIDENCE_BY_NAME)) {
            return first;
        }
        List<String> toks = NameTokens.tokens(n.d.name());
        for (SourceFinding x : n.bodyByKey.getOrDefault(f, List.of())) {
            for (String seg : x.rule().id().split("\\.")) {
                if (toks.contains(seg)) {
                    return x;
                }
            }
        }
        return first;
    }

    /** The innermost definition of a file whose span contains the line (SPEC 18.1), or -1. */
    private static int innermost(Outline o, int line) {
        int best = -1;
        for (Outline.Def d : o.defs) {
            if (d.line() <= line && line <= d.endLine()) {
                if (best < 0) {
                    best = d.index();
                } else {
                    Outline.Def b = o.defs.get(best);
                    if (d.line() > b.line() || (d.line() == b.line() && d.nesting() > b.nesting())) {
                        best = d.index();
                    }
                }
            }
        }
        return best;
    }

    private void levels() {
        // level 1 (SPEC 18.5)
        for (Outline o : outlines.values()) {
            boolean named = options.named(o.lang);
            boolean thin = options.thin(o.lang);
            for (Node n : nodes.get(o)) {
                if (named) {
                    for (String f : n.nameFams) {
                        SourceFinding e = n.direct.get(f);
                        if (e != null) {
                            n.carry.put(f, new Carry(1, 1, byName(n, f, e), List.of(n)));
                        }
                    }
                }
                if (thin && n.d.endLine() - n.d.line() + 1 <= thinLines(o.lang)) {
                    Set<String> ks = thinKeys(n.thinDirect.keySet());
                    if (ks.size() == 1) {
                        String k = ks.iterator().next();
                        n.carry.putIfAbsent(k, new Carry(1, 1, n.thinDirect.get(k), List.of(n)));
                    }
                }
            }
        }
        // further levels until nothing changes (SPEC 18.5); a chain never exceeds maxDepth definitions
        for (int level = 2; level < MAX_LEVELS; level++) {
            List<Map.Entry<Node, Map<String, Carry>>> pending = new ArrayList<>();
            for (Outline o : outlines.values()) {
                boolean named = options.named(o.lang);
                boolean thin = options.thin(o.lang);
                if (!named && !thin) {
                    continue;
                }
                List<Node> l = nodes.get(o);
                int[] cs = callers.get(o);
                Res[] rs = resolutions.get(o);
                // the calls of each definition's body, in file order
                Map<Integer, List<Integer>> callsOf = new TreeMap<>();
                for (int i = 0; i < cs.length; i++) {
                    if (cs[i] >= 0 && !rs[i].group().isEmpty()) {
                        callsOf.computeIfAbsent(cs[i], k -> new ArrayList<>()).add(i);
                    }
                }
                for (Map.Entry<Integer, List<Integer>> e : callsOf.entrySet()) {
                    Node n = l.get(e.getKey());
                    Map<String, Carry> m = new TreeMap<>(Texts.CODE_POINT_ORDER);
                    if (named) {
                        for (String f : n.nameFams) {
                            if (!n.carry.containsKey(f)) {
                                Carry c = bestVia(n, f, e.getValue(), rs, level);
                                if (c != null) {
                                    m.put(f, c);
                                }
                            }
                        }
                    }
                    if (thin && n.carry.isEmpty() && m.isEmpty() && n.d.endLine() - n.d.line() + 1 <= thinLines(o.lang)) {
                        Set<String> keys = new TreeSet<>(Texts.CODE_POINT_ORDER);
                        keys.addAll(n.thinDirect.keySet());
                        List<Integer> unguarded = new ArrayList<>();
                        for (int i : e.getValue()) {
                            if (!guarded(o, e.getKey(), o.calls.get(i).line())) {
                                unguarded.add(i);
                                keys.addAll(carriedBelow(rs[i].group(), level));
                            }
                        }
                        keys = thinKeys(keys);
                        if (keys.size() == 1) {
                            String f = keys.iterator().next();
                            Carry c = bestVia(n, f, unguarded, rs, level);
                            if (c != null) {
                                m.put(f, c);
                            }
                        }
                    }
                    if (!m.isEmpty()) {
                        pending.add(Map.entry(n, m));
                    }
                }
            }
            if (pending.isEmpty()) {
                break;
            }
            for (Map.Entry<Node, Map<String, Carry>> e : pending) {
                e.getKey().carry.putAll(e.getValue());
            }
        }
    }

    /**
     * The carry of {@code n} for {@code f} through the best of its calls (the representative with the
     * smallest depth, then the first call), from groups carrying {@code f} below {@code level}; null if
     * none or if the chain would exceed {@link #maxDepth}.
     */
    private Carry bestVia(Node n, String f, List<Integer> calls, Res[] rs, int level) {
        Carry best = null;
        for (int i : calls) {
            Node rep = representative(rs[i].group(), f, level);
            if (rep == null) {
                continue;
            }
            Carry rc = rep.carry.get(f);
            if (rc.depth() + 1 > maxDepth) {
                continue;
            }
            if (best == null || rc.depth() + 1 < best.depth()) {
                List<Node> chain = new ArrayList<>(rc.chain().size() + 1);
                chain.add(n);
                chain.addAll(rc.chain());
                best = new Carry(rc.depth() + 1, level, rc.evidence(), List.copyOf(chain));
            }
        }
        return best;
    }

    /** The family keys every member of a group carries below {@code level}. */
    private static Set<String> carriedBelow(List<Node> group, int level) {
        Set<String> s = new TreeSet<>(Texts.CODE_POINT_ORDER);
        boolean first = true;
        for (Node m : group) {
            Set<String> k = new TreeSet<>(Texts.CODE_POINT_ORDER);
            for (Map.Entry<String, Carry> e : m.carry.entrySet()) {
                if (e.getValue().level() < level) {
                    k.add(e.getKey());
                }
            }
            if (first) {
                s.addAll(k);
                first = false;
            } else {
                s.retainAll(k);
            }
        }
        return s;
    }

    /**
     * The representative of a group for a family key (SPEC 18.5): every member must carry it (from a
     * level below {@code level}); then the member with the smallest depth, path, line. Null if the
     * group does not carry it.
     */
    private static Node representative(List<Node> group, String f, int level) {
        Node best = null;
        for (Node m : group) {
            Carry c = m.carry.get(f);
            if (c == null || c.level() >= level) {
                return null;
            }
            if (best == null || c.depth() < best.carry.get(f).depth()
                    || (c.depth() == best.carry.get(f).depth() && NODE_ORDER.compare(m, best) < 0)) {
                best = m;
            }
        }
        return best;
    }

    /**
     * The names whose files the index must read (SPEC 18.2), per language: the names of the crypto
     * callables found by the last {@link #compute} and, for Java, the simple names of their classes
     * (so that a same-named class that shadows an on-demand import is known).
     */
    public Map<Outline.Lang, Set<String>> callableNames() {
        Map<Outline.Lang, Set<String>> out = new TreeMap<>();
        for (GoPkg g : goPkgs.values()) {
            // a call x.F of a package-name package: its file names the package (import path or local name)
            Set<String> s = out.computeIfAbsent(Outline.Lang.GO, k -> new TreeSet<>());
            s.add(g.name());
            String last = g.dir().substring(g.dir().lastIndexOf('/') + 1);
            if (!last.isEmpty()) {
                s.add(last);
            }
        }
        for (Outline o : outlines.values()) {
            for (Node n : nodes.get(o)) {
                if (!n.carry.isEmpty()) {
                    Set<String> s = out.computeIfAbsent(o.lang, k -> new TreeSet<>());
                    s.add(n.d.name());
                    if (o.lang == Outline.Lang.JAVA) {
                        for (int k = n.d.ownerClass(); k >= 0; k = o.javaClasses.get(k).parent()) {
                            if (!o.javaClasses.get(k).simpleName().isEmpty()) {
                                s.add(o.javaClasses.get(k).simpleName());
                            }
                        }
                    }
                }
            }
        }
        return out;
    }

    // ======================================================================== report

    /**
     * The propagated findings (SPEC 18.7) of the last {@link #compute}. {@code text} returns the
     * decoded text of a file (for the snippet), or null if it cannot be read.
     */
    public Result report(Function<String, String> text) {
        Set<String> directKeys = new HashSet<>();
        for (SourceFinding f : direct) {
            directKeys.add(f.path() + "\u0000" + f.line() + "\u0000" + familyKey(f.rule()));
        }
        List<SourceFinding> out = new ArrayList<>();
        int callables = 0;
        int ambiguous = 0;
        for (Outline o : outlines.values()) {
            for (Node n : nodes.get(o)) {
                if (!n.carry.isEmpty()) {
                    callables++;
                }
            }
        }
        for (Outline o : outlines.values()) {
            Res[] rs = resolutions.get(o);
            Integer[] order = new Integer[o.calls.size()];
            for (int i = 0; i < order.length; i++) {
                order[i] = i;
            }
            java.util.Arrays.sort(order, Comparator.comparingInt(i -> o.calls.get(i).start()));
            Set<String> seen = new HashSet<>();
            String fileText = null;
            boolean read = false;
            for (int i : order) {
                Res r = rs[i];
                if (r.ambiguous()) {
                    if (r.collision().stream().anyMatch(n -> !n.carry.isEmpty())) {
                        ambiguous++;
                    }
                    continue;
                }
                if (r.group().isEmpty()) {
                    continue;
                }
                Outline.Call c = o.calls.get(i);
                for (String f : carried(r.group())) {
                    String k = o.path + "\u0000" + c.line() + "\u0000" + f;
                    if (directKeys.contains(k) || !seen.add(k)) {
                        continue; // folding (SPEC 18.7)
                    }
                    Node rep = representative(r.group(), f, Integer.MAX_VALUE);
                    Carry rc = rep.carry.get(f);
                    if (!read) {
                        fileText = text.apply(o.path);
                        read = true;
                    }
                    String snippet = fileText != null && c.end() <= fileText.length()
                            ? Texts.truncateCodePoints(fileText.substring(c.start(), c.end()), SNIPPET_MAX)
                            : c.symbol();
                    List<String> via = new ArrayList<>(rc.chain().size());
                    for (Node v : rc.chain()) {
                        via.add(v.where());
                    }
                    SourceFinding e = rc.evidence();
                    out.add(new SourceFinding(o.path, c.line(), e.rule(), e.name(), c.symbol(), snippet, e.param(),
                            e.oid(), o.test, via, e.path() + ":" + e.line()));
                }
            }
            // package-name consistency (SPEC 18.8): after the callables, so that a callable's chain wins
            if (o.lang == Outline.Lang.GO && !goPkgs.isEmpty()) {
                int[] cs = callers.get(o);
                for (int i : order) {
                    if (rs[i].ambiguous()) {
                        continue;
                    }
                    Outline.Call c = o.calls.get(i);
                    GoPkg g = goPackageOf(o, c, cs[i]);
                    if (g == null) {
                        continue;
                    }
                    for (Map.Entry<String, SourceFinding> ev : g.evidence().entrySet()) {
                        String k = o.path + "\u0000" + c.line() + "\u0000" + ev.getKey();
                        if (directKeys.contains(k) || !seen.add(k)) {
                            continue;
                        }
                        if (!read) {
                            fileText = text.apply(o.path);
                            read = true;
                        }
                        String snippet = fileText != null && c.end() <= fileText.length()
                                ? Texts.truncateCodePoints(fileText.substring(c.start(), c.end()), SNIPPET_MAX)
                                : c.symbol();
                        SourceFinding e = ev.getValue();
                        out.add(new SourceFinding(o.path, c.line(), e.rule(), e.name(), c.symbol(), snippet, e.param(),
                                e.oid(), o.test, List.of(g.dir() + ": package " + g.name()), e.path() + ":" + e.line()));
                    }
                }
            }
        }
        return new Result(out, callables, ambiguous);
    }

    /** The family keys every member of a group carries, in code-point order. */
    private static Set<String> carried(List<Node> group) {
        Set<String> s = new TreeSet<>(Texts.CODE_POINT_ORDER);
        s.addAll(group.get(0).carry.keySet());
        for (Node m : group) {
            s.retainAll(m.carry.keySet());
        }
        return s;
    }

    // ======================================================================== index

    private void index(Outline o, List<Node> l) {
        switch (o.lang) {
            case JAVA -> {
                for (int k = 0; k < o.javaClasses.size(); k++) {
                    Outline.JavaClass c = o.javaClasses.get(k);
                    if (c.addressable()) {
                        javaClassOwners.computeIfAbsent(c.fqn(), x -> new ArrayList<>()).add(o.path);
                    }
                }
                for (Node n : l) {
                    javaMethods.computeIfAbsent(n.d.owner(), x -> new HashMap<>())
                            .computeIfAbsent(n.d.name(), x -> new ArrayList<>()).add(n);
                }
            }
            case PYTHON -> {
                pyModules.putIfAbsent(o.pyModule, o);
                for (Node n : l) {
                    if (!n.d.addressable()) {
                        continue;
                    }
                    if (n.d.pyClass() == null) {
                        pyFuncs.computeIfAbsent(o.pyModule, x -> new HashMap<>())
                                .computeIfAbsent(n.d.name(), x -> new ArrayList<>()).add(n);
                    } else {
                        pyMethods.computeIfAbsent(o.pyModule + "\u0000" + n.d.pyClass(), x -> new HashMap<>())
                                .computeIfAbsent(n.d.name(), x -> new ArrayList<>()).add(n);
                    }
                }
            }
            case GO -> {
                boolean testPkg = o.goPackage.endsWith("_test");
                for (Node n : l) {
                    String pkgKey = o.goDir + "|" + o.goPackage;
                    if (n.d.recv() == null) {
                        goFuncs.computeIfAbsent(pkgKey, x -> new HashMap<>())
                                .computeIfAbsent(n.d.name(), x -> new ArrayList<>()).add(n);
                        if (!testPkg) {
                            goDirFuncs.computeIfAbsent(o.goDir, x -> new HashMap<>())
                                    .computeIfAbsent(n.d.name(), x -> new ArrayList<>()).add(n);
                        }
                    } else {
                        goMethods.computeIfAbsent(pkgKey + "|" + n.d.recv(), x -> new HashMap<>())
                                .computeIfAbsent(n.d.name(), x -> new ArrayList<>()).add(n);
                        if (!testPkg) {
                            goDirMethods.computeIfAbsent(o.goDir + "|" + n.d.recv(), x -> new HashMap<>())
                                    .computeIfAbsent(n.d.name(), x -> new ArrayList<>()).add(n);
                        }
                    }
                }
            }
            default -> throw new IllegalStateException();
        }
    }

    /** FQN → paths of the files declaring an addressable class with that FQN (in index order). */
    private final Map<String, List<String>> javaClassOwners = new HashMap<>();

    // ======================================================================== resolution (SPEC 18.4)

    private Res resolve(Outline o, int i) {
        Outline.Call c = o.calls.get(i);
        int caller = callers.get(o)[i];
        List<Node> cand = switch (o.lang) {
            case JAVA -> resolveJava(o, c);
            case PYTHON -> resolvePython(o, c, caller);
            case GO -> resolveGo(o, c, caller);
        };
        if (cand == null || cand.isEmpty()) {
            return Res.NONE;
        }
        List<Node> l = new ArrayList<>(cand.size());
        Set<String> owners = new TreeSet<>();
        for (Node n : cand) {
            if (n.o == o && n.d.index() == caller) {
                continue; // the caller itself: an overload is the likelier target
            }
            if (n.o.test && !o.test) {
                continue; // test-file definitions serve test call sites only
            }
            if (!l.contains(n)) {
                l.add(n);
                owners.add(n.d.owner());
            }
        }
        if (l.isEmpty()) {
            return Res.NONE;
        }
        l.sort(NODE_ORDER);
        if (owners.size() > 1) {
            return new Res(List.of(), List.copyOf(l));
        }
        return new Res(List.copyOf(l), List.of());
    }

    // ---- Java

    private List<Node> resolveJava(Outline o, Outline.Call c) {
        List<String> q = c.qualifier();
        if (q.isEmpty() || q.get(0).equals("this")) {
            boolean self = !q.isEmpty();
            for (int k = c.javaClass(); k >= 0; k = o.javaClasses.get(k).parent()) {
                List<Node> ms = javaMethods.getOrDefault(o.path + "#" + k, Map.of()).get(c.name());
                if (ms != null) {
                    return arity(ms, c.arity());
                }
                if (self) {
                    return null;
                }
            }
            if (self) {
                return null;
            }
            String cls = o.javaStaticImports.get(c.name());
            if (cls != null) {
                return methodsOf(classesByFqn(cls), c);
            }
            List<String[]> refs = new ArrayList<>();
            for (String s : o.javaStaticOnDemand) {
                refs.addAll(classesByFqn(s));
            }
            return methodsOf(refs, c);
        }
        String text = q.get(0);
        String[] segs = text.split("\\.");
        if (segs.length == 0 || segs[0].isEmpty()) {
            return null;
        }
        List<String[]> refs;
        int from;
        if (Character.isLowerCase(segs[0].charAt(0))) {
            if (segs.length == 1) {
                return null; // a variable
            }
            // fully qualified: the longest prefix that names a project class, then member classes
            refs = null;
            from = segs.length;
            for (int k = segs.length; k >= 2; k--) {
                List<String[]> r = classesByFqn(String.join(".", java.util.Arrays.copyOfRange(segs, 0, k)));
                if (!r.isEmpty()) {
                    refs = r;
                    from = k;
                    break;
                }
            }
            if (refs == null) {
                return null;
            }
        } else if (Character.isUpperCase(segs[0].charAt(0))) {
            refs = simpleClass(o, segs[0]);
            from = 1;
        } else {
            return null;
        }
        for (int k = from; k < segs.length && !refs.isEmpty(); k++) {
            List<String[]> next = new ArrayList<>();
            for (String[] r : refs) {
                Outline ro = byPath.get(r[0]);
                int parent = Integer.parseInt(r[1]);
                for (int j = 0; j < ro.javaClasses.size(); j++) {
                    Outline.JavaClass jc = ro.javaClasses.get(j);
                    if (jc.parent() == parent && jc.simpleName().equals(segs[k])) {
                        next.add(new String[] {r[0], Integer.toString(j)});
                    }
                }
            }
            refs = next;
        }
        return methodsOf(refs, c);
    }

    /** A simple class name used as qualifier (SPEC 18.4 Java step 2): (path, class index) refs. */
    private List<String[]> simpleClass(Outline o, String s) {
        List<String[]> own = new ArrayList<>();
        for (int j = 0; j < o.javaClasses.size(); j++) {
            if (o.javaClasses.get(j).simpleName().equals(s)) {
                own.add(new String[] {o.path, Integer.toString(j)});
            }
        }
        if (!own.isEmpty()) {
            return own;
        }
        String imp = o.javaImports.get(s);
        if (imp != null) {
            return classesByFqn(imp);
        }
        String same = o.javaPackage.isEmpty() ? s : o.javaPackage + "." + s;
        List<String[]> r = classesByFqn(same);
        if (!r.isEmpty()) {
            return r;
        }
        String dir = GoOutliner.dirOf(o.path);
        if (project.javaFiles().contains(dir.isEmpty() ? s + ".java" : dir + "/" + s + ".java")) {
            return List.of(); // a same-package class the index did not read
        }
        List<String[]> out = new ArrayList<>();
        for (String p : o.javaOnDemand) {
            out.addAll(classesByFqn(p + "." + s));
        }
        return out;
    }

    private List<String[]> classesByFqn(String fqn) {
        List<String> paths = javaClassOwners.get(fqn);
        if (paths == null) {
            return List.of();
        }
        List<String[]> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>(paths);
        for (String p : seen) {
            Outline ro = byPath.get(p);
            for (int j = 0; j < ro.javaClasses.size(); j++) {
                if (fqn.equals(ro.javaClasses.get(j).fqn())) {
                    out.add(new String[] {p, Integer.toString(j)});
                }
            }
        }
        return out;
    }

    private List<Node> methodsOf(List<String[]> refs, Outline.Call c) {
        List<Node> out = new ArrayList<>();
        for (String[] r : refs) {
            List<Node> ms = javaMethods.getOrDefault(r[0] + "#" + r[1], Map.of()).get(c.name());
            if (ms != null) {
                out.addAll(arity(ms, c.arity()));
            }
        }
        return out;
    }

    private static List<Node> arity(List<Node> ms, int n) {
        List<Node> out = new ArrayList<>();
        for (Node m : ms) {
            if (m.d.arity() == n || (m.d.varargs() && n >= m.d.arity() - 1)) {
                out.add(m);
            }
        }
        return out;
    }

    // ---- Python

    /** A resolved Python entity: a module, or a class of a module. */
    private record PyEntity(String module, String cls) {}

    private List<Node> resolvePython(Outline o, Outline.Call c, int caller) {
        List<String> q = c.qualifier();
        Set<String> locals = caller >= 0 ? o.defs.get(caller).locals() : Set.of();
        if (q.isEmpty()) {
            if (locals.contains(c.name())) {
                return null;
            }
            List<Outline.PyBinding> bs = o.pyImports.get(c.name());
            if (bs != null) {
                if (bs.size() != 1) {
                    return null;
                }
                Outline.PyBinding b = bs.get(0);
                if (b.member() == null) {
                    return null; // a module is not callable
                }
                return member(b.module(), b.member(), 0);
            }
            return pyFuncs.getOrDefault(o.pyModule, Map.of()).get(c.name());
        }
        String x = q.get(0);
        PyEntity e;
        if ((x.equals("self") || x.equals("cls")) && q.size() == 1 && c.pyClass() != null) {
            e = new PyEntity(o.pyModule, c.pyClass());
        } else if (locals.contains(x)) {
            return null;
        } else if (o.pyImports.containsKey(x)) {
            List<Outline.PyBinding> bs = o.pyImports.get(x);
            if (bs.size() != 1) {
                return null;
            }
            e = entity(bs.get(0), 0);
        } else if (o.pyClasses.contains(x)) {
            e = new PyEntity(o.pyModule, x);
        } else {
            return null;
        }
        for (int k = 1; k < q.size() && e != null; k++) {
            if (e.cls() != null) {
                return null;
            }
            e = childEntity(e.module(), q.get(k), 0);
        }
        if (e == null) {
            return null;
        }
        if (e.cls() == null) {
            return member(e.module(), c.name(), 0);
        }
        return pyMethods.getOrDefault(e.module() + "\u0000" + e.cls(), Map.of()).get(c.name());
    }

    /** The project module a dotted name denotes (SPEC 18.4): itself, else the single one ending with it. */
    private String module(String d) {
        if (d == null || d.isEmpty()) {
            return null;
        }
        if (project.pythonModules().contains(d)) {
            return d;
        }
        if (pyLookupCache.containsKey(d)) {
            return pyLookupCache.get(d);
        }
        String found = null;
        int n = 0;
        String suffix = "." + d;
        for (String m : project.pythonModules()) {
            if (m.endsWith(suffix)) {
                n++;
                if (found == null || Texts.compareCodePoints(m, found) < 0) {
                    found = m;
                }
            }
        }
        String r = n == 1 ? found : null;
        pyLookupCache.put(d, r);
        return r;
    }

    private PyEntity entity(Outline.PyBinding b, int hops) {
        if (b.member() == null) {
            String m = module(b.module());
            // a package without __init__.py is not a module of the index, but its submodules are
            return new PyEntity(m == null ? b.module() : m, null);
        }
        if (b.module().isEmpty()) {
            String m = module(b.member());
            return m == null ? null : new PyEntity(m, null);
        }
        return childEntity(b.module(), b.member(), hops);
    }

    /** {@code mod.name} as a submodule, else as a class member of {@code mod} (following re-exports). */
    private PyEntity childEntity(String mod, String name, int hops) {
        String sub = module(mod + "." + name);
        if (sub != null) {
            return new PyEntity(sub, null);
        }
        String m = module(mod);
        Outline mo = m == null ? null : pyModules.get(m);
        if (mo == null) {
            return null; // not a module, or one the index did not need (it names nothing relevant)
        }
        if (mo.pyClasses.contains(name)) {
            return new PyEntity(m, name);
        }
        List<Outline.PyBinding> bs = mo.pyImports.get(name);
        if (bs != null && bs.size() == 1 && hops < MAX_REEXPORT_HOPS) {
            return entity(bs.get(0), hops + 1);
        }
        return null;
    }

    /** The functions {@code name} of module {@code mod} (following re-exports, SPEC 18.4). */
    private List<Node> member(String mod, String name, int hops) {
        if (mod.isEmpty() || module(mod + "." + name) != null) {
            return null; // a module
        }
        String m = module(mod);
        if (m == null) {
            return null;
        }
        List<Node> fs = pyFuncs.getOrDefault(m, Map.of()).get(name);
        if (fs != null) {
            return fs;
        }
        Outline mo = pyModules.get(m);
        List<Outline.PyBinding> bs = mo == null ? null : mo.pyImports.get(name);
        if (bs != null && bs.size() == 1 && bs.get(0).member() != null && hops < MAX_REEXPORT_HOPS) {
            return member(bs.get(0).module(), bs.get(0).member(), hops + 1);
        }
        return null;
    }

    // ---- Go

    private List<Node> resolveGo(Outline o, Outline.Call c, int caller) {
        Outline.Def d = caller >= 0 ? o.defs.get(caller) : null;
        Set<String> locals = d == null ? Set.of() : d.locals();
        Map<String, Outline.TypeRef> types = d == null ? Map.of() : d.types();
        List<String> q = c.qualifier();
        String pkgKey = o.goDir + "|" + o.goPackage;
        if (q.isEmpty()) {
            if (locals.contains(c.name())) {
                return null;
            }
            return goFuncs.getOrDefault(pkgKey, Map.of()).get(c.name());
        }
        String x = q.get(0);
        Outline.TypeRef t = types.get(x);
        if (q.size() == 2) {
            if (t == null || t == GoOutliner.CONFLICT || t.pkg() != null) {
                return null;
            }
            Map<String, Outline.TypeRef> fields = o.goStructs.get(t.name());
            Outline.TypeRef ft = fields == null ? null : fields.get(q.get(1));
            if (ft == null || ft == GoOutliner.CONFLICT) {
                return null;
            }
            return methodsOfType(o, ft, c.name());
        }
        if (t != null) {
            return t == GoOutliner.CONFLICT ? null : methodsOfType(o, t, c.name());
        }
        if (locals.contains(x)) {
            return null;
        }
        String path = o.goImports.get(x);
        if (path == null) {
            return null;
        }
        String dir = importDir(path, o.goDir);
        return dir == null ? null : goDirFuncs.getOrDefault(dir, Map.of()).get(c.name());
    }

    private List<Node> methodsOfType(Outline o, Outline.TypeRef t, String name) {
        if (t.pkg() == null) {
            return goMethods.getOrDefault(o.goDir + "|" + o.goPackage + "|" + t.name(), Map.of()).get(name);
        }
        String path = o.goImports.get(t.pkg());
        String dir = path == null ? null : importDir(path, o.goDir);
        return dir == null ? null : goDirMethods.getOrDefault(dir + "|" + t.name(), Map.of()).get(name);
    }

    /**
     * The directory of a project package (SPEC 18.4): through the longest matching module path of the
     * {@code go.mod} files, else {@code vendor/<path>} below the calling file's module directory.
     */
    String importDir(String path, String fromDir) {
        String best = null;
        String bestDir = null;
        for (Map.Entry<String, String> e : project.goModules().entrySet()) {
            String m = e.getValue();
            if ((path.equals(m) || path.startsWith(m + "/")) && (best == null || m.length() > best.length())) {
                best = m;
                String rest = path.substring(m.length());
                String d = e.getKey();
                bestDir = d.isEmpty() ? (rest.isEmpty() ? "" : rest.substring(1)) : d + rest;
            }
        }
        if (bestDir != null) {
            return bestDir;
        }
        String modDir = null;
        for (String d : project.goModules().keySet()) {
            boolean ancestor = d.isEmpty() || fromDir.equals(d) || fromDir.startsWith(d + "/");
            if (ancestor && (modDir == null || d.length() > modDir.length())) {
                modDir = d;
            }
        }
        if (modDir == null) {
            return null;
        }
        String v = modDir.isEmpty() ? "vendor/" + path : modDir + "/vendor/" + path;
        return project.goDirs().contains(v) ? v : null;
    }
}
