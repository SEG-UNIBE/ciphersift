/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang.python;

import ch.unibe.seg.ciphersift.model.SourceFinding;
import ch.unibe.seg.ciphersift.rules.PythonPattern;
import ch.unibe.seg.ciphersift.rules.RuleSet;
import ch.unibe.seg.ciphersift.rules.SourceRule;
import ch.unibe.seg.ciphersift.syntax.SyntaxNode;
import ch.unibe.seg.ciphersift.util.Texts;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Python source analysis (SPEC 8). One instance per scan; {@link #analyze} is thread-safe. */
public final class PythonAnalyzer {
    static final int MAX_CANDIDATES = 8;
    /** SPEC 6.3 / DECISIONS M4. */
    static final int MAX_ATTRIBUTE_LEVELS = 64;
    static final int MAX_BINDING_STEPS = 16;
    static final int MAX_STRINGS_DEPTH = 12;
    static final int MAX_COLLECT_DEPTH = 6;
    static final int MAX_SHAPE_DEPTH = 8;
    static final int SNIPPET_MAX = 500;
    private static final Set<String> REPORT_AT_CHAIN = Set.of("argument_list", "keyword_argument", "call",
            "parenthesized_expression", "list", "tuple", "conditional_expression");
    private static final Pattern DIGITS = Pattern.compile("[0-9]+");

    private final PythonRuleIndex index;

    public PythonAnalyzer(RuleSet rules) {
        this.index = new PythonRuleIndex(rules.pythonRules());
    }

    /** Analyses one parsed Python file. */
    public List<SourceFinding> analyze(SyntaxNode root, String relativePath, boolean test) {
        return new FileRun(root, relativePath, test).run();
    }

    // ====================================================================== scopes

    static final class Scope {
        final Scope parent;
        final Map<String, List<SyntaxNode>> assigned = new HashMap<>();
        final Set<String> params = new HashSet<>();
        final Map<String, Resolved> resolved = new HashMap<>();

        Scope(Scope parent) {
            this.parent = parent;
        }
    }

    private record Binding(SyntaxNode rhs, Scope scope) {}

    /** Memoised resolveName result and the number of binding steps its computation used. */
    private record Resolved(List<String> names, int height) {}

    private record Located(SyntaxNode node, Scope scope) {}

    private record Hit(SourceRule rule, String nameUsed, PythonPattern pattern) {}

    private record Range(int start, int end) {}

    /** State of one file analysis. */
    private final class FileRun {
        final SyntaxNode root;
        final String rel;
        final boolean test;
        final Map<String, List<String>> imports = new HashMap<>();
        final List<String> starModules = new ArrayList<>();
        final List<Located> calls = new ArrayList<>();
        final List<Located> attributeAssignments = new ArrayList<>();
        final Set<String> emitted = new HashSet<>();
        final Map<SourceRule, List<Range>> ranges = new IdentityHashMap<>();
        final List<SourceFinding> out = new ArrayList<>();

        /** Cycle guard of resolveName: (scope, name) pairs being resolved. */
        final Set<Object> resolving = new HashSet<>();
        /** Set when a computation hit the cycle guard or a depth limit (its result is context-dependent). */
        boolean tainted;

        FileRun(SyntaxNode root, String rel, boolean test) {
            this.root = root;
            this.rel = rel;
            this.test = test;
        }

        List<SourceFinding> run() {
            collect();
            for (Located c : calls) {
                matchCall(c.node(), c.scope());
            }
            if (!index.assignRules.isEmpty()) {
                for (Located a : attributeAssignments) {
                    matchAssignment(a.node(), a.scope());
                }
            }
            return out;
        }

        // ------------------------------------------------------------------ 8.1 collection walk

        private void collect() {
            Scope module = new Scope(null);
            ArrayDeque<Located> stack = new ArrayDeque<>();
            stack.push(new Located(root, module));
            while (!stack.isEmpty()) {
                Located l = stack.pop();
                SyntaxNode n = l.node();
                Scope s = l.scope();
                switch (n.type()) {
                    case "import_statement" -> {
                        importStatement(n);
                        continue;
                    }
                    case "import_from_statement" -> {
                        importFrom(n);
                        continue;
                    }
                    case "function_definition", "lambda" -> {
                        Scope inner = new Scope(s);
                        SyntaxNode params = n.field("parameters");
                        if (params != null) {
                            bindParameters(params, inner);
                        }
                        s = inner;
                    }
                    case "assignment" -> {
                        SyntaxNode left = n.field("left");
                        SyntaxNode right = n.field("right");
                        if (left != null && left.is("identifier") && right != null) {
                            s.assigned.computeIfAbsent(left.text(), k -> new ArrayList<>(1)).add(right);
                        }
                        if (left != null && left.is("attribute")) {
                            attributeAssignments.add(new Located(n, s));
                        }
                    }
                    case "augmented_assignment" -> {
                        SyntaxNode left = n.field("left");
                        if (left != null && left.is("attribute")) {
                            attributeAssignments.add(new Located(n, s));
                        }
                    }
                    case "call" -> calls.add(new Located(n, s));
                    default -> {
                        // nothing
                    }
                }
                for (int i = n.childCount() - 1; i >= 0; i--) {
                    SyntaxNode c = n.child(i);
                    if (c.isNamed()) {
                        stack.push(new Located(c, s));
                    }
                }
            }
        }

        private void addImport(String local, String target) {
            List<String> l = imports.computeIfAbsent(local, k -> new ArrayList<>(1));
            if (!l.contains(target)) {
                l.add(target);
            }
        }

        private void importStatement(SyntaxNode n) {
            for (int i = 0; i < n.childCount(); i++) {
                SyntaxNode c = n.child(i);
                if (c.is("dotted_name")) {
                    String t = dotted(c);
                    String first = t.contains(".") ? t.substring(0, t.indexOf('.')) : t;
                    addImport(first, first);
                } else if (c.is("aliased_import")) {
                    SyntaxNode name = c.field("name");
                    SyntaxNode alias = c.field("alias");
                    if (name != null && alias != null) {
                        addImport(alias.text(), dotted(name));
                    }
                }
            }
        }

        private void importFrom(SyntaxNode n) {
            SyntaxNode mod = n.field("module_name");
            String m = mod == null || mod.is("relative_import") ? "" : dotted(mod);
            if (n.hasChildOfType("wildcard_import")) {
                if (!m.isEmpty() && !starModules.contains(m)) {
                    starModules.add(m);
                }
            }
            for (int i = 0; i < n.childCount(); i++) {
                SyntaxNode c = n.child(i);
                if (!"name".equals(c.field())) {
                    continue;
                }
                if (c.is("dotted_name")) {
                    String t = dotted(c);
                    addImport(Texts.lastSegment(t), m.isEmpty() ? t : m + "." + t);
                } else if (c.is("aliased_import")) {
                    SyntaxNode name = c.field("name");
                    SyntaxNode alias = c.field("alias");
                    if (name != null && alias != null) {
                        String t = dotted(name);
                        addImport(alias.text(), m.isEmpty() ? t : m + "." + t);
                    }
                }
            }
        }

        private String dotted(SyntaxNode n) {
            return Texts.removeWhitespace(n.text());
        }

        private void bindParameters(SyntaxNode params, Scope s) {
            for (int i = 0; i < params.childCount(); i++) {
                SyntaxNode p = params.child(i);
                switch (p.type()) {
                    case "identifier" -> s.params.add(p.text());
                    case "default_parameter", "typed_default_parameter" -> {
                        SyntaxNode name = p.field("name");
                        if (name != null) {
                            s.params.add(name.text());
                        }
                    }
                    case "typed_parameter", "list_splat_pattern", "dictionary_splat_pattern" -> {
                        SyntaxNode id = p.childOfType("identifier");
                        if (id != null) {
                            s.params.add(id.text());
                        }
                    }
                    default -> {
                        // separators, tuple patterns: not bound
                    }
                }
            }
        }

        // ------------------------------------------------------------------ 8.3 / 8.4 resolution

        private List<Binding> bindings(String name, Scope s) {
            for (Scope t = s; t != null; t = t.parent) {
                List<SyntaxNode> a = t.assigned.get(name);
                if (a != null || t.params.contains(name)) {
                    if (a == null) {
                        return List.of();
                    }
                    List<Binding> l = new ArrayList<>(a.size());
                    for (SyntaxNode rhs : a) {
                        l.add(new Binding(rhs, t));
                    }
                    return l;
                }
            }
            return List.of();
        }

        List<String> resolveName(String name, Scope s) {
            cut = false;
            List<String> r = resolveName(name, s, 0);
            cut = false;
            return r;
        }

        /** Deepest binding-step count reached by the current computation (for memo validity). */
        int deepest;
        /**
         * Set when the current resolution reached the binding-step limit: the name (and every name
         * resolved through it) is then unresolved, i.e. has no candidates (SPEC 6.3, DECISIONS M4/O4).
         */
        boolean cut;

        private List<String> resolveName(String name, Scope s, int steps) {
            if (steps > MAX_BINDING_STEPS) {
                tainted = true;
                cut = true;
                return List.of();
            }
            Resolved cached = s.resolved.get(name);
            if (cached != null && steps + cached.height() <= MAX_BINDING_STEPS) {
                deepest = Math.max(deepest, steps + cached.height());
                return cached.names();
            }
            boolean outerTaint = tainted;
            boolean outerCut = cut;
            int outerDeepest = deepest;
            tainted = false;
            cut = false;
            deepest = steps;
            LinkedHashSet<String> out = new LinkedHashSet<>();
            Object key = new GuardKey(s, name);
            if (resolving.contains(key)) {
                // cycle guard: skip the bindings step (SPEC 8.4.1)
                tainted = true;
            } else {
                List<Binding> bs = bindings(name, s);
                if (!bs.isEmpty()) {
                    resolving.add(key);
                    try {
                        for (Binding b : bs) {
                            if (b.rhs().is("identifier") || b.rhs().is("attribute")) {
                                out.addAll(resolveDotted(b.rhs(), b.scope(), steps + 1));
                            }
                        }
                    } finally {
                        resolving.remove(key);
                    }
                }
            }
            boolean ownCut = cut;
            List<String> result;
            if (ownCut) {
                result = List.of(); // the chain is longer than the limit: unresolved (no fallback)
            } else {
                List<String> targets = imports.get(name);
                if (targets != null) {
                    out.addAll(targets);
                }
                if (out.isEmpty()) {
                    out.add(name);
                    for (String m : starModules) {
                        out.add(m + "." + name);
                    }
                }
                result = truncate(out);
            }
            if (!tainted) {
                // context-independent result; valid wherever steps + height stays within the limit
                s.resolved.put(name, new Resolved(result, deepest - steps));
            }
            tainted = tainted || outerTaint;
            cut = ownCut || outerCut;
            deepest = Math.max(deepest, outerDeepest);
            return result;
        }

        List<String> resolveDotted(SyntaxNode e, Scope s) {
            cut = false;
            List<String> r = resolveDotted(e, s, 0);
            cut = false;
            return r;
        }

        private List<String> resolveDotted(SyntaxNode e, Scope s, int steps) {
            if (e.is("identifier")) {
                return resolveName(e.text(), s, steps);
            }
            if (!e.is("attribute")) {
                return List.of();
            }
            ArrayList<String> attrs = new ArrayList<>();
            SyntaxNode cur = e;
            while (cur != null && cur.is("attribute")) {
                if (attrs.size() >= MAX_ATTRIBUTE_LEVELS) {
                    return List.of();
                }
                SyntaxNode a = cur.field("attribute");
                if (a == null) {
                    return List.of();
                }
                attrs.add(a.text());
                cur = cur.field("object");
            }
            if (cur == null || !cur.is("identifier")) {
                return List.of();
            }
            List<String> base = resolveName(cur.text(), s, steps);
            if (base.isEmpty()) {
                return List.of();
            }
            StringBuilder suffix = new StringBuilder();
            for (int i = attrs.size() - 1; i >= 0; i--) {
                suffix.append('.').append(attrs.get(i));
            }
            List<String> out = new ArrayList<>(Math.min(base.size(), MAX_CANDIDATES));
            for (String b : base) {
                if (out.size() >= MAX_CANDIDATES) {
                    break;
                }
                out.add(b + suffix);
            }
            return out;
        }

        private List<String> truncate(LinkedHashSet<String> s) {
            List<String> l = new ArrayList<>(Math.min(s.size(), MAX_CANDIDATES));
            for (String x : s) {
                if (l.size() >= MAX_CANDIDATES) {
                    break;
                }
                l.add(x);
            }
            return List.copyOf(l);
        }

        List<String> boundCalls(String name, Scope s) {
            LinkedHashSet<String> out = new LinkedHashSet<>();
            for (Binding b : bindings(name, s)) {
                if (b.rhs().is("call")) {
                    out.addAll(callNames(b.rhs(), b.scope()));
                }
            }
            return new ArrayList<>(out);
        }

        List<String> constantValues(String name, Scope s) {
            LinkedHashSet<String> out = new LinkedHashSet<>();
            for (Binding b : bindings(name, s)) {
                String v = stringValue(b.rhs());
                if (v == null) {
                    v = integerValue(b.rhs());
                }
                if (v != null) {
                    out.add(v);
                }
            }
            return new ArrayList<>(out);
        }

        /** Call names of a call (SPEC 8.4.2); memoised per node. */
        private final IdentityHashMap<SyntaxNode, List<String>> callNameCache = new IdentityHashMap<>();

        List<String> callNames(SyntaxNode call, Scope s) {
            List<String> c = callNameCache.get(call);
            if (c != null) {
                return c;
            }
            SyntaxNode f = call.field("function");
            List<String> names = List.of();
            if (f != null) {
                names = resolveDotted(f, s);
                if (names.isEmpty() && f.is("attribute")) {
                    String sh = shape(f, s, 0);
                    names = sh == null ? List.of() : List.of(sh);
                }
            }
            callNameCache.put(call, names);
            return names;
        }

        private String shape(SyntaxNode e, Scope s, int depth) {
            if (depth > MAX_SHAPE_DEPTH || e == null) {
                return null;
            }
            switch (e.type()) {
                case "identifier" -> {
                    List<String> r = resolveName(e.text(), s);
                    return r.isEmpty() ? null : r.get(0);
                }
                case "attribute" -> {
                    SyntaxNode a = e.field("attribute");
                    if (a == null) {
                        return null;
                    }
                    String o = shape(e.field("object"), s, depth + 1);
                    return (o == null ? "<expr>" : o) + "." + a.text();
                }
                case "call" -> {
                    String f = shape(e.field("function"), s, depth + 1);
                    return (f == null ? "<expr>" : f) + "()";
                }
                default -> {
                    return null;
                }
            }
        }

        static String methodName(SyntaxNode call) {
            SyntaxNode f = call.field("function");
            if (f == null) {
                return "";
            }
            if (f.is("attribute")) {
                SyntaxNode a = f.field("attribute");
                return a == null ? "" : a.text();
            }
            return Texts.trim(f.text());
        }

        // ------------------------------------------------------------------ 8.5 argument analysis

        /** String value of a {@code string} / {@code concatenated_string}, or null. */
        String stringValue(SyntaxNode n) {
            if (n.is("string")) {
                if (n.childCount() == 0) {
                    return null;
                }
                String start = Texts.lower(n.child(0).text());
                if (start.indexOf('b') >= 0 || start.indexOf('f') >= 0) {
                    return null;
                }
                StringBuilder b = new StringBuilder();
                for (int i = 0; i < n.childCount(); i++) {
                    SyntaxNode c = n.child(i);
                    if (c.is("interpolation")) {
                        return null;
                    }
                    if (c.is("string_content")) {
                        b.append(c.text());
                    }
                }
                return b.toString();
            }
            if (n.is("concatenated_string")) {
                StringBuilder b = new StringBuilder();
                for (int i = 0; i < n.childCount(); i++) {
                    SyntaxNode c = n.child(i);
                    if (!c.isNamed() || c.is("comment")) {
                        continue;
                    }
                    String v = stringValue(c);
                    if (v == null) {
                        return null;
                    }
                    b.append(v);
                }
                return b.toString();
            }
            return null;
        }

        static String integerValue(SyntaxNode n) {
            return n.is("integer") ? n.text().replace("_", "") : null;
        }

        void strings(SyntaxNode e, Scope s, int depth, List<String> out) {
            if (depth > MAX_STRINGS_DEPTH) {
                return;
            }
            String v = stringValue(e);
            if (v != null) {
                out.add(v);
                return;
            }
            switch (e.type()) {
                case "identifier" -> {
                    for (String c : constantValues(e.text(), s)) {
                        if (!DIGITS.matcher(c).matches()) {
                            out.add(c);
                        }
                    }
                }
                case "list", "tuple", "set", "parenthesized_expression" -> {
                    for (int i = 0; i < e.childCount(); i++) {
                        SyntaxNode c = e.child(i);
                        if (c.isNamed()) {
                            strings(c, s, depth + 1, out);
                        }
                    }
                }
                default -> {
                    // nothing
                }
            }
        }

        void collectSymbols(SyntaxNode e, Scope s, int d, Set<String> out) {
            if (d > MAX_COLLECT_DEPTH) {
                return;
            }
            switch (e.type()) {
                case "identifier" -> {
                    out.addAll(resolveDotted(e, s));
                    out.addAll(boundCalls(e.text(), s));
                }
                case "attribute" -> {
                    out.addAll(resolveDotted(e, s));
                    SyntaxNode o = e.field("object");
                    if (o != null && !o.is("identifier") && !o.is("attribute")) {
                        collectSymbols(o, s, d + 1, out);
                    }
                }
                case "call" -> {
                    out.addAll(callNames(e, s));
                    SyntaxNode f = e.field("function");
                    if (f != null && !f.is("identifier") && !f.is("attribute")) {
                        collectSymbols(f, s, d + 1, out);
                    }
                    SyntaxNode a = e.field("arguments");
                    if (a != null) {
                        collectSymbols(a, s, d + 1, out);
                    }
                }
                case "lambda", "string", "integer", "float", "comment" -> {
                    // nothing
                }
                default -> {
                    for (int i = 0; i < e.childCount(); i++) {
                        SyntaxNode c = e.child(i);
                        if (c.isNamed()) {
                            collectSymbols(c, s, d + 1, out);
                        }
                    }
                }
            }
        }

        List<String> valueTexts(SyntaxNode e, Scope s) {
            List<String> l = new ArrayList<>();
            l.add(e.text());
            String v = stringValue(e);
            if (v != null) {
                l.add(v);
            }
            if (e.is("identifier")) {
                l.addAll(constantValues(e.text(), s));
            }
            if (e.is("identifier") || e.is("attribute")) {
                l.addAll(resolveDotted(e, s));
            }
            if (e.is("call")) {
                l.addAll(callNames(e, s));
            }
            return l;
        }

        // ------------------------------------------------------------------ 8.6 matching calls

        /** Lazily computed argument analysis of one call. */
        private final class Args {
            final SyntaxNode call;
            final Scope scope;
            final List<SyntaxNode> positional = new ArrayList<>();
            final List<Map.Entry<String, SyntaxNode>> keywords = new ArrayList<>();
            final SyntaxNode generator;
            private List<String> strings;
            private Set<String> symbols;

            Args(SyntaxNode call, Scope scope) {
                this.call = call;
                this.scope = scope;
                SyntaxNode a = call.field("arguments");
                SyntaxNode gen = null;
                if (a != null && a.is("generator_expression")) {
                    gen = a;
                } else if (a != null) {
                    for (int i = 0; i < a.childCount(); i++) {
                        SyntaxNode c = a.child(i);
                        if (!c.isNamed()) {
                            continue;
                        }
                        switch (c.type()) {
                            case "keyword_argument" -> {
                                SyntaxNode name = c.field("name");
                                SyntaxNode value = c.field("value");
                                if (name != null && value != null) {
                                    keywords.add(Map.entry(name.text(), value));
                                }
                            }
                            case "list_splat", "dictionary_splat", "comment" -> {
                                // ignored
                            }
                            default -> positional.add(c);
                        }
                    }
                }
                this.generator = gen;
            }

            boolean hasKeyword(String k) {
                for (Map.Entry<String, SyntaxNode> e : keywords) {
                    if (e.getKey().equals(k)) {
                        return true;
                    }
                }
                return false;
            }

            SyntaxNode keyword(String k) {
                for (Map.Entry<String, SyntaxNode> e : keywords) {
                    if (e.getKey().equals(k)) {
                        return e.getValue();
                    }
                }
                return null;
            }

            List<String> strings() {
                if (strings == null) {
                    List<String> l = new ArrayList<>();
                    if (generator == null) {
                        for (SyntaxNode p : positional) {
                            FileRun.this.strings(p, scope, 0, l);
                        }
                        for (Map.Entry<String, SyntaxNode> k : keywords) {
                            FileRun.this.strings(k.getValue(), scope, 0, l);
                        }
                    }
                    strings = l;
                }
                return strings;
            }

            Set<String> symbols() {
                if (symbols == null) {
                    Set<String> s = new HashSet<>();
                    if (generator != null) {
                        collectSymbols(generator, scope, 0, s);
                    } else {
                        for (SyntaxNode p : positional) {
                            collectSymbols(p, scope, 0, s);
                        }
                        for (Map.Entry<String, SyntaxNode> k : keywords) {
                            collectSymbols(k.getValue(), scope, 0, s);
                        }
                    }
                    symbols = s;
                }
                return symbols;
            }
        }

        private record Candidate(PythonPattern pattern, String nameUsed) {}

        private void matchCall(SyntaxNode call, Scope s) {
            List<String> names = callNames(call, s);
            if (names.isEmpty()) {
                return;
            }
            String m = methodName(call);
            List<Candidate> cands = new ArrayList<>();
            Set<PythonPattern> seen = new HashSet<>();
            for (String n : names) {
                String[] seg = n.split("\\.", -1);
                for (int k = seg.length; k >= 1; k--) {
                    String prefix = String.join(".", java.util.Arrays.copyOf(seg, k));
                    List<PythonPattern> ps = index.byCall.get(prefix);
                    if (ps != null) {
                        for (PythonPattern p : ps) {
                            if (seen.add(p)) {
                                cands.add(new Candidate(p, n));
                            }
                        }
                    }
                }
            }
            List<PythonPattern> byMethod = index.byMethod.get(m);
            if (byMethod != null) {
                for (PythonPattern p : byMethod) {
                    if (seen.add(p)) {
                        cands.add(new Candidate(p, names.get(0)));
                    }
                }
            }
            Args args = null;
            if (!index.anyCall.isEmpty()) {
                args = new Args(call, s);
                boolean any = false;
                for (String k : index.anyCallKeywords) {
                    if (args.hasKeyword(k)) {
                        any = true;
                        break;
                    }
                }
                if (any) {
                    for (PythonPattern p : index.anyCall) {
                        if (seen.add(p)) {
                            cands.add(new Candidate(p, names.get(0)));
                        }
                    }
                }
            }
            if (cands.isEmpty()) {
                return;
            }
            if (args == null) {
                args = new Args(call, s);
            }
            // hits
            List<Hit> hits = new ArrayList<>();
            Set<SourceRule> hitRules = new HashSet<>();
            for (Candidate c : cands) {
                SourceRule r = c.pattern().rule;
                if (hitRules.contains(r)) {
                    continue;
                }
                if (conditionsHold(c.pattern(), args, m)) {
                    hits.add(new Hit(r, c.nameUsed(), c.pattern()));
                    hitRules.add(r);
                }
            }
            if (hits.isEmpty()) {
                return;
            }
            // refinement
            Set<String> refinedIdentities = new HashSet<>();
            for (Hit h : hits) {
                if (h.rule().asset().refined()) {
                    refinedIdentities.add(h.rule().asset().identity());
                }
            }
            for (Hit h : hits) {
                if (!h.rule().asset().refined() && refinedIdentities.contains(h.rule().asset().identity())) {
                    continue;
                }
                emit(h, call, args);
            }
        }

        private boolean conditionsHold(PythonPattern p, Args a, String method) {
            if (p.call != null && p.methods != null && !p.methods.contains(method)) {
                return false;
            }
            if (p.firstString != null) {
                List<String> s = a.strings();
                if (s.isEmpty() || !p.firstString.matcher(s.get(0)).lookingAt()) {
                    return false;
                }
            }
            if (p.stringContains != null) {
                boolean any = false;
                outer:
                for (String s : a.strings()) {
                    String l = Texts.lower(s);
                    for (String n : p.stringContains) {
                        if (l.contains(n)) {
                            any = true;
                            break outer;
                        }
                    }
                }
                if (!any) {
                    return false;
                }
            }
            if (p.anySymbol != null) {
                boolean any = false;
                for (String n : p.anySymbol) {
                    if (symbolHit(n, a.symbols())) {
                        any = true;
                        break;
                    }
                }
                if (!any) {
                    return false;
                }
            }
            if (p.allSymbols != null) {
                for (String n : p.allSymbols) {
                    if (!symbolHit(n, a.symbols())) {
                        return false;
                    }
                }
            }
            if (p.kwargs != null) {
                for (Map.Entry<String, Pattern> kw : p.kwargs.entrySet()) {
                    boolean found = false;
                    for (Map.Entry<String, SyntaxNode> k : a.keywords) {
                        if (!k.getKey().equals(kw.getKey())) {
                            continue;
                        }
                        for (String t : valueTexts(k.getValue(), a.scope)) {
                            if (kw.getValue().matcher(t).find()) {
                                found = true;
                                break;
                            }
                        }
                        if (found) {
                            break;
                        }
                    }
                    if (!found) {
                        return false;
                    }
                }
            }
            return true;
        }

        private boolean symbolHit(String name, Set<String> symbols) {
            if (symbols.contains(name)) {
                return true;
            }
            String suffix = "." + name;
            for (String s : symbols) {
                if (s.endsWith(suffix)) {
                    return true;
                }
            }
            return false;
        }

        private void emit(Hit h, SyntaxNode call, Args args) {
            List<Range> rs = ranges.computeIfAbsent(h.rule(), k -> new ArrayList<>());
            // Calls arrive in pre-order, i.e. with non-decreasing start offsets: a range that ends at or
            // before this call's start cannot contain this or any later call. Dropping those keeps the
            // list at the nesting depth instead of growing with every finding (quadratic on big files).
            rs.removeIf(r -> r.end() <= call.start());
            for (Range r : rs) {
                if (call.start() >= r.start() && call.end() <= r.end()) {
                    return;
                }
            }
            SyntaxNode argsNode = call.field("arguments");
            if (argsNode != null) {
                rs.add(new Range(argsNode.start(), argsNode.end()));
            }
            SyntaxNode report = call;
            if (h.pattern().reportAt != null) {
                SyntaxNode op = operationCall(call, h.pattern().reportAt);
                if (op != null) {
                    report = op;
                }
            }
            int line;
            SyntaxNode f = report.field("function");
            SyntaxNode attr = f != null && f.is("attribute") ? f.field("attribute") : null;
            line = attr != null ? attr.line() : report.line();
            if (!emitted.add(h.rule().id() + "\u0000" + line)) {
                return;
            }
            String param = h.pattern().hasParam ? param(h.pattern(), h.nameUsed(), args) : null;
            out.add(new SourceFinding(rel, line, h.rule(), h.nameUsed(), h.nameUsed(),
                    Texts.truncateCodePoints(report.text(), SNIPPET_MAX), param, test));
        }

        /** SPEC 8.7. */
        private SyntaxNode operationCall(SyntaxNode c, List<String> reportAt) {
            SyntaxNode x = c;
            SyntaxNode p = x.parent();
            while (p != null && REPORT_AT_CHAIN.contains(p.type())) {
                if (p.is("call")) {
                    SyntaxNode a = p.field("arguments");
                    if (a == null || !(x.start() >= a.start() && x.end() <= a.end())) {
                        return null;
                    }
                    if (reportAt.contains(methodName(p))) {
                        return p;
                    }
                }
                x = p;
                p = p.parent();
            }
            return null;
        }

        /** SPEC 8.8. */
        private String param(PythonPattern p, String nameUsed, Args a) {
            if (p.paramSelf) {
                int dot = nameUsed.lastIndexOf('.');
                return dot < 0 ? null : nameUsed.substring(dot + 1);
            }
            SyntaxNode arg = null;
            if (p.paramKeyword != null) {
                arg = a.keyword(p.paramKeyword);
            }
            if (arg == null && p.paramIndex != null && p.paramIndex < a.positional.size()) {
                arg = a.positional.get(p.paramIndex);
            }
            if (arg == null) {
                return null;
            }
            String v = integerValue(arg);
            if (v == null) {
                v = stringValue(arg);
            }
            if (v != null) {
                return v;
            }
            List<String> cands = List.of();
            if (arg.is("identifier")) {
                List<String> cv = constantValues(arg.text(), a.scope);
                if (!cv.isEmpty()) {
                    return cv.get(0);
                }
                cands = boundCalls(arg.text(), a.scope);
                if (cands.isEmpty()) {
                    String self = arg.text();
                    List<String> rn = new ArrayList<>(resolveName(self, a.scope));
                    rn.removeIf(x -> x.equals(self));
                    cands = rn;
                }
            } else if (arg.is("call")) {
                cands = callNames(arg, a.scope);
            } else if (arg.is("attribute")) {
                cands = resolveDotted(arg, a.scope);
            }
            for (String c : cands) {
                int dot = c.lastIndexOf('.');
                if (dot >= 0) {
                    return c.substring(dot + 1);
                }
            }
            return null;
        }

        // ------------------------------------------------------------------ 8.9 attribute assignments

        private void matchAssignment(SyntaxNode n, Scope s) {
            SyntaxNode left = n.field("left");
            SyntaxNode right = n.field("right");
            SyntaxNode attr = left == null ? null : left.field("attribute");
            if (attr == null || right == null) {
                return;
            }
            String field = attr.text();
            if (!index.assignFields.contains(field)) {
                return;
            }
            List<String> texts = null;
            for (Map.Entry<SourceRule, List<PythonPattern>> e : index.assignRules) {
                boolean hit = false;
                for (PythonPattern p : e.getValue()) {
                    if (!p.assign.equals(field)) {
                        continue;
                    }
                    if (texts == null) {
                        texts = valueTexts(right, s);
                    }
                    if (p.value != null) {
                        boolean any = false;
                        for (String t : texts) {
                            if (p.value.matcher(t).find()) {
                                any = true;
                                break;
                            }
                        }
                        if (!any) {
                            continue;
                        }
                    }
                    if (p.valueContains != null) {
                        boolean any = false;
                        outer:
                        for (String t : texts) {
                            String l = Texts.lower(t);
                            for (String needle : p.valueContains) {
                                if (l.contains(needle)) {
                                    any = true;
                                    break outer;
                                }
                            }
                        }
                        if (!any) {
                            continue;
                        }
                    }
                    hit = true;
                    break;
                }
                if (!hit) {
                    continue;
                }
                int line = n.line();
                if (!emitted.add(e.getKey().id() + "\u0000" + line)) {
                    continue;
                }
                out.add(new SourceFinding(rel, line, e.getKey(), field, field,
                        Texts.truncateCodePoints(n.text(), SNIPPET_MAX), null, test));
            }
        }
    }

    private record GuardKey(Scope scope, String name) {}
}
