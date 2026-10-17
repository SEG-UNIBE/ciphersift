/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang.go;

import ch.unibe.seg.ciphersift.lang.OidTable;
import ch.unibe.seg.ciphersift.model.SourceFinding;
import ch.unibe.seg.ciphersift.rules.GoPattern;
import ch.unibe.seg.ciphersift.rules.RuleSet;
import ch.unibe.seg.ciphersift.rules.SourceRule;
import ch.unibe.seg.ciphersift.syntax.SyntaxNode;
import ch.unibe.seg.ciphersift.util.Texts;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Go source analysis (SPEC 17). One instance per scan; {@link #analyze} is thread-safe. */
public final class GoAnalyzer {
    /** Depth limit of value / bound-name evaluation (SPEC 17.6, like Java 7.4.1). */
    static final int MAX_DEPTH = 12;
    /** Depth limit of the symbol collection (SPEC 17.7, like Python 8.5.2). */
    static final int MAX_COLLECT_DEPTH = 6;
    static final int SNIPPET_MAX = 500;

    private static final Set<String> FUNCTIONS = Set.of("function_declaration", "method_declaration", "func_literal");
    /** Expression ancestors of the nested-duplicate check (SPEC 17.8, DECISIONS G8). */
    private static final Set<String> EXPRESSION_ANCESTORS = Set.of("argument_list", "call_expression",
            "parenthesized_expression", "unary_expression", "composite_literal", "literal_value", "literal_element",
            "keyed_element");
    private static final Set<String> COMPARISONS = Set.of("==", "!=", "<", "<=", ">", ">=");
    private static final Set<String> NO_SYMBOLS = Set.of("func_literal", "interpreted_string_literal",
            "raw_string_literal", "int_literal", "float_literal", "imaginary_literal", "rune_literal", "comment");
    private static final Pattern MAJOR_VERSION = Pattern.compile("v[0-9]+");
    private static final Pattern DOT_MAJOR_VERSION = Pattern.compile("\\.v[0-9]+$");
    private static final Pattern DECIMAL = Pattern.compile("0|[1-9][0-9_]*");

    private final GoRuleIndex index;

    public GoAnalyzer(RuleSet rules) {
        this.index = new GoRuleIndex(rules.goRules());
    }

    /** Analyses one parsed Go file. */
    public List<SourceFinding> analyze(SyntaxNode root, String relativePath, boolean test) {
        if (index.isEmpty()) {
            return List.of();
        }
        return new FileRun(root, relativePath, test).run();
    }

    /**
     * The local name an import without explicit name gets (SPEC 17.4): the last path segment, the one
     * before a major-version suffix {@code vN}, without a trailing {@code .vN}.
     */
    static String defaultLocalName(String path) {
        String[] seg = path.split("/", -1);
        String last = seg[seg.length - 1];
        if (seg.length > 1 && MAJOR_VERSION.matcher(last).matches()) {
            last = seg[seg.length - 2];
        }
        return DOT_MAJOR_VERSION.matcher(last).replaceFirst("");
    }

    /** Decodes the content of an interpreted string literal (SPEC 17.6). */
    static String decodeInterpreted(String s) {
        StringBuilder b = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) {
                b.append(c);
                i++;
                continue;
            }
            char e = s.charAt(i + 1);
            int consumed = 2;
            switch (e) {
                case 'a' -> b.append('\u0007');
                case 'b' -> b.append('\b');
                case 'f' -> b.append('\f');
                case 'n' -> b.append('\n');
                case 'r' -> b.append('\r');
                case 't' -> b.append('\t');
                case 'v' -> b.append('\u000b');
                case '\\' -> b.append('\\');
                case '\'' -> b.append('\'');
                case '"' -> b.append('"');
                case 'x', 'u', 'U' -> {
                    int len = e == 'x' ? 2 : e == 'u' ? 4 : 8;
                    int cp = hex(s, i + 2, len);
                    // surrogate halves are not code points (Go rejects them; SPEC 11.6: no lone surrogates)
                    if (cp < 0 || cp > Character.MAX_CODE_POINT || (cp >= 0xD800 && cp <= 0xDFFF)) {
                        b.append(s, i, Math.min(s.length(), i + 2));
                    } else {
                        b.appendCodePoint(cp);
                        consumed = 2 + len;
                    }
                }
                default -> {
                    if (octal(s, i + 1) >= 0) {
                        b.append((char) octal(s, i + 1));
                        consumed = 4;
                    } else {
                        b.append(c).append(e); // invalid escape: keep its text
                    }
                }
            }
            i += consumed;
        }
        return b.toString();
    }

    private static int hex(String s, int from, int len) {
        if (from + len > s.length()) {
            return -1;
        }
        int v = 0;
        for (int k = from; k < from + len; k++) {
            int d = Character.digit(s.charAt(k), 16);
            if (d < 0) {
                return -1;
            }
            v = v * 16 + d;
        }
        return v;
    }

    private static int octal(String s, int from) {
        if (from + 3 > s.length()) {
            return -1;
        }
        int v = 0;
        for (int k = from; k < from + 3; k++) {
            char ch = s.charAt(k);
            if (ch < '0' || ch > '7') {
                return -1;
            }
            v = v * 8 + (ch - '0');
        }
        return v <= 255 ? v : -1;
    }

    // ====================================================================== per file

    private enum Kind { CALL, REF, COMPOSITE, ASSIGN }

    /**
     * An event (SPEC 17.5). {@code names}: the qualified names (call, ref, composite); {@code field} and
     * {@code value}: assign events; {@code args}: the argument list of a call event; {@code body}: the
     * literal value of a composite event.
     */
    private record Event(Kind kind, SyntaxNode node, List<String> names, String field, SyntaxNode value,
            SyntaxNode args, SyntaxNode body, int line) {}

    private record Selected(Event event, SourceRule rule, GoPattern pattern, String nameUsed) {}

    /** A binding of a name in a scope (SPEC 17.6); {@code value} is null for a binding without value. */
    private record Binding(SyntaxNode value) {}

    /** A plain assignment {@code name = value} (value null: compound assignment, ++, --, range). */
    private record Assignment(SyntaxNode scope, String name, SyntaxNode value) {}

    /** A resolved value (SPEC 17.6) and whether it is a string. */
    private record Val(String text, boolean string) {}

    private final class FileRun {
        final SyntaxNode root;
        final String rel;
        final boolean test;
        final Map<String, String> imports = new HashMap<>();
        final List<String> dotPaths = new ArrayList<>();
        final Set<String> declared = new HashSet<>();
        /** scope node → name → bindings (in walk order). */
        final Map<SyntaxNode, Map<String, List<Binding>>> scopes = new IdentityHashMap<>();
        /** Type arguments of {@code new(T)} composite events; not reference events themselves. */
        final Set<SyntaxNode> consumed = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
        final Set<Object> resolving = new HashSet<>();
        /** Plain assignments, bound after all declarations are known (SPEC 17.6). */
        final List<Assignment> assignments = new ArrayList<>();
        final Map<Event, Set<String>> symbolCache = new IdentityHashMap<>();

        FileRun(SyntaxNode root, String rel, boolean test) {
            this.root = root;
            this.rel = rel;
            this.test = test;
        }

        List<SourceFinding> run() {
            declarations();
            List<Event> events = events();
            List<Selected> selected = new ArrayList<>();
            Map<SyntaxNode, List<Selected>> byNode = new IdentityHashMap<>();
            for (Event e : events) {
                for (Selected s : select(e)) {
                    selected.add(s);
                    byNode.computeIfAbsent(e.node(), k -> new ArrayList<>()).add(s);
                }
            }
            List<SourceFinding> out = new ArrayList<>();
            for (Selected s : selected) {
                if (nestedDuplicate(s, byNode)) {
                    continue;
                }
                Event e = s.event();
                String name = e.kind() == Kind.ASSIGN ? e.field() : s.nameUsed();
                out.add(new SourceFinding(rel, e.line(), s.rule(), name, name,
                        Texts.truncateCodePoints(e.node().text(), SNIPPET_MAX), param(s), test));
            }
            return out;
        }

        // ------------------------------------------------------------------ 17.4 / 17.6 declarations

        private void declarations() {
            ArrayDeque<SyntaxNode> stack = new ArrayDeque<>();
            stack.push(root);
            while (!stack.isEmpty()) {
                SyntaxNode n = stack.pop();
                switch (n.type()) {
                    case "import_spec" -> importSpec(n);
                    case "function_declaration", "method_declaration", "func_literal" -> {
                        if (n.is("function_declaration")) {
                            declare(n.field("name"));
                        }
                        for (String f : List.of("receiver", "parameters", "result")) {
                            SyntaxNode pl = n.field(f);
                            if (pl != null && pl.is("parameter_list")) {
                                for (SyntaxNode pd : pl.namedChildren()) {
                                    if (pd.is("parameter_declaration") || pd.is("variadic_parameter_declaration")) {
                                        for (SyntaxNode id : pd.fields("name")) {
                                            declare(id);
                                            bind(n, id.text(), null);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    case "const_spec", "var_spec" -> {
                        List<SyntaxNode> names = new ArrayList<>();
                        for (SyntaxNode id : n.fields("name")) {
                            if (id.is("identifier")) {
                                names.add(id);
                            }
                        }
                        SyntaxNode values = n.field("value");
                        pair(scopeOf(n), names, values == null ? List.of() : expressions(values));
                        names.forEach(this::declare);
                    }
                    case "short_var_declaration" -> {
                        List<SyntaxNode> left = expressions(n.field("left"));
                        pair(scopeOf(n), left, expressions(n.field("right")));
                        for (SyntaxNode id : left) {
                            if (id.is("identifier")) {
                                declare(id);
                            }
                        }
                    }
                    case "assignment_statement" -> {
                        SyntaxNode op = n.field("operator");
                        List<SyntaxNode> left = expressions(n.field("left"));
                        List<SyntaxNode> right = op != null && op.text().equals("=")
                                ? expressions(n.field("right")) : List.of();
                        for (int i = 0; i < left.size(); i++) {
                            if (left.get(i).is("identifier")) {
                                assignments.add(new Assignment(scopeOf(n), left.get(i).text(), paired(left, right, i)));
                            }
                        }
                    }
                    case "inc_statement", "dec_statement" -> {
                        SyntaxNode id = n.firstNamedChild();
                        if (id != null && id.is("identifier")) {
                            assignments.add(new Assignment(scopeOf(n), id.text(), null));
                        }
                    }
                    case "range_clause" -> {
                        boolean declares = n.hasChildOfType(":=");
                        for (SyntaxNode id : expressions(n.field("left"))) {
                            if (id.is("identifier")) {
                                if (declares) {
                                    declare(id);
                                    bind(scopeOf(n), id.text(), null);
                                } else {
                                    assignments.add(new Assignment(scopeOf(n), id.text(), null));
                                }
                            }
                        }
                    }
                    case "type_spec", "type_alias" -> declare(n.field("name"));
                    default -> {
                        // nothing
                    }
                }
                for (int i = n.childCount() - 1; i >= 0; i--) {
                    SyntaxNode c = n.child(i);
                    if (c.isNamed()) {
                        stack.push(c);
                    }
                }
            }
            // a plain assignment binds the variable where it is declared: the innermost scope, from the
            // assignment's function outwards, that declares the name; else the file (SPEC 17.6)
            for (Assignment a : assignments) {
                SyntaxNode s = a.scope();
                while (s != root && !declares(s, a.name())) {
                    s = scopeOf(s);
                }
                bind(s, a.name(), a.value());
            }
        }

        private boolean declares(SyntaxNode scope, String name) {
            Map<String, List<Binding>> m = scopes.get(scope);
            return m != null && m.containsKey(name);
        }

        private void importSpec(SyntaxNode n) {
            SyntaxNode p = n.field("path");
            if (p == null) {
                return;
            }
            String t = p.text();
            if (t.length() < 2) {
                return;
            }
            String path = t.substring(1, t.length() - 1);
            if (path.isEmpty()) {
                return;
            }
            SyntaxNode name = n.field("name");
            if (name == null) {
                imports.put(defaultLocalName(path), path);
            } else if (name.is("dot")) {
                if (!dotPaths.contains(path)) {
                    dotPaths.add(path);
                }
            } else if (name.is("package_identifier")) {
                imports.put(name.text(), path);
            }
            // blank import: no name
        }

        private void declare(SyntaxNode id) {
            if (id != null) {
                declared.add(id.text());
            }
        }

        /** Pairs left names with right values (SPEC 17.6): same count → by index; one value → all; else none. */
        private void pair(SyntaxNode scope, List<SyntaxNode> left, List<SyntaxNode> right) {
            for (int i = 0; i < left.size(); i++) {
                SyntaxNode id = left.get(i);
                if (id.is("identifier")) {
                    bind(scope, id.text(), paired(left, right, i));
                }
            }
        }

        private SyntaxNode paired(List<SyntaxNode> left, List<SyntaxNode> right, int i) {
            return left.size() == right.size() ? right.get(i) : right.size() == 1 ? right.get(0) : null;
        }

        private void bind(SyntaxNode scope, String name, SyntaxNode value) {
            if (name.equals("_")) {
                return;
            }
            scopes.computeIfAbsent(scope, k -> new HashMap<>()).computeIfAbsent(name, k -> new ArrayList<>(1))
                    .add(new Binding(value));
        }

        /** The named, non-comment children of an expression list (or of an argument list). */
        private List<SyntaxNode> expressions(SyntaxNode list) {
            if (list == null) {
                return List.of();
            }
            List<SyntaxNode> l = new ArrayList<>();
            for (SyntaxNode c : list.namedChildren()) {
                if (!c.is("comment")) {
                    l.add(c);
                }
            }
            return l;
        }

        /** The innermost function scope containing {@code n} (itself included), else the file. */
        private SyntaxNode scopeOf(SyntaxNode n) {
            for (SyntaxNode x = n.parent(); x != null; x = x.parent()) {
                if (FUNCTIONS.contains(x.type())) {
                    return x;
                }
            }
            return root;
        }

        /** {@code bindings(N, x)} of SPEC 17.6 and the scope they belong to. */
        private Map.Entry<SyntaxNode, List<Binding>> bindings(String name, SyntaxNode at) {
            SyntaxNode s = scopeOf(at);
            while (true) {
                Map<String, List<Binding>> m = scopes.get(s);
                List<Binding> l = m == null ? null : m.get(name);
                if (l != null) {
                    return Map.entry(s, l);
                }
                if (s == root) {
                    return null;
                }
                s = scopeOf(s);
            }
        }

        // ------------------------------------------------------------------ 17.4 names

        /** The name of a qualified selector, or null. */
        private String qualified(SyntaxNode sel) {
            if (!sel.is("selector_expression")) {
                return null;
            }
            SyntaxNode op = sel.field("operand");
            SyntaxNode f = sel.field("field");
            if (op == null || f == null || !op.is("identifier")) {
                return null;
            }
            String path = imports.get(op.text());
            return path == null ? null : path + "." + f.text();
        }

        /** Dot-import names of an unqualified identifier or type identifier (SPEC 17.4). */
        private List<String> dotNames(String name) {
            // only exported names (upper-case first letter) are visible through a dot import
            if (dotPaths.isEmpty() || name.isEmpty() || !Character.isUpperCase(name.codePointAt(0))
                    || declared.contains(name) || imports.containsKey(name)) {
                return List.of();
            }
            List<String> l = new ArrayList<>(dotPaths.size());
            for (String p : dotPaths) {
                l.add(p + "." + name);
            }
            return l;
        }

        /** Names of a qualified selector or an unqualified identifier; empty otherwise. */
        private List<String> names(SyntaxNode e) {
            if (e == null) {
                return List.of();
            }
            if (e.is("selector_expression")) {
                String q = qualified(e);
                return q == null ? List.of() : List.of(q);
            }
            if (e.is("identifier")) {
                return dotNames(e.text());
            }
            return List.of();
        }

        /** Names of a type (SPEC 17.4): a qualified type or a type identifier with dot imports. */
        private List<String> typeNames(SyntaxNode t) {
            if (t == null) {
                return List.of();
            }
            if (t.is("qualified_type")) {
                SyntaxNode pkg = t.field("package");
                SyntaxNode name = t.field("name");
                String path = pkg == null ? null : imports.get(pkg.text());
                return path == null || name == null ? List.of() : List.of(path + "." + name.text());
            }
            if (t.is("type_identifier")) {
                return dotNames(t.text());
            }
            if (t.is("selector_expression")) {
                return names(t);
            }
            return List.of();
        }

        // ------------------------------------------------------------------ 17.5 events

        private List<Event> events() {
            List<Event> out = new ArrayList<>();
            ArrayDeque<SyntaxNode> stack = new ArrayDeque<>();
            stack.push(root);
            while (!stack.isEmpty()) {
                SyntaxNode n = stack.pop();
                switch (n.type()) {
                    case "import_declaration" -> {
                        continue; // import paths are not expressions
                    }
                    case "call_expression" -> callEvent(n, out);
                    case "composite_literal" -> {
                        List<String> tn = typeNames(n.field("type"));
                        if (!tn.isEmpty()) {
                            out.add(new Event(Kind.COMPOSITE, n, tn, null, null, null, n.field("body"), n.line()));
                        }
                    }
                    case "selector_expression" -> {
                        String q = qualified(n);
                        if (q != null && isReferencePosition(n)) {
                            out.add(new Event(Kind.REF, n, List.of(q), null, null, null, null, n.field("field").line()));
                        }
                    }
                    case "identifier" -> {
                        if (!dotPaths.isEmpty() && isReferencePosition(n)) {
                            List<String> dn = dotNames(n.text());
                            if (!dn.isEmpty()) {
                                out.add(new Event(Kind.REF, n, dn, null, null, null, null, n.line()));
                            }
                        }
                    }
                    case "keyed_element" -> {
                        SyntaxNode key = n.field("key");
                        SyntaxNode value = n.field("value");
                        List<SyntaxNode> k = key == null ? List.of() : expressions(key);
                        if (k.size() == 1 && k.get(0).is("identifier") && value != null) {
                            SyntaxNode v = value.firstNamedChild();
                            out.add(new Event(Kind.ASSIGN, n, List.of(), k.get(0).text(), v == null ? value : v, null,
                                    null, n.line()));
                        }
                    }
                    case "assignment_statement" -> {
                        SyntaxNode op = n.field("operator");
                        List<SyntaxNode> left = expressions(n.field("left"));
                        List<SyntaxNode> right = expressions(n.field("right"));
                        if (op != null && op.text().equals("=") && left.size() == right.size()) {
                            for (int i = 0; i < left.size(); i++) {
                                SyntaxNode l = left.get(i);
                                SyntaxNode f = l.is("selector_expression") ? l.field("field") : null;
                                if (f != null) {
                                    out.add(new Event(Kind.ASSIGN, n, List.of(), f.text(), right.get(i), null, null,
                                            n.line()));
                                }
                            }
                        }
                    }
                    default -> {
                        // nothing
                    }
                }
                for (int i = n.childCount() - 1; i >= 0; i--) {
                    SyntaxNode c = n.child(i);
                    if (c.isNamed()) {
                        stack.push(c);
                    }
                }
            }
            return out;
        }

        private void callEvent(SyntaxNode n, List<Event> out) {
            SyntaxNode fn = n.field("function");
            SyntaxNode args = n.field("arguments");
            if (fn == null) {
                return;
            }
            if (fn.is("identifier") && fn.text().equals("new") && !declared.contains("new") && args != null) {
                List<SyntaxNode> a = expressions(args);
                if (a.size() == 1) {
                    List<String> tn = typeNames(a.get(0));
                    if (!tn.isEmpty()) {
                        consumed.add(a.get(0));
                        out.add(new Event(Kind.COMPOSITE, n, tn, null, null, null, null, n.line()));
                    }
                }
                return;
            }
            List<String> names = names(fn);
            if (names.isEmpty()) {
                return;
            }
            int line = fn.is("selector_expression") ? fn.field("field").line() : n.line();
            out.add(new Event(Kind.CALL, n, names, null, null, args, null, line));
        }

        /**
         * Is a qualified selector or identifier a reference (SPEC 17.5): not a call's function, not the
         * type of {@code new(T)}, not (in) the key of a keyed element, not an import name, not in a test
         * position.
         */
        private boolean isReferencePosition(SyntaxNode x) {
            SyntaxNode p = x.parent();
            if (p == null || consumed.contains(x)) {
                return false;
            }
            if (p.is("call_expression") && "function".equals(x.field())) {
                return false;
            }
            if (p.is("selector_expression") && "operand".equals(x.field()) && x.is("identifier")
                    && imports.containsKey(x.text())) {
                return false;
            }
            if (p.is("literal_element") && "key".equals(p.field()) && p.parent() != null
                    && p.parent().is("keyed_element")) {
                return false;
            }
            SyntaxNode y = x;
            while (p != null && (p.is("parenthesized_expression") || p.is("unary_expression"))) {
                y = p;
                p = p.parent();
            }
            if (p == null) {
                return true;
            }
            if (p.is("binary_expression") && ("left".equals(y.field()) || "right".equals(y.field()))) {
                SyntaxNode op = p.field("operator");
                if (op != null && COMPARISONS.contains(op.text())) {
                    return false;
                }
            }
            if (p.is("expression_list") && "value".equals(p.field()) && p.parent() != null
                    && p.parent().is("expression_case")) {
                return false;
            }
            return true;
        }

        // ------------------------------------------------------------------ 17.8 selection

        private record Candidate(GoPattern pattern, String name) {}

        private List<Candidate> candidates(Event e) {
            Map<GoPattern, String> found = new LinkedHashMap<>();
            switch (e.kind()) {
                case CALL -> {
                    for (String n : e.names()) {
                        addAll(found, index.callExact.get(n), n);
                        addPrefix(found, index.callPrefix, n);
                    }
                }
                case REF -> {
                    for (String n : e.names()) {
                        addAll(found, index.refExact.get(n), n);
                        addPrefix(found, index.refPrefix, n);
                    }
                }
                case COMPOSITE -> {
                    for (String n : e.names()) {
                        addAll(found, index.composite.get(n), n);
                    }
                }
                case ASSIGN -> addAll(found, index.assign.get(e.field()), e.field());
                default -> throw new IllegalStateException();
            }
            List<Candidate> l = new ArrayList<>(found.size());
            found.forEach((p, n) -> l.add(new Candidate(p, n)));
            l.sort((a, b) -> a.pattern().rule.order() != b.pattern().rule.order()
                    ? Integer.compare(a.pattern().rule.order(), b.pattern().rule.order())
                    : Integer.compare(a.pattern().position, b.pattern().position));
            return l;
        }

        private void addAll(Map<GoPattern, String> found, List<GoPattern> ps, String name) {
            if (ps != null) {
                for (GoPattern p : ps) {
                    found.putIfAbsent(p, name);
                }
            }
        }

        private void addPrefix(Map<GoPattern, String> found, List<GoPattern> ps, String name) {
            for (GoPattern p : ps) {
                if (p.nameMatches(name)) {
                    found.putIfAbsent(p, name);
                }
            }
        }

        /** The rules reported for an event: Java's selection (SPEC 7.7.1 via 17.8). */
        private List<Selected> select(Event e) {
            List<Candidate> cands = candidates(e);
            if (cands.isEmpty()) {
                return List.of();
            }
            Map<SourceRule, Selected> chosen = new LinkedHashMap<>();
            Map<SourceRule, Integer> spec = new HashMap<>();
            for (Candidate c : cands) {
                GoPattern p = c.pattern();
                Integer have = spec.get(p.rule);
                if (have != null && have >= p.specificity) {
                    continue;
                }
                if (holds(p, e)) {
                    spec.put(p.rule, p.specificity);
                    chosen.put(p.rule, new Selected(e, p.rule, p, c.name()));
                }
            }
            Map<String, Integer> maxByType = new HashMap<>();
            for (Map.Entry<SourceRule, Integer> x : spec.entrySet()) {
                maxByType.merge(x.getKey().asset().type(), x.getValue(), Math::max);
            }
            List<Selected> out = new ArrayList<>();
            for (Selected s : chosen.values()) {
                if (spec.get(s.rule()).equals(maxByType.get(s.rule().asset().type()))) {
                    out.add(s);
                }
            }
            return out;
        }

        private boolean holds(GoPattern p, Event e) {
            if (p.anySymbol != null) {
                if (e.kind() != Kind.CALL && e.kind() != Kind.COMPOSITE) {
                    return false;
                }
                Set<String> sym = symbols(e);
                boolean any = false;
                for (String s : p.anySymbol) {
                    if (sym.contains(s)) {
                        any = true;
                        break;
                    }
                }
                if (!any) {
                    return false;
                }
            }
            if (p.value != null || p.valueContains != null) {
                List<String> texts = valueTexts(e.value());
                if (p.value != null && texts.stream().noneMatch(t -> p.value.matcher(t).find())) {
                    return false;
                }
                if (p.valueContains != null) {
                    boolean any = false;
                    for (String t : texts) {
                        String lt = Texts.lower(t);
                        for (String needle : p.valueContains) {
                            if (lt.contains(needle)) {
                                any = true;
                                break;
                            }
                        }
                    }
                    if (!any) {
                        return false;
                    }
                }
            }
            return true;
        }

        /** SPEC 7.7.2 with the Go expression ancestors (17.8). */
        private boolean nestedDuplicate(Selected s, Map<SyntaxNode, List<Selected>> byNode) {
            String family = s.rule().asset().family();
            if (family == null) {
                return false;
            }
            String type = s.rule().asset().type();
            for (SyntaxNode p = s.event().node().parent(); p != null && EXPRESSION_ANCESTORS.contains(p.type());
                    p = p.parent()) {
                List<Selected> l = byNode.get(p);
                if (l != null) {
                    for (Selected o : l) {
                        if (type.equals(o.rule().asset().type()) && family.equals(o.rule().asset().family())) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        // ------------------------------------------------------------------ 17.6 values

        private Val value(SyntaxNode e, int d) {
            if (e == null || d > MAX_DEPTH) {
                return null;
            }
            switch (e.type()) {
                case "interpreted_string_literal" -> {
                    String t = e.text();
                    if (t.length() < 2) {
                        return null;
                    }
                    return new Val(decodeInterpreted(t.substring(1, t.length() - 1)), true);
                }
                case "raw_string_literal" -> {
                    String t = e.text();
                    if (t.length() < 2) {
                        return null;
                    }
                    return new Val(t.substring(1, t.length() - 1).replace("\r", ""), true);
                }
                case "int_literal" -> {
                    String t = e.text();
                    return DECIMAL.matcher(t).matches() ? new Val(t.replace("_", ""), false) : null;
                }
                case "true", "false" -> {
                    return new Val(e.text(), false);
                }
                case "parenthesized_expression" -> {
                    return value(firstExpression(e), d + 1);
                }
                case "binary_expression" -> {
                    SyntaxNode op = e.field("operator");
                    if (op == null || !op.text().equals("+")) {
                        return null;
                    }
                    Val l = value(e.field("left"), d + 1);
                    Val r = l == null || !l.string() ? null : value(e.field("right"), d + 1);
                    return r == null || !r.string() ? null : new Val(l.text() + r.text(), true);
                }
                case "identifier" -> {
                    Map.Entry<SyntaxNode, List<Binding>> b = bindings(e.text(), e);
                    if (b == null || b.getValue().isEmpty()) {
                        return null;
                    }
                    Object key = List.of("value", b.getKey(), e.text());
                    if (!resolving.add(key)) {
                        return null;
                    }
                    try {
                        Val first = null;
                        for (Binding x : b.getValue()) {
                            if (x.value() == null) {
                                return null;
                            }
                            Val v = value(x.value(), d + 1);
                            if (v == null || (first != null && !first.equals(v))) {
                                return null;
                            }
                            first = v;
                        }
                        return first;
                    } finally {
                        resolving.remove(key);
                    }
                }
                default -> {
                    return null;
                }
            }
        }

        private SyntaxNode firstExpression(SyntaxNode e) {
            for (SyntaxNode c : e.namedChildren()) {
                if (!c.is("comment")) {
                    return c;
                }
            }
            return null;
        }

        /** {@code boundNames(N, x, d)} of SPEC 17.6. */
        private void boundNames(String name, SyntaxNode at, int d, Set<String> out) {
            if (d > MAX_DEPTH) {
                return;
            }
            Map.Entry<SyntaxNode, List<Binding>> b = bindings(name, at);
            if (b == null) {
                return;
            }
            Object key = List.of("bound", b.getKey(), name);
            if (!resolving.add(key)) {
                return;
            }
            try {
                for (Binding x : b.getValue()) {
                    SyntaxNode v = x.value();
                    while (v != null && v.is("parenthesized_expression")) {
                        v = firstExpression(v);
                    }
                    if (v == null) {
                        continue;
                    }
                    switch (v.type()) {
                        case "call_expression" -> out.addAll(names(v.field("function")));
                        case "selector_expression" -> out.addAll(names(v));
                        case "identifier" -> {
                            List<String> dn = names(v);
                            if (!dn.isEmpty()) {
                                out.addAll(dn);
                            } else {
                                boundNames(v.text(), v, d + 1, out);
                            }
                        }
                        case "composite_literal" -> out.addAll(typeNames(v.field("type")));
                        case "unary_expression" -> {
                            SyntaxNode o = v.field("operand");
                            if (o != null && o.is("composite_literal")) {
                                out.addAll(typeNames(o.field("type")));
                            }
                        }
                        default -> {
                            // no names
                        }
                    }
                }
            } finally {
                resolving.remove(key);
            }
        }

        // ------------------------------------------------------------------ 17.7 symbols, value texts

        private Set<String> symbols(Event e) {
            Set<String> s = symbolCache.get(e);
            if (s == null) {
                s = new LinkedHashSet<>();
                if (e.kind() == Kind.CALL && e.args() != null) {
                    for (SyntaxNode a : expressions(e.args())) {
                        collect(a, 0, s);
                    }
                } else if (e.kind() == Kind.COMPOSITE && e.body() != null) {
                    collect(e.body(), 0, s);
                }
                symbolCache.put(e, s);
            }
            return s;
        }

        private void collect(SyntaxNode e, int d, Set<String> out) {
            if (e == null || d > MAX_COLLECT_DEPTH || NO_SYMBOLS.contains(e.type())) {
                return;
            }
            switch (e.type()) {
                case "selector_expression" -> {
                    String q = qualified(e);
                    if (q != null) {
                        out.add(q);
                    } else {
                        collect(e.field("operand"), d + 1, out);
                    }
                }
                case "identifier" -> {
                    out.addAll(names(e));
                    boundNames(e.text(), e, 0, out);
                }
                case "call_expression" -> {
                    SyntaxNode fn = e.field("function");
                    out.addAll(names(fn));
                    if (fn != null && !fn.is("identifier") && qualified(fn) == null) {
                        collect(fn, d + 1, out);
                    }
                    SyntaxNode args = e.field("arguments");
                    if (args != null) {
                        for (SyntaxNode a : expressions(args)) {
                            collect(a, d + 1, out);
                        }
                    }
                }
                case "composite_literal" -> {
                    out.addAll(typeNames(e.field("type")));
                    collect(e.field("body"), d + 1, out);
                }
                default -> {
                    for (SyntaxNode c : e.namedChildren()) {
                        collect(c, d + 1, out);
                    }
                }
            }
        }

        private List<String> valueTexts(SyntaxNode v) {
            if (v == null) {
                return List.of();
            }
            List<String> l = new ArrayList<>(3);
            l.add(v.text());
            Val x = value(v, 0);
            if (x != null) {
                l.add(x.text());
            }
            if (v.is("selector_expression") || v.is("identifier")) {
                l.addAll(names(v));
            } else if (v.is("call_expression")) {
                l.addAll(names(v.field("function")));
            }
            return l;
        }

        // ------------------------------------------------------------------ 17.9 params

        private String param(Selected s) {
            GoPattern p = s.pattern();
            String v = null;
            if (p.paramValue != null) {
                v = p.paramValue;
            } else if (p.paramSelf) {
                v = mapMember(s.nameUsed());
            } else if (p.paramIndex != null && s.event().kind() == Kind.CALL && s.event().args() != null) {
                List<SyntaxNode> args = expressions(s.event().args());
                if (p.paramIndex < args.size()) {
                    SyntaxNode a = args.get(p.paramIndex);
                    Val c = value(a, 0);
                    if (c != null) {
                        v = c.text();
                    } else {
                        for (String cand : candidates(a)) {
                            if (cand.indexOf('.') >= 0) {
                                v = mapMember(cand);
                                break;
                            }
                        }
                    }
                }
            }
            return v == null ? null : OidTable.map(v);
        }

        /** The candidates of a param argument (SPEC 17.9). */
        private List<String> candidates(SyntaxNode a) {
            // iterative: parentheses and unary operators (&x, *x) are passed through
            while (a != null && (a.is("parenthesized_expression") || a.is("unary_expression"))) {
                a = a.is("unary_expression") ? a.field("operand") : firstExpression(a);
            }
            if (a == null) {
                return List.of();
            }
            switch (a.type()) {
                case "selector_expression" -> {
                    return names(a);
                }
                case "identifier" -> {
                    Set<String> s = new LinkedHashSet<>(names(a));
                    boundNames(a.text(), a, 0, s);
                    return new ArrayList<>(s);
                }
                case "call_expression" -> {
                    return names(a.field("function"));
                }
                case "composite_literal" -> {
                    return typeNames(a.field("type"));
                }
                default -> {
                    return List.of();
                }
            }
        }

        /** A qualified name's param: a rule's fixed {@code param: {value}} for it, else its member. */
        private String mapMember(String qualifiedName) {
            String fixed = index.paramValues.get(qualifiedName);
            if (fixed != null) {
                return fixed;
            }
            int dot = qualifiedName.lastIndexOf('.');
            return dot < 0 ? qualifiedName : qualifiedName.substring(dot + 1);
        }
    }
}
