/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.wrappers;

import ch.unibe.seg.ciphersift.syntax.SyntaxNode;
import ch.unibe.seg.ciphersift.util.Texts;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Python definitions, call sites and import bindings (SPEC 18.2–18.4). */
final class PythonOutliner {
    private PythonOutliner() {}

    /**
     * @param cls the innermost enclosing module-level class (for {@code self} calls), or null
     * @param level 0 module level, 1 directly in a module-level class body, 2 anywhere else
     * @param def the innermost definition, or -1 (assignments go to its locals)
     */
    private record Frame(SyntaxNode node, String cls, int level, int def, int nesting) {}

    /** The module of a relative path (SPEC 18.2): without {@code .py}, {@code /} → {@code .}, no {@code .__init__}. */
    static String moduleOf(String path) {
        String p = path.endsWith(".py") ? path.substring(0, path.length() - 3) : path;
        p = p.replace('/', '.');
        if (p.equals("__init__")) {
            return "";
        }
        if (p.endsWith(".__init__")) {
            p = p.substring(0, p.length() - ".__init__".length());
        }
        return p;
    }

    static Outline outline(SyntaxNode root, String path, boolean test) {
        Outline o = new Outline(Outline.Lang.PYTHON, path, test);
        o.pyModule = moduleOf(path);
        boolean init = path.equals("__init__.py") || path.endsWith("/__init__.py");
        int dot = o.pyModule.lastIndexOf('.');
        o.pyPackage = init ? o.pyModule : dot < 0 ? "" : o.pyModule.substring(0, dot);
        List<Set<String>> locals = new ArrayList<>();
        ArrayDeque<Frame> stack = new ArrayDeque<>();
        stack.push(new Frame(root, null, 0, -1, 0));
        while (!stack.isEmpty()) {
            Frame f = stack.pop();
            SyntaxNode n = f.node();
            String cls = f.cls();
            int level = f.level();
            int def = f.def();
            int nesting = f.nesting();
            switch (n.type()) {
                case "import_statement" -> {
                    importStatement(o, n);
                    continue;
                }
                case "import_from_statement" -> {
                    importFrom(o, n);
                    continue;
                }
                case "class_definition" -> {
                    SyntaxNode name = n.field("name");
                    if (level == 0 && name != null) {
                        o.pyClasses.add(name.text());
                        cls = name.text();
                        level = 1;
                    } else {
                        level = 2;
                        cls = null;
                    }
                    nesting++;
                    if (name != null && def >= 0) {
                        locals.get(def).add(name.text());
                    }
                }
                case "function_definition" -> {
                    SyntaxNode name = n.field("name");
                    if (name == null) {
                        break;
                    }
                    if (def >= 0) {
                        locals.get(def).add(name.text());
                    }
                    boolean addressable = level == 0 || (level == 1 && cls != null);
                    String pyClass = level == 1 ? cls : null;
                    String owner = pyClass == null ? o.pyModule : o.pyModule + "." + pyClass;
                    String display = (o.pyModule.isEmpty() ? "" : o.pyModule + ".")
                            + (pyClass == null ? "" : pyClass + ".") + name.text();
                    Set<String> loc = new HashSet<>();
                    params(n.field("parameters"), loc);
                    int endLine = n.startRow() + 1 + JavaOutliner.countLines(n.text());
                    o.defs.add(new Outline.Def(o.defs.size(), name.text(), name.line(), endLine, n.start(), nesting,
                            display, addressable, owner, -1, pyClass, 0, false, null, loc, Map.of()));
                    locals.add(loc);
                    def = o.defs.size() - 1;
                    level = 2;
                    nesting++;
                }
                case "lambda" -> {
                    level = 2;
                }
                case "call" -> call(o, n, cls);
                case "assignment", "augmented_assignment" -> {
                    if (def >= 0) {
                        targets(n.field("left"), locals.get(def));
                    }
                }
                case "for_statement", "for_in_clause" -> {
                    if (def >= 0) {
                        targets(n.field("left"), locals.get(def));
                    }
                }
                case "as_pattern" -> {
                    if (def >= 0) {
                        targets(n.field("alias"), locals.get(def));
                    }
                }
                case "named_expression" -> {
                    if (def >= 0) {
                        targets(n.field("name"), locals.get(def));
                    }
                }
                default -> {
                    // nothing
                }
            }
            for (int i = n.childCount() - 1; i >= 0; i--) {
                SyntaxNode c = n.child(i);
                if (c.isNamed()) {
                    stack.push(new Frame(c, cls, level, def, nesting));
                }
            }
        }
        return o;
    }

    private static void params(SyntaxNode params, Set<String> out) {
        if (params == null) {
            return;
        }
        for (SyntaxNode p : params.namedChildren()) {
            switch (p.type()) {
                case "identifier" -> out.add(p.text());
                case "default_parameter", "typed_default_parameter" -> {
                    SyntaxNode name = p.field("name");
                    if (name != null) {
                        out.add(name.text());
                    }
                }
                case "typed_parameter", "list_splat_pattern", "dictionary_splat_pattern" -> {
                    SyntaxNode id = p.childOfType("identifier");
                    if (id != null) {
                        out.add(id.text());
                    }
                }
                default -> {
                    // separators
                }
            }
        }
    }

    /** Identifiers bound by an assignment target (not attributes or subscripts). */
    private static void targets(SyntaxNode t, Set<String> out) {
        if (t == null) {
            return;
        }
        ArrayDeque<SyntaxNode> st = new ArrayDeque<>();
        st.push(t);
        while (!st.isEmpty()) {
            SyntaxNode n = st.pop();
            switch (n.type()) {
                case "identifier" -> out.add(n.text());
                case "pattern_list", "tuple_pattern", "list_pattern", "expression_list", "tuple", "list",
                        "list_splat_pattern", "parenthesized_expression", "as_pattern_target" -> {
                    for (SyntaxNode c : n.namedChildren()) {
                        st.push(c);
                    }
                }
                default -> {
                    // attribute, subscript: not a name
                }
            }
        }
    }

    private static void call(Outline o, SyntaxNode n, String cls) {
        SyntaxNode fn = n.field("function");
        if (fn == null) {
            return;
        }
        List<String> parts = new ArrayList<>();
        SyntaxNode x = fn;
        while (x.is("attribute")) {
            SyntaxNode a = x.field("attribute");
            if (a == null || !a.is("identifier")) {
                return;
            }
            parts.add(0, a.text());
            x = x.field("object");
            if (x == null) {
                return;
            }
        }
        if (!x.is("identifier")) {
            return;
        }
        parts.add(0, x.text());
        String name = parts.get(parts.size() - 1);
        List<String> q = List.copyOf(parts.subList(0, parts.size() - 1));
        int line = fn.is("attribute") ? fn.field("attribute").line() : n.line();
        o.calls.add(new Outline.Call(name, q, line, n.start(), n.end(), 0, Texts.removeWhitespace(fn.text()), -1, -1,
                cls));
    }

    private static void bind(Outline o, String local, Outline.PyBinding b) {
        List<Outline.PyBinding> l = o.pyImports.computeIfAbsent(local, k -> new ArrayList<>(1));
        if (!l.contains(b)) {
            l.add(b);
        }
    }

    private static void importStatement(Outline o, SyntaxNode n) {
        for (int i = 0; i < n.childCount(); i++) {
            SyntaxNode c = n.child(i);
            if (c.is("dotted_name")) {
                String t = Texts.removeWhitespace(c.text());
                String first = t.contains(".") ? t.substring(0, t.indexOf('.')) : t;
                bind(o, first, new Outline.PyBinding(first, null));
            } else if (c.is("aliased_import")) {
                SyntaxNode name = c.field("name");
                SyntaxNode alias = c.field("alias");
                if (name != null && alias != null) {
                    bind(o, alias.text(), new Outline.PyBinding(Texts.removeWhitespace(name.text()), null));
                }
            }
        }
    }

    private static void importFrom(Outline o, SyntaxNode n) {
        SyntaxNode mod = n.field("module_name");
        if (mod == null) {
            return;
        }
        String base;
        if (mod.is("relative_import")) {
            int dots = 0;
            String rest = null;
            for (SyntaxNode c : mod.children()) {
                if (c.is("import_prefix")) {
                    dots = c.text().trim().length();
                } else if (c.is("dotted_name")) {
                    rest = Texts.removeWhitespace(c.text());
                }
            }
            List<String> pkg = new ArrayList<>(o.pyPackage.isEmpty() ? List.of() : List.of(o.pyPackage.split("\\.")));
            for (int k = 1; k < dots; k++) {
                if (pkg.isEmpty()) {
                    return; // beyond the top: not resolvable
                }
                pkg.remove(pkg.size() - 1);
            }
            String p = String.join(".", pkg);
            base = rest == null ? p : p.isEmpty() ? rest : p + "." + rest;
        } else {
            base = Texts.removeWhitespace(mod.text());
        }
        for (int i = 0; i < n.childCount(); i++) {
            SyntaxNode c = n.child(i);
            if (!"name".equals(c.field())) {
                continue;
            }
            if (c.is("dotted_name")) {
                String t = Texts.removeWhitespace(c.text());
                bind(o, Texts.lastSegment(t), new Outline.PyBinding(base, t));
            } else if (c.is("aliased_import")) {
                SyntaxNode name = c.field("name");
                SyntaxNode alias = c.field("alias");
                if (name != null && alias != null) {
                    bind(o, alias.text(), new Outline.PyBinding(base, Texts.removeWhitespace(name.text())));
                }
            }
        }
    }
}
