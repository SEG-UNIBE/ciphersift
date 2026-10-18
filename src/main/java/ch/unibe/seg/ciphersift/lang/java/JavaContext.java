/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang.java;

import ch.unibe.seg.ciphersift.syntax.SyntaxNode;
import ch.unibe.seg.ciphersift.util.Texts;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** The file context of a Java file (SPEC 7.3.1). Immutable once {@link #freeze() frozen}. */
final class JavaContext {
    /** One entry of {@code fields[name]}. */
    static final class FieldEntry {
        final String text;
        final boolean isFinal;
        private SyntaxNode node;
        private volatile JExpr expr;

        FieldEntry(SyntaxNode node, boolean isFinal) {
            this.node = node;
            this.text = node.text();
            this.isFinal = isFinal;
        }

        /** The initialiser as an expression form without positions (fallback lookups only). */
        JExpr expr() {
            JExpr e = expr;
            if (e == null) {
                e = JExpr.of(node, false);
                expr = e;
            }
            return e;
        }

        void freeze() {
            expr();
            node = null;
        }
    }

    final Path file;
    final String packageName;
    final Map<String, String> imports = new HashMap<>();
    final List<String> wildcards = new ArrayList<>();
    final Map<String, String> staticImports = new HashMap<>();
    final List<String> staticWildcards = new ArrayList<>();
    final Set<String> localClasses = new HashSet<>();
    final Map<String, List<FieldEntry>> fields = new HashMap<>();
    final Set<String> reassigned = new HashSet<>();
    /**
     * Supertypes named by the file's type declarations ({@code extends}, {@code implements}), as written (whitespace
     * and generic arguments removed), in walk order without duplicates (SPEC 7.3.1, t3 J-INH).
     */
    final List<String> supertypes = new ArrayList<>();
    /**
     * Constant getters (SPEC 7.4.1, DECISIONS B-J-JP1): method name → the returned expression, for a name
     * declared by exactly one method of the file, which has no parameters and whose body is {@code return e;}.
     */
    final Map<String, FieldEntry> getters = new HashMap<>();

    private JavaContext(Path file, String packageName) {
        this.file = file;
        this.packageName = packageName;
    }

    /** Converts all field initialisers and drops the syntax nodes (for the cross-file cache). */
    JavaContext freeze() {
        for (List<FieldEntry> l : fields.values()) {
            for (FieldEntry e : l) {
                e.freeze();
            }
        }
        for (FieldEntry e : getters.values()) {
            e.freeze();
        }
        return this;
    }

    private static final Set<String> CLASS_DECLS = Set.of("class_declaration", "interface_declaration",
            "enum_declaration", "record_declaration", "annotation_type_declaration");

    /** One iterative walk over the whole tree (SPEC 7.3.1). */
    static JavaContext build(Path file, SyntaxNode root) {
        String pkg = null;
        List<SyntaxNode> importNodes = new ArrayList<>();
        JavaContext ctx = null;
        List<SyntaxNode> fieldDecls = new ArrayList<>();
        Set<String> classes = new HashSet<>();
        Set<String> reassigned = new HashSet<>();
        java.util.LinkedHashSet<String> supers = new java.util.LinkedHashSet<>();
        Map<String, List<SyntaxNode>> methods = new HashMap<>();
        ArrayDeque<SyntaxNode> stack = new ArrayDeque<>();
        stack.push(root);
        while (!stack.isEmpty()) {
            SyntaxNode n = stack.pop();
            switch (n.type()) {
                case "package_declaration" -> {
                    if (pkg == null) {
                        SyntaxNode id = n.childOfType("scoped_identifier");
                        if (id == null) {
                            id = n.childOfType("identifier");
                        }
                        if (id != null) {
                            pkg = Texts.removeWhitespace(id.text());
                        }
                    }
                }
                case "import_declaration" -> importNodes.add(n);
                case "method_declaration" -> {
                    SyntaxNode name = n.field("name");
                    if (name != null) {
                        methods.computeIfAbsent(name.text(), k -> new ArrayList<>(1)).add(n);
                    }
                }
                case "field_declaration", "constant_declaration" -> fieldDecls.add(n);
                case "assignment_expression" -> {
                    SyntaxNode left = n.field("left");
                    if (left != null) {
                        if (left.is("identifier")) {
                            reassigned.add(left.text());
                        } else if (left.is("field_access")) {
                            SyntaxNode f = left.field("field");
                            if (f != null) {
                                reassigned.add(f.text());
                            }
                        }
                    }
                }
                default -> {
                    if (CLASS_DECLS.contains(n.type())) {
                        SyntaxNode name = n.field("name");
                        if (name != null) {
                            classes.add(name.text());
                        }
                        collectSupertypes(n, supers);
                    }
                }
            }
            for (int i = n.childCount() - 1; i >= 0; i--) {
                SyntaxNode c = n.child(i);
                if (c.isNamed()) {
                    stack.push(c);
                }
            }
        }
        ctx = new JavaContext(file, pkg == null ? "" : pkg);
        for (SyntaxNode imp : importNodes) {
            SyntaxNode id = imp.childOfType("scoped_identifier");
            if (id == null) {
                id = imp.childOfType("identifier");
            }
            if (id == null) {
                continue;
            }
            String name = Texts.removeWhitespace(id.text());
            boolean isStatic = imp.hasChildOfType("static");
            boolean wildcard = imp.hasChildOfType("asterisk");
            if (isStatic) {
                if (wildcard) {
                    ctx.staticWildcards.add(name);
                } else {
                    int dot = name.lastIndexOf('.');
                    if (dot > 0) {
                        ctx.staticImports.put(name.substring(dot + 1), name.substring(0, dot));
                    }
                }
            } else if (wildcard) {
                ctx.wildcards.add(name);
            } else {
                ctx.imports.put(Texts.lastSegment(name), name);
            }
        }
        for (SyntaxNode decl : fieldDecls) {
            boolean fin = decl.is("constant_declaration")
                    || (decl.parent() != null && decl.parent().is("interface_body"));
            if (!fin) {
                SyntaxNode mods = decl.childOfType("modifiers");
                fin = mods != null && Texts.containsWord(mods.text(), "final");
            }
            for (int i = 0; i < decl.childCount(); i++) {
                SyntaxNode vd = decl.child(i);
                if (!vd.is("variable_declarator")) {
                    continue;
                }
                SyntaxNode name = vd.field("name");
                SyntaxNode value = vd.field("value");
                if (name == null || value == null) {
                    continue;
                }
                ctx.fields.computeIfAbsent(name.text(), k -> new ArrayList<>(1)).add(new FieldEntry(value, fin));
            }
        }
        for (Map.Entry<String, List<SyntaxNode>> e : methods.entrySet()) {
            if (e.getValue().size() == 1) {
                SyntaxNode ret = constantReturn(e.getValue().get(0));
                if (ret != null) {
                    ctx.getters.put(e.getKey(), new FieldEntry(ret, true));
                }
            }
        }
        ctx.localClasses.addAll(classes);
        ctx.reassigned.addAll(reassigned);
        ctx.supertypes.addAll(supers);
        return ctx;
    }

    /** The types of the {@code superclass}, {@code super_interfaces} and {@code extends_interfaces} children of a type declaration. */
    private static void collectSupertypes(SyntaxNode decl, Set<String> out) {
        for (SyntaxNode c : decl.namedChildren()) {
            if (!c.is("superclass") && !c.is("super_interfaces") && !c.is("extends_interfaces")) {
                continue;
            }
            for (SyntaxNode t : c.namedChildren()) {
                List<SyntaxNode> types = t.is("type_list") ? t.namedChildren() : List.of(t);
                for (SyntaxNode x : types) {
                    if (x.is("type_identifier") || x.is("scoped_type_identifier") || x.is("generic_type")) {
                        String name = JavaAnalyzer.removeGenerics(Texts.removeWhitespace(x.text()));
                        if (!name.isEmpty()) {
                            out.add(name);
                        }
                    }
                }
            }
        }
    }

    /** The {@code e} of a method {@code m() { return e; }} without parameters, else null (DECISIONS B-J-JP1). */
    private static SyntaxNode constantReturn(SyntaxNode m) {
        SyntaxNode params = m.field("parameters");
        SyntaxNode body = m.field("body");
        if (params == null || body == null || !params.namedChildren().stream().allMatch(JExpr::isComment)) {
            return null;
        }
        SyntaxNode stmt = null;
        for (SyntaxNode c : body.namedChildren()) {
            if (JExpr.isComment(c)) {
                continue;
            }
            if (stmt != null) {
                return null;
            }
            stmt = c;
        }
        if (stmt == null || !stmt.is("return_statement")) {
            return null;
        }
        SyntaxNode e = null;
        for (SyntaxNode c : stmt.namedChildren()) {
            if (!JExpr.isComment(c)) {
                e = c;
            }
        }
        return e;
    }
}
