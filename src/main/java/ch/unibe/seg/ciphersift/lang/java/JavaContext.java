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
        ctx.localClasses.addAll(classes);
        ctx.reassigned.addAll(reassigned);
        return ctx;
    }
}
