/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.wrappers;

import ch.unibe.seg.ciphersift.syntax.SyntaxNode;
import ch.unibe.seg.ciphersift.util.Texts;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Java definitions and call sites (SPEC 18.2, 18.3). */
final class JavaOutliner {
    private static final Set<String> CLASS_LIKE = Set.of("class_declaration", "interface_declaration",
            "enum_declaration", "record_declaration", "annotation_type_declaration");
    /** Nodes whose children are code, not member declarations. */
    private static final Set<String> CODE = Set.of("method_declaration", "constructor_declaration",
            "compact_constructor_declaration", "lambda_expression", "static_initializer", "block");

    private JavaOutliner() {}

    private record Frame(SyntaxNode node, int cls, boolean inCode, int nesting) {}

    static Outline outline(SyntaxNode root, String path, boolean test) {
        return outline(root, path, test, false);
    }

    /**
     * @param constructors constructors are definitions (named like their class) and {@code new C(…)} without a class
     *        body is a call of them (t3 J-CTOR)
     */
    static Outline outline(SyntaxNode root, String path, boolean test, boolean constructors) {
        Outline o = new Outline(Outline.Lang.JAVA, path, test);
        ArrayDeque<Frame> stack = new ArrayDeque<>();
        stack.push(new Frame(root, -1, false, 0));
        while (!stack.isEmpty()) {
            Frame f = stack.pop();
            SyntaxNode n = f.node();
            int cls = f.cls();
            boolean inCode = f.inCode();
            int nesting = f.nesting();
            switch (n.type()) {
                case "package_declaration" -> {
                    for (SyntaxNode c : n.namedChildren()) {
                        if (c.is("scoped_identifier") || c.is("identifier")) {
                            o.javaPackage = Texts.removeWhitespace(c.text());
                        }
                    }
                    continue;
                }
                case "import_declaration" -> {
                    importDecl(o, n);
                    continue;
                }
                case "method_invocation" -> call(o, n, cls);
                case "object_creation_expression" -> {
                    SyntaxNode body = n.childOfType("class_body");
                    if (body != null) {
                        o.javaClasses.add(new Outline.JavaClass("", null, cls, false));
                        int anon = o.javaClasses.size() - 1;
                        for (int i = n.childCount() - 1; i >= 0; i--) {
                            SyntaxNode c = n.child(i);
                            if (c.isNamed()) {
                                stack.push(c == body ? new Frame(c, anon, false, nesting + 1)
                                        : new Frame(c, cls, inCode, nesting));
                            }
                        }
                        continue;
                    }
                    if (constructors) {
                        newCall(o, n, cls);
                    }
                }
                default -> {
                    // below
                }
            }
            if (CLASS_LIKE.contains(n.type())) {
                SyntaxNode name = n.field("name");
                boolean addressable = !inCode && (cls < 0 || o.javaClasses.get(cls).addressable());
                String simple = name == null ? "" : name.text();
                String fqn = null;
                if (addressable) {
                    String outer = cls < 0 ? o.javaPackage : o.javaClasses.get(cls).fqn();
                    fqn = outer.isEmpty() ? simple : outer + "." + simple;
                }
                o.javaClasses.add(new Outline.JavaClass(simple, fqn, cls, addressable));
                cls = o.javaClasses.size() - 1;
                inCode = false;
                nesting++;
            } else if (n.is("method_declaration") || (constructors && n.is("constructor_declaration") && cls >= 0)) {
                method(o, n, cls, nesting);
                inCode = true;
                nesting++;
            } else if (CODE.contains(n.type())) {
                inCode = true;
                if (!n.is("block")) {
                    nesting++;
                }
            }
            for (int i = n.childCount() - 1; i >= 0; i--) {
                SyntaxNode c = n.child(i);
                if (c.isNamed()) {
                    stack.push(new Frame(c, cls, inCode, nesting));
                }
            }
        }
        return o;
    }

    private static void importDecl(Outline o, SyntaxNode n) {
        boolean isStatic = false;
        boolean star = false;
        String name = null;
        for (int i = 0; i < n.childCount(); i++) {
            SyntaxNode c = n.child(i);
            switch (c.type()) {
                case "static" -> isStatic = true;
                case "asterisk" -> star = true;
                case "scoped_identifier", "identifier" -> name = Texts.removeWhitespace(c.text());
                default -> {
                    // keywords, punctuation, comments
                }
            }
        }
        if (name == null) {
            return;
        }
        int dot = name.lastIndexOf('.');
        if (isStatic) {
            if (star) {
                o.javaStaticOnDemand.add(name);
            } else if (dot > 0) {
                o.javaStaticImports.putIfAbsent(name.substring(dot + 1), name.substring(0, dot));
            }
        } else if (star) {
            o.javaOnDemand.add(name);
        } else {
            o.javaImports.putIfAbsent(dot < 0 ? name : name.substring(dot + 1), name);
        }
    }

    private static void method(Outline o, SyntaxNode n, int cls, int nesting) {
        SyntaxNode name = n.field("name");
        if (name == null) {
            return;
        }
        int arity = 0;
        boolean varargs = false;
        SyntaxNode params = n.field("parameters");
        if (params != null) {
            for (SyntaxNode p : params.namedChildren()) {
                if (p.is("formal_parameter")) {
                    arity++;
                } else if (p.is("spread_parameter")) {
                    arity++;
                    varargs = true;
                }
            }
        }
        boolean addressable = cls >= 0 && o.javaClasses.get(cls).addressable();
        StringBuilder display = new StringBuilder();
        for (int k = cls; k >= 0; k = o.javaClasses.get(k).parent()) {
            String s = o.javaClasses.get(k).simpleName();
            display.insert(0, (s.isEmpty() ? "<anonymous>" : s) + ".");
        }
        display.append(name.text());
        int endLine = n.startRow() + 1 + countLines(n.text());
        o.defs.add(new Outline.Def(o.defs.size(), name.text(), name.line(), endLine, n.start(), nesting,
                display.toString(), addressable, o.path + "#" + cls, cls, null, arity, varargs, null,
                new HashSet<>(), Map.of()));
    }

    /**
     * {@code new T(…)} as a call of the constructors of T (t3 J-CTOR): name = the last segment of T, qualifier = T
     * (generic arguments removed), so that 18.4 Java step 2 resolves the class and step 3 its constructors.
     */
    private static void newCall(Outline o, SyntaxNode n, int cls) {
        SyntaxNode type = n.field("type");
        if (type == null) {
            return;
        }
        String t = removeGenerics(Texts.removeWhitespace(type.text()));
        if (t.isEmpty() || t.indexOf('<') >= 0) {
            return;
        }
        String name = Texts.lastSegment(t);
        if (name.isEmpty() || !Character.isUpperCase(name.charAt(0))) {
            return;
        }
        int arity = 0;
        SyntaxNode args = n.field("arguments");
        if (args != null) {
            for (SyntaxNode a : args.namedChildren()) {
                if (!a.is("line_comment") && !a.is("block_comment")) {
                    arity++;
                }
            }
        }
        o.calls.add(new Outline.Call(name, List.of(t), type.line(), n.start(), n.end(), arity, "new " + t, -1, cls,
                null));
    }

    private static String removeGenerics(String s) {
        String prev;
        do {
            prev = s;
            s = s.replaceAll("<[^<>]*>", "");
        } while (!s.equals(prev));
        return s;
    }

    /** Number of line feeds in a node's text (its last row minus its start row). */
    static int countLines(String text) {
        int k = 0;
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) == '\n') {
                k++;
            }
        }
        return k;
    }

    private static void call(Outline o, SyntaxNode n, int cls) {
        SyntaxNode name = n.field("name");
        if (name == null) {
            return;
        }
        SyntaxNode obj = n.field("object");
        List<String> q;
        String symbol;
        if (obj == null) {
            q = List.of();
            symbol = name.text();
        } else if (obj.is("this")) {
            q = List.of("this");
            symbol = "this." + name.text();
        } else if (obj.is("identifier") || obj.is("field_access") || obj.is("scoped_identifier")) {
            String t = Texts.removeWhitespace(obj.text());
            q = List.of(t);
            symbol = t + "." + name.text();
        } else {
            return;
        }
        int arity = 0;
        SyntaxNode args = n.field("arguments");
        if (args != null) {
            for (SyntaxNode a : args.namedChildren()) {
                if (!a.is("line_comment") && !a.is("block_comment")) {
                    arity++;
                }
            }
        }
        o.calls.add(new Outline.Call(name.text(), q, name.line(), n.start(), n.end(), arity, symbol, -1, cls, null));
    }
}
