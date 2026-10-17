/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.wrappers;

import ch.unibe.seg.ciphersift.lang.go.GoAnalyzer;
import ch.unibe.seg.ciphersift.syntax.SyntaxNode;
import ch.unibe.seg.ciphersift.util.Texts;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Go definitions, call sites, imports and declared types (SPEC 18.2–18.4). */
final class GoOutliner {
    /** Marks a name with two different declared types. */
    static final Outline.TypeRef CONFLICT = new Outline.TypeRef("", "");

    private GoOutliner() {}

    private record Frame(SyntaxNode node, int def, int nesting) {}

    static String dirOf(String path) {
        int s = path.lastIndexOf('/');
        return s < 0 ? "" : path.substring(0, s);
    }

    static Outline outline(SyntaxNode root, String path, boolean test) {
        Outline o = new Outline(Outline.Lang.GO, path, test);
        o.goDir = dirOf(path);
        List<Set<String>> locals = new ArrayList<>();
        List<Map<String, Outline.TypeRef>> types = new ArrayList<>();
        ArrayDeque<Frame> stack = new ArrayDeque<>();
        stack.push(new Frame(root, -1, 0));
        while (!stack.isEmpty()) {
            Frame f = stack.pop();
            SyntaxNode n = f.node();
            int def = f.def();
            int nesting = f.nesting();
            switch (n.type()) {
                case "package_clause" -> {
                    SyntaxNode id = n.childOfType("package_identifier");
                    if (id != null) {
                        o.goPackage = id.text();
                    }
                    continue;
                }
                case "import_spec" -> {
                    importSpec(o, n);
                    continue;
                }
                case "type_spec" -> struct(o, n);
                case "function_declaration", "method_declaration" -> {
                    SyntaxNode name = n.field("name");
                    if (name != null) {
                        Set<String> loc = new HashSet<>();
                        Map<String, Outline.TypeRef> ty = new HashMap<>();
                        String recv = null;
                        if (n.is("method_declaration")) {
                            SyntaxNode r = n.field("receiver");
                            if (r != null) {
                                for (SyntaxNode pd : r.namedChildren()) {
                                    if (pd.is("parameter_declaration")) {
                                        Outline.TypeRef t = typeRef(pd.field("type"));
                                        recv = t == null || t.pkg() != null ? null : t.name();
                                        for (SyntaxNode id : pd.fields("name")) {
                                            loc.add(id.text());
                                            if (recv != null) {
                                                declare(ty, id.text(), new Outline.TypeRef(null, recv));
                                            }
                                        }
                                    }
                                }
                            }
                            if (recv == null) {
                                break; // a receiver of a type that cannot be named: not a definition
                            }
                        }
                        params(n.field("parameters"), loc, ty);
                        params(n.field("result"), loc, ty);
                        String display = (o.goPackage.isEmpty() ? "" : o.goPackage + ".")
                                + (recv == null ? "" : recv + ".") + name.text();
                        String owner = o.goDir + "|" + o.goPackage + "|" + (recv == null ? "" : recv);
                        int endLine = n.startRow() + 1 + JavaOutliner.countLines(n.text());
                        o.defs.add(new Outline.Def(o.defs.size(), name.text(), name.line(), endLine, n.start(),
                                nesting, display, true, owner, -1, null, 0, false, recv, loc, ty));
                        locals.add(loc);
                        types.add(ty);
                        def = o.defs.size() - 1;
                        nesting++;
                    }
                }
                case "func_literal" -> {
                    if (def >= 0) {
                        params(n.field("parameters"), locals.get(def), types.get(def));
                    }
                }
                case "short_var_declaration" -> {
                    if (def >= 0) {
                        List<SyntaxNode> left = expressions(n.field("left"));
                        List<SyntaxNode> right = expressions(n.field("right"));
                        for (int i = 0; i < left.size(); i++) {
                            SyntaxNode id = left.get(i);
                            if (id.is("identifier")) {
                                locals.get(def).add(id.text());
                                declare(types.get(def), id.text(),
                                        left.size() == right.size() ? valueType(right.get(i)) : null);
                            }
                        }
                    }
                }
                case "var_spec" -> {
                    if (def >= 0) {
                        Outline.TypeRef declared = typeRef(n.field("type"));
                        SyntaxNode values = n.field("value");
                        List<SyntaxNode> vals = values == null ? List.of() : expressions(values);
                        List<SyntaxNode> names = n.fields("name");
                        for (int i = 0; i < names.size(); i++) {
                            SyntaxNode id = names.get(i);
                            locals.get(def).add(id.text());
                            Outline.TypeRef t = declared != null ? declared
                                    : vals.size() == names.size() ? valueType(vals.get(i)) : null;
                            declare(types.get(def), id.text(), t);
                        }
                    }
                }
                case "range_clause" -> {
                    if (def >= 0) {
                        for (SyntaxNode id : expressions(n.field("left"))) {
                            if (id.is("identifier")) {
                                locals.get(def).add(id.text());
                                declare(types.get(def), id.text(), null);
                            }
                        }
                    }
                }
                case "call_expression" -> call(o, n);
                default -> {
                    // nothing
                }
            }
            for (int i = n.childCount() - 1; i >= 0; i--) {
                SyntaxNode c = n.child(i);
                if (c.isNamed()) {
                    stack.push(new Frame(c, def, nesting));
                }
            }
        }
        return o;
    }

    /** Records a declared type; a second, different one (or an untyped declaration) makes it a conflict. */
    private static void declare(Map<String, Outline.TypeRef> ty, String name, Outline.TypeRef t) {
        Outline.TypeRef v = t == null ? CONFLICT : t;
        Outline.TypeRef old = ty.putIfAbsent(name, v);
        if (old != null && !old.equals(v)) {
            ty.put(name, CONFLICT);
        }
    }

    private static void params(SyntaxNode pl, Set<String> loc, Map<String, Outline.TypeRef> ty) {
        if (pl == null || !pl.is("parameter_list")) {
            return;
        }
        for (SyntaxNode pd : pl.namedChildren()) {
            if (pd.is("parameter_declaration") || pd.is("variadic_parameter_declaration")) {
                Outline.TypeRef t = pd.is("parameter_declaration") ? typeRef(pd.field("type")) : null;
                for (SyntaxNode id : pd.fields("name")) {
                    loc.add(id.text());
                    declare(ty, id.text(), t);
                }
            }
        }
    }

    private static List<SyntaxNode> expressions(SyntaxNode n) {
        if (n == null) {
            return List.of();
        }
        if (n.is("expression_list")) {
            List<SyntaxNode> out = new ArrayList<>();
            for (SyntaxNode c : n.namedChildren()) {
                if (!c.is("comment")) {
                    out.add(c);
                }
            }
            return out;
        }
        return List.of(n);
    }

    /** A named type: {@code T}, {@code *T}, {@code p.T}, {@code T[X]}; else null. */
    static Outline.TypeRef typeRef(SyntaxNode t) {
        while (t != null) {
            switch (t.type()) {
                case "pointer_type", "parenthesized_type" -> t = t.firstNamedChild();
                case "generic_type" -> t = t.field("type");
                case "type_identifier" -> {
                    return new Outline.TypeRef(null, t.text());
                }
                case "qualified_type" -> {
                    SyntaxNode p = t.field("package");
                    SyntaxNode nm = t.field("name");
                    return p == null || nm == null ? null : new Outline.TypeRef(p.text(), nm.text());
                }
                default -> {
                    return null;
                }
            }
        }
        return null;
    }

    /** The type of {@code T{…}}, {@code &T{…}}, {@code new(T)}; else null (SPEC 18.4). */
    private static Outline.TypeRef valueType(SyntaxNode e) {
        if (e == null) {
            return null;
        }
        if (e.is("unary_expression")) {
            SyntaxNode op = e.field("operator");
            SyntaxNode x = e.field("operand");
            if (op != null && op.text().equals("&") && x != null && x.is("composite_literal")) {
                return typeRef(x.field("type"));
            }
            return null;
        }
        if (e.is("composite_literal")) {
            return typeRef(e.field("type"));
        }
        if (e.is("call_expression")) {
            SyntaxNode fn = e.field("function");
            SyntaxNode args = e.field("arguments");
            if (fn != null && fn.is("identifier") && fn.text().equals("new") && args != null) {
                List<SyntaxNode> a = args.namedChildren();
                if (a.size() == 1) {
                    SyntaxNode t = a.get(0);
                    if (t.is("selector_expression")) {
                        SyntaxNode op = t.field("operand");
                        SyntaxNode fld = t.field("field");
                        return op != null && op.is("identifier") && fld != null
                                ? new Outline.TypeRef(op.text(), fld.text()) : null;
                    }
                    if (t.is("identifier")) {
                        return new Outline.TypeRef(null, t.text());
                    }
                    return typeRef(t);
                }
            }
        }
        return null;
    }

    private static void importSpec(Outline o, SyntaxNode n) {
        SyntaxNode p = n.field("path");
        if (p == null || p.text().length() < 2) {
            return;
        }
        String t = p.text();
        String path = t.substring(1, t.length() - 1);
        if (path.isEmpty()) {
            return;
        }
        SyntaxNode name = n.field("name");
        if (name == null) {
            o.goImports.put(GoAnalyzer.defaultLocalName(path), path);
        } else if (name.is("package_identifier")) {
            o.goImports.put(name.text(), path);
        }
    }

    private static void struct(Outline o, SyntaxNode n) {
        SyntaxNode name = n.field("name");
        SyntaxNode t = n.field("type");
        if (name == null || t == null || !t.is("struct_type")) {
            return;
        }
        Map<String, Outline.TypeRef> fields = new HashMap<>();
        SyntaxNode list = t.childOfType("field_declaration_list");
        if (list != null) {
            for (SyntaxNode fd : list.namedChildren()) {
                if (fd.is("field_declaration")) {
                    Outline.TypeRef ft = typeRef(fd.field("type"));
                    for (SyntaxNode id : fd.fields("name")) {
                        fields.put(id.text(), ft == null ? CONFLICT : ft);
                    }
                }
            }
        }
        o.goStructs.put(name.text(), fields);
    }

    private static void call(Outline o, SyntaxNode n) {
        SyntaxNode fn = n.field("function");
        if (fn == null) {
            return;
        }
        if (fn.is("identifier")) {
            o.calls.add(new Outline.Call(fn.text(), List.of(), n.line(), n.start(), n.end(), 0, fn.text(), -1, -1, null));
            return;
        }
        if (!fn.is("selector_expression")) {
            return;
        }
        SyntaxNode field = fn.field("field");
        SyntaxNode op = fn.field("operand");
        if (field == null || op == null) {
            return;
        }
        List<String> q;
        if (op.is("identifier")) {
            q = List.of(op.text());
        } else if (op.is("selector_expression")) {
            SyntaxNode x = op.field("operand");
            SyntaxNode f2 = op.field("field");
            if (x == null || f2 == null || !x.is("identifier")) {
                return;
            }
            q = List.of(x.text(), f2.text());
        } else {
            return;
        }
        o.calls.add(new Outline.Call(field.text(), q, field.line(), n.start(), n.end(), 0,
                Texts.removeWhitespace(fn.text()), -1, -1, null));
    }
}
