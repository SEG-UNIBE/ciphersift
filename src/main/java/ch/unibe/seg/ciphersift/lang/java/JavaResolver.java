/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang.java;

import ch.unibe.seg.ciphersift.rules.RuleSet;
import ch.unibe.seg.ciphersift.syntax.SyntaxNode;
import ch.unibe.seg.ciphersift.util.Texts;
import ch.unibe.seg.ciphersift.files.FileNames;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/** Constant resolution (SPEC 7.4): {@code value}, lookups, string lists and constant bytes. */
final class JavaResolver {
    static final int MAX_DEPTH = 12;
    /** Calls that return their receiver's value (SPEC 7.4.1); {@code getId}: DECISIONS B-J-JP2. */
    private static final Set<String> VALUE_METHODS = Set.of("getName", "toString", "name", "trim", "intern", "getId");
    private static final Set<String> DECODERS = Set.of("getBytes", "toCharArray", "decode", "decodeHex",
            "decodeBase64", "parseHexBinary", "parseBase64Binary", "fromHexString", "hexStringToByteArray",
            "hexToBytes", "fromHex");
    /** Decoders whose data is their receiver; an argument is a charset (t3 J-GB, SPEC 7.4.7). */
    private static final Set<String> RECEIVER_DECODERS = Set.of("getBytes", "toCharArray");

    /**
     * A lookup result: an initialiser in its context, or a constants-table string; or, for a local assigned
     * different values after its declaration (DECISIONS B-J-JP3), those values as {@code alternatives} (then
     * the value is unresolved).
     */
    record Resolution(JExpr expr, JavaContext ctx, String constant, List<JExpr> alternatives) {
        static Resolution of(JExpr e, JavaContext c) {
            return new Resolution(e, c, null, null);
        }

        static Resolution constant(String s) {
            return new Resolution(null, null, s, null);
        }
    }

    private final RuleSet rules;
    private final JavaContexts contexts;
    /** DECISIONS B-J-JP1 / B-J-JP5 and B-J-JP3. */
    private final boolean getters;
    private final boolean deferred;
    /**
     * Start offsets of the deferred locals being resolved (DECISIONS B-J-JP3): a value that needs the local itself
     * (s = s + "x", or a = b; b = a) is unresolved instead of recursing without bound.
     */
    private final java.util.Set<Integer> resolvingDeferred = new java.util.HashSet<>();

    /** t3 J-INH: constants inherited from project supertypes; J-XMOD: classes in other source roots. */
    private final boolean inherited;
    private final boolean crossModule;
    /** Supertype levels followed for an inherited constant (t3 J-INH). */
    static final int MAX_SUPER = 4;

    JavaResolver(RuleSet rules, JavaContexts contexts) {
        this(rules, contexts, true, true, true, true);
    }

    JavaResolver(RuleSet rules, JavaContexts contexts, boolean getters, boolean deferred, boolean inherited,
            boolean crossModule) {
        this.rules = rules;
        this.contexts = contexts;
        this.getters = getters;
        this.deferred = deferred;
        this.inherited = inherited;
        this.crossModule = crossModule;
    }

    // ------------------------------------------------------------------ value (7.4.1)

    String value(JExpr e, JavaContext ctx, int d) {
        if (d > MAX_DEPTH || e == null) {
            return null;
        }
        switch (e) {
            case JExpr.Str s -> {
                return s.value();
            }
            case JExpr.Lit l -> {
                return l.value();
            }
            case JExpr.Paren p -> {
                return value(p.first(), ctx, d + 1);
            }
            case JExpr.Binary b -> {
                if (!b.plus()) {
                    return null;
                }
                String l = value(b.left(), ctx, d + 1);
                if (l == null) {
                    return null;
                }
                String r = value(b.right(), ctx, d + 1);
                return r == null ? null : l + r;
            }
            case JExpr.Call c -> {
                if (c.object() != null && VALUE_METHODS.contains(c.name())) {
                    return value(c.object(), ctx, d + 1);
                }
                if (!getters) {
                    return null;
                }
                if (c.object() == null && c.firstArgument() == null) {
                    // the file's only declaration of the name returns a constant expression (DECISIONS B-J-JP1)
                    JavaContext.FieldEntry g = ctx.getters.get(c.name());
                    return g == null ? null : value(g.expr(), ctx, d + 1);
                }
                if (c.object() != null && c.firstArgument() == null && c.name().equals("getAlgorithm")) {
                    // key.getAlgorithm() of a key built as new SecretKeySpec(…, alg) (DECISIONS B-J-JP5)
                    JExpr o = c.object();
                    JavaContext oc = ctx;
                    if (o instanceof JExpr.Ident id) {
                        Resolution r = lookupIdentifier(id, ctx);
                        o = r == null ? null : r.expr();
                        oc = r == null ? null : r.ctx();
                    }
                    if (o instanceof JExpr.New n && Texts.lastSegment(n.type()).equals("SecretKeySpec")) {
                        return value(n.lastArgument(), oc, d + 1);
                    }
                }
                return null;
            }
            case JExpr.Ident id -> {
                return valueOf(lookupIdentifier(id, ctx), d);
            }
            case JExpr.FieldRef f -> {
                return valueOf(lookupField(f, ctx), d);
            }
            default -> {
                return null;
            }
        }
    }

    private String valueOf(Resolution r, int d) {
        if (r == null || r.alternatives() != null) {
            return null;
        }
        if (r.constant() != null) {
            return r.constant();
        }
        return value(r.expr(), r.ctx(), d + 1);
    }

    // ------------------------------------------------------------------ lookups (7.4.3, 7.4.4)

    Resolution lookupIdentifier(JExpr.Ident id, JavaContext ctx) {
        String name = id.name();
        SyntaxNode x = id.position();
        if (x != null) {
            SyntaxNode c = x;
            SyntaxNode p = x.parent();
            while (p != null) {
                switch (p.type()) {
                    case "block", "switch_block_statement_group", "constructor_body" -> {
                        LocalDeclaration last = lastDeclarationBefore(p, name, c.start());
                        SyntaxNode found = last == null ? null : last.declarator();
                        SyntaxNode foundDecl = last == null ? null : last.declaration();
                        if (found != null) {
                            SyntaxNode init = found.field("value");
                            if (init == null) {
                                return deferred ? deferredLocal(p, foundDecl, name, ctx) : null;
                            }
                            SyntaxNode mods = foundDecl.childOfType("modifiers");
                            boolean fin = mods != null && Texts.containsWord(mods.text(), "final");
                            if (!fin && ctx.reassigned.contains(name)) {
                                return null;
                            }
                            return Resolution.of(JExpr.of(init, true), ctx);
                        }
                    }
                    case "method_declaration", "constructor_declaration", "lambda_expression" -> {
                        SyntaxNode params = p.field("parameters");
                        if (params != null && Texts.containsWord(params.text(), name)) {
                            return null;
                        }
                    }
                    case "enhanced_for_statement" -> {
                        SyntaxNode n = p.field("name");
                        if (n != null && n.text().equals(name)) {
                            return null;
                        }
                    }
                    default -> {
                        // continue upwards
                    }
                }
                c = p;
                p = p.parent();
            }
        }
        Resolution r = fieldLookup(name, ctx);
        if (r != null) {
            return r;
        }
        String cls = ctx.staticImports.get(name);
        if (cls != null) {
            return staticField(cls, name, ctx);
        }
        for (String w : ctx.staticWildcards) {
            r = staticField(w, name, ctx);
            if (r != null) {
                return r;
            }
        }
        return inherited ? inheritedField(name, ctx, 1, new java.util.HashSet<>()) : null;
    }

    /**
     * A constant inherited from a supertype of the file's type declarations (t3 J-INH, SPEC 7.4.3 step 4): for each
     * supertype in order that is not a class of the file, its declaring file (7.4.5) and its field {@code name}, else,
     * recursively, that file's supertypes (at most {@link #MAX_SUPER} levels; each file once).
     */
    private Resolution inheritedField(String name, JavaContext ctx, int depth, java.util.Set<Path> seen) {
        if (depth > MAX_SUPER || contexts == null) {
            return null;
        }
        for (String s : ctx.supertypes) {
            int dot = s.indexOf('.');
            String g = dot < 0 ? s : s.substring(0, dot);
            if (ctx.localClasses.contains(g) || g.isEmpty() || !Character.isUpperCase(g.charAt(0)) && dot < 0) {
                continue;
            }
            for (String cls : classCandidates(s, ctx)) {
                JavaContext decl = locate(cls, ctx);
                if (decl == null) {
                    continue;
                }
                if (decl != ctx && seen.add(decl.file)) {
                    Resolution r = fieldLookup(name, decl);
                    if (r == null) {
                        r = inheritedField(name, decl, depth + 1, seen);
                    }
                    if (r != null) {
                        return r;
                    }
                }
                break;
            }
        }
        return null;
    }

    /** Fully qualified candidates for a type name as written in {@code ctx} (as for 7.4.4 step 3). */
    private static List<String> classCandidates(String q, JavaContext ctx) {
        int dot = q.indexOf('.');
        String g = dot < 0 ? q : q.substring(0, dot);
        String imported = ctx.imports.get(g);
        if (imported != null) {
            return List.of(imported + (dot < 0 ? "" : q.substring(dot)));
        }
        if (dot >= 0 && !Character.isUpperCase(g.charAt(0))) {
            return List.of(q);
        }
        List<String> out = new ArrayList<>();
        if (!ctx.packageName.isEmpty()) {
            out.add(ctx.packageName + "." + q);
        }
        for (String w : ctx.wildcards) {
            out.add(w + "." + q);
        }
        if (ctx.packageName.isEmpty()) {
            out.add(q);
        }
        return out;
    }

    /**
     * A local declared without initialiser (SPEC 7.4.3, DECISIONS B-J-JP3): the right-hand sides of the plain
     * assignments {@code name = v} to it in its block after the declaration; null if there is none, if the name is
     * also the target of a compound assignment, increment or decrement there, or if a value is unresolved (also
     * one that needs the local itself). All values equal: that value; else the alternatives.
     */
    private Resolution deferredLocal(SyntaxNode block, SyntaxNode decl, String name, JavaContext ctx) {
        if (!resolvingDeferred.add(decl.start())) {
            return null;
        }
        try {
            return deferredLocal0(block, decl, name, ctx);
        } finally {
            resolvingDeferred.remove(decl.start());
        }
    }

    private Resolution deferredLocal0(SyntaxNode block, SyntaxNode decl, String name, JavaContext ctx) {
        List<JExpr> values = new ArrayList<>();
        java.util.ArrayDeque<SyntaxNode> stack = new java.util.ArrayDeque<>();
        stack.push(block);
        while (!stack.isEmpty()) {
            SyntaxNode n = stack.pop();
            if (n.is("assignment_expression") && n.start() >= decl.end()) {
                SyntaxNode left = n.field("left");
                SyntaxNode op = n.field("operator");
                if (left != null && left.is("identifier") && left.text().equals(name)) {
                    if (op == null || !op.text().equals("=")) {
                        return null;
                    }
                    values.add(JExpr.of(n.field("right"), true));
                }
            } else if (n.is("update_expression")) {
                for (SyntaxNode c : n.namedChildren()) {
                    if (c.is("identifier") && c.text().equals(name)) {
                        return null;
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
        if (values.isEmpty()) {
            return null;
        }
        String first = null;
        boolean same = true;
        for (JExpr v : values) {
            String s = value(v, ctx, 1);
            if (s == null) {
                return null;
            }
            if (first == null) {
                first = s;
            } else if (!first.equals(s)) {
                same = false;
            }
        }
        return same ? Resolution.of(values.get(0), ctx) : new Resolution(null, ctx, null, List.copyOf(values));
    }

    /** The values of a deferred local with different assignments (DECISIONS B-J-JP3), or null. */
    List<String> alternatives(JExpr.Ident id, JavaContext ctx) {
        Resolution r = lookupIdentifier(id, ctx);
        if (r == null || r.alternatives() == null) {
            return null;
        }
        List<String> out = new ArrayList<>();
        for (JExpr e : r.alternatives()) {
            String s = value(e, r.ctx(), 1);
            if (s == null) {
                return null;
            }
            if (!out.contains(s)) {
                out.add(s);
            }
        }
        return out;
    }

    /** A {@code variable_declarator} of a {@code local_variable_declaration} that is a child of a block. */
    private record LocalDeclaration(int start, SyntaxNode declaration, SyntaxNode declarator) {}

    /** Per block: local declarations by name, in child order (built once per block and file). */
    private final java.util.IdentityHashMap<SyntaxNode, java.util.Map<String, List<LocalDeclaration>>> blockIndex =
            new java.util.IdentityHashMap<>();

    /**
     * The last {@code variable_declarator} named {@code name} among the {@code local_variable_declaration}
     * children of {@code block} that start before {@code before} (SPEC 7.4.3), or null. Indexed per
     * block, so that a block with many statements is not rescanned for every lookup.
     */
    private LocalDeclaration lastDeclarationBefore(SyntaxNode block, String name, int before) {
        java.util.Map<String, List<LocalDeclaration>> index = blockIndex.get(block);
        if (index == null) {
            index = new java.util.HashMap<>();
            for (int i = 0; i < block.childCount(); i++) {
                SyntaxNode s = block.child(i);
                if (!s.isNamed() || !s.is("local_variable_declaration")) {
                    continue;
                }
                for (int k = 0; k < s.childCount(); k++) {
                    SyntaxNode vd = s.child(k);
                    if (vd.is("variable_declarator")) {
                        SyntaxNode n = vd.field("name");
                        if (n != null) {
                            index.computeIfAbsent(n.text(), x -> new ArrayList<>(1))
                                    .add(new LocalDeclaration(s.start(), s, vd));
                        }
                    }
                }
            }
            blockIndex.put(block, index);
        }
        List<LocalDeclaration> l = index.get(name);
        if (l == null) {
            return null;
        }
        // children are in offset order: binary search for the last declaration starting before `before`
        int lo = 0;
        int hi = l.size() - 1;
        int found = -1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            if (l.get(mid).start() < before) {
                found = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        if (found < 0) {
            return null;
        }
        // several declarators of one declaration share its start: the last one in order wins
        return l.get(found);
    }

    Resolution lookupField(JExpr.FieldRef f, JavaContext ctx) {
        String q = f.qualifier();
        String field = f.field();
        String s = Texts.lastSegment(q);
        String c = rules.javaConstant(s, field);
        if (c != null) {
            return Resolution.constant(c);
        }
        if (f.thisObject() || ctx.localClasses.contains(s)) {
            Resolution r = fieldLookup(field, ctx);
            // this.F / C.F of a class of the file, F declared in a supertype (t3 J-INH)
            return r == null && inherited ? inheritedField(field, ctx, 1, new java.util.HashSet<>()) : r;
        }
        if (!s.isEmpty() && Character.isUpperCase(s.charAt(0))) {
            int dot = q.indexOf('.');
            String g = dot < 0 ? q : q.substring(0, dot);
            String imported = ctx.imports.get(g);
            if (imported != null) {
                return staticField(imported + (dot < 0 ? "" : q.substring(dot)), field, ctx);
            }
            if (dot < 0) {
                if (!ctx.packageName.isEmpty()) {
                    Resolution r = staticField(ctx.packageName + "." + q, field, ctx);
                    if (r != null) {
                        return r;
                    }
                }
                for (String w : ctx.wildcards) {
                    Resolution r = staticField(w + "." + q, field, ctx);
                    if (r != null) {
                        return r;
                    }
                }
                return null;
            }
            return staticField(q, field, ctx);
        }
        return null;
    }

    /** Field lookup in one file (SPEC 7.4.4.1). */
    static Resolution fieldLookup(String name, JavaContext ctx) {
        List<JavaContext.FieldEntry> entries = ctx.fields.get(name);
        if (entries == null || entries.isEmpty()) {
            return null;
        }
        JavaContext.FieldEntry first = entries.get(0);
        for (int i = 1; i < entries.size(); i++) {
            if (!entries.get(i).text.equals(first.text)) {
                return null;
            }
        }
        if (!first.isFinal && ctx.reassigned.contains(name)) {
            return null;
        }
        return Resolution.of(first.expr(), ctx);
    }

    /** Static field (C, F) on behalf of {@code ctx} (SPEC 7.4.5). */
    Resolution staticField(String cls, String field, JavaContext ctx) {
        String c = rules.javaConstant(Texts.lastSegment(cls), field);
        if (c != null) {
            return Resolution.constant(c);
        }
        JavaContext decl = locate(cls, ctx);
        if (decl == null) {
            return null;
        }
        Resolution r = fieldLookup(field, decl);
        if (r == null && inherited) {
            // C.F where F is declared in a supertype of C (t3 J-INH)
            java.util.Set<Path> seen = new java.util.HashSet<>();
            if (decl.file != null) {
                seen.add(decl.file);
            }
            r = inheritedField(field, decl, 1, seen);
        }
        return r;
    }

    /**
     * The declaring file of class {@code cls} (SPEC 7.4.5 step 2): below {@code ctx}'s source root; else (t3 J-XMOD)
     * the only Java file of the scan whose path ends with the class's package path, for the longest such suffix
     * that names any file (several files: none).
     */
    private JavaContext locate(String cls, JavaContext ctx) {
        Path root = sourceRoot(ctx);
        String[] seg = cls.split("\\.", -1);
        for (String s : seg) {
            if (s.isEmpty() || s.indexOf('/') >= 0 || s.indexOf('\\') >= 0 || s.equals("..")) {
                return null;
            }
        }
        if (root != null) {
            for (int i = seg.length; i >= 1; i--) {
                // names are matched as UTF-8 whatever the locale (DECISIONS O1); a qualifier from broken
                // source that is no file name makes the candidate absent
                Path cand = root;
                for (int k = 0; k < i && cand != null; k++) {
                    cand = FileNames.resolve(cand, k == i - 1 ? seg[k] + ".java" : seg[k]);
                }
                if (cand == null) {
                    continue;
                }
                if (cand.normalize().equals(ctx.file)) {
                    return ctx;
                }
                Optional<JavaContext> other = contexts.get(cand);
                if (other.isPresent()) {
                    return other.get();
                }
            }
        }
        if (root == null || !crossModule || seg.length < 2) {
            // a file whose source root lies outside the scan root gets no cross-file result (Appendix A, D5)
            return null;
        }
        for (int i = seg.length; i >= 2; i--) {
            StringBuilder sb = new StringBuilder();
            for (int k = 0; k < i; k++) {
                sb.append(seg[k]).append(k == i - 1 ? ".java" : "/");
            }
            List<Path> files = contexts.filesEndingWith(sb.toString());
            if (files.size() > 1) {
                return null;
            }
            if (files.size() == 1) {
                Path f = files.get(0);
                if (f.equals(ctx.file)) {
                    return ctx;
                }
                return contexts.get(f).orElse(null);
            }
        }
        return null;
    }

    private Path sourceRoot(JavaContext ctx) {
        if (ctx.file == null || contexts == null) {
            return null;
        }
        Path dir = ctx.file.getParent();
        if (!ctx.packageName.isEmpty()) {
            int n = ctx.packageName.split("\\.", -1).length;
            for (int i = 0; i < n && dir != null; i++) {
                dir = dir.getParent();
            }
        }
        if (dir == null || !dir.startsWith(contexts.scanRoot())) {
            return null;
        }
        return dir;
    }

    // ------------------------------------------------------------------ string list (7.4.6)

    List<String> stringList(List<SyntaxNode> args, JavaContext ctx) {
        return stringList(args, ctx, null, null);
    }

    /** The string list with one identifier argument given a fixed value (DECISIONS B-J-JP3). */
    List<String> stringList(List<SyntaxNode> args, JavaContext ctx, SyntaxNode fixed, String fixedValue) {
        List<String> out = new ArrayList<>();
        for (SyntaxNode a : args) {
            if (a == fixed) {
                out.add(fixedValue);
                continue;
            }
            switch (a.type()) {
                case "array_creation_expression" -> {
                    SyntaxNode init = a.childOfType("array_initializer");
                    if (init != null) {
                        addElements((JExpr.ArrayInit) JExpr.of(init, true), ctx, out);
                    }
                }
                case "array_initializer" -> addElements((JExpr.ArrayInit) JExpr.of(a, true), ctx, out);
                case "identifier", "field_access" -> {
                    JExpr e = JExpr.of(a, true);
                    Resolution r = e instanceof JExpr.Ident id ? lookupIdentifier(id, ctx)
                            : e instanceof JExpr.FieldRef f ? lookupField(f, ctx) : null;
                    JExpr.ArrayInit arr = null;
                    if (r != null && r.expr() != null) {
                        if (r.expr() instanceof JExpr.ArrayInit ai) {
                            arr = ai;
                        } else if (r.expr() instanceof JExpr.ArrayNew an && an.initializer() != null) {
                            arr = an.initializer();
                        }
                    }
                    if (arr != null && r.alternatives() == null) {
                        addElements(arr, r.ctx(), out);
                    } else {
                        String v = r == null ? null : valueOf(r, 0);
                        if (v != null) {
                            out.add(v);
                        }
                    }
                }
                default -> {
                    String v = value(JExpr.of(a, true), ctx, 0);
                    if (v != null) {
                        out.add(v);
                    }
                }
            }
        }
        return out;
    }

    private void addElements(JExpr.ArrayInit arr, JavaContext ctx, List<String> out) {
        for (JExpr el : arr.elements()) {
            if (JExpr.isDataElement(el)) {
                continue;
            }
            String v = value(el, ctx, 0);
            if (v != null) {
                out.add(v);
            }
        }
    }

    // ------------------------------------------------------------------ constant bytes (7.4.7)

    boolean isConst(JExpr e, JavaContext ctx, int d, boolean viaVar) {
        if (d > MAX_DEPTH || e == null) {
            return false;
        }
        switch (e) {
            case JExpr.Str s -> {
                return true;
            }
            case JExpr.ArrayInit a -> {
                return a.literalElements();
            }
            case JExpr.ArrayNew a -> {
                if (a.initializer() != null) {
                    return isConst(a.initializer(), ctx, d + 1, viaVar);
                }
                return !viaVar && a.hasDimensions();
            }
            case JExpr.Paren p -> {
                return isConst(p.last(), ctx, d + 1, viaVar);
            }
            case JExpr.Cast c -> {
                return isConst(c.last(), ctx, d + 1, viaVar);
            }
            case JExpr.Call c -> {
                if (!DECODERS.contains(c.name())) {
                    return false;
                }
                if (c.object() != null && RECEIVER_DECODERS.contains(c.name())) {
                    // s.getBytes("UTF-8"): the argument is a charset, only the receiver is data (t3 J-GB)
                    return value(c.object(), ctx, d + 1) != null;
                }
                return (c.object() != null && value(c.object(), ctx, d + 1) != null)
                        || (c.firstArgument() != null && value(c.firstArgument(), ctx, d + 1) != null);
            }
            case JExpr.Ident id -> {
                return constOf(lookupIdentifier(id, ctx), d);
            }
            case JExpr.FieldRef f -> {
                return constOf(lookupField(f, ctx), d);
            }
            default -> {
                return false;
            }
        }
    }

    private boolean constOf(Resolution r, int d) {
        if (r == null) {
            return false;
        }
        if (r.constant() != null) {
            return true;
        }
        return isConst(r.expr(), r.ctx(), d + 1, true);
    }
}
