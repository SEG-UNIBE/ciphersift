/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang.java;

import ch.unibe.seg.ciphersift.syntax.SyntaxNode;
import ch.unibe.seg.ciphersift.util.Texts;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Small immutable expression form on which constant resolution (SPEC 7.4) is evaluated
 * (the advice of SPEC 7.4.5). Expressions of the analysed file are converted on demand and keep
 * the position of identifiers (for local-variable lookup); field initialisers are converted when a
 * file context is built and have no positions, so their identifiers always use the fallback of
 * 7.4.3 (see IMPLEMENTATION-NOTES.md). Conversion stops below {@link #MAX_DEPTH}: deeper parts can
 * never be resolved, because {@code value} and {@code isConst} give up beyond depth 12.
 */
sealed interface JExpr {
    int MAX_DEPTH = 16;

    Set<String> INTEGER_LITERALS = Set.of(
            "decimal_integer_literal", "hex_integer_literal", "octal_integer_literal", "binary_integer_literal");

    /** {@code string_literal}: decoded value. */
    record Str(String value) implements JExpr {}

    /** Another literal; {@code value} is set for decimal integers and characters only. */
    record Lit(String type, String value) implements JExpr {}

    /** {@code binary_expression}. */
    record Binary(boolean plus, JExpr left, JExpr right) implements JExpr {}

    /** {@code parenthesized_expression}: first and last named child. */
    record Paren(JExpr first, JExpr last) implements JExpr {}

    /** {@code cast_expression}: last named child. */
    record Cast(JExpr last) implements JExpr {}

    /** {@code unary_expression}. */
    record Unary() implements JExpr {}

    /** {@code identifier}; {@code position} is {@code null} for field initialisers. */
    record Ident(String name, SyntaxNode position) implements JExpr {}

    /** {@code field_access}: object text without whitespace, whether the object is {@code this}, field name. */
    record FieldRef(String qualifier, boolean thisObject, String field) implements JExpr {}

    /** {@code method_invocation}: object (or null), name, first argument (or null). */
    record Call(JExpr object, String name, JExpr firstArgument) implements JExpr {}

    /** {@code array_initializer}: elements, and whether every named non-comment child is literal-like (7.4.7). */
    record ArrayInit(List<JExpr> elements, boolean literalElements) implements JExpr {}

    /** {@code array_creation_expression}. */
    record ArrayNew(ArrayInit initializer, boolean hasDimensions) implements JExpr {}

    /** Anything else. */
    record Other() implements JExpr {}

    Other OTHER = new Other();
    Unary UNARY = new Unary();

    /** Is this element excluded from string lists (integer, character literal, unary, cast; SPEC 7.4.6)? */
    static boolean isDataElement(JExpr e) {
        if (e instanceof Lit l) {
            return INTEGER_LITERALS.contains(l.type()) || "character_literal".equals(l.type());
        }
        return e instanceof Unary || e instanceof Cast;
    }

    /** Converts a syntax node. {@code live} keeps identifier positions. */
    static JExpr of(SyntaxNode n, boolean live) {
        return convert(n, live, 0);
    }

    private static JExpr convert(SyntaxNode n, boolean live, int depth) {
        if (n == null || depth > MAX_DEPTH) {
            return OTHER;
        }
        String t = n.type();
        switch (t) {
            case "string_literal":
                return new Str(JavaStrings.decodeLiteral(n));
            case "decimal_integer_literal": {
                String s = n.text();
                if (s.endsWith("l") || s.endsWith("L")) {
                    s = s.substring(0, s.length() - 1);
                }
                return new Lit(t, s);
            }
            case "character_literal": {
                String s = n.text();
                int a = 0;
                int b = s.length();
                while (a < b && s.charAt(a) == '\'') {
                    a++;
                }
                while (b > a && s.charAt(b - 1) == '\'') {
                    b--;
                }
                return new Lit(t, s.substring(a, b));
            }
            case "parenthesized_expression":
                return new Paren(convert(n.firstNamedChild(), live, depth + 1),
                        convert(n.lastNamedChild(), live, depth + 1));
            case "cast_expression":
                return new Cast(convert(n.lastNamedChild(), live, depth + 1));
            case "unary_expression":
                return UNARY;
            case "binary_expression": {
                SyntaxNode op = n.field("operator");
                boolean plus = op != null && "+".equals(op.text());
                if (!plus) {
                    return new Binary(false, OTHER, OTHER);
                }
                return new Binary(true, convert(n.field("left"), live, depth + 1),
                        convert(n.field("right"), live, depth + 1));
            }
            case "identifier":
                return new Ident(n.text(), live ? n : null);
            case "field_access": {
                SyntaxNode o = n.field("object");
                SyntaxNode f = n.field("field");
                if (o == null || f == null) {
                    return OTHER;
                }
                return new FieldRef(Texts.removeWhitespace(o.text()), o.is("this"), f.text());
            }
            case "method_invocation": {
                SyntaxNode name = n.field("name");
                if (name == null) {
                    return OTHER;
                }
                SyntaxNode o = n.field("object");
                SyntaxNode args = n.field("arguments");
                SyntaxNode first = null;
                if (args != null) {
                    for (int i = 0; i < args.childCount(); i++) {
                        SyntaxNode c = args.child(i);
                        if (c.isNamed() && !isComment(c)) {
                            first = c;
                            break;
                        }
                    }
                }
                return new Call(o == null ? null : convert(o, live, depth + 1), name.text(),
                        first == null ? null : convert(first, live, depth + 1));
            }
            case "array_initializer":
                return arrayInit(n, live, depth);
            case "array_creation_expression": {
                SyntaxNode init = n.childOfType("array_initializer");
                return new ArrayNew(init == null ? null : arrayInit(init, live, depth + 1),
                        n.hasChildOfType("dimensions_expr"));
            }
            default:
                if (t.endsWith("literal")) {
                    return new Lit(t, null);
                }
                return OTHER;
        }
    }

    private static ArrayInit arrayInit(SyntaxNode n, boolean live, int depth) {
        List<JExpr> elems = new ArrayList<>();
        boolean literal = true;
        for (int i = 0; i < n.childCount(); i++) {
            SyntaxNode c = n.child(i);
            if (!c.isNamed()) {
                continue;
            }
            if (isComment(c)) {
                continue; // comments are not elements (DECISIONS O3)
            }
            String ct = c.type();
            if (!(ct.endsWith("literal") || ct.equals("cast_expression") || ct.equals("unary_expression"))) {
                literal = false;
            }
            elems.add(convert(c, live, depth + 1));
        }
        return new ArrayInit(List.copyOf(elems), literal);
    }

    static boolean isComment(SyntaxNode n) {
        return n.is("line_comment") || n.is("block_comment");
    }
}
