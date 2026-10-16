/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.syntax;

import java.util.ArrayList;
import java.util.List;

/**
 * An immutable Java copy of one tree-sitter node. The whole tree is copied once per file
 * ({@link SyntaxTrees#parse}), after which the native tree is closed; all analysis runs on these
 * objects. Offsets are char indices into the decoded source text (they correspond one-to-one to
 * the UTF-8 byte offsets tree-sitter reports).
 */
public final class SyntaxNode {
    private static final SyntaxNode[] NO_CHILDREN = new SyntaxNode[0];

    final String source;
    final String type;
    final boolean named;
    final String field;
    final int start;
    final int end;
    final int startRow;
    SyntaxNode parent;
    SyntaxNode[] children = NO_CHILDREN;
    int index;

    SyntaxNode(String source, String type, boolean named, String field, int start, int end, int startRow) {
        this.source = source;
        this.type = type;
        this.named = named;
        this.field = field;
        this.start = start;
        this.end = end;
        this.startRow = startRow;
    }

    /** Node type (tree-sitter {@code ts_node_type}). */
    public String type() {
        return type;
    }

    public boolean is(String t) {
        return type.equals(t);
    }

    public boolean isNamed() {
        return named;
    }

    /** Name of the field through which the parent refers to this node, or {@code null}. */
    public String field() {
        return field;
    }

    public SyntaxNode parent() {
        return parent;
    }

    /** Start offset (char index into the source text). */
    public int start() {
        return start;
    }

    /** End offset (exclusive). */
    public int end() {
        return end;
    }

    /** 0-based start row. */
    public int startRow() {
        return startRow;
    }

    /** 1-based start line. */
    public int line() {
        return startRow + 1;
    }

    public String text() {
        return source.substring(start, end);
    }

    public int childCount() {
        return children.length;
    }

    public SyntaxNode child(int i) {
        return children[i];
    }

    /** Index of this node among its parent's children. */
    public int indexInParent() {
        return index;
    }

    public List<SyntaxNode> children() {
        return List.of(children);
    }

    /** Named children in order (comments included: they are named nodes). */
    public List<SyntaxNode> namedChildren() {
        List<SyntaxNode> l = new ArrayList<>(children.length);
        for (SyntaxNode c : children) {
            if (c.named) {
                l.add(c);
            }
        }
        return l;
    }

    public SyntaxNode firstNamedChild() {
        for (SyntaxNode c : children) {
            if (c.named) {
                return c;
            }
        }
        return null;
    }

    public SyntaxNode lastNamedChild() {
        for (int i = children.length - 1; i >= 0; i--) {
            if (children[i].named) {
                return children[i];
            }
        }
        return null;
    }

    /** First child with the given field name, or {@code null}. */
    public SyntaxNode field(String name) {
        for (SyntaxNode c : children) {
            if (name.equals(c.field)) {
                return c;
            }
        }
        return null;
    }

    /** All children with the given field name. */
    public List<SyntaxNode> fields(String name) {
        List<SyntaxNode> l = new ArrayList<>(2);
        for (SyntaxNode c : children) {
            if (name.equals(c.field)) {
                l.add(c);
            }
        }
        return l;
    }

    /** First child (named or not) of the given type, or {@code null}. */
    public SyntaxNode childOfType(String t) {
        for (SyntaxNode c : children) {
            if (c.type.equals(t)) {
                return c;
            }
        }
        return null;
    }

    public boolean hasChildOfType(String t) {
        return childOfType(t) != null;
    }

    /** True iff this node lies completely inside {@code other} (by offsets). */
    public boolean within(int s, int e) {
        return start >= s && end <= e;
    }

    @Override
    public String toString() {
        return type + "[" + start + "," + end + "]";
    }
}
