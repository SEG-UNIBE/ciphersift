/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.wrappers;

import ch.unibe.seg.ciphersift.syntax.SyntaxNode;

/** Builds the outline of a parsed source file (SPEC 18.2, 18.3). */
public final class Outlines {
    private Outlines() {}

    /** The 1-based line of a node's last character: its first line plus the line feeds in its text. */
    static int lastLine(SyntaxNode n) {
        String text = n.text();
        int k = 0;
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) == '\n') {
                k++;
            }
        }
        return n.startRow() + 1 + k;
    }

    /** @param javaConstructors Java constructors and {@code new C(…)} take part (t3 J-CTOR) */
    public static Outline of(Outline.Lang lang, SyntaxNode root, String path, boolean test, boolean javaConstructors) {
        return switch (lang) {
            case JAVA -> JavaOutliner.outline(root, path, test, javaConstructors);
            case PYTHON -> PythonOutliner.outline(root, path, test);
            case GO -> GoOutliner.outline(root, path, test);
        };
    }
}
