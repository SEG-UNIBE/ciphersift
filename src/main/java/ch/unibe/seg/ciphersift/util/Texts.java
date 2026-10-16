/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.util;

import java.util.Comparator;
import java.util.Locale;

/** Small text helpers shared by the analysers. */
public final class Texts {
    /** Compares strings by Unicode code points (SPEC 11.6), not UTF-16 units. */
    public static final Comparator<String> CODE_POINT_ORDER = Texts::compareCodePoints;

    private Texts() {}

    public static int compareCodePoints(String a, String b) {
        int i = 0;
        int j = 0;
        while (i < a.length() && j < b.length()) {
            int ca = a.codePointAt(i);
            int cb = b.codePointAt(j);
            if (ca != cb) {
                return Integer.compare(ca, cb);
            }
            i += Character.charCount(ca);
            j += Character.charCount(cb);
        }
        return Integer.compare(a.length() - i, b.length() - j);
    }

    /** Null-safe code-point comparison where {@code null} sorts before any value. */
    public static int compareNullFirst(String a, String b) {
        if (a == null) {
            return b == null ? 0 : -1;
        }
        if (b == null) {
            return 1;
        }
        return compareCodePoints(a, b);
    }

    /** Whitespace as in {@code \s} of {@code java.util.regex}: space, tab, LF, VT, FF, CR. */
    public static boolean isWhitespace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\u000B' || c == '\f' || c == '\r';
    }

    /** Removes all whitespace characters. */
    public static String removeWhitespace(String s) {
        int n = s.length();
        int k = 0;
        while (k < n && !isWhitespace(s.charAt(k))) {
            k++;
        }
        if (k == n) {
            return s;
        }
        StringBuilder b = new StringBuilder(n);
        b.append(s, 0, k);
        for (int i = k; i < n; i++) {
            char c = s.charAt(i);
            if (!isWhitespace(c)) {
                b.append(c);
            }
        }
        return b.toString();
    }

    /** Replaces every run of whitespace characters by one space. */
    public static String collapseWhitespace(String s) {
        StringBuilder b = new StringBuilder(s.length());
        boolean inWs = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (isWhitespace(c)) {
                if (!inWs) {
                    b.append(' ');
                    inWs = true;
                }
            } else {
                b.append(c);
                inWs = false;
            }
        }
        return b.toString();
    }

    /** Trims whitespace characters (as in {@link #isWhitespace}) at both ends. */
    public static String trim(String s) {
        int a = 0;
        int e = s.length();
        while (a < e && isWhitespace(s.charAt(a))) {
            a++;
        }
        while (e > a && isWhitespace(s.charAt(e - 1))) {
            e--;
        }
        return s.substring(a, e);
    }

    /** At most {@code max} code points. */
    public static String truncateCodePoints(String s, int max) {
        if (s.length() <= max) {
            return s;
        }
        int count = s.codePointCount(0, s.length());
        if (count <= max) {
            return s;
        }
        return s.substring(0, s.offsetByCodePoints(0, max));
    }

    public static String lower(String s) {
        return s.toLowerCase(Locale.ROOT);
    }

    public static String upper(String s) {
        return s.toUpperCase(Locale.ROOT);
    }

    /** Last {@code .}-separated segment. */
    public static String lastSegment(String s) {
        int i = s.lastIndexOf('.');
        return i < 0 ? s : s.substring(i + 1);
    }

    /** Is {@code word} contained in {@code text} as a whole word (not adjacent to {@code [A-Za-z0-9_]})? */
    public static boolean containsWord(String text, String word) {
        if (word.isEmpty()) {
            return false;
        }
        int from = 0;
        while (true) {
            int i = text.indexOf(word, from);
            if (i < 0) {
                return false;
            }
            int e = i + word.length();
            boolean before = i > 0 && isWordChar(text.charAt(i - 1));
            boolean after = e < text.length() && isWordChar(text.charAt(e));
            if (!before && !after) {
                return true;
            }
            from = i + 1;
        }
    }

    public static boolean isWordChar(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
    }
}
