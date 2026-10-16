/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang.java;

import ch.unibe.seg.ciphersift.syntax.SyntaxNode;
import java.util.ArrayList;
import java.util.List;

/** Java string literal decoding (SPEC 7.4.2). */
public final class JavaStrings {
    private JavaStrings() {}

    /** Decodes a {@code string_literal} node (ordinary literal or text block). */
    static String decodeLiteral(SyntaxNode n) {
        return replaceLoneSurrogates(decodeRaw(n));
    }

    private static String decodeRaw(SyntaxNode n) {
        String text = n.text();
        if (text.startsWith("\"\"\"")) {
            int end = text.length() >= 6 && text.endsWith("\"\"\"") ? text.length() - 3 : text.length();
            return decodeTextBlock(text.substring(3, Math.max(3, end)));
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < n.childCount(); i++) {
            SyntaxNode c = n.child(i);
            switch (c.type()) {
                case "string_fragment", "multiline_string_fragment" -> b.append(c.text());
                case "escape_sequence" -> b.append(decodeEscapes(c.text(), false));
                default -> {
                    // quote tokens and anything else are ignored
                }
            }
        }
        return b.toString();
    }

    /**
     * Decodes the raw content of a text block (between the delimiters) per JLS 3.10.6: drop the
     * opening line, normalise line terminators, strip incidental indentation and trailing white
     * space, then interpret escape sequences.
     */
    public static String decodeTextBlock(String raw) {
        int nl = -1;
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '\n' || c == '\r') {
                nl = i;
                if (c == '\r' && i + 1 < raw.length() && raw.charAt(i + 1) == '\n') {
                    nl = i + 1;
                }
                break;
            }
        }
        String content = nl < 0 ? "" : raw.substring(nl + 1);
        content = content.replace("\r\n", "\n").replace('\r', '\n');
        List<String> lines = new ArrayList<>(List.of(content.split("\n", -1)));
        int min = Integer.MAX_VALUE;
        for (int i = 0; i < lines.size(); i++) {
            String l = lines.get(i);
            boolean blank = isBlank(l);
            boolean last = i == lines.size() - 1;
            // non-blank lines count, and the last line even if blank (closing delimiter on its own line)
            if (!blank || last) {
                min = Math.min(min, leadingWhitespace(l));
            }
        }
        if (min == Integer.MAX_VALUE) {
            min = 0;
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < lines.size(); i++) {
            String l = lines.get(i);
            String out;
            if (isBlank(l)) {
                out = "";
            } else {
                out = stripTrailing(l.substring(Math.min(min, l.length())));
            }
            if (i > 0) {
                b.append('\n');
            }
            b.append(out);
        }
        return decodeEscapes(b.toString(), true);
    }

    private static boolean isBlank(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isWhitespace(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static int leadingWhitespace(String s) {
        int i = 0;
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
            i++;
        }
        return i;
    }

    private static String stripTrailing(String s) {
        int e = s.length();
        while (e > 0 && Character.isWhitespace(s.charAt(e - 1))) {
            e--;
        }
        return s.substring(0, e);
    }

    /**
     * Interprets escape sequences: {@code \b \t \n \f \r \s \" \' \\}, octal {@code \0}–{@code \377},
     * Unicode {@code \}{@code uXXXX} (one or more {@code u}); an unknown escape keeps its text. In text
     * blocks a backslash before a line terminator removes both.
     */
    public static String decodeEscapes(String s, boolean textBlock) {
        if (s.indexOf('\\') < 0) {
            return s;
        }
        StringBuilder b = new StringBuilder(s.length());
        int i = 0;
        int n = s.length();
        while (i < n) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= n) {
                b.append(c);
                i++;
                continue;
            }
            char d = s.charAt(i + 1);
            switch (d) {
                case 'b' -> { b.append('\b'); i += 2; }
                case 't' -> { b.append('\t'); i += 2; }
                case 'n' -> { b.append('\n'); i += 2; }
                case 'f' -> { b.append('\f'); i += 2; }
                case 'r' -> { b.append('\r'); i += 2; }
                case 's' -> { b.append(' '); i += 2; }
                case '"' -> { b.append('"'); i += 2; }
                case '\'' -> { b.append('\''); i += 2; }
                case '\\' -> { b.append('\\'); i += 2; }
                case '\n' -> {
                    if (textBlock) {
                        i += 2;
                    } else {
                        b.append(c);
                        i++;
                    }
                }
                case 'u' -> {
                    int k = i + 1;
                    while (k < n && s.charAt(k) == 'u') {
                        k++;
                    }
                    if (k + 4 <= n && isHex(s, k, k + 4)) {
                        b.append((char) Integer.parseInt(s.substring(k, k + 4), 16));
                        i = k + 4;
                    } else {
                        b.append(c);
                        i++;
                    }
                }
                default -> {
                    if (d >= '0' && d <= '7') {
                        int k = i + 1;
                        int max = d <= '3' ? 3 : 2;
                        int e = k;
                        while (e < n && e - k < max && s.charAt(e) >= '0' && s.charAt(e) <= '7') {
                            e++;
                        }
                        b.append((char) Integer.parseInt(s.substring(k, e), 8));
                        i = e;
                    } else {
                        // unknown escape: keep its text
                        b.append(c).append(d);
                        i += 2;
                    }
                }
            }
        }
        return b.toString();
    }

    /**
     * Replaces unpaired surrogates (which Unicode escapes such as {@code \\uD800} can produce) by
     * U+FFFD, so that decoded values are well-formed Unicode like all other text (SPEC 11.6: lone
     * surrogates cannot occur in the output).
     */
    static String replaceLoneSurrogates(String s) {
        StringBuilder b = null;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean lone;
            if (Character.isHighSurrogate(c)) {
                lone = i + 1 >= s.length() || !Character.isLowSurrogate(s.charAt(i + 1));
            } else if (Character.isLowSurrogate(c)) {
                lone = i == 0 || !Character.isHighSurrogate(s.charAt(i - 1));
            } else {
                lone = false;
            }
            if (lone && b == null) {
                b = new StringBuilder(s.length());
                b.append(s, 0, i);
            }
            if (b != null) {
                b.append(lone ? '\uFFFD' : c);
            }
        }
        return b == null ? s : b.toString();
    }

    private static boolean isHex(String s, int a, int e) {
        for (int i = a; i < e; i++) {
            if (Character.digit(s.charAt(i), 16) < 0) {
                return false;
            }
        }
        return true;
    }
}
