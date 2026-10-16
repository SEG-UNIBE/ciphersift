/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.deps;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds the matches of the Gradle map-notation regex of SPEC 9.6 step 4,
 *
 * <pre>
 * group\s*[:=]\s*(['"])(.+?)\1\s*,\s*name\s*[:=]\s*(['"])(.+?)\3(?:\s*,\s*version\s*[:=]\s*(['"])(.+?)\5)?
 * </pre>
 *
 * with exactly the results of {@code Matcher.find()} (same matches, same groups), but in
 * O(n log n) time. The regex itself backtracks over the rest of the line for every
 * {@code group:'…'} that is not followed by a {@code name}, which makes a crafted single-line build
 * script of a few megabytes take hours ({@link MavenManifests#MAP_NOTATION} is kept as the
 * reference for the tests).
 *
 * <p>The search is split at the three lazy groups: each {@code (.+?)Q} is the first quote
 * {@code Q} after at least one character on the same line (Java's {@code .} excludes line
 * terminators) for which the rest of the pattern matches, and every other part of the pattern is
 * deterministic.
 */
final class MapNotation {
    /** One match: start offset and groups 2, 4 and 6 (version may be null). */
    record Match(int start, int end, String group, String name, String version) {}

    private static final Pattern HEAD = Pattern.compile("group\\s*[:=]\\s*(['\"])");
    /** Applied at a quote: the part between group 2 and group 4. */
    private static final Pattern TAIL = Pattern.compile("(['\"])\\s*,\\s*name\\s*[:=]\\s*(['\"])");
    /** Applied after the closing quote of group 4: the optional version part (without its value). */
    private static final Pattern VERSION = Pattern.compile("\\s*,\\s*version\\s*[:=]\\s*(['\"])");

    private final String text;
    private final int[] singles;
    private final int[] doubles;
    private final int[] lineEnds;

    private MapNotation(String text) {
        this.text = text;
        int s = 0;
        int d = 0;
        int l = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\'') {
                s++;
            } else if (c == '"') {
                d++;
            } else if (isLineTerminator(c)) {
                l++;
            }
        }
        singles = new int[s];
        doubles = new int[d];
        lineEnds = new int[l];
        s = 0;
        d = 0;
        l = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\'') {
                singles[s++] = i;
            } else if (c == '"') {
                doubles[d++] = i;
            } else if (isLineTerminator(c)) {
                lineEnds[l++] = i;
            }
        }
    }

    /** Line terminators that Java's {@code .} does not match (no flags). */
    static boolean isLineTerminator(char c) {
        return c == '\n' || c == '\r' || c == '\u0085' || c == ' ' || c == ' ';
    }

    /** Smallest element of the sorted array that is {@code >= x}, or -1. */
    private static int next(int[] sorted, int x) {
        int i = Arrays.binarySearch(sorted, x);
        if (i < 0) {
            i = -i - 1;
        }
        return i < sorted.length ? sorted[i] : -1;
    }

    /** First offset {@code >= x} that is a line terminator, or the text length. */
    private int lineEnd(int x) {
        int e = next(lineEnds, x);
        return e < 0 ? text.length() : e;
    }

    /**
     * End of {@code (.+?)q} starting at {@code open} (the first content character): the offset of the
     * first {@code q} at or after {@code open + 1} on the same line, or -1.
     */
    private int lazyQuoted(int open, char q) {
        if (open >= text.length()) {
            return -1;
        }
        int close = next(q == '\'' ? singles : doubles, open + 1);
        return close >= 0 && close <= lineEnd(open) ? close : -1;
    }

    static List<Match> findAll(String text) {
        return new MapNotation(text).findAll();
    }

    private List<Match> findAll() {
        List<Match> out = new ArrayList<>();
        // tails: quote offsets e at which TAIL matches and whose group 4 can be closed, per quote char
        List<Integer> tailsSingle = new ArrayList<>();
        List<Integer> tailsDouble = new ArrayList<>();
        Matcher tail = TAIL.matcher(text);
        for (int[] quotes : new int[][] {singles, doubles}) {
            for (int e : quotes) {
                tail.region(e, text.length());
                if (tail.lookingAt() && lazyQuoted(tail.end(), tail.group(2).charAt(0)) >= 0) {
                    (text.charAt(e) == '\'' ? tailsSingle : tailsDouble).add(e);
                }
            }
        }
        int[] validSingle = tailsSingle.stream().mapToInt(Integer::intValue).toArray();
        int[] validDouble = tailsDouble.stream().mapToInt(Integer::intValue).toArray();
        Matcher head = HEAD.matcher(text);
        Matcher version = VERSION.matcher(text);
        int from = 0;
        while (from <= text.length() && head.find(from)) {
            int start = head.start();
            char q = head.group(1).charAt(0);
            int cs = head.end();
            // group 2: at least one character, no line terminator, up to the first valid tail with quote q
            int e = cs < text.length() ? next(q == '\'' ? validSingle : validDouble, cs + 1) : -1;
            if (e < 0 || e > lineEnd(cs)) {
                from = start + 1;
                continue;
            }
            tail.region(e, text.length());
            if (!tail.lookingAt()) {
                throw new IllegalStateException("tail vanished");
            }
            int o = tail.end();
            char q2 = tail.group(2).charAt(0);
            int f = lazyQuoted(o, q2);
            int end = f + 1;
            String ver = null;
            version.region(end, text.length());
            if (version.lookingAt()) {
                int o5 = version.end();
                int f5 = lazyQuoted(o5, version.group(1).charAt(0));
                if (f5 >= 0) {
                    ver = text.substring(o5, f5);
                    end = f5 + 1;
                }
            }
            out.add(new Match(start, end, text.substring(cs, e), text.substring(o, f), ver));
            from = end;
        }
        return out;
    }
}
