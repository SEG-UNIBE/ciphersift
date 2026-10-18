/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.scan;

import ch.unibe.seg.ciphersift.rules.GoPattern;
import ch.unibe.seg.ciphersift.rules.JavaPattern;
import ch.unibe.seg.ciphersift.rules.PythonPattern;
import ch.unibe.seg.ciphersift.rules.SourceRule;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A sound textual pre-check: can any pattern of the rule set possibly fire in a source text? If not,
 * the file needs neither parsing nor analysis, because its findings are empty by construction.
 *
 * <p>Every anchor compares node texts of the analysed file with literal names of the pattern
 * (SPEC 7.2, 7.3.2, 7.6, 8.2–8.6, 8.9), so those names occur in the file's text:
 *
 * <ul>
 *   <li>Java {@code call: C.m} / {@code field: C.F}: the member ({@code m}, a prefix for {@code m*})
 *       is the text of the event's name; the simple name of {@code C} is part of the receiver text
 *       (every case of {@code denotes}) or of the static import that supplies the static candidate.
 *   <li>Java {@code new: C}: the simple name of {@code C} is the last segment of the type text.
 *   <li>Java member types ({@code a.b.Outer.Inner}, any anchor): the top-level class name occurs in the
 *       reference or in the import that makes the member type visible (SPEC 7.3.2 step 6).
 *   <li>Java {@code method}/{@code override}: the name (or prefix).
 *   <li>Python {@code call: a.b.c}: a resolved call name is built only from identifier texts,
 *       attribute names and import texts of the file, so every identifier part of the value occurs;
 *       {@code method}: one of the names; {@code anyCall}: each required keyword;
 *       {@code assign}: the attribute name; {@code ref} and bare references matched by {@code call}
 *       patterns (SPEC 8.6.1) are resolved names like call names, so the same argument applies. The
 *       symbol conditions {@code anySymbol} / {@code allSymbols} hit only resolved names, so the
 *       identifier parts of one (of all) listed names occur as well. A {@code kwargs} keyword is the
 *       text of a keyword-argument name, and a {@code dictItems} key is the string value of a
 *       dictionary key (escapes are not interpreted, so it is a substring of the text).
 *   <li>Go {@code call} / {@code ref} / {@code composite: path.M} (SPEC 17.3–17.5): a name
 *       {@code path.M} exists only through an import spec whose literal content is {@code path}
 *       (escapes are not interpreted), and {@code M} (or the prefix) is the text of the selector's
 *       field, of the dot-imported identifier or of the type name; {@code assign}: the field name.
 * </ul>
 *
 * A file passes if, for some pattern, all of its required names occur as substrings anywhere in the
 * text (strings and comments included; no word boundaries are checked, so the test only ever errs
 * towards analysing a file). The check is one pass of an Aho–Corasick automaton over the text.
 * Patterns whose required names cannot be determined make the filter accept every text.
 */
final class AnchorPrefilter {
    /** Accepts every text. */
    static final AnchorPrefilter ALL = new AnchorPrefilter(null, null, 0, null, null, 0);

    /** For each pattern: its clauses; a clause is satisfied by any of its token ids. */
    private final int[][][] patterns;
    /** Character class of each ASCII character (0: occurs in no name). */
    private final byte[] classes;
    private final int width;
    /** Complete automaton: next state = delta[state * width + class]. */
    private final int[] delta;
    /** Per state: ids of the names ending here (failure links included), or null. */
    private final int[][] outputs;
    private final int tokenCount;

    private AnchorPrefilter(int[][][] patterns, byte[] classes, int width, int[] delta, int[][] outputs,
            int tokenCount) {
        this.patterns = patterns;
        this.classes = classes;
        this.width = width;
        this.delta = delta;
        this.outputs = outputs;
        this.tokenCount = tokenCount;
    }

    /** The filter for the Java rules. */
    static AnchorPrefilter java(List<SourceRule> rules) {
        return java(rules, Features.DEFAULTS);
    }

    /**
     * The filter for the Java rules that are on with these feature switches (SPEC 5.5 {@code feature}). An
     * enabled {@code anyCall} pattern has no required name (its strings may come from other files), so the
     * filter then accepts every text.
     */
    static AnchorPrefilter java(List<SourceRule> rules, Features features) {
        List<List<List<String>>> pats = new ArrayList<>();
        for (SourceRule r : rules) {
            for (JavaPattern p : r.javaPatterns()) {
                if (p.feature != null && !features.on(p.feature)) {
                    continue;
                }
                List<List<String>> clauses = new ArrayList<>();
                switch (p.anchor) {
                    case CALL, FIELD -> {
                        classClauses(p.className, clauses);
                        if (!p.member.isEmpty()) {
                            clauses.add(List.of(p.member));
                        }
                    }
                    case NEW -> classClauses(p.className, clauses);
                    default -> {
                        if (!p.member.isEmpty()) {
                            clauses.add(List.of(p.member));
                        }
                    }
                }
                pats.add(clauses);
            }
        }
        return build(pats);
    }

    /** The filter for the Python rules. */
    static AnchorPrefilter python(List<SourceRule> rules) {
        List<List<List<String>>> pats = new ArrayList<>();
        for (SourceRule r : rules) {
            for (PythonPattern p : r.pythonPatterns()) {
                List<List<String>> clauses = new ArrayList<>();
                if (p.call != null) {
                    for (String part : identifierParts(p.call)) {
                        clauses.add(List.of(part));
                    }
                    if (p.methods != null) {
                        clauses.add(List.copyOf(p.methods));
                    }
                } else if (p.methods != null) {
                    clauses.add(List.copyOf(p.methods));
                } else if (p.anyCall) {
                    if (p.kwargs != null) {
                        for (String k : p.kwargs.keySet()) {
                            clauses.add(List.of(k));
                        }
                    }
                } else if (p.assign != null) {
                    clauses.add(List.of(p.assign));
                } else if (p.ref != null) {
                    // a bare reference resolves like a call name (SPEC 8.6.1)
                    for (String part : identifierParts(p.ref)) {
                        clauses.add(List.of(part));
                    }
                }
                if (clauses.isEmpty()) {
                    pats.add(clauses); // makes the filter accept everything
                    continue;
                }
                // kwargs requires the call to have each keyword argument, and dictItems a dictionary key
                // with each listed string value (SPEC 5.6): those names occur in the text as well
                if (p.kwargs != null && !p.anyCall) {
                    for (String k : p.kwargs.keySet()) {
                        clauses.add(List.of(k));
                    }
                }
                if (p.dictItems != null) {
                    for (String k : p.dictItems.keySet()) {
                        if (!k.isEmpty() && k.chars().allMatch(ch -> ch < 128)) {
                            clauses.add(List.of(k));
                        }
                    }
                }
                // a symbol hits a listed name if it equals the name or ends with "." + name (SPEC 8.5.2);
                // symbols are resolved names, so every identifier part of a hit name occurs in the text
                if (p.allSymbols != null) {
                    for (String n : p.allSymbols) {
                        for (String part : identifierParts(n)) {
                            clauses.add(List.of(part));
                        }
                    }
                }
                if (p.anySymbol != null && !p.anySymbol.isEmpty()) {
                    for (String n : p.anySymbol) {
                        List<List<String>> c = new ArrayList<>(clauses);
                        for (String part : identifierParts(n)) {
                            c.add(List.of(part));
                        }
                        pats.add(c);
                    }
                } else {
                    pats.add(clauses);
                }
            }
        }
        return build(pats);
    }

    /** The filter for the Go rules (SPEC 17). */
    static AnchorPrefilter go(List<SourceRule> rules) {
        List<List<List<String>>> pats = new ArrayList<>();
        for (SourceRule r : rules) {
            for (GoPattern p : r.goPatterns()) {
                List<List<String>> clauses = new ArrayList<>();
                if (p.anchor == GoPattern.Anchor.ASSIGN) {
                    clauses.add(List.of(p.name));
                } else {
                    clauses.add(List.of(p.path));
                    if (!p.member().isEmpty()) {
                        clauses.add(List.of(p.member()));
                    }
                }
                pats.add(clauses);
            }
        }
        return build(pats);
    }

    /**
     * The names a reference to {@code className} contains: its simple name, and for a member type
     * ({@code a.b.Outer.Inner}) also the simple name of its top-level class, which occurs either in the
     * reference itself or in the import that brings the member type into scope (SPEC 7.3.2).
     */
    private static void classClauses(String className, List<List<String>> clauses) {
        String simple = simpleName(className);
        clauses.add(List.of(simple));
        if (className != null) {
            for (String seg : className.split("\\.", -1)) {
                if (!seg.isEmpty() && Character.isUpperCase(seg.charAt(0))) {
                    if (!seg.equals(simple)) {
                        clauses.add(List.of(seg));
                    }
                    break;
                }
            }
        }
    }

    private static String simpleName(String className) {
        if (className == null) {
            return "";
        }
        int dot = className.lastIndexOf('.');
        return dot < 0 ? className : className.substring(dot + 1);
    }

    /** The maximal runs of {@code [A-Za-z0-9_]} of a dotted value, skipping {@code <…>} placeholders. */
    static List<String> identifierParts(String dotted) {
        List<String> out = new ArrayList<>();
        for (String seg : dotted.split("\\.", -1)) {
            if (seg.indexOf('<') >= 0 || seg.indexOf('>') >= 0) {
                continue; // e.g. <expr> (SPEC 8.4.2 shape): not source text
            }
            int i = 0;
            while (i < seg.length()) {
                while (i < seg.length() && !isWordChar(seg.charAt(i))) {
                    i++;
                }
                int s = i;
                while (i < seg.length() && isWordChar(seg.charAt(i))) {
                    i++;
                }
                if (i > s) {
                    out.add(seg.substring(s, i));
                }
            }
        }
        return out;
    }

    private static boolean isWordChar(char c) {
        return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    }

    private static AnchorPrefilter build(List<List<List<String>>> pats) {
        Map<String, Integer> ids = new LinkedHashMap<>();
        int[][][] compiled = new int[pats.size()][][];
        for (int i = 0; i < pats.size(); i++) {
            List<List<String>> clauses = pats.get(i);
            if (clauses.isEmpty()) {
                return ALL; // a pattern without required names can fire anywhere
            }
            compiled[i] = new int[clauses.size()][];
            for (int c = 0; c < clauses.size(); c++) {
                List<String> alts = clauses.get(c);
                int[] a = new int[alts.size()];
                for (int k = 0; k < alts.size(); k++) {
                    String t = alts.get(k);
                    if (t.isEmpty()) {
                        return ALL;
                    }
                    for (int j = 0; j < t.length(); j++) {
                        if (t.charAt(j) >= 128) {
                            return ALL; // the automaton covers ASCII names only
                        }
                    }
                    Integer id = ids.get(t);
                    if (id == null) {
                        id = ids.size();
                        ids.put(t, id);
                    }
                    a[k] = id;
                }
                compiled[i][c] = a;
            }
        }
        if (compiled.length == 0) {
            return new AnchorPrefilter(compiled, new byte[128], 1, new int[1], new int[1][], 0); // never fires
        }
        // character classes: 0 for every character that occurs in no name, 1..k otherwise
        byte[] classes = new byte[128];
        int k = 0;
        for (String t : ids.keySet()) {
            for (int j = 0; j < t.length(); j++) {
                char ch = t.charAt(j);
                if (classes[ch] == 0) {
                    classes[ch] = (byte) ++k; // at most 127 classes
                }
            }
        }
        int width = k + 1;
        // trie (state 0 is the root), then failure links breadth first, making the automaton complete
        int[] delta = new int[width * 16];
        Arrays.fill(delta, -1);
        int states = 1;
        List<List<Integer>> out = new ArrayList<>();
        out.add(new ArrayList<>());
        for (Map.Entry<String, Integer> e : ids.entrySet()) {
            int st = 0;
            for (int j = 0; j < e.getKey().length(); j++) {
                int c = classes[e.getKey().charAt(j)];
                int t = delta[st * width + c];
                if (t < 0) {
                    t = states++;
                    if (states * width > delta.length) {
                        int old = delta.length;
                        delta = Arrays.copyOf(delta, old * 2);
                        Arrays.fill(delta, old, delta.length, -1);
                    }
                    out.add(new ArrayList<>());
                    delta[st * width + c] = t;
                }
                st = t;
            }
            out.get(st).add(e.getValue());
        }
        int[] fail = new int[states];
        int[] queue = new int[states];
        int head = 0;
        int tail = 0;
        for (int c = 0; c < width; c++) {
            int t = delta[c];
            if (t < 0) {
                delta[c] = 0;
            } else {
                fail[t] = 0;
                queue[tail++] = t;
            }
        }
        while (head < tail) {
            int st = queue[head++];
            out.get(st).addAll(out.get(fail[st]));
            for (int c = 0; c < width; c++) {
                int t = delta[st * width + c];
                int viaFail = delta[fail[st] * width + c];
                if (t < 0) {
                    delta[st * width + c] = viaFail;
                } else {
                    fail[t] = viaFail;
                    queue[tail++] = t;
                }
            }
        }
        int[][] outputs = new int[states][];
        for (int st = 0; st < states; st++) {
            List<Integer> o = out.get(st);
            if (!o.isEmpty()) {
                outputs[st] = o.stream().distinct().mapToInt(Integer::intValue).toArray();
            }
        }
        return new AnchorPrefilter(compiled, classes, width, Arrays.copyOf(delta, states * width), outputs,
                ids.size());
    }

    /** Is it possible that some pattern fires in {@code text}? */
    boolean mayMatch(CharSequence text) {
        if (patterns == null) {
            return true;
        }
        if (tokenCount == 0) {
            return false;
        }
        boolean[] found = new boolean[tokenCount];
        int[] d = delta;
        byte[] cls = classes;
        int w = width;
        int[][] outs = outputs;
        int st = 0;
        for (int i = 0, len = text.length(); i < len; i++) {
            char c = text.charAt(i);
            // no name contains a non-ASCII character: such a character leads back to the root
            st = c < 128 ? d[st * w + cls[c]] : 0;
            int[] o = outs[st];
            if (o != null) {
                boolean fresh = false;
                for (int t : o) {
                    if (!found[t]) {
                        found[t] = true;
                        fresh = true;
                    }
                }
                if (fresh && satisfied(found)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean satisfied(boolean[] found) {
        outer:
        for (int[][] clauses : patterns) {
            for (int[] alts : clauses) {
                boolean any = false;
                for (int t : alts) {
                    if (found[t]) {
                        any = true;
                        break;
                    }
                }
                if (!any) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}
