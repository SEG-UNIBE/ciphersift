/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.deps;

import ch.unibe.seg.ciphersift.syntax.SyntaxNode;
import ch.unibe.seg.ciphersift.util.Texts;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Requirements declared in {@code setup.py} and {@code setup.cfg} (SPEC 9.8): the literal
 * {@code install_requires} and {@code extras_require} of a {@code setup()} call, and the same keys of
 * {@code setup.cfg}. Nothing is evaluated.
 */
public final class SetupManifests {
    /** Manifest label of requirements taken from {@code setup.py} (SPEC 9, 11.4). */
    public static final String SETUP_PY_LABEL = "setup-py";
    /** Text that must occur in a {@code setup.py} for it to declare requirements. */
    public static final List<String> SETUP_PY_KEYWORDS = List.of("install_requires", "extras_require");
    private static final int MAX_DEPTH = 12;

    private SetupManifests() {}

    /** Is the relative path a {@code setup.py} (case-insensitive base name)? */
    public static boolean isSetupPy(String relativePath) {
        int slash = relativePath.lastIndexOf('/');
        return relativePath.substring(slash + 1).toLowerCase(Locale.ROOT).equals("setup.py");
    }

    /** May the text declare requirements (a cheap check before parsing)? */
    public static boolean maybeDeclaresRequirements(String text) {
        for (String k : SETUP_PY_KEYWORDS) {
            if (text.contains(k)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Entries of a parsed {@code setup.py}, in order: for every call of {@code setup},
     * {@code setuptools.setup} or {@code distutils.core.setup} (pre-order), the strings of its
     * {@code install_requires} value, then those of each value of its {@code extras_require} dictionary.
     * A value may be written inline or as a name bound at module level (all such bindings, in order).
     */
    public static List<ManifestEntry> setupPy(SyntaxNode root) {
        Map<String, List<SyntaxNode>> moduleBindings = new HashMap<>();
        for (int i = 0; i < root.childCount(); i++) {
            SyntaxNode st = root.child(i);
            if (!st.is("expression_statement")) {
                continue;
            }
            for (int j = 0; j < st.childCount(); j++) {
                SyntaxNode a = st.child(j);
                SyntaxNode left = a.is("assignment") ? a.field("left") : null;
                SyntaxNode right = left == null ? null : a.field("right");
                if (left != null && left.is("identifier") && right != null) {
                    moduleBindings.computeIfAbsent(left.text(), k -> new ArrayList<>()).add(right);
                }
            }
        }
        List<ManifestEntry> out = new ArrayList<>();
        ArrayDeque<SyntaxNode> stack = new ArrayDeque<>();
        stack.push(root);
        while (!stack.isEmpty()) {
            SyntaxNode n = stack.pop();
            if (n.is("call") && isSetupCall(n)) {
                SyntaxNode args = n.field("arguments");
                SyntaxNode install = keyword(args, "install_requires");
                SyntaxNode extras = keyword(args, "extras_require");
                if (install != null) {
                    requirementStrings(install, moduleBindings, 0, out);
                }
                if (extras != null) {
                    for (SyntaxNode d : values(extras, moduleBindings)) {
                        if (d.is("dictionary")) {
                            for (int i = 0; i < d.childCount(); i++) {
                                SyntaxNode pair = d.child(i);
                                SyntaxNode v = pair.is("pair") ? pair.field("value") : null;
                                if (v != null) {
                                    requirementStrings(v, moduleBindings, 0, out);
                                }
                            }
                        }
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
        return out;
    }

    private static boolean isSetupCall(SyntaxNode call) {
        SyntaxNode f = call.field("function");
        if (f == null) {
            return false;
        }
        if (f.is("identifier")) {
            return f.text().equals("setup");
        }
        if (f.is("attribute")) {
            SyntaxNode a = f.field("attribute");
            SyntaxNode o = f.field("object");
            if (a == null || o == null || !a.text().equals("setup")) {
                return false;
            }
            String obj = Texts.removeWhitespace(o.text());
            return obj.equals("setuptools") || obj.equals("distutils.core");
        }
        return false;
    }

    private static SyntaxNode keyword(SyntaxNode args, String name) {
        if (args == null || !args.is("argument_list")) {
            return null;
        }
        for (int i = 0; i < args.childCount(); i++) {
            SyntaxNode k = args.child(i);
            if (k.is("keyword_argument")) {
                SyntaxNode kn = k.field("name");
                if (kn != null && kn.text().equals(name)) {
                    return k.field("value");
                }
            }
        }
        return null;
    }

    /** The expression itself, or for a module-level name the right-hand sides bound to it. */
    private static List<SyntaxNode> values(SyntaxNode e, Map<String, List<SyntaxNode>> bindings) {
        if (e.is("identifier")) {
            return bindings.getOrDefault(e.text(), List.of());
        }
        return List.of(e);
    }

    private static void requirementStrings(SyntaxNode e, Map<String, List<SyntaxNode>> bindings, int depth,
            List<ManifestEntry> out) {
        if (depth > MAX_DEPTH) {
            return;
        }
        String v = stringValue(e);
        if (v != null) {
            // a direct reference (pkg @ https://…) is skipped as in requirements files (SPEC 9.2)
            if (!v.contains("://")) {
                ManifestEntry m = PythonManifests.pep508(v);
                if (m != null) {
                    out.add(m);
                }
            }
            return;
        }
        if (e.is("identifier") && depth == 0) {
            for (SyntaxNode b : values(e, bindings)) {
                requirementStrings(b, bindings, depth + 1, out);
            }
            return;
        }
        if (e.is("list") || e.is("tuple") || e.is("parenthesized_expression")) {
            for (int i = 0; i < e.childCount(); i++) {
                SyntaxNode c = e.child(i);
                if (c.isNamed() && !c.is("comment")) {
                    requirementStrings(c, bindings, depth + 1, out);
                }
            }
        }
    }

    /** String value as in SPEC 8.5.1 (no bytes, no f-strings, escapes not interpreted). */
    static String stringValue(SyntaxNode n) {
        if (n.is("string")) {
            if (n.childCount() == 0) {
                return null;
            }
            String start = Texts.lower(n.child(0).text());
            if (start.indexOf('b') >= 0 || start.indexOf('f') >= 0) {
                return null;
            }
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < n.childCount(); i++) {
                SyntaxNode c = n.child(i);
                if (c.is("interpolation")) {
                    return null;
                }
                if (c.is("string_content")) {
                    b.append(c.text());
                }
            }
            return b.toString();
        }
        if (n.is("concatenated_string")) {
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < n.childCount(); i++) {
                SyntaxNode c = n.child(i);
                if (!c.isNamed() || c.is("comment")) {
                    continue;
                }
                String v = stringValue(c);
                if (v == null) {
                    return null;
                }
                b.append(v);
            }
            return b.toString();
        }
        return null;
    }

    /**
     * {@code setup.cfg}: the values of {@code install_requires} in section {@code [options]} and of every
     * key of {@code [options.extras_require]}, one PEP 508 requirement per line (a value may start on
     * the key's line and continue on indented lines). Lines starting with {@code #} or {@code ;} are
     * comments; {@code file:} / {@code attr:} directives are not followed.
     */
    static List<ManifestEntry> setupCfg(String text) {
        List<ManifestEntry> out = new ArrayList<>();
        String section = "";
        boolean collecting = false;
        for (String raw : text.split("\n", -1)) {
            String line = raw.endsWith("\r") ? raw.substring(0, raw.length() - 1) : raw;
            String t = line.strip();
            if (t.isEmpty() || t.startsWith("#") || t.startsWith(";")) {
                continue;
            }
            boolean continuation = Character.isWhitespace(line.charAt(0));
            if (!continuation && t.startsWith("[") && t.endsWith("]")) {
                section = t.substring(1, t.length() - 1).strip().toLowerCase(Locale.ROOT);
                collecting = false;
                continue;
            }
            String value;
            if (continuation) {
                if (!collecting) {
                    continue;
                }
                value = t;
            } else {
                int eq = indexOfSeparator(t);
                if (eq < 0) {
                    collecting = false;
                    continue;
                }
                String key = t.substring(0, eq).strip().toLowerCase(Locale.ROOT).replace('-', '_');
                collecting = (section.equals("options") && key.equals("install_requires"))
                        || section.equals("options.extras_require");
                value = t.substring(eq + 1).strip();
            }
            if (!collecting || value.isEmpty() || value.startsWith("file:") || value.startsWith("attr:")) {
                continue;
            }
            value = PythonManifests.stripComment(value).strip();
            if (value.isEmpty() || value.contains("://")) {
                continue;
            }
            ManifestEntry m = PythonManifests.pep508(value);
            if (m != null) {
                out.add(m);
            }
        }
        return out;
    }

    /** Position of the first {@code =} or {@code :} that separates key and value, or -1. */
    private static int indexOfSeparator(String t) {
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == '=' || c == ':') {
                return i;
            }
        }
        return -1;
    }
}
