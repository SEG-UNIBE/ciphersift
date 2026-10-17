/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.deps;

import java.util.ArrayList;
import java.util.List;

/** Go module manifests {@code go.mod} and {@code go.sum} (SPEC 17.10). */
public final class GoManifests {
    private GoManifests() {}

    /** The {@code require} entries of a {@code go.mod}, in file order. */
    public static List<ManifestEntry> goMod(String text) {
        List<ManifestEntry> out = new ArrayList<>();
        String block = null; // directive of the open "( … )" block, or null
        for (String raw : text.split("\n", -1)) {
            String line = raw.endsWith("\r") ? raw.substring(0, raw.length() - 1) : raw;
            int c = line.indexOf("//");
            if (c >= 0) {
                line = line.substring(0, c);
            }
            line = line.strip();
            if (line.isEmpty()) {
                continue;
            }
            if (block != null) {
                if (line.equals(")")) {
                    block = null;
                } else if (block.equals("require")) {
                    entry(line, out);
                }
                continue;
            }
            if (line.matches("[A-Za-z]+\\(.*")) {
                line = line.replaceFirst("\\(", " ("); // "require(" as "require ("
            }
            String[] t = line.split("\\s+", 2);
            String directive = t[0];
            String rest = t.length > 1 ? t[1].strip() : "";
            if (rest.equals("(")) {
                block = directive;
            } else if (directive.equals("require")) {
                entry(rest, out);
            }
        }
        return out;
    }

    /** {@code PATH VERSION} (the path optionally quoted). */
    private static void entry(String s, List<ManifestEntry> out) {
        String[] t = s.split("\\s+");
        if (t.length < 2) {
            return;
        }
        String path = unquote(t[0]);
        String version = t[1];
        if (path.isEmpty() || version.isEmpty()) {
            return;
        }
        out.add(new ManifestEntry(path, version, path + "@" + version));
    }

    private static String unquote(String s) {
        if (s.length() >= 2 && ((s.startsWith("\"") && s.endsWith("\"")) || (s.startsWith("`") && s.endsWith("`")))) {
            return s.substring(1, s.length() - 1);
        }
        return s;
    }

    /**
     * The modules of a {@code go.sum}: one entry per line {@code PATH VERSION HASH}, except the lines for
     * a module's {@code go.mod} only ({@code VERSION} ending with {@code /go.mod}).
     */
    public static List<ManifestEntry> goSum(String text) {
        List<ManifestEntry> out = new ArrayList<>();
        for (String raw : text.split("\n", -1)) {
            String[] t = raw.strip().split("\\s+");
            if (t.length < 3 || t[1].endsWith("/go.mod")) {
                continue;
            }
            out.add(new ManifestEntry(t[0], t[1], t[0] + "@" + t[1]));
        }
        return out;
    }
}
