/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.deps;

import ch.unibe.seg.ciphersift.util.Texts;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** PyPI manifests (SPEC 9.2–9.4). */
final class PythonManifests {
    /** SPEC 9.2. */
    static final Pattern PEP508 = Pattern.compile(
            "^\\s*([A-Za-z0-9][A-Za-z0-9._-]*)\\s*(\\[[^\\]]*\\])?\\s*(?:\\(?\\s*(===|==|~=|>=|<=|!=|>|<)\\s*([^\\s;,)]+))?");
    /** SPEC 9.3: exact Poetry version. */
    static final Pattern POETRY_EXACT = Pattern.compile("^=?=?\\s*(\\d[^\\s,*]*)$");
    private static final Pattern NORMALISE = Pattern.compile("[-_.]+");

    static final TomlMapper TOML = new TomlMapper();
    static final ObjectMapper JSON = new ObjectMapper();

    private PythonManifests() {}

    /** PEP 503 normalised name. */
    static String normalise(String name) {
        return NORMALISE.matcher(Texts.lower(name)).replaceAll("-");
    }

    static ManifestEntry entry(String rawName, String version) {
        String key = normalise(rawName);
        String v = version == null ? null : version.strip();
        if (v != null && v.isEmpty()) {
            v = null;
        }
        return new ManifestEntry(key, v, v == null ? key : key + "==" + v);
    }

    /** Parses the start of a PEP 508 string, or {@code null} if it does not match. */
    static ManifestEntry pep508(String s) {
        Matcher m = PEP508.matcher(s);
        if (!m.lookingAt()) {
            return null;
        }
        String op = m.group(3);
        String ver = m.group(4);
        String version = ("==".equals(op) || "===".equals(op)) && ver != null && ver.indexOf('*') < 0 ? ver : null;
        return entry(m.group(1), version);
    }

    /** {@code requirements*.txt} (SPEC 9.2). */
    static List<ManifestEntry> requirements(String text) {
        List<ManifestEntry> out = new ArrayList<>();
        String[] raw = text.split("\n", -1);
        List<String> lines = new ArrayList<>();
        StringBuilder cur = null;
        for (String r : raw) {
            String l = r.endsWith("\r") ? r.substring(0, r.length() - 1) : r;
            if (l.endsWith("\\")) {
                if (cur == null) {
                    cur = new StringBuilder();
                }
                cur.append(l, 0, l.length() - 1);
                continue;
            }
            if (cur != null) {
                cur.append(l);
                lines.add(cur.toString());
                cur = null;
            } else {
                lines.add(l);
            }
        }
        if (cur != null) {
            lines.add(cur.toString());
        }
        for (String line : lines) {
            String l = stripComment(line).strip();
            if (l.isEmpty() || l.startsWith("-") || l.contains("://")) {
                continue;
            }
            ManifestEntry e = pep508(l);
            if (e != null) {
                out.add(e);
            }
        }
        return out;
    }

    /** Removes a comment starting with {@code #} at the beginning of the line or after whitespace. */
    static String stripComment(String line) {
        for (int i = 0; i < line.length(); i++) {
            if (line.charAt(i) == '#' && (i == 0 || Character.isWhitespace(line.charAt(i - 1)))) {
                return line.substring(0, i);
            }
        }
        return line;
    }

    /** {@code pyproject.toml} (SPEC 9.3). */
    static List<ManifestEntry> pyproject(String text) throws IOException {
        JsonNode root = TOML.readTree(text);
        List<ManifestEntry> out = new ArrayList<>();
        JsonNode project = root.path("project");
        pep508Array(project.path("dependencies"), out);
        JsonNode opt = project.path("optional-dependencies");
        if (opt.isObject()) {
            for (Iterator<JsonNode> it = opt.elements(); it.hasNext();) {
                pep508Array(it.next(), out);
            }
        }
        JsonNode groups = root.path("dependency-groups");
        if (groups.isObject()) {
            for (Iterator<JsonNode> it = groups.elements(); it.hasNext();) {
                pep508Array(it.next(), out);
            }
        }
        JsonNode poetry = root.path("tool").path("poetry");
        poetryTable(poetry.path("dependencies"), out);
        poetryTable(poetry.path("dev-dependencies"), out);
        JsonNode pg = poetry.path("group");
        if (pg.isObject()) {
            for (Iterator<JsonNode> it = pg.elements(); it.hasNext();) {
                poetryTable(it.next().path("dependencies"), out);
            }
        }
        return out;
    }

    private static void pep508Array(JsonNode arr, List<ManifestEntry> out) {
        if (!arr.isArray()) {
            return;
        }
        for (JsonNode s : arr) {
            // a direct reference (pkg @ https://…) is skipped as in requirements files (DECISIONS O5)
            if (s.isTextual() && !s.asText().contains("://")) {
                ManifestEntry e = pep508(s.asText());
                if (e != null) {
                    out.add(e);
                }
            }
        }
    }

    private static void poetryTable(JsonNode table, List<ManifestEntry> out) {
        if (!table.isObject()) {
            return;
        }
        for (Iterator<Map.Entry<String, JsonNode>> it = table.properties().iterator(); it.hasNext();) {
            Map.Entry<String, JsonNode> e = it.next();
            String name = e.getKey();
            if (name.equals("python")) {
                continue;
            }
            JsonNode v = e.getValue();
            String constraint = null;
            if (v.isTextual()) {
                constraint = v.asText();
            } else if (v.isObject() && v.path("version").isTextual()) {
                constraint = v.path("version").asText();
            }
            String version = null;
            if (constraint != null) {
                Matcher m = POETRY_EXACT.matcher(constraint.strip());
                if (m.matches()) {
                    version = m.group(1);
                }
            }
            out.add(entry(name, version));
        }
    }

    /**
     * {@code Pipfile} (SPEC 9.4, DECISIONS B-G2): the TOML tables {@code [packages]} and {@code [dev-packages]},
     * name → version specifier string or table with {@code version}; an exact pin ({@code ==X}) gives the
     * version (https://pipenv.pypa.io/en/latest/pipfile.html).
     */
    static List<ManifestEntry> pipfile(String text) throws IOException {
        JsonNode root = TOML.readTree(text);
        List<ManifestEntry> out = new ArrayList<>();
        poetryTable(root.path("packages"), out);
        poetryTable(root.path("dev-packages"), out);
        return out;
    }

    /** {@code Pipfile.lock} (SPEC 9.4). */
    static List<ManifestEntry> pipfileLock(String text) throws IOException {
        JsonNode root = JSON.readTree(text);
        if (root == null || !root.isObject()) {
            throw new IOException("not a JSON object");
        }
        List<ManifestEntry> out = new ArrayList<>();
        for (String section : List.of("default", "develop")) {
            JsonNode s = root.path(section);
            if (!s.isObject()) {
                continue;
            }
            for (Iterator<Map.Entry<String, JsonNode>> it = s.properties().iterator(); it.hasNext();) {
                Map.Entry<String, JsonNode> e = it.next();
                JsonNode v = e.getValue().path("version");
                String version = null;
                if (v.isTextual()) {
                    String t = v.asText();
                    int i = 0;
                    while (i < t.length() && t.charAt(i) == '=') {
                        i++;
                    }
                    version = t.substring(i);
                }
                out.add(entry(e.getKey(), version));
            }
        }
        return out;
    }

    /** {@code poetry.lock} (SPEC 9.4). */
    static List<ManifestEntry> poetryLock(String text) throws IOException {
        JsonNode root = TOML.readTree(text);
        List<ManifestEntry> out = new ArrayList<>();
        JsonNode pkgs = root.path("package");
        if (pkgs.isArray()) {
            for (JsonNode p : pkgs) {
                JsonNode name = p.path("name");
                if (!name.isTextual()) {
                    continue;
                }
                JsonNode v = p.path("version");
                out.add(entry(name.asText(), v.isTextual() ? v.asText() : null));
            }
        }
        return out;
    }
}
