/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.deps;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/** Maven and Gradle manifests (SPEC 9.5–9.7). */
final class MavenManifests {
    /** SPEC 9.6 step 3. */
    static final Pattern COORDINATE = Pattern.compile(
            "^([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)(?::([^:@\\s]+))?(?::[^:@\\s]+)?(?:@[A-Za-z0-9]+)?$");
    /** SPEC 9.6 step 4 (reference; {@link MapNotation} computes the same matches without backtracking). */
    static final Pattern MAP_NOTATION = Pattern.compile(
            "group\\s*[:=]\\s*(['\"])(.+?)\\1\\s*,\\s*name\\s*[:=]\\s*(['\"])(.+?)\\3"
                    + "(?:\\s*,\\s*version\\s*[:=]\\s*(['\"])(.+?)\\5)?");
    private static final Pattern VARIABLE = Pattern.compile(
            "\\b(?:val|var|def)\\s+([A-Za-z_][A-Za-z0-9_]*)(?:\\s*:\\s*String)?\\s*=\\s*(?:\"([^\"$\\n]*)\"|'([^'$\\n]*)')");
    private static final Pattern EXT_VARIABLE = Pattern.compile(
            "\\bext\\.([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(?:\"([^\"$\\n]*)\"|'([^'$\\n]*)')");
    private static final Pattern REFERENCE = Pattern.compile(
            "\\$\\{([A-Za-z_][A-Za-z0-9_]*)\\}|\\$([A-Za-z_][A-Za-z0-9_]*)");
    private static final Pattern PROPERTY = Pattern.compile("\\$\\{([^}]*)\\}");

    private MavenManifests() {}

    static ManifestEntry entry(String group, String artifact, String version) {
        String g = group.strip();
        String a = artifact.strip();
        String v = version == null ? null : version.strip();
        if (v != null && (v.isEmpty() || isRange(v))) {
            v = null;
        }
        String key = g + ":" + a;
        return new ManifestEntry(key, v, v == null ? key : key + ":" + v);
    }

    /**
     * Version ranges and dynamic versions are never reported (SPEC 9.1): Maven ranges
     * ({@code [1.0,2.0)}, {@code (,1.0]}), Gradle dynamic versions ({@code 1.+}, {@code +},
     * {@code latest.release}).
     */
    static boolean isRange(String v) {
        return v.startsWith("[") || v.startsWith("(") || v.endsWith("]") || v.endsWith(")") || v.indexOf(',') >= 0
                || v.endsWith("+") || v.startsWith("latest.");
    }

    // ------------------------------------------------------------------ pom.xml (9.5)

    static List<ManifestEntry> pom(byte[] bytes) throws IOException {
        Document doc = parseXml(bytes);
        Element root = doc.getDocumentElement();
        Map<String, String> props = new HashMap<>();
        Element properties = child(root, "properties");
        if (properties != null) {
            for (Element p : children(properties)) {
                props.put(local(p), p.getTextContent().strip());
            }
        }
        Element parent = child(root, "parent");
        String rootVersion = childText(root, "version");
        String parentVersion = parent == null ? null : childText(parent, "version");
        String rootGroup = childText(root, "groupId");
        String parentGroup = parent == null ? null : childText(parent, "groupId");
        String projectVersion = rootVersion != null ? rootVersion : parentVersion;
        String projectGroup = rootGroup != null ? rootGroup : parentGroup;
        if (projectVersion != null) {
            props.put("project.version", projectVersion);
            props.put("version", projectVersion);
        }
        if (projectGroup != null) {
            props.put("project.groupId", projectGroup);
        }
        if (parentVersion != null) {
            props.put("project.parent.version", parentVersion);
        }
        List<ManifestEntry> out = new ArrayList<>();
        List<Element> deps = new ArrayList<>();
        collect(root, "dependency", deps);
        for (Element d : deps) {
            String g = childText(d, "groupId");
            String a = childText(d, "artifactId");
            if (g == null || g.isEmpty() || a == null || a.isEmpty()) {
                continue;
            }
            String v = childText(d, "version");
            if (v != null) {
                v = substitute(v, props);
            }
            out.add(entry(g, a, v));
        }
        return out;
    }

    private static String substitute(String v, Map<String, String> props) {
        String cur = v;
        for (int round = 0; round < 10 && cur.contains("${"); round++) {
            Matcher m = PROPERTY.matcher(cur);
            StringBuilder b = new StringBuilder();
            boolean changed = false;
            while (m.find()) {
                String val = props.get(m.group(1));
                if (val != null) {
                    changed = true;
                    m.appendReplacement(b, Matcher.quoteReplacement(val));
                } else {
                    m.appendReplacement(b, Matcher.quoteReplacement(m.group()));
                }
            }
            m.appendTail(b);
            cur = b.toString();
            if (!changed) {
                break;
            }
        }
        if (cur.contains("${")) {
            return null;
        }
        cur = cur.strip();
        return cur.isEmpty() ? null : cur;
    }

    private static Document parseXml(byte[] bytes) throws IOException {
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setNamespaceAware(false);
            f.setValidating(false);
            f.setExpandEntityReferences(false);
            f.setXIncludeAware(false);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setFeature("http://xml.org/sax/features/external-general-entities", false);
            f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            DocumentBuilder b = f.newDocumentBuilder();
            b.setErrorHandler(new ErrorHandler() {
                @Override
                public void warning(SAXParseException e) {
                    // ignore
                }

                @Override
                public void error(SAXParseException e) throws SAXException {
                    throw e;
                }

                @Override
                public void fatalError(SAXParseException e) throws SAXException {
                    throw e;
                }
            });
            b.setEntityResolver((publicId, systemId) -> {
                throw new SAXException("external entities are not allowed");
            });
            return b.parse(new ByteArrayInputStream(bytes));
        } catch (ParserConfigurationException | SAXException ex) {
            throw new IOException(ex.getMessage(), ex);
        }
    }

    static String local(Node n) {
        String name = n.getNodeName();
        int c = name.indexOf(':');
        return c < 0 ? name : name.substring(c + 1);
    }

    private static List<Element> children(Element e) {
        List<Element> l = new ArrayList<>();
        NodeList nl = e.getChildNodes();
        for (int i = 0; i < nl.getLength(); i++) {
            if (nl.item(i) instanceof Element c) {
                l.add(c);
            }
        }
        return l;
    }

    private static Element child(Element e, String name) {
        for (Element c : children(e)) {
            if (local(c).equals(name)) {
                return c;
            }
        }
        return null;
    }

    private static String childText(Element e, String name) {
        Element c = child(e, name);
        return c == null ? null : c.getTextContent().strip();
    }

    private static void collect(Element root, String name, List<Element> out) {
        java.util.ArrayDeque<Element> stack = new java.util.ArrayDeque<>();
        stack.push(root);
        while (!stack.isEmpty()) {
            Element e = stack.pop();
            if (local(e).equals(name)) {
                out.add(e);
            }
            List<Element> cs = children(e);
            for (int i = cs.size() - 1; i >= 0; i--) {
                stack.push(cs.get(i));
            }
        }
    }

    // ------------------------------------------------------------------ Gradle scripts (9.6)

    /** A string literal of the comment-free text. */
    private record Literal(int start, String content, boolean triple) {}

    static List<ManifestEntry> gradle(String text) {
        List<Literal> literals = new ArrayList<>();
        String clean = stripComments(text, literals);
        Map<String, String> vars = new HashMap<>();
        // variables in order of appearance; later definitions replace earlier ones
        List<int[]> spans = new ArrayList<>();
        List<String[]> defs = new ArrayList<>();
        for (Pattern p : List.of(VARIABLE, EXT_VARIABLE)) {
            Matcher m = p.matcher(clean);
            while (m.find()) {
                String val = m.group(2) != null ? m.group(2) : m.group(3);
                spans.add(new int[] {m.start(), defs.size()});
                defs.add(new String[] {m.group(1), val});
            }
        }
        spans.sort((a, b) -> Integer.compare(a[0], b[0]));
        for (int[] s : spans) {
            String[] d = defs.get(s[1]);
            vars.put(d[0], d[1]);
        }
        record Positioned(int start, ManifestEntry entry) {}
        List<Positioned> found = new ArrayList<>();
        for (Literal l : literals) {
            if (l.triple()) {
                continue;
            }
            String v = substituteVariables(l.content(), vars);
            ManifestEntry e = coordinate(v);
            if (e != null) {
                found.add(new Positioned(l.start(), e));
            }
        }
        // same matches as MAP_NOTATION.matcher(clean).find(), in linear-logarithmic time
        for (MapNotation.Match m : MapNotation.findAll(clean)) {
            String g = substituteVariables(m.group(), vars);
            String a = substituteVariables(m.name(), vars);
            String v = m.version() == null ? null : substituteVariables(m.version(), vars);
            if (g.indexOf('$') >= 0 || a.indexOf('$') >= 0) {
                continue;
            }
            if (v != null && v.indexOf('$') >= 0) {
                v = null;
            }
            found.add(new Positioned(m.start(), entry(g, a, v)));
        }
        found.sort((x, y) -> Integer.compare(x.start(), y.start()));
        List<ManifestEntry> out = new ArrayList<>();
        for (Positioned p : found) {
            out.add(p.entry());
        }
        return out;
    }

    /** A {@code g:a[:v]} coordinate string (SPEC 9.6 step 3), or null. */
    static ManifestEntry coordinate(String s) {
        Matcher m = COORDINATE.matcher(s);
        if (!m.matches()) {
            return null;
        }
        String v = m.group(3);
        if (v != null && v.indexOf('$') >= 0) {
            v = null;
        }
        return entry(m.group(1), m.group(2), v);
    }

    private static String substituteVariables(String s, Map<String, String> vars) {
        if (s.indexOf('$') < 0) {
            return s;
        }
        Matcher m = REFERENCE.matcher(s);
        StringBuilder b = new StringBuilder();
        while (m.find()) {
            String name = m.group(1) != null ? m.group(1) : m.group(2);
            String val = vars.get(name);
            m.appendReplacement(b, Matcher.quoteReplacement(val != null ? val : m.group()));
        }
        m.appendTail(b);
        return b.toString();
    }

    /**
     * Removes {@code //} and {@code /* *}{@code /} comments outside string literals (each comment becomes
     * one space; line breaks are kept) and records the string literals with their offsets in the
     * returned text.
     */
    static String stripComments(String t, List<Literal> literals) {
        StringBuilder out = new StringBuilder(t.length());
        int i = 0;
        int n = t.length();
        while (i < n) {
            char c = t.charAt(i);
            if (c == '/' && i + 1 < n && t.charAt(i + 1) == '/') {
                int e = i;
                while (e < n && t.charAt(e) != '\n') {
                    e++;
                }
                out.append(' ');
                i = e;
                continue;
            }
            if (c == '/' && i + 1 < n && t.charAt(i + 1) == '*') {
                int e = t.indexOf("*/", i + 2);
                e = e < 0 ? n : e + 2;
                out.append(' ');
                i = e;
                continue;
            }
            if (c == '"' || c == '\'') {
                boolean triple = i + 2 < n && t.charAt(i + 1) == c && t.charAt(i + 2) == c;
                int startOut = out.length();
                int contentStart = i + (triple ? 3 : 1);
                int k = contentStart;
                int contentEnd = -1;
                while (k < n) {
                    char d = t.charAt(k);
                    if (d == '\\' && k + 1 < n) {
                        k += 2;
                        continue;
                    }
                    if (triple) {
                        if (d == c && k + 2 < n && t.charAt(k + 1) == c && t.charAt(k + 2) == c) {
                            contentEnd = k;
                            k += 3;
                            break;
                        }
                    } else {
                        if (d == c) {
                            contentEnd = k;
                            k++;
                            break;
                        }
                        if (d == '\n') {
                            break; // unterminated single-line literal
                        }
                    }
                    k++;
                }
                if (contentEnd < 0) {
                    // unterminated: copy the quote and continue scanning after it
                    out.append(c);
                    i++;
                    continue;
                }
                out.append(t, i, k);
                literals.add(new Literal(startOut, t.substring(contentStart, contentEnd), triple));
                i = k;
                continue;
            }
            out.append(c);
            i++;
        }
        return out.toString();
    }

    // ------------------------------------------------------------------ version catalogs (9.7)

    static List<ManifestEntry> versionCatalog(String text) throws IOException {
        JsonNode root = PythonManifests.TOML.readTree(text);
        Map<String, String> versions = new HashMap<>();
        JsonNode vs = root.path("versions");
        if (vs.isObject()) {
            for (Iterator<Map.Entry<String, JsonNode>> it = vs.properties().iterator(); it.hasNext();) {
                Map.Entry<String, JsonNode> e = it.next();
                String v = richVersion(e.getValue());
                if (v != null) {
                    versions.put(e.getKey(), v);
                }
            }
        }
        List<ManifestEntry> out = new ArrayList<>();
        JsonNode libs = root.path("libraries");
        if (!libs.isObject()) {
            return out;
        }
        for (Iterator<Map.Entry<String, JsonNode>> it = libs.properties().iterator(); it.hasNext();) {
            JsonNode lib = it.next().getValue();
            if (lib.isTextual()) {
                ManifestEntry e = coordinate(lib.asText());
                if (e != null) {
                    out.add(e);
                }
                continue;
            }
            if (!lib.isObject()) {
                continue;
            }
            String group = null;
            String name = null;
            JsonNode module = lib.path("module");
            if (module.isTextual()) {
                String mod = module.asText();
                int c = mod.indexOf(':');
                if (c > 0 && c < mod.length() - 1 && mod.indexOf(':', c + 1) < 0) {
                    group = mod.substring(0, c);
                    name = mod.substring(c + 1);
                }
            } else if (lib.path("group").isTextual() && lib.path("name").isTextual()) {
                group = lib.path("group").asText();
                name = lib.path("name").asText();
            }
            if (group == null || name == null || group.isBlank() || name.isBlank()) {
                continue;
            }
            String version = null;
            JsonNode v = lib.path("version");
            if (v.isTextual()) {
                version = v.asText();
            } else if (v.isObject()) {
                if (v.path("ref").isTextual()) {
                    version = versions.get(v.path("ref").asText());
                } else {
                    version = richVersion(v);
                }
            }
            out.add(entry(group, name, version));
        }
        return out;
    }

    private static String richVersion(JsonNode v) {
        if (v.isTextual()) {
            return v.asText();
        }
        if (v.isObject()) {
            for (String k : List.of("strictly", "require", "prefer")) {
                if (v.path(k).isTextual()) {
                    return v.path(k).asText();
                }
            }
        }
        return null;
    }
}
