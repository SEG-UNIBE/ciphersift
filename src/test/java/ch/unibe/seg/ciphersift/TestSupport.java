/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.stream.Stream;

/** Shared test helpers: project paths and the conformance normalisation (spec/conformance/README.md). */
public final class TestSupport {
    public static final ObjectMapper JSON = new ObjectMapper();

    static final List<String> SOURCE_FIELDS = List.of("file", "line", "rule", "type", "subtype", "primitive",
            "family", "variant", "protocol", "version", "param", "oid", "name", "via", "origin", "test");
    static final List<String> DEP_FIELDS = List.of("file", "line", "rule", "type", "ecosystem", "package", "version",
            "test");

    private TestSupport() {}

    /** The project base directory. */
    public static Path baseDir() {
        String p = System.getProperty("ciphersift.basedir");
        if (p != null) {
            return Path.of(p);
        }
        Path cwd = Path.of("").toAbsolutePath();
        while (cwd != null && !Files.exists(cwd.resolve("spec/SPEC.md"))) {
            cwd = cwd.getParent();
        }
        if (cwd == null) {
            throw new IllegalStateException("project base directory not found");
        }
        return cwd;
    }

    public static Path casesDir() {
        return baseDir().resolve("spec/conformance/cases");
    }

    /** All conformance cases as relative names ({@code java/selection}), sorted. */
    public static List<String> cases() throws IOException {
        List<String> out = new ArrayList<>();
        Path root = casesDir();
        try (Stream<Path> s = Files.walk(root)) {
            s.filter(p -> p.getFileName().toString().equals("expected.json"))
                    .forEach(p -> out.add(root.relativize(p.getParent()).toString().replace('\\', '/')));
        }
        out.sort(null);
        return out;
    }

    /** Extra CLI arguments of a case (options.json). */
    public static List<String> caseArgs(String c) throws IOException {
        Path opt = casesDir().resolve(c).resolve("options.json");
        List<String> l = new ArrayList<>();
        if (Files.exists(opt)) {
            for (JsonNode a : JSON.readTree(opt.toFile()).path("args")) {
                l.add(a.asText());
            }
        }
        return l;
    }

    /** Expected findings of a case as canonical strings. */
    public static List<String> expected(String c) throws IOException {
        JsonNode e = JSON.readTree(casesDir().resolve(c).resolve("expected.json").toFile());
        List<String> l = new ArrayList<>();
        for (JsonNode f : e.path("findings")) {
            Map<String, Object> m = new HashMap<>();
            f.properties().iterator().forEachRemaining(kv -> m.put(kv.getKey(), value(kv.getValue())));
            l.add(key(m));
        }
        return l;
    }

    private static Object value(JsonNode n) {
        if (n == null || n.isNull() || n.isMissingNode()) {
            return null;
        }
        if (n.isInt() || n.isLong()) {
            return n.asLong();
        }
        if (n.isBoolean()) {
            return n.asBoolean();
        }
        if (n.isArray()) {
            List<String> l = new ArrayList<>();
            n.forEach(x -> l.add(x.asText()));
            return l.toString();
        }
        return n.asText();
    }

    /** Canonical key of a normalised finding: all fields of its kind, missing ones as null. */
    static String key(Map<String, Object> m) {
        List<String> fields = "library".equals(m.get("type")) ? DEP_FIELDS : SOURCE_FIELDS;
        Map<String, Object> k = new LinkedHashMap<>();
        for (String f : fields) {
            k.put(f, m.get(f));
        }
        return k.toString();
    }

    /** Normalises a CBOM into the finding list (spec/conformance/README.md, "How to compare"). */
    public static List<String> normalise(byte[] cbom) throws IOException {
        JsonNode doc = JSON.readTree(cbom);
        List<String> out = new ArrayList<>();
        for (JsonNode comp : doc.path("components")) {
            Map<String, String> props = new HashMap<>();
            for (JsonNode p : comp.path("properties")) {
                props.put(p.path("name").asText(), p.path("value").asText());
            }
            for (JsonNode occ : comp.path("evidence").path("occurrences")) {
                JsonNode ctx = JSON.readTree(occ.path("additionalContext").asText());
                Map<String, Object> f = new HashMap<>();
                f.put("file", occ.path("location").asText());
                f.put("line", occ.has("line") ? occ.path("line").asLong() : null);
                f.put("rule", ctx.path("ruleId").asText());
                if (ctx.path("test").asBoolean(false)) {
                    f.put("test", true);
                }
                // wrapper propagation (SPEC 18.7, 11.4)
                f.put("via", value(ctx.get("via")));
                f.put("origin", value(ctx.get("origin")));
                if ("library".equals(comp.path("type").asText())) {
                    String eco = props.get("ciphersift:ecosystem");
                    f.put("type", "library");
                    f.put("ecosystem", eco);
                    f.put("package", "maven".equals(eco) ? comp.path("group").asText() + ":" + comp.path("name").asText()
                            : comp.path("name").asText());
                    f.put("version", comp.has("version") ? comp.path("version").asText() : null);
                } else {
                    JsonNode cp = comp.path("cryptoProperties");
                    String type = props.getOrDefault("ciphersift:assetType", cp.path("assetType").asText());
                    f.put("type", type);
                    f.put("subtype", props.get("ciphersift:subtype"));
                    f.put("primitive", props.get("ciphersift:primitive"));
                    f.put("family", props.get("ciphersift:family"));
                    f.put("variant", props.get("ciphersift:variant"));
                    JsonNode proto = cp.path("protocolProperties");
                    f.put("protocol", proto.has("type") ? proto.path("type").asText() : null);
                    f.put("version", proto.has("version") ? proto.path("version").asText() : null);
                    JsonNode alg = cp.path("algorithmProperties");
                    f.put("param", alg.has("parameterSetIdentifier") ? alg.path("parameterSetIdentifier").asText()
                            : null);
                    f.put("oid", cp.has("oid") ? cp.path("oid").asText() : null);
                    f.put("name", "algorithm".equals(type) ? comp.path("name").asText() : null);
                }
                out.add(key(f));
            }
        }
        return out;
    }

    /** Differences between the normalised CBOM and the expectation; empty if the case passes. */
    public static List<String> compare(List<String> got, List<String> expected) {
        TreeSet<String> g = new TreeSet<>(got);
        TreeSet<String> e = new TreeSet<>(expected);
        List<String> msgs = new ArrayList<>();
        for (String x : e) {
            if (!g.contains(x)) {
                msgs.add("missing:    " + x);
            }
        }
        for (String x : g) {
            if (!e.contains(x)) {
                msgs.add("unexpected: " + x);
            }
        }
        if (got.size() != g.size()) {
            msgs.add((got.size() - g.size()) + " duplicate occurrence(s)");
        }
        return msgs;
    }

    public static String read(Path p) throws IOException {
        return Files.readString(p, StandardCharsets.UTF_8);
    }

    /** Recursively copies a directory tree. */
    public static void copyTree(Path from, Path to) throws IOException {
        try (Stream<Path> s = Files.walk(from)) {
            for (Path p : (Iterable<Path>) s::iterator) {
                Path t = to.resolve(from.relativize(p).toString());
                if (Files.isDirectory(p)) {
                    Files.createDirectories(t);
                } else {
                    Files.createDirectories(t.getParent());
                    Files.copy(p, t);
                }
            }
        }
    }
}
