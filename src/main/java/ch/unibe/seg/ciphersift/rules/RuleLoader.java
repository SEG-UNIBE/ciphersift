/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.rules;

import ch.unibe.seg.ciphersift.util.Texts;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLParser;
import com.networknt.schema.Error;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;
import com.networknt.schema.path.NodePath;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Loads rule documents, validates them (SPEC 5.8) and compiles them into a {@link RuleSet}. */
public final class RuleLoader {
    /** Resource prefix of the bundled rule set in the jar. */
    public static final String BUNDLED_PREFIX = "rules/";
    private static final String SCHEMA_RESOURCE = "schema/rule-schema.json";
    private static final String SCHEMA_ID = "https://ciphersift.example/schema/rule-1.json";
    private static final int CI = Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE;


    private RuleLoader() {}

    /** A rule file: path relative to the rule directory ({@code /}-separated) and its bytes. */
    public record RuleFile(String path, byte[] bytes) {}

    /**
     * Resources written at build time by {@link BundledRulesCheck} after the bundled rules passed the
     * full validation (SPEC 5.8): the parsed documents as one JSON array ({@code [{"path":…,"doc":…},…]},
     * in file order), and the {@link #validationKey} of exactly those rule files, that schema and that
     * array.
     */
    static final String VALIDATED_RESOURCE = "ch/unibe/seg/ciphersift/rules/bundled-rules.validated";
    static final String BUNDLE_RESOURCE = "ch/unibe/seg/ciphersift/rules/bundled-rules.json";

    /**
     * Loads the bundled rules. If they are byte-identical to the set that was fully validated when the
     * jar was built (same {@link #validationKey}), neither the YAML parsing nor the JSON-schema
     * validation is repeated: the documents are read from the pre-parsed JSON array, and the semantic
     * checks and the compilation run as usual. Otherwise (no build marker, or a modified jar) the rules
     * are validated in full like a {@code --rules} directory.
     */
    public static RuleSet loadBundled() throws RuleException {
        java.util.concurrent.FutureTask<RuleSet> pending = PREFETCHED.getAndSet(null);
        if (pending != null) {
            try {
                return pending.get();
            } catch (java.util.concurrent.ExecutionException ex) {
                Throwable c = ex.getCause();
                if (c instanceof RuleException re) {
                    throw re;
                }
                if (c instanceof RuntimeException re) {
                    throw re;
                }
                if (c instanceof java.lang.Error er) {
                    throw er;
                }
                throw new IllegalStateException(c);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                // fall through: load on this thread
            }
        }
        return loadBundledNow();
    }

    private static final java.util.concurrent.atomic.AtomicReference<java.util.concurrent.FutureTask<RuleSet>>
            PREFETCHED = new java.util.concurrent.atomic.AtomicReference<>();

    /**
     * Starts loading the bundled rules on a background thread; the next {@link #loadBundled} call
     * returns that result (or throws its exception). A start-up optimisation without side effects:
     * the command-line parsing and the rule loading overlap.
     */
    public static void prefetchBundled() {
        java.util.concurrent.FutureTask<RuleSet> task = new java.util.concurrent.FutureTask<>(RuleLoader::loadBundledNow);
        if (PREFETCHED.compareAndSet(null, task)) {
            Thread t = new Thread(task, "ciphersift-rules");
            t.setDaemon(true);
            t.start();
        }
    }

    private static RuleSet loadBundledNow() throws RuleException {
        List<RuleFile> files = bundledFiles();
        String marker = resourceText(VALIDATED_RESOURCE);
        if (marker != null) {
            byte[] schema = resourceBytes(SCHEMA_RESOURCE);
            byte[] bundle = resourceBytes(BUNDLE_RESOURCE);
            if (schema != null && bundle != null && marker.strip().equals(validationKey(files, schema, bundle))) {
                RuleSet trusted = loadTrusted(files, bundle);
                if (trusted != null) {
                    return trusted;
                }
            }
        }
        return load(files);
    }

    /**
     * The key of a validated rule set: {@code sha256:<hex>} over the rules-digest input (SPEC 11.6) of
     * the rule files followed by the schema and the pre-parsed bundle.
     */
    static String validationKey(List<RuleFile> files, byte[] schema, byte[] bundle) {
        List<RuleFile> all = new ArrayList<>(files);
        all.add(new RuleFile("\u0000schema", schema));
        all.add(new RuleFile("\u0000bundle", bundle));
        return digest(all);
    }

    private static String resourceText(String name) {
        byte[] b = resourceBytes(name);
        return b == null ? null : new String(b, StandardCharsets.UTF_8);
    }

    static byte[] resourceBytes(String name) {
        try (InputStream in = RuleLoader.class.getClassLoader().getResourceAsStream(name)) {
            return in == null ? null : in.readAllBytes();
        } catch (IOException ex) {
            return null;
        }
    }

    /**
     * Compiles rule files that are known to be schema-valid from their pre-parsed documents (no
     * YAML parsing, no schema validation). Returns null if the bundle does not fit the files or
     * anything unexpected happens, so that the caller can fall back to the full validation.
     */
    static RuleSet loadTrusted(List<RuleFile> files, byte[] bundle) {
        try {
            List<Map.Entry<String, JsonNode>> parsed = TreeReader.readBundle(bundle);
            if (parsed.size() != files.size()) {
                return null;
            }
            List<Map.Entry<RuleFile, JsonNode>> docs = new ArrayList<>(files.size());
            for (int i = 0; i < files.size(); i++) {
                if (!parsed.get(i).getKey().equals(files.get(i).path())) {
                    return null;
                }
                docs.add(Map.entry(files.get(i), parsed.get(i).getValue()));
            }
            return compile(files, docs);
        } catch (IOException | RuleException | RuntimeException ex) {
            return null;
        }
    }

    /** The pre-parsed bundle of fully validated rule files, as {@link BundledRulesCheck} writes it. */
    static byte[] bundle(List<RuleFile> files) throws RuleException {
        com.fasterxml.jackson.databind.node.ArrayNode arr = Mappers.JSON.createArrayNode();
        for (RuleFile f : files) {
            arr.addObject().put("path", f.path()).set("doc", parse(f));
        }
        try {
            return Mappers.JSON.writeValueAsBytes(arr);
        } catch (IOException ex) {
            throw new RuleException("bundle cannot be written: " + ex.getMessage());
        }
    }

    /** Loads every rule document under {@code dir} (recursively). */
    public static RuleSet loadDirectory(Path dir) throws RuleException {
        return load(directoryFiles(dir));
    }

    /** Is the path a rule document by its extension (SPEC 5.1)? */
    static boolean isRuleDocument(String path) {
        String l = path.toLowerCase(Locale.ROOT);
        return l.endsWith(".yaml") || l.endsWith(".yml") || l.endsWith(".json");
    }

    /** The bundled rule files, in code-point order of their relative path. */
    public static List<RuleFile> bundledFiles() throws RuleException {
        TreeMap<String, byte[]> files = new TreeMap<>(Texts.CODE_POINT_ORDER);
        try {
            var src = RuleLoader.class.getProtectionDomain().getCodeSource();
            Path loc = src == null ? null : Path.of(src.getLocation().toURI());
            if (loc != null && Files.isDirectory(loc)) {
                Path root = loc.resolve("rules");
                if (Files.isDirectory(root)) {
                    for (RuleFile f : directoryFiles(root)) {
                        files.put(f.path(), f.bytes());
                    }
                }
            } else if (loc != null && Files.isRegularFile(loc)) {
                try (ZipFile zip = new ZipFile(loc.toFile())) {
                    Enumeration<? extends ZipEntry> en = zip.entries();
                    while (en.hasMoreElements()) {
                        ZipEntry e = en.nextElement();
                        String name = e.getName();
                        if (!e.isDirectory() && name.startsWith(BUNDLED_PREFIX)
                                && isRuleDocument(name)) {
                            try (InputStream in = zip.getInputStream(e)) {
                                files.put(name.substring(BUNDLED_PREFIX.length()), in.readAllBytes());
                            }
                        }
                    }
                }
            }
        } catch (IOException | URISyntaxException | SecurityException | IllegalArgumentException ex) {
            throw new RuleException("bundled rules: cannot be read: " + ex.getMessage());
        }
        if (files.isEmpty()) {
            throw new RuleException("bundled rules: none found in the CipherSift jar");
        }
        List<RuleFile> out = new ArrayList<>();
        files.forEach((p, b) -> out.add(new RuleFile(p, b)));
        return out;
    }

    /**
     * Rule documents under {@code dir}, in code-point order of their relative path. {@code dir} itself
     * may be a symbolic link to a directory; symbolic links inside it are not allowed (DECISIONS O6):
     * each one is reported as a rule error. Other non-regular files are ignored. Relative paths use
     * the UTF-8 file names whatever the locale (DECISIONS O1).
     */
    public static List<RuleFile> directoryFiles(Path dir) throws RuleException {
        if (!Files.isDirectory(dir)) {
            throw new RuleException(dir + ": not a directory");
        }
        TreeMap<String, Path> paths = new TreeMap<>(Texts.CODE_POINT_ORDER);
        List<String> problems = new ArrayList<>();
        java.util.ArrayDeque<Map.Entry<Path, String>> pending = new java.util.ArrayDeque<>();
        pending.push(Map.entry(dir, ""));
        while (!pending.isEmpty()) {
            Map.Entry<Path, String> d = pending.pop();
            try (java.nio.file.DirectoryStream<Path> ds = Files.newDirectoryStream(d.getKey())) {
                for (Path p : ds) {
                    String name = ch.unibe.seg.ciphersift.files.FileNames.name(p);
                    String rel = d.getValue().isEmpty() ? name : d.getValue() + "/" + name;
                    java.nio.file.attribute.BasicFileAttributes a = Files.readAttributes(p,
                            java.nio.file.attribute.BasicFileAttributes.class, java.nio.file.LinkOption.NOFOLLOW_LINKS);
                    if (a.isSymbolicLink()) {
                        problems.add(rel + ": (document): symbolic links are not allowed in a rule directory");
                    } else if (a.isDirectory()) {
                        pending.push(Map.entry(p, rel));
                    } else if (a.isRegularFile() && isRuleDocument(rel)) {
                        paths.put(rel, p);
                    }
                }
            } catch (IOException | java.nio.file.DirectoryIteratorException | SecurityException ex) {
                throw new RuleException(dir + ": cannot be read: " + ex.getMessage());
            }
        }
        if (!problems.isEmpty()) {
            problems.sort(Texts.CODE_POINT_ORDER);
            throw new RuleException(problems);
        }
        List<RuleFile> out = new ArrayList<>();
        for (Map.Entry<String, Path> e : paths.entrySet()) {
            try (InputStream in = Files.newInputStream(e.getValue(), java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                out.add(new RuleFile(e.getKey(), in.readAllBytes()));
            } catch (IOException ex) {
                throw new RuleException(e.getKey() + ": cannot be read: " + ex.getMessage());
            }
        }
        return out;
    }

    /** {@code sha256:<hex>} over (path, NUL, bytes, NUL) of each file in order (SPEC 11.6). */
    public static String digest(List<RuleFile> files) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (RuleFile f : files) {
                md.update(f.path().getBytes(StandardCharsets.UTF_8));
                md.update((byte) 0);
                md.update(f.bytes());
                md.update((byte) 0);
            }
            return "sha256:" + HexFormat.of().formatHex(md.digest());
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /** Parses, validates and compiles rule files (sorted by path). */
    public static RuleSet load(List<RuleFile> files) throws RuleException {
        List<String> problems = new ArrayList<>();
        List<Map.Entry<RuleFile, JsonNode>> docs = new ArrayList<>();
        Schemas sc = schemas();
        for (RuleFile f : files) {
            JsonNode doc;
            try {
                doc = parse(f);
            } catch (RuleException ex) {
                problems.addAll(ex.problems());
                continue;
            }
            List<Error> errors = sc.forDocument(doc).validate(doc);
            if (!errors.isEmpty()) {
                for (Error e : errors) {
                    String ptr = pointer(e.getInstanceLocation());
                    problems.add(f.path() + ": " + displayPointer(ptr) + ": " + message(doc, ptr, e.getMessage()));
                }
                continue;
            }
            docs.add(Map.entry(f, doc));
        }
        if (!problems.isEmpty()) {
            throw new RuleException(problems);
        }
        return compile(files, docs);
    }

    /** The semantic checks of SPEC 5.8 and the compilation, for schema-valid documents. */
    private static RuleSet compile(List<RuleFile> files, List<Map.Entry<RuleFile, JsonNode>> docs)
            throws RuleException {
        List<String> problems = new ArrayList<>();
        Map<String, String> ids = new HashMap<>();
        Map<String, String> constantsByLanguage = new HashMap<>();
        Map<String, String> depByEcosystem = new HashMap<>();
        List<SourceRule> javaRules = new ArrayList<>();
        List<SourceRule> pythonRules = new ArrayList<>();
        List<SourceRule> goRules = new ArrayList<>();
        Map<String, DependencyRule> deps = new LinkedHashMap<>();
        Map<String, Map<String, String>> constants = new HashMap<>();
        int constantsDocs = 0;

        for (Map.Entry<RuleFile, JsonNode> e : docs) {
            String file = e.getKey().path();
            JsonNode doc = e.getValue();
            String id = doc.get("id").asText();
            String kind = doc.get("kind").asText();
            String prev = ids.putIfAbsent(id, file);
            if (prev != null) {
                problems.add(file + ": /id: duplicate rule id " + id + " (also in " + prev + ")");
                continue;
            }
            switch (kind) {
                case "source" -> {
                    String lang = doc.get("language").asText();
                    if (!id.startsWith(lang + ".")) {
                        problems.add(file + ": /id: a " + lang + " source rule id must start with \"" + lang + ".\"");
                        continue;
                    }
                    SourceRule r = switch (lang) {
                        case "java" -> javaRule(file, doc, problems);
                        case "go" -> goRule(file, doc, problems);
                        default -> pythonRule(file, doc, problems);
                    };
                    if (r != null) {
                        (switch (lang) {
                            case "java" -> javaRules;
                            case "go" -> goRules;
                            default -> pythonRules;
                        }).add(r);
                    }
                }
                case "dependency" -> {
                    String eco = doc.get("ecosystem").asText();
                    String p = depByEcosystem.putIfAbsent(eco, file);
                    if (p != null) {
                        problems.add(file + ": /ecosystem: a second dependency rule for ecosystem " + eco
                                + " (first in " + p + ")");
                        continue;
                    }
                    List<Pattern> pkgs = new ArrayList<>();
                    List<String> usedIf = new ArrayList<>();
                    for (JsonNode pk : doc.get("packages")) {
                        pkgs.add(DependencyRule.compilePackage(pk.get("package").asText()));
                        usedIf.add(pk.has("usedIf") ? pk.get("usedIf").asText() : null);
                    }
                    deps.put(eco, new DependencyRule(id, eco, doc.get("name").asText(), List.copyOf(pkgs),
                            java.util.Collections.unmodifiableList(usedIf)));
                }
                case "constants" -> {
                    String lang = doc.get("language").asText();
                    String p = constantsByLanguage.putIfAbsent(lang, file);
                    if (p != null) {
                        problems.add(file + ": /kind: a second constants document for language " + lang
                                + " (first in " + p + ")");
                        continue;
                    }
                    constantsDocs++;
                    Iterator<Map.Entry<String, JsonNode>> it = doc.get("constants").properties().iterator();
                    while (it.hasNext()) {
                        Map.Entry<String, JsonNode> c = it.next();
                        Map<String, String> fields = new HashMap<>();
                        c.getValue().properties().iterator().forEachRemaining(fv -> fields.put(fv.getKey(), fv.getValue().asText()));
                        constants.put(c.getKey(), Map.copyOf(fields));
                    }
                }
                default -> problems.add(file + ": /kind: unknown kind " + kind);
            }
        }
        if (!problems.isEmpty()) {
            throw new RuleException(problems);
        }
        javaRules.sort((a, b) -> Texts.compareCodePoints(a.id(), b.id()));
        pythonRules.sort((a, b) -> Texts.compareCodePoints(a.id(), b.id()));
        for (int i = 0; i < javaRules.size(); i++) {
            javaRules.get(i).order = i;
        }
        for (int i = 0; i < pythonRules.size(); i++) {
            pythonRules.get(i).order = i;
        }
        goRules.sort((a, b) -> Texts.compareCodePoints(a.id(), b.id()));
        for (int i = 0; i < goRules.size(); i++) {
            goRules.get(i).order = i;
        }
        return new RuleSet(javaRules, pythonRules, goRules, deps, Map.copyOf(constants), digest(files), constantsDocs);
    }

    // ------------------------------------------------------------------ parsing

    /** YAML 1.2 core schema for booleans: only true/false are booleans, yes/no/on/off are strings (SPEC 5.1). */
    /** The object mappers, initialised on first use (they are not needed for the trusted bundled set). */
    private static final class Mappers {
        static final YAMLMapper YAML = YAMLMapper.builder(YAMLFactory.builder()
                        .enable(YAMLParser.Feature.PARSE_BOOLEAN_LIKE_WORDS_AS_STRINGS).build())
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .build();
        static final ObjectMapper JSON = JsonMapper.builder()
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .build();
    }

    static JsonNode parse(RuleFile f) throws RuleException {
        String lower = f.path().toLowerCase(Locale.ROOT);
        try {
            if (lower.endsWith(".json")) {
                JsonNode n = Mappers.JSON.readTree(f.bytes());
                if (n == null || n.isMissingNode()) {
                    throw new RuleException(f.path() + ": (document): empty document");
                }
                return n;
            }
            List<JsonNode> docs = new ArrayList<>();
            try (JsonParser p = Mappers.YAML.createParser(f.bytes());
                    MappingIterator<JsonNode> it = Mappers.YAML.readValues(p, JsonNode.class)) {
                while (it.hasNextValue()) {
                    docs.add(it.nextValue());
                }
            }
            if (docs.size() != 1) {
                throw new RuleException(f.path() + ": (document): a YAML rule file must contain exactly one document, found "
                        + docs.size());
            }
            JsonNode n = docs.get(0);
            if (n == null || n.isMissingNode() || n.isNull()) {
                throw new RuleException(f.path() + ": (document): empty document");
            }
            return n;
        } catch (IOException ex) {
            String msg = ex.getMessage() == null ? ex.toString() : ex.getMessage().lines().findFirst().orElse("");
            throw new RuleException(f.path() + ": (document): cannot be parsed: " + msg);
        }
    }

    /**
     * The rule schema and its three document branches. A document whose {@code kind} names a branch is
     * validated against that branch only (equivalent to the top-level {@code oneOf}, whose other branches
     * require a different {@code kind}), which gives precise error messages.
     */
    private record Schemas(Schema all, Map<String, Schema> byKind) {
        Schema forDocument(JsonNode doc) {
            JsonNode k = doc.isObject() ? doc.get("kind") : null;
            Schema s = k != null && k.isTextual() ? byKind.get(k.asText()) : null;
            return s == null ? all : s;
        }
    }

    private static volatile Schemas schemas;

    private static Schemas schemas() throws RuleException {
        Schemas s = schemas;
        if (s == null) {
            synchronized (RuleLoader.class) {
                s = schemas;
                if (s == null) {
                    try {
                        byte[] bytes = resourceBytes(SCHEMA_RESOURCE);
                        if (bytes == null) {
                            throw new RuleException("rule schema " + SCHEMA_RESOURCE + " missing from the jar");
                        }
                        String text = new String(bytes, StandardCharsets.UTF_8);
                        String id = Mappers.JSON.readTree(text).path("$id").asText(SCHEMA_ID);
                        SchemaRegistry reg = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12,
                                b -> b.schemas(Map.of(id, text)));
                        Schema all = reg.getSchema(SchemaLocation.of(id));
                        Map<String, Schema> byKind = Map.of(
                                "source", reg.getSchema(SchemaLocation.of(id + "#/$defs/sourceRule")),
                                "dependency", reg.getSchema(SchemaLocation.of(id + "#/$defs/dependencyRule")),
                                "constants", reg.getSchema(SchemaLocation.of(id + "#/$defs/constantsDoc")));
                        s = new Schemas(all, byKind);
                        schemas = s;
                    } catch (IOException | RuntimeException ex) {
                        throw new RuleException("rule schema cannot be loaded: " + ex.getMessage());
                    }
                }
            }
        }
        return s;
    }

    private static final Pattern NEW_POINTER = Pattern.compile("/match/[0-9]+/new");

    /** Schema messages, with a clear one for {@code new: X*} (DECISIONS O6) instead of the bare regex. */
    private static String message(JsonNode doc, String ptr, String schemaMessage) {
        if (NEW_POINTER.matcher(ptr).matches()) {
            JsonNode v = doc.at(ptr);
            if (v.isTextual() && v.asText().endsWith("*")) {
                return NEW_STAR;
            }
        }
        return schemaMessage;
    }

    static final String NEW_STAR = "a new anchor names a class; \"*\" is not allowed";

    private static String displayPointer(String p) {
        return p.isEmpty() ? "(document)" : p;
    }

    /** JSON pointer (RFC 6901) of a node path. */
    static String pointer(NodePath path) {
        if (path == null) {
            return "";
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < path.getNameCount(); i++) {
            Object el = path.getElement(i);
            b.append('/').append(String.valueOf(el).replace("~", "~0").replace("/", "~1"));
        }
        return b.toString();
    }

    // ------------------------------------------------------------------ compiling

    private static Pattern regex(String file, String ptr, JsonNode n, int flags, List<String> problems) {
        if (n == null) {
            return null;
        }
        try {
            return Pattern.compile(n.asText(), flags);
        } catch (PatternSyntaxException ex) {
            problems.add(file + ": " + ptr + ": invalid regular expression: "
                    + ex.getDescription() + " near index " + ex.getIndex());
            return null;
        }
    }

    private static List<String> strings(JsonNode n, boolean lower) {
        if (n == null) {
            return null;
        }
        List<String> l = new ArrayList<>();
        if (n.isArray()) {
            for (JsonNode x : n) {
                l.add(lower ? Texts.lower(x.asText()) : x.asText());
            }
        } else {
            l.add(lower ? Texts.lower(n.asText()) : n.asText());
        }
        return List.copyOf(l);
    }

    private static Asset asset(JsonNode a) {
        return new Asset(text(a, "type"), text(a, "subtype"), text(a, "primitive"), text(a, "family"),
                text(a, "variant"), a.has("securityLevel") ? a.get("securityLevel").asInt() : null,
                text(a, "protocol"), text(a, "version"));
    }

    private static String text(JsonNode n, String key) {
        JsonNode v = n.get(key);
        return v == null || v.isNull() ? null : v.asText();
    }

    private static SourceRule javaRule(String file, JsonNode doc, List<String> problems) {
        List<JavaPattern> patterns = new ArrayList<>();
        SourceRule rule = new SourceRule(doc.get("id").asText(), "java", doc.get("name").asText(),
                asset(doc.get("asset")), patterns, file, text(doc, "indicator"));
        int before = problems.size();
        JsonNode match = doc.get("match");
        for (int i = 0; i < match.size(); i++) {
            JsonNode p = match.get(i);
            String ptr = "/match/" + i;
            JavaPattern.Anchor anchor;
            String value;
            if (p.has("call")) {
                anchor = JavaPattern.Anchor.CALL;
                value = p.get("call").asText();
            } else if (p.has("new")) {
                anchor = JavaPattern.Anchor.NEW;
                value = p.get("new").asText();
            } else if (p.has("method")) {
                anchor = JavaPattern.Anchor.METHOD;
                value = p.get("method").asText();
            } else if (p.has("field")) {
                anchor = JavaPattern.Anchor.FIELD;
                value = p.get("field").asText();
            } else if (p.has("anyCall")) {
                anchor = JavaPattern.Anchor.ANY_CALL;
                value = "";
            } else {
                anchor = JavaPattern.Anchor.OVERRIDE;
                value = p.get("override").asText();
            }
            boolean prefix = value.endsWith("*");
            String v = prefix ? value.substring(0, value.length() - 1) : value;
            String cls = null;
            String member;
            switch (anchor) {
                case CALL, FIELD -> {
                    int dot = v.lastIndexOf('.');
                    cls = v.substring(0, dot);
                    member = v.substring(dot + 1);
                }
                case NEW -> {
                    cls = v;
                    member = Texts.lastSegment(v);
                }
                default -> member = v;
            }
            if (prefix && member.isEmpty() && anchor != JavaPattern.Anchor.NEW) {
                // "C.*": any member
                member = "";
            }
            JsonNode param = p.get("param");
            Integer paramIndex = null;
            if (param != null) {
                Iterator<String> names = param.fieldNames();
                while (names.hasNext()) {
                    String k = names.next();
                    if (!"index".equals(k)) {
                        problems.add(file + ": " + ptr + "/param/" + k
                                + ": a Java pattern's param may only contain \"index\"");
                    }
                }
                if (param.has("index")) {
                    paramIndex = param.get("index").asInt();
                }
            }
            if (anchor == JavaPattern.Anchor.NEW && prefix) {
                problems.add(file + ": " + ptr + "/new: " + NEW_STAR); // also checked by the schema
            }
            // param is not a filter, so it does not make a pattern specific (DECISIONS O2)
            boolean hasCondition = false;
            Iterator<String> keys = p.fieldNames();
            while (keys.hasNext()) {
                String k = keys.next();
                if (!List.of("call", "new", "method", "field", "override", "param", "anyCall", "feature").contains(k)) {
                    hasCondition = true;
                }
            }
            patterns.add(new JavaPattern(rule, i, anchor, cls, member, prefix,
                    regex(file, ptr + "/firstString", p.get("firstString"), CI, problems),
                    regex(file, ptr + "/anyString", p.get("anyString"), CI, problems),
                    strings(p.get("stringContains"), true),
                    regex(file, ptr + "/argsText", p.get("argsText"), 0, problems),
                    strings(p.get("argsTextContains"), false),
                    p.has("constantArg") ? p.get("constantArg").asInt() : null,
                    strings(p.get("inType"), false),
                    regex(file, ptr + "/body", p.get("body"), 0, problems),
                    paramIndex, hasCondition, feature(file, ptr, p, problems)));
        }
        return problems.size() == before ? rule : null;
    }

    /** The {@code feature} of a pattern (SPEC 5.5), which must be a known feature id (3.1); else null. */
    private static String feature(String file, String ptr, JsonNode p, List<String> problems) {
        if (!p.has("feature")) {
            return null;
        }
        String f = p.get("feature").asText();
        if (!ch.unibe.seg.ciphersift.scan.Features.known().containsKey(f)) {
            problems.add(file + ": " + ptr + "/feature: unknown feature \"" + f + "\"");
        }
        return f;
    }

    /** Compiles a Go source rule (SPEC 17.3). */
    private static SourceRule goRule(String file, JsonNode doc, List<String> problems) {
        List<GoPattern> patterns = new ArrayList<>();
        SourceRule rule = new SourceRule(doc.get("id").asText(), "go", doc.get("name").asText(),
                asset(doc.get("asset")), patterns, file, text(doc, "indicator"));
        int before = problems.size();
        JsonNode match = doc.get("match");
        for (int i = 0; i < match.size(); i++) {
            JsonNode p = match.get(i);
            String ptr = "/match/" + i;
            GoPattern.Anchor anchor;
            String key;
            if (p.has("call")) {
                anchor = GoPattern.Anchor.CALL;
                key = "call";
            } else if (p.has("ref")) {
                anchor = GoPattern.Anchor.REF;
                key = "ref";
            } else if (p.has("composite")) {
                anchor = GoPattern.Anchor.COMPOSITE;
                key = "composite";
            } else if (p.has("method")) {
                anchor = GoPattern.Anchor.METHOD;
                key = "method";
            } else {
                anchor = GoPattern.Anchor.ASSIGN;
                key = "assign";
            }
            String value = p.get(key).asText();
            boolean prefix = value.endsWith("*");
            String name = prefix ? value.substring(0, value.length() - 1) : value;
            String path = null;
            if (anchor != GoPattern.Anchor.ASSIGN) {
                int dot = name.lastIndexOf('.');
                if (anchor == GoPattern.Anchor.METHOD && dot > 0) {
                    dot = name.lastIndexOf('.', dot - 1); // path.Type.Method: the path ends before the type
                }
                path = dot <= 0 ? "" : name.substring(0, dot);
                if (path.isEmpty()) {
                    problems.add(file + ": " + ptr + "/" + key + ": the import path before the last \".\" is empty");
                }
            }
            JsonNode param = p.get("param");
            patterns.add(new GoPattern(rule, i, anchor, name, prefix, path,
                    strings(p.get("anySymbol"), false),
                    regex(file, ptr + "/value", p.get("value"), CI, problems),
                    strings(p.get("valueContains"), true),
                    param != null && param.has("index") ? param.get("index").asInt() : null,
                    param != null && param.has("self") && param.get("self").asBoolean(),
                    param == null ? null : text(param, "value")));
        }
        return problems.size() == before ? rule : null;
    }

    /** A {@code kwargs}-like map (name → case-insensitive regex) in document order, or {@code null}. */
    private static Map<String, Pattern> regexMap(String file, String ptr, String key, JsonNode p, List<String> problems) {
        if (!p.has(key)) {
            return null;
        }
        Map<String, Pattern> m = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> it = p.get(key).properties().iterator();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> kv = it.next();
            m.put(kv.getKey(), regex(file, ptr + "/" + key + "/" + kv.getKey(), kv.getValue(), CI, problems));
        }
        return java.util.Collections.unmodifiableMap(m);
    }

    private static SourceRule pythonRule(String file, JsonNode doc, List<String> problems) {
        List<PythonPattern> patterns = new ArrayList<>();
        SourceRule rule = new SourceRule(doc.get("id").asText(), "python", doc.get("name").asText(),
                asset(doc.get("asset")), patterns, file, text(doc, "indicator"));
        int before = problems.size();
        JsonNode match = doc.get("match");
        for (int i = 0; i < match.size(); i++) {
            JsonNode p = match.get(i);
            String ptr = "/match/" + i;
            Map<String, Pattern> kwargs = regexMap(file, ptr, "kwargs", p, problems);
            Map<String, Pattern> dictItems = regexMap(file, ptr, "dictItems", p, problems);
            JsonNode param = p.get("param");
            if (p.has("ref") && param != null && !param.has("self") && !param.has("value")) {
                problems.add(file + ": " + ptr + "/param: a ref pattern's param may only be {self: true} or {value: …}"); // also the schema
            }
            patterns.add(new PythonPattern(rule, i,
                    text(p, "call"),
                    strings(p.get("method"), false),
                    p.has("anyCall") && p.get("anyCall").asBoolean(),
                    text(p, "assign"),
                    text(p, "ref"),
                    regex(file, ptr + "/firstString", p.get("firstString"), CI, problems),
                    strings(p.get("stringContains"), true),
                    strings(p.get("anySymbol"), false),
                    strings(p.get("allSymbols"), false),
                    kwargs,
                    dictItems,
                    strings(p.get("notInside"), false),
                    regex(file, ptr + "/value", p.get("value"), CI, problems),
                    strings(p.get("valueContains"), true),
                    param == null ? null : text(param, "keyword"),
                    param != null && param.has("index") ? param.get("index").asInt() : null,
                    param != null && param.has("self") && param.get("self").asBoolean(),
                    param == null ? null : text(param, "value"),
                    param != null,
                    strings(p.get("reportAt"), false),
                    strings(p.get("noSymbolPrefix"), false),
                    p.has("minArgs") ? p.get("minArgs").asInt() : null,
                    p.has("noString") && p.get("noString").asBoolean(),
                    strings(p.get("literal"), false),
                    feature(file, ptr, p, problems)));
        }
        return problems.size() == before ? rule : null;
    }
}
