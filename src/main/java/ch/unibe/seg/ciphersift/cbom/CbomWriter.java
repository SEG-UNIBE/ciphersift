/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.cbom;

import ch.unibe.seg.ciphersift.rules.Asset;
import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.core.util.Separators;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

/** Serialises the CBOM (SPEC 11) deterministically with Jackson's streaming generator. */
public final class CbomWriter {
    private static final JsonFactory FACTORY = JsonFactory.builder().build();

    /** Document-level inputs; {@code cyclonedx} is the output version (SPEC 11.2). */
    public record Metadata(String toolVersion, String rootName, String rulesDigest, boolean testsIncluded,
            long filesScanned, long filesSkipped, Long sourceDateEpoch, boolean weaknessIndicatorsIncluded,
            CycloneDxVersion cyclonedx, boolean pythonThinWrappers, String features) {
        public Metadata {
            if (cyclonedx == null) {
                cyclonedx = CycloneDxVersion.DEFAULT;
            }
        }

        /** Metadata of a scan with the default feature switches (SPEC 3.1). */
        public Metadata(String toolVersion, String rootName, String rulesDigest, boolean testsIncluded,
                long filesScanned, long filesSkipped, Long sourceDateEpoch, boolean weaknessIndicatorsIncluded,
                CycloneDxVersion cyclonedx, boolean pythonThinWrappers) {
            this(toolVersion, rootName, rulesDigest, testsIncluded, filesScanned, filesSkipped, sourceDateEpoch,
                    weaknessIndicatorsIncluded, cyclonedx, pythonThinWrappers, null);
        }

        /** Metadata of a scan without {@code --python-thin-wrappers} (the default, DECISIONS T3). */
        public Metadata(String toolVersion, String rootName, String rulesDigest, boolean testsIncluded,
                long filesScanned, long filesSkipped, Long sourceDateEpoch, boolean weaknessIndicatorsIncluded,
                CycloneDxVersion cyclonedx) {
            this(toolVersion, rootName, rulesDigest, testsIncluded, filesScanned, filesSkipped, sourceDateEpoch,
                    weaknessIndicatorsIncluded, cyclonedx, false);
        }

        /** Metadata of a scan in the default CycloneDX version. */
        public Metadata(String toolVersion, String rootName, String rulesDigest, boolean testsIncluded,
                long filesScanned, long filesSkipped, Long sourceDateEpoch, boolean weaknessIndicatorsIncluded) {
            this(toolVersion, rootName, rulesDigest, testsIncluded, filesScanned, filesSkipped, sourceDateEpoch,
                    weaknessIndicatorsIncluded, CycloneDxVersion.DEFAULT);
        }

        /** Metadata of a scan without weakness indicators (the default, DECISIONS E2). */
        public Metadata(String toolVersion, String rootName, String rulesDigest, boolean testsIncluded,
                long filesScanned, long filesSkipped, Long sourceDateEpoch) {
            this(toolVersion, rootName, rulesDigest, testsIncluded, filesScanned, filesSkipped, sourceDateEpoch, false);
        }
    }

    private CbomWriter() {}

    /** The complete document: serialised once without {@code serialNumber}, hashed, then again with it. */
    public static byte[] write(Metadata meta, List<Component> components) {
        Map<Component, String> refs = bomRefs(components);
        byte[] first = serialise(meta, components, refs, null);
        String serial = serialNumber(first);
        return serialise(meta, components, refs, serial);
    }

    // ------------------------------------------------------------------ references (11.6)

    static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /** Compact JSON array of strings, serialised like the document. */
    static String compactArray(String... values) {
        StringWriter w = new StringWriter();
        try (JsonGenerator g = FACTORY.createGenerator(w)) {
            g.writeStartArray();
            for (String v : values) {
                g.writeString(v);
            }
            g.writeEndArray();
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        return w.toString();
    }

    /** Full-length bom-ref of a cryptographic component: {@code <assetType>:<64 hex>}. */
    static String fullRef(Component.Crypto c) {
        Asset a = c.rule().asset();
        String type = a.cyclonedxType();
        String param = c.param() == null ? "" : c.param();
        // a component with an OID (SPEC 5.11) appends it, so that components without one keep their bom-refs
        String json = !"algorithm".equals(type) ? compactArray(type, c.rule().id())
                : c.oid() == null ? compactArray("algorithm", c.rule().id(), c.name(), param)
                : compactArray("algorithm", c.rule().id(), c.name(), param, c.oid());
        return type + ":" + sha256Hex(json.getBytes(StandardCharsets.UTF_8));
    }

    static Map<Component, String> bomRefs(List<Component> components) {
        Map<Component, String> full = new IdentityHashMap<>();
        Map<String, Integer> shortCount = new HashMap<>();
        for (Component c : components) {
            if (c instanceof Component.Crypto cc) {
                String f = fullRef(cc);
                full.put(c, f);
                shortCount.merge(shorten(f), 1, Integer::sum);
            }
        }
        Map<Component, String> refs = new IdentityHashMap<>();
        for (Component c : components) {
            if (c instanceof Component.Crypto) {
                String f = full.get(c);
                String s = shorten(f);
                refs.put(c, shortCount.get(s) > 1 ? f : s);
            } else if (c instanceof Component.Library l) {
                refs.put(c, l.purl());
            }
        }
        return refs;
    }

    private static String shorten(String fullRef) {
        int colon = fullRef.lastIndexOf(':');
        return fullRef.substring(0, colon + 1 + 16);
    }

    /** UUID (version nibble 8, variant 10) from the SHA-256 of the document without serial number. */
    static String serialNumber(byte[] document) {
        byte[] h;
        try {
            h = MessageDigest.getInstance("SHA-256").digest(document);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
        byte[] u = java.util.Arrays.copyOf(h, 16);
        u[6] = (byte) ((u[6] & 0x0f) | 0x80);
        u[8] = (byte) ((u[8] & 0x3f) | 0x80);
        String hex = HexFormat.of().formatHex(u);
        return "urn:uuid:" + hex.substring(0, 8) + "-" + hex.substring(8, 12) + "-" + hex.substring(12, 16) + "-"
                + hex.substring(16, 20) + "-" + hex.substring(20, 32);
    }

    // ------------------------------------------------------------------ serialisation

    static DefaultPrettyPrinter prettyPrinter() {
        DefaultIndenter ind = new DefaultIndenter("  ", "\n");
        Separators sep = Separators.createDefaultInstance()
                .withObjectFieldValueSpacing(Separators.Spacing.AFTER)
                .withObjectEntrySpacing(Separators.Spacing.NONE)
                .withArrayValueSpacing(Separators.Spacing.NONE)
                .withObjectEmptySeparator("")
                .withArrayEmptySeparator("")
                .withRootSeparator("");
        return new DefaultPrettyPrinter(sep).withObjectIndenter(ind).withArrayIndenter(ind);
    }

    private static byte[] serialise(Metadata meta, List<Component> components, Map<Component, String> refs,
            String serial) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(64 * 1024);
        try (JsonGenerator g = FACTORY.createGenerator(out, JsonEncoding.UTF8)) {
            g.setPrettyPrinter(prettyPrinter());
            g.writeStartObject();
            g.writeStringField("bomFormat", "CycloneDX");
            g.writeStringField("specVersion", meta.cyclonedx().spec());
            if (serial != null) {
                g.writeStringField("serialNumber", serial);
            }
            g.writeNumberField("version", 1);
            writeMetadata(g, meta);
            g.writeArrayFieldStart("components");
            List<String> libraryRefs = new ArrayList<>();
            for (Component c : components) {
                if (c instanceof Component.Crypto cc) {
                    writeCrypto(g, cc, refs.get(c), meta.cyclonedx());
                } else if (c instanceof Component.Library l) {
                    writeLibrary(g, l, refs.get(c));
                    libraryRefs.add(refs.get(c));
                }
            }
            g.writeEndArray();
            if (!libraryRefs.isEmpty()) {
                g.writeArrayFieldStart("dependencies");
                g.writeStartObject();
                g.writeStringField("ref", "root");
                g.writeArrayFieldStart("dependsOn");
                for (String r : libraryRefs) {
                    g.writeString(r);
                }
                g.writeEndArray();
                g.writeEndObject();
                g.writeEndArray();
            }
            g.writeEndObject();
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        out.write('\n');
        return out.toByteArray();
    }

    private static void writeMetadata(JsonGenerator g, Metadata m) throws IOException {
        g.writeObjectFieldStart("metadata");
        if (m.sourceDateEpoch() != null) {
            g.writeStringField("timestamp",
                    DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochSecond(m.sourceDateEpoch())));
        }
        g.writeObjectFieldStart("tools");
        g.writeArrayFieldStart("components");
        g.writeStartObject();
        g.writeStringField("type", "application");
        g.writeStringField("name", "ciphersift");
        g.writeStringField("version", m.toolVersion());
        g.writeEndObject();
        g.writeEndArray();
        g.writeEndObject();
        g.writeObjectFieldStart("component");
        g.writeStringField("type", "application");
        g.writeStringField("bom-ref", "root");
        g.writeStringField("name", m.rootName());
        g.writeEndObject();
        g.writeArrayFieldStart("properties");
        property(g, "ciphersift:rulesDigest", m.rulesDigest());
        property(g, "ciphersift:testFiles", m.testsIncluded() ? "included" : "excluded");
        property(g, "ciphersift:filesScanned", Long.toString(m.filesScanned()));
        property(g, "ciphersift:filesSkipped", Long.toString(m.filesSkipped()));
        if (m.weaknessIndicatorsIncluded()) {
            property(g, "ciphersift:weaknessIndicators", "included");
        }
        if (m.pythonThinWrappers()) {
            property(g, "ciphersift:pythonThinWrappers", "included");
        }
        if (m.features() != null) {
            property(g, "ciphersift:features", m.features());
        }
        g.writeEndArray();
        g.writeEndObject();
    }

    private static void property(JsonGenerator g, String name, String value) throws IOException {
        if (value == null) {
            return;
        }
        g.writeStartObject();
        g.writeStringField("name", name);
        g.writeStringField("value", value);
        g.writeEndObject();
    }

    static String mode(String variant) {
        if (variant == null) {
            return null;
        }
        return switch (variant.toUpperCase(java.util.Locale.ROOT)) {
            case "ECB" -> "ecb";
            case "CBC" -> "cbc";
            case "CCM" -> "ccm";
            case "GCM" -> "gcm";
            case "CFB" -> "cfb";
            case "OFB" -> "ofb";
            case "CTR" -> "ctr";
            case "EAX", "OCB", "SIV", "GCM-SIV", "XTS", "KW" -> "other";
            default -> null;
        };
    }

    static String padding(Asset a) {
        if (a.variant() != null) {
            switch (a.variant().toUpperCase(java.util.Locale.ROOT)) {
                case "OAEP" -> {
                    return "oaep";
                }
                case "PKCS1V15" -> {
                    return "pkcs1v15";
                }
                case "PSS" -> {
                    return "other";
                }
                default -> {
                    // fall through to the subtype rule
                }
            }
        }
        return "pkcs1-v1_5-encrypt".equals(a.subtype()) ? "pkcs1v15" : null;
    }

    static String relatedType(String subtype) {
        if (subtype == null) {
            return "other";
        }
        return switch (subtype) {
            case "hardcoded-key" -> "secret-key";
            case "static-iv" -> "initialization-vector";
            case "hardcoded-password" -> "password";
            case "jwt-none-algorithm" -> "token";
            case "private-key" -> "private-key";
            case "public-key" -> "public-key";
            case "cms-signed-data" -> "signature";
            case "cms-enveloped-data" -> "ciphertext";
            default -> "other";
        };
    }

    private static void writeCrypto(JsonGenerator g, Component.Crypto c, String ref, CycloneDxVersion cdx)
            throws IOException {
        Asset a = c.rule().asset();
        String type = a.cyclonedxType();
        g.writeStartObject();
        g.writeStringField("type", "cryptographic-asset");
        g.writeStringField("bom-ref", ref);
        g.writeStringField("name", c.name());
        g.writeObjectFieldStart("cryptoProperties");
        g.writeStringField("assetType", type);
        switch (type) {
            case "algorithm" -> {
                boolean defs = cdx.hasCryptographyDefs();
                g.writeObjectFieldStart("algorithmProperties");
                g.writeStringField("primitive", a.primitive() == null ? "unknown" : a.primitive());
                String family = defs ? CryptoRegistry.algorithmFamily(a, c.name()) : null;
                if (family != null) {
                    g.writeStringField("algorithmFamily", family);
                }
                if (c.param() != null) {
                    g.writeStringField("parameterSetIdentifier", c.param());
                }
                String curve = defs ? CryptoRegistry.ellipticCurve(a, c.param()) : null;
                if (curve != null) {
                    g.writeStringField("ellipticCurve", curve);
                }
                String mode = mode(a.variant());
                if (mode != null) {
                    g.writeStringField("mode", mode);
                }
                String pad = padding(a);
                if (pad != null) {
                    g.writeStringField("padding", pad);
                }
                if (a.securityLevel() != null) {
                    g.writeNumberField("classicalSecurityLevel", a.securityLevel());
                }
                g.writeEndObject();
            }
            case "protocol" -> {
                g.writeObjectFieldStart("protocolProperties");
                g.writeStringField("type", a.protocol());
                if (a.version() != null) {
                    g.writeStringField("version", a.version());
                }
                g.writeEndObject();
            }
            case "related-crypto-material" -> {
                g.writeObjectFieldStart("relatedCryptoMaterialProperties");
                g.writeStringField("type", relatedType(a.subtype()));
                g.writeEndObject();
            }
            default -> {
                // certificate: no further properties
            }
        }
        if (c.oid() != null) {
            g.writeStringField("oid", c.oid());
        }
        g.writeEndObject();
        g.writeArrayFieldStart("properties");
        property(g, "ciphersift:ruleId", c.rule().id());
        property(g, "ciphersift:language", c.rule().language());
        if (!a.type().equals(type)) {
            property(g, "ciphersift:assetType", a.type());
        }
        property(g, "ciphersift:primitive", a.primitive());
        property(g, "ciphersift:family", a.family());
        property(g, "ciphersift:variant", a.variant());
        property(g, "ciphersift:subtype", a.subtype());
        property(g, "ciphersift:indicator", c.rule().indicator());
        if (testOnly(c.occurrences())) {
            property(g, "ciphersift:testOnly", "true");
        }
        g.writeEndArray();
        writeEvidence(g, c.occurrences());
        g.writeEndObject();
    }

    private static void writeLibrary(JsonGenerator g, Component.Library l, String ref) throws IOException {
        g.writeStartObject();
        g.writeStringField("type", "library");
        g.writeStringField("bom-ref", ref);
        if (l.group() != null) {
            g.writeStringField("group", l.group());
        }
        g.writeStringField("name", l.name());
        if (l.version() != null) {
            g.writeStringField("version", l.version());
        }
        g.writeStringField("purl", l.purl());
        g.writeArrayFieldStart("properties");
        property(g, "ciphersift:ruleId", l.ruleId());
        property(g, "ciphersift:ecosystem", l.ecosystem());
        if (testOnly(l.occurrences())) {
            property(g, "ciphersift:testOnly", "true");
        }
        g.writeEndArray();
        writeEvidence(g, l.occurrences());
        g.writeEndObject();
    }

    private static boolean testOnly(List<Component.Occurrence> occ) {
        if (occ.isEmpty()) {
            return false;
        }
        for (Component.Occurrence o : occ) {
            if (!o.test()) {
                return false;
            }
        }
        return true;
    }

    private static void writeEvidence(JsonGenerator g, List<Component.Occurrence> occ) throws IOException {
        g.writeObjectFieldStart("evidence");
        g.writeArrayFieldStart("occurrences");
        for (Component.Occurrence o : occ) {
            g.writeStartObject();
            g.writeStringField("location", o.location());
            if (o.line() != null) {
                g.writeNumberField("line", o.line());
            }
            if (o.symbol() != null) {
                g.writeStringField("symbol", o.symbol());
            }
            g.writeStringField("additionalContext", additionalContext(o));
            g.writeEndObject();
        }
        g.writeEndArray();
        g.writeEndObject();
    }

    /** Compact JSON with keys ruleId, snippet, param, manifest, via, origin, test (SPEC 11.4). */
    static String additionalContext(Component.Occurrence o) {
        StringWriter w = new StringWriter();
        try (JsonGenerator g = FACTORY.createGenerator(w)) {
            g.writeStartObject();
            g.writeStringField("ruleId", o.ruleId());
            g.writeStringField("snippet", o.snippet());
            if (o.param() != null) {
                g.writeStringField("param", o.param());
            }
            if (o.manifest() != null) {
                g.writeStringField("manifest", o.manifest());
            }
            if (o.via() != null) {
                g.writeArrayFieldStart("via");
                for (String v : o.via()) {
                    g.writeString(v);
                }
                g.writeEndArray();
                g.writeStringField("origin", o.origin());
            }
            if (o.test()) {
                g.writeBooleanField("test", true);
            }
            g.writeEndObject();
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        return w.toString();
    }
}
