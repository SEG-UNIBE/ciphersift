/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift;

import ch.unibe.seg.ciphersift.cbom.CycloneDxVersion;
import com.networknt.schema.Error;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.cyclonedx.Version;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.JsonParser;

/**
 * Validates CBOMs against the CycloneDX schemas vendored in {@code src/test/resources/cyclonedx/}
 * (specification tag 1.7.2) with networknt, and against the schemas bundled in cyclonedx-core-java
 * (SPEC 11.1). Both must accept a document.
 */
public final class CycloneDxSchemas {
    private static final String BASE = "http://cyclonedx.org/schema/";
    private static final List<String> FILES = List.of("bom-1.6.schema.json", "bom-1.7.schema.json",
            "spdx.schema.json", "jsf-0.82.schema.json", "cryptography-defs.schema.json");
    private static final Map<CycloneDxVersion, Schema> SCHEMAS = new EnumMap<>(CycloneDxVersion.class);

    private CycloneDxSchemas() {}

    static String resource(String name) {
        try (InputStream in = CycloneDxSchemas.class.getResourceAsStream("/cyclonedx/" + name)) {
            if (in == null) {
                throw new IllegalStateException("vendored schema missing: " + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    private static synchronized Schema schema(CycloneDxVersion v) {
        return SCHEMAS.computeIfAbsent(v, k -> {
            Map<String, String> texts = new HashMap<>();
            for (String f : FILES) {
                texts.put(BASE + f, resource(f));
            }
            SchemaRegistry reg = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_7,
                    b -> b.schemas(texts));
            return reg.getSchema(SchemaLocation.of(BASE + "bom-" + k.spec() + ".schema.json"));
        });
    }

    /** Messages of both validators; empty if the document is valid CycloneDX {@code v}. */
    public static List<String> validate(byte[] cbom, CycloneDxVersion v) throws Exception {
        List<String> out = new ArrayList<>();
        var doc = TestSupport.JSON.readTree(cbom);
        if (!v.spec().equals(doc.path("specVersion").asText())) {
            out.add("specVersion is " + doc.path("specVersion") + ", expected " + v.spec());
        }
        for (Error e : schema(v).validate(doc)) {
            out.add("vendored " + v.spec() + " schema: " + e.getMessage());
        }
        Version core = v == CycloneDxVersion.V1_6 ? Version.VERSION_16 : Version.VERSION_17;
        for (ParseException e : new JsonParser().validate(cbom, core)) {
            out.add("cyclonedx-core-java " + v.spec() + ": " + e.getMessage());
        }
        return out;
    }
}
