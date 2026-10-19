/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.rules;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ContainerNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLParser;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Reads one rule document into a {@link JsonNode} tree with the streaming parsers only, without an
 * {@code ObjectMapper} (whose initialisation dominates the start-up time otherwise). The parser
 * settings are those of {@code RuleLoader}'s mappers (YAML 1.2 booleans, duplicate keys rejected,
 * exactly one document); the node types are those that {@code ObjectMapper.readTree} produces.
 * Used for the pre-parsed bundled rule set, whose trees {@link BundledRulesCheck} compares with the
 * mapper's at build time.
 */
final class TreeReader {
    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;
    private static final YAMLFactory YAML = YAMLFactory.builder()
            .enable(YAMLParser.Feature.PARSE_BOOLEAN_LIKE_WORDS_AS_STRINGS)
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .build();
    private static final JsonFactory JSON = JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .build();

    private TreeReader() {}

    /** Parses a whole document; throws {@link IOException} for anything but exactly one value. */
    static JsonNode read(String path, byte[] bytes) throws IOException {
        boolean json = path.toLowerCase(Locale.ROOT).endsWith(".json");
        try (JsonParser p = json ? JSON.createParser(bytes) : YAML.createParser(bytes)) {
            JsonToken t = p.nextToken();
            if (t == null) {
                throw new IOException("empty document");
            }
            JsonNode root = value(p, t);
            if (p.nextToken() != null) {
                throw new IOException("more than one document or trailing tokens");
            }
            return root;
        }
    }

    /** Reads a bundle {@code [{"path": …, "doc": …}, …]} written by {@link RuleLoader#bundle}. */
    static List<Map.Entry<String, JsonNode>> readBundle(byte[] bytes) throws IOException {
        JsonNode root;
        try (JsonParser p = JSON.createParser(bytes)) {
            JsonToken t = p.nextToken();
            if (t != JsonToken.START_ARRAY) {
                throw new IOException("bundle is not an array");
            }
            root = value(p, t);
            if (p.nextToken() != null) {
                throw new IOException("trailing tokens in bundle");
            }
        }
        List<Map.Entry<String, JsonNode>> out = new ArrayList<>(root.size());
        for (JsonNode e : root) {
            JsonNode path = e.get("path");
            JsonNode doc = e.get("doc");
            if (path == null || !path.isTextual() || doc == null || e.size() != 2) {
                throw new IOException("malformed bundle entry");
            }
            out.add(Map.entry(path.asText(), doc));
        }
        return out;
    }

    /** Reads the value starting at the current token {@code t} (iteratively, any depth). */
    private static JsonNode value(JsonParser p, JsonToken t) throws IOException {
        if (t != JsonToken.START_OBJECT && t != JsonToken.START_ARRAY) {
            return scalar(p, t);
        }
        ArrayDeque<ContainerNode<?>> stack = new ArrayDeque<>();
        ContainerNode<?> root = t == JsonToken.START_OBJECT ? NODES.objectNode() : NODES.arrayNode();
        stack.push(root);
        while (!stack.isEmpty()) {
            ContainerNode<?> top = stack.peek();
            JsonToken n = p.nextToken();
            if (n == null) {
                throw new IOException("unexpected end of document");
            }
            if (n == JsonToken.END_OBJECT || n == JsonToken.END_ARRAY) {
                stack.pop();
                continue;
            }
            String name = null;
            if (top instanceof ObjectNode) {
                if (n != JsonToken.FIELD_NAME) {
                    throw new IOException("expected a field name, found " + n);
                }
                name = p.currentName();
                n = p.nextToken();
                if (n == null) {
                    throw new IOException("unexpected end of document");
                }
            }
            JsonNode v;
            if (n == JsonToken.START_OBJECT) {
                v = NODES.objectNode();
            } else if (n == JsonToken.START_ARRAY) {
                v = NODES.arrayNode();
            } else {
                v = scalar(p, n);
            }
            if (top instanceof ObjectNode o) {
                o.set(name, v);
            } else {
                ((ArrayNode) top).add(v);
            }
            if (v instanceof ContainerNode<?> c) {
                stack.push(c);
            }
        }
        return root;
    }

    private static JsonNode scalar(JsonParser p, JsonToken t) throws IOException {
        switch (t) {
            case VALUE_STRING:
                return NODES.textNode(p.getText());
            case VALUE_NUMBER_INT:
                switch (p.getNumberType()) {
                    case INT:
                        return NODES.numberNode(p.getIntValue());
                    case LONG:
                        return NODES.numberNode(p.getLongValue());
                    default:
                        return NODES.numberNode(p.getBigIntegerValue());
                }
            case VALUE_NUMBER_FLOAT:
                switch (p.getNumberType()) {
                    case BIG_DECIMAL:
                        return NODES.numberNode(p.getDecimalValue());
                    case FLOAT:
                        return NODES.numberNode(p.getFloatValue());
                    default:
                        return NODES.numberNode(p.getDoubleValue());
                }
            case VALUE_TRUE:
                return NODES.booleanNode(true);
            case VALUE_FALSE:
                return NODES.booleanNode(false);
            case VALUE_NULL:
                return NODES.nullNode();
            case VALUE_EMBEDDED_OBJECT:
                Object o = p.getEmbeddedObject();
                if (o == null) {
                    return NODES.nullNode();
                }
                return o instanceof byte[] b ? NODES.binaryNode(b) : NODES.pojoNode(o);
            default:
                throw new IOException("unexpected token " + t);
        }
    }
}
