/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.rules;

import java.util.List;

/**
 * A source rule (SPEC 5.3). {@code patterns} holds {@link JavaPattern}s or {@link PythonPattern}s
 * in file order. {@code order} is the rule's position in id order among the rules of its language.
 */
public final class SourceRule {
    private final String id;
    private final String language;
    private final String name;
    private final Asset asset;
    private final List<? extends Object> patterns;
    private final String file;
    private final String indicator;
    int order;

    SourceRule(String id, String language, String name, Asset asset, List<? extends Object> patterns, String file,
            String indicator) {
        this.id = id;
        this.language = language;
        this.name = name;
        this.asset = asset;
        this.patterns = patterns;
        this.file = file;
        this.indicator = indicator;
    }

    public String id() {
        return id;
    }

    public String language() {
        return language;
    }

    public String name() {
        return name;
    }

    public Asset asset() {
        return asset;
    }

    /** Position among the rules of the language in ascending id order. */
    public int order() {
        return order;
    }

    /**
     * The rule's {@code indicator} (SPEC 5.3), e.g. {@code weakness}: its findings are signs of a possible
     * weakness rather than cryptographic assets. {@code null} for ordinary rules.
     */
    public String indicator() {
        return indicator;
    }

    /** Rule-set relative path of the defining file. */
    public String file() {
        return file;
    }

    @SuppressWarnings("unchecked")
    public List<JavaPattern> javaPatterns() {
        return (List<JavaPattern>) patterns;
    }

    @SuppressWarnings("unchecked")
    public List<PythonPattern> pythonPatterns() {
        return (List<PythonPattern>) patterns;
    }

    @Override
    public String toString() {
        return id;
    }
}
