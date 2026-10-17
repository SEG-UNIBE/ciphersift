/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.rules;

import java.util.List;
import java.util.Map;

/** A loaded and validated rule set (SPEC 5). Rules of each language are in ascending id order. */
public final class RuleSet {
    private final List<SourceRule> javaRules;
    private final List<SourceRule> pythonRules;
    private final List<SourceRule> goRules;
    private final Map<String, DependencyRule> dependencyRules;
    private final Map<String, Map<String, String>> javaConstants;
    private final String digest;
    private final int constantsDocuments;

    RuleSet(List<SourceRule> javaRules, List<SourceRule> pythonRules, List<SourceRule> goRules,
            Map<String, DependencyRule> dependencyRules, Map<String, Map<String, String>> javaConstants, String digest,
            int constantsDocuments) {
        this.javaRules = List.copyOf(javaRules);
        this.pythonRules = List.copyOf(pythonRules);
        this.goRules = List.copyOf(goRules);
        this.dependencyRules = Map.copyOf(dependencyRules);
        this.javaConstants = javaConstants;
        this.digest = digest;
        this.constantsDocuments = constantsDocuments;
    }

    public List<SourceRule> javaRules() {
        return javaRules;
    }

    public List<SourceRule> pythonRules() {
        return pythonRules;
    }

    /** Go source rules (SPEC 17), in ascending id order. */
    public List<SourceRule> goRules() {
        return goRules;
    }

    /** Dependency rule of an ecosystem ({@code maven}, {@code pypi}, {@code golang}) or {@code null}. */
    public DependencyRule dependencyRule(String ecosystem) {
        return dependencyRules.get(ecosystem);
    }

    public Map<String, DependencyRule> dependencyRules() {
        return dependencyRules;
    }

    /** Constants-table lookup (SPEC 5.10): simple class name and field → string, or {@code null}. */
    public String javaConstant(String simpleClass, String field) {
        Map<String, String> m = javaConstants.get(simpleClass);
        return m == null ? null : m.get(field);
    }

    /** {@code sha256:<hex>} over the rule files (SPEC 11.6). */
    public String digest() {
        return digest;
    }

    public int constantsDocuments() {
        return constantsDocuments;
    }
}
