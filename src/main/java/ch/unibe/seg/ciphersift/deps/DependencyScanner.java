/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.deps;

import ch.unibe.seg.ciphersift.files.FileClass;
import ch.unibe.seg.ciphersift.files.SourceText;
import ch.unibe.seg.ciphersift.model.DependencyFinding;
import ch.unibe.seg.ciphersift.rules.DependencyRule;
import ch.unibe.seg.ciphersift.rules.RuleSet;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Dependency manifests (SPEC 9): parse, deduplicate per manifest, match the ecosystem's rule. */
public final class DependencyScanner {
    /** The manifest cannot be parsed (SPEC 9: warning, no entries). */
    public static final class MalformedManifestException extends Exception {
        private static final long serialVersionUID = 1L;

        public MalformedManifestException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private final RuleSet rules;

    public DependencyScanner(RuleSet rules) {
        this.rules = rules;
    }

    /** Parses a manifest's entries in declaration order. */
    public static List<ManifestEntry> entries(FileClass fc, byte[] bytes) throws MalformedManifestException {
        try {
            return switch (fc) {
                case POM -> MavenManifests.pom(bytes);
                case GRADLE -> MavenManifests.gradle(SourceText.decode(bytes));
                case GRADLE_CATALOG -> MavenManifests.versionCatalog(SourceText.decode(bytes));
                case REQUIREMENTS -> PythonManifests.requirements(SourceText.decode(bytes));
                case PYPROJECT -> PythonManifests.pyproject(SourceText.decode(bytes));
                case PIPFILE_LOCK -> PythonManifests.pipfileLock(SourceText.decode(bytes));
                case POETRY_LOCK -> PythonManifests.poetryLock(SourceText.decode(bytes));
                default -> throw new IllegalArgumentException("not a manifest: " + fc);
            };
        } catch (IOException ex) {
            String msg = ex.getMessage() == null ? ex.getClass().getSimpleName()
                    : ex.getMessage().lines().findFirst().orElse("");
            throw new MalformedManifestException(msg, ex);
        }
    }

    /**
     * One entry per key: a declaration with a version beats one without; otherwise the last one wins
     * (SPEC 9, DECISIONS M2).
     */
    static List<ManifestEntry> deduplicate(List<ManifestEntry> entries) {
        Map<String, ManifestEntry> m = new LinkedHashMap<>();
        for (ManifestEntry e : entries) {
            ManifestEntry prev = m.get(e.key());
            if (prev == null || e.version() != null || prev.version() == null) {
                m.put(e.key(), e);
            }
        }
        return new ArrayList<>(m.values());
    }

    /** Findings of one manifest. */
    public List<DependencyFinding> scan(String relativePath, FileClass fc, byte[] bytes, boolean test)
            throws MalformedManifestException {
        DependencyRule rule = rules.dependencyRule(fc.ecosystem());
        List<ManifestEntry> entries = entries(fc, bytes);
        if (rule == null) {
            return List.of();
        }
        List<DependencyFinding> out = new ArrayList<>();
        for (ManifestEntry e : deduplicate(entries)) {
            if (rule.matches(e.key())) {
                out.add(new DependencyFinding(relativePath, rule, fc.ecosystem(), e.key(), e.version(), fc.label(),
                        e.snippet(), test));
            }
        }
        return out;
    }
}
