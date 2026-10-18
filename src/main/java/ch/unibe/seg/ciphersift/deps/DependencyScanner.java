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
import ch.unibe.seg.ciphersift.scan.Features;
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
    /** Report transitive requirements too: go.mod {@code // indirect} entries and all lock files (DECISIONS B-G1, B-G2). */
    private final boolean transitive;
    /** Skip poetry.lock and Pipfile.lock too (feature skip-python-lock-files; DECISIONS B-G2). */
    private final boolean skipPythonLocks;

    public DependencyScanner(RuleSet rules, Features features) {
        this.rules = rules;
        this.transitive = features.on(Features.TRANSITIVE_DEPS);
        this.skipPythonLocks = features.on(Features.SKIP_PYTHON_LOCK_FILES);
    }

    /** A scanner with the default features. */
    public DependencyScanner(RuleSet rules) {
        this(rules, Features.DEFAULTS);
    }

    /**
     * Lock files list every resolved package, transitive ones included (SPEC 9.4, 17.10; DECISIONS B-G2):
     * go.sum is not reported by default, poetry.lock and Pipfile.lock only with {@code skip-python-lock-files}.
     */
    boolean skipsLockFile(FileClass fc) {
        if (transitive) {
            return false;
        }
        return fc == FileClass.GO_SUM
                || skipPythonLocks && (fc == FileClass.POETRY_LOCK || fc == FileClass.PIPFILE_LOCK);
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
                case PIPFILE -> PythonManifests.pipfile(SourceText.decode(bytes));
                case PIPFILE_LOCK -> PythonManifests.pipfileLock(SourceText.decode(bytes));
                case POETRY_LOCK -> PythonManifests.poetryLock(SourceText.decode(bytes));
                case SETUP_CFG -> SetupManifests.setupCfg(SourceText.decode(bytes));
                case GO_MOD -> GoManifests.goMod(SourceText.decode(bytes));
                case GO_SUM -> GoManifests.goSum(SourceText.decode(bytes));
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

    /**
     * Findings of the requirements declared in a parsed {@code setup.py} (SPEC 9.8); the file itself is
     * Python source.
     */
    public List<DependencyFinding> setupPy(String relativePath, ch.unibe.seg.ciphersift.syntax.SyntaxNode root,
            boolean test) {
        return findings(relativePath, "pypi", SetupManifests.SETUP_PY_LABEL, SetupManifests.setupPy(root), test);
    }

    private List<DependencyFinding> findings(String relativePath, String ecosystem, String label,
            List<ManifestEntry> entries, boolean test) {
        DependencyRule rule = rules.dependencyRule(ecosystem);
        if (rule == null) {
            return List.of();
        }
        List<DependencyFinding> out = new ArrayList<>();
        for (ManifestEntry e : deduplicate(entries)) {
            if (e.transitive() && !transitive) {
                continue; // go.mod "// indirect" (SPEC 17.10, DECISIONS B-G1)
            }
            if (rule.matches(e.key())) {
                out.add(new DependencyFinding(relativePath, rule, ecosystem, e.key(), e.version(), label,
                        e.snippet(), test));
            }
        }
        return out;
    }

    /** Findings of one manifest. */
    public List<DependencyFinding> scan(String relativePath, FileClass fc, byte[] bytes, boolean test)
            throws MalformedManifestException {
        if (skipsLockFile(fc)) {
            return List.of(); // DECISIONS B-G2: still a scanned manifest, without findings
        }
        List<ManifestEntry> entries = entries(fc, bytes);
        return findings(relativePath, fc.ecosystem(), fc.label(), entries, test);
    }
}
