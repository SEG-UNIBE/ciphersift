/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.deps;

/**
 * One manifest entry (SPEC 9).
 *
 * @param key Maven {@code groupId:artifactId}, PyPI normalised name or Go module path
 * @param version version or {@code null}
 * @param snippet the coordinate as text
 * @param transitive the manifest marks the entry as a transitive requirement (go.mod {@code // indirect},
 *        SPEC 17.10, DECISIONS B-G1)
 * @param testScope declared for tests only: Maven {@code <scope>test</scope>}, a Gradle test configuration
 *        (t3 J-TSCOPE)
 */
public record ManifestEntry(String key, String version, String snippet, boolean transitive, boolean testScope) {
    /** A direct entry. */
    public ManifestEntry(String key, String version, String snippet) {
        this(key, version, snippet, false, false);
    }

    public ManifestEntry(String key, String version, String snippet, boolean transitive) {
        this(key, version, snippet, transitive, false);
    }

    /** This entry declared for tests only. */
    ManifestEntry asTestScope() {
        return new ManifestEntry(key, version, snippet, transitive, true);
    }
}
