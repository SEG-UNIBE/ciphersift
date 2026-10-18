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
 */
public record ManifestEntry(String key, String version, String snippet, boolean transitive) {
    /** A direct entry. */
    public ManifestEntry(String key, String version, String snippet) {
        this(key, version, snippet, false);
    }
}
