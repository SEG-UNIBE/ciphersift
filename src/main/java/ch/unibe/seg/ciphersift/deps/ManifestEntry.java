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
 */
public record ManifestEntry(String key, String version, String snippet) {}
