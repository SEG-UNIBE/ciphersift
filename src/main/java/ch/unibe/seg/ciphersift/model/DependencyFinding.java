/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.model;

import ch.unibe.seg.ciphersift.rules.DependencyRule;

/**
 * A dependency finding (SPEC 2.1).
 *
 * @param path relative path of the manifest
 * @param ecosystem {@code maven} or {@code pypi}
 * @param packageKey Maven {@code groupId:artifactId} or PyPI normalised name
 * @param version version or {@code null}
 * @param manifest manifest label (SPEC 9)
 * @param snippet the coordinate as text
 */
public record DependencyFinding(String path, DependencyRule rule, String ecosystem, String packageKey,
        String version, String manifest, String snippet, boolean test) {}
