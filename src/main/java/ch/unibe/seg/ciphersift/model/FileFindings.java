/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.model;

import java.util.List;

/** The findings of one file. */
public record FileFindings(List<SourceFinding> source, List<DependencyFinding> dependencies) {
    public static final FileFindings EMPTY = new FileFindings(List.of(), List.of());

    public static FileFindings ofSource(List<SourceFinding> s) {
        return new FileFindings(List.copyOf(s), List.of());
    }

    public static FileFindings ofDependencies(List<DependencyFinding> d) {
        return new FileFindings(List.of(), List.copyOf(d));
    }
}
