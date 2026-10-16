/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.model;

import ch.unibe.seg.ciphersift.rules.SourceRule;

/**
 * A source finding (SPEC 2.1).
 *
 * @param path relative path
 * @param line 1-based line
 * @param name component name (SPEC 10.2)
 * @param symbol the API the finding is anchored on
 * @param snippet source text, at most 500 code points
 * @param param parameter-set identifier or {@code null}
 * @param test the file is a test file
 */
public record SourceFinding(String path, int line, SourceRule rule, String name, String symbol, String snippet,
        String param, boolean test) {}
