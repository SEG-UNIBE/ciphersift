/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.model;

import ch.unibe.seg.ciphersift.rules.SourceRule;
import java.util.List;

/**
 * A source finding (SPEC 2.1).
 *
 * @param path relative path
 * @param line 1-based line
 * @param name component name (SPEC 10.2)
 * @param symbol the API the finding is anchored on
 * @param snippet source text, at most 500 code points
 * @param param parameter-set identifier or {@code null}
 * @param oid the object identifier the matched string was given as (SPEC 5.11), or {@code null}
 * @param test the file is a test file
 * @param via the wrapper chain of a propagated finding (SPEC 18.7), {@code null} for a finding of phase 3
 * @param origin {@code path:line} of a propagated finding's evidence, {@code null} for a finding of phase 3
 */
public record SourceFinding(String path, int line, SourceRule rule, String name, String symbol, String snippet,
        String param, String oid, boolean test, List<String> via, String origin) {
    public SourceFinding {
        via = via == null ? null : List.copyOf(via);
    }

    /** A finding of phase 3 (not propagated). */
    public SourceFinding(String path, int line, SourceRule rule, String name, String symbol, String snippet,
            String param, String oid, boolean test) {
        this(path, line, rule, name, symbol, snippet, param, oid, test, null, null);
    }

    /** A finding whose matched string was not an OID. */
    public SourceFinding(String path, int line, SourceRule rule, String name, String symbol, String snippet,
            String param, boolean test) {
        this(path, line, rule, name, symbol, snippet, param, null, test);
    }
}
