/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.rules;

/**
 * The {@code asset} block of a source rule (SPEC 5.4). Absent values are {@code null}.
 *
 * @param type asset type as written in the rule ({@code key-material} is kept)
 */
public record Asset(String type, String subtype, String primitive, String family, String variant,
        Integer securityLevel, String protocol, String version) {

    /** The CycloneDX asset type: {@code key-material} is written as {@code related-crypto-material}. */
    public String cyclonedxType() {
        return "key-material".equals(type) ? "related-crypto-material" : type;
    }

    /** Python refinement identity (SPEC 8.6): (type, primitive, family, protocol, subtype). */
    public String identity() {
        return type + "\u0000" + primitive + "\u0000" + family + "\u0000" + protocol + "\u0000" + subtype;
    }

    /** A rule is refined if it has a variant or a version (SPEC 8.6). */
    public boolean refined() {
        return variant != null || version != null;
    }
}
