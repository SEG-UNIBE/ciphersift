/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.cbom;

/** The CycloneDX version of the output (SPEC 11.2, option {@code --cyclonedx-version}). */
public enum CycloneDxVersion {
    V1_6("1.6"),
    V1_7("1.7");

    /** The version written without an option. */
    public static final CycloneDxVersion DEFAULT = V1_7;

    private final String spec;

    CycloneDxVersion(String spec) {
        this.spec = spec;
    }

    /** The {@code specVersion} value. */
    public String spec() {
        return spec;
    }

    /** The version named {@code s} ("1.6", "1.7"), or null. */
    public static CycloneDxVersion of(String s) {
        for (CycloneDxVersion v : values()) {
            if (v.spec.equals(s)) {
                return v;
            }
        }
        return null;
    }

    /** True from 1.7 on: {@code algorithmFamily} and {@code ellipticCurve}. */
    public boolean hasCryptographyDefs() {
        return this.compareTo(V1_7) >= 0;
    }

    @Override
    public String toString() {
        return spec;
    }
}
