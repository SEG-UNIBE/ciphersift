/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.cbom;

import ch.unibe.seg.ciphersift.rules.SourceRule;
import java.util.List;

/** A normalised component (SPEC 10): cryptographic asset or library. */
public sealed interface Component {
    /** An occurrence (SPEC 11.4). {@code line} and {@code symbol} are null for dependency findings. */
    record Occurrence(String location, Integer line, String symbol, String ruleId, String snippet, String param,
            String manifest, boolean test) {}

    List<Occurrence> occurrences();

    /** A cryptographic-asset component. {@code param} and {@code oid} only for algorithms. */
    record Crypto(SourceRule rule, String name, String param, String oid, List<Occurrence> occurrences)
            implements Component {
        /** A component without OID. */
        public Crypto(SourceRule rule, String name, String param, List<Occurrence> occurrences) {
            this(rule, name, param, null, occurrences);
        }
    }

    /** A library component. */
    record Library(String ruleId, String ecosystem, String packageKey, String version, List<Occurrence> occurrences)
            implements Component {
        public String group() {
            if (!"maven".equals(ecosystem)) {
                return null;
            }
            int c = packageKey.indexOf(':');
            return packageKey.substring(0, c);
        }

        public String name() {
            if (!"maven".equals(ecosystem)) {
                return packageKey;
            }
            return packageKey.substring(packageKey.indexOf(':') + 1);
        }

        public String purl() {
            return "maven".equals(ecosystem) ? Purl.maven(group(), name(), version) : Purl.pypi(packageKey, version);
        }
    }
}
