/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang.go;

import ch.unibe.seg.ciphersift.rules.GoPattern;
import ch.unibe.seg.ciphersift.rules.SourceRule;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Index of Go patterns (SPEC 17.3, 17.8): per event kind, exact anchors by qualified name and the
 * prefix anchors; rules in id order, patterns in file order.
 */
final class GoRuleIndex {
    final Map<String, List<GoPattern>> callExact = new HashMap<>();
    final List<GoPattern> callPrefix = new ArrayList<>();
    /** {@code ref} patterns and the {@code call} patterns that also fire on references. */
    final Map<String, List<GoPattern>> refExact = new HashMap<>();
    final List<GoPattern> refPrefix = new ArrayList<>();
    final Map<String, List<GoPattern>> composite = new HashMap<>();
    final Map<String, List<GoPattern>> assign = new HashMap<>();
    /** {@code method} patterns by {@code path.Type.Method} (SPEC 17.3, DECISIONS B-G-B1a). */
    final Map<String, List<GoPattern>> method = new HashMap<>();
    /** Fixed {@code param: {value}} of exact call / ref anchors, first in rule and file order (SPEC 17.9). */
    final Map<String, String> paramValues = new HashMap<>();
    /** {@code literal} patterns by string value (DECISIONS T3-G10); rules in id order. */
    final Map<String, List<GoPattern>> literals = new HashMap<>();

    GoRuleIndex(List<SourceRule> rules) {
        for (SourceRule r : rules) {
            for (GoPattern p : r.goPatterns()) {
                switch (p.anchor) {
                    case CALL -> add(callExact, callPrefix, p);
                    case COMPOSITE -> composite.computeIfAbsent(p.name, k -> new ArrayList<>()).add(p);
                    case ASSIGN -> assign.computeIfAbsent(p.name, k -> new ArrayList<>()).add(p);
                    case METHOD -> method.computeIfAbsent(p.name, k -> new ArrayList<>()).add(p);
                    case LITERAL -> {
                        for (String v : p.literal) {
                            literals.computeIfAbsent(v, k -> new ArrayList<>()).add(p);
                        }
                    }
                    default -> {
                        // REF: indexed below
                    }
                }
                if (p.matchesReferences()) {
                    add(refExact, refPrefix, p);
                }
                if (p.paramValue != null && !p.prefix
                        && (p.anchor == GoPattern.Anchor.CALL || p.anchor == GoPattern.Anchor.REF)) {
                    paramValues.putIfAbsent(p.name, p.paramValue);
                }
            }
        }
    }

    private static void add(Map<String, List<GoPattern>> exact, List<GoPattern> prefix, GoPattern p) {
        if (p.prefix) {
            prefix.add(p);
        } else {
            exact.computeIfAbsent(p.name, k -> new ArrayList<>()).add(p);
        }
    }

    boolean isEmpty() {
        return callExact.isEmpty() && callPrefix.isEmpty() && refExact.isEmpty() && refPrefix.isEmpty()
                && composite.isEmpty() && assign.isEmpty() && method.isEmpty() && literals.isEmpty();
    }
}
