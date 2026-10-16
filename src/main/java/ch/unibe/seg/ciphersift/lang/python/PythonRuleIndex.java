/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang.python;

import ch.unibe.seg.ciphersift.rules.PythonPattern;
import ch.unibe.seg.ciphersift.rules.SourceRule;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Index of Python patterns (SPEC 8.6): by {@code call} value, by method name, {@code anyCall}, {@code assign}. */
final class PythonRuleIndex {
    /** Patterns by their {@code call} value; rules in id order, patterns in file order. */
    final Map<String, List<PythonPattern>> byCall = new HashMap<>();
    /** Patterns without {@code call}, by each of their method names. */
    final Map<String, List<PythonPattern>> byMethod = new HashMap<>();
    /** All {@code anyCall} patterns. */
    final List<PythonPattern> anyCall = new ArrayList<>();
    /** Keywords required by some {@code anyCall} pattern. */
    final Set<String> anyCallKeywords = new HashSet<>();
    /** Rules (id order) with their {@code assign} patterns. */
    final List<Map.Entry<SourceRule, List<PythonPattern>>> assignRules = new ArrayList<>();
    /** All assign field names. */
    final Set<String> assignFields = new HashSet<>();

    PythonRuleIndex(List<SourceRule> rules) {
        for (SourceRule r : rules) {
            List<PythonPattern> assigns = new ArrayList<>();
            for (PythonPattern p : r.pythonPatterns()) {
                if (p.call != null) {
                    byCall.computeIfAbsent(p.call, k -> new ArrayList<>()).add(p);
                } else if (p.methods != null) {
                    for (String m : p.methods) {
                        List<PythonPattern> l = byMethod.computeIfAbsent(m, k -> new ArrayList<>());
                        if (!l.contains(p)) {
                            l.add(p);
                        }
                    }
                } else if (p.anyCall) {
                    anyCall.add(p);
                    if (p.kwargs != null) {
                        anyCallKeywords.addAll(p.kwargs.keySet());
                    }
                } else if (p.assign != null) {
                    assigns.add(p);
                    assignFields.add(p.assign);
                }
            }
            if (!assigns.isEmpty()) {
                assignRules.add(Map.entry(r, List.copyOf(assigns)));
            }
        }
    }
}
