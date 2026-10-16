/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang.java;

import ch.unibe.seg.ciphersift.rules.JavaPattern;
import ch.unibe.seg.ciphersift.rules.SourceRule;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Index of Java patterns by (event kind, name) with prefix keys (SPEC 7.5). */
public final class JavaRuleIndex {
    private record PrefixKey(String prefix, List<JavaPattern> patterns) {}

    private final Map<JavaPattern.EventKind, Map<String, List<JavaPattern>>> exact =
            new EnumMap<>(JavaPattern.EventKind.class);
    private final Map<JavaPattern.EventKind, List<PrefixKey>> prefixes = new EnumMap<>(JavaPattern.EventKind.class);

    private static final Comparator<JavaPattern> ORDER =
            Comparator.<JavaPattern>comparingInt(p -> p.rule.order()).thenComparingInt(p -> p.position);

    public JavaRuleIndex(List<SourceRule> rules) {
        Map<JavaPattern.EventKind, Map<String, List<JavaPattern>>> pre = new EnumMap<>(JavaPattern.EventKind.class);
        for (JavaPattern.EventKind k : JavaPattern.EventKind.values()) {
            exact.put(k, new HashMap<>());
            pre.put(k, new HashMap<>());
        }
        for (SourceRule r : rules) {
            for (JavaPattern p : r.javaPatterns()) {
                var target = p.prefix ? pre.get(p.eventKind()) : exact.get(p.eventKind());
                target.computeIfAbsent(p.member, x -> new ArrayList<>()).add(p);
            }
        }
        for (JavaPattern.EventKind k : JavaPattern.EventKind.values()) {
            List<PrefixKey> l = new ArrayList<>();
            pre.get(k).forEach((prefix, ps) -> {
                ps.sort(ORDER);
                l.add(new PrefixKey(prefix, List.copyOf(ps)));
            });
            l.sort(Comparator.comparing(PrefixKey::prefix));
            prefixes.put(k, List.copyOf(l));
            exact.get(k).replaceAll((key, ps) -> {
                ps.sort(ORDER);
                return List.copyOf(ps);
            });
        }
    }

    /** Is there any candidate for this event (cheap pre-check)? */
    public boolean hasCandidates(JavaPattern.EventKind kind, String name) {
        if (exact.get(kind).containsKey(name)) {
            return true;
        }
        for (PrefixKey pk : prefixes.get(kind)) {
            if (name.startsWith(pk.prefix())) {
                return true;
            }
        }
        return false;
    }

    /** Candidate patterns of an event, ordered by rule (id order) and then by position in the rule. */
    public List<JavaPattern> candidates(JavaPattern.EventKind kind, String name) {
        List<JavaPattern> ex = exact.get(kind).get(name);
        List<JavaPattern> out = null;
        for (PrefixKey pk : prefixes.get(kind)) {
            if (name.startsWith(pk.prefix())) {
                if (out == null) {
                    out = new ArrayList<>();
                    if (ex != null) {
                        out.addAll(ex);
                    }
                }
                out.addAll(pk.patterns());
            }
        }
        if (out == null) {
            return ex == null ? List.of() : ex;
        }
        out.sort(ORDER);
        return out;
    }
}
