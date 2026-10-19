/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang.java;

import ch.unibe.seg.ciphersift.rules.JavaPattern;
import ch.unibe.seg.ciphersift.rules.SourceRule;
import ch.unibe.seg.ciphersift.scan.Features;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Index of Java patterns by (event kind, name) with prefix keys (SPEC 7.5). */
public final class JavaRuleIndex {
    private record PrefixKey(String prefix, List<JavaPattern> patterns) {}

    private final Map<JavaPattern.EventKind, Map<String, List<JavaPattern>>> exact =
            new EnumMap<>(JavaPattern.EventKind.class);
    private final Map<JavaPattern.EventKind, List<PrefixKey>> prefixes = new EnumMap<>(JavaPattern.EventKind.class);

    /**
     * Methods an {@code anyCall} anchor does not fire on (SPEC 5.5): comparisons and look-ups, logging and
     * printing, collection builders, the JCA factories (their own patterns decide), messages and properties.
     */
    static final Set<String> ANY_CALL_EXCLUDED = Set.of("equals", "equalsIgnoreCase", "contains",
            "containsKey", "containsValue", "startsWith", "endsWith", "indexOf", "lastIndexOf", "matches", "compareTo",
            "compareToIgnoreCase", "regionMatches", "getInstance", "debug", "info", "warn", "warning", "error", "trace",
            "fine", "finer", "finest", "log", "println", "printf", "print", "format", "append", "fail", "getProperty",
            "getString", "getMessage", "isLoggable", "add", "addAll", "of", "setOf", "asList", "stream", "copyOf");
    /** Prefixes of method names an {@code anyCall} anchor does not fire on (SPEC 5.5). */
    static final List<String> ANY_CALL_EXCLUDED_PREFIXES = List.of("assert", "equals", "contains", "log");

    /** Whether an {@code anyCall} anchor fires on a call with this method name (SPEC 5.5). */
    public static boolean anyCallFires(String name) {
        if (ANY_CALL_EXCLUDED.contains(name)) {
            return false;
        }
        for (String p : ANY_CALL_EXCLUDED_PREFIXES) {
            if (name.startsWith(p)) {
                return false;
            }
        }
        return true;
    }

    private final List<JavaPattern> anyCall = new ArrayList<>();

    private static final Comparator<JavaPattern> ORDER =
            Comparator.<JavaPattern>comparingInt(p -> p.rule.order()).thenComparingInt(p -> p.position);

    /** The index of the patterns that are on with these feature switches (SPEC 5.5 {@code feature}). */
    public JavaRuleIndex(List<SourceRule> rules, Features features) {
        Map<JavaPattern.EventKind, Map<String, List<JavaPattern>>> pre = new EnumMap<>(JavaPattern.EventKind.class);
        for (JavaPattern.EventKind k : JavaPattern.EventKind.values()) {
            exact.put(k, new HashMap<>());
            pre.put(k, new HashMap<>());
        }
        for (SourceRule r : rules) {
            for (JavaPattern p : r.javaPatterns()) {
                if (p.feature != null && !features.on(p.feature)) {
                    continue;
                }
                if (p.anchor == JavaPattern.Anchor.ANY_CALL) {
                    anyCall.add(p);
                    continue;
                }
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
        anyCall.sort(ORDER);
    }

    /** Is there any candidate for this event (cheap pre-check)? */
    public boolean hasCandidates(JavaPattern.EventKind kind, String name) {
        if (kind == JavaPattern.EventKind.CALL && !anyCall.isEmpty() && anyCallFires(name)) {
            return true;
        }
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
        if (kind == JavaPattern.EventKind.CALL && !anyCall.isEmpty() && anyCallFires(name)) {
            out = new ArrayList<>(anyCall);
            if (ex != null) {
                out.addAll(ex);
            }
        }
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
