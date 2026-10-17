/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.cbom;

import ch.unibe.seg.ciphersift.model.DependencyFinding;
import ch.unibe.seg.ciphersift.model.SourceFinding;
import ch.unibe.seg.ciphersift.rules.SourceRule;
import ch.unibe.seg.ciphersift.util.Texts;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Findings to components (SPEC 10) in output order (SPEC 11.6). */
public final class Normaliser {
    private Normaliser() {}

    /** Occurrence order: (location, line — absent first, symbol, snippet). */
    static final Comparator<Component.Occurrence> OCCURRENCE_ORDER = (a, b) -> {
        int c = Texts.compareCodePoints(a.location(), b.location());
        if (c != 0) {
            return c;
        }
        if (!Objects.equals(a.line(), b.line())) {
            if (a.line() == null) {
                return -1;
            }
            if (b.line() == null) {
                return 1;
            }
            return Integer.compare(a.line(), b.line());
        }
        c = Texts.compareNullFirst(a.symbol(), b.symbol());
        if (c != 0) {
            return c;
        }
        return Texts.compareNullFirst(a.snippet(), b.snippet());
    };

    private record CryptoKey(String ruleId, String name, String param, String oid) {}

    private record LibraryKey(String ecosystem, String pkg, String version) {}

    /** Component name of a source finding (SPEC 10.2). */
    static String componentName(SourceRule rule, String findingName) {
        String type = rule.asset().type();
        if ("algorithm".equals(type)) {
            return findingName;
        }
        if ("protocol".equals(type)) {
            String p = Texts.upper(rule.asset().protocol());
            return rule.asset().version() == null ? p : p + " " + rule.asset().version();
        }
        return rule.name();
    }

    public static List<Component> normalise(List<SourceFinding> source, List<DependencyFinding> deps) {
        Map<CryptoKey, List<SourceFinding>> crypto = new LinkedHashMap<>();
        Map<CryptoKey, SourceRule> rules = new HashMap<>();
        for (SourceFinding f : source) {
            boolean alg = "algorithm".equals(f.rule().asset().type());
            CryptoKey k = alg ? new CryptoKey(f.rule().id(), f.name(), f.param(), f.oid())
                    : new CryptoKey(f.rule().id(), componentName(f.rule(), f.name()), null, null);
            crypto.computeIfAbsent(k, x -> new ArrayList<>()).add(f);
            rules.putIfAbsent(k, f.rule());
        }
        List<Component.Crypto> cryptoComponents = new ArrayList<>();
        for (Map.Entry<CryptoKey, List<SourceFinding>> e : crypto.entrySet()) {
            CryptoKey k = e.getKey();
            List<Component.Occurrence> occ = new ArrayList<>();
            for (SourceFinding f : e.getValue()) {
                occ.add(new Component.Occurrence(f.path(), f.line(), f.symbol(), f.rule().id(), f.snippet(), f.param(),
                        null, f.test()));
            }
            cryptoComponents.add(new Component.Crypto(rules.get(k), k.name(), k.param(), k.oid(), dedupe(occ, true)));
        }
        cryptoComponents.sort((a, b) -> {
            int c = Texts.compareCodePoints(a.rule().id(), b.rule().id());
            if (c != 0) {
                return c;
            }
            c = Texts.compareCodePoints(a.name(), b.name());
            if (c != 0) {
                return c;
            }
            c = Texts.compareNullFirst(a.param(), b.param());
            if (c != 0) {
                return c;
            }
            return Texts.compareNullFirst(a.oid(), b.oid());
        });

        Map<LibraryKey, List<DependencyFinding>> libs = new LinkedHashMap<>();
        for (DependencyFinding d : deps) {
            libs.computeIfAbsent(new LibraryKey(d.ecosystem(), d.packageKey(), d.version()), x -> new ArrayList<>())
                    .add(d);
        }
        List<Component.Library> libComponents = new ArrayList<>();
        for (Map.Entry<LibraryKey, List<DependencyFinding>> e : libs.entrySet()) {
            LibraryKey k = e.getKey();
            List<Component.Occurrence> occ = new ArrayList<>();
            String ruleId = null;
            for (DependencyFinding d : e.getValue()) {
                ruleId = d.rule().id();
                occ.add(new Component.Occurrence(d.path(), null, null, d.rule().id(), d.snippet(), null, d.manifest(),
                        d.test()));
            }
            libComponents.add(new Component.Library(ruleId, k.ecosystem(), k.pkg(), k.version(), dedupe(occ, false)));
        }
        libComponents.sort((a, b) -> {
            int c = Texts.compareCodePoints(a.ecosystem(), b.ecosystem());
            if (c != 0) {
                return c;
            }
            c = Texts.compareCodePoints(a.packageKey(), b.packageKey());
            if (c != 0) {
                return c;
            }
            return Texts.compareNullFirst(a.version(), b.version());
        });
        List<Component> out = new ArrayList<>(cryptoComponents.size() + libComponents.size());
        out.addAll(cryptoComponents);
        out.addAll(libComponents);
        return out;
    }

    /**
     * Occurrences with the same (path, line) — libraries: the same path — are one: sorted by
     * (symbol, snippet), the first is kept (SPEC 10.3). The result is in occurrence order.
     */
    static List<Component.Occurrence> dedupe(List<Component.Occurrence> occ, boolean byLine) {
        List<Component.Occurrence> sorted = new ArrayList<>(occ);
        sorted.sort(OCCURRENCE_ORDER);
        List<Component.Occurrence> out = new ArrayList<>(sorted.size());
        Component.Occurrence prev = null;
        for (Component.Occurrence o : sorted) {
            if (prev != null && prev.location().equals(o.location())
                    && (!byLine || Objects.equals(prev.line(), o.line()))) {
                continue;
            }
            out.add(o);
            prev = o;
        }
        return out;
    }
}
