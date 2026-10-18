/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.scan;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Named analysis switches (SPEC 3.1 {@code --feature}, DECISIONS B0): each detection booster of the t2 round
 * has an id and a default; {@code --feature ID=on|off} overrides it. The non-default settings of a scan are
 * recorded in the CBOM metadata (SPEC 11.2.1), so that two CBOMs made with different switches can be told
 * apart.
 */
public final class Features {
    /** Id → default (SPEC 3.1 table), in documentation order. */
    static final Map<String, Boolean> KNOWN = new LinkedHashMap<>();

    private static void known(String id, boolean def) {
        if (KNOWN.put(id, def) != null) {
            throw new IllegalStateException("duplicate feature " + id);
        }
    }

    /** Keep go.mod {@code // indirect} requirements and lock files (go.sum, poetry.lock, Pipfile.lock). */
    public static final String TRANSITIVE_DEPS = "transitive-deps";

    /** Wrapper-name aliases for certificates, keys and protocols (V2, SPEC 18.6). */
    public static final String WRAPPER_ALIASES_V2 = "wrapper-aliases-v2";

    static {
        known(TRANSITIVE_DEPS, false);
        known(WRAPPER_ALIASES_V2, true);
    }

    /** The defaults. */
    public static final Features DEFAULTS = new Features(Map.of());

    private final Map<String, Boolean> overrides;

    private Features(Map<String, Boolean> overrides) {
        this.overrides = Collections.unmodifiableMap(new TreeMap<>(overrides));
    }

    /** Whether a feature is on. */
    public boolean on(String id) {
        Boolean v = overrides.get(id);
        if (v != null) {
            return v;
        }
        Boolean d = KNOWN.get(id);
        if (d == null) {
            throw new IllegalArgumentException("unknown feature " + id);
        }
        return d;
    }

    /** These features with one more setting. */
    public Features with(String id, boolean value) {
        if (!KNOWN.containsKey(id)) {
            throw new IllegalArgumentException("unknown feature " + id);
        }
        Map<String, Boolean> m = new TreeMap<>(overrides);
        if (KNOWN.get(id) == value) {
            m.remove(id);
        } else {
            m.put(id, value);
        }
        return new Features(m);
    }

    /**
     * Parses {@code --feature} values {@code ID=on|off} (also {@code true}/{@code false}); a later setting
     * of the same id wins.
     *
     * @throws IllegalArgumentException with a message for the user
     */
    public static Features parse(List<String> specs, Features base) {
        Features f = base;
        for (String s : specs) {
            int eq = s.indexOf('=');
            if (eq <= 0) {
                throw new IllegalArgumentException("--feature expects ID=on or ID=off, not '" + s + "'");
            }
            String id = s.substring(0, eq).strip();
            String v = s.substring(eq + 1).strip().toLowerCase(Locale.ROOT);
            if (!KNOWN.containsKey(id)) {
                throw new IllegalArgumentException("unknown feature '" + id + "' (known: " + String.join(", ", KNOWN.keySet()) + ")");
            }
            boolean b = switch (v) {
                case "on", "true" -> true;
                case "off", "false" -> false;
                default -> throw new IllegalArgumentException("--feature " + id + " expects on or off, not '" + v + "'");
            };
            f = f.with(id, b);
        }
        return f;
    }

    /** The non-default settings as {@code id=on,id=off} in code-point order of the ids, or null if none. */
    public String describe() {
        if (overrides.isEmpty()) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Boolean> e : overrides.entrySet()) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(e.getKey()).append('=').append(e.getValue() ? "on" : "off");
        }
        return sb.toString();
    }

    /** The known ids and their defaults (for help texts and tests). */
    public static Map<String, Boolean> known() {
        return Collections.unmodifiableMap(KNOWN);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Features f && f.overrides.equals(overrides);
    }

    @Override
    public int hashCode() {
        return overrides.hashCode();
    }

    @Override
    public String toString() {
        String d = describe();
        return d == null ? "defaults" : d;
    }
}
