/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.rules;

import java.util.List;
import java.util.regex.Pattern;

/** One Go pattern (SPEC 17.3), compiled. */
public final class GoPattern {
    /** Pattern anchors. */
    public enum Anchor { CALL, REF, COMPOSITE, ASSIGN }

    public final SourceRule rule;
    public final int position;
    public final Anchor anchor;
    /**
     * The anchor value without a trailing {@code *}: {@code path.Member} (or {@code path.} for
     * {@code path.*}) for call / ref / composite, the field name for assign.
     */
    public final String name;
    /** True if the anchor ends with {@code *} (prefix match on the member). */
    public final boolean prefix;
    /** The import path of a call / ref / composite anchor; {@code null} for assign. */
    public final String path;
    public final List<String> anySymbol;
    public final Pattern value;
    /** Lower-case needles. */
    public final List<String> valueContains;
    public final Integer paramIndex;
    public final boolean paramSelf;
    public final String paramValue;
    public final int specificity;

    GoPattern(SourceRule rule, int position, Anchor anchor, String name, boolean prefix, String path,
            List<String> anySymbol, Pattern value, List<String> valueContains, Integer paramIndex, boolean paramSelf,
            String paramValue) {
        this.rule = rule;
        this.position = position;
        this.anchor = anchor;
        this.name = name;
        this.prefix = prefix;
        this.path = path;
        this.anySymbol = anySymbol;
        this.value = value;
        this.valueContains = valueContains;
        this.paramIndex = paramIndex;
        this.paramSelf = paramSelf;
        this.paramValue = paramValue;
        this.specificity = anySymbol != null || value != null || valueContains != null ? 2 : 1;
    }

    /** Does a qualified event name match the anchor (exactly, or as prefix for {@code *})? */
    public boolean nameMatches(String qualified) {
        return prefix ? qualified.startsWith(name) : qualified.equals(name);
    }

    /** A {@code call} pattern without {@code anySymbol} also fires on references (SPEC 17.3, DECISIONS G5). */
    public boolean matchesReferences() {
        return anchor == Anchor.REF || (anchor == Anchor.CALL && anySymbol == null);
    }

    /** The member of a call / ref / composite anchor (without {@code *}); the field name for assign. */
    public String member() {
        return path == null ? name : name.substring(path.length() + 1);
    }

    @Override
    public String toString() {
        return rule.id() + "#" + position;
    }
}
