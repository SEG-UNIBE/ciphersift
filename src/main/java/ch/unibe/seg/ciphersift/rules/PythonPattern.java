/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.rules;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/** One Python pattern (SPEC 5.6), compiled. */
public final class PythonPattern {
    public final SourceRule rule;
    public final int position;
    /** {@code call} anchor or {@code null}. */
    public final String call;
    /** {@code method} names or {@code null}. */
    public final List<String> methods;
    public final boolean anyCall;
    /** {@code assign} field name or {@code null}. */
    public final String assign;
    /** {@code ref} anchor (a bare reference, SPEC 8.6.1) or {@code null}. */
    public final String ref;

    public final Pattern firstString;
    /** Lower-case needles. */
    public final List<String> stringContains;
    public final List<String> anySymbol;
    public final List<String> allSymbols;
    /** keyword → regex (find, case-insensitive), in document order. */
    public final Map<String, Pattern> kwargs;
    /** {@code dictItems}: dictionary key → regex (find, case-insensitive), in document order. */
    public final Map<String, Pattern> dictItems;
    /** {@code notInside}: method names of operation calls the call must not be an argument of. */
    public final List<String> notInside;
    public final Pattern value;
    /** Lower-case needles. */
    public final List<String> valueContains;
    public final String paramKeyword;
    public final Integer paramIndex;
    public final boolean paramSelf;
    /** {@code param: {value: s}}: a fixed parameter-set identifier, or {@code null}. */
    public final String paramValue;
    public final boolean hasParam;
    public final List<String> reportAt;
    /** {@code noSymbolPrefix}: no symbol may start with one of these (SPEC 5.6, DECISIONS B-P-U1). */
    public final List<String> noSymbolPrefix;
    /** {@code minArgs}: the least number of positional arguments, or null. */
    public final Integer minArgs;
    /** {@code noString}: the call's string list (8.5.1) is empty (SPEC 5.6, DECISIONS B-P-U1 review). */
    public final boolean noString;
    /** {@code literal} anchor: exact string values (SPEC 5.6, DECISIONS B-P-LIT), or null. */
    public final List<String> literal;
    /** The feature switch the pattern belongs to (SPEC 5.6 {@code feature}), or null. */
    public final String feature;

    PythonPattern(SourceRule rule, int position, String call, List<String> methods, boolean anyCall, String assign,
            String ref, Pattern firstString, List<String> stringContains, List<String> anySymbol,
            List<String> allSymbols, Map<String, Pattern> kwargs, Map<String, Pattern> dictItems,
            List<String> notInside, Pattern value, List<String> valueContains, String paramKeyword,
            Integer paramIndex, boolean paramSelf, String paramValue, boolean hasParam, List<String> reportAt,
            List<String> noSymbolPrefix, Integer minArgs, boolean noString, List<String> literal, String feature) {
        this.rule = rule;
        this.position = position;
        this.call = call;
        this.methods = methods;
        this.anyCall = anyCall;
        this.assign = assign;
        this.ref = ref;
        this.firstString = firstString;
        this.stringContains = stringContains;
        this.anySymbol = anySymbol;
        this.allSymbols = allSymbols;
        this.kwargs = kwargs;
        this.dictItems = dictItems;
        this.notInside = notInside;
        this.value = value;
        this.valueContains = valueContains;
        this.paramKeyword = paramKeyword;
        this.paramIndex = paramIndex;
        this.paramSelf = paramSelf;
        this.paramValue = paramValue;
        this.hasParam = hasParam;
        this.reportAt = reportAt;
        this.noSymbolPrefix = noSymbolPrefix;
        this.minArgs = minArgs;
        this.noString = noString;
        this.literal = literal;
        this.feature = feature;
    }

    /**
     * Can the pattern fire on a bare reference (SPEC 8.6.1)? {@code ref} patterns, and {@code call}
     * patterns without any filter (only {@code param} and {@code reportAt}, which are not filters).
     */
    public boolean matchesReferences() {
        if (ref != null) {
            return true;
        }
        return call != null && methods == null && firstString == null && stringContains == null
                && anySymbol == null && allSymbols == null && kwargs == null && dictItems == null
                && notInside == null && noSymbolPrefix == null && minArgs == null && !noString;
    }

    /** The name a reference must resolve to: the {@code ref} or {@code call} value. */
    public String referenceName() {
        return ref != null ? ref : call;
    }

    @Override
    public String toString() {
        return rule.id() + "#" + position;
    }
}
