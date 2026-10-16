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

    public final Pattern firstString;
    /** Lower-case needles. */
    public final List<String> stringContains;
    public final List<String> anySymbol;
    public final List<String> allSymbols;
    /** keyword → regex (find, case-insensitive), in document order. */
    public final Map<String, Pattern> kwargs;
    public final Pattern value;
    /** Lower-case needles. */
    public final List<String> valueContains;
    public final String paramKeyword;
    public final Integer paramIndex;
    public final boolean paramSelf;
    public final boolean hasParam;
    public final List<String> reportAt;

    PythonPattern(SourceRule rule, int position, String call, List<String> methods, boolean anyCall, String assign,
            Pattern firstString, List<String> stringContains, List<String> anySymbol, List<String> allSymbols,
            Map<String, Pattern> kwargs, Pattern value, List<String> valueContains, String paramKeyword,
            Integer paramIndex, boolean paramSelf, boolean hasParam, List<String> reportAt) {
        this.rule = rule;
        this.position = position;
        this.call = call;
        this.methods = methods;
        this.anyCall = anyCall;
        this.assign = assign;
        this.firstString = firstString;
        this.stringContains = stringContains;
        this.anySymbol = anySymbol;
        this.allSymbols = allSymbols;
        this.kwargs = kwargs;
        this.value = value;
        this.valueContains = valueContains;
        this.paramKeyword = paramKeyword;
        this.paramIndex = paramIndex;
        this.paramSelf = paramSelf;
        this.hasParam = hasParam;
        this.reportAt = reportAt;
    }

    @Override
    public String toString() {
        return rule.id() + "#" + position;
    }
}
