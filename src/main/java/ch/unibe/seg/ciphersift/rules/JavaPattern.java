/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.rules;

import java.util.List;
import java.util.regex.Pattern;

/** One Java pattern (SPEC 5.5), compiled. */
public final class JavaPattern {
    /** Pattern anchors. */
    public enum Anchor { CALL, NEW, METHOD, FIELD, OVERRIDE, ANY_CALL }

    /** Event kinds used as index keys (SPEC 7.5). */
    public enum EventKind { CALL, NEW, FIELD, DECL }

    public final SourceRule rule;
    public final int position;
    public final Anchor anchor;
    /** The class {@code C} of {@code call}, {@code new}, {@code field}; {@code null} otherwise. */
    public final String className;
    /** The member ({@code m}, {@code F}, method name) without a trailing {@code *}; for {@code new} the last segment. */
    public final String member;
    /** True if the member ends with {@code *} (prefix match). */
    public final boolean prefix;

    public final Pattern firstString;
    public final Pattern anyString;
    /** Lower-case needles. */
    public final List<String> stringContains;
    public final Pattern argsText;
    public final List<String> argsTextContains;
    public final Integer constantArg;
    public final List<String> inType;
    public final Pattern body;
    public final Integer paramIndex;
    public final int specificity;
    /** The feature switch the pattern belongs to (SPEC 5.5 {@code feature}), or null. */
    public final String feature;

    JavaPattern(SourceRule rule, int position, Anchor anchor, String className, String member, boolean prefix,
            Pattern firstString, Pattern anyString, List<String> stringContains, Pattern argsText,
            List<String> argsTextContains, Integer constantArg, List<String> inType, Pattern body,
            Integer paramIndex, boolean hasCondition, String feature) {
        this.rule = rule;
        this.position = position;
        this.anchor = anchor;
        this.className = className;
        this.member = member;
        this.prefix = prefix;
        this.firstString = firstString;
        this.anyString = anyString;
        this.stringContains = stringContains;
        this.argsText = argsText;
        this.argsTextContains = argsTextContains;
        this.constantArg = constantArg;
        this.inType = inType;
        this.body = body;
        this.paramIndex = paramIndex;
        this.specificity = hasCondition ? 2 : 1;
        this.feature = feature;
    }

    /** The event kind this pattern is indexed under. */
    public EventKind eventKind() {
        return switch (anchor) {
            case CALL, METHOD, ANY_CALL -> EventKind.CALL;
            case NEW -> EventKind.NEW;
            case FIELD -> EventKind.FIELD;
            case OVERRIDE -> EventKind.DECL;
        };
    }

    /** Does an event name match the member (exactly or as prefix)? */
    public boolean nameMatches(String name) {
        return prefix ? name.startsWith(member) : name.equals(member);
    }

    @Override
    public String toString() {
        return rule.id() + "#" + position;
    }
}
