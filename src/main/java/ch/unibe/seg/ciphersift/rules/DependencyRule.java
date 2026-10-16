/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.rules;

import java.util.List;
import java.util.regex.Pattern;

/** A dependency rule (SPEC 5.9): the crypto-library list of one ecosystem. */
public final class DependencyRule {
    private final String id;
    private final String ecosystem;
    private final String name;
    private final List<Pattern> packages;

    DependencyRule(String id, String ecosystem, String name, List<Pattern> packages) {
        this.id = id;
        this.ecosystem = ecosystem;
        this.name = name;
        this.packages = packages;
    }

    public String id() {
        return id;
    }

    public String ecosystem() {
        return ecosystem;
    }

    public String name() {
        return name;
    }

    /** True iff the package key matches at least one pattern (whole key, case-insensitive). */
    public boolean matches(String key) {
        for (Pattern p : packages) {
            if (p.matcher(key).matches()) {
                return true;
            }
        }
        return false;
    }

    /** Compiles a package pattern: {@code *} matches any run of characters, everything else literally. */
    static Pattern compilePackage(String pattern) {
        StringBuilder re = new StringBuilder();
        int last = 0;
        for (int i = 0; i < pattern.length(); i++) {
            if (pattern.charAt(i) == '*') {
                if (i > last) {
                    re.append(Pattern.quote(pattern.substring(last, i)));
                }
                re.append(".*");
                last = i + 1;
            }
        }
        if (last < pattern.length()) {
            re.append(Pattern.quote(pattern.substring(last)));
        }
        return Pattern.compile(re.toString(), Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
    }
}
