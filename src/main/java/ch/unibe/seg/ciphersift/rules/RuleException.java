/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.rules;

import java.util.List;

/** Rule loading or validation failed (exit code 4, SPEC 5.8). Each problem names file and JSON pointer. */
public final class RuleException extends Exception {
    private static final long serialVersionUID = 1L;
    private final List<String> problems;

    public RuleException(List<String> problems) {
        super(String.join("; ", problems));
        this.problems = List.copyOf(problems);
    }

    public RuleException(String problem) {
        this(List.of(problem));
    }

    public List<String> problems() {
        return problems;
    }
}
