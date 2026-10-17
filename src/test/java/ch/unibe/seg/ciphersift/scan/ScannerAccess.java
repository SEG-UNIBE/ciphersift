/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.scan;

import java.util.Set;

/** Test access to package-private helpers of {@link Scanner}. */
public final class ScannerAccess {
    private ScannerAccess() {}

    public static boolean hasIdentifier(String text, Set<String> names) {
        return Scanner.hasIdentifier(text, names);
    }
}
