/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift;

/** Test access to the package-private helpers of {@link Main}. */
public final class MainAccess {
    private MainAccess() {}

    public static int javaMajor(String spec) {
        return Main.javaMajor(spec);
    }

    public static String tooOld(String found) {
        return Main.tooOld(found);
    }
}
