/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.natives;

/** The native libraries cannot be provided or loaded (exit code 1, SPEC 13). */
public final class NativeLoadException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public NativeLoadException(String message) {
        super(message);
    }

    public NativeLoadException(String message, Throwable cause) {
        super(message, cause);
    }
}
