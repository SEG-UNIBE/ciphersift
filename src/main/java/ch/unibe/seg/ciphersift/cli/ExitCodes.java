/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.cli;

/** Exit codes (SPEC 3.3). */
public final class ExitCodes {
    public static final int OK = 0;
    public static final int INTERNAL = 1;
    public static final int USAGE = 2;
    public static final int SCAN_ROOT = 3;
    public static final int RULES = 4;
    public static final int OUTPUT = 5;
    public static final int INTERRUPTED = 130;

    private ExitCodes() {}

    /** An error that ends the command with a given exit code; the message is logged at error level. */
    public static final class ExitException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final int code;

        public ExitException(int code, String message) {
            super(message);
            this.code = code;
        }

        public ExitException(int code, String message, Throwable cause) {
            super(message, cause);
            this.code = code;
        }

        public int code() {
            return code;
        }
    }
}
