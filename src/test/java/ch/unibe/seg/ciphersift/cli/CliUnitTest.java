/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

/** Small CLI helpers: log sanitising (SPEC 3.2) and SOURCE_DATE_EPOCH (SPEC 11.2.1). */
class CliUnitTest {
    @Test
    void logLinesCannotBeSplitOrCarryTerminalEscapes() {
        assertEquals("cannot read a\\u001B[31mb\\u000Ac.py", Log.sanitise("cannot read a\u001B[31mb\nc.py"));
        assertEquals("café 中 \\u0009?", Log.sanitise("café 中 \t?"));
        assertEquals("x\\u0085y\\u007F", Log.sanitise("x\u0085y\u007F"));
        assertEquals("plain", Log.sanitise("plain"));
    }

    @Test
    void sourceDateEpoch() {
        assertEquals(1767225600L, ScanCommand.parseSourceDateEpoch("1767225600"));
        assertEquals(0L, ScanCommand.parseSourceDateEpoch("0"));
        assertNull(ScanCommand.parseSourceDateEpoch(null));
        assertNull(ScanCommand.parseSourceDateEpoch("-1"));
        assertNull(ScanCommand.parseSourceDateEpoch("1.5"));
        assertNull(ScanCommand.parseSourceDateEpoch(" 1"));
        assertNull(ScanCommand.parseSourceDateEpoch("99999999999999999"), "beyond Instant.MAX");
        assertNull(ScanCommand.parseSourceDateEpoch("99999999999999999999"), "beyond long");
    }

    /** The Java-8 entry point's version check (DECISIONS follow-up F1). */
    @Test
    void javaVersionCheck() {
        assertEquals(8, ch.unibe.seg.ciphersift.MainAccess.javaMajor("1.8"));
        assertEquals(21, ch.unibe.seg.ciphersift.MainAccess.javaMajor("21"));
        assertEquals(25, ch.unibe.seg.ciphersift.MainAccess.javaMajor("25"));
        assertEquals(26, ch.unibe.seg.ciphersift.MainAccess.javaMajor("26-ea"));
        assertEquals(0, ch.unibe.seg.ciphersift.MainAccess.javaMajor(null));
        assertEquals(0, ch.unibe.seg.ciphersift.MainAccess.javaMajor("x"));
        assertEquals("ciphersift: error: CipherSift needs Java 23 or newer; found 21.0.2; set CIPHERSIFT_JAVA or JAVA_HOME",
                ch.unibe.seg.ciphersift.MainAccess.tooOld("21.0.2"));
    }
}
