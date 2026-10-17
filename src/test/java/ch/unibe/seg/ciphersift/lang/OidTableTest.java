/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.unibe.seg.ciphersift.TestSupport;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/** The built-in OID table (SPEC 5.11, DECISIONS E15). */
class OidTableTest {
    @Test
    void lookupNeedsExactlyADottedOid() {
        assertEquals("SHA256withECDSA", OidTable.lookup("1.2.840.10045.4.3.2").name());
        assertEquals("1.2.840.10045.4.3.2", OidTable.lookup("OID.1.2.840.10045.4.3.2").oid());
        assertEquals("SHA-256", OidTable.lookup("oid.2.16.840.1.101.3.4.2.1").name());
        assertNull(OidTable.lookup(" 1.2.840.10045.4.3.2"));
        assertNull(OidTable.lookup("1.2.840.10045.4.3.2 "));
        assertNull(OidTable.lookup("1.2.840.10045.4.3.2.1"));
        assertNull(OidTable.lookup("1.2.840.10045.04.3.2"), "leading zero");
        assertNull(OidTable.lookup("2.5.4.3"), "commonName is not an algorithm");
        assertNull(OidTable.lookup("SHA-256"));
        assertNull(OidTable.lookup(""));
        assertNull(OidTable.lookup(null));
        assertEquals("AES", OidTable.map("AES"));
        assertEquals("secp256r1", OidTable.map("1.2.840.10045.3.1.7"));
        assertNull(OidTable.map(null));
    }

    @Test
    void tableHasNoDuplicatesAndOnlyWellFormedOids() {
        List<String> seen = new ArrayList<>();
        for (OidTable.Entry e : OidTable.entries()) {
            assertTrue(e.oid().matches("[0-2](\\.(0|[1-9][0-9]*))+"), e.oid());
            assertTrue(!seen.contains(e.oid()), "duplicate " + e.oid());
            seen.add(e.oid());
            assertEquals(e, OidTable.lookup(e.oid()));
        }
        assertEquals(128, seen.size());
    }

    /** The table in SPEC 5.11 is the documentation of this table: same rows, same order. */
    @Test
    void tableEqualsTheSpecTable() throws Exception {
        String spec = Files.readString(TestSupport.baseDir().resolve("spec/SPEC.md"), StandardCharsets.UTF_8);
        int start = spec.indexOf("### 5.11 Algorithm OIDs");
        int end = spec.indexOf("\n---", start);
        Matcher m = Pattern.compile("(?m)^\\| `([0-9.]+)` \\| ([^|]+) \\| `([^`]+)` \\|").matcher(spec.substring(start, end));
        List<String> documented = new ArrayList<>();
        while (m.find()) {
            documented.add(m.group(1) + " " + m.group(2).trim() + " " + m.group(3));
        }
        List<String> table = new ArrayList<>();
        for (OidTable.Entry e : OidTable.entries()) {
            table.add(e.oid() + " " + e.asn1Name() + " " + e.name());
        }
        assertEquals(table, documented);
    }
}
