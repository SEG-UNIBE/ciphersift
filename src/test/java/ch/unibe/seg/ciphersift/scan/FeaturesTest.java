/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class FeaturesTest {
    @Test
    void defaultsAndOverrides() {
        assertFalse(Features.DEFAULTS.on(Features.TRANSITIVE_DEPS));
        assertNull(Features.DEFAULTS.describe());
        Features f = Features.parse(List.of("transitive-deps=on"), Features.DEFAULTS);
        assertTrue(f.on(Features.TRANSITIVE_DEPS));
        assertEquals("transitive-deps=on", f.describe());
        // a later setting wins; setting the default removes the override
        Features g = Features.parse(List.of("transitive-deps=on", "transitive-deps=off"), Features.DEFAULTS);
        assertNull(g.describe());
        assertEquals(Features.DEFAULTS, g);
    }

    @Test
    void errors() {
        assertThrows(IllegalArgumentException.class, () -> Features.parse(List.of("nope=on"), Features.DEFAULTS));
        assertThrows(IllegalArgumentException.class, () -> Features.parse(List.of("transitive-deps"), Features.DEFAULTS));
        assertThrows(IllegalArgumentException.class,
                () -> Features.parse(List.of("transitive-deps=maybe"), Features.DEFAULTS));
    }
}
