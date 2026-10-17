/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/** Version information. */
public final class CipherSift {
    private static final Properties PROPS = load();

    private CipherSift() {}

    private static Properties load() {
        Properties p = new Properties();
        try (InputStream in = CipherSift.class.getResourceAsStream("version.properties")) {
            if (in != null) {
                p.load(in);
            }
        } catch (IOException ex) {
            // defaults below
        }
        return p;
    }

    /** CipherSift version, e.g. {@code 1.1.1}. */
    public static String version() {
        return PROPS.getProperty("version", "unknown");
    }

    /** The jtreesitter version CipherSift was built with. */
    public static String jtreesitterVersion() {
        return PROPS.getProperty("jtreesitter", "unknown");
    }
}
