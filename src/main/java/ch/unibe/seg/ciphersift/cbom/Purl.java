/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.cbom;

import java.nio.charset.StandardCharsets;

/** Package URLs of library components (SPEC 11.3.5). */
public final class Purl {
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private Purl() {}

    /** {@code pkg:maven/<groupId>/<artifactId>[@<version>]}. */
    public static String maven(String groupId, String artifactId, String version) {
        return "pkg:maven/" + encode(groupId) + "/" + encode(artifactId) + (version == null ? "" : "@" + encode(version));
    }

    /** {@code pkg:pypi/<name>[@<version>]}. */
    public static String pypi(String name, String version) {
        return "pkg:pypi/" + encode(name) + (version == null ? "" : "@" + encode(version));
    }

    /** Percent-encodes every character outside {@code A-Z a-z 0-9 . - _ ~} (UTF-8, upper-case hex). */
    public static String encode(String s) {
        StringBuilder b = new StringBuilder(s.length());
        for (byte x : s.getBytes(StandardCharsets.UTF_8)) {
            int c = x & 0xFF;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '-' || c == '_' || c == '~') {
                b.append((char) c);
            } else {
                b.append('%').append(HEX[c >> 4]).append(HEX[c & 0xF]);
            }
        }
        return b.toString();
    }
}
