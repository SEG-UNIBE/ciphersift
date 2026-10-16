/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.natives;

import java.util.List;
import java.util.Locale;

/** Platform ids for the bundled native libraries (SPEC 15.3). */
public final class Platform {
    /** Platform ids that a jar may contain, in display order. */
    public static final List<String> KNOWN = List.of(
            "linux-x86_64", "linux-aarch64", "darwin-aarch64", "darwin-x86_64", "windows-x86_64");

    private Platform() {}

    /** The platform id of the running JVM, e.g. {@code linux-x86_64}. */
    public static String current() {
        return id(System.getProperty("os.name", ""), System.getProperty("os.arch", ""));
    }

    static String id(String osName, String osArch) {
        String n = osName.toLowerCase(Locale.ROOT);
        String os;
        if (n.startsWith("linux")) {
            os = "linux";
        } else if (n.startsWith("mac") || n.startsWith("darwin")) {
            os = "darwin";
        } else if (n.startsWith("windows")) {
            os = "windows";
        } else {
            os = n.replace(' ', '_');
        }
        String a = osArch.toLowerCase(Locale.ROOT);
        String arch = switch (a) {
            case "amd64", "x86_64" -> "x86_64";
            case "aarch64", "arm64" -> "aarch64";
            default -> a;
        };
        return os + "-" + arch;
    }

    /** File name of a shared library for the platform, e.g. {@code libtree-sitter-java.so}. */
    public static String libraryFile(String platform, String base) {
        if (platform.startsWith("darwin-")) {
            return "lib" + base + ".dylib";
        }
        if (platform.startsWith("windows-")) {
            return "lib" + base + ".dll";
        }
        return "lib" + base + ".so";
    }
}
