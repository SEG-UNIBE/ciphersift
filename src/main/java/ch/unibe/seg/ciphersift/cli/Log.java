/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.cli;

import java.io.PrintStream;

/** Standard-error logging, {@code ciphersift: <level>: <message>} (SPEC 3.2). Thread-safe. */
public final class Log {
    /** Log levels, most severe first. */
    public enum Level { ERROR, WARNING, INFO, DEBUG }

    private static volatile Level threshold = Level.INFO;
    private static volatile PrintStream out = System.err;

    private Log() {}

    public static void setThreshold(Level level) {
        threshold = level;
    }

    public static Level threshold() {
        return threshold;
    }

    /** Redirects output (tests). */
    public static void setOutput(PrintStream stream) {
        out = stream;
    }

    public static boolean enabled(Level level) {
        return level.ordinal() <= threshold.ordinal();
    }

    public static void error(String message) {
        log(Level.ERROR, message);
    }

    public static void warning(String message) {
        log(Level.WARNING, message);
    }

    public static void info(String message) {
        log(Level.INFO, message);
    }

    public static void debug(String message) {
        log(Level.DEBUG, message);
    }

    /**
     * Escapes control characters (C0, DEL, C1) as {@code \\uXXXX}: messages contain file names from the
     * scanned (untrusted) repository, which must not inject terminal escape sequences or extra lines.
     */
    static String sanitise(String message) {
        if (message == null) {
            return "null";
        }
        StringBuilder b = null;
        for (int i = 0; i < message.length(); i++) {
            char c = message.charAt(i);
            boolean control = c < 0x20 || (c >= 0x7F && c <= 0x9F);
            if (control && b == null) {
                b = new StringBuilder(message.length() + 16);
                b.append(message, 0, i);
            }
            if (b != null) {
                if (control) {
                    b.append(String.format(java.util.Locale.ROOT, "\\u%04X", (int) c));
                } else {
                    b.append(c);
                }
            }
        }
        return b == null ? message : b.toString();
    }

    public static void log(Level level, String message) {
        if (!enabled(level)) {
            return;
        }
        String line = "ciphersift: " + level.name().toLowerCase(java.util.Locale.ROOT) + ": " + sanitise(message);
        PrintStream o = out;
        synchronized (Log.class) {
            o.println(line);
            o.flush();
        }
    }
}
