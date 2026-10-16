/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Entry point of the {@code ciphersift} command (SPEC 3).
 *
 * <p>This class is compiled for Java 8 (class-file version 52) so that an older runtime can still
 * load it and report a clear error instead of an {@code UnsupportedClassVersionError}: it checks the
 * runtime version first and only then calls the real command line ({@code cli.Main}, Java 23)
 * reflectively. It must not refer to any other CipherSift class directly.
 */
public final class Main {
    /** The minimum Java version (SPEC 15.2: {@code release 23}). */
    static final int MIN_JAVA = 23;
    /** Exit code for a Java runtime that is too old (SPEC 3.3). */
    static final int EXIT_OLD_JAVA = 6;

    private Main() {}

    public static void main(String[] args) {
        int code = run(args);
        System.out.flush();
        System.err.flush();
        Runtime.getRuntime().exit(code);
    }

    /** Runs the command line without exiting the JVM; returns the exit code. */
    public static int run(String... args) {
        int major = javaMajor(System.getProperty("java.specification.version"));
        if (major != 0 && major < MIN_JAVA) { // unknown (0): try anyway
            System.err.println(tooOld(System.getProperty("java.version")));
            return EXIT_OLD_JAVA;
        }
        try {
            Method m = Class.forName("ch.unibe.seg.ciphersift.cli.Main").getMethod("run", String[].class);
            return (Integer) m.invoke(null, (Object) args);
        } catch (InvocationTargetException ex) {
            Throwable c = ex.getCause();
            if (c instanceof RuntimeException) {
                throw (RuntimeException) c;
            }
            if (c instanceof Error) {
                throw (Error) c;
            }
            throw new IllegalStateException(c);
        } catch (ReflectiveOperationException ex) {
            throw new IllegalStateException("cannot start CipherSift: " + ex, ex);
        }
    }

    /** The one-line error for a runtime that is too old. */
    static String tooOld(String found) {
        return "ciphersift: error: CipherSift needs Java " + MIN_JAVA + " or newer; found "
                + (found == null || found.isEmpty() ? "unknown" : found) + "; set CIPHERSIFT_JAVA or JAVA_HOME";
    }

    /** Major version of {@code java.specification.version} ({@code 1.8} → 8, {@code 25} → 25); 0 if unknown. */
    static int javaMajor(String spec) {
        if (spec == null) {
            return 0;
        }
        String s = spec.startsWith("1.") ? spec.substring(2) : spec;
        int end = 0;
        while (end < s.length() && Character.isDigit(s.charAt(end))) {
            end++;
        }
        if (end == 0) {
            return 0;
        }
        try {
            return Integer.parseInt(s.substring(0, end));
        } catch (NumberFormatException ex) {
            return 0;
        }
    }
}
