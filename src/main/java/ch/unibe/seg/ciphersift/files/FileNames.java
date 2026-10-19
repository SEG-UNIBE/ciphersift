/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.files;

import java.io.ByteArrayOutputStream;
import java.io.IOError;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.Locale;

/**
 * File names decoded as UTF-8 whatever the locale (DECISIONS O1, SPEC 12).
 *
 * <p>The JVM decodes file names with {@code sun.jnu.encoding}, which follows the locale and cannot be
 * overridden; under a C/POSIX locale every non-ASCII byte becomes U+FFFD. The raw bytes of a name
 * are still available through {@link Path#toUri()}, which percent-encodes them. When the JVM's
 * file-name charset is not UTF-8, names containing non-ASCII characters are therefore decoded from
 * those bytes, giving exactly the names (malformed bytes → U+FFFD) a UTF-8 locale would give.
 */
public final class FileNames {
    /** Does the JVM decode file names as UTF-8 already? */
    static final boolean JNU_UTF8 = isUtf8(System.getProperty("sun.jnu.encoding"));

    private FileNames() {}

    static boolean isUtf8(String charset) {
        if (charset == null) {
            return false;
        }
        String c = charset.toLowerCase(Locale.ROOT).replace("-", "").replace("_", "");
        return c.equals("utf8");
    }

    /** Is the JVM's file-name charset UTF-8 (so that file names need no special handling)? */
    public static boolean jvmUsesUtf8() {
        return JNU_UTF8;
    }

    /** The last name element of {@code p} decoded as UTF-8, or {@code ""} if it has none. */
    public static String name(Path p) {
        Path f = p.getFileName();
        if (f == null) {
            return "";
        }
        String s = f.toString();
        if (JNU_UTF8 || isAscii(s)) {
            return s; // ASCII bytes decode identically in every charset the JVM uses for file names
        }
        return fromUri(p);
    }

    private static boolean isAscii(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) >= 0x80) {
                return false;
            }
        }
        return true;
    }

    /** Decodes the last segment of the URI's raw (percent-encoded) path as UTF-8. */
    private static String fromUri(Path p) {
        String raw;
        try {
            raw = p.toUri().getRawPath();
        } catch (RuntimeException | IOError ex) {
            return p.getFileName().toString();
        }
        if (raw == null) {
            return p.getFileName().toString();
        }
        int end = raw.length();
        while (end > 1 && raw.charAt(end - 1) == '/') {
            end--; // directories get a trailing slash
        }
        int start = raw.lastIndexOf('/', end - 1) + 1;
        ByteArrayOutputStream b = new ByteArrayOutputStream(end - start);
        for (int i = start; i < end; i++) {
            char c = raw.charAt(i);
            if (c == '%' && i + 2 < end) {
                int hi = Character.digit(raw.charAt(i + 1), 16);
                int lo = Character.digit(raw.charAt(i + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    b.write(hi * 16 + lo);
                    i += 2;
                    continue;
                }
            }
            b.write(c); // the raw path is ASCII
        }
        return new String(b.toByteArray(), StandardCharsets.UTF_8);
    }

    /**
     * {@code dir.resolve(name)} for a name given as text, also when the name cannot be encoded in the
     * JVM's file-name charset: then the directory entry whose UTF-8 name equals {@code name} is
     * returned, or null if there is none.
     */
    public static Path resolve(Path dir, String name) {
        if (JNU_UTF8 || isAscii(name)) {
            try {
                return dir.resolve(name);
            } catch (InvalidPathException ex) {
                return null;
            }
        }
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
            for (Path p : ds) {
                if (name.equals(name(p))) {
                    return p;
                }
            }
        } catch (IOException | DirectoryIteratorException | SecurityException ex) {
            return null;
        }
        return null;
    }
}
