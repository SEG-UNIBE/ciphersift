/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.files;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/** Byte-level helpers: decoding (SPEC 4.4) and binary detection (SPEC 4.6). */
public final class SourceText {
    /** Size limit for source files and manifests (SPEC 4.3). */
    public static final long MAX_SIZE = 10L * 1024 * 1024;

    private SourceText() {}

    /** Thrown by {@link #readBounded} when the file is larger than {@link #MAX_SIZE}. */
    public static final class TooLargeException extends IOException {
        private static final long serialVersionUID = 1L;

        public TooLargeException(String message) {
            super(message);
        }
    }

    /**
     * Reads a regular file completely, without following a symbolic link (the file may have been
     * replaced by a link since it was collected) and without reading more than {@link #MAX_SIZE}
     * bytes (the file may have grown since its size was checked).
     *
     * @throws TooLargeException if the file has more than {@link #MAX_SIZE} bytes
     */
    public static byte[] readBounded(Path path) throws IOException {
        try (InputStream in = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            byte[] data = in.readNBytes((int) MAX_SIZE + 1);
            if (data.length > MAX_SIZE) {
                throw new TooLargeException("larger than 10 MiB");
            }
            return data;
        }
    }

    /** Decodes UTF-8, removing a leading BOM and replacing malformed input by U+FFFD. */
    public static String decode(byte[] bytes) {
        int off = 0;
        if (bytes.length >= 3 && (bytes[0] & 0xFF) == 0xEF && (bytes[1] & 0xFF) == 0xBB && (bytes[2] & 0xFF) == 0xBF) {
            off = 3;
        }
        CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE)
                .replaceWith("�");
        try {
            CharBuffer cb = dec.decode(ByteBuffer.wrap(bytes, off, bytes.length - off));
            return cb.toString();
        } catch (CharacterCodingException ex) {
            // cannot happen with REPLACE
            throw new IllegalStateException(ex);
        }
    }

    /** Binary content check: control bytes 0x00–0x08, 0x0E–0x1F in the first 8 KiB, count × 10 > n. */
    public static boolean isBinary(byte[] bytes) {
        int n = Math.min(8192, bytes.length);
        if (n == 0) {
            return false;
        }
        int count = 0;
        for (int i = 0; i < n; i++) {
            int b = bytes[i] & 0xFF;
            if (b <= 0x08 || (b >= 0x0E && b <= 0x1F)) {
                count++;
            }
        }
        return (long) count * 10 > n;
    }
}
