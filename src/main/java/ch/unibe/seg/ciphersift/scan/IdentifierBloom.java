/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.scan;

/**
 * A Bloom filter of the identifiers (SPEC 18.2) of a source file that phase 3 did not parse, built
 * while the text is in memory. Wrapper propagation reads such a file again only if a callable's name
 * may occur in it; a false positive costs one extra read (the exact check follows), a false negative
 * cannot happen.
 */
final class IdentifierBloom {
    private static final int MIN_BITS = 512;
    private static final int MAX_BITS = 1 << 16;
    private static final int PROBES = 3;

    private final long[] bits;
    private final int mask;

    private IdentifierBloom(int nbits) {
        bits = new long[nbits / 64];
        mask = nbits - 1;
    }

    static IdentifierBloom of(String text) {
        int count = 0;
        int n = text.length();
        for (int i = 0; i < n;) {
            char c = text.charAt(i);
            if (Character.isLetter(c) || c == '_' || c == '$') {
                count++;
                while (i < n && isPart(text.charAt(i))) {
                    i++;
                }
            } else if (Character.isDigit(c)) {
                while (i < n && (Character.isLetterOrDigit(text.charAt(i)) || text.charAt(i) == '_')) {
                    i++;
                }
            } else {
                i++;
            }
        }
        int want = Math.min(MAX_BITS, Math.max(MIN_BITS, Integer.highestOneBit(Math.max(1, count * 8)) << 1));
        IdentifierBloom b = new IdentifierBloom(want);
        for (int i = 0; i < n;) {
            char c = text.charAt(i);
            if (Character.isLetter(c) || c == '_' || c == '$') {
                int h = 0;
                while (i < n && isPart(text.charAt(i))) {
                    h = 31 * h + text.charAt(i);
                    i++;
                }
                b.add(h);
            } else if (Character.isDigit(c)) {
                while (i < n && (Character.isLetterOrDigit(text.charAt(i)) || text.charAt(i) == '_')) {
                    i++;
                }
            } else {
                i++;
            }
        }
        return b;
    }

    private static boolean isPart(char d) {
        return Character.isLetterOrDigit(d) || d == '_' || d == '$';
    }

    private static int second(int h) {
        int x = h * 0x9E3779B9;
        return (x ^ (x >>> 16)) | 1;
    }

    private void add(int h) {
        int g = second(h);
        for (int k = 0; k < PROBES; k++) {
            int bit = (h + k * g) & mask;
            bits[bit >>> 6] |= 1L << (bit & 63);
        }
    }

    /** False if {@code name} certainly does not occur as an identifier. */
    boolean mightContain(String name) {
        int h = name.hashCode();
        int g = second(h);
        for (int k = 0; k < PROBES; k++) {
            int bit = (h + k * g) & mask;
            if ((bits[bit >>> 6] & (1L << (bit & 63))) == 0) {
                return false;
            }
        }
        return true;
    }
}
