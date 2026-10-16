/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.syntax;

import io.github.treesitter.jtreesitter.Language;
import io.github.treesitter.jtreesitter.Node;
import io.github.treesitter.jtreesitter.Parser;
import io.github.treesitter.jtreesitter.Tree;
import io.github.treesitter.jtreesitter.TreeCursor;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentAllocator;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;

/**
 * Parses source text with tree-sitter and copies the tree into {@link SyntaxNode}s (SPEC 6.1).
 * The copy is made with an iterative cursor walk (SPEC 6.3), and the native tree is closed before
 * this method returns.
 */
public final class SyntaxTrees {
    private static final ConcurrentHashMap<Language, Symbols> SYMBOLS = new ConcurrentHashMap<>();

    private SyntaxTrees() {}

    /** Thrown when tree-sitter returns no tree (SPEC 6.1: a failure of that file). */
    public static final class ParseFailedException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public ParseFailedException(String message) {
            super(message);
        }
    }

    /** A parsed file: the copied root and whether tree-sitter reported syntax errors. */
    public record Parsed(SyntaxNode root, boolean hasError) {}

    /** Prepares the per-language tables and makes one throw-away parse (start-up optimisation only). */
    public static void warmUp(Language language) {
        try (Parser p = new Parser(language)) {
            parseChecked(p, language, "x");
        }
    }

    /** Parses {@code text} with {@code parser} (whose language is {@code language}). */
    public static SyntaxNode parse(Parser parser, Language language, String text) {
        return parseChecked(parser, language, text).root();
    }

    /** Like {@link #parse}, also reporting whether the tree contains ERROR or MISSING nodes. */
    public static Parsed parseChecked(Parser parser, Language language, String text) {
        Symbols sym = SYMBOLS.computeIfAbsent(language, Symbols::new);
        OffsetMap offsets = OffsetMap.of(text); // before parsing, so that nothing can fail between parse and close
        Optional<Tree> parsed = parser.parse(text);
        if (parsed.isEmpty()) {
            throw new ParseFailedException("tree-sitter returned no tree");
        }
        try (Tree tree = parsed.get(); Arena arena = Arena.ofConfined(); TreeCursor cur = tree.walk()) {
            boolean hasError = tree.getRootNode().hasError();
            COPIES.acquireUninterruptibly();
            try {
                return new Parsed(copy(cur, arena, sym, offsets, text), hasError);
            } finally {
                COPIES.release();
            }
        }
    }

    /**
     * Limits the number of threads copying trees at the same time. jtreesitter creates a
     * {@code Node} with its own automatic arena for every visited node, and every such arena is
     * registered with the JDK's single common {@code Cleaner}; with many threads copying at once
     * they mostly contend for the cleaner's lock (measured: 8 threads were slower than 4). Parsing
     * itself (native) and the analysis are not limited.
     */
    private static final Semaphore COPIES = new Semaphore(2);

    /**
     * Copies the tree in one iterative pre-order cursor walk (SPEC 6.3). The children of the nodes on
     * the current path are kept on one shared stack ({@code pending}); a node's frame starts at
     * {@code frames[depth]}.
     */
    private static SyntaxNode copy(TreeCursor cur, Arena arena, Symbols sym, OffsetMap offsets, String text) {
        MemorySegment scratch = arena.allocate(64, 8);
        SegmentAllocator alloc = SegmentAllocator.prefixAllocator(scratch);
        OffsetMap.Rows rows = offsets.rows();
        SyntaxNode[] path = new SyntaxNode[64];
        int[] frames = new int[64];
        SyntaxNode[] pending = new SyntaxNode[256];
        int pendingSize = 0;
        int depth = 0;
        SyntaxNode root = make(cur, alloc, sym, offsets, rows, text);
        path[0] = root;
        frames[0] = 0;
        while (true) {
            boolean down = cur.gotoFirstChild();
            if (!down) {
                // close finished nodes until one has a next sibling
                while (true) {
                    SyntaxNode done = path[depth];
                    int from = frames[depth];
                    if (pendingSize > from) {
                        done.children = Arrays.copyOfRange(pending, from, pendingSize);
                        Arrays.fill(pending, from, pendingSize, null);
                        pendingSize = from;
                    }
                    if (depth == 0) {
                        return root;
                    }
                    depth--;
                    if (cur.gotoNextSibling()) {
                        break;
                    }
                    if (!cur.gotoParent()) {
                        // cannot happen while depth > 0; keep the copy consistent anyway
                        throw new IllegalStateException("tree cursor lost its parent");
                    }
                }
            }
            SyntaxNode parent = path[depth];
            SyntaxNode n = make(cur, alloc, sym, offsets, rows, text);
            n.parent = parent;
            n.index = pendingSize - frames[depth];
            if (pendingSize == pending.length) {
                pending = Arrays.copyOf(pending, pendingSize * 2);
            }
            pending[pendingSize++] = n;
            depth++;
            if (depth == path.length) {
                path = Arrays.copyOf(path, depth * 2);
                frames = Arrays.copyOf(frames, depth * 2);
            }
            path[depth] = n;
            frames[depth] = pendingSize;
        }
    }

    private static SyntaxNode make(TreeCursor cur, SegmentAllocator alloc, Symbols sym, OffsetMap offsets,
            OffsetMap.Rows rows, String text) {
        Node n = cur.getCurrentNode(alloc);
        int s = n.getSymbol() & 0xFFFF;
        String type;
        boolean named;
        if (s < sym.types.length) {
            type = sym.types[s];
            named = sym.named[s];
        } else {
            type = n.getType();
            named = n.isNamed();
        }
        int fid = cur.getCurrentFieldId() & 0xFFFF;
        String field = fid == 0 || fid >= sym.fields.length ? null : sym.fields[fid];
        int start = offsets.toChar(n.getStartByte());
        int end = offsets.toChar(n.getEndByte());
        return new SyntaxNode(text, type, named, field, start, end, rows.row(start));
    }

    /** Cached symbol and field names of a language. */
    private static final class Symbols {
        final String[] types;
        final boolean[] named;
        final String[] fields;

        Symbols(Language lang) {
            int n = lang.getSymbolCount();
            types = new String[n];
            named = new boolean[n];
            for (int i = 0; i < n; i++) {
                String t = lang.getSymbolName((short) i);
                types[i] = t == null ? "" : t.intern();
                named[i] = lang.isNamed((short) i);
            }
            int f = lang.getFieldCount();
            fields = new String[f + 1];
            for (int i = 1; i <= f; i++) {
                String name = lang.getFieldNameForId((short) i);
                fields[i] = name == null ? null : name.intern();
            }
        }
    }

    /** Maps UTF-8 byte offsets to char indices. */
    static final class OffsetMap {
        private final int[] map;
        /** Char offsets of the line starts (index = 0-based row); only the first {@code lineCount} are used. */
        private int[] lineStarts;
        private int lineCount;

        private OffsetMap(int[] map) {
            this.map = map;
        }

        /** 0-based row of a char offset: the number of LF characters before it (SPEC 1.3, 6.1). */
        int row(int charOffset) {
            int lo = 0;
            int hi = lineCount - 1;
            while (lo < hi) {
                int mid = (lo + hi + 1) >>> 1;
                if (lineStarts[mid] <= charOffset) {
                    lo = mid;
                } else {
                    hi = mid - 1;
                }
            }
            return lo;
        }

        /**
         * A row finder for offsets that mostly arrive in non-decreasing order (a pre-order walk):
         * it moves forward from the previous row and falls back to binary search otherwise.
         */
        Rows rows() {
            return new Rows(this);
        }

        static final class Rows {
            private final OffsetMap m;
            private int row;

            Rows(OffsetMap m) {
                this.m = m;
            }

            int row(int charOffset) {
                int[] ls = m.lineStarts;
                int r = row;
                if (ls[r] > charOffset) {
                    r = m.row(charOffset);
                } else {
                    int last = m.lineCount - 1;
                    while (r < last && ls[r + 1] <= charOffset) {
                        r++;
                    }
                }
                row = r;
                return r;
            }
        }

        static OffsetMap of(String text) {
            int n = text.length();
            int[] ls = new int[Math.max(16, n / 40)];
            int lines = 1;
            boolean ascii = true;
            for (int i = 0; i < n; i++) {
                char c = text.charAt(i);
                if (c == '\n') {
                    if (lines == ls.length) {
                        ls = Arrays.copyOf(ls, lines * 2);
                    }
                    ls[lines++] = i + 1;
                } else if (c >= 0x80) {
                    ascii = false;
                }
            }
            OffsetMap m = ascii ? new OffsetMap(null) : of0(text);
            m.lineStarts = ls;
            m.lineCount = lines;
            return m;
        }

        private static OffsetMap of0(String text) {
            int bytes = 0;
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                if (c < 0x80) {
                    bytes += 1;
                } else if (c < 0x800) {
                    bytes += 2;
                } else if (Character.isHighSurrogate(c) && i + 1 < text.length()
                        && Character.isLowSurrogate(text.charAt(i + 1))) {
                    bytes += 4;
                    i++;
                } else {
                    bytes += 3;
                }
            }
            int[] m = new int[bytes + 1];
            int b = 0;
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                int len;
                int width = 1;
                if (c < 0x80) {
                    len = 1;
                } else if (c < 0x800) {
                    len = 2;
                } else if (Character.isHighSurrogate(c) && i + 1 < text.length()
                        && Character.isLowSurrogate(text.charAt(i + 1))) {
                    len = 4;
                    width = 2;
                } else {
                    len = 3;
                }
                for (int k = 0; k < len; k++) {
                    m[b + k] = i;
                }
                b += len;
                i += width - 1;
            }
            m[bytes] = text.length();
            return new OffsetMap(m);
        }

        int toChar(int byteOffset) {
            if (map == null) {
                return byteOffset;
            }
            if (byteOffset < 0) {
                return 0;
            }
            if (byteOffset >= map.length) {
                return map[map.length - 1];
            }
            return map[byteOffset];
        }
    }
}
