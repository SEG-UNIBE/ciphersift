/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang.java;

import ch.unibe.seg.ciphersift.files.SourceText;
import ch.unibe.seg.ciphersift.syntax.SyntaxNode;
import ch.unibe.seg.ciphersift.syntax.SyntaxTrees;
import io.github.treesitter.jtreesitter.Language;
import io.github.treesitter.jtreesitter.Parser;
import java.io.File;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Cross-file constant contexts (SPEC 7.4.5): contexts of other Java files inside the scan root,
 * built on demand and cached for the whole scan (including negative results), keyed by the
 * normalised absolute path. Safe for concurrent use; a context depends only on the file's content.
 */
public final class JavaContexts {
    private final Path scanRoot;
    private final Language language;
    private final Supplier<Parser> parsers;
    private final ConcurrentHashMap<Path, Optional<JavaContext>> cache = new ConcurrentHashMap<>();

    /**
     * @param scanRoot canonical scan root
     * @param parsers supplies the calling thread's Java parser
     */
    public JavaContexts(Path scanRoot, Language language, Supplier<Parser> parsers) {
        this.scanRoot = scanRoot;
        this.language = language;
        this.parsers = parsers;
    }

    Path scanRoot() {
        return scanRoot;
    }

    /** The context of the Java file at {@code path}, or empty if it is absent or unusable. */
    Optional<JavaContext> get(Path path) {
        Path key = path.toAbsolutePath().normalize();
        if (!key.startsWith(scanRoot)) {
            return Optional.empty();
        }
        Optional<JavaContext> c = cache.get(key);
        if (c != null) {
            return c;
        }
        Optional<JavaContext> built = build(key);
        Optional<JavaContext> prev = cache.putIfAbsent(key, built);
        return prev != null ? prev : built;
    }

    /** Java files under the scan root by file name (t3 J-XMOD), built on first use. */
    private volatile Map<String, List<Path>> byName;

    /**
     * The Java files under the scan root whose path ends with {@code suffix} (a relative path {@code a/b/C.java},
     * matched at a directory boundary), in path order. Directories named {@code .git}, {@code .hg}, {@code .svn}
     * and symbolic links are not entered (SPEC 4.1).
     */
    List<Path> filesEndingWith(String suffix) {
        Map<String, List<Path>> m = byName;
        if (m == null) {
            synchronized (this) {
                m = byName;
                if (m == null) {
                    m = indexByName();
                    byName = m;
                }
            }
        }
        int slash = suffix.lastIndexOf('/');
        List<Path> l = m.get(slash < 0 ? suffix : suffix.substring(slash + 1));
        if (l == null) {
            return List.of();
        }
        List<Path> out = new ArrayList<>(1);
        for (Path p : l) {
            String rel = scanRoot.relativize(p).toString().replace(File.separatorChar, '/');
            if (rel.equals(suffix) || rel.endsWith("/" + suffix)) {
                out.add(p);
            }
        }
        return out;
    }

    private Map<String, List<Path>> indexByName() {
        TreeMap<String, List<Path>> m = new TreeMap<>();
        ArrayDeque<Path> dirs = new ArrayDeque<>();
        dirs.push(scanRoot);
        while (!dirs.isEmpty()) {
            Path d = dirs.pop();
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(d)) {
                for (Path c : ds) {
                    String n = c.getFileName().toString();
                    BasicFileAttributes a;
                    try {
                        a = Files.readAttributes(c, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                    } catch (IOException ex) {
                        continue;
                    }
                    if (a.isDirectory()) {
                        if (!n.equals(".git") && !n.equals(".hg") && !n.equals(".svn")) {
                            dirs.push(c);
                        }
                    } else if (a.isRegularFile() && n.endsWith(".java")) {
                        m.computeIfAbsent(n, k -> new ArrayList<>(1)).add(c.toAbsolutePath().normalize());
                    }
                }
            } catch (IOException | RuntimeException ex) {
                // unreadable directory: skipped
            }
        }
        for (List<Path> l : m.values()) {
            l.sort(null);
        }
        return m;
    }

    int size() {
        return cache.size();
    }

    private Optional<JavaContext> build(Path p) {
        try {
            BasicFileAttributes a = Files.readAttributes(p, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!a.isRegularFile() || a.size() > SourceText.MAX_SIZE) {
                return Optional.empty();
            }
            // no symbolic links on the way (SPEC 4.1: links are never followed)
            if (!p.toRealPath().equals(p)) {
                return Optional.empty();
            }
            byte[] bytes = SourceText.readBounded(p);
            if (SourceText.isBinary(bytes)) {
                return Optional.empty();
            }
            String text = SourceText.decode(bytes);
            SyntaxNode root = SyntaxTrees.parse(parsers.get(), language, text);
            return Optional.of(JavaContext.build(p, root).freeze());
        } catch (IOException | RuntimeException | StackOverflowError ex) {
            return Optional.empty();
        }
    }
}
