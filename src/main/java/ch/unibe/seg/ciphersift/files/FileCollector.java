/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.files;

import ch.unibe.seg.ciphersift.cli.Log;
import ch.unibe.seg.ciphersift.util.Texts;
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
import java.util.Set;

/** Walks the scan root, applies exclusions and classifies files (SPEC 4.1, 4.2, 4.5, 4.7). */
public final class FileCollector {
    private static final Set<String> VCS_DIRS = Set.of(".git", ".hg", ".svn");

    /** A collected, classified file. {@code size} is the size at collection time. */
    public record CollectedFile(String relativePath, Path path, FileClass fileClass, boolean test, long size) {}

    private final Path root;
    private final List<Glob> excludes;
    private final boolean excludeTests;

    public FileCollector(Path root, List<Glob> excludes, boolean excludeTests) {
        this.root = root;
        this.excludes = List.copyOf(excludes);
        this.excludeTests = excludeTests;
    }

    private boolean excluded(String rel, boolean dir) {
        for (Glob g : excludes) {
            if (g.matches(rel, dir)) {
                return true;
            }
        }
        return false;
    }

    /** A directory still to be listed: its path and its relative path ({@code ""} for the root). */
    private record PendingDir(Path path, String rel) {}

    /**
     * Collects the files to analyse, in walk order. Ignored files are not returned.
     *
     * <p>Paths are taken from the directory stream and never rebuilt from their (decoded) names, so
     * that file names that are not valid in the platform encoding (e.g. non-UTF-8 bytes, or any
     * non-ASCII name under a C locale) are still reachable and cannot abort the walk.
     */
    public List<CollectedFile> collect() {
        List<CollectedFile> out = new ArrayList<>();
        ArrayDeque<PendingDir> dirs = new ArrayDeque<>();
        dirs.push(new PendingDir(root, ""));
        while (!dirs.isEmpty()) {
            PendingDir pending = dirs.pop();
            String relDir = pending.rel();
            List<Map.Entry<String, Path>> entries = new ArrayList<>();
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(pending.path())) {
                for (Path p : ds) {
                    entries.add(Map.entry(FileNames.name(p), p)); // UTF-8 whatever the locale (O1)
                }
            } catch (IOException | SecurityException | java.nio.file.DirectoryIteratorException ex) {
                Log.warning("cannot list directory " + (relDir.isEmpty() ? "." : relDir) + ": " + message(ex));
                continue;
            }
            entries.sort(Map.Entry.comparingByKey(Texts.CODE_POINT_ORDER));
            List<PendingDir> subdirs = new ArrayList<>();
            for (Map.Entry<String, Path> entry : entries) {
                String name = entry.getKey();
                Path p = entry.getValue();
                String rel = relDir.isEmpty() ? name : relDir + "/" + name;
                BasicFileAttributes attrs;
                try {
                    attrs = Files.readAttributes(p, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                } catch (IOException | SecurityException ex) {
                    Log.warning("cannot read attributes of " + rel + ": " + message(ex));
                    continue;
                }
                if (attrs.isSymbolicLink()) {
                    Log.debug("skipping symbolic link " + rel);
                    continue;
                }
                if (attrs.isDirectory()) {
                    if (VCS_DIRS.contains(name)) {
                        continue;
                    }
                    if (excluded(rel, true)) {
                        Log.debug("excluded directory " + rel);
                        continue;
                    }
                    subdirs.add(new PendingDir(p, rel));
                    continue;
                }
                if (!attrs.isRegularFile()) {
                    Log.debug("skipping special file " + rel);
                    continue;
                }
                if (excluded(rel, false)) {
                    Log.debug("excluded " + rel);
                    continue;
                }
                FileClass fc = FileClass.of(rel);
                if (fc == FileClass.IGNORED && FileClass.mayBeScript(rel) && pythonScript(p, rel)) {
                    fc = FileClass.PYTHON; // extensionless script with a Python interpreter line (4.5)
                }
                if (fc == FileClass.IGNORED) {
                    continue;
                }
                boolean test = TestFiles.isTest(rel);
                if (test && excludeTests) {
                    Log.debug("excluded test file " + rel);
                    continue;
                }
                out.add(new CollectedFile(rel, p, fc, test, attrs.size()));
            }
            // depth-first, children in name order
            for (int i = subdirs.size() - 1; i >= 0; i--) {
                dirs.push(subdirs.get(i));
            }
        }
        return out;
    }

    /** Reads the start of an extensionless file and checks for a Python interpreter line (SPEC 4.5). */
    private static boolean pythonScript(Path p, String rel) {
        byte[] head = new byte[FileClass.SHEBANG_BYTES];
        int n = 0;
        try (java.io.InputStream in = Files.newInputStream(p)) {
            int r;
            while (n < head.length && (r = in.read(head, n, head.length - n)) > 0) {
                n += r;
            }
        } catch (IOException | SecurityException ex) {
            Log.debug("cannot read " + rel + ": " + message(ex));
            return false;
        }
        return FileClass.isPythonShebang(head, n);
    }

    private static String message(Exception ex) {
        return ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
    }
}
