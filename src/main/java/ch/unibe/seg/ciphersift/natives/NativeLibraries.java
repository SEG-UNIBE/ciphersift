/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.natives;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Extracts the bundled native libraries ({@code /native/<platform>/}) to a cache directory and
 * verifies them against {@code SHA256SUMS} (SPEC 15.3, "Loading at run time").
 */
public final class NativeLibraries {
    public static final String CORE = "tree-sitter";
    public static final String JAVA = "tree-sitter-java";
    public static final String PYTHON = "tree-sitter-python";

    private static volatile NativeLibraries instance;

    private final String platform;
    private final Path directory;
    private final Map<String, Path> files;

    private NativeLibraries(String platform, Path directory, Map<String, Path> files) {
        this.platform = platform;
        this.directory = directory;
        this.files = files;
    }

    /** Extracts (once per JVM) and returns the libraries; throws {@link NativeLoadException} on failure. */
    public static NativeLibraries get() {
        NativeLibraries i = instance;
        if (i == null) {
            synchronized (NativeLibraries.class) {
                i = instance;
                if (i == null) {
                    i = extract();
                    instance = i;
                }
            }
        }
        return i;
    }

    public String platform() {
        return platform;
    }

    public Path directory() {
        return directory;
    }

    /** Path of the extracted library with the given base name ({@link #CORE}, {@link #JAVA}, {@link #PYTHON}). */
    public Path library(String base) {
        Path p = files.get(Platform.libraryFile(platform, base));
        if (p == null) {
            throw new NativeLoadException("native library " + base + " missing for platform " + platform);
        }
        return p;
    }

    private static NativeLibraries extract() {
        String platform = Platform.current();
        String prefix = "native/" + platform + "/";
        byte[] sums = resource(prefix + "SHA256SUMS");
        if (sums == null) {
            List<String> supported = new ArrayList<>();
            for (String p : Platform.KNOWN) {
                if (resource("native/" + p + "/SHA256SUMS") != null) {
                    supported.add(p);
                }
            }
            throw new NativeLoadException("no native libraries for platform " + platform
                    + "; supported platforms: " + (supported.isEmpty() ? "(none)" : String.join(", ", supported)));
        }
        Map<String, String> expected = parseSums(new String(sums, StandardCharsets.UTF_8));
        String dirName = hex(sha256(sums));
        Path dir = cacheDirectory(dirName);
        boolean temporary = false;
        if (dir == null) {
            dir = temporaryDirectory();
            temporary = true;
        }
        Map<String, Path> out = new LinkedHashMap<>();
        try {
            for (Map.Entry<String, String> e : expected.entrySet()) {
                out.put(e.getKey(), install(prefix, dir, e.getKey(), e.getValue(), temporary));
            }
        } catch (IOException ex) {
            if (temporary) {
                throw new NativeLoadException("cannot extract native libraries: " + ex.getMessage(), ex);
            }
            // cache directory turned out not to be writable: fall back to a fresh temporary directory
            dir = temporaryDirectory();
            out.clear();
            try {
                for (Map.Entry<String, String> e : expected.entrySet()) {
                    out.put(e.getKey(), install(prefix, dir, e.getKey(), e.getValue(), true));
                }
            } catch (IOException ex2) {
                throw new NativeLoadException("cannot extract native libraries: " + ex2.getMessage(), ex2);
            }
        }
        return new NativeLibraries(platform, dir, Map.copyOf(out));
    }

    private static Path install(String prefix, Path dir, String name, String sum, boolean deleteOnExit)
            throws IOException {
        Path target = dir.resolve(name);
        if (Files.isRegularFile(target) && sum.equals(hex(sha256(Files.readAllBytes(target))))) {
            return target;
        }
        byte[] data = resource(prefix + name);
        if (data == null) {
            throw new NativeLoadException("bundled native library " + prefix + name + " is missing");
        }
        if (!sum.equals(hex(sha256(data)))) {
            throw new NativeLoadException("bundled native library " + prefix + name + " does not match SHA256SUMS");
        }
        Path tmp = Files.createTempFile(dir, "." + name + ".", ".tmp");
        try {
            Files.write(tmp, data);
            try {
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException ex) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
        if (deleteOnExit) {
            target.toFile().deleteOnExit();
        }
        // verify before use (another process may have replaced it concurrently with the same content)
        if (!sum.equals(hex(sha256(Files.readAllBytes(target))))) {
            throw new NativeLoadException("extracted native library " + target + " does not match SHA256SUMS");
        }
        return target;
    }

    /**
     * Are the libraries already present in the cache directory (so that {@link #get} will not have to
     * write anything)? A cheap existence check; {@link #get} verifies everything as usual.
     */
    public static boolean cachedAlready() {
        try {
            String platform = Platform.current();
            byte[] sums = resource("native/" + platform + "/SHA256SUMS");
            if (sums == null) {
                return false;
            }
            Path base = cacheBase();
            if (base == null) {
                return false;
            }
            Path dir = base.resolve("ciphersift").resolve("native").resolve(hex(sha256(sums)));
            for (String name : parseSums(new String(sums, StandardCharsets.UTF_8)).keySet()) {
                if (!Files.isRegularFile(dir.resolve(name), java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                    return false;
                }
            }
            return true;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    /** {@code $XDG_CACHE_HOME}, else {@code ~/.cache}, or null. */
    private static Path cacheBase() {
        String xdg = System.getenv("XDG_CACHE_HOME");
        if (xdg != null && !xdg.isBlank()) {
            return Path.of(xdg);
        }
        String home = System.getProperty("user.home");
        if (home == null || home.isBlank()) {
            return null;
        }
        return Path.of(home, ".cache");
    }

    private static Path cacheDirectory(String digest) {
        String xdg = System.getenv("XDG_CACHE_HOME");
        Path base;
        if (xdg != null && !xdg.isBlank()) {
            base = Path.of(xdg);
        } else {
            String home = System.getProperty("user.home");
            if (home == null || home.isBlank()) {
                return null;
            }
            base = Path.of(home, ".cache");
        }
        Path dir = base.resolve("ciphersift").resolve("native").resolve(digest);
        try {
            if (dir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                Files.createDirectories(dir, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                        java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")));
            } else {
                Files.createDirectories(dir);
            }
            // A library is verified and then loaded by path: nobody else may be able to swap it in between.
            if (!privateDirectory(dir) || !privateDirectory(dir.getParent())
                    || !privateDirectory(dir.getParent().getParent())) {
                return null;
            }
            return dir;
        } catch (IOException | SecurityException | UnsupportedOperationException ex) {
            return null;
        }
    }

    /**
     * Is {@code dir} a real directory (not a link) that only this user (or root) can modify? On file
     * systems without POSIX attributes the check is skipped.
     */
    static boolean privateDirectory(Path dir) throws IOException {
        java.nio.file.attribute.BasicFileAttributes a = Files.readAttributes(dir,
                java.nio.file.attribute.BasicFileAttributes.class, java.nio.file.LinkOption.NOFOLLOW_LINKS);
        if (!a.isDirectory()) {
            return false;
        }
        if (!dir.getFileSystem().supportedFileAttributeViews().contains("unix")) {
            return true;
        }
        int owner = (Integer) Files.getAttribute(dir, "unix:uid", java.nio.file.LinkOption.NOFOLLOW_LINKS);
        Integer self = currentUid();
        if (self != null && owner != self && owner != 0) {
            return false;
        }
        int mode = (Integer) Files.getAttribute(dir, "unix:mode", java.nio.file.LinkOption.NOFOLLOW_LINKS);
        if ((mode & 0022) != 0 && self != null && owner == self) {
            // our own cache directory, created group-writable under a umask of 002: tighten it
            var perms = Files.getPosixFilePermissions(dir, java.nio.file.LinkOption.NOFOLLOW_LINKS);
            perms.remove(java.nio.file.attribute.PosixFilePermission.GROUP_WRITE);
            perms.remove(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE);
            Files.setPosixFilePermissions(dir, perms);
            mode = (Integer) Files.getAttribute(dir, "unix:mode", java.nio.file.LinkOption.NOFOLLOW_LINKS);
        }
        return (mode & 0022) == 0; // not group- or world-writable
    }

    /** The uid of this process (owner of {@code /proc/self} on Linux), or null if unknown. */
    private static Integer currentUid() {
        try {
            return (Integer) Files.getAttribute(Path.of("/proc/self"), "unix:uid");
        } catch (IOException | RuntimeException ex) {
            return null;
        }
    }

    private static Path temporaryDirectory() {
        IOException first;
        try {
            Path dir = Files.createTempDirectory("ciphersift-native-");
            dir.toFile().deleteOnExit();
            return dir;
        } catch (IOException ex) {
            first = ex;
        }
        // java.io.tmpdir may be unusable (e.g. a read-only /tmp); try $TMPDIR as well
        String env = System.getenv("TMPDIR");
        if (env != null && !env.isBlank()) {
            try {
                Path dir = Files.createTempDirectory(Path.of(env), "ciphersift-native-");
                dir.toFile().deleteOnExit();
                return dir;
            } catch (IOException | RuntimeException ex) {
                // fall through
            }
        }
        throw new NativeLoadException("cannot create a directory for the native libraries: " + first.getMessage(),
                first);
    }

    static Map<String, String> parseSums(String text) {
        Map<String, String> m = new LinkedHashMap<>();
        for (String line : text.split("\n")) {
            String l = line.strip();
            if (l.isEmpty()) {
                continue;
            }
            int sp = l.indexOf(' ');
            if (sp < 0) {
                throw new NativeLoadException("malformed SHA256SUMS line: " + l);
            }
            String sum = l.substring(0, sp).toLowerCase(java.util.Locale.ROOT);
            String name = l.substring(sp).strip();
            if (name.startsWith("*")) {
                name = name.substring(1);
            }
            m.put(name, sum);
        }
        return m;
    }

    private static byte[] resource(String name) {
        try (InputStream in = NativeLibraries.class.getClassLoader().getResourceAsStream(name)) {
            return in == null ? null : in.readAllBytes();
        } catch (IOException ex) {
            return null;
        }
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }
}
