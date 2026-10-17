/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.files;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Pattern;

/** File classes (SPEC 4.5, 17.1) with the manifest label of SPEC 9, 11.4 and 17.10. */
public enum FileClass {
    JAVA(null, null),
    PYTHON(null, null),
    GO(null, null),
    POM("maven", "pom"),
    GRADLE("maven", "gradle"),
    GRADLE_CATALOG("maven", "gradle-catalog"),
    REQUIREMENTS("pypi", "requirements"),
    PYPROJECT("pypi", "pyproject"),
    PIPFILE_LOCK("pypi", "pipfile-lock"),
    POETRY_LOCK("pypi", "poetry-lock"),
    SETUP_CFG("pypi", "setup-cfg"),
    GO_MOD("golang", "go-mod"),
    GO_SUM("golang", "go-sum"),
    IGNORED(null, null);

    private final String ecosystem;
    private final String label;

    FileClass(String ecosystem, String label) {
        this.ecosystem = ecosystem;
        this.label = label;
    }

    public boolean isSource() {
        return this == JAVA || this == PYTHON || this == GO;
    }

    public boolean isManifest() {
        return ecosystem != null;
    }

    /** {@code maven}, {@code pypi} or {@code golang} for manifests. */
    public String ecosystem() {
        return ecosystem;
    }

    /** Manifest label (SPEC 9 table). */
    public String label() {
        return label;
    }

    /** Bytes of an extensionless file read for the interpreter line (SPEC 4.5, DECISIONS F7). */
    public static final int SHEBANG_BYTES = 256;

    /**
     * A Python interpreter line: {@code #!}, optional blanks, an absolute interpreter path, either the
     * interpreter itself or {@code env} (options starting with {@code -} skipped) followed by it, where
     * the interpreter's base name is {@code python}, optionally followed by a version of digits and dots.
     */
    private static final Pattern PYTHON_SHEBANG = Pattern.compile(
            "#![ \\t]*/\\S*/(?:python[0-9.]*|env(?:[ \\t]+-\\S*)*[ \\t]+(?:\\S*/)?python[0-9.]*)(?:[ \\t].*)?");

    /** True for a base name without {@code .}, whose content may make it a Python script (SPEC 4.5). */
    public static boolean mayBeScript(String relativePath) {
        int slash = relativePath.lastIndexOf('/');
        String name = slash < 0 ? relativePath : relativePath.substring(slash + 1);
        return !name.isEmpty() && name.indexOf('.') < 0;
    }

    /** True if the first line of {@code head} is a Python interpreter line (SPEC 4.5, DECISIONS F7). */
    public static boolean isPythonShebang(byte[] head, int length) {
        if (length < 2 || head[0] != '#' || head[1] != '!') {
            return false;
        }
        int end = 0;
        while (end < length && head[end] != '\n') {
            end++;
        }
        if (end == length && length >= SHEBANG_BYTES) {
            return false; // no line end within the limit
        }
        String line = new String(head, 0, end, StandardCharsets.ISO_8859_1);
        if (line.endsWith("\r")) {
            line = line.substring(0, line.length() - 1);
        }
        return PYTHON_SHEBANG.matcher(line).matches();
    }

    /** Classifies a relative path ({@code /}-separated); the first matching row wins (SPEC 4.5). */
    public static FileClass of(String relativePath) {
        int slash = relativePath.lastIndexOf('/');
        String name = slash < 0 ? relativePath : relativePath.substring(slash + 1);
        String parent = "";
        if (slash > 0) {
            int s2 = relativePath.lastIndexOf('/', slash - 1);
            parent = relativePath.substring(s2 + 1, slash);
        }
        String n = name.toLowerCase(Locale.ROOT);
        if (n.endsWith(".java")) {
            return JAVA;
        }
        if (n.endsWith(".py")) {
            return PYTHON;
        }
        if (n.endsWith(".go")) {
            return GO;
        }
        if (n.equals("pom.xml")) {
            return POM;
        }
        if (n.equals("build.gradle") || n.equals("build.gradle.kts")) {
            return GRADLE;
        }
        if (n.endsWith(".versions.toml")) {
            return GRADLE_CATALOG;
        }
        if ((n.startsWith("requirements") && n.endsWith(".txt"))
                || (n.endsWith(".txt") && parent.toLowerCase(Locale.ROOT).equals("requirements"))) {
            return REQUIREMENTS;
        }
        if (n.equals("pyproject.toml")) {
            return PYPROJECT;
        }
        if (n.equals("pipfile.lock")) {
            return PIPFILE_LOCK;
        }
        if (n.equals("poetry.lock")) {
            return POETRY_LOCK;
        }
        if (n.equals("setup.cfg")) {
            return SETUP_CFG;
        }
        if (n.equals("go.mod")) {
            return GO_MOD;
        }
        if (n.equals("go.sum")) {
            return GO_SUM;
        }
        return IGNORED;
    }
}
