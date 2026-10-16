/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.files;

import java.util.Locale;
import java.util.Set;

/** Test-file detection (SPEC 4.7 as amended by DECISIONS M1). */
public final class TestFiles {
    private static final Set<String> TEST_DIRS = Set.of(
            "test", "tests", "testing", "__tests__", "testdata", "test-data", "testfixtures", "test-fixtures",
            "integrationtest", "integration-test", "integration-tests");

    private TestFiles() {}

    /** Is the file at this relative path ({@code /}-separated) a test file? */
    public static boolean isTest(String relativePath) {
        String[] seg = relativePath.split("/", -1);
        // 1. directory rule (case-insensitive), all classes
        for (int i = 0; i < seg.length - 1; i++) {
            String s = seg[i].toLowerCase(Locale.ROOT);
            if (TEST_DIRS.contains(s)) {
                return true;
            }
            if (s.equals("it") && i > 0 && seg[i - 1].toLowerCase(Locale.ROOT).equals("src")) {
                return true;
            }
        }
        String name = seg[seg.length - 1];
        // 2. Java file names (case-sensitive)
        if (name.endsWith(".java")) {
            String stem = name.substring(0, name.length() - ".java".length());
            if (stem.endsWith("Test") || stem.endsWith("Tests") || stem.endsWith("TestCase") || stem.endsWith("IT")) {
                return true;
            }
            if (stem.startsWith("Test") && stem.length() > 4 && Character.isUpperCase(stem.charAt(4))) {
                return true;
            }
            return false;
        }
        // 3. Python file names (case-sensitive)
        if (name.endsWith(".py")) {
            return name.startsWith("test_") || name.endsWith("_test.py") || name.equals("tests.py")
                    || name.equals("conftest.py");
        }
        return false;
    }
}
