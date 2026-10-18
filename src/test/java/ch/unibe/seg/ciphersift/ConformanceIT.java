/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Stream;
import ch.unibe.seg.ciphersift.cbom.CycloneDxVersion;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.io.TempDir;

/**
 * Runs the whole conformance suite through the built jar (SPEC 16), compares the normalised
 * findings with {@code expected.json}, and validates every produced CBOM against the CycloneDX 1.7
 * schema (SPEC 11.1). Each case runs a second time with {@code --cyclonedx-version 1.6}: same
 * findings, valid CycloneDX 1.6.
 */
class ConformanceIT {
    @TempDir
    static Path tmp;

    private static final Map<String, JarRunner.Run> RUNS = new LinkedHashMap<>();
    private static final Map<String, byte[]> CBOMS = new LinkedHashMap<>();
    private static final Map<String, JarRunner.Run> RUNS_16 = new LinkedHashMap<>();
    private static final Map<String, byte[]> CBOMS_16 = new LinkedHashMap<>();

    @BeforeAll
    static void runAll() throws Exception {
        runAll("", List.of(), RUNS, CBOMS);
        runAll("-1.6", List.of("--cyclonedx-version", "1.6"), RUNS_16, CBOMS_16);
    }

    private static void runAll(String suffix, List<String> extra, Map<String, JarRunner.Run> runs,
            Map<String, byte[]> cboms) throws Exception {
        List<String> cases = TestSupport.cases();
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            Map<String, Future<JarRunner.Run>> futures = new LinkedHashMap<>();
            for (String c : cases) {
                Path out = tmp.resolve(c.replace('/', '_') + suffix + ".cdx.json");
                List<String> args = new ArrayList<>(List.of("scan",
                        TestSupport.casesDir().resolve(c).resolve("input").toString(), "-o", out.toString()));
                args.addAll(TestSupport.caseArgs(c));
                args.addAll(extra);
                futures.put(c, pool.submit(() -> JarRunner.run(args.toArray(new String[0]))));
            }
            for (Map.Entry<String, Future<JarRunner.Run>> e : futures.entrySet()) {
                JarRunner.Run r = e.getValue().get();
                runs.put(e.getKey(), r);
                Path out = tmp.resolve(e.getKey().replace('/', '_') + suffix + ".cdx.json");
                if (Files.exists(out)) {
                    cboms.put(e.getKey(), Files.readAllBytes(out));
                }
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @TestFactory
    Stream<DynamicTest> conformance() throws Exception {
        return TestSupport.cases().stream().map(c -> DynamicTest.dynamicTest(c, () -> {
            JarRunner.Run r = RUNS.get(c);
            assertEquals(0, r.exit(), () -> "exit code of " + c + "\n" + r.stderr());
            byte[] cbom = CBOMS.get(c);
            if (cbom == null) {
                fail("no CBOM written for " + c);
            }
            List<String> diff = TestSupport.compare(TestSupport.normalise(cbom), TestSupport.expected(c));
            assertTrue(diff.isEmpty(), () -> c + ":\n  " + String.join("\n  ", diff));
        }));
    }

    @TestFactory
    Stream<DynamicTest> cycloneDxSchema() throws Exception {
        return TestSupport.cases().stream().map(c -> DynamicTest.dynamicTest(c, () -> {
            byte[] cbom = CBOMS.get(c);
            if (cbom == null) {
                fail("no CBOM written for " + c);
            }
            List<String> errors = CycloneDxSchemas.validate(cbom, CycloneDxVersion.V1_7);
            assertTrue(errors.isEmpty(), () -> c + ": " + errors);
        }));
    }

    /** {@code --cyclonedx-version 1.6}: the same findings (the comparison is version-independent), valid 1.6. */
    @TestFactory
    Stream<DynamicTest> cycloneDx16() throws Exception {
        return TestSupport.cases().stream().map(c -> DynamicTest.dynamicTest(c, () -> {
            JarRunner.Run r = RUNS_16.get(c);
            assertEquals(0, r.exit(), () -> "exit code of " + c + " (1.6)\n" + r.stderr());
            byte[] cbom = CBOMS_16.get(c);
            if (cbom == null) {
                fail("no 1.6 CBOM written for " + c);
            }
            List<String> errors = CycloneDxSchemas.validate(cbom, CycloneDxVersion.V1_6);
            assertTrue(errors.isEmpty(), () -> c + ": " + errors);
            List<String> diff = TestSupport.compare(TestSupport.normalise(cbom), TestSupport.expected(c));
            assertTrue(diff.isEmpty(), () -> c + " (1.6):\n  " + String.join("\n  ", diff));
            String s = new String(cbom, java.nio.charset.StandardCharsets.UTF_8);
            assertTrue(!s.contains("\"algorithmFamily\"") && !s.contains("\"ellipticCurve\""),
                    c + ": 1.7 fields in a 1.6 document");
        }));
    }

    @Test
    void allCasesHaveFindingsAndNoEmptyComponents() throws Exception {
        int total = 0;
        for (String c : TestSupport.cases()) {
            total += TestSupport.expected(c).size();
            byte[] cbom = CBOMS.get(c);
            if (cbom == null) {
                fail("no CBOM for " + c);
            }
            for (var comp : TestSupport.JSON.readTree(cbom).path("components")) {
                assertTrue(comp.path("evidence").path("occurrences").size() > 0, c + ": component without occurrences");
            }
        }
        assertEquals(1648, total, "expected findings in the suite");
    }
}
