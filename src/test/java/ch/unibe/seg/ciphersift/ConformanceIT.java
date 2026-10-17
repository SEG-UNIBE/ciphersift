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
import org.cyclonedx.Version;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.io.TempDir;

/**
 * Runs the whole conformance suite through the built jar (SPEC 16), compares the normalised
 * findings with {@code expected.json}, and validates every produced CBOM against the CycloneDX 1.6
 * schema with cyclonedx-core-java (SPEC 11.1).
 */
class ConformanceIT {
    @TempDir
    static Path tmp;

    private static final Map<String, JarRunner.Run> RUNS = new LinkedHashMap<>();
    private static final Map<String, byte[]> CBOMS = new LinkedHashMap<>();

    @BeforeAll
    static void runAll() throws Exception {
        List<String> cases = TestSupport.cases();
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            Map<String, Future<JarRunner.Run>> futures = new LinkedHashMap<>();
            for (String c : cases) {
                Path out = tmp.resolve(c.replace('/', '_') + ".cdx.json");
                List<String> args = new ArrayList<>(List.of("scan",
                        TestSupport.casesDir().resolve(c).resolve("input").toString(), "-o", out.toString()));
                args.addAll(TestSupport.caseArgs(c));
                futures.put(c, pool.submit(() -> JarRunner.run(args.toArray(new String[0]))));
            }
            for (Map.Entry<String, Future<JarRunner.Run>> e : futures.entrySet()) {
                JarRunner.Run r = e.getValue().get();
                RUNS.put(e.getKey(), r);
                Path out = tmp.resolve(e.getKey().replace('/', '_') + ".cdx.json");
                if (Files.exists(out)) {
                    CBOMS.put(e.getKey(), Files.readAllBytes(out));
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
        JsonParser parser = new JsonParser();
        return TestSupport.cases().stream().map(c -> DynamicTest.dynamicTest(c, () -> {
            byte[] cbom = CBOMS.get(c);
            if (cbom == null) {
                fail("no CBOM written for " + c);
            }
            List<ParseException> errors = parser.validate(cbom, Version.VERSION_16);
            assertTrue(errors.isEmpty(), () -> c + ": " + errors);
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
        assertEquals(1021, total, "expected findings in the suite");
    }
}
