/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.rules;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Build step (Maven {@code process-classes}): validates the bundled rule set in the build output in
 * full (JSON schema and SPEC 5.8 checks), writes the pre-parsed documents
 * ({@link RuleLoader#BUNDLE_RESOURCE}), checks that the streaming {@link TreeReader} reads every
 * document and the bundle exactly like the object mapper reads the YAML, and then writes
 * {@link RuleLoader#VALIDATED_RESOURCE}.
 * Any problem fails the build. At run time, {@link RuleLoader#loadBundled} skips the schema
 * validation only when the jar's rules and schema still have the recorded key.
 *
 * <p>Usage: {@code BundledRulesCheck <classes directory>}.
 */
public final class BundledRulesCheck {
    private BundledRulesCheck() {}

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("usage: BundledRulesCheck <classes directory>");
            System.exit(2);
        }
        try {
            String key = check(Path.of(args[0]));
            System.out.println("bundled rules validated: " + key);
        } catch (RuleException ex) {
            for (String p : ex.problems()) {
                System.err.println("bundled rules: " + p);
            }
            System.exit(1);
        } catch (IOException ex) {
            System.err.println("bundled rules: " + ex.getMessage());
            System.exit(1);
        }
    }

    /** Validates {@code classes/rules} against {@code classes/schema/rule-schema.json} and writes the marker. */
    static String check(Path classes) throws RuleException, IOException {
        Path marker = classes.resolve(RuleLoader.VALIDATED_RESOURCE);
        Files.deleteIfExists(marker); // never leave a stale marker behind
        Files.deleteIfExists(classes.resolve(RuleLoader.BUNDLE_RESOURCE));
        List<RuleLoader.RuleFile> files = RuleLoader.directoryFiles(classes.resolve("rules"));
        if (files.isEmpty()) {
            throw new RuleException("no rule documents under " + classes.resolve("rules"));
        }
        byte[] schema = Files.readAllBytes(classes.resolve("schema/rule-schema.json"));
        byte[] loaded = RuleLoader.resourceBytes("schema/rule-schema.json");
        if (loaded == null || !Arrays.equals(loaded, schema)) {
            throw new RuleException("the schema on the class path differs from " + classes.resolve("schema"));
        }
        RuleSet full = RuleLoader.load(files); // full validation; throws on any problem
        List<String> problems = new ArrayList<>();
        for (RuleLoader.RuleFile f : files) {
            JsonNode a = RuleLoader.parse(f);
            JsonNode b;
            try {
                b = TreeReader.read(f.path(), f.bytes());
            } catch (IOException ex) {
                problems.add(f.path() + ": streaming reader failed: " + ex.getMessage());
                continue;
            }
            if (!a.equals(b)) {
                problems.add(f.path() + ": streaming reader gives a different tree");
            }
        }
        byte[] bundle = RuleLoader.bundle(files);
        List<Map.Entry<String, JsonNode>> back = TreeReader.readBundle(bundle);
        for (int i = 0; i < files.size(); i++) {
            RuleLoader.RuleFile f = files.get(i);
            if (i >= back.size() || !back.get(i).getKey().equals(f.path())
                    || !back.get(i).getValue().equals(RuleLoader.parse(f))) {
                problems.add(f.path() + ": the pre-parsed bundle does not reproduce the document");
            }
        }
        RuleSet trusted = RuleLoader.loadTrusted(files, bundle);
        if (trusted == null || !trusted.digest().equals(full.digest())
                || trusted.javaRules().size() != full.javaRules().size()
                || trusted.pythonRules().size() != full.pythonRules().size()
                || trusted.goRules().size() != full.goRules().size()) {
            problems.add("the trusted load differs from the validated load");
        }
        if (!problems.isEmpty()) {
            throw new RuleException(problems);
        }
        String key = RuleLoader.validationKey(files, schema, bundle);
        Files.createDirectories(marker.getParent());
        Files.write(classes.resolve(RuleLoader.BUNDLE_RESOURCE), bundle);
        Files.write(marker, (key + "\n").getBytes(StandardCharsets.UTF_8));
        return key;
    }
}
