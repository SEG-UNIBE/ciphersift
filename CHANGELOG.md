<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 The CipherSift Authors -->

# Changelog

## 1.0.0 (unreleased)

First implementation of the CipherSift specification 1.0 (rule format version 1).

* `scan`, `rules validate`, `rules export`, `--version`; exit codes 0–5 as specified.
* Java analysis: imports and class references, constant resolution (locals, fields, cross-file
  constants inside the scan root, constants table, text blocks, arrays), constant-bytes check,
  specificity-based rule selection, nested-duplicate suppression, `override` rules.
* Python analysis: imports, scopes with parameter shadowing, alias and bound-call resolution,
  string lists, symbol sets, `reportAt` attribution, refinement, attribute assignments; depth
  limits 64 / 16 / 12 (DECISIONS M4).
* Dependency manifests: `pom.xml` (properties, same-POM managed versions — DECISIONS M2),
  Gradle scripts and version catalogs, `requirements*.txt`, `requirements/*.txt`,
  `pyproject.toml` (PEP 621, PEP 735, Poetry), `Pipfile.lock`, `poetry.lock`.
* Deterministic CycloneDX 1.6 output with content-derived serial number and stable bom-refs.
* Bundled rules: 88 Java, 79 Python, constants table, Maven and PyPI library lists.
* Native tree-sitter core v0.26.10, tree-sitter-java v0.23.5, tree-sitter-python v0.25.0
  (linux-x86_64), built by `native/build-natives.sh`.
* Conformance suite: 25 cases (two added: `deps/maven-managed-version`,
  `python/deep-call-args`), 562 findings, all passing.

### Follow-up (code-review items, start-up and speed)

* Java version check: `bin/ciphersift` selects `CIPHERSIFT_JAVA`, `JAVA_HOME/bin/java` or `java`
  on `PATH`, falls back only to another explicitly configured runtime, and reports a runtime older
  than 23 in one line with the new exit code 6. The jar's entry point is compiled for Java 8, so
  `java -jar` on Java 8–22 gives the same message instead of `UnsupportedClassVersionError`.
* Start-up about 1.3 s → 0.5 s: the bundled rules are validated in full at build time (the build
  fails on invalid rules) and loaded from a pre-parsed, digest-verified copy without schema
  validation at run time (`--rules` directories are still validated in full); rules, native
  libraries and grammars are prepared on background threads while the command line is parsed.
* Throughput: source files in which no rule's names occur are not parsed (textual Aho–Corasick
  pre-filter; output unchanged); fewer allocations in the tree copy; at most two threads copy
  trees at once (jtreesitter's per-node cleaner registrations contend otherwise). JDK sources
  (5.1 M lines): 67 s → 24 s single-threaded, 41 s → 11 s with 8 threads.
* File names are decoded as UTF-8 under any locale, also with plain `java -jar` (DECISIONS O1);
  a warning names command-line arguments the locale cannot decode.
* Decisions O2–O7: `param` no longer makes a Java pattern specific; comments in byte-array
  initialisers are ignored by the constant-bytes check; alias chains longer than 16 steps are
  unresolved; `pkg @ https://…` in `pyproject.toml` is skipped; `new: X*` gives a clear rule
  error and symbolic links inside `--rules` directories are rule errors; SPEC 15.4 updated.
* Conformance suite: 28 cases (added `java/array-comments`, `python/alias-chain-limit`,
  `deps/pyproject-direct-reference`), 573 findings, all passing.
