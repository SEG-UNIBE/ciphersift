/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.natives;

import io.github.treesitter.jtreesitter.Language;
import java.lang.foreign.Arena;
import java.lang.foreign.SymbolLookup;
import java.util.ArrayList;
import java.util.List;

/** The grammars (SPEC 6.1, 15.3 step 4, 17.2) and the field-name check of Appendix C. */
public final class Grammars {
    /** Field names of Appendix C, Java grammar. */
    static final List<String> JAVA_FIELDS = List.of(
            "name", "superclass", "interfaces", "value", "parameters", "body", "object", "arguments",
            "type", "field", "left", "operator", "right");
    /** Field names of Appendix C, Python grammar. */
    static final List<String> PYTHON_FIELDS = List.of(
            "name", "alias", "module_name", "parameters", "left", "right", "function", "arguments",
            "object", "attribute", "value", "key");
    /** Field names of Appendix C, Go grammar (SPEC 17). */
    static final List<String> GO_FIELDS = List.of(
            "name", "path", "function", "arguments", "operand", "field", "type", "body", "key", "value",
            "left", "right", "operator", "parameters", "receiver", "result", "package");

    private static volatile Grammars instance;

    private final Language java;
    private final Language python;
    private final Language go;

    private Grammars(Language java, Language python, Language go) {
        this.java = java;
        this.python = python;
        this.go = go;
    }

    public static Grammars get() {
        Grammars g = instance;
        if (g == null) {
            synchronized (Grammars.class) {
                g = instance;
                if (g == null) {
                    g = load();
                    instance = g;
                }
            }
        }
        return g;
    }

    public Language java() {
        return java;
    }

    public Language python() {
        return python;
    }

    public Language go() {
        return go;
    }

    private static Grammars load() {
        NativeLibraries libs = NativeLibraries.get();
        try {
            Language j = Language.load(
                    SymbolLookup.libraryLookup(libs.library(NativeLibraries.JAVA), Arena.global()), "tree_sitter_java");
            Language p = Language.load(
                    SymbolLookup.libraryLookup(libs.library(NativeLibraries.PYTHON), Arena.global()),
                    "tree_sitter_python");
            Language go = Language.load(
                    SymbolLookup.libraryLookup(libs.library(NativeLibraries.GO), Arena.global()), "tree_sitter_go");
            List<String> missing = new ArrayList<>();
            for (String f : JAVA_FIELDS) {
                if (j.getFieldIdForName(f) == 0) {
                    missing.add("java:" + f);
                }
            }
            for (String f : PYTHON_FIELDS) {
                if (p.getFieldIdForName(f) == 0) {
                    missing.add("python:" + f);
                }
            }
            for (String f : GO_FIELDS) {
                if (go.getFieldIdForName(f) == 0) {
                    missing.add("go:" + f);
                }
            }
            if (!missing.isEmpty()) {
                throw new NativeLoadException("grammar lacks required field names: " + missing);
            }
            return new Grammars(j, p, go);
        } catch (NativeLoadException ex) {
            throw ex;
        } catch (RuntimeException | LinkageError ex) {
            throw new NativeLoadException("cannot load the tree-sitter grammars: " + ex, ex);
        }
    }
}
