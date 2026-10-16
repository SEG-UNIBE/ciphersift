/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.natives;

import io.github.treesitter.jtreesitter.NativeLibraryLookup;
import java.lang.foreign.Arena;
import java.lang.foreign.SymbolLookup;

/**
 * Provides the extracted tree-sitter core library to jtreesitter (SPEC 15.3 step 3). Registered in
 * {@code META-INF/services/io.github.treesitter.jtreesitter.NativeLibraryLookup}. Extraction happens
 * here at the latest, so the order of class initialisation does not matter.
 */
public final class TreeSitterLibraryLookup implements NativeLibraryLookup {
    @Override
    public SymbolLookup get(Arena arena) {
        return SymbolLookup.libraryLookup(NativeLibraries.get().library(NativeLibraries.CORE), arena);
    }
}
