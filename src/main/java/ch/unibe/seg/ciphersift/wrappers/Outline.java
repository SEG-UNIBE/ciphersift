/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.wrappers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The definitions and call sites of one source file (SPEC 18.2, 18.3), with what the resolution of its
 * language needs (18.4). Built from the syntax tree, which is not kept.
 */
public final class Outline {
    /** The language of an outline. */
    public enum Lang { JAVA, PYTHON, GO }

    /** A Go type reference: an optional package local name and a type name. */
    public record TypeRef(String pkg, String name) {}

    /**
     * A definition (SPEC 18.2).
     *
     * @param index index in {@link #defs}
     * @param name the function or method name
     * @param line the row of the name + 1
     * @param endLine the last row + 1
     * @param start start offset of the declaration node (nesting tie-break)
     * @param nesting number of enclosing definitions and classes
     * @param display display name for {@code via} (SPEC 18.7)
     * @param addressable whether calls from elsewhere can reach it (SPEC 18.2)
     * @param owner the owner key (class declaration, module/class, package/receiver type)
     * @param ownerClass Java: index into {@link #javaClasses}; Python: the class name or null; Go: -1
     * @param arity Java: number of formal parameters
     * @param varargs Java: the last parameter is a variable-arity one
     * @param recv Go: the receiver type name, or null for a function
     * @param locals Python/Go: parameters and assigned names (calls through them are not resolved)
     * @param types Go: declared types of names (null value: conflicting)
     */
    public record Def(int index, String name, int line, int endLine, int start, int nesting, String display,
            boolean addressable, String owner, int ownerClass, String pyClass, int arity, boolean varargs, String recv,
            Set<String> locals, Map<String, TypeRef> types) {}

    /**
     * A call site (SPEC 18.3).
     *
     * @param name the called name (last segment)
     * @param qualifier the qualifier segments (empty for an unqualified call); Java: the object text
     *        as one element, {@code this} for {@code this.m()}
     * @param line its line
     * @param start start offset of the call node
     * @param end end offset of the call node
     * @param arity Java: number of arguments
     * @param symbol the occurrence symbol
     * @param caller index of the innermost definition containing the line, or -1
     * @param javaClass Java: index of the innermost enclosing class, or -1
     * @param pyClass Python: name of the innermost enclosing module-level class, or null
     */
    public record Call(String name, List<String> qualifier, int line, int start, int end, int arity, String symbol,
            int caller, int javaClass, String pyClass) {}

    /** A Java class-like declaration. */
    public record JavaClass(String simpleName, String fqn, int parent, boolean addressable) {}

    /** A Python import binding: {@code import a.b as x} → module {@code a.b}; {@code from a import b} → (a, b). */
    public record PyBinding(String module, String member) {}

    public final Lang lang;
    public final String path;
    public final boolean test;
    public final List<Def> defs = new ArrayList<>();
    public final List<Call> calls = new ArrayList<>();

    // Java
    public String javaPackage = "";
    /** Single-type imports: simple name → fully qualified name. */
    public final Map<String, String> javaImports = new HashMap<>();
    /** On-demand imports {@code p.*}: the qualifier {@code p}. */
    public final List<String> javaOnDemand = new ArrayList<>();
    /** Single-static imports: member → class FQN. */
    public final Map<String, String> javaStaticImports = new HashMap<>();
    /** Static on-demand imports: class FQNs. */
    public final List<String> javaStaticOnDemand = new ArrayList<>();
    public final List<JavaClass> javaClasses = new ArrayList<>();

    // Python
    public String pyModule = "";
    /** The package against which relative imports resolve. */
    public String pyPackage = "";
    public final Map<String, List<PyBinding>> pyImports = new HashMap<>();
    /** Names of the module-level classes. */
    public final List<String> pyClasses = new ArrayList<>();
    /**
     * Python: indices into {@link #defs} of the module-level class definitions (SPEC 18.2, DECISIONS P3-CLS); they are
     * definitions only for the class-wrapper test and are ignored without the feature {@code python-class-wrappers}.
     */
    public final Set<Integer> pyClassDefs = new java.util.TreeSet<>();
    /** Python: class definition index → its base-class references, as call-like records (never call sites). */
    public final Map<Integer, List<Call>> pyBases = new HashMap<>();
    /**
     * Python: definition index → local name → the call it is bound to, for names bound exactly once in the definition
     * by {@code x = f(…)} with {@code f} a name or attribute chain (instances of class wrappers, DECISIONS P3-CLS).
     */
    public final Map<Integer, Map<String, Call>> pyInstances = new HashMap<>();

    // Go
    public String goDir = "";
    public String goPackage = "";
    public final Map<String, String> goImports = new HashMap<>();
    /** Struct type → field → field type (this file only). */
    public final Map<String, Map<String, TypeRef>> goStructs = new HashMap<>();
    /**
     * Go: definition index → the line ranges ({@code {first, last}}) of its conditional returns (SPEC 18.5,
     * fallback-getter guard, DECISIONS B-G-E); only definitions with at least two return statements have any.
     */
    public final Map<Integer, List<int[]>> goGuards = new HashMap<>();

    public Outline(Lang lang, String path, boolean test) {
        this.lang = lang;
        this.path = path;
        this.test = test;
    }
}
