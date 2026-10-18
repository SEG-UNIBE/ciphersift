/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.wrappers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.unibe.seg.ciphersift.cbom.Component;
import ch.unibe.seg.ciphersift.rules.RuleLoader;
import ch.unibe.seg.ciphersift.rules.RuleSet;
import ch.unibe.seg.ciphersift.scan.Scanner;
import ch.unibe.seg.ciphersift.scan.ScannerAccess;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Wrapper propagation end to end through {@link Scanner} (SPEC 18). */
class WrapperPropagationTest {
    static RuleSet rules;

    @TempDir
    Path tmp;

    @BeforeAll
    static void load() throws Exception {
        rules = RuleLoader.loadBundled();
    }

    private int n;

    /** Propagated occurrences as {@code path:line ruleId <- via[0] … | origin}, sorted. */
    private List<String> scan(WrapperOptions opts, int threads, String... pathAndText) throws Exception {
        Path root = Files.createDirectories(tmp.resolve("r" + n++)).toRealPath();
        for (int i = 0; i < pathAndText.length; i += 2) {
            Path p = root.resolve(pathAndText[i]);
            Files.createDirectories(p.getParent());
            Files.writeString(p, pathAndText[i + 1], StandardCharsets.UTF_8);
        }
        Scanner.Result r = new Scanner(new Scanner.Options(root, List.of(), false, threads, rules, false, opts)).run();
        List<String> out = new ArrayList<>();
        for (Component c : r.components()) {
            for (Component.Occurrence o : c.occurrences()) {
                if (o.via() != null) {
                    out.add(o.location() + ":" + o.line() + " " + o.ruleId() + " <- " + String.join(" , ", o.via())
                            + " | " + o.origin() + (o.test() ? " test" : ""));
                }
            }
        }
        out.sort(null);
        return out;
    }

    private List<String> scan(String... pathAndText) throws Exception {
        return scan(WrapperOptions.defaults(false), 1, pathAndText);
    }

    private static final String HASH_JAVA = """
            package p;
            import java.security.MessageDigest;
            public class Hash {
                public static byte[] sha256(byte[] d) throws Exception {
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    md.update(d);
                    md.update(d);
                    md.update(d);
                    md.update(d);
                    md.update(d);
                    return md.digest();
                }
            }
            """;

    @Test
    void javaInheritedAndArity() throws Exception {
        List<String> got = scan("p/Hash.java", HASH_JAVA, "p/Sub.java", """
                package p;
                class Sub extends Hash {
                    void a(byte[] d) throws Exception {
                        sha256(d); // inherited: not resolved
                        Hash.sha256(d, d); // no such arity
                        Hash.sha256(d);
                    }
                }
                """);
        assertEquals(List.of("p/Sub.java:6 java.hash.sha2 <- p/Hash.java:4 Hash.sha256 | p/Hash.java:5"), got);
    }

    @Test
    void javaVarargsNestedAndAnonymous() throws Exception {
        List<String> got = scan("q/Outer.java", """
                package q;
                import java.security.MessageDigest;
                public class Outer {
                    public static class Inner {
                        public static byte[] md5(byte[]... parts) throws Exception {
                            return MessageDigest.getInstance("MD5").digest(parts[0]);
                        }
                    }
                    Runnable r = new Runnable() {
                        public void run() {
                            try { Inner.md5(); } catch (Exception e) { }
                        }
                    };
                }
                """, "q/Use.java", """
                package q;
                class Use {
                    void u() throws Exception {
                        Outer.Inner.md5(new byte[0], new byte[1]);
                        q.Outer.Inner.md5(new byte[0]);
                    }
                }
                """);
        assertEquals(List.of(
                "q/Outer.java:11 java.hash.md5 <- q/Outer.java:5 Outer.Inner.md5 | q/Outer.java:6",
                "q/Use.java:4 java.hash.md5 <- q/Outer.java:5 Outer.Inner.md5 | q/Outer.java:6",
                "q/Use.java:5 java.hash.md5 <- q/Outer.java:5 Outer.Inner.md5 | q/Outer.java:6"), got);
    }

    @Test
    void javaDuplicateFqnIsACollision() throws Exception {
        List<String> got = scan("a/p/Hash.java", HASH_JAVA, "b/p/Hash.java", HASH_JAVA, "c/U.java", """
                import p.Hash;
                class U { void u(byte[] d) throws Exception { Hash.sha256(d); } }
                """);
        assertEquals(List.of(), got);
    }

    @Test
    void depthLimitAndCycles() throws Exception {
        List<String> got = scan("go.mod", "module m\n", "h.go", """
                package h

                import "crypto/sha1"

                func sha1A(b []byte) [20]byte { return sha1.Sum(b) }
                func sha1B(b []byte) [20]byte { return sha1A(b) }
                func sha1C(b []byte) [20]byte { return sha1B(b) }
                func sha1D(b []byte) [20]byte { return sha1C(b) }
                func sha1E(b []byte) [20]byte { return sha1D(b) }
                func sha1X(b []byte) [20]byte { return sha1Y(b) }
                func sha1Y(b []byte) [20]byte { return sha1X(b) }
                """);
        assertEquals(List.of(
                "h.go:6 go.hash.sha1 <- h.go:5 h.sha1A | h.go:5",
                "h.go:7 go.hash.sha1 <- h.go:6 h.sha1B , h.go:5 h.sha1A | h.go:5",
                "h.go:8 go.hash.sha1 <- h.go:7 h.sha1C , h.go:6 h.sha1B , h.go:5 h.sha1A | h.go:5",
                // DECISIONS B-C: chains of up to 4 definitions
                "h.go:9 go.hash.sha1 <- h.go:8 h.sha1D , h.go:7 h.sha1C , h.go:6 h.sha1B , h.go:5 h.sha1A | h.go:5"), got);
    }

    @Test
    void thinWrappersAreTransitiveAndOptional() throws Exception {
        String[] files = {"a.py", """
                import hashlib, os


                def h(x):
                    return hashlib.sha1(x)


                def g(x):
                    return h(x)


                def r():
                    return os.urandom(8)


                h(1)
                g(1)
                r()
                """};
        assertEquals(List.of(), scan(files));
        assertEquals(List.of("a.py:16 python.hash.sha1 <- a.py:4 a.h | a.py:5",
                "a.py:17 python.hash.sha1 <- a.py:8 a.g , a.py:4 a.h | a.py:5",
                "a.py:9 python.hash.sha1 <- a.py:4 a.h | a.py:5"), scan(WrapperOptions.defaults(true), 1, files));
        assertEquals(List.of(), scan(WrapperOptions.OFF, 1, files));
    }

    @Test
    void weaknessIndicatorsAreNotPropagated() throws Exception {
        assertEquals(List.of(), scan("a.py", """
                import random


                def md5ish():
                    return random.random()


                md5ish()
                """));
    }

    @Test
    void pythonImportsAndReexports() throws Exception {
        List<String> got = scan(
                "src/lib/__init__.py", "from .a import sha1_hex\n",
                "src/lib/a.py", "from .b import sha1_hex\n",
                "src/lib/b.py", """
                        import hashlib


                        def sha1_hex(x):
                            return hashlib.sha1(x).hexdigest()
                        """,
                "app/x.py", """
                        import lib
                        from lib import sha1_hex
                        from lib.b import sha1_hex as other
                        import lib.b as lb


                        def f(x, sha1_hex2):
                            sha1_hex(x)
                            other(x)
                            lb.sha1_hex(x)
                            lib.sha1_hex(x)  # an attribute of a package, through its re-exports
                        """,
                "ns/m.py", """
                        import nspkg.mod


                        nspkg.mod.sha1_hex(1)
                        """,
                "nspkg/mod.py", "from lib.b import sha1_hex\n");
        assertEquals(List.of(
                "app/x.py:10 python.hash.sha1 <- src/lib/b.py:4 src.lib.b.sha1_hex | src/lib/b.py:5",
                "app/x.py:11 python.hash.sha1 <- src/lib/b.py:4 src.lib.b.sha1_hex | src/lib/b.py:5",
                "app/x.py:8 python.hash.sha1 <- src/lib/b.py:4 src.lib.b.sha1_hex | src/lib/b.py:5",
                "app/x.py:9 python.hash.sha1 <- src/lib/b.py:4 src.lib.b.sha1_hex | src/lib/b.py:5",
                "ns/m.py:4 python.hash.sha1 <- src/lib/b.py:4 src.lib.b.sha1_hex | src/lib/b.py:5"), got);
    }

    @Test
    void pythonConflictingBindingsAndClasses() throws Exception {
        List<String> got = scan("k.py", """
                import hashlib


                class Keys:
                    @classmethod
                    def md5_of(cls, x):
                        return hashlib.md5(x)

                    def go(self):
                        return self.md5_of(1)


                def run():
                    Keys.md5_of(1)
                """, "u.py", """
                try:
                    from k import Keys
                except ImportError:
                    from other import Keys
                Keys.md5_of(2)
                """, "v.py", """
                from k import Keys
                Keys.md5_of(3)
                """);
        assertEquals(List.of(
                "k.py:10 python.hash.md5 <- k.py:6 k.Keys.md5_of | k.py:7",
                "k.py:14 python.hash.md5 <- k.py:6 k.Keys.md5_of | k.py:7",
                "v.py:2 python.hash.md5 <- k.py:6 k.Keys.md5_of | k.py:7"), got);
    }

    @Test
    void goTypesFieldsAndModules() throws Exception {
        List<String> got = scan(
                "go.mod", "module example.com/top // comment\n",
                "sub/go.mod", "module \"example.com/other\"\n",
                "sub/x/x.go", """
                        package x

                        import "crypto/md5"

                        type T struct{}

                        func (t T) MD5(b []byte) [16]byte { return md5.Sum(b) }
                        """,
                "main.go", """
                        package main

                        import "example.com/other/x"

                        type S struct {
                        	t x.T
                        	u *x.T
                        }

                        func (s S) run(b []byte) {
                        	s.t.MD5(b)
                        	s.u.MD5(b)
                        	var v x.T
                        	v.MD5(b)
                        	w := new(x.T)
                        	w.MD5(b)
                        	z := x.T{}
                        	z = other()
                        	z.MD5(b)
                        }

                        func other() x.T { return x.T{} }
                        """);
        assertEquals(List.of(
                "main.go:11 go.hash.md5 <- sub/x/x.go:7 x.T.MD5 | sub/x/x.go:7",
                "main.go:12 go.hash.md5 <- sub/x/x.go:7 x.T.MD5 | sub/x/x.go:7",
                "main.go:14 go.hash.md5 <- sub/x/x.go:7 x.T.MD5 | sub/x/x.go:7",
                "main.go:16 go.hash.md5 <- sub/x/x.go:7 x.T.MD5 | sub/x/x.go:7",
                "main.go:19 go.hash.md5 <- sub/x/x.go:7 x.T.MD5 | sub/x/x.go:7"), got);
    }

    @Test
    void testFilesAndThreads() throws Exception {
        String[] files = {"p/Hash.java", HASH_JAVA, "src/test/java/p/HashTest.java", """
                package p;
                class HashTest {
                    void t() throws Exception { Hash.sha256(new byte[0]); }
                }
                """};
        List<String> one = scan(WrapperOptions.defaults(false), 1, files);
        assertEquals(List.of("src/test/java/p/HashTest.java:3 java.hash.sha2 <- p/Hash.java:4 Hash.sha256 | p/Hash.java:5"
                + " test"), one);
        assertEquals(one, scan(WrapperOptions.defaults(false), 4, files));
    }

    @Test
    void identifierScan() {
        assertTrue(ScannerAccess.hasIdentifier("x = sha256(y)", java.util.Set.of("sha256")));
        assertTrue(!ScannerAccess.hasIdentifier("x = sha256d(y) + 1sha256",
                java.util.Set.of("sha256")));
        assertTrue(ScannerAccess.hasIdentifier("$sha256$", java.util.Set.of("$sha256$")));
    }

    @Test
    void directFindingOnTheLineWins() throws Exception {
        assertEquals(List.of(), scan("p/Hash.java", HASH_JAVA, "p/U.java", """
                package p;
                import java.security.MessageDigest;
                class U { byte[] u(byte[] d) throws Exception { return Hash.sha256(MessageDigest.getInstance("SHA-512").digest(d)); } }
                """));
    }
}
