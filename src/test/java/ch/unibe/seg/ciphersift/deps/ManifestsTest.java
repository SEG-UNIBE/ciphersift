/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.deps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import ch.unibe.seg.ciphersift.files.FileClass;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

/** Manifest parsing (SPEC 9). */
class ManifestsTest {
    private static String keys(List<ManifestEntry> l) {
        return l.stream().map(e -> e.key() + "@" + e.version()).collect(Collectors.joining(" "));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
        "cryptography==42.0.5 | cryptography | 42.0.5",
        "PyNaCl>=1.5 | pynacl | ",
        "pyjwt[crypto]==2.8.0 ; python_version >= \"3.8\" | pyjwt | 2.8.0",
        "Paramiko~=3.4 | paramiko | ",
        "pycryptodome===3.20.0 | pycryptodome | 3.20.0",
        "argon2_cffi==23.1.0 | argon2-cffi | 23.1.0",
        "foo == 1.0.* | foo | ",
        "Foo.Bar__baz (==1.2) | foo-bar-baz | 1.2",
        "bcrypt==4.1.2 --hash=sha256:0123 | bcrypt | 4.1.2",
        "x==1,<2 | x | 1",
    })
    void pep508(String line, String name, String version) {
        ManifestEntry e = PythonManifests.pep508(line);
        assertEquals(name, e.key());
        assertEquals(version, e.version());
    }

    @Test
    void goMod() {
        String mod = "module example.com/m // the module itself\r\ngo 1.23\nrequire golang.org/x/crypto v0.31.0\n"
                + "require (\n\t\"filippo.io/age\" v1.2.1 // indirect\n\n\t`github.com/x/y` v0.0.0-2024+incompatible\n)\n"
                + "replace golang.org/x/crypto => ../crypto\nexclude (\n\tgo.step.sm/crypto v0.1.0\n)\n"
                + "require golang.org/x/crypto v0.32.0\nrequire broken\n";
        assertEquals("golang.org/x/crypto@v0.31.0 filippo.io/age@v1.2.1 github.com/x/y@v0.0.0-2024+incompatible "
                + "golang.org/x/crypto@v0.32.0", keys(GoManifests.goMod(mod)));
        assertEquals("golang.org/x/crypto@v0.32.0", DependencyScanner.deduplicate(GoManifests.goMod(mod)).get(0).key()
                + "@" + DependencyScanner.deduplicate(GoManifests.goMod(mod)).get(0).version());
        assertEquals("filippo.io/age@v1.2.1", GoManifests.goMod(mod).get(1).snippet());
    }

    @Test
    void goSum() {
        String sum = "a.io/m v1.0.0 h1:x=\na.io/m v1.0.0/go.mod h1:y=\nb.io/n v2.0.0/go.mod h1:z=\n\na.io/m v1.1.0 h1:w=\n";
        assertEquals("a.io/m@v1.0.0 a.io/m@v1.1.0", keys(GoManifests.goSum(sum)));
        assertEquals("pkg:golang/golang.org/x/crypto@v0.31.0",
                ch.unibe.seg.ciphersift.cbom.Purl.golang("golang.org/x/crypto", "v0.31.0"));
        assertEquals("pkg:golang/github.com/x/y@v0.0.0-2024%2Bincompatible",
                ch.unibe.seg.ciphersift.cbom.Purl.golang("github.com/x/y", "v0.0.0-2024+incompatible"));
        assertEquals("pkg:golang/a%20b/c", ch.unibe.seg.ciphersift.cbom.Purl.golang("a b/c", null));
    }

    @Test
    void requirementsFile() {
        String text = "# comment\ncryptography==1 # trailing\n-r other.txt\n--hash=x\nfoo @ https://x/y.whl\n"
                + "pyjwt\\\n==2.0\nurl#frag==3\n\n";
        assertEquals("cryptography@1 pyjwt@2.0 url@null", keys(PythonManifests.requirements(text)));
    }

    /** setup.cfg (SPEC 9.8): [options] install_requires and [options.extras_require], dangling lists. */
    @Test
    void setupCfg() {
        String t = "[metadata]\nname = x\ninstall_requires = notme\n[options]\ninstall_requires =\n    cryptography>=41\n"
                + "    # comment\n    pynacl==1.5.0 ; python_version>'3'\nzip_safe = False\n  ignored\n"
                + "[options.extras_require]\njwt = pyjwt==2.8.0\nssh =\n    paramiko\n    file: other.txt\n[isort]\nprofile = black\n";
        assertEquals("cryptography@null pynacl@1.5.0 pyjwt@2.8.0 paramiko@null", keys(SetupManifests.setupCfg(t)));
        assertEquals(FileClass.SETUP_CFG, FileClass.of("a/setup.cfg"));
        assertEquals("setup-cfg", FileClass.SETUP_CFG.label());
    }

    @Test
    void pyprojectOrderAndPoetry() throws Exception {
        String t = """
                [project]
                dependencies = ["a==1"]
                [project.optional-dependencies]
                x = ["b>=2"]
                [dependency-groups]
                dev = ["c==3", {include-group = "x"}]
                [tool.poetry.dependencies]
                python = "^3.11"
                d = "1.5.0"
                e = { version = "==2.14.2" }
                f = "^4.0"
                g = { git = "https://x" }
                [tool.poetry.group.test.dependencies]
                h = "0.19.0"
                """;
        assertEquals("a@1 b@null c@3 d@1.5.0 e@2.14.2 f@null g@null h@0.19.0", keys(PythonManifests.pyproject(t)));
    }

    @Test
    void locks() throws Exception {
        assertEquals("rsa@4.9 m2crypto@0.40.1 six@null", keys(PythonManifests.pipfileLock(
                "{\"default\": {\"rsa\": {\"version\": \"==4.9\"}}, \"develop\": {\"M2Crypto\": {\"version\": \"==0.40.1\"},"
                        + " \"six\": {}}}")));
        assertEquals("pynacl@1.5.0", keys(PythonManifests.poetryLock("[[package]]\nname = \"PyNaCl\"\nversion = \"1.5.0\"\n")));
    }

    @Test
    void pomPropertiesAndManagedVersions() throws Exception {
        String pom = """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <parent><groupId>g</groupId><version>9</version></parent>
                  <properties><bc>1.78</bc><a>${bc}</a></properties>
                  <dependencyManagement><dependencies>
                    <dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov</artifactId><version>${a}</version></dependency>
                  </dependencies></dependencyManagement>
                  <dependencies>
                    <dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov</artifactId></dependency>
                    <dependency><groupId>x</groupId><artifactId>y</artifactId><version>${project.version}</version></dependency>
                    <dependency><groupId>x</groupId><artifactId>z</artifactId><version>${nope}</version></dependency>
                    <dependency><groupId>x</groupId><artifactId>r</artifactId><version>[1.0,2.0)</version></dependency>
                    <!-- <dependency><groupId>c</groupId><artifactId>d</artifactId></dependency> -->
                    <dependency><groupId> </groupId><artifactId>e</artifactId></dependency>
                  </dependencies>
                </project>
                """;
        List<ManifestEntry> e = DependencyScanner.deduplicate(
                DependencyScanner.entries(FileClass.POM, pom.getBytes(StandardCharsets.UTF_8)));
        assertEquals("org.bouncycastle:bcprov@1.78 x:y@9 x:z@null x:r@null", keys(e));
    }

    @Test
    void pomDoctypeIsRejected() {
        String evil = "<?xml version=\"1.0\"?><!DOCTYPE p [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"
                + "<project><dependencies><dependency><groupId>&x;</groupId><artifactId>a</artifactId>"
                + "</dependency></dependencies></project>";
        assertThrows(DependencyScanner.MalformedManifestException.class,
                () -> DependencyScanner.entries(FileClass.POM, evil.getBytes(StandardCharsets.UTF_8)));
        assertThrows(DependencyScanner.MalformedManifestException.class,
                () -> DependencyScanner.entries(FileClass.POM, "<project>".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void gradleScripts() {
        String g = """
                val bc = "1.77"
                def jj = '0.12'
                ext.tink = "1.12.0"
                // implementation 'com.jcraft:jsch:0.1.55'
                /* implementation 'a:b:1' */
                implementation "org.bouncycastle:bcprov-jdk18on:$bc"
                implementation "io.jsonwebtoken:jjwt-api:${jj}"
                implementation group: 'com.google.crypto.tink', name: 'tink', version: "${tink}"
                implementation(group = "de.m", name = "argon2", version = "2.11")
                implementation 'x:y:$unknown'
                implementation 'p:q:1.0:sources@jar'
                def url = "http://example.org/a:b"
                implementation '''t:u:1'''
                """;
        assertEquals("org.bouncycastle:bcprov-jdk18on@1.77 io.jsonwebtoken:jjwt-api@0.12 "
                + "com.google.crypto.tink:tink@1.12.0 de.m:argon2@2.11 x:y@null p:q@1.0", keys(MavenManifests.gradle(g)));
    }

    @Test
    void versionCatalog() throws Exception {
        String t = """
                [versions]
                a = "1.0"
                b = { strictly = "2.0" }
                [libraries]
                one = { module = "g:one", version.ref = "a" }
                two = { group = "g", name = "two", version = { ref = "b" } }
                three = "g:three:3.0"
                four = { module = "g:four" }
                five = { module = "g:five", version = { require = "5.0" } }
                six = { module = "g:six", version.ref = "missing" }
                [bundles]
                x = ["one"]
                """;
        assertEquals("g:one@1.0 g:two@2.0 g:three@3.0 g:four@null g:five@5.0 g:six@null",
                keys(MavenManifests.versionCatalog(t)));
    }

    @Test
    void normalisation() {
        assertEquals("pyjwt", PythonManifests.normalise("PyJWT"));
        assertEquals("argon2-cffi", PythonManifests.normalise("argon2_cffi"));
        assertEquals("a-b-c", PythonManifests.normalise("A._-B..C"));
        assertNull(MavenManifests.coordinate("not a coordinate"));
    }
    /** The linear map-notation matcher gives exactly the matches of the SPEC 9.6 regex. */
    @Test
    void mapNotationEqualsRegex() {
        String[] tokens = {"group", "name", "version", "'", "\"", ":", "=", ",", " ", "\n", "\r", "a", "g", "$x",
            "\u2028", "group: '", "name: '", ", name = \"", ", version: '", ", version = \"", "1", "group = \""};
        java.util.Random rnd = new java.util.Random(42);
        for (int round = 0; round < 60000; round++) {
            StringBuilder b = new StringBuilder();
            int len = rnd.nextInt(40);
            for (int i = 0; i < len; i++) {
                b.append(tokens[rnd.nextInt(tokens.length)]);
            }
            String text = b.toString();
            List<String> expected = new java.util.ArrayList<>();
            java.util.regex.Matcher m = MavenManifests.MAP_NOTATION.matcher(text);
            while (m.find()) {
                expected.add(m.start() + "-" + m.end() + "|" + m.group(2) + "|" + m.group(4) + "|" + m.group(6));
            }
            List<String> actual = MapNotation.findAll(text).stream()
                    .map(x -> x.start() + "-" + x.end() + "|" + x.group() + "|" + x.name() + "|" + x.version())
                    .collect(Collectors.toList());
            assertEquals(expected, actual, () -> "input: " + text.replace("\n", "\\n"));
        }
    }

    /** A crafted one-line build script made the backtracking regex run for hours. */
    @Test
    void mapNotationIsLinear() {
        String evil = "group:'a'".repeat(200_000) + "\n" + "', name:'".repeat(100_000);
        long t0 = System.nanoTime();
        List<ManifestEntry> l = MavenManifests.gradle(evil + "\nimplementation group: 'g', name: 'a', version: '1'\n");
        long ms = (System.nanoTime() - t0) / 1_000_000;
        assertEquals("g:a@1", keys(l));
        org.junit.jupiter.api.Assertions.assertTrue(ms < 20_000, "took " + ms + " ms");
    }

    /** DECISIONS O5: direct references in pyproject.toml are skipped like in requirements files. */
    @Test
    void pyprojectDirectReferencesSkipped() throws Exception {
        String t = "[project]\ndependencies = [\"a==1\", \"b @ https://x.org/b.tar.gz\", \"c @ git+https://x/c.git\"]\n"
                + "[project.optional-dependencies]\nx = [\"d @ file:///tmp/d.whl\", \"e\"]\n"
                + "[dependency-groups]\ndev = [\"f @ https://x/f.whl\", \"g==2\"]\n";
        assertEquals("a@1 e@null g@2", keys(PythonManifests.pyproject(t)));
    }
}
