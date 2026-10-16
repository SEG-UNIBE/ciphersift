// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The CipherSift Authors
// Run: java RegexParity.java <cases.tsv>   (single-file source launcher, JDK 11+)
// Each line: mode \t base64(regex) \t base64(probe) \t expected(0|1). Modes as in SPEC.md 5.7.
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.regex.Pattern;

public class RegexParity {
    public static void main(String[] args) throws Exception {
        int total = 0, bad = 0;
        for (String line : Files.readAllLines(Path.of(args[0]), StandardCharsets.UTF_8)) {
            String[] f = line.split("\t");
            String rx = new String(Base64.getDecoder().decode(f[1]), StandardCharsets.UTF_8);
            String s = new String(Base64.getDecoder().decode(f[2]), StandardCharsets.UTF_8);
            boolean expected = f[3].equals("1");
            int flags = f[0].endsWith("-i") ? Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE : 0;
            var m = Pattern.compile(rx, flags).matcher(s);
            boolean got = f[0].startsWith("match") ? m.lookingAt() : m.find();
            total++;
            if (got != expected) {
                bad++;
                if (bad <= 30) System.out.println("MISMATCH " + f[0] + " /" + rx + "/ on '" + s + "': python=" + expected + " java=" + got);
            }
        }
        System.out.println("regex parity: " + total + " checks, " + bad + " mismatches");
        System.exit(bad == 0 ? 0 : 1);
    }
}
