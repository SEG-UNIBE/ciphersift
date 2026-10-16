/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.files;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * An {@code --exclude} glob (SPEC 4.2). {@code *} and {@code ?} do not cross {@code /}; {@code [..]}
 * and {@code [!..]} are character sets; {@code **} as a whole segment matches zero or more segments.
 * A glob without {@code /} is matched against the base name, one with {@code /} against the whole
 * relative path (a leading {@code /} is ignored, a trailing {@code /} restricts it to directories).
 */
public final class Glob {
    private final String text;
    private final Pattern pattern;
    private final boolean baseName;
    private final boolean directoriesOnly;

    private Glob(String text, Pattern pattern, boolean baseName, boolean directoriesOnly) {
        this.text = text;
        this.pattern = pattern;
        this.baseName = baseName;
        this.directoriesOnly = directoriesOnly;
    }

    public static Glob compile(String glob) {
        String g = glob;
        boolean dirOnly = false;
        while (g.endsWith("/") && g.length() > 1) {
            g = g.substring(0, g.length() - 1);
            dirOnly = true;
        }
        if (g.equals("/")) {
            g = "";
        }
        boolean hadSlash = g.indexOf('/') >= 0;
        while (g.startsWith("/")) {
            g = g.substring(1);
        }
        boolean base = !hadSlash;
        return new Glob(glob, Pattern.compile(toRegex(g), Pattern.DOTALL), base, dirOnly);
    }

    /** Does the glob match this relative path ({@code /}-separated)? */
    public boolean matches(String relativePath, boolean directory) {
        if (directoriesOnly && !directory) {
            return false;
        }
        String subject = relativePath;
        if (baseName) {
            int i = relativePath.lastIndexOf('/');
            subject = i < 0 ? relativePath : relativePath.substring(i + 1);
        }
        return pattern.matcher(subject).matches();
    }

    @Override
    public String toString() {
        return text;
    }

    static String toRegex(String glob) {
        List<String> segments = new ArrayList<>(List.of(glob.split("/", -1)));
        StringBuilder re = new StringBuilder();
        int n = segments.size();
        for (int i = 0; i < n; i++) {
            String seg = segments.get(i);
            boolean last = i == n - 1;
            if (seg.equals("**")) {
                if (last) {
                    // "a/**": everything below a (the "a/" is already in the regex); "**" alone: anything
                    re.append(".*");
                } else {
                    // zero or more segments, each followed by "/"
                    re.append("(?:[^/]*/)*");
                }
                continue;
            }
            re.append(segment(seg));
            if (!last) {
                re.append('/');
            }
        }
        return re.toString();
    }

    private static String segment(String seg) {
        StringBuilder re = new StringBuilder();
        int i = 0;
        while (i < seg.length()) {
            char c = seg.charAt(i);
            switch (c) {
                case '*' -> {
                    while (i + 1 < seg.length() && seg.charAt(i + 1) == '*') {
                        i++;
                    }
                    re.append("[^/]*");
                }
                case '?' -> re.append("[^/]");
                case '[' -> {
                    int close = findClose(seg, i);
                    if (close < 0) {
                        re.append("\\[");
                    } else {
                        String body = seg.substring(i + 1, close);
                        boolean neg = body.startsWith("!");
                        if (neg) {
                            body = body.substring(1);
                        }
                        StringBuilder cls = new StringBuilder("[");
                        if (neg) {
                            cls.append('^');
                        }
                        for (int k = 0; k < body.length(); k++) {
                            char b = body.charAt(k);
                            if (b == '-' && k > 0 && k < body.length() - 1) {
                                cls.append('-');
                            } else if (Character.isLetterOrDigit(b)) {
                                cls.append(b);
                            } else {
                                cls.append('\\').append(b);
                            }
                        }
                        if (neg) {
                            cls.append('/');
                        }
                        cls.append(']');
                        re.append(neg ? cls.toString() : "(?:(?!/)" + cls + ")");
                        i = close;
                    }
                }
                default -> {
                    if (Character.isLetterOrDigit(c)) {
                        re.append(c);
                    } else {
                        re.append(Pattern.quote(String.valueOf(c)));
                    }
                }
            }
            i++;
        }
        return re.toString();
    }

    private static int findClose(String seg, int open) {
        int k = open + 1;
        if (k < seg.length() && seg.charAt(k) == '!') {
            k++;
        }
        if (k < seg.length() && seg.charAt(k) == ']') {
            k++;
        }
        for (; k < seg.length(); k++) {
            if (seg.charAt(k) == ']') {
                return k;
            }
        }
        return -1;
    }
}
