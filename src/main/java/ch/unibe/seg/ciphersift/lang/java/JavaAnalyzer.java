/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang.java;

import ch.unibe.seg.ciphersift.lang.OidTable;
import ch.unibe.seg.ciphersift.model.SourceFinding;
import ch.unibe.seg.ciphersift.rules.JavaPattern;
import ch.unibe.seg.ciphersift.rules.JavaPattern.EventKind;
import ch.unibe.seg.ciphersift.rules.RuleSet;
import ch.unibe.seg.ciphersift.rules.SourceRule;
import ch.unibe.seg.ciphersift.scan.Features;
import ch.unibe.seg.ciphersift.syntax.SyntaxNode;
import ch.unibe.seg.ciphersift.util.Texts;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/** Java source analysis (SPEC 7). One instance per scan; {@link #analyze} is thread-safe. */
public final class JavaAnalyzer {
    private static final Set<String> EXPRESSION_ANCESTORS = Set.of("argument_list", "object_creation_expression",
            "method_invocation", "parenthesized_expression", "cast_expression", "array_initializer",
            "array_creation_expression", "binary_expression");
    private static final Pattern GENERIC_GROUP = Pattern.compile("<[^<>]*>");
    private static final Pattern BLOCK_COMMENT = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
    private static final Pattern LINE_COMMENT = Pattern.compile("//[^\\n]*");
    static final int SNIPPET_MAX = 500;

    private final RuleSet rules;
    private final JavaRuleIndex index;
    private final JavaContexts contexts;
    private final boolean getters;
    private final boolean deferred;
    private final boolean inherited;
    private final boolean crossModule;
    private final boolean constructorCalls;
    /** DECISIONS R3-X-A1: anyCall does not fire on logging calls and type-label setters. */
    private final boolean anyCallMetadata;

    public JavaAnalyzer(RuleSet rules, JavaContexts contexts) {
        this(rules, contexts, Features.DEFAULTS);
    }

    public JavaAnalyzer(RuleSet rules, JavaContexts contexts, Features features) {
        this.rules = rules;
        this.index = new JavaRuleIndex(rules.javaRules(), features);
        this.contexts = contexts;
        this.getters = features.on(Features.JAVA_CONSTANT_GETTERS);
        this.deferred = features.on(Features.JAVA_DEFERRED_LOCALS);
        this.inherited = features.on(Features.JAVA_INHERITED_CONSTANTS);
        this.crossModule = features.on(Features.JAVA_CROSS_MODULE_CONSTANTS);
        this.constructorCalls = features.on(Features.JAVA_CONSTRUCTOR_CALLS);
        this.anyCallMetadata = features.on(Features.JAVA_ANY_CALL_METADATA);
    }

    /**
     * Logging methods beyond the base list of SPEC 5.5: {@code fatal} (Log4j, Commons Logging, JBoss Logging) and the
     * JBoss Logging message-format variants {@code tracev}, {@code tracef}, … (org.jboss.logging.BasicLogger).
     */
    static final Set<String> ANY_CALL_LOG_VARIANTS = Set.of("fatal", "tracev", "debugv", "infov", "warnv", "errorv",
            "fatalv", "tracef", "debugf", "infof", "warnf", "errorf", "fatalf");
    /** A receiver that is a logger: its last segment is {@code log} or {@code logger} (any case, {@code LOG}, {@code LOGGER}). */
    static final Pattern LOGGER_RECEIVER = Pattern.compile("(?:^|[._])(?i:log|logger)$");
    /** Setters of a type label (a JWK {@code kty}, a key wrapper's key type): a key type names no algorithm use. */
    static final Set<String> TYPE_SETTERS = Set.of("setType", "setKeyType");
    /**
     * DECISIONS R3-X-A1 (feature {@code java-any-call-metadata}, SPEC 5.5): an {@code anyCall} pattern does not hold
     * for a call that logs (a logging variant or a logger receiver) or sets a type label.
     */
    private static boolean anyCallMetadata(Event ev) {
        if (ANY_CALL_LOG_VARIANTS.contains(ev.name) || TYPE_SETTERS.contains(ev.name)) {
            return true;
        }
        if (ev.receiver != null && LOGGER_RECEIVER.matcher(ev.receiver).find()) {
            return true;
        }
        return false;
    }

    /** An event (SPEC 7.2). */
    static final class Event {
        final EventKind kind;
        final SyntaxNode node;
        final String name;
        /** Receiver text (call with qualifying object, new: T, field: object), or null. */
        final String receiver;
        /** Static candidates of an unqualified call. */
        final List<String> staticCandidates;
        final SyntaxNode arguments;
        final int line;
        private List<SyntaxNode> args;
        private List<String> strings;
        /** The OID each element of {@link #strings} was given as (SPEC 5.11), or null; parallel to it. */
        private List<String> stringOids;
        private String collapsedArgs;

        Event(EventKind kind, SyntaxNode node, String name, String receiver, List<String> staticCandidates,
                SyntaxNode arguments, int line) {
            this.kind = kind;
            this.node = node;
            this.name = name;
            this.receiver = receiver;
            this.staticCandidates = staticCandidates;
            this.arguments = arguments;
            this.line = line;
        }

        List<SyntaxNode> args() {
            if (args == null) {
                List<SyntaxNode> l = new ArrayList<>();
                if (arguments != null) {
                    for (int i = 0; i < arguments.childCount(); i++) {
                        SyntaxNode c = arguments.child(i);
                        if (c.isNamed() && !JExpr.isComment(c)) {
                            l.add(c);
                        }
                    }
                }
                args = l;
            }
            return args;
        }
    }

    private record Selected(Event event, SourceRule rule, JavaPattern chosen, String matched, String oid) {}

    /**
     * Analyses one parsed Java file.
     *
     * @param file normalised absolute path (for cross-file lookup)
     */
    public List<SourceFinding> analyze(SyntaxNode root, Path file, String relativePath, boolean test) {
        JavaContext ctx = JavaContext.build(file, root);
        JavaResolver resolver = new JavaResolver(rules, contexts, getters, deferred, inherited, crossModule);
        List<Selected> selected = new ArrayList<>();
        IdentityHashMap<SyntaxNode, List<Selected>> byNode = new IdentityHashMap<>();

        ArrayDeque<SyntaxNode> stack = new ArrayDeque<>();
        stack.push(root);
        while (!stack.isEmpty()) {
            SyntaxNode n = stack.pop();
            Event ev = event(n, ctx);
            if (ev != null) {
                List<Selected> s = select(ev, ctx, resolver);
                if (!s.isEmpty()) {
                    selected.addAll(s);
                    byNode.put(n, s);
                }
            }
            for (int i = n.childCount() - 1; i >= 0; i--) {
                SyntaxNode c = n.child(i);
                if (c.isNamed()) {
                    stack.push(c);
                }
            }
        }

        List<SourceFinding> out = new ArrayList<>();
        for (Selected s : selected) {
            if (nestedDuplicate(s, byNode)) {
                continue;
            }
            out.add(finding(s, ctx, resolver, relativePath, test));
        }
        return out;
    }

    // ------------------------------------------------------------------ events

    private Event event(SyntaxNode n, JavaContext ctx) {
        switch (n.type()) {
            case "method_invocation": {
                SyntaxNode nameNode = n.field("name");
                if (nameNode == null) {
                    return null;
                }
                String name = nameNode.text();
                if (!index.hasCandidates(EventKind.CALL, name)) {
                    return null;
                }
                SyntaxNode obj = n.field("object");
                String receiver = null;
                List<String> statics = List.of();
                if (obj != null) {
                    if (obj.is("identifier") || obj.is("field_access") || obj.is("scoped_identifier")) {
                        receiver = Texts.removeWhitespace(obj.text());
                    }
                } else {
                    String cls = ctx.staticImports.get(name);
                    if (cls != null) {
                        statics = List.of(cls);
                    } else {
                        statics = List.copyOf(ctx.staticWildcards);
                    }
                }
                return new Event(EventKind.CALL, n, name, receiver, statics, n.field("arguments"), n.line());
            }
            case "explicit_constructor_invocation": {
                // super(…) / this(…): a call without receiver named "super" / "this"; only anyCall patterns can
                // hold for it (no rule names these methods), t3 J-SUPER
                SyntaxNode ctor = n.field("constructor");
                if (!constructorCalls || ctor == null || n.field("object") != null) {
                    return null;
                }
                String name = ctor.text();
                if (!(name.equals("super") || name.equals("this")) || !index.hasCandidates(EventKind.CALL, name)) {
                    return null;
                }
                return new Event(EventKind.CALL, n, name, null, List.of(), n.field("arguments"), n.line());
            }
            case "object_creation_expression": {
                SyntaxNode type = n.field("type");
                if (type == null) {
                    return null;
                }
                String t = removeGenerics(Texts.removeWhitespace(type.text()));
                String name = Texts.lastSegment(t);
                if (!index.hasCandidates(EventKind.NEW, name)) {
                    return null;
                }
                return new Event(EventKind.NEW, n, name, t, List.of(), n.field("arguments"), n.line());
            }
            case "field_access": {
                SyntaxNode obj = n.field("object");
                SyntaxNode f = n.field("field");
                if (obj == null || f == null) {
                    return null;
                }
                SyntaxNode parent = n.parent();
                if (parent != null && parent.is("method_invocation") && "object".equals(n.field())) {
                    return null;
                }
                String name = f.text();
                if (!index.hasCandidates(EventKind.FIELD, name)) {
                    return null;
                }
                return new Event(EventKind.FIELD, n, name, Texts.removeWhitespace(obj.text()), List.of(), null,
                        n.line());
            }
            case "method_declaration": {
                SyntaxNode nameNode = n.field("name");
                if (nameNode == null) {
                    return null;
                }
                String name = nameNode.text();
                if (!index.hasCandidates(EventKind.DECL, name)) {
                    return null;
                }
                return new Event(EventKind.DECL, n, name, null, List.of(), null, nameNode.line());
            }
            default:
                return null;
        }
    }

    static String removeGenerics(String s) {
        if (s.indexOf('<') < 0) {
            return s;
        }
        String prev;
        String cur = s;
        do {
            prev = cur;
            cur = GENERIC_GROUP.matcher(cur).replaceAll("");
        } while (!cur.equals(prev));
        return cur;
    }

    // ------------------------------------------------------------------ denotes (7.3.2)

    static boolean denotes(String reference, String cls, JavaContext ctx) {
        String ref = removeGenerics(Texts.removeWhitespace(reference));
        if (ref.isEmpty()) {
            return false;
        }
        if (ref.equals(cls)) {
            return true;
        }
        int dot = ref.indexOf('.');
        String f = dot < 0 ? ref : ref.substring(0, dot);
        String r = dot < 0 ? "" : ref.substring(dot + 1);
        String imported = ctx.imports.get(f);
        if (imported != null) {
            return (r.isEmpty() ? imported : imported + "." + r).equals(cls);
        }
        if (ctx.localClasses.contains(f)) {
            return false;
        }
        if (f.isEmpty() || !Character.isUpperCase(f.charAt(0))) {
            return false;
        }
        if (!cls.endsWith("." + ref)) {
            return false;
        }
        // A member type is in scope by its simple name only through an import: if the reference starts
        // below an enclosing class of C (Inner for a.b.Outer.Inner), that class must be imported on demand
        // or statically; Outer.Inner itself is assumed like a top-level class (SPEC 7.3.2 step 6).
        String enclosing = cls.substring(0, cls.length() - ref.length() - 1);
        String last = Texts.lastSegment(enclosing);
        if (!last.isEmpty() && Character.isUpperCase(last.charAt(0))) {
            return ctx.wildcards.contains(enclosing) || ctx.staticWildcards.contains(enclosing)
                    || enclosing.equals(ctx.staticImports.get(f));
        }
        return true;
    }

    // ------------------------------------------------------------------ evaluation and selection (7.6, 7.7.1)

    private List<Selected> select(Event ev, JavaContext ctx, JavaResolver resolver) {
        List<Selected> normal = select0(ev, ctx, resolver);
        if (!deferred || (ev.kind != EventKind.CALL && ev.kind != EventKind.NEW)) {
            return normal;
        }
        // a local assigned different values (DECISIONS B-J-JP3): if every value selects the same rules, those
        // rules; the matched string (and oid) only if it is the same for every value
        SyntaxNode var = null;
        List<String> alts = null;
        for (SyntaxNode a : ev.args()) {
            if (a.is("identifier")) {
                alts = resolver.alternatives((JExpr.Ident) JExpr.of(a, true), ctx);
                if (alts != null) {
                    var = a;
                    break;
                }
            }
        }
        if (alts == null) {
            return normal;
        }
        List<List<Selected>> per = new ArrayList<>();
        for (String v : alts) {
            Event e2 = new Event(ev.kind, ev.node, ev.name, ev.receiver, ev.staticCandidates, ev.arguments, ev.line);
            List<String> raw = resolver.stringList(ev.args(), ctx, var, v);
            mapOids(e2, raw);
            per.add(select0(e2, ctx, resolver));
        }
        List<Selected> first = per.get(0);
        if (first.isEmpty()) {
            return normal;
        }
        for (List<Selected> l : per) {
            if (l.size() != first.size()) {
                return normal;
            }
            for (int i = 0; i < l.size(); i++) {
                if (l.get(i).rule() != first.get(i).rule()) {
                    return normal;
                }
            }
        }
        List<Selected> out = new ArrayList<>();
        for (int i = 0; i < first.size(); i++) {
            Selected f = first.get(i);
            boolean same = true;
            for (List<Selected> l : per) {
                same &= Objects.equals(l.get(i).matched(), f.matched())
                        && Objects.equals(l.get(i).oid(), f.oid());
            }
            out.add(new Selected(ev, f.rule(), f.chosen(), same ? f.matched() : null, same ? f.oid() : null));
        }
        return out;
    }

    private List<Selected> select0(Event ev, JavaContext ctx, JavaResolver resolver) {
        List<JavaPattern> cands = index.candidates(ev.kind, ev.name);
        if (cands.isEmpty()) {
            return List.of();
        }
        // per rule: best specificity and chosen pattern; anyCall patterns only where no other pattern holds
        // (SPEC 5.5: a fallback for names given to an API no rule knows)
        Map<SourceRule, JavaPattern> chosen = choose(cands, ev, ctx, resolver, false);
        if (chosen.isEmpty()) {
            chosen = choose(cands, ev, ctx, resolver, true);
        }
        if (chosen.isEmpty()) {
            return List.of();
        }
        Map<String, Integer> maxByType = new HashMap<>();
        chosen.forEach((r, p) -> maxByType.merge(r.asset().type(), p.specificity, Math::max));
        List<Selected> out = new ArrayList<>();
        chosen.forEach((r, p) -> {
            if (p.specificity == maxByType.get(r.asset().type())) {
                int i = matchedIndex(p, ev, ctx, resolver);
                out.add(new Selected(ev, r, p, i < 0 ? null : ev.strings.get(i), i < 0 ? null : ev.stringOids.get(i)));
            }
        });
        return out;
    }

    /** The holding patterns per rule (SPEC 7.7.1), among the anyCall patterns or among the others. */
    private Map<SourceRule, JavaPattern> choose(List<JavaPattern> cands, Event ev, JavaContext ctx,
            JavaResolver resolver, boolean anyCall) {
        Map<SourceRule, JavaPattern> chosen = new LinkedHashMap<>();
        for (JavaPattern p : cands) {
            if ((p.anchor == JavaPattern.Anchor.ANY_CALL) != anyCall) {
                continue;
            }
            JavaPattern best = chosen.get(p.rule);
            if (best != null && best.specificity >= p.specificity) {
                continue; // cannot improve: an earlier pattern with at least this specificity already holds
            }
            if (holds(p, ev, ctx, resolver)) {
                chosen.put(p.rule, p);
            }
        }
        return chosen;
    }

    private boolean holds(JavaPattern p, Event ev, JavaContext ctx, JavaResolver resolver) {
        switch (p.anchor) {
            case CALL -> {
                if (ev.kind != EventKind.CALL || !p.nameMatches(ev.name)) {
                    return false;
                }
                if (ev.receiver != null) {
                    if (!denotes(ev.receiver, p.className, ctx)) {
                        return false;
                    }
                } else if (!ev.staticCandidates.contains(p.className)) {
                    return false;
                }
            }
            case METHOD -> {
                if (ev.kind != EventKind.CALL || !p.nameMatches(ev.name)) {
                    return false;
                }
            }
            case ANY_CALL -> {
                if (ev.kind != EventKind.CALL || !JavaRuleIndex.anyCallFires(ev.name)
                        || (anyCallMetadata && anyCallMetadata(ev))) {
                    return false;
                }
            }
            case NEW -> {
                if (ev.kind != EventKind.NEW || !denotes(ev.receiver, p.className, ctx)) {
                    return false;
                }
            }
            case FIELD -> {
                if (ev.kind != EventKind.FIELD || !p.nameMatches(ev.name)
                        || !denotes(ev.receiver, p.className, ctx)) {
                    return false;
                }
            }
            case OVERRIDE -> {
                if (ev.kind != EventKind.DECL || !p.nameMatches(ev.name)) {
                    return false;
                }
            }
            default -> {
                return false;
            }
        }
        if (p.firstString != null) {
            List<String> s = strings(ev, ctx, resolver);
            if (s.isEmpty() || !p.firstString.matcher(s.get(0)).lookingAt()) {
                return false;
            }
        }
        if (p.anyString != null && firstMatching(p.anyString, strings(ev, ctx, resolver)) == null) {
            return false;
        }
        if (p.stringContains != null && firstContaining(p.stringContains, strings(ev, ctx, resolver)) == null) {
            return false;
        }
        if (p.argsText != null) {
            if (ev.arguments == null) {
                return false;
            }
            if (ev.collapsedArgs == null) {
                ev.collapsedArgs = Texts.collapseWhitespace(ev.arguments.text());
            }
            if (!p.argsText.matcher(ev.collapsedArgs).find()) {
                return false;
            }
        }
        if (p.argsTextContains != null) {
            if (ev.arguments == null) {
                return false;
            }
            String raw = ev.arguments.text();
            boolean any = false;
            for (String needle : p.argsTextContains) {
                if (raw.contains(needle)) {
                    any = true;
                    break;
                }
            }
            if (!any) {
                return false;
            }
        }
        if (p.constantArg != null) {
            List<SyntaxNode> args = ev.args();
            int i = p.constantArg;
            if (args.size() <= i || !resolver.isConst(JExpr.of(args.get(i), true), ctx, 0, false)) {
                return false;
            }
        }
        if (p.inType != null) {
            String owner = ownerText(ev.node);
            boolean any = false;
            for (String t : p.inType) {
                if (Texts.containsWord(owner, t)) {
                    any = true;
                    break;
                }
            }
            if (!any) {
                return false;
            }
        }
        if (p.body != null) {
            SyntaxNode body = ev.node.field("body");
            if (body == null) {
                return false;
            }
            if (!p.body.matcher(normalisedBody(body.text())).find()) {
                return false;
            }
        }
        return true;
    }

    private List<String> strings(Event ev, JavaContext ctx, JavaResolver resolver) {
        if (ev.strings == null) {
            mapOids(ev, ev.kind == EventKind.CALL || ev.kind == EventKind.NEW
                    ? resolver.stringList(ev.args(), ctx) : List.of());
        }
        return ev.strings;
    }

    /** Sets the event's string list from the raw strings: table OIDs replaced by their names (SPEC 5.11). */
    private static void mapOids(Event ev, List<String> raw) {
        {
            // a dotted OID of the built-in table is treated like the algorithm name it maps to (SPEC 5.11)
            List<String> mapped = raw;
            List<String> oids = null;
            for (int i = 0; i < raw.size(); i++) {
                OidTable.Entry x = OidTable.lookup(raw.get(i));
                if (x != null) {
                    if (oids == null) {
                        mapped = new ArrayList<>(raw);
                        oids = new ArrayList<>(Collections.nCopies(raw.size(), (String) null));
                    }
                    mapped.set(i, x.name());
                    oids.set(i, x.oid());
                }
            }
            ev.strings = mapped;
            ev.stringOids = oids == null ? Collections.nCopies(raw.size(), (String) null) : oids;
        }
    }

    private static String firstMatching(Pattern p, List<String> strings) {
        for (String s : strings) {
            if (p.matcher(s).lookingAt()) {
                return s;
            }
        }
        return null;
    }

    private static String firstContaining(List<String> needles, List<String> strings) {
        for (String s : strings) {
            String l = Texts.lower(s);
            for (String n : needles) {
                if (l.contains(n)) {
                    return s;
                }
            }
        }
        return null;
    }

    /**
     * Index in the string list of the matched string of the chosen pattern (SPEC 7.7.1), or -1: the first
     * string for {@code firstString}, else the first containing a needle, else the first matching
     * {@code anyString}.
     */
    private int matchedIndex(JavaPattern p, Event ev, JavaContext ctx, JavaResolver resolver) {
        if (p.firstString != null) {
            return strings(ev, ctx, resolver).isEmpty() ? -1 : 0;
        }
        if (p.stringContains != null) {
            String s = firstContaining(p.stringContains, strings(ev, ctx, resolver));
            return s == null ? -1 : ev.strings.indexOf(s);
        }
        if (p.anyString != null) {
            String s = firstMatching(p.anyString, strings(ev, ctx, resolver));
            return s == null ? -1 : ev.strings.indexOf(s);
        }
        return -1;
    }

    /** Owner text of a method declaration for {@code inType} (SPEC 7.6). */
    static String ownerText(SyntaxNode decl) {
        SyntaxNode a = decl.parent();
        while (a != null && !(a.is("class_body") || a.is("enum_body"))) {
            a = a.parent();
        }
        if (a == null || a.parent() == null) {
            return "";
        }
        SyntaxNode p = a.parent();
        if (p.is("object_creation_expression")) {
            SyntaxNode t = p.field("type");
            return t == null ? "" : t.text();
        }
        SyntaxNode sup = p.field("superclass");
        SyntaxNode itf = p.field("interfaces");
        return (sup == null ? "" : sup.text()) + " " + (itf == null ? "" : itf.text());
    }

    /** Body text for {@code body}: comments removed, whitespace collapsed, trimmed (SPEC 7.6). */
    static String normalisedBody(String body) {
        String s = BLOCK_COMMENT.matcher(body).replaceAll(" ");
        s = LINE_COMMENT.matcher(s).replaceAll(" ");
        return Texts.trim(Texts.collapseWhitespace(s));
    }

    // ------------------------------------------------------------------ nested duplicates (7.7.2)

    private static boolean nestedDuplicate(Selected s, IdentityHashMap<SyntaxNode, List<Selected>> byNode) {
        String family = s.rule().asset().family();
        if (family == null) {
            return false;
        }
        String type = s.rule().asset().type();
        SyntaxNode a = s.event().node.parent();
        while (a != null && EXPRESSION_ANCESTORS.contains(a.type())) {
            List<Selected> l = byNode.get(a);
            if (l != null) {
                for (Selected o : l) {
                    if (type.equals(o.rule().asset().type()) && family.equals(o.rule().asset().family())) {
                        return true;
                    }
                }
            }
            a = a.parent();
        }
        return false;
    }

    // ------------------------------------------------------------------ findings (7.8)

    private SourceFinding finding(Selected s, JavaContext ctx, JavaResolver resolver, String rel, boolean test) {
        Event ev = s.event();
        JavaPattern p = s.chosen();
        String name = s.matched() != null ? s.matched() : displayName(ev);
        String symbol = switch (p.anchor) {
            case CALL -> p.className + "." + ev.name;
            case NEW -> p.className;
            case FIELD -> p.className + "." + ev.name;
            case METHOD, OVERRIDE, ANY_CALL -> ev.name;
        };
        String snippet;
        if (ev.kind == EventKind.DECL) {
            String t = ev.node.text();
            int brace = t.indexOf('{');
            snippet = Texts.trim(brace < 0 ? t : t.substring(0, brace));
        } else {
            snippet = ev.node.text();
        }
        snippet = Texts.truncateCodePoints(snippet, SNIPPET_MAX);
        String param = null;
        if (p.paramIndex != null) {
            List<SyntaxNode> args = ev.args();
            if (p.paramIndex < args.size()) {
                param = OidTable.map(resolver.value(JExpr.of(args.get(p.paramIndex), true), ctx, 0));
            }
        }
        return new SourceFinding(rel, ev.line, s.rule(), name, symbol, snippet, param, s.oid(), test);
    }

    static String displayName(Event ev) {
        switch (ev.kind) {
            case CALL -> {
                if (ev.receiver != null) {
                    return Texts.lastSegment(ev.receiver) + "." + ev.name;
                }
                if (ev.node.field("object") == null && ev.staticCandidates.size() == 1) {
                    return Texts.lastSegment(ev.staticCandidates.get(0)) + "." + ev.name;
                }
                return ev.name;
            }
            case NEW -> {
                String t = ev.receiver;
                while (true) {
                    int dot = t.indexOf('.');
                    if (dot < 0 || t.isEmpty() || Character.isUpperCase(t.charAt(0))) {
                        break;
                    }
                    t = t.substring(dot + 1);
                }
                return t;
            }
            case FIELD -> {
                return Texts.lastSegment(ev.receiver) + "." + ev.name;
            }
            default -> {
                return ev.name;
            }
        }
    }
}
