/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_territory — the lib/territory gate.
 *
 * The scorecard's whole value is that its three reachability buckets can be
 * trusted, so this file proves the two properties that make them trustworthy
 * against a HERMETIC fixture tree rather than against the checkout (whose
 * numbers move every commit):
 *
 *   1. THE BUCKETS PARTITION. reached + unreached + unknown equals
 *      public_symbols exactly, and no symbol carries a verdict outside the
 *      three. A tool that could double-count or drop a symbol would be able
 *      to report a flattering total.
 *
 *   2. AN UNREACHED SYMBOL IS REPORTED UNREACHED. The fixture declares three
 *      public functions with three different, deliberately chosen shapes:
 *        alpha_reached      — called from a function the registered entry
 *                             point calls: must be REACHED
 *        alpha_dead         — referenced nowhere at all: must be UNREACHED
 *        alpha_dispatch_id  — referenced only where NO function encloses the
 *                             reference (the registry-row shape): must be
 *                             UNKNOWN, because a source call graph cannot
 *                             follow an indirect dispatch
 *      If the classifier ever defaulted to "reached", or folded the
 *      file-scope case into either neighbour, one of these three fails.
 *
 *   3. THE REFUSAL IS REAL. With no reached set at all, every symbol must
 *      come back UNKNOWN/walk-bounded — not unreached, which would be a
 *      guess dressed as a measurement.
 *
 * The fixture is scanned, never compiled, so it is written to exercise the
 * scanner's reference rule (an identifier followed by '(' inside braces)
 * rather than to be valid translation units.
 *
 * All scratch work happens under ./test-tmp/ (project no-/tmp convention). */

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "territory/territory.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define TERR_FIX "test-tmp/terr_fix"

/* Write content to <dir>/<rel>, creating parent dirs. */
static bool terr_write(const char *dir, const char *rel, const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; (void)mkdir(full, 0755); *p = '/'; }
    }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    if (content && content[0]) fwrite(content, 1, strlen(content), f);
    fclose(f);
    return true;
}

static const char *ALPHA_H =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " *\n"
    " * alpha \xe2\x80\x94 fixture public surface for the territory scorecard.\n"
    " */\n"
    "#ifndef FIX_ALPHA_H\n"
    "#define FIX_ALPHA_H\n"
    "\n"
    "/* Reached: a registered entry point transitively calls this. */\n"
    "void alpha_reached(void);\n"
    "\n"
    "/* Unreached: nothing in the fixture tree names it. */\n"
    "void alpha_dead(void);\n"
    "\n"
    "/* Unknown: named only from a registry row, where no function encloses\n"
    " * the reference. */\n"
    "int alpha_dispatch_id(void);\n"
    "\n"
    "struct alpha_row { const char *name; int slot; };\n"
    "\n"
    "#define ALPHA_SLOT_MAX 8\n"
    "\n"
    "#endif\n";

/* The code index attributes a function declaration only at FILE SCOPE, and
 * `extern "C" {` opens a brace, so every declaration in a header shaped like
 * this one is invisible to it. 62 headers under lib/ are shaped like this
 * today. The scorecard must not report that invisibility as a small public
 * surface, so it counts such headers separately — this fixture pins that. */
static const char *BETA_H =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " *\n"
    " * beta \xe2\x80\x94 fixture header the index cannot see into.\n"
    " */\n"
    "#ifndef FIX_BETA_H\n"
    "#define FIX_BETA_H\n"
    "\n"
    "#ifdef __cplusplus\n"
    "extern \"C\" {\n"
    "#endif\n"
    "\n"
    "void beta_invisible(void);\n"
    "\n"
    "#ifdef __cplusplus\n"
    "}\n"
    "#endif\n"
    "\n"
    "#endif\n";

static const char *ALPHA_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " *\n"
    " * alpha \xe2\x80\x94 fixture definitions.\n"
    " */\n"
    "#include \"base/alpha.h\"\n"
    "\n"
    "void alpha_reached(void)\n"
    "{\n"
    "    int unused = 0;\n"
    "    (void)unused;\n"
    "}\n"
    "\n"
    "void alpha_dead(void)\n"
    "{\n"
    "    int unused = 0;\n"
    "    (void)unused;\n"
    "}\n"
    "\n"
    "int alpha_dispatch_id(void)\n"
    "{\n"
    "    return 1;\n"
    "}\n";

/* The dispatch-table shape. The reference to alpha_dispatch_id sits inside an
 * initializer at file scope, ABOVE every function definition in the file, so
 * the scanner records it with no enclosing function — exactly what a registry
 * row looks like, and exactly the case the classifier must refuse to decide. */
static const char *REGISTRY_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " *\n"
    " * registry \xe2\x80\x94 fixture dispatch table.\n"
    " */\n"
    "#include \"base/alpha.h\"\n"
    "\n"
    "static const struct alpha_row g_rows[] = {\n"
    "    { \"dispatch\", alpha_dispatch_id() },\n"
    "};\n"
    "\n"
    "const struct alpha_row *alpha_rows(void)\n"
    "{\n"
    "    return g_rows;\n"
    "}\n";

static const char *CALLER_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " *\n"
    " * caller \xe2\x80\x94 fixture middle of the call chain.\n"
    " */\n"
    "#include \"base/alpha.h\"\n"
    "\n"
    "void net_call_alpha(void)\n"
    "{\n"
    "    alpha_reached();\n"
    "}\n";

static const char *TEST_ENTRY_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " *\n"
    " * test_fixgroup \xe2\x80\x94 fixture registered proof entry point.\n"
    " */\n"
    "void net_call_alpha(void);\n"
    "\n"
    "int test_fixgroup(void)\n"
    "{\n"
    "    net_call_alpha();\n"
    "    return 0;\n"
    "}\n";

/* The fixture's registered proof catalog: one entry point. Supplied through
 * the same port the real command fills from tools/dev's catalog, which is why
 * this test can prove the UNREACHED path without touching the real one. */
/* ── the lint-gate wiring the brief derives `refuses` from ───────────────
 * Three gates, one of each bucket, so a test can assert the partition rather
 * than a magic number: one names lib/base (and owes it a baseline row), one
 * names lib/net only, and one names no territory path at all. */
static const char *RUN_LINT_SH =
    "#!/bin/sh\n"
    "gate_command() {\n"
    "    case \"$1\" in\n"
    "        check-base-shape) echo './tools/lint/check_base_shape.sh' ;;\n"
    "        check-net-shape)  echo './tools/lint/check_net_shape.sh' ;;\n"
    "        check-treewide)   echo './tools/lint/check_treewide.sh' ;;\n"
    "    esac\n"
    "}\n";

static const char *GATE_BASE_SH =
    "#!/bin/sh\n"
    "BASELINE=tools/lint/base_shape_baseline.txt\n"
    "grep -rn alpha lib/base/src/ || exit 1\n";

static const char *GATE_NET_SH =
    "#!/bin/sh\n"
    "grep -rn call lib/net/src/ || exit 1\n";

/* Deliberately names no path with a slash beyond the interpreter line, which
 * belongs to no territory: this gate is the UNKNOWN-scope case. */
static const char *GATE_TREEWIDE_SH =
    "#!/bin/sh\n"
    "grep -rn TODO . || exit 0\n";

static const char *GATE_BASE_BASELINE =
    "# grandfathered rows\n"
    "lib/base/src/alpha.c alpha_dead 120\n";

static const char *const g_fix_entries[] = { "test_fixgroup" };

static const char *fix_entry_at(size_t index, void *user)
{
    (void)user;
    return index < sizeof(g_fix_entries) / sizeof(g_fix_entries[0])
               ? g_fix_entries[index]
               : NULL;
}

/* An empty catalog: no registered group exists at all. Every public symbol
 * must then be unreached or unknown, never reached. */
static const char *fix_entry_none(size_t index, void *user)
{
    (void)index; (void)user;
    return NULL;
}

/* A router that puts every fixture file in one group, so the brief has a
 * routed group whose reproducibility it can report as UNKNOWN. */
static size_t fix_route(const char *path, char (*out)[TERRITORY_GROUP_MAX],
                        size_t cap, void *user)
{
    (void)user;
    if (cap == 0 || !path) return 0;
    if (strstr(path, "/src/") == NULL) return 0;   /* headers route nowhere */
    (void)snprintf(out[0], TERRITORY_GROUP_MAX, "fixgroup");
    return 1;
}

static const struct territory_symbol *find_sym(
    const struct territory_report *r, const char *name)
{
    for (int i = 0; i < r->public_symbols; i++)
        if (strcmp(r->symbols[i].name, name) == 0) return &r->symbols[i];
    return NULL;
}

int test_territory(void);
int test_territory(void)
{
    int failures = 0;
    struct codeindex *ci = NULL;
    struct territory_reach_set *rs = NULL;
    struct territory_report *r = NULL;
    /* Declared here, not beside their first use: a failing ASSERT jumps to
     * _test_next, and jumping past a declaration's initializer would leave
     * the cleanup below freeing an indeterminate pointer. */
    struct territory_gates *gates = NULL;
    struct territory_brief *b = NULL;
    static char gnames[128][TERRITORY_NAME_MAX];
    int gcount = 0;

    test_rm_rf(TERR_FIX);
    if (!terr_write(TERR_FIX, "lib/base/include/base/alpha.h", ALPHA_H) ||
        !terr_write(TERR_FIX, "lib/base/include/base/beta.h", BETA_H) ||
        !terr_write(TERR_FIX, "lib/base/src/alpha.c", ALPHA_C) ||
        !terr_write(TERR_FIX, "lib/base/src/registry.c", REGISTRY_C) ||
        !terr_write(TERR_FIX, "lib/net/src/caller.c", CALLER_C) ||
        !terr_write(TERR_FIX, "lib/test/src/test_fixgroup.c", TEST_ENTRY_C) ||
        !terr_write(TERR_FIX, "tools/lint/run_lint.sh", RUN_LINT_SH) ||
        !terr_write(TERR_FIX, "tools/lint/check_base_shape.sh", GATE_BASE_SH) ||
        !terr_write(TERR_FIX, "tools/lint/check_net_shape.sh", GATE_NET_SH) ||
        !terr_write(TERR_FIX, "tools/lint/check_treewide.sh",
                    GATE_TREEWIDE_SH) ||
        !terr_write(TERR_FIX, "tools/lint/base_shape_baseline.txt",
                    GATE_BASE_BASELINE)) {
        printf("test_territory: could not write the fixture tree\n");
        return 1;
    }

    ci = codeindex_open(TERR_FIX);
    if (!ci) {
        printf("test_territory: could not open the fixture index\n");
        return 1;
    }

    struct territory_proof_source src = {
        .at = fix_entry_at, .count = 1, .user = NULL };
    struct territory_proof_source none = {
        .at = fix_entry_none, .count = 0, .user = NULL };

    TEST("territory_list: names the fixture's declared modules") {
        static char names[128][TERRITORY_NAME_MAX];
        int n = territory_list(ci, names, 128);
        ASSERT(n > 0);
        bool saw_base = false, saw_net = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(names[i], "lib/base") == 0) saw_base = true;
            if (strcmp(names[i], "lib/net") == 0) saw_net = true;
        }
        ASSERT(saw_base);
        ASSERT(saw_net);
        PASS();
    }

    /* root=NULL: no on-disk memo, so this walk is unambiguously the walk. */
    struct territory_reach_stats stats = {0};
    rs = territory_reach_open(ci, NULL, &src, &stats);
    ASSERT(rs != NULL);

    TEST("reach walk: the closure contains the entry point and its callees") {
        ASSERT(territory_reach_contains(rs, "test_fixgroup"));
        ASSERT(territory_reach_contains(rs, "net_call_alpha"));
        ASSERT(territory_reach_contains(rs, "alpha_reached"));
        ASSERT(!territory_reach_contains(rs, "alpha_dead"));
        ASSERT(!stats.truncated);
        ASSERT_EQ(stats.from_cache, false);
        PASS();
    }

    r = territory_scorecard(ci, TERR_FIX, "lib/base", rs, NULL);
    ASSERT(r != NULL);

    TEST("scorecard: owns exactly the fixture's lib/base files") {
        ASSERT(r->found);
        ASSERT_EQ(r->file_count, 4);
        ASSERT_EQ(r->header_count, 2);
        ASSERT_EQ(r->source_count, 2);
        ASSERT(r->bytes > 0);
        ASSERT(!r->files_truncated);
        PASS();
    }

    TEST("scorecard: the three buckets PARTITION the public symbols") {
        ASSERT_EQ(r->public_symbols, 3);
        ASSERT_EQ(r->reached + r->unreached + r->unknown, r->public_symbols);
        int counted[3] = {0, 0, 0};
        for (int i = 0; i < r->public_symbols; i++) {
            enum territory_reach_verdict v = r->symbols[i].verdict;
            ASSERT(v == TERRITORY_REACHED || v == TERRITORY_UNREACHED ||
                   v == TERRITORY_UNKNOWN);
            counted[(int)v]++;
        }
        ASSERT_EQ(counted[(int)TERRITORY_REACHED], r->reached);
        ASSERT_EQ(counted[(int)TERRITORY_UNREACHED], r->unreached);
        ASSERT_EQ(counted[(int)TERRITORY_UNKNOWN], r->unknown);
        PASS();
    }

    TEST("scorecard: a symbol a test really calls is REACHED") {
        const struct territory_symbol *s = find_sym(r, "alpha_reached");
        ASSERT(s != NULL);
        ASSERT_EQ((int)s->verdict, (int)TERRITORY_REACHED);
        ASSERT_EQ((int)s->reason, (int)TERRITORY_REASON_IN_CLOSURE);
        ASSERT_STR_EQ(s->header, "lib/base/include/base/alpha.h");
        PASS();
    }

    TEST("scorecard: a symbol nothing references is UNREACHED, not unknown") {
        const struct territory_symbol *s = find_sym(r, "alpha_dead");
        ASSERT(s != NULL);
        ASSERT_EQ((int)s->verdict, (int)TERRITORY_UNREACHED);
        ASSERT_EQ((int)s->reason, (int)TERRITORY_REASON_NO_REFS);
        ASSERT_EQ(s->refs, 0);
        PASS();
    }

    TEST("scorecard: a registry-row symbol is UNKNOWN, not folded either way") {
        const struct territory_symbol *s = find_sym(r, "alpha_dispatch_id");
        ASSERT(s != NULL);
        ASSERT_EQ((int)s->verdict, (int)TERRITORY_UNKNOWN);
        ASSERT_EQ((int)s->reason, (int)TERRITORY_REASON_FILE_SCOPE_REF);
        ASSERT(s->refs > 0);
        PASS();
    }

    TEST("scorecard: types and macros are counted apart from functions") {
        ASSERT_EQ(r->public_types, 1);   /* struct alpha_row */
        /* ALPHA_SLOT_MAX and the include guard FIX_ALPHA_H. The scanner does
         * not special-case an include guard, so the macro count is "#define
         * lines in the public headers", not "constants a caller may use".
         * Pinned at the real number rather than the flattering one: neither
         * is a callable symbol, which is the only reason both sit outside the
         * three reachability buckets. */
        ASSERT_EQ(r->public_macros, 3);  /* + the second include guard */
        PASS();
    }

    TEST("scorecard: an extern \"C\" header is counted, not read as empty") {
        /* beta_invisible is declared, but inside `extern \"C\" { … }`, so the
         * index attributes it to no file. The scorecard must not present that
         * as "this header has no public functions". */
        ASSERT(find_sym(r, "beta_invisible") == NULL);
        ASSERT_EQ(r->headers_without_functions, 1);
        ASSERT_EQ(r->headers_extern_c, 1);
        PASS();
    }

    TEST("scorecard: with no router, no file claims a routed group") {
        ASSERT_EQ(r->group_count, 0);
        ASSERT_EQ(r->files_unrouted, r->file_count);
        for (int i = 0; i < r->file_count; i++)
            ASSERT(!r->files[i].routed);
        PASS();
    }

    TEST("scorecard: an absent include graph is reported, not read as zero") {
        ASSERT(!r->deps_available);
        ASSERT_EQ(r->deps_out_count, 0);
        ASSERT_EQ(r->deps_in_count, 0);
        PASS();
    }

    territory_report_free(r);
    r = territory_scorecard(ci, TERR_FIX, "lib/base", NULL, NULL);
    ASSERT(r != NULL);

    TEST("no reached set: every verdict is UNKNOWN — a refusal, not a guess") {
        ASSERT_EQ(r->public_symbols, 3);
        ASSERT_EQ(r->reached, 0);
        ASSERT_EQ(r->unreached, 0);
        ASSERT_EQ(r->unknown, 3);
        for (int i = 0; i < r->public_symbols; i++) {
            ASSERT_EQ((int)r->symbols[i].verdict, (int)TERRITORY_UNKNOWN);
            ASSERT_EQ((int)r->symbols[i].reason,
                      (int)TERRITORY_REASON_WALK_TRUNCATED);
        }
        PASS();
    }

    territory_report_free(r);
    r = NULL;
    territory_reach_free(rs);
    rs = NULL;

    TEST("empty catalog: nothing is reached, and nothing pretends to be") {
        struct territory_reach_stats s2 = {0};
        struct territory_reach_set *empty =
            territory_reach_open(ci, NULL, &none, &s2);
        ASSERT(empty != NULL);
        ASSERT_EQ(territory_reach_count(empty), (size_t)0);
        ASSERT(!territory_reach_contains(empty, "alpha_reached"));
        struct territory_report *r2 =
            territory_scorecard(ci, TERR_FIX, "lib/base", empty, NULL);
        ASSERT(r2 != NULL);
        ASSERT_EQ(r2->reached, 0);
        ASSERT_EQ(r2->reached + r2->unreached + r2->unknown, r2->public_symbols);
        territory_report_free(r2);
        territory_reach_free(empty);
        PASS();
    }

    TEST("reach memo: a second open answers from the memo, byte-for-byte") {
        struct territory_reach_stats w = {0}, c = {0};
        struct territory_reach_set *walked =
            territory_reach_open(ci, TERR_FIX, &src, &w);
        ASSERT(walked != NULL);
        ASSERT_EQ(w.from_cache, false);
        ASSERT_EQ(w.cache_written, true);
        size_t walked_count = territory_reach_count(walked);
        territory_reach_free(walked);

        struct territory_reach_set *cached =
            territory_reach_open(ci, TERR_FIX, &src, &c);
        ASSERT(cached != NULL);
        ASSERT_EQ(c.from_cache, true);
        ASSERT_EQ(territory_reach_count(cached), walked_count);
        ASSERT(territory_reach_contains(cached, "alpha_reached"));
        ASSERT(!territory_reach_contains(cached, "alpha_dead"));
        territory_reach_free(cached);
        PASS();
    }

    TEST("reach memo: a corrupted memo is rejected, never served") {
        char path[4096];
        snprintf(path, sizeof(path), "%s/.codeindex/territory_reach.v1",
                 TERR_FIX);
        FILE *f = fopen(path, "r+b");
        ASSERT(f != NULL);
        /* Flip one byte of the payload, leaving the header's generation key
         * intact: only the payload digest can catch this. */
        if (fseek(f, 100, SEEK_SET) == 0) {
            int b = fgetc(f);
            if (b != EOF && fseek(f, 100, SEEK_SET) == 0)
                (void)fputc(b ^ 0xff, f);
        }
        fclose(f);
        struct territory_reach_stats c = {0};
        struct territory_reach_set *again =
            territory_reach_open(ci, TERR_FIX, &src, &c);
        ASSERT(again != NULL);
        ASSERT_EQ(c.from_cache, false);   /* rebuilt, not trusted */
        ASSERT(territory_reach_contains(again, "alpha_reached"));
        territory_reach_free(again);
        PASS();
    }

    TEST("labels: every verdict and reason has a distinct printable name") {
        ASSERT_STR_EQ(territory_reach_verdict_label(TERRITORY_REACHED),
                      "reached");
        ASSERT_STR_EQ(territory_reach_verdict_label(TERRITORY_UNREACHED),
                      "unreached");
        ASSERT_STR_EQ(territory_reach_verdict_label(TERRITORY_UNKNOWN),
                      "unknown");
        ASSERT_STR_EQ(
            territory_reach_reason_label(TERRITORY_REASON_FILE_SCOPE_REF),
            "file-scope-reference-only");
        ASSERT_STR_EQ(territory_reach_reason_label(TERRITORY_REASON_NO_REFS),
                      "no-reference-in-tree");
        PASS();
    }

    /* ── the general's brief ─────────────────────────────────────────── */

    gcount = territory_list(ci, gnames, 128);
    if (gcount < 0) gcount = 0;
    gates = territory_gates_open(TERR_FIX, gnames, gcount);
    struct territory_router frouter = { .route = fix_route, .user = NULL };

    TEST("gates: the wiring table is read from run_lint.sh's case rows") {
        ASSERT(gates != NULL);
        ASSERT(territory_gates_wiring_found(gates));
        ASSERT_EQ(territory_gates_total(gates), 3);
        /* The one baseline row the fixture declares, attributed to lib/base;
         * the comment line names no path and is not counted. */
        ASSERT_EQ(territory_gates_baseline_rows(gates), 1);
        ASSERT_EQ(territory_gates_baseline_unattributed(gates), 0);
        PASS();
    }

    b = territory_brief_build(ci, TERR_FIX, "lib/base", rs, &frouter, gates,
                              NULL);
    ASSERT(b != NULL);

    TEST("brief: binds + the two unknown buckets PARTITION the wired gates") {
        ASSERT(b->gate_wiring_found);
        ASSERT_EQ(b->gates_total, 3);
        ASSERT_EQ(b->gates_binding + b->gates_unknown_named_others +
                      b->gates_unknown_named_none,
                  b->gates_total);
        ASSERT_EQ(b->gates_binding, 1);                /* check-base-shape */
        ASSERT_EQ(b->gates_unknown_named_others, 1);   /* check-net-shape */
        ASSERT_EQ(b->gates_unknown_named_none, 1);     /* check-treewide */
        PASS();
    }

    TEST("brief: a binding gate is named with the evidence that bound it") {
        ASSERT_EQ(b->refusal_count, 1);
        ASSERT(!b->refusals_truncated);
        ASSERT_STR_EQ(b->refuses[0].gate, "check-base-shape");
        ASSERT(b->refuses[0].named_in_gate);
        ASSERT_EQ(b->refuses[0].baseline_rows, 1);
        PASS();
    }

    TEST("brief: trusts is REPORTED as unknown, never omitted or guessed") {
        ASSERT(b->report != NULL);
        ASSERT(b->report->group_count > 0);
        ASSERT_EQ(b->trust_reproducible, 0);
        ASSERT_EQ(b->trust_not_reproducible, 0);
        /* Every routed group, counted — the hole is the size of the evidence
         * it covers, not an empty field a reader would read as "fine". */
        ASSERT_EQ(b->trust_unknown, b->report->group_count);
        ASSERT(b->trust_source[0] != '\0');
        PASS();
    }

    TEST("brief: unproven is exactly unreached + unknown") {
        ASSERT_EQ(b->unproven, b->report->unreached + b->report->unknown);
        ASSERT_EQ(b->unrouted_files, b->report->files_unrouted);
        PASS();
    }

    TEST("brief: absent gate wiring reports unreadable, not zero gates") {
        struct territory_gates *none_g =
            territory_gates_open(TERR_FIX "/lib", gnames, gcount);
        ASSERT(none_g != NULL);
        ASSERT(!territory_gates_wiring_found(none_g));
        ASSERT_EQ(territory_gates_total(none_g), 0);
        struct territory_brief *nb =
            territory_brief_build(ci, TERR_FIX, "lib/base", rs, &frouter,
                                  none_g, NULL);
        ASSERT(nb != NULL);
        ASSERT(!nb->gate_wiring_found);
        ASSERT_EQ(nb->gates_total, 0);
        ASSERT_EQ(nb->gates_binding, 0);
        territory_brief_free(nb);
        territory_gates_free(none_g);
        PASS();
    }

    /* ── the roll-up ─────────────────────────────────────────────────── */

    TEST("rollup: ranked by unproven, and the totals equal the rows") {
        struct territory_rollup *u =
            territory_rollup_build(ci, NULL, rs, &frouter);
        ASSERT(u != NULL);
        ASSERT(u->count > 0);
        ASSERT_EQ(u->failed, 0);
        ASSERT_EQ(u->scored, u->count);
        int64_t files = 0, pub = 0, reached = 0, unreached = 0, unknown = 0;
        for (int i = 0; i < u->count; i++) {
            /* the rank key is non-increasing */
            if (i > 0) ASSERT(u->ranks[i - 1].unproven >= u->ranks[i].unproven);
            /* each row's own buckets partition its public surface */
            ASSERT_EQ(u->ranks[i].reached + u->ranks[i].unreached +
                          u->ranks[i].unknown,
                      u->ranks[i].public_symbols);
            ASSERT_EQ(u->ranks[i].unproven,
                      u->ranks[i].unreached + u->ranks[i].unknown);
            files     += u->ranks[i].files;
            pub       += u->ranks[i].public_symbols;
            reached   += u->ranks[i].reached;
            unreached += u->ranks[i].unreached;
            unknown   += u->ranks[i].unknown;
        }
        /* every printed total is the sum of printed rows, so a reader can
         * check it without trusting us */
        ASSERT_EQ(u->total_files, files);
        ASSERT_EQ(u->total_public, pub);
        ASSERT_EQ(u->total_reached, reached);
        ASSERT_EQ(u->total_unreached, unreached);
        ASSERT_EQ(u->total_unknown, unknown);
        ASSERT_EQ(u->total_public, reached + unreached + unknown);
        ASSERT_EQ(u->from_cache, false);   /* root=NULL: no memo at all */
        territory_rollup_free(u);
        PASS();
    }

    TEST("rollup memo: round-trips, and a corrupted memo is rebuilt not "
         "trusted") {
        struct territory_rollup *first =
            territory_rollup_build(ci, TERR_FIX, rs, &frouter);
        ASSERT(first != NULL);
        ASSERT_EQ(first->from_cache, false);
        ASSERT(first->cache_written);
        int64_t want_public = first->total_public;
        int want_count = first->count;
        territory_rollup_free(first);

        struct territory_rollup *again =
            territory_rollup_build(ci, TERR_FIX, rs, &frouter);
        ASSERT(again != NULL);
        ASSERT(again->from_cache);
        ASSERT_EQ(again->total_public, want_public);
        ASSERT_EQ(again->count, want_count);
        territory_rollup_free(again);

        FILE *f = fopen(TERR_FIX "/.codeindex/territory_rollup.v1", "r+b");
        ASSERT(f != NULL);
        if (fseek(f, 96, SEEK_SET) == 0) {
            int by = fgetc(f);
            if (by != EOF && fseek(f, 96, SEEK_SET) == 0)
                (void)fputc(by ^ 0xff, f);
        }
        fclose(f);
        struct territory_rollup *third =
            territory_rollup_build(ci, TERR_FIX, rs, &frouter);
        ASSERT(third != NULL);
        ASSERT_EQ(third->from_cache, false);   /* digest refused it */
        ASSERT_EQ(third->total_public, want_public);
        territory_rollup_free(third);
        PASS();
    }

    TEST("trust labels: each state has its own printable name") {
        ASSERT_STR_EQ(territory_trust_label(TERRITORY_TRUST_UNKNOWN),
                      "unknown");
        ASSERT_STR_EQ(territory_trust_label(TERRITORY_TRUST_REPRODUCIBLE),
                      "reproducible");
        ASSERT_STR_EQ(territory_trust_label(TERRITORY_TRUST_NOT_REPRODUCIBLE),
                      "not-reproducible");
        PASS();
    }

_test_next:;
    territory_brief_free(b);
    territory_gates_free(gates);
    territory_report_free(r);
    territory_reach_free(rs);
    if (ci) codeindex_close(ci);
    test_rm_rf(TERR_FIX);

    if (failures == 0)
        printf("test_territory: all passed\n");
    else
        printf("test_territory: %d FAILED\n", failures);
    return failures;
}
