/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftest of check-cyclomatic-complexity. Proves the metric (the
 * decision points, the preprocessor branch structure, the literal and comment
 * skipping) and the ratchet semantics (exact pins, growth, retired and stale
 * pins, --tighten-baseline, --write-baseline) against fixtures under a private
 * scratch directory. The gate itself lives in gate_function_complexity.c and
 * shares its scanner and ratchet through gate_function_complexity_priv.h.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_function_complexity_priv.h"

/* ── selftest ──────────────────────────────────────────────────────────── */

struct cyc_st_acc {
    char name[32][CYC_NAME];
    int m[32];
    int n;
};

static int cyc_st_collect(const char *path, const char *name, int line,
                          int m, void *ctx)
{
    struct cyc_st_acc *a = ctx;
    (void)path;
    (void)line;
    if (a->n >= 32 || strlen(name) >= CYC_NAME)
        return die("z23-lint: selftest overflow\n", "");
    memcpy(a->name[a->n], name, strlen(name) + 1);
    a->m[a->n] = m;
    a->n++;
    return 0;
}

/* Scan text; want exactly one function named `name` with metric `m`. */
static int cyc_st_one(const char *text, const char *name, int m)
{
    struct cyc_st_acc a;
    memset(&a, 0, sizeof a);
    if (cyc_scan_text(text, "st.c", cyc_st_collect, &a))
        return 1;
    if (a.n != 1 || strcmp(a.name[0], name) != 0 || a.m[0] != m) {
        fprintf(stderr, "check_cyclomatic_complexity selftest: want %s M=%d, "
                "got n=%d%s\n", name, m, a.n,
                a.n ? "" : " (no function found)");
        return 1;
    }
    return 0;
}

/* Scan text; want exactly two functions, in order, with those metrics. */
static int cyc_st_two(const char *text, const char *n1, int m1,
                      const char *n2, int m2)
{
    struct cyc_st_acc a;
    memset(&a, 0, sizeof a);
    if (cyc_scan_text(text, "st.c", cyc_st_collect, &a))
        return 1;
    if (a.n != 2 || strcmp(a.name[0], n1) != 0 || a.m[0] != m1
        || strcmp(a.name[1], n2) != 0 || a.m[1] != m2) {
        fprintf(stderr, "check_cyclomatic_complexity selftest: want %s M=%d "
                "then %s M=%d, got n=%d (first %s M=%d)\n", n1, m1, n2, m2,
                a.n, a.n ? a.name[0] : "-", a.n ? a.m[0] : 0);
        return 1;
    }
    return 0;
}

static int cyc_st_none(const char *text)
{
    struct cyc_st_acc a;
    memset(&a, 0, sizeof a);
    if (cyc_scan_text(text, "st.c", cyc_st_collect, &a))
        return 1;
    if (a.n != 0) {
        fprintf(stderr, "check_cyclomatic_complexity selftest: want no "
                "function, got %s\n", a.name[0]);
        return 1;
    }
    return 0;
}

/* && and || count once, and only when the two characters are adjacent. */
static int cyc_st_logic_ops(void)
{
    int bad = 0;
    /* address-of and bitwise & never pair: one decision here, the if */
    bad |= cyc_st_one("int amp_addr(int a, int b)\n{\n"
                      "    f(&a);\n"
                      "    g(&a, &b);\n"
                      "    if (a & b) {\n        return 1;\n    }\n"
                      "    return 0;\n}\n", "amp_addr", 2);
    /* a real && is one decision on top of the if */
    bad |= cyc_st_one("int amp_and(int a, int b)\n{\n"
                      "    if (a && b)\n        return 1;\n"
                      "    return 0;\n}\n", "amp_and", 3);
    /* bitwise | never pairs with a later ||; the || is one decision */
    bad |= cyc_st_one("int bar_or(int p, int q, int c, int d)\n{\n"
                      "    int x = p | q;\n"
                      "    if (c || d)\n        return x;\n"
                      "    return 0;\n}\n", "bar_or", 3);
    /* &=, |=, &&= and ||= are not decisions */
    bad |= cyc_st_one("int assign_ops(int a, int b)\n{\n"
                      "    a &= b;\n    a |= b;\n"
                      "    return a;\n}\n", "assign_ops", 1);
    return bad;
}

/* Every branch of a preprocessor conditional is counted; only the brace and
 * paren structure comes from the first branch. */
static int cyc_st_pp_cond(void)
{
    int bad = 0;
    /* branches that each open a brace would desynchronise the depth and
     * swallow every later function; the decisions in both branches count,
     * and the if after the #endif belongs to the function it is written in */
    bad |= cyc_st_two("int split_brace(int x)\n{\n"
                      "#if ZCL_ALT\n"
                      "    if (x > 0) {\n"
                      "#else\n"
                      "    if (x < 0) {\n"
                      "#endif\n"
                      "        x++;\n"
                      "    }\n"
                      "    if (x > 5)\n        x = 5;\n"
                      "    return x;\n}\n"
                      "int after_region(int y)\n{\n"
                      "    if (y)\n        return 1;\n"
                      "    return 0;\n}\n",
                      "split_brace", 4, "after_region", 2);
    /* #if inside #if, in both the first and a later branch: the region
     * stack pairs each #endif with its own opener */
    bad |= cyc_st_two("int nest(int x)\n{\n"
                      "#if A\n"
                      "#if B\n"
                      "    if (x) x++;\n"
                      "#endif\n"
                      "    if (x) x--;\n"
                      "#else\n"
                      "#if C\n"
                      "    if (x) x += 2;\n"
                      "#endif\n"
                      "    if (x) x += 3;\n"
                      "#endif\n"
                      "    return x;\n}\n"
                      "int tail(int y) { if (y) return 1; return 0; }\n",
                      "nest", 5, "tail", 2);
    /* an #elif chain: every arm is measured, the last arm restores the
     * first arm's structure, and the next function is still found */
    bad |= cyc_st_two("int elifs(int x)\n{\n"
                      "#if A\n"
                      "    if (x) x += 1;\n"
                      "#elif B\n"
                      "    if (x) x += 2;\n"
                      "#elifdef C\n"
                      "    if (x) x += 3;\n"
                      "#else\n"
                      "    if (x) x += 4;\n"
                      "#endif\n"
                      "    return x;\n}\n"
                      "int elif_tail(int y) { if (y) return 1; return 0; }\n",
                      "elifs", 5, "elif_tail", 2);
    /* #ifndef with no #else at all: the single branch is the structure */
    bad |= cyc_st_two("int noelse(int x)\n{\n"
                      "#ifndef ZCL_ALT\n"
                      "    if (x) x++;\n"
                      "#endif\n"
                      "    if (x) x--;\n"
                      "    return x;\n}\n"
                      "int noelse_tail(int y) { if (y) return 1; "
                      "return 0; }\n",
                      "noelse", 3, "noelse_tail", 2);
    /* the #else definition of a name is a second definition, keyed name#2 */
    bad |= cyc_st_two("#ifdef ZCL_ALT\n"
                      "int dup_fn(int x) { return x ? 1 : 0; }\n"
                      "#else\n"
                      "int dup_fn(int x) { if (x) return x ? 1 : 0; "
                      "return 0; }\n"
                      "#endif\n", "dup_fn", 2, "dup_fn#2", 3);
    /* a name defined twice outside any conditional still keys as name#2 */
    bad |= cyc_st_two("int twice(int x) { return x ? 1 : 0; }\n"
                      "int twice(int x) { if (x) return 1; return 0; }\n",
                      "twice", 2, "twice#2", 2);
    return bad;
}

/* A `#endif` inside a block comment, a line comment, or a continued string
 * literal is not a directive: honouring one would close the region early,
 * leave the later braces unpaired, and swallow the next function. */
static int cyc_st_pp_hidden(void)
{
    return cyc_st_two("int cmt_pp(int x)\n{\n"
                      "#if ZCL_ALT\n"
                      "    /* #endif */\n"
                      "    /*\n"
                      "#endif\n"
                      "     */\n"
                      "    // #endif\n"
                      "    const char *s = \"\\\n"
                      "#endif\\\n"
                      "\";\n"
                      "    if (x) {\n"
                      "#else\n"
                      "    if (x) {\n"
                      "#endif\n"
                      "        x++;\n"
                      "    }\n"
                      "    return (int)s[x];\n}\n"
                      "int cmt_tail(int y)\n{\n"
                      "    if (y)\n        return 1;\n"
                      "    return 0;\n}\n",
                      "cmt_pp", 3, "cmt_tail", 2);
}

/* Branches that do not end at the same depth have no single structure to
 * resume from. The gate refuses the file instead of silently attributing
 * every later function to this one. */
static int cyc_st_pp_desync(void)
{
    struct cyc_st_acc a;
    memset(&a, 0, sizeof a);
    fputs("check_cyclomatic_complexity selftest: the next z23-lint line is "
          "expected\n", stderr);
    if (cyc_scan_text("int lopsided(int x)\n{\n"
                      "#if ZCL_WIN\n"
                      "    if (x) {\n"
                      "    return 1;\n"
                      "#else\n"
                      "    if (x) { return 2; }\n"
                      "#endif\n"
                      "    return 0;\n}\n"
                      "int swallowed(int y)\n{\n"
                      "    if (y)\n        return 1;\n"
                      "    return 0;\n}\n",
                      "st.c", cyc_st_collect, &a))
        return 0;
    fputs("check_cyclomatic_complexity selftest: unbalanced preprocessor "
          "branches were not refused\n", stderr);
    return 1;
}

/* CRLF must preserve the same macro/comment splices and decisions as LF. */
static int cyc_st_pp_splice(void)
{
    static const char text[] =
        "#if ENABLED\n"
        "int splice(int x)\n{\n"
        "#define BODY do { \\\n"
        "    if (x) { } \\\n"
        "} while (0)\n"
        "    // continued comment \\\n"
        "    if (x) return 99;\n"
        "    if (x) return 1;\n"
        "    return 0;\n}\n"
        "#else\n#define UNAVAILABLE 1\n#endif\n"
        "int splice_tail(int y) { if (y) return 1; return 0; }\n";
    char crlf[2 * sizeof text];
    size_t j = 0;
    for (size_t i = 0; i < sizeof text - 1; i++) {
        if (text[i] == '\n')
            crlf[j++] = '\r';
        crlf[j++] = text[i];
    }
    crlf[j] = '\0';
    return cyc_st_two(text, "splice", 2, "splice_tail", 2)
        | cyc_st_two(crlf, "splice", 2, "splice_tail", 2);
}

static int cyc_st_metric(void)
{
    int bad = cyc_st_logic_ops() | cyc_st_pp_cond() | cyc_st_pp_hidden()
        | cyc_st_pp_desync() | cyc_st_pp_splice();
    /* exactly at the cap passes the cap: 14 decision points -> M=15 */
    bad |= cyc_st_one("int cap15(int x)\n{\n"
                      "    int r = 0;\n"
                      "    if (x > 0) r++;\n    if (x > 1) r++;\n"
                      "    if (x > 2) r++;\n    if (x > 3) r++;\n"
                      "    if (x > 4) r++;\n    if (x > 5) r++;\n"
                      "    if (x > 6) r++;\n    if (x > 7) r++;\n"
                      "    if (x > 8) r++;\n    if (x > 9) r++;\n"
                      "    if (x > 10) r++;\n   if (x > 11) r++;\n"
                      "    if (x > 12) r++;\n   if (x > 13) r++;\n"
                      "    return r;\n}\n", "cap15", 15);
    /* one more decision point -> M=16 */
    bad |= cyc_st_one("int cap16(int x)\n{\n"
                      "    int r = 0;\n"
                      "    if (x > 0) r++;\n    if (x > 1) r++;\n"
                      "    if (x > 2) r++;\n    if (x > 3) r++;\n"
                      "    if (x > 4) r++;\n    if (x > 5) r++;\n"
                      "    if (x > 6) r++;\n    if (x > 7) r++;\n"
                      "    if (x > 8) r++;\n    if (x > 9) r++;\n"
                      "    if (x > 10) r++;\n   if (x > 11) r++;\n"
                      "    if (x > 12) r++;\n   if (x > 13) r++;\n"
                      "    if (x > 14) r++;\n   return r;\n}\n", "cap16", 16);
    /* each of &&, ||, ?, case adds exactly one; else/default/switch none */
    bad |= cyc_st_one("int ops(int a, int b)\n{\n"
                      "    switch (a) {\n"
                      "    case 1:\n"
                      "        return a && b ? 2 : 3;\n"
                      "    default:\n"
                      "        return a || b;\n"
                      "    }\n}\n", "ops", 5);
    bad |= cyc_st_one("int loops(int x)\n{\n"
                      "    for (int i = 0; i < x; i++) {\n"
                      "        while (x > 3)\n"
                      "            x--;\n"
                      "    }\n"
                      "    if (x)\n"
                      "        return 1;\n"
                      "    else\n"
                      "        return 0;\n}\n", "loops", 4);
    /* keywords inside string/char literals and both comment kinds hide */
    bad |= cyc_st_one("int hidden(void)\n{\n"
                      "    const char *s = \"if (x) && y ? z : case 1\";\n"
                      "    const char *q = \"quote \\\" if (y)\";\n"
                      "    char c = '?';\n"
                      "    // if (a) || b ? c : d, case 9:\n"
                      "    /* for (;;) while (1) case 7: && || ? */\n"
                      "    return s[0] == c && q[0] != c;\n}\n",
                      "hidden", 2);
    /* multi-line parameter list, attribute between return type and name */
    bad |= cyc_st_one("static ZCL_MUST_USE int\n"
                      "multi_line(\n"
                      "    int a,\n"
                      "    int b)\n"
                      "{\n"
                      "    return a + b;\n}\n", "multi_line", 1);
    bad |= cyc_st_one("static inline int inl(int x) { return x ? x : 0; }\n",
                      "inl", 2);
    /* prototypes, calls, struct/enum definitions, and initializers open
     * no body */
    bad |= cyc_st_none("int proto(int x);\n"
                       "extern int ext_fn(int);\n"
                       "struct point { int x; int y; };\n"
                       "struct point g_origin = { .x = 0, .y = 0 };\n"
                       "enum { RED, GREEN };\n"
                       "int arr[3] = { 1, 2, 3 };\n");
    bad |= cyc_st_none("typedef int (*cmp_fn)(const void *, const void *);\n");
    return bad;
}

static const char k_cyc_st_fn[] =
    "int over_cap(int x)\n"
    "{\n"
    "    int r = 0;\n"
    "    if (x > 0) r++;\n    if (x > 1) r++;\n"
    "    if (x > 2) r++;\n    if (x > 3) r++;\n"
    "    if (x > 4) r++;\n    if (x > 5) r++;\n"
    "    if (x > 6) r++;\n    if (x > 7) r++;\n"
    "    if (x > 8) r++;\n    if (x > 9) r++;\n"
    "    if (x > 10) r++;\n   if (x > 11) r++;\n"
    "    if (x > 12) r++;\n   if (x > 13) r++;\n"
    "    if (x > 14) r++;\n   return r;\n"
    "}\n"
    "int calm(int x)\n"
    "{\n"
    "    return x + 1;\n"
    "}\n";

/* One gate run captured: the return code and both streams. */
struct cyc_st_run {
    int rc;
    char out[8192];
    char err[8192];
};

static int cyc_st_base_path(const char *root, char *bpath, size_t cap)
{
    return ovf(snprintf(bpath, cap, "%s/baseline.txt", root), cap);
}

/* Write base_body as the fixture baseline and run the gate once against the
 * fixture, optionally with --tighten-baseline semantics. */
static int cyc_st_exec(const char *root, const char *base_body,
                       const char *mode, int tighten, struct cyc_st_run *r)
{
    char bpath[8192];
    if (cyc_st_base_path(root, bpath, sizeof bpath)
        || csr_write(bpath, base_body))
        return 1;
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        return 1;
    }
    r->rc = cyc_check(root, bpath, mode, 0, tighten, out, err);
    int bad = csr_slurp(out, r->out, sizeof r->out)
        || csr_slurp(err, r->err, sizeof r->err);
    fclose(out);
    fclose(err);
    return bad;
}

/* Pass when the run returned want_rc and needle (NULL: any text) appears on
 * stdout or stderr. */
static int cyc_st_want(const struct cyc_st_run *r, const char *what,
                       int want_rc, const char *needle)
{
    if (r->rc == want_rc
        && (!needle || strstr(r->out, needle) || strstr(r->err, needle)))
        return 0;
    fprintf(stderr, "check_cyclomatic_complexity selftest: %s want rc %d "
            "needle '%s'; got rc %d and:\n%s%s\n", what, want_rc,
            needle ? needle : "(none)", r->rc, r->out, r->err);
    return 1;
}

/* Run the check against the fixture with the given baseline body; assert
 * the return code and (when needle non-NULL) that the output names it. */
static int cyc_st_case(const char *root, const char *base_body,
                       const char *mode, int want_rc, const char *needle)
{
    struct cyc_st_run r;
    if (cyc_st_exec(root, base_body, mode, 0, &r))
        return 1;
    return cyc_st_want(&r, mode, want_rc, needle);
}

/* Read the fixture baseline back into buf. */
static int cyc_st_read_base(const char *root, char *buf, size_t cap)
{
    char bpath[8192];
    if (cyc_st_base_path(root, bpath, sizeof bpath))
        return 1;
    FILE *f = fopen(bpath, "r");
    if (!f)
        return 1;
    int bad = csr_slurp(f, buf, cap);
    fclose(f);
    return bad;
}

/* Run --tighten-baseline against base_body and assert: the return code, the
 * counts line, the reason text (NULL: none), and that the rewritten file is
 * exactly the generated header followed by rows. */
static int cyc_st_tighten(const char *root, const char *base_body,
                          int want_rc, const char *reason,
                          const char *counts, const char *rows)
{
    struct cyc_st_run r;
    char want[8192], got[8192];
    if (cyc_st_exec(root, base_body, "RATCHET", 1, &r))
        return 1;
    int bad = cyc_st_want(&r, "tighten", want_rc, counts);
    if (!bad && reason && !strstr(r.out, reason) && !strstr(r.err, reason)) {
        fprintf(stderr, "check_cyclomatic_complexity selftest: tighten "
                "missing reason '%s'\n", reason);
        bad = 1;
    }
    if (bad)
        return 1;
    if (ovf(snprintf(want, sizeof want, "%s%s", k_cyc_base_hdr, rows),
            sizeof want))
        return 1;
    if (cyc_st_read_base(root, got, sizeof got) || strcmp(got, want) != 0) {
        fprintf(stderr, "check_cyclomatic_complexity selftest: tighten "
                "rewrote the baseline wrongly:\n%s\n", got);
        return 1;
    }
    return 0;
}

/* A second tighten over its own output changes nothing: same counts, and
 * the file is byte-identical. */
static int cyc_st_tighten_twice(const char *root)
{
    struct cyc_st_run r;
    char first[8192], second[8192];
    if (cyc_st_exec(root, "case.c:over_cap:17\n", "RATCHET", 1, &r)
        || cyc_st_read_base(root, first, sizeof first))
        return 1;
    if (cyc_st_exec(root, first, "RATCHET", 1, &r)
        || cyc_st_want(&r, "tighten again", 0, "lowered=0 deleted=0 kept=1")
        || cyc_st_read_base(root, second, sizeof second))
        return 1;
    if (strcmp(first, second) != 0) {
        fputs("check_cyclomatic_complexity selftest: second tighten changed "
              "the baseline\n", stderr);
        return 1;
    }
    return 0;
}

/* --write-baseline regenerates exact pins: verify the generated file pins
 * the over-cap fixture function, excludes the under-cap one, and passes the
 * gate unchanged. */
static int cyc_st_writeback(const char *root)
{
    char wb[8192];
    if (ovf(snprintf(wb, sizeof wb, "%s/gen_baseline.txt", root), sizeof wb))
        return 1;
    if (cyc_write_baseline(root, wb))
        return 1;
    FILE *g = fopen(wb, "r");
    char body[8192];
    if (!g || csr_slurp(g, body, sizeof body)) {
        if (g)
            fclose(g);
        return 1;
    }
    fclose(g);
    if (strstr(body, "case.c:over_cap:16\n") == NULL
        || strstr(body, "calm") != NULL) {
        fputs("check_cyclomatic_complexity selftest: generated baseline "
              "content wrong\n", stderr);
        return 1;
    }
    FILE *out = tmpfile(), *err = tmpfile();
    int bad = !out || !err
        || cyc_check(root, wb, "RATCHET", 0, 0, out, err);
    if (bad)
        fputs("check_cyclomatic_complexity selftest: generated baseline "
              "did not pass\n", stderr);
    if (out)
        fclose(out);
    if (err)
        fclose(err);
    return bad;
}

int check_cyclomatic_complexity_selftest(void)
{
    int bad = cyc_st_metric();
    const char *td = env_or("TMPDIR", cyc_tmp_default);
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-cyc-XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    char src[8192];
    if (ovf(snprintf(src, sizeof src, "%s/case.c", root), sizeof src))
        bad = 1;
    else if (csr_write(src, k_cyc_st_fn))
        bad = 1;
    if (!bad) {
        /* exact pin passes */
        bad |= cyc_st_case(root, "case.c:over_cap:16\n", "RATCHET", 0, NULL);
        /* an unpinned over-cap function fails as new complexity */
        bad |= cyc_st_case(root, "", "RATCHET", 1, "not pinned");
        /* a pin below the current M fails as growth */
        bad |= cyc_st_case(root, "case.c:over_cap:15\n", "RATCHET", 1,
                           "grew M=15 -> M=16");
        /* a pin above the current M passes with a note; tighten lowers it */
        bad |= cyc_st_case(root, "case.c:over_cap:17\n", "RATCHET", 0,
                           "shrank M=17 -> M=16");
        /* a pin for a function now within the cap fails as retired, so it
         * cannot regrow under the old line */
        bad |= cyc_st_case(root, "case.c:over_cap:16\ncase.c:calm:3\n",
                           "RATCHET", 1,
                           "now within the cap (M=1 <= 15); delete the "
                           "baseline line");
        /* tighten: a shrunk pin is lowered to the current M */
        bad |= cyc_st_tighten(root, "case.c:over_cap:17\n", 0, NULL,
                              "lowered=1 deleted=0 kept=0",
                              "case.c:over_cap:16\n");
        /* tighten: a pin for a missing function is deleted */
        bad |= cyc_st_tighten(root, "case.c:over_cap:16\ncase.c:ghost:20\n",
                              0, NULL, "lowered=0 deleted=1 kept=1",
                              "case.c:over_cap:16\n");
        /* tighten: a pin for a function within the cap is deleted */
        bad |= cyc_st_tighten(root, "case.c:over_cap:16\ncase.c:calm:3\n",
                              0, NULL, "lowered=0 deleted=1 kept=1",
                              "case.c:over_cap:16\n");
        /* tighten never raises a pin: a 15 pin on M=16 is kept and the gate
         * still fails as growth */
        bad |= cyc_st_tighten(root, "case.c:over_cap:15\n", 1,
                              "grew M=15 -> M=16", "lowered=0 deleted=0 kept=1",
                              "case.c:over_cap:15\n");
        /* tighten never adds a row: an unpinned over-cap function stays
         * unpinned and still fails */
        bad |= cyc_st_tighten(root, "", 1, "not pinned",
                              "lowered=0 deleted=0 kept=0", "");
        bad |= cyc_st_tighten_twice(root);
        /* a pin for a missing function fails as stale */
        bad |= cyc_st_case(root, "case.c:over_cap:16\ncase.c:ghost:20\n",
                           "RATCHET", 1, "stale baseline, delete the line");
        /* a duplicated baseline row fails closed at load */
        bad |= cyc_st_case(root, "case.c:over_cap:16\ncase.c:over_cap:16\n",
                           "RATCHET", 2, "duplicate baseline entry");
        /* a row without :M fails closed at load */
        bad |= cyc_st_case(root, "case.c:over_cap\n", "RATCHET", 2,
                           "malformed baseline M in line");
        /* WARN reports but exits 0 */
        bad |= cyc_st_case(root, "", "WARN", 0, "not pinned");
        /* FAIL mode trips even an exactly pinned function */
        bad |= cyc_st_case(root, "case.c:over_cap:16\n", "FAIL", 1,
                           "baseline ignored");
        bad |= cyc_st_writeback(root);
    }
    (void)rap_rm_rf(root);
    return st_ok(bad, "check_cyclomatic_complexity selftest: OK\n");
}
