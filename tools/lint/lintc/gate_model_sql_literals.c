/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-model-sql-literals of the C23 lint runtime,
 * the replacement for tools/lint/check_model_sql_literals.sh. A model file
 * must not carry a hand-written SQL statement (reads/writes build one with
 * engine/models/include/models/query_builder.h); every file still holding a
 * literal is pinned as a "path" row (not a "key:M" ratchet) in
 * tools/lint/model_sql_literal_baseline.txt via the shared bln_* shrink-only
 * baseline API (lintc.h). No file-scope mutable state — every helper takes
 * its context as an explicit parameter. Selftest lives in the sibling
 * gate_model_sql_literals_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"

static const char k_msl_baseline_default[] = "tools/lint/model_sql_literal_baseline.txt";
static const char k_msl_gate[] = "check_model_sql_literals";
enum { MSL_FLOOR_DEFAULT = 80, MSL_LINE = 8192 };

/* The builder itself, by path suffix — it emits these keywords by
 * construction and would be unfixable if flagged for its own output. */
static int msl_is_the_rail(const char *path)
{
    static const char *const rail[] = {
        "/query_builder.c", "/query_builder.h", "/query_schema.def"
    };
    size_t pl = strlen(path);
    for (size_t i = 0; i < sizeof rail / sizeof rail[0]; i++) {
        size_t rl = strlen(rail[i]);
        if (pl >= rl && strcmp(path + pl - rl, rail[i]) == 0)
            return 1;
    }
    return 0;
}

/* Line-preserving comment stripper: blank out // and block comments, keep
 * string/char literal bodies VERBATIM (a literal is exactly the evidence
 * this gate looks for), same contract as tools/lint/strip_c_comments.awk
 * with strings=0. *in_block persists across calls for one file (a block
 * comment can span lines); reset to 0 per file. */
static void msl_strip_line(int *in_block, const char *line, char *out, size_t cap)
{
    size_t i = 0, o = 0, n = strlen(line);
    while (i < n && o + 1 < cap) {
        if (*in_block) {
            if (line[i] == '*' && i + 1 < n && line[i + 1] == '/') {
                *in_block = 0;
                i += 2;
                out[o++] = ' ';
            } else {
                i++;
            }
            continue;
        }
        if (line[i] == '/' && i + 1 < n && line[i + 1] == '*') {
            *in_block = 1;
            i += 2;
            out[o++] = ' ';
            continue;
        }
        if (line[i] == '/' && i + 1 < n && line[i + 1] == '/') {
            out[o++] = ' ';
            break;
        }
        if (line[i] == '"' || line[i] == '\'') {
            char q = line[i];
            out[o++] = line[i++];
            while (i < n && o + 1 < cap) {
                if (line[i] == '\\' && i + 1 < n && o + 2 < cap) {
                    out[o++] = line[i];
                    out[o++] = line[i + 1];
                    i += 2;
                    continue;
                }
                out[o++] = line[i];
                if (line[i] == q) { i++; break; }
                i++;
            }
            continue;
        }
        out[o++] = line[i++];
    }
    out[o] = '\0';
}

/* A string literal whose first non-space token opens a SQL statement:
 * '"' [:space:]* (SELECT|INSERT|UPDATE|DELETE|REPLACE|WITH|CREATE|ALTER|
 * DROP|PRAGMA) [:space:] — the exact RE_SQL_LITERAL from the shell gate. */
static int msl_re_compile(regex_t *re)
{
    return compile_pat(re, REG_EXTENDED,
                       "\"[[:space:]]*(SELECT|INSERT|UPDATE|DELETE|REPLACE|"
                       "WITH|CREATE|ALTER|DROP|PRAGMA)[[:space:]]", "", "", "");
}

/* Reads path with comments stripped (literals verbatim) and reports whether
 * any line opens a SQL statement literal. Returns 0 ok (*hit set), -1 on a
 * permission-denied/unreadable file (caller reports UNPROVEN and names the
 * path), or a positive die()'d rc on a harder failure. */
static int msl_scan_one(const char *path, const regex_t *re, int *hit)
{
    *hit = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return errno == EACCES ? -1 : die("z23-lint: cannot open %s\n", path);
    char *raw = NULL;
    size_t cap = 0;
    ssize_t n;
    int in_block = 0, rc = 0;
    while (rc == 0 && !*hit && (n = getline(&raw, &cap, f)) >= 0) {
        if (n > 0 && raw[n - 1] == '\n') raw[--n] = '\0';
        char stripped[MSL_LINE];
        msl_strip_line(&in_block, raw, stripped, sizeof stripped);
        if (regexec(re, stripped, 0, NULL, 0) == 0)
            *hit = 1;
    }
    rc = fin(f, raw, path, rc);
    return rc;
}

struct msl_walk {
    const regex_t *re;
    struct bln_set *found;
    int total;   /* every .c/.h/.def under the model rooms, rail included */
    int kept;    /* the above minus the rail */
    int unreadable_rc;
    char unreadable_path[4096];
};

static int msl_visit(const char *path, void *vctx)
{
    struct msl_walk *w = vctx;
    w->total++;
    if (msl_is_the_rail(path))
        return 0;
    w->kept++;
    int hit = 0;
    int rc = msl_scan_one(path, w->re, &hit);
    if (rc == -1) {
        w->unreadable_rc = 2;
        if (ovf(snprintf(w->unreadable_path, sizeof w->unreadable_path, "%s",
                         path), sizeof w->unreadable_path))
            return 2;
        return 1; /* stop the walk; caller checks unreadable_rc */
    }
    if (rc)
        return rc;
    return hit ? bln_add(w->found, path) : 0;
}

static int msl_walk_roots(const char *const roots[], int nroots, int hdrs,
                          struct msl_walk *w)
{
    int rc = 0;
    for (int i = 0; rc == 0 && i < nroots; i++)
        rc = walk_src(roots[i], hdrs, msl_visit, w);
    return rc;
}

static int msl_resolve_roots(char roots[][RS_PATH], int max, int *n)
{
    const char *ov = env_or("ZCL_MODEL_SQL_SCAN_ROOT", "");
    if (ov[0]) {
        if (ovf(snprintf(roots[0], RS_PATH, "%s", ov), RS_PATH))
            return 2;
        *n = 1;
        return 0;
    }
    return repo_shape_room_dirs("models", roots, max, n);
}

static int msl_floor(void)
{
    const char *e = getenv("ZCL_MODEL_SQL_FILE_FLOOR");
    return (e && e[0]) ? atoi(e) : MSL_FLOOR_DEFAULT;
}

static int msl_check_roots_exist(char roots[][RS_PATH], int n)
{
    for (int i = 0; i < n; i++) {
        struct stat st;
        if (stat(roots[i], &st) != 0) {
            fprintf(stderr, "%s: FATAL — scan root '%s' does not exist\n",
                   k_msl_gate, roots[i]);
            return 2;
        }
    }
    return 0;
}

/* One pass over the roots for BOTH extension classes (.c/.h via hdrs=1,
 * .def via hdrs=2 — walk_src's own two match modes; see lib.c
 * walk_src_match). Mirrors the shell gate's single `find ... -name '*.c'
 * -o -name '*.h' -o -name '*.def'`. */
static int msl_scan_all(char roots[][RS_PATH], int n, const regex_t *re,
                        struct msl_walk *w)
{
    static const char *rootp[RS_MAX];
    for (int i = 0; i < n; i++) rootp[i] = roots[i];
    w->re = re;
    w->total = 0;
    w->kept = 0;
    w->unreadable_rc = 0;
    int rc = msl_walk_roots(rootp, n, 1, w);
    if (rc == 0 && !w->unreadable_rc)
        rc = msl_walk_roots(rootp, n, 2, w);
    return rc;
}

static int msl_report_unreadable(const struct msl_walk *w)
{
    fprintf(stderr, "[%s] UNPROVEN — %s exists but is not readable; "
           "refusing to report a clean scan\n", k_msl_gate, w->unreadable_path);
    return 2;
}

static const char k_msl_fix_hint[] =
    "\n  Build the statement instead — models/query_builder.h:\n"
    "    qb_select(&q, QB_T_<table>);  qb_select_columns(&q, cols, n);\n"
    "    qb_where_int/_text/_blob(&q, QB_C_<table>_<col>, QB_EQ, v);\n"
    "    qb_order_by(&q, col, QB_DESC);  qb_limit(&q, n);\n"
    "    QB_QUERY_LIST(ndb, &q, s, out, max, row_reader(s, &out[count]));\n"
    "  Identifiers come from engine/models/include/models/query_schema.def\n"
    "  (add the table there first); values are bound, never pasted.\n";

static int msl_report(FILE *out, const struct bln_set *base,
                      const struct bln_set *found, const char *baseline_path,
                      const char *mode, int total)
{
    static struct bln_set newc, stale;
    newc.count = 0;
    stale.count = 0;
    int rc = 0;
    for (int i = 0; rc == 0 && i < found->count; i++)
        if (!bln_has(base, found->n[i]))
            rc = bln_add(&newc, found->n[i]);
    for (int i = 0; rc == 0 && i < base->count; i++)
        if (!bln_has(found, base->n[i]))
            rc = bln_add(&stale, base->n[i]);
    if (rc)
        return rc;
    if (newc.count == 0 && stale.count == 0) {
        return fprintf(out, "[%s] PASS (%d model files scanned, %d still "
                       "carrying literal SQL, all %d baselined)\n", k_msl_gate,
                       total, found->count, base->count) < 0
            ? die("z23-lint: write failed\n", "") : 0;
    }
    if (newc.count > 0) {
        fprintf(out, "\n[%s] %d model file(s) carry a hand-written SQL "
               "statement and are not in the shrink-only baseline:\n",
               k_msl_gate, newc.count);
        for (int i = 0; i < newc.count; i++)
            fprintf(out, "  %s\n", newc.n[i]);
        fputs(k_msl_fix_hint, out);
        fprintf(out, "  Adding a row to %s is NOT a fix; the list may only "
               "shrink.\n", baseline_path);
    }
    if (stale.count > 0) {
        fprintf(out, "\n[%s] %d STALE baseline row(s) — the file no longer "
               "carries literal SQL. Delete them from %s:\n", k_msl_gate,
               stale.count, baseline_path);
        for (int i = 0; i < stale.count; i++)
            fprintf(out, "  %s\n", stale.n[i]);
        fputs("\n  Leaving a converted file listed would let it silently "
             "regress.\n", out);
    }
    return strcmp(mode, "FAIL") == 0 ? 1 : 0;
}

static const char k_msl_update_header[] =
    "# check_model_sql_literals baseline — model files that still carry a "
    "hand-written\n"
    "# SQL statement instead of building it with\n"
    "# engine/models/include/models/query_builder.h.\n"
    "#\n"
    "# One path per line. THE LIST MAY ONLY SHRINK. Adding a row is\n"
    "# not a fix; a row whose file no longer carries literal SQL must\n"
    "# be DELETED, and this gate fails until it is.\n"
    "#\n"
    "# Regenerate: ZCL_LINT_MODE=UPDATE tools/lint/check_model_sql_literals.sh\n";

static int msl_bln_cmp(const void *a, const void *b)
{ return strcmp((const char *)a, (const char *)b); }

static int msl_update(const struct bln_set *found, const char *baseline_path)
{
    FILE *f = fopen(baseline_path, "w");
    if (!f)
        return die("z23-lint: cannot open %s\n", baseline_path);
    static char sorted[BLN_MAX][BLN_ROW];
    memcpy(sorted, found->n, sizeof(char) * (size_t)found->count * BLN_ROW);
    qsort(sorted, (size_t)found->count, BLN_ROW, msl_bln_cmp);
    int bad = fputs(k_msl_update_header, f) < 0;
    for (int i = 0; !bad && i < found->count; i++)
        bad = fprintf(f, "%s\n", sorted[i]) < 0;
    if (fclose(f) != 0 || bad)
        return die("z23-lint: write failed: %s\n", baseline_path);
    return printf("[%s] baseline UPDATED: %s (%d file(s))\n", k_msl_gate,
                 baseline_path, found->count) < 0
        ? die("z23-lint: write failed\n", "") : 0;
}

int check_model_sql_literals_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    const char *mode = env_or("ZCL_LINT_MODE", "FAIL");
    const char *baseline_path = env_or("ZCL_MODEL_SQL_BASELINE",
                                       k_msl_baseline_default);
    int floor = msl_floor();

    char roots[RS_MAX][RS_PATH];
    int nroots = 0;
    int rc = msl_resolve_roots(roots, RS_MAX, &nroots);
    if (rc)
        return rc;
    rc = msl_check_roots_exist(roots, nroots);
    if (rc)
        return rc;

    regex_t re;
    rc = msl_re_compile(&re);
    if (rc)
        return rc;

    static struct bln_set found;
    found.count = 0;
    struct msl_walk w = { .found = &found };
    rc = msl_scan_all(roots, nroots, &re, &w);
    regfree(&re);
    if (rc)
        return rc;
    if (w.unreadable_rc)
        return msl_report_unreadable(&w);

    rc = gate_require_scanned(w.total, floor, k_msl_gate,
                              "no model .c/.h under the physical model rooms");
    if (rc)
        return rc;
    rc = gate_require_scanned(w.kept, floor, k_msl_gate,
                              "every scanned file was the builder itself — "
                              "impossible");
    if (rc)
        return rc;

    if (strcmp(mode, "UPDATE") == 0)
        return msl_update(&found, baseline_path);

    static struct bln_set base;
    base.count = 0;
    rc = bln_load(&base, baseline_path);
    if (rc)
        return rc;

    return msl_report(stdout, &base, &found, baseline_path, mode, w.kept);
}
