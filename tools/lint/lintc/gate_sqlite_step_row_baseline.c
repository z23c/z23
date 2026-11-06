/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-sqlite-step-row — the per-file count baseline (load,
 * UPDATE write) and the shrink-only comparison report. The scan lives in
 * gate_sqlite_step_row.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_sqlite_step_row_priv.h"

enum { SSR_LINE = 1024 };

int ssr_set_put(struct ssr_set *s, const char *path, int count)
{
    if (s->n >= SSR_ROWS)
        return die("z23-lint: check-sqlite-step-row: too many files (%s)\n",
                   path);
    if (ovf(snprintf(s->rows[s->n].path, RS_PATH, "%s", path), RS_PATH))
        return die("z23-lint: check-sqlite-step-row: path too long: %s\n", path);
    s->rows[s->n].count = count;
    s->n++;
    return 0;
}

/* The count recorded for path, or 0 when it has no row. */
int ssr_set_get(const struct ssr_set *s, const char *path)
{
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->rows[i].path, path) == 0)
            return s->rows[i].count;
    return 0;
}

/* One `<path> <count>` row; a malformed row is fatal, never skipped. */
static int ssr_parse_row(struct ssr_set *s, char *line, const char *bpath,
                         int lineno)
{
    char *sp = strchr(line, ' ');
    char *end = NULL;
    long v = sp ? strtol(sp + 1, &end, 10) : 0;
    if (!sp || !end || end == sp + 1 || *end != '\0' || v <= 0 ||
        v > 1000000) {
        fprintf(stderr, "z23-lint: check-sqlite-step-row: %s:%d: malformed "
                "row '%s' (want `<path> <count>`, count >= 1)\n", bpath,
                lineno, line);
        return 2;
    }
    *sp = '\0';
    if (ssr_set_get(s, line) != 0) {
        fprintf(stderr, "z23-lint: check-sqlite-step-row: %s:%d: duplicate "
                "row for %s\n", bpath, lineno, line);
        return 2;
    }
    return ssr_set_put(s, line, (int)v);
}

int ssr_load_baseline(struct ssr_set *s, const char *path)
{
    FILE *f = fopen(path, "r");
    char line[SSR_LINE];
    int rc = 0, lineno = 0;
    s->n = 0;
    if (!f)
        return die("z23-lint: check-sqlite-step-row: cannot read baseline "
                   "%s\n", path);
    while (rc == 0 && fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        lineno++;
        while (n && isspace((unsigned char)line[n - 1]))
            line[--n] = '\0';
        if (n == 0 || line[0] == '#')
            continue;
        rc = ssr_parse_row(s, line, path, lineno);
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: check-sqlite-step-row: read failed: %s\n", path);
    fclose(f);
    return rc;
}

static int ssr_row_cmp(const void *a, const void *b)
{
    return strcmp(((const struct ssr_row *)a)->path,
                  ((const struct ssr_row *)b)->path);
}

int ssr_write_baseline(const struct ssr_set *live, const char *path, FILE *out)
{
    static struct ssr_set sorted;
    sorted = *live;
    qsort(sorted.rows, (size_t)sorted.n, sizeof sorted.rows[0], ssr_row_cmp);
    FILE *f = fopen(path, "w");
    if (!f)
        return die("z23-lint: check-sqlite-step-row: cannot write %s\n", path);
    fputs("# check-sqlite-step-row baseline: files that still compare a SQLite\n"
          "# step straight to SQLITE_ROW, folding a step error into \"no row\".\n"
          "# `<path> <count>`. THE COUNTS MAY ONLY SHRINK; a file that gains a\n"
          "# site or a new file fails, and a fixed site fails until its row is\n"
          "# lowered or deleted here. Fix a site with ar_step_checked()\n"
          "# (util/ar_step_readonly.h): ROW, DONE, or ERROR that fails closed.\n"
          "# Regenerate: ZCL_LINT_MODE=UPDATE ./build/bin/z23-lint "
          "check-sqlite-step-row\n", f);
    for (int i = 0; i < sorted.n; i++)
        fprintf(f, "%s %d\n", sorted.rows[i].path, sorted.rows[i].count);
    if (fclose(f) != 0)
        return die("z23-lint: check-sqlite-step-row: cannot write %s\n", path);
    fprintf(out, "[check-sqlite-step-row] baseline UPDATED: %s (%d files)\n",
            path, sorted.n);
    return 0;
}

static int ssr_report_grown(const struct ssr_set *live,
                            const struct ssr_set *base, FILE *out)
{
    int bad = 0;
    for (int i = 0; i < live->n; i++) {
        int was = ssr_set_get(base, live->rows[i].path);
        if (live->rows[i].count <= was)
            continue;
        if (bad++ == 0)
            fputs("\n[check-sqlite-step-row] new step-to-SQLITE_ROW "
                  "comparisons (a step error would read as \"no row\"):\n",
                  out);
        fprintf(out, "  %s: %d (baseline %d)\n", live->rows[i].path,
                live->rows[i].count, was);
    }
    if (bad)
        fputs("  Use ar_step_checked() from util/ar_step_readonly.h and fail "
              "closed on\n  ZCL_STEP_ERROR. Raising the baseline is not a "
              "fix.\n", out);
    return bad;
}

static int ssr_report_stale(const struct ssr_set *live,
                            const struct ssr_set *base, const char *base_path,
                            FILE *out)
{
    int bad = 0;
    for (int i = 0; i < base->n; i++) {
        int now = ssr_set_get(live, base->rows[i].path);
        if (now >= base->rows[i].count)
            continue;
        if (bad++ == 0)
            fprintf(out, "\n[check-sqlite-step-row] STALE baseline rows: "
                    "sites were fixed; lower or delete them in %s:\n",
                    base_path);
        fprintf(out, "  %s: baseline %d, now %d\n", base->rows[i].path,
                base->rows[i].count, now);
    }
    return bad;
}

int ssr_report(const struct ssr_set *live, const struct ssr_set *base,
               const char *base_path, int files, FILE *out)
{
    int grown = ssr_report_grown(live, base, out);
    int stale = ssr_report_stale(live, base, base_path, out);
    if (grown || stale) {
        fprintf(out, "[check-sqlite-step-row] FAIL (%d grown or new, %d "
                "stale)\n", grown, stale);
        return 1;
    }
    int sites = 0;
    for (int i = 0; i < live->n; i++)
        sites += live->rows[i].count;
    fprintf(out, "[check-sqlite-step-row] PASS (%d files scanned, %d sites in "
            "%d baselined files)\n", files, sites, live->n);
    return 0;
}
