/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: report half of gate check-no-operator-paths. Loads the RATCHET
 * baseline, compares it with the current counts (new rows, grown rows,
 * stale rows) and prints the verdict; ZCL_LINT_MODE=UPDATE rewrites the
 * baseline instead. Never scans: the counts come from
 * gate_no_operator_paths.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_no_operator_paths_priv.h"

static char g_bask[NOP_ROWS][NOP_KEY];
static int g_basn[NOP_ROWS];
static int g_nbas;

/* ── baseline table ─────────────────────────────────────────────────────── */

static int nop_base_set(const char *key, int n)
{
    for (int i = 0; i < g_nbas; i++)
        if (strcmp(g_bask[i], key) == 0) {
            g_basn[i] = n;
            return 0;
        }
    if (g_nbas >= NOP_ROWS)
        return nop_ovf("baseline row set", NOP_ROWS);
    size_t len = strlen(key);
    if (len >= NOP_KEY)
        return nop_ovf("baseline key length", NOP_KEY);
    memcpy(g_bask[g_nbas], key, len + 1);
    g_basn[g_nbas] = n;
    g_nbas++;
    return 0;
}

static int nop_base_find(const char *key, int *n)
{
    for (int i = 0; i < g_nbas; i++)
        if (strcmp(g_bask[i], key) == 0) {
            *n = g_basn[i];
            return 1;
        }
    return 0;
}

static int nop_cur_find(const char *key)
{
    for (int i = 0; i < nop_ncur; i++)
        if (strcmp(nop_curk[i], key) == 0)
            return 1;
    return 0;
}

/* Reads one "<prong> <path> <count>" row; '#' starts a comment. */
static int nop_base_row(char *line)
{
    char *h = strchr(line, '#');
    if (h)
        *h = '\0';
    char *prong = strtok(line, " \t\r\n");
    char *path = prong ? strtok(NULL, " \t\r\n") : NULL;
    char *cnt = path ? strtok(NULL, " \t\r\n") : NULL;
    if (!prong || !path || !cnt)
        return 0;
    char key[NOP_KEY];
    if (ovf(snprintf(key, sizeof key, "%s %s", prong, path), sizeof key))
        return 2;
    return nop_base_set(key, atoi(cnt));
}

int nop_load_baseline(void)
{
    FILE *f = fopen(nop_baseline, "r");
    if (!f)
        return 0;
    char line[NOP_KEY + 64];
    while (fgets(line, sizeof line, f)) {
        int rc = nop_base_row(line);
        if (rc) {
            fclose(f);
            return rc;
        }
    }
    if (ferror(f)) {
        fclose(f);
        fprintf(stderr, "%s: read error on %s\n", nop_gate_name, nop_baseline);
        return 2;
    }
    fclose(f);
    return 0;
}

/* ── compare and report ─────────────────────────────────────────────────── */

static int nop_rowcmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static void nop_print_sorted(FILE *out, char rows[][NOP_RROW], int n)
{
    qsort(rows, (size_t)n, NOP_RROW, nop_rowcmp);
    for (int i = 0; i < n; i++)
        fprintf(out, "  %s\n", rows[i]);
}

static int nop_row_new(char rows[][NOP_RROW], int *n, int i)
{
    if (*n >= NOP_ROWS)
        return nop_ovf("report rows", NOP_ROWS);
    if (ovf(snprintf(rows[*n], NOP_RROW, "%s (%d occurrence(s))",
                     nop_curk[i], nop_curn[i]), NOP_RROW))
        return 2;
    (*n)++;
    return 0;
}

static int nop_row_grown(char rows[][NOP_RROW], int *n, int i, int b)
{
    if (*n >= NOP_ROWS)
        return nop_ovf("report rows", NOP_ROWS);
    if (ovf(snprintf(rows[*n], NOP_RROW, "%s (%d -> %d)",
                     nop_curk[i], b, nop_curn[i]), NOP_RROW))
        return 2;
    (*n)++;
    return 0;
}

static int nop_rows_newgrown(char newr[][NOP_RROW], int *nn,
                             char growr[][NOP_RROW], int *ng)
{
    int rc;
    *nn = 0;
    *ng = 0;
    for (int i = 0; i < nop_ncur; i++) {
        int b;
        if (!nop_base_find(nop_curk[i], &b)) {
            rc = nop_row_new(newr, nn, i);
            if (rc)
                return rc;
        } else if (nop_curn[i] > b) {
            rc = nop_row_grown(growr, ng, i, b);
            if (rc)
                return rc;
        }
    }
    return 0;
}

static int nop_rows_stale(char rows[][NOP_RROW], int *n)
{
    *n = 0;
    for (int i = 0; i < g_nbas; i++) {
        if (nop_cur_find(g_bask[i]))
            continue;
        if (*n >= NOP_ROWS)
            return nop_ovf("report rows", NOP_ROWS);
        if (ovf(snprintf(rows[*n], NOP_RROW, "%s (baseline %d, now 0)",
                         g_bask[i], g_basn[i]), NOP_RROW))
            return 2;
        (*n)++;
    }
    return 0;
}

static void nop_pass_totals(int *a, int *b, int *c)
{
    *a = *b = *c = 0;
    for (int i = 0; i < nop_ncur; i++) {
        if (nop_curk[i][0] == 'A')
            *a += nop_curn[i];
        else if (nop_curk[i][0] == 'B')
            *b += nop_curn[i];
        else if (nop_curk[i][0] == 'C')
            *c += nop_curn[i];
    }
}

static void nop_print_new(FILE *out, char rows[][NOP_RROW], int n)
{
    fprintf(out, "\n[%s] %d NEW operator-identity leak(s) in tracked "
            "files:\n", nop_gate_name, n);
    nop_print_sorted(out, rows, n);
    fprintf(out,
            "  A committed file must name no local filesystem path, "
            "operator\n"
            "  username, or hostname. Use a repo-relative path, a "
            "stable opaque\n"
            "  label resolved at run time, $HOME/$USER, or omit the "
            "field.\n"
            "  Adding a row to %s is not a fix; the baseline only "
            "shrinks.\n", nop_baseline);
}

static void nop_print_stale(FILE *out, char rows[][NOP_RROW], int n)
{
    fprintf(out, "\n[%s] %d STALE baseline row(s) — delete them from "
            "%s:\n", nop_gate_name, n, nop_baseline);
    nop_print_sorted(out, rows, n);
    fprintf(out,
            "  The leak is gone; leaving the row would let it come "
            "back for free.\n");
}

int nop_report(FILE *out, int override)
{
    static char newr[NOP_ROWS][NOP_RROW], growr[NOP_ROWS][NOP_RROW];
    static char staler[NOP_ROWS][NOP_RROW];
    int nnew = 0, ngrow = 0, nstale = 0, fail = 0;
    int rc = nop_rows_newgrown(newr, &nnew, growr, &ngrow);
    if (rc)
        return rc;
    if (!override) {
        rc = nop_rows_stale(staler, &nstale);
        if (rc)
            return rc;
    }
    if (nnew > 0) {
        fail = 1;
        nop_print_new(out, newr, nnew);
    }
    if (ngrow > 0) {
        fail = 1;
        fprintf(out, "\n[%s] %d baselined file(s) leak MORE than before:\n",
                nop_gate_name, ngrow);
        nop_print_sorted(out, growr, ngrow);
        fprintf(out, "  Grandfathered debt may shrink, never grow.\n");
    }
    if (nstale > 0) {
        fail = 1;
        nop_print_stale(out, staler, nstale);
    }
    if (fail)
        return 1;
    int a, b, c;
    nop_pass_totals(&a, &b, &c);
    fprintf(out, "[%s] PASS (%d baselined row(s): prong A %d "
            "absolute-home-path occurrence(s); prong B %d — "
            "source-derived account tokens; prong C %d — "
            "structured explicit host identities)\n",
            nop_gate_name, nop_ncur, a, b, c);
    return 0;
}

/* ── UPDATE mode ────────────────────────────────────────────────────────── */

struct nop_rowp { const char *k; int n; };

static int nop_rowp_cmp(const void *a, const void *b)
{
    const struct nop_rowp *x = a, *y = b;
    return strcmp(x->k, y->k);
}

static void nop_update_header(FILE *f)
{
    fputs("# check_no_operator_paths RATCHET baseline — SHRINK-ONLY.\n"
          "#\n"
          "# Format: <prong> <path> <occurrences>\n"
          "#   A  absolute home path (/home/<x>, /Users/<x>) — universal\n"
          "#   B  an account token exposed by prong A (source-derived)\n"
          "#   C  an explicit structured host identity (source-derived)\n"
          "#\n"
          "# Counts may only DECREASE. A new path/prong pair fails HARD; "
          "a row\n"
          "# whose count reaches zero is STALE and must be deleted — that "
          "is\n"
          "# how the ratchet tightens. Raising a number is never a fix.\n"
          "#\n"
          "# Regenerate after removing some:\n"
          "#   ZCL_LINT_MODE=UPDATE ./build/bin/z23-lint check-no-operator-"
          "paths\n", f);
}

int nop_update(FILE *out)
{
    FILE *f = fopen(nop_baseline, "w");
    if (!f) {
        fprintf(stderr, "%s: cannot write %s\n", nop_gate_name, nop_baseline);
        return 2;
    }
    nop_update_header(f);
    static struct nop_rowp idx[NOP_ROWS];
    for (int i = 0; i < nop_ncur; i++) {
        idx[i].k = nop_curk[i];
        idx[i].n = nop_curn[i];
    }
    qsort(idx, (size_t)nop_ncur, sizeof idx[0], nop_rowp_cmp);
    for (int i = 0; i < nop_ncur; i++)
        fprintf(f, "%s %d\n", idx[i].k, idx[i].n);
    if (ferror(f)) {
        fclose(f);
        fprintf(stderr, "%s: write error on %s\n", nop_gate_name, nop_baseline);
        return 2;
    }
    fclose(f);
    fprintf(out, "[%s] baseline UPDATED (%d rows)\n", nop_gate_name, nop_ncur);
    return 0;
}
