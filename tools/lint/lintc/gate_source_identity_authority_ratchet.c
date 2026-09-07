/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the ratchet half of the check-source-identity-authority
 * family (the 700-line family ceiling split) — the gate_load_kv_file
 * baseline, the violation/tolerated/stale evaluation, the ceiling and
 * UPDATE-mode baseline rewrite, and the verdict report. The gate body
 * and the list helpers live in gate_source_identity_authority.c, the
 * walk and per-file counter in gate_source_identity_authority_scan.c,
 * and the planted-violation selftest in
 * gate_source_identity_authority_selftest.c; the files share their
 * internals through gate_source_identity_authority_priv.h. The parity
 * contract for these verdicts is documented in
 * gate_source_identity_authority.c's header.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "gate_source_identity_authority_priv.h"

static const char k_gate[] = "check_source_identity_authority";

/* ── the gate_load_kv_file baseline ───────────────────────────────────── */

void sia_kvset_free(struct sia_kvset *s)
{
    for (size_t i = 0; i < s->n; i++) {
        free(s->v[i].k);
        free(s->v[i].val);
    }
    free(s->v);
    s->v = NULL;
    s->n = s->cap = 0;
}

/* ARRAY["$key"]="$val": an existing key's value is overwritten. */
static int sia_kv_put(struct sia_kvset *s, const char *key, const char *val)
{
    for (size_t i = 0; i < s->n; i++) {
        if (strcmp(s->v[i].k, key) == 0) {
            char *nv = malloc(strlen(val) + 1); // raw-alloc-ok:lint-runtime
            if (!nv)
                return die("z23-lint: out of memory\n", "");
            strcpy(nv, val);
            free(s->v[i].val);
            s->v[i].val = nv;
            return 0;
        }
    }
    if (s->n == s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 32;
        struct sia_kv *nv = realloc(s->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv)
            return die("z23-lint: out of memory\n", "");
        s->v = nv;
        s->cap = nc;
    }
    char *k = malloc(strlen(key) + 1); // raw-alloc-ok:lint-runtime
    char *v = malloc(strlen(val) + 1); // raw-alloc-ok:lint-runtime
    if (!k || !v) {
        free(k);
        free(v);
        return die("z23-lint: out of memory\n", "");
    }
    strcpy(k, key);
    strcpy(v, val);
    s->v[s->n].k = k;
    s->v[s->n].val = v;
    s->v[s->n].hit = 0;
    s->n++;
    return 0;
}

static int sia_base_line(char *line, struct sia_kvset *s)
{
    char *h = strchr(line, '#');
    if (h)
        *h = '\0';
    char *p = line;
    while (*p && isspace((unsigned char)*p))
        p++;
    size_t n = strlen(p);
    while (n && isspace((unsigned char)p[n - 1]))
        p[--n] = '\0';
    if (!n)
        return 0;
    char *last = strrchr(p, ' ');
    const char *val = last ? last + 1 : p;
    char *first = strchr(p, ' ');
    if (first)
        *first = '\0';
    return sia_kv_put(s, p, val);
}

int sia_base_load(const char *path, struct sia_kvset *s)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0)
        rc = sia_base_line(line, s);
    return fin(f, line, path, rc);
}

static const char *sia_base_get(struct sia_kvset *s, const char *key)
{
    for (size_t i = 0; i < s->n; i++) {
        if (strcmp(s->v[i].k, key) == 0) {
            s->v[i].hit = 1;
            return s->v[i].val;
        }
    }
    return NULL;
}

/* ── the ratchet verdict ──────────────────────────────────────────────── */

void sia_eval_free(struct sia_eval *e)
{
    sia_free(&e->violations);
    sia_free(&e->tolerated);
    sia_free(&e->stale);
}

static int sia_eval_row(struct sia_count *row, struct sia_kvset *base,
                        struct sia_eval *e)
{
    char debt[32];
    if (ovf(snprintf(debt, sizeof debt, "%ld", row->debt), sizeof debt))
        return 2;
    const char *allowed = sia_base_get(base, row->path);
    if (!allowed)
        return sia_addf(&e->violations,
                        "%s — %s occurrence(s) found, not in the baseline "
                        "(new file may carry ZERO)", row->path, debt, "");
    if (row->debt <= strtol(allowed, NULL, 10))
        return sia_addf(&e->tolerated, "%s (%s/%s)", row->path, debt,
                        allowed);
    return sia_addf(&e->violations,
                    "%s — %s occurrence(s) found, baseline allows %s",
                    row->path, debt, allowed);
}

int sia_evaluate(struct sia_counts *counts, struct sia_kvset *base,
                 struct sia_eval *e)
{
    int rc = 0;
    e->total_copies = 0;
    e->baseline_sum = 0;
    for (size_t i = 0; i < base->n; i++)
        e->baseline_sum += strtol(base->v[i].val, NULL, 10);
    for (size_t i = 0; rc == 0 && i < counts->n; i++) {
        e->total_copies += counts->v[i].debt;
        rc = sia_eval_row(&counts->v[i], base, e);
    }
    for (size_t i = 0; rc == 0 && i < base->n; i++) {
        if (!base->v[i].hit)
            rc = sia_addf(&e->stale, "%s (baseline says %s, actual 0)",
                          base->v[i].k, base->v[i].val, "");
    }
    return rc;
}

/* The baseline-sum-over-ceiling block (stdout) plus its violation row. */
static int sia_ceiling(struct sia_eval *e, const char *baseline,
                       const char *ceiling, FILE *out)
{
    if (e->baseline_sum <= strtol(ceiling, NULL, 10))
        return 0;
    if (fprintf(out, "\n[%s] baseline sum (%ld) exceeds the ratchet "
                "ceiling (%s)\n"
                "        in %s — the baseline was edited upward. Lower it "
                "back,\n"
                "        or lower RATCHET_CEILING in this script if debt "
                "has genuinely\n"
                "        and legitimately grown (a change that belongs in "
                "code review,\n"
                "        not a quiet data-file edit).\n",
                k_gate, e->baseline_sum, ceiling, baseline) < 0)
        return die("z23-lint: write failed\n", "");
    char sum[32];
    if (ovf(snprintf(sum, sizeof sum, "%ld", e->baseline_sum), sizeof sum))
        return 2;
    return sia_addf(&e->violations,
                    "%s — baseline sum %s exceeds ceiling %s", baseline,
                    sum, ceiling);
}

static const char k_update_hdr[] =
    "# check_source_identity_authority baseline — reviewed exceptions to the\n"
    "# Q1 (baked build)/Q2 (working tree) source_id_sha256 naming and reader\n"
    "# ratchet. See tools/lint/check_source_identity_authority.sh's header for\n"
    "# class R (positional agentbuild read) and class P (bare-key working-tree\n"
    "# producer).\n"
    "#\n"
    "# Format: <path> <count>.  COUNTS MAY ONLY SHRINK.\n"
    "#\n"
    "# Regenerate: ZCL_LINT_MODE=UPDATE "
    "tools/lint/check_source_identity_authority.sh\n";

static int sia_update_rows(struct sia_counts *counts, struct sia_list *rows)
{
    for (size_t i = 0; i < counts->n; i++) {
        char debt[32];
        if (ovf(snprintf(debt, sizeof debt, "%ld", counts->v[i].debt),
                sizeof debt))
            return 2;
        int rc = sia_addf(rows, "%s %s", counts->v[i].path, debt, "");
        if (rc != 0)
            return rc;
    }
    sia_sort(rows);
    return 0;
}

static int sia_update_write(const char *baseline, const struct sia_list *rows)
{
    FILE *f = fopen(baseline, "w");
    if (!f)
        return die("z23-lint: cannot open %s\n", baseline);
    int rc = 0;
    if (fputs(k_update_hdr, f) < 0)
        rc = die("z23-lint: write failed\n", "");
    for (size_t i = 0; rc == 0 && i < rows->n; i++)
        if (fprintf(f, "%s\n", rows->v[i]) < 0)
            rc = die("z23-lint: write failed\n", "");
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", baseline);
    return rc;
}

static int sia_update(const char *baseline, struct sia_counts *counts,
                      FILE *out)
{
    struct sia_list rows = { 0 };
    int rc = sia_update_rows(counts, &rows);
    if (rc == 0)
        rc = sia_update_write(baseline, &rows);
    sia_free(&rows);
    if (rc == 0 && fprintf(out, "[%s] baseline UPDATED: %s\n", k_gate,
                           baseline) < 0)
        rc = die("z23-lint: write failed\n", "");
    return rc;
}

static int sia_print_sorted(FILE *out, struct sia_list *l)
{
    sia_sort(l);
    for (size_t i = 0; i < l->n; i++)
        if (fprintf(out, "  %s\n", l->v[i]) < 0)
            return die("z23-lint: write failed\n", "");
    return 0;
}

static int sia_report(struct sia_eval *e, const char *baseline, FILE *out)
{
    int fail = 0;
    if (e->violations.n) {
        fail = 1;
        if (fprintf(out, "\n[%s] %d violation(s) — a new or grown "
                    "positional\n"
                    "        agentbuild source_id_sha256 read, or a "
                    "working-tree identity\n"
                    "        published under the bare source_id_sha256 "
                    "key:\n", k_gate, (int)e->violations.n) < 0)
            return die("z23-lint: write failed\n", "");
        if (sia_print_sorted(out, &e->violations))
            return 2;
        if (fprintf(out, "\n  Class R: use zcl_agentbuild_v2_top_source_id "
                    "(tools/scripts/source_identity_lib.sh).\n"
                    "  Class P: rename the producer's key to name the "
                    "tree, e.g.\n"
                    "           working_tree_source_id_sha256.\n"
                    "  Raising a number in %s is NOT a fix; counts may "
                    "only shrink.\n", baseline) < 0)
            return die("z23-lint: write failed\n", "");
    }
    if (e->stale.n) {
        fail = 1;
        if (fprintf(out, "\n[%s] %d STALE baseline row(s) — the file no "
                    "longer carries\n"
                    "        any counted occurrence. Delete them from "
                    "%s:\n", k_gate, (int)e->stale.n, baseline) < 0
            || sia_print_sorted(out, &e->stale))
            return die("z23-lint: write failed\n", "");
    }
    return fail;
}

int sia_finish(struct sia_eval *e, struct sia_counts *counts,
               const char *baseline, const char *ceiling,
               const char *mode, int nfiles, int baseline_count, FILE *out)
{
    int rc = sia_ceiling(e, baseline, ceiling, out);
    if (rc == 0 && strcmp(mode, "UPDATE") == 0)
        return sia_update(baseline, counts, out);
    int fail = 0;
    if (rc == 0) {
        fail = sia_report(e, baseline, out);
        if (fail == 2)
            rc = 2;
    }
    if (rc)
        return rc;
    if (fail && strcmp(mode, "FAIL") == 0)
        return 1;
    char total[32], sum[32];
    if (ovf(snprintf(total, sizeof total, "%ld", e->total_copies),
            sizeof total)
        || ovf(snprintf(sum, sizeof sum, "%ld", e->baseline_sum),
               sizeof sum))
        return 2;
    if (fprintf(out, "[%s] PASS (%d files scanned, %d carrying an "
                "occurrence, %s total, %d baselined file(s) summing to "
                "%s/%s, %d tolerated)\n", k_gate, nfiles,
                (int)counts->n, total, baseline_count, sum, ceiling,
                (int)e->tolerated.n) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}
