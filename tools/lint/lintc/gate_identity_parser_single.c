/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check_identity_parser_single — shrink-only ratchet against
 * a tenth copy of the source-identity JSON parser growing back under the
 * scan root. Ported from tools/lint/check_identity_parser_single.sh
 * (deleted); see that header, preserved in spirit here:
 *
 *   A. a local re-definition of the 64-lowercase-hex validator, caught by
 *      name (json_first_string_field) AND structurally (any short function
 *      whose body performs a 64-hex boolean validity check).
 *   B. an inline grep/sed extraction of the "source_id_sha256" JSON key.
 *
 * The baseline file (default tools/lint/identity_parser_baseline.txt)
 * names files still carrying a copy and how many; counts may only shrink.
 * The zcl-identity-parser-allow marker exempts a single match and is
 * itself bounded by MARKER_CEILING (total) and MARKER_ALLOWED_FILES
 * (where). Selftest: gate_identity_parser_single_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_identity_parser_single_priv.h"

struct ips_baserow {
    char path[IPS_PATH];
    int val;
    int hit;
};

struct ips_base {
    struct ips_baserow rows[IPS_MAXBASE];
    size_t n;
};

/* ── baseline file (gate_load_kv_file semantics) ──────────────────────── */

/* Drops a '#' comment and surrounding blanks in place; returns the start and
 * stores the trimmed length in *n. */
static char *ips_line_trim(char *raw, size_t *n)
{
    char *h = strchr(raw, '#');
    if (h)
        *h = '\0';
    char *s = raw;
    while (*s == ' ' || *s == '\t')
        s++;
    size_t k = strlen(s);
    while (k && (s[k - 1] == ' ' || s[k - 1] == '\t'))
        s[--k] = '\0';
    *n = k;
    return s;
}

static int ips_base_line(struct ips_base *b, char *raw)
{
    size_t n = 0;
    char *s = ips_line_trim(raw, &n);
    if (!n)
        return 0;
    char *last = s + n;
    while (last > s && last[-1] != ' ' && last[-1] != '\t')
        last--;
    char *kend = s;
    while (*kend && *kend != ' ' && *kend != '\t')
        kend++;
    if (b->n >= IPS_MAXBASE) {
        fprintf(stderr, "%s: baseline rows exceed %d\n", k_ips_gate,
                IPS_MAXBASE);
        return 2;
    }
    if ((size_t)(kend - s) >= IPS_PATH)
        return 2;
    struct ips_baserow *r = &b->rows[b->n++];
    memcpy(r->path, s, (size_t)(kend - s));
    r->path[kend - s] = '\0';
    r->val = atoi(last);
    return 0;
}

static int ips_load_baseline(const struct ips_cfg *cfg, struct ips_base *b)
{
    FILE *f = fopen(cfg->baseline_path, "r");
    if (!f)
        return 0; /* a missing baseline is empty, per gate_load_kv_file */
    char line[4096];
    int rc = 0;
    while (fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        if (n + 1 == sizeof line && line[n - 1] != '\n') {
            fprintf(stderr, "%s: baseline line exceeds 4095 bytes\n",
                    k_ips_gate);
            rc = 2;
            break;
        }
        if (n && line[n - 1] == '\n')
            line[n - 1] = '\0';
        rc = ips_base_line(b, line);
        if (rc)
            break;
    }
    if (!rc && ferror(f)) {
        fprintf(stderr, "%s: read error on %s\n", k_ips_gate,
                cfg->baseline_path);
        rc = 2;
    }
    fclose(f);
    return rc;
}

static struct ips_baserow *ips_base_find(struct ips_base *b, const char *path)
{
    for (size_t i = 0; i < b->n; i++)
        if (strcmp(b->rows[i].path, path) == 0)
            return &b->rows[i];
    return NULL;
}

static int ips_base_sum(const struct ips_base *b)
{
    int sum = 0;
    for (size_t i = 0; i < b->n; i++)
        sum += b->rows[i].val;
    return sum;
}

/* ── violation assembly ───────────────────────────────────────────────── */

static int ips_push(char rows[][IPS_MAXMSG], size_t *n, const char *fmt, ...)
{
    if (*n >= IPS_MAXV) {
        fprintf(stderr, "%s: violation rows exceed %d\n", k_ips_gate,
                IPS_MAXV);
        return 2;
    }
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(rows[*n], IPS_MAXMSG, fmt, ap);
    va_end(ap);
    if (ovf(w, IPS_MAXMSG))
        return 2;
    (*n)++;
    return 0;
}

static int ips_diff_rows(const struct ips_scanres *res, struct ips_base *b,
                         char viol[][IPS_MAXMSG], size_t *nviol,
                         char tol[][IPS_MAXMSG], size_t *ntol, int *total)
{
    for (size_t i = 0; i < res->nrows; i++) {
        const struct ips_row *row = &res->rows[i];
        *total += row->debt;
        struct ips_baserow *base = ips_base_find(b, row->path);
        if (!base) {
            int rc = ips_push(viol, nviol,
                              "%s — %d copy/copies found, not in the baseline"
                              " (new file may carry ZERO)",
                              row->path, row->debt);
            if (rc)
                return rc;
        } else {
            base->hit = 1;
            if (row->debt <= base->val) {
                int rc = ips_push(tol, ntol, "%s (%d/%d)", row->path,
                                  row->debt, base->val);
                if (rc)
                    return rc;
            } else {
                int rc = ips_push(viol, nviol,
                                  "%s — %d copy/copies found, baseline allows"
                                  " %d",
                                  row->path, row->debt, base->val);
                if (rc)
                    return rc;
            }
        }
    }
    return 0;
}

static int ips_stale_rows(const struct ips_base *b, char stale[][IPS_MAXMSG],
                          size_t *nstale)
{
    for (size_t i = 0; i < b->n; i++) {
        if (b->rows[i].hit)
            continue;
        int rc = ips_push(stale, nstale, "%s (baseline says %d, actual 0)",
                          b->rows[i].path, b->rows[i].val);
        if (rc)
            return rc;
    }
    return 0;
}

static int ips_ceiling_check(const struct ips_cfg *cfg, int base_sum,
                             char viol[][IPS_MAXMSG], size_t *nviol)
{
    if (base_sum <= cfg->ceiling)
        return 0;
    fprintf(cfg->out,
            "\n[%s] baseline sum (%d) exceeds the ratchet ceiling (%d)\n"
            "        in %s — the baseline was edited upward. Lower it back,\n"
            "        or lower RATCHET_CEILING in this script if debt has"
            " genuinely\n"
            "        and legitimately grown (a change that belongs in code"
            " review,\n"
            "        not a quiet data-file edit).\n",
            k_ips_gate, base_sum, cfg->ceiling, cfg->baseline_path);
    return ips_push(viol, nviol, "%s — baseline sum %d exceeds ceiling %d",
                    cfg->baseline_path, base_sum, cfg->ceiling);
}

static int ips_marker_allowed(const struct ips_cfg *cfg, const char *f)
{
    for (size_t i = 0; i < cfg->nmarker_allowed; i++)
        if (strcmp(f, cfg->marker_allowed[i]) == 0)
            return 1;
    return 0;
}

static int ips_marker_check(const struct ips_cfg *cfg,
                            const struct ips_scanres *res,
                            const char *allowlist, char viol[][IPS_MAXMSG],
                            size_t *nviol)
{
    for (size_t i = 0; i < res->nm; i++) {
        if (ips_marker_allowed(cfg, res->mfiles[i]))
            continue;
        int rc = ips_push(viol, nviol,
                          "%s — carries a zcl-identity-parser-allow marker"
                          " but is not on MARKER_ALLOWED_FILES (only %s may"
                          " exempt a copy this way)",
                          res->mfiles[i], allowlist);
        if (rc)
            return rc;
    }
    if (res->marker_total > cfg->marker_ceiling) {
        fprintf(cfg->out,
                "\n[%s] zcl-identity-parser-allow marker count (%d) exceeds\n"
                "        MARKER_CEILING (%d) — a new marker exempts a copy"
                " from\n"
                "        the ratchet invisibly; raising MARKER_CEILING is a"
                " visible\n"
                "        source diff in this script, not a comment nobody"
                " reviews.\n",
                k_ips_gate, res->marker_total, cfg->marker_ceiling);
        int rc = ips_push(viol, nviol,
                          "marker count %d exceeds MARKER_CEILING %d",
                          res->marker_total, cfg->marker_ceiling);
        if (rc)
            return rc;
    }
    return 0;
}

/* ── reporting ────────────────────────────────────────────────────────── */

static int ips_cmp_msg(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int ips_cmp_row(const void *a, const void *b)
{
    return strcmp(((const struct ips_row *)a)->path,
                  ((const struct ips_row *)b)->path);
}

static void ips_report_violations(const struct ips_cfg *cfg,
                                  char viol[][IPS_MAXMSG], size_t nviol)
{
    qsort(viol, nviol, IPS_MAXMSG, ips_cmp_msg);
    fprintf(cfg->out,
            "\n[%s] %zu violation(s) — a new or grown inline copy of the\n"
            "        source-identity JSON parser:\n",
            k_ips_gate, nviol);
    for (size_t i = 0; i < nviol; i++)
        fprintf(cfg->out, "  %s\n", viol[i]);
    fprintf(cfg->out,
            "\n  Source tools/scripts/source_identity_lib.sh instead:\n"
            "    zcl_is_sha256 / zcl_json_first_string /"
            " zcl_json_first_sha256 /\n"
            "    zcl_binary_source_id\n"
            "  Raising a number in %s is NOT a fix; counts may only"
            " shrink.\n",
            cfg->baseline_path);
}

static void ips_report_stale(const struct ips_cfg *cfg,
                             char stale[][IPS_MAXMSG], size_t nstale)
{
    qsort(stale, nstale, IPS_MAXMSG, ips_cmp_msg);
    fprintf(cfg->out,
            "\n[%s] %zu STALE baseline row(s) — the file no longer carries\n"
            "        any inline copy. Delete them from %s:\n",
            k_ips_gate, nstale, cfg->baseline_path);
    for (size_t i = 0; i < nstale; i++)
        fprintf(cfg->out, "  %s\n", stale[i]);
}

static int ips_update(const struct ips_cfg *cfg, struct ips_row *rows,
                      size_t n)
{
    qsort(rows, n, sizeof rows[0], ips_cmp_row);
    FILE *f = fopen(cfg->baseline_path, "w");
    if (!f) {
        fprintf(cfg->err, "%s: cannot write %s\n", k_ips_gate,
                cfg->baseline_path);
        return 2;
    }
    fprintf(f,
            "# check_identity_parser_single baseline — files still carrying"
            " an inline\n"
            "# copy of the source-identity JSON parser (a local"
            " is_sha256/is_hex64/\n"
            "# json_first_string_field/is_source_id_sha256 definition, or an"
            " inline\n"
            "# grep/sed extraction of the \"source_id_sha256\" JSON key)"
            " instead of\n"
            "# sourcing tools/scripts/source_identity_lib.sh.\n"
            "#\n"
            "# Format: <path> <count>.  COUNTS MAY ONLY SHRINK.\n"
            "#\n"
            "# Regenerate: ZCL_LINT_MODE=UPDATE"
            " ./build/bin/z23-lint check-identity-parser-single\n");
    for (size_t i = 0; i < n; i++)
        fprintf(f, "%s %d\n", rows[i].path, rows[i].debt);
    fclose(f);
    fprintf(cfg->out, "[%s] baseline UPDATED: %s\n", k_ips_gate,
            cfg->baseline_path);
    return 0;
}

static void ips_floor_fail(const struct ips_cfg *cfg, size_t nfiles)
{
    fprintf(cfg->err,
            "%s: FATAL — scan set is '%zu' (< floor %d).\n"
            "  The scan producer (find/glob/grep) returned too little; a\n"
            "  scanned dir/file was likely renamed, moved, or deleted.\n"
            "  Refusing to report 'clean' off a hollow (empty) scan.\n"
            "  no *.sh files found under %s — the scan root moved\n",
            k_ips_gate, nfiles, cfg->file_floor, cfg->scan_root);
}

/* ── main flow ────────────────────────────────────────────────────────── */

/* Everything one gate run accumulates; static so the large scan set and
 * violation tables stay out of the stack. */
struct ips_work {
    struct ips_scanres res;
    struct ips_base base;
    char viol[IPS_MAXV][IPS_MAXMSG];
    char tol[IPS_MAXV][IPS_MAXMSG];
    char stale[IPS_MAXV][IPS_MAXMSG];
    char allowlist[IPS_LINE];
    size_t nviol, ntol, nstale;
    int total;
};

/* Space-joins the marker-allowed files for the report, bounded by cap. */
static void ips_join_allowlist(const struct ips_cfg *cfg, char *out,
                               size_t cap)
{
    size_t used = 0;
    out[0] = '\0';
    for (size_t i = 0; i < cfg->nmarker_allowed && i < IPS_MAXALLOW; i++) {
        int w = snprintf(out + used, cap - used, "%s%s", i ? " " : "",
                         cfg->marker_allowed[i]);
        if (w < 0 || (size_t)w >= cap - used) {
            out[cap - 1] = '\0';
            return;
        }
        used += (size_t)w;
    }
}

static int ips_check_ratchet(const struct ips_cfg *cfg, struct ips_work *w)
{
    int rc = ips_diff_rows(&w->res, &w->base, w->viol, &w->nviol, w->tol,
                           &w->ntol, &w->total);
    if (rc == 0)
        rc = ips_stale_rows(&w->base, w->stale, &w->nstale);
    if (rc == 0)
        rc = ips_ceiling_check(cfg, ips_base_sum(&w->base), w->viol,
                               &w->nviol);
    if (rc == 0) {
        ips_join_allowlist(cfg, w->allowlist, sizeof w->allowlist);
        rc = ips_marker_check(cfg, &w->res, w->allowlist, w->viol, &w->nviol);
    }
    return rc;
}

static int ips_report(const struct ips_cfg *cfg, struct ips_work *w)
{
    int fail = 0;
    if (w->nviol > 0) {
        ips_report_violations(cfg, w->viol, w->nviol);
        fail = 1;
    }
    if (w->nstale > 0) {
        ips_report_stale(cfg, w->stale, w->nstale);
        fail = 1;
    }
    if (fail && strcmp(cfg->mode, "FAIL") == 0)
        return 1;
    fprintf(cfg->out,
            "[%s] PASS (%zu *.sh files scanned, %zu carrying a copy,"
            " %d total, %zu baselined file(s) summing to %d/%d,"
            " %zu tolerated, %d/%d allow-marker(s))\n",
            k_ips_gate, w->res.nfiles, w->res.nrows, w->total, w->base.n,
            ips_base_sum(&w->base), cfg->ceiling, w->ntol,
            w->res.marker_total, cfg->marker_ceiling);
    return 0;
}

int ips_run_cfg(const struct ips_cfg *cfg)
{
    static struct ips_work w;
    memset(&w, 0, sizeof w);
    int rc = ips_scan_all(cfg, &w.res);
    if (rc)
        return rc;
    if ((long)w.res.nfiles < cfg->file_floor) {
        ips_floor_fail(cfg, w.res.nfiles);
        return 2;
    }
    rc = ips_load_baseline(cfg, &w.base);
    if (rc)
        return rc;
    rc = ips_check_ratchet(cfg, &w);
    if (rc)
        return rc;
    if (strcmp(cfg->mode, "UPDATE") == 0)
        return ips_update(cfg, w.res.rows, w.res.nrows);
    return ips_report(cfg, &w);
}

int check_identity_parser_single_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    static char allowbuf[IPS_LINE];
    static const char *allowed[IPS_MAXALLOW];
    size_t nallow = 0;
    const char *e = getenv("ZCL_IDENTITY_PARSER_MARKER_ALLOWED");
    if (e && e[0]) {
        if (strlen(e) >= sizeof allowbuf) {
            fprintf(stderr, "%s: marker allowlist exceeds %d bytes\n",
                    k_ips_gate, IPS_LINE);
            return 2;
        }
        if (ovf(snprintf(allowbuf, sizeof allowbuf, "%s", e), sizeof allowbuf))
            return 2;
        char *p = allowbuf;
        while (p && nallow < IPS_MAXALLOW) {
            char *sp = strchr(p, ' ');
            if (sp)
                *sp = '\0';
            if (*p)
                allowed[nallow++] = p;
            p = sp ? sp + 1 : NULL;
        }
    } else {
        allowed[0] = "tools/scripts/install_z23.sh";
        nallow = 1;
    }
    struct ips_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.mode = env_or("ZCL_LINT_MODE", "FAIL");
    cfg.baseline_path = env_or("ZCL_IDENTITY_PARSER_BASELINE",
                               "tools/lint/identity_parser_baseline.txt");
    cfg.scan_root = env_or("ZCL_IDENTITY_PARSER_SCAN_ROOT", "tools");
    cfg.ceiling = atoi(env_or("ZCL_IDENTITY_PARSER_CEILING", "16"));
    cfg.marker_ceiling =
        atoi(env_or("ZCL_IDENTITY_PARSER_MARKER_CEILING", "1"));
    cfg.file_floor = atoi(env_or("ZCL_IDENTITY_PARSER_FILE_FLOOR", "5"));
    cfg.marker_allowed = allowed;
    cfg.nmarker_allowed = nallow;
    cfg.out = stdout;
    cfg.err = stderr;
    return ips_run_cfg(&cfg);
}
