/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-crypto-perf, the standing crypto-vs-Rust performance
 * gate. Measures every C crypto primitive live (median ns/op, from
 * build/bin/zclassic23 -bench-crypto-vs-rust) and enforces the ratchet and
 * the beat/behind rules against tools/crypto_perf_baseline.csv. Ported from
 * tools/scripts/check_crypto_perf.sh (deleted). Verdicts live in
 * gate_crypto_perf_eval.c, the -h text in gate_crypto_perf_usage.c, and the
 * selftest in gate_crypto_perf_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_proc.h"
#include "lintc_sig.h"
#include "lintc_text.h"
#include "gate_crypto_perf_priv.h"

enum { CCP_GRACE_MS = 1000 };

static const char k_ccp_gate[] = "check-crypto-perf";
static const char k_ccp_dashes[] =
    "---------------------------------------------------------------------------------";

/* The script's ${VAR:-fallback}: an empty value falls back too. The caller
 * passes getenv("ZCL_...") itself so the flag scanner sees the literal read. */
static const char *ccp_or(const char *v, const char *fallback)
{
    return v && *v ? v : fallback;
}


/* Moves a captured run into buf. A truncated capture is an error, never a
 * short bench. The script's $(...) dropped trailing newlines and NULs, which
 * lcp_buf_subst does too. */
static int ccp_take(struct lcp_buf *out, char *buf, size_t cap, size_t *len,
                    FILE *err)
{
    if (out->lost != LCP_LOST_NONE) {
        fprintf(err, "%s: bench output was truncated or ran out of memory\n",
                k_ccp_gate);
        return 2;
    }
    if (out->data)
        lcp_buf_subst(out);
    *len = out->data ? out->len : 0;
    if (*len >= cap) {
        fprintf(err, "%s: bench output exceeds %d bytes\n", k_ccp_gate,
                CCP_RAW);
        return 2;
    }
    if (*len)
        memcpy(buf, out->data, *len);
    buf[*len] = '\0';
    return 0;
}

/* Handles lcp_run's status. A forwarded termination signal re-raises after the
 * child group is reaped. A start failure or an unreadable status is fatal. A
 * normal non-zero exit is ignored, as the script's `|| true` did: the bench
 * exits 1 only when it produced no rows (fatal below: no CRYPTOPERF rows) or
 * could not append to the history CSV, which leaves its printed rows valid
 * (bench_crypto_vs_rust in engine/entry/main_cli_modes.c). Status above
 * 128 is also fatal: lcp_run reports a signal death as 128 plus the signal, so
 * a bench that exits with such a status is indistinguishable from one killed. */
static int ccp_bench_status(int rc, int code, struct lcp_buf *out,
                            const struct ccp_opts *o)
{
    if (rc == 1) {
        int sig = lsc_pending();
        lcp_buf_free(out);
        lsc_finish(sig);
        return 2;
    }
    if (rc < 0) {
        lcp_buf_free(out);
        fprintf(o->err, "%s: cannot run bench %s\n", k_ccp_gate, o->binary);
        return 2;
    }
    if (code > 128) {
        lcp_buf_free(out);
        fprintf(o->err, "%s: bench %s ended by a signal (status %d)\n",
                k_ccp_gate, o->binary, code);
        return 2;
    }
    return 0;
}

/* Runs `binary -bench-crypto-vs-rust` with ZCL_BENCH_HISTORY set and captures
 * stdout; stderr is discarded. */
static int ccp_run_bench(const struct ccp_opts *o, char *buf, size_t cap,
                         size_t *len)
{
    char hist[CCP_PATH];
    if (ovf(snprintf(hist, sizeof hist, "ZCL_BENCH_HISTORY=%s", o->history),
            sizeof hist))
        return 2;
    char *argv[] = { (char *)o->binary, (char *)"-bench-crypto-vs-rust", NULL };
    const char *env[] = { hist, NULL };
    struct lcp_spec sp = { .argv = argv, .setenv = env, .mode = LCP_OUT,
                           .grace_ms = CCP_GRACE_MS };
    struct lcp_buf out = { 0 };
    int code = 1;
    if (lsc_install() != 0)
        return die("z23-lint: cannot install signal handlers\n", "");
    lsc_unblock();
    int rc = lcp_run(&sp, &out, &code);
    int bad = ccp_bench_status(rc, code, &out, o);
    if (bad)
        return bad;
    bad = ccp_take(&out, buf, cap, len, o->err);
    lcp_buf_free(&out);
    return bad;
}

static int ccp_slurp(const struct ccp_opts *o, char *buf, size_t cap,
                     size_t *len)
{
    FILE *f = fopen(o->bench_file, "r");
    if (!f) {
        fprintf(o->err, "bench file not found: %s\n", o->bench_file);
        return 2;
    }
    size_t got = fread(buf, 1, cap - 1, f);
    int more = fgetc(f) != EOF;
    int bad = ferror(f);
    fclose(f);
    if (bad)
        return die("z23-lint: read failed: %s\n", o->bench_file);
    if (more) {
        fprintf(o->err, "%s: bench file exceeds %d bytes\n", k_ccp_gate,
                CCP_RAW);
        return 2;
    }
    while (got > 0 && buf[got - 1] == '\n')
        got--;
    buf[got] = '\0';
    *len = got;
    return 0;
}

static int ccp_bench_raw(const struct ccp_opts *o, char *buf, size_t cap,
                         size_t *len)
{
    return o->bench_file ? ccp_slurp(o, buf, cap, len)
                         : ccp_run_bench(o, buf, cap, len);
}

static int ccp_copy(char *dst, size_t cap, const char *src, FILE *err)
{
    if (strlen(src) >= cap) {
        fprintf(err, "%s: bench field too long: %.40s\n", k_ccp_gate, src);
        return 2;
    }
    memcpy(dst, src, strlen(src) + 1);
    return 0;
}

/* Splits "key ns" the way the script's `read` did: blanks separate fields,
 * and a missing ns leaves the empty string. */
static void ccp_fields(char *p, char **key, char **ns)
{
    p += strspn(p, " \t");
    *key = p;
    p += strcspn(p, " \t");
    if (*p)
        *p++ = '\0';
    p += strspn(p, " \t");
    *ns = p;
    p[strcspn(p, " \t")] = '\0';
}

/* Records one CRYPTOPERF key/value, last value wins as the script's
 * associative array did. Key order is first appearance. */
static int ccp_meas_put(struct ccp_meas *m, int *n, const char *key,
                        const char *ns, FILE *err)
{
    int i = 0;
    while (i < *n && strcmp(m[i].key, key) != 0)
        i++;
    if (i == *n) {
        if (*n >= CCP_KEYS) {
            fprintf(err, "%s: measured keys exceed %d\n", k_ccp_gate,
                    CCP_KEYS);
            return 2;
        }
        if (ccp_copy(m[i].key, sizeof m[i].key, key, err))
            return 2;
        (*n)++;
    }
    return ccp_copy(m[i].ns, sizeof m[i].ns, ns, err);
}

/* Handles one bench line; only lines starting "CRYPTOPERF " count. The line
 * is copied first so the raw output stays intact for the FATAL tail. */
static int ccp_parse_line(const char *raw_line, size_t len,
                          struct ccp_meas *m, int *n, FILE *err)
{
    static const char tag[] = "CRYPTOPERF ";
    char line[CCP_LINE];
    if (strncmp(raw_line, tag, sizeof tag - 1) != 0)
        return 0;
    if (len >= sizeof line) {
        fprintf(err, "%s: bench row too long\n", k_ccp_gate);
        return 2;
    }
    memcpy(line, raw_line, len);
    line[len] = '\0';
    char *key, *ns;
    ccp_fields(line + sizeof tag - 1, &key, &ns);
    return ccp_meas_put(m, n, key, ns, err);
}

static int ccp_parse_meas(const char *raw, struct ccp_meas *m, int *n,
                          FILE *err)
{
    const char *p = raw;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (ccp_parse_line(p, len, m, n, err))
            return 2;
        p += len + (nl ? 1 : 0);
    }
    return 0;
}

/* The script's `echo "$MEAS_RAW" | tail -20`: the last 20 lines of the raw
 * output, each newline terminated. */
static void ccp_tail20(FILE *err, const char *raw)
{
    size_t lines = 1;
    for (const char *p = raw; *p; p++)
        if (*p == '\n')
            lines++;
    const char *p = raw;
    for (size_t skip = lines > 20 ? lines - 20 : 0; skip > 0; skip--)
        p = strchr(p, '\n') + 1;
    fprintf(err, "%s\n", p);
}

static int ccp_no_rows(FILE *err, const char *raw)
{
    fputs("FATAL: bench produced no CRYPTOPERF rows "
          "(teeth refused everything?)\n", err);
    ccp_tail20(err, raw);
    return 1;
}

static const struct ccp_meas *ccp_find(const struct ccp_meas *m, int n,
                                       const char *key)
{
    for (int i = 0; i < n; i++)
        if (strcmp(m[i].key, key) == 0)
            return &m[i];
    return NULL;
}

struct ccp_gate {
    const struct ccp_meas *m;
    int nmeas;
    const char *margin;
    int fails, skipped, behind, measured;
    FILE *out;
    FILE *err;
};

static void ccp_row_out(FILE *out, const char *prim, const char *m,
                        const char *rust, const char *ratio, const char *mode,
                        const char *tag)
{
    fprintf(out, "%-26s %12s %12s %8s %-8s %s\n", prim, m, rust, ratio, mode,
            tag);
}

/* One baseline row: measured, or SKIP when the bench did not emit it. */
static int ccp_base_eval(struct ccp_gate *g, char **f)
{
    const char *prim = f[0], *cbase = f[1], *rust = f[2], *mode = f[3];
    const struct ccp_meas *me = ccp_find(g->m, g->nmeas, prim);
    if (!me || me->ns[0] == '\0') {
        ccp_row_out(g->out, prim, "-", rust, "-", mode,
                    "SKIP (not measured — params absent?)");
        g->skipped++;
        return 0;
    }
    g->measured++;
    char ratio[CCP_NUM];
    int v = ccp_eval_row(me->ns, cbase, rust, mode, g->margin, ratio,
                         sizeof ratio);
    if (v < 0)
        return 2;
    ccp_row_out(g->out, prim, me->ns, rust, ratio, mode, ccp_verdict_tag(v));
    if (v == CCP_OK_BEHIND) {
        g->behind++;
        fprintf(g->out, "    BEHIND RUST — optimize %s (ratio %sx; %s)\n",
                prim, ratio, f[4]);
    } else if (v != CCP_OK_BEAT) {
        g->fails++;
    }
    return 0;
}

/* Splits a baseline line on commas as `IFS=, read` did: fields 0-4 are
 * primitive, cbase, rust, mode and rust_source; the rest is notes. */
static void ccp_split(char *buf, char **f)
{
    size_t i = 0;
    f[0] = buf;
    for (char *c = buf; *c && i < 5; c++) {
        if (*c == ',') {
            *c = '\0';
            f[++i] = c + 1;
        }
    }
    for (size_t j = i + 1; j < 5; j++)
        f[j] = "";
}

/* A non-numeric c_ns or rust_ns is fatal here, wherever the row sits. The
 * script's awk only printed a diagnostic there and could still pass. */
static int ccp_base_check(FILE *err, const char *line, size_t len,
                          char **f)
{
    if (ccp_is_number(f[1]) && ccp_is_number(f[2]))
        return 0;
    fprintf(err, "%s: malformed baseline row (c_ns and rust_ns must be "
            "numbers): %.*s\n", k_ccp_gate, (int)len, line);
    return 2;
}

static int ccp_base_row(void *ctx, const char *line, size_t len)
{
    struct ccp_gate *g = ctx;
    char buf[CCP_LINE];
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len >= sizeof buf) {
        fprintf(g->err, "%s: baseline line exceeds %d bytes\n", k_ccp_gate,
                CCP_LINE);
        return 2;
    }
    memcpy(buf, line, len);
    buf[len] = '\0';
    char *f[6];
    ccp_split(buf, f);
    if (f[0][0] == '\0' || f[0][0] == '#' || strcmp(f[0], "primitive") == 0)
        return 0;
    if (ccp_base_check(g->err, line, len, f))
        return 2;
    return ccp_base_eval(g, f);
}

static int ccp_table(const struct ccp_opts *o, const struct ccp_meas *meas,
                     int nmeas)
{
    fprintf(o->out, "\n%-26s %12s %12s %8s %-8s %s\n", "primitive", "c_ns",
            "rust_ns", "ratio", "mode", "verdict");
    fprintf(o->out, "%s\n", k_ccp_dashes);
    struct ccp_gate g = { .m = meas, .nmeas = nmeas, .margin = o->margin,
                          .out = o->out, .err = o->err };
    int rc = lc_each_line(o->baseline, ccp_base_row, &g, 1);
    if (rc)
        return rc == 1 ? 2 : rc;
    fprintf(o->out, "%s\n", k_ccp_dashes);
    fprintf(o->out, "measured=%d  behind=%d  skipped=%d  fails=%d  "
            "(margin=%s)\n", g.measured, g.behind, g.skipped, g.fails,
            o->margin);
    if (g.fails) {
        fprintf(o->out, "%s: FAIL — %d primitive(s) violated the ratchet or "
                "lost the lead.\n", k_ccp_gate, g.fails);
        return 1;
    }
    fprintf(o->out, "%s: OK — no self-regression, no lost lead. Behind-rust "
            "rows are ratchet-tracked.\n", k_ccp_gate);
    return 0;
}

int ccp_core(const struct ccp_opts *o)
{
    if (!lct_readable(o->baseline) || lintc_is_dir(o->baseline)) {
        fprintf(o->err, "baseline not found: %s\n", o->baseline);
        return 2;
    }
    if (!o->bench_file && access(o->binary, X_OK) != 0) {
        fprintf(o->err, "binary not found/executable: %s "
                "(build first: make zclassic23)\n", o->binary);
        return 2;
    }
    fprintf(o->out, "crypto-perf gate: measuring %s (margin=%s, history=%s)\n",
            o->binary, o->margin, o->history);
    static char raw[CCP_RAW];
    size_t len = 0;
    int rc = ccp_bench_raw(o, raw, sizeof raw, &len);
    if (rc)
        return rc;
    struct ccp_meas meas[CCP_KEYS];
    int nmeas = 0;
    rc = ccp_parse_meas(raw, meas, &nmeas, o->err);
    if (rc)
        return rc;
    if (nmeas == 0)
        return ccp_no_rows(o->err, raw);
    return ccp_table(o, meas, nmeas);
}

int check_crypto_perf_run(int argc, char **argv)
{
    struct ccp_opts o = {
        .binary = ccp_or(getenv("ZCL_CRYPTO_PERF_BIN"), "build/bin/zclassic23"),
        .baseline = ccp_or(getenv("ZCL_CRYPTO_PERF_BASELINE"),
                           "tools/crypto_perf_baseline.csv"),
        .margin = ccp_or(getenv("ZCL_CRYPTO_PERF_MARGIN"), "0.20"),
        .history = ccp_or(getenv("ZCL_BENCH_HISTORY"), "docs/bench-history.csv"),
        .out = stdout,
        .err = stderr,
    };
    int selftest = 0;
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--selftest") == 0)
            selftest = 1;
        else if (strncmp(a, "--margin=", 9) == 0)
            o.margin = a + 9;
        else if (strncmp(a, "--binary=", 9) == 0)
            o.binary = a + 9;
        else if (strncmp(a, "--baseline=", 11) == 0)
            o.baseline = a + 11;
        else if (strncmp(a, "--history=", 10) == 0)
            o.history = a + 10;
        else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            ccp_usage(stdout);
            return 0;
        } else {
            fprintf(stderr, "unknown arg: %s\n", a);
            return 2;
        }
    }
    if (selftest)
        return check_crypto_perf_selftest();
    return ccp_core(&o);
}
