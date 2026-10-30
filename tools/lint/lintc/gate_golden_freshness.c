/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-golden-freshness — golden-table tip-coverage-lag
 * check (item 2b of the golden immutable-history evidence wiring lane).
 * Ported from tools/scripts/check_golden_freshness.sh (deleted).
 * Selftest: gate_golden_freshness_selftest.c.
 *
 * test_golden_staleness_canary catches a REGRESSION that silently drops
 * entries from the compiled SHA3 window table / UTXO root ladder; it cannot
 * catch the tables simply never being re-minted while the real chain grows.
 * This gate compares the highest height the compiled tables corroborate
 * against the REAL current chain tip via the zclassic-cli RPC — nightly
 * only (make simnet-nightly step 6), never hermetic CI. Env-gated OFF by
 * default (ZCL_GOLDEN_FRESHNESS=1) so a dev box with no live node is a
 * clean SKIP.
 *
 * Parses the three generated golden-table files as text and reads the tip
 * with: timeout 5 $ZCL_CLI -datadir=.. -rpcport=.. getblockcount (spawned
 * via lcp_run, never a shell). Like the shell's "|| true", stdout is kept
 * whatever the exit; an empty or non-digit reply is the same SKIP. A
 * missing table file scans as empty,
 * taking the script's defaults. A non-numeric or negative
 * ZCL_GOLDEN_FRESHNESS_LAG_MAX is fatal (rc 2). The shell hands it to
 * `[ -gt ]`: non-numeric prints a false PASS after a bash integer error,
 * and a negative value is accepted. Both are deliberate fail-closed
 * differences, kept and reported.
 *
 * Exit codes: 0 SKIP/PASS, 1 FAIL, 2 fatal. All SKIP/PASS/FAIL lines are
 * byte-identical to the shell original (em dashes included).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_text.h"
#include "lintc_proc.h"
#include "lintc_sig.h"
#include "gate_golden_freshness_priv.h"

enum {
    GF_PATH = 1024,
    GF_TIP = 128,
    GF_PORT = 64,
    GF_ARG = GF_PATH,
    GF_GRACE_MS = 1000
};

static const char k_gf_gate[] = "check-golden-freshness";
static const char k_gf_sha3_src[] = "core/modules/chain/src/sha3_windows.c";
static const char k_gf_sha3_hdr[] =
    "core/modules/chain/include/chain/sha3_windows.h";
static const char k_gf_ladder_src[] = "core/modules/chain/src/utxo_root_ladder.c";

/* Parses an optionally-negative decimal immediately after needle in line.
 * Returns 1 and sets *out on success, 0 otherwise. Overflow returns 0. */
static int gf_num_after(const char *line, const char *needle, int allow_neg,
                        long *out)
{
    const char *p = strstr(line, needle);
    if (!p)
        return 0;
    p += strlen(needle);
    int neg = 0;
    if (allow_neg && *p == '-') {
        neg = 1;
        p++;
    }
    if (*p < '0' || *p > '9')
        return 0;
    long v = 0;
    while (*p >= '0' && *p <= '9') {
        if (v > (LONG_MAX - (*p - '0')) / 10)
            return 0;
        v = v * 10 + (*p - '0');
        p++;
    }
    *out = neg ? -v : v;
    return 1;
}

static int gf_digits_long(const char *s, long *out)
{
    if (!lct_is_digits(s))
        return 0;
    long v = 0;
    for (; *s; s++) {
        if (v > (LONG_MAX - (*s - '0')) / 10)
            return 0;
        v = v * 10 + (*s - '0');
    }
    *out = v;
    return 1;
}

/* First-match scan (the shell's sed | head -1). */
struct gf_num_scan {
    const char *needle;
    int allow_neg;
    int found;
    long value;
};

static int gf_num_line(void *ctx, const char *line, size_t len)
{
    struct gf_num_scan *s = ctx;
    (void)len;
    long v;
    if (!s->found && gf_num_after(line, s->needle, s->allow_neg, &v)) {
        s->found = 1;
        s->value = v;
    }
    return 0;
}

/* Ladder-row scan: rows that open with blanks, a brace, blanks and digits;
 * tracks the max leading height (the shell's grep -oE pair in a loop). */
struct gf_ladder_scan {
    long max;
};

/* Leading height of a ladder row (blanks, brace, blanks, digits); 1 with
 * *out set on a match, 0 otherwise (overflow counts as no match). */
static int gf_ladder_height(const char *line, size_t len, long *out)
{
    size_t i = 0;
    while (i < len && (line[i] == ' ' || line[i] == '\t'))
        i++;
    if (i >= len || line[i] != '{')
        return 0;
    i++;
    while (i < len && line[i] == ' ')
        i++;
    if (i >= len || line[i] < '0' || line[i] > '9')
        return 0;
    long v = 0;
    while (i < len && line[i] >= '0' && line[i] <= '9') {
        if (v > (LONG_MAX - (line[i] - '0')) / 10)
            return 0;
        v = v * 10 + (line[i] - '0');
        i++;
    }
    *out = v;
    return 1;
}

static int gf_ladder_line(void *ctx, const char *line, size_t len)
{
    struct gf_ladder_scan *s = ctx;
    long v;
    if (gf_ladder_height(line, len, &v) && v > s->max)
        s->max = v;
    return 0;
}

/* A missing or unreadable table scans as empty, like the script's
 * sed/grep under `|| true`, so its declarations keep their defaults. */
static void gf_read_table(const char *root, const char *rel,
                          int (*cb)(void *, const char *, size_t), void *ctx)
{
    char path[GF_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return;
    (void)lc_each_line(path, cb, ctx, 1);
}

/* Highest height either golden table corroborates. The script's defaults:
 * count 0, window 1000, dense height -1. */
static int gf_golden_max(const char *root, long *out)
{
    struct gf_num_scan cnt = { "g_sha3_windows_count = ", 0, 0, 0 };
    struct gf_num_scan win = { "#define SHA3_WINDOW_SIZE ", 0, 0, 1000 };
    struct gf_num_scan dense = { "g_utxo_root_ladder_dense_height = ", 1, 0,
                                 -1 };
    struct gf_ladder_scan lad = { -1 };
    gf_read_table(root, k_gf_sha3_src, gf_num_line, &cnt);
    gf_read_table(root, k_gf_sha3_hdr, gf_num_line, &win);
    gf_read_table(root, k_gf_ladder_src, gf_ladder_line, &lad);
    gf_read_table(root, k_gf_ladder_src, gf_num_line, &dense);
    long sha3_max = -1;
    if (cnt.value > 0) {
        if (win.value > 0 && cnt.value > LONG_MAX / win.value)
            return 2;
        sha3_max = cnt.value * win.value - 1;
    }
    long ladder_max = lad.max;
    if (dense.value > ladder_max)
        ladder_max = dense.value;
    *out = sha3_max > ladder_max ? sha3_max : ladder_max;
    return 0;
}

static int gf_lag_max(long *out)
{
    const char *s = getenv("ZCL_GOLDEN_FRESHNESS_LAG_MAX");
    if (!s || !*s) {
        *out = 70000;
        return 0;
    }
    if (!gf_digits_long(s, out)) {
        fprintf(stderr, "%s: unparsable ZCL_GOLDEN_FRESHNESS_LAG_MAX\n",
                k_gf_gate);
        return 2;
    }
    return 0;
}

static int gf_rpc_defaults(char *dd, size_t ddc, char *port, size_t pc)
{
    const char *d = getenv("ZCL_GOLDEN_FRESHNESS_DATADIR");
    int n;
    if (d && *d)
        n = snprintf(dd, ddc, "%s", d);
    else
        n = snprintf(dd, ddc, "%s/.zclassic-c23", env_or("HOME", ""));
    if (ovf(n, ddc))
        return 2;
    const char *p = getenv("ZCL_GOLDEN_FRESHNESS_RPCPORT");
    n = snprintf(port, pc, "%s", (p && *p) ? p : "18232");
    if (ovf(n, pc))
        return 2;
    return 0;
}

/* Stores a validated numeric tip (string + value). 0 ok, 1 not numeric. */
static int gf_store_tip(const char *s, char *tip, size_t cap, long *val)
{
    if (!gf_digits_long(s, val))
        return 1;
    if (ovf(snprintf(tip, cap, "%s", s), cap))
        return 2;
    return 0;
}

/* Live-node tip via timeout 5 $ZCL_CLI ... getblockcount (lcp_run, no
 * shell). Returns 0 with the tip stored, 1 = no usable reply (SKIP), 2
 * fatal. */
static int gf_cli_tip(char *tip, size_t cap, long *val)
{
    const char *cli = env_or("ZCL_CLI", "build/bin/zclassic-cli");
    if (access(cli, X_OK) != 0)
        return 1;
    char dd[GF_PATH], port[GF_PORT], arg_dd[GF_ARG], arg_rp[GF_ARG];
    if (gf_rpc_defaults(dd, sizeof dd, port, sizeof port))
        return 2;
    if (ovf(snprintf(arg_dd, sizeof arg_dd, "-datadir=%s", dd), sizeof arg_dd))
        return 2;
    if (ovf(snprintf(arg_rp, sizeof arg_rp, "-rpcport=%s", port),
             sizeof arg_rp))
        return 2;
    char *av[7] = { (char *)"timeout", (char *)"5", (char *)cli, arg_dd,
                    arg_rp, (char *)"getblockcount", NULL };
    struct lcp_spec sp = { .argv = av, .mode = LCP_OUT, .grace_ms = GF_GRACE_MS };
    struct lcp_buf bo = { 0 };
    int code = 0;
    int rc = lcp_run(&sp, &bo, &code);
    int ok = 0;
    if (rc == 0) {
        /* The script's $(... || true) keeps stdout whatever the exit. */
        lcp_buf_subst(&bo);
        if (bo.data && lct_is_digits(bo.data))
            ok = gf_store_tip(bo.data, tip, cap, val) == 0;
    }
    lcp_buf_free(&bo);
    return ok ? 0 : 1;
}

static int gf_get_tip(char *tip, size_t cap, long *val)
{
    const char *e = getenv("ZCL_GOLDEN_FRESHNESS_TIP");
    if (e && *e)
        return gf_store_tip(e, tip, cap, val) == 1 ? 1 : 0;
    return gf_cli_tip(tip, cap, val);
}

int gf_check_root(const char *root, FILE *out)
{
    const char *on = getenv("ZCL_GOLDEN_FRESHNESS");
    if (!on || strcmp(on, "1") != 0) {
        fprintf(out, "golden_freshness: SKIP (set ZCL_GOLDEN_FRESHNESS=1 to "
                     "run — nightly-only, pages golden-table tip-coverage "
                     "decay)\n");
        return 0;
    }
    long lag_max;
    if (gf_lag_max(&lag_max))
        return 2;
    long golden_max;
    int rc = gf_golden_max(root, &golden_max);
    if (rc)
        return rc;
    if (golden_max < 0) {
        fprintf(out, "golden_freshness: SKIP (no golden coverage compiled in "
                     "— placeholder tables, nothing to check yet)\n");
        return 0;
    }
    char tip[GF_TIP];
    long tipv = 0;
    if (gf_get_tip(tip, sizeof tip, &tipv) != 0) {
        char dd[GF_PATH], port[GF_PORT];
        if (gf_rpc_defaults(dd, sizeof dd, port, sizeof port))
            return 2;
        fprintf(out, "golden_freshness: SKIP (no live node reachable at "
                     "%s:%s to read the current chain tip — set "
                     "ZCL_GOLDEN_FRESHNESS_TIP=<height> to force a check "
                     "without one)\n", dd, port);
        return 0;
    }
    long lag = tipv - golden_max;
    fprintf(out, "golden_freshness: tip=%s golden_covered_max=%ld lag=%ld "
                 "(fail-over=%ld)\n", tip, golden_max, lag, lag_max);
    if (lag > lag_max) {
        fprintf(out, "==> golden_freshness FAILED (golden tables are %ld "
                     "blocks behind the live tip, over the %ld-block ceiling "
                     "— re-mint tools/gen_sha3_windows and/or "
                     "tools/gen_utxo_root_ladder)\n", lag, lag_max);
        return 1;
    }
    fprintf(out, "==> golden_freshness PASSED\n");
    return 0;
}

int check_golden_freshness_run(int argc, char **argv)
{
    const char *root = argc >= 1 ? argv[0] : ".";
    if (lsc_install() != 0)
        return die("z23-lint: cannot install signal handlers\n", "");
    int rc = gf_check_root(root, stdout);
    fflush(stdout);
    int sig = lsc_pending();
    if (sig)
        lsc_finish(sig);
    return rc;
}
