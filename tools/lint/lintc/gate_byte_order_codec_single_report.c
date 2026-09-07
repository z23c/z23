/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: C23 lint gate — check-byte-order-codec-single, part 2: the
 * git-index coverage oracle, the shrink-only baseline ratchet (violation/
 * stale reporting and the ZCL_LINT_MODE=UPDATE regenerate path), and the
 * check_byte_order_codec_single_run() entry point. Detectors and scan-set
 * collection live in gate_byte_order_codec_single.c; the two share their
 * internals through gate_byte_order_codec_single_priv.h.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_byte_order_codec_single_priv.h"

static const char k_bo_baseline_default[] =
    "tools/lint/byte_order_codec_baseline.txt";
static const char k_bo_gate[] = "check_byte_order_codec_single";

struct bo_oracle_ctx {
    const char (*roots)[RS_PATH];
    int nroots;
    struct bo_pathset *set;
};

static int bo_covered_default(const char (*roots)[RS_PATH], int nroots,
                              const char *path)
{
    char pat[RS_PATH + 8];
    int matched = 0;
    for (int i = 0; i < nroots && !matched; i++) {
        if (ovf(snprintf(pat, sizeof pat, "%s/*.c", roots[i]), sizeof pat))
            return -2;
        if (fnmatch(pat, path, 0) == 0)
            matched = 1;
        if (!matched) {
            if (ovf(snprintf(pat, sizeof pat, "%s/*.h", roots[i]), sizeof pat))
                return -2;
            if (fnmatch(pat, path, 0) == 0)
                matched = 1;
        }
    }
    if (!matched)
        return 0;
    return bo_excluded(path) ? 0 : 1;
}

static int bo_oracle_cb(const char *path, int stage, void *vctx)
{
    if (stage != 0)
        return 0;
    struct bo_oracle_ctx *ctx = vctx;
    int c = bo_covered_default(ctx->roots, ctx->nroots, path);
    if (c < 0)
        return 2;
    return c ? bo_pathset_add(ctx->set, path) : 0;
}

static int bo_oracle_build(const char (*def_roots)[RS_PATH], int ndef,
                           struct bo_pathset *oracle, FILE *err)
{
    oracle->n = 0;
    struct bo_oracle_ctx ctx = { .roots = def_roots, .nroots = ndef,
                                 .set = oracle };
    char badext[5] = "";
    int rc = lint_git_index_foreach(bo_oracle_cb, &ctx, badext);
    if (badext[0]) {
        fprintf(err,
               "%s: UNPROVEN — the git index carries a mandatory extension "
               "('%s') this native reader does not interpret; refusing to "
               "grade.\n",
               k_bo_gate, badext);
        return 2;
    }
    if (rc) {
        char spec[8192];
        if (bo_pathspec_msg(def_roots, ndef, spec, sizeof spec))
            return 2;
        fprintf(err,
               "%s: UNPROVEN — the coverage oracle could not run:\n"
               "  'git ls-files -- %s' exited %d.\n"
               "  Without an independent expectation this gate cannot tell a\n"
               "  complete scan from a partial one, so it refuses to grade\n"
               "  either way. Run it from inside the checkout.\n",
               k_bo_gate, spec, 128);
        return 2;
    }
    if (oracle->n == 0) {
        fprintf(err,
               "%s: UNPROVEN — the coverage oracle is empty: git tracks no "
               "matching file.\n",
               k_bo_gate);
        return 2;
    }
    return 0;
}

int bo_coverage_check(const struct bo_pathset *scan, int allowance, FILE *err)
{
    char def_roots[256][RS_PATH];
    int ndef = 0;
    int rc = bo_default_roots(def_roots, 256, &ndef);
    if (rc)
        return rc;
    static struct bo_pathset oracle;
    rc = bo_oracle_build(def_roots, ndef, &oracle, err);
    if (rc)
        return rc;
    int missing = 0;
    for (int i = 0; i < oracle.n; i++) {
        if (!bo_pathset_has(scan, oracle.p[i]))
            missing++;
    }
    if (missing > allowance) {
        fprintf(err,
               "%s: UNPROVEN — the scan reached %d of the %d entries an "
               "independent oracle says it should have reached; %d missing, "
               "above the allowance of %d.\n",
               k_bo_gate, oracle.n - missing, oracle.n, missing, allowance);
        return 2;
    }
    if (missing < allowance) {
        fprintf(err,
               "%s: VIOLATION — the coverage allowance is stale: the scan "
               "now misses only %d of %d expected entries, below the "
               "recorded allowance of %d. Lower it in the same commit.\n",
               k_bo_gate, missing, oracle.n, allowance);
        return 1;
    }
    return 0;
}

static int bo_write_baseline(const char *path, const struct bo_pathset *found)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    int rc = 0;
    if (fputs(
            "# check_byte_order_codec_single baseline — production files "
            "that still pack or unpack a\n"
            "# fixed-width integer by hand instead of calling\n"
            "# platform/modules/base/include/base/serialize_le.h.\n"
            "# One path per line. THE LIST MAY ONLY SHRINK.\n"
            "#\n"
            "# Fix a row by deleting the private helper and calling:\n"
            "#   zcl_write_u16_le/u32_le/u64_le(p, v)   store, LSB at p[0]\n"
            "#   zcl_read_u16_le/u32_le/u64_le(p)       load, LSB at p[0]\n"
            "#   zcl_write_i32_le/i64_le, zcl_read_i32_le/i64_le\n"
            "#   zcl_write_u32_be/u64_be, zcl_read_u32_be/u64_be\n"
            "# then delete the line here. Adding a row is not a fix.\n"
            "# Regenerate: ZCL_LINT_MODE=UPDATE "
            "tools/lint/check_byte_order_codec_single.sh\n",
            f) < 0)
        rc = die("z23-lint: write failed\n", "");
    for (int i = 0; rc == 0 && i < found->n; i++) {
        if (fprintf(f, "%s\n", found->p[i]) < 0)
            rc = die("z23-lint: write failed\n", "");
    }
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int bo_print_sorted(FILE *out, const struct bo_pathset *set)
{
    static struct bo_pathset tmp;
    tmp = *set;
    bo_pathset_sort(&tmp);
    for (int i = 0; i < tmp.n; i++) {
        if (fprintf(out, "  %s\n", tmp.p[i]) < 0)
            return die("z23-lint: write failed\n", "");
    }
    return 0;
}

static int bo_report_violations(FILE *out, const struct bo_pathset *found,
                                const struct bln_set *base,
                                const char *baseline, struct bo_pathset *viol)
{
    viol->n = 0;
    for (int i = 0; i < found->n; i++) {
        if (!bln_has(base, found->p[i])) {
            int rc = bo_pathset_add(viol, found->p[i]);
            if (rc)
                return rc;
        }
    }
    if (viol->n == 0)
        return 0;
    if (fprintf(out,
               "\n[%s] %d file(s) pack or unpack a fixed-width\n"
               "        integer by hand outside platform/modules/base:\n",
               k_bo_gate, viol->n) < 0)
        return die("z23-lint: write failed\n", "");
    int rc = bo_print_sorted(out, viol);
    if (rc)
        return rc;
    if (fprintf(out,
               "\n  Delete it and include \"base/serialize_le.h\" instead:\n"
               "    zcl_write_u16_le(p, v)  zcl_read_u16_le(p)\n"
               "    zcl_write_u32_le(p, v)  zcl_read_u32_le(p)\n"
               "    zcl_write_u64_le(p, v)  zcl_read_u64_le(p)\n"
               "    zcl_write_i32_le/i64_le, zcl_read_i32_le/i64_le  (two's\n"
               "                            complement bits, no extra "
               "encoding)\n"
               "    zcl_write_u32_be/u64_be, zcl_read_u32_be/u64_be  "
               "(network\n"
               "                            order: PNG, BIP32, the SHA/AES "
               "cores)\n"
               "  Unaligned addresses are fine — every access goes through "
               "memcpy.\n"
               "  Adding a row to %s is NOT a fix; the list may only "
               "shrink.\n",
               baseline) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int bo_report_stale(FILE *out, const struct bln_set *base,
                           const struct bo_pathset *found, const char *baseline,
                           int *nstale)
{
    static struct bo_pathset stale;
    stale.n = 0;
    for (int i = 0; i < base->count; i++) {
        if (!bo_pathset_has(found, base->n[i])) {
            int rc = bo_pathset_add(&stale, base->n[i]);
            if (rc)
                return rc;
        }
    }
    *nstale = stale.n;
    if (stale.n == 0)
        return 0;
    if (fprintf(out,
               "\n[%s] %d STALE baseline row(s) — the file no longer\n"
               "        packs an integer by hand. Delete them from %s:\n",
               k_bo_gate, stale.n, baseline) < 0)
        return die("z23-lint: write failed\n", "");
    return bo_print_sorted(out, &stale);
}

static int bo_finish_report(FILE *out, int nviol, int nstale, const char *mode,
                            const struct bo_pathset *scan,
                            const struct bo_pathset *found, int baseline_count)
{
    if ((nviol || nstale) && strcmp(mode, "FAIL") == 0)
        return 1;
    if (fprintf(out, "[%s] PASS (%d files scanned, %d still packing by hand, "
               "all %d baselined)\n",
               k_bo_gate, scan->n, found->n, baseline_count) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int bo_eval_report(const struct bo_pathset *scan,
                          const struct bo_pathset *found, const char *baseline,
                          const char *mode, FILE *out)
{
    struct bln_set base = {0};
    int rc = bln_load(&base, baseline);
    if (rc)
        return rc;
    struct bo_pathset viol;
    rc = bo_report_violations(out, found, &base, baseline, &viol);
    if (rc)
        return rc;
    int nstale = 0;
    rc = bo_report_stale(out, &base, found, baseline, &nstale);
    if (rc)
        return rc;
    return bo_finish_report(out, viol.n, nstale, mode, scan, found,
                            base.count);
}

static int bo_eval_scan(const struct bo_eval_opts *opts, FILE *err,
                        struct bo_pathset *scan, struct bo_pathset *found)
{
    int rc = bo_collect(opts->roots, opts->nroots, scan);
    if (rc)
        return rc;
    rc = gate_require_scanned(scan->n, opts->floor, k_bo_gate,
                              "no production .c/.h under the declared roots");
    if (rc)
        return rc;
    if (opts->coverage) {
        rc = bo_coverage_check(scan, opts->coverage_allowance, err);
        if (rc)
            return rc;
    }
    struct bo_regexes r;
    rc = bo_comp_regexes(&r);
    if (rc)
        return rc;
    rc = bo_find_hits(scan, &r, found);
    bo_drop_regexes(&r);
    return rc;
}

int bo_eval(const struct bo_eval_opts *opts, FILE *out, FILE *err)
{
    static struct bo_pathset scan, found;
    int rc = bo_eval_scan(opts, err, &scan, &found);
    if (rc)
        return rc;
    if (strcmp(opts->mode, "UPDATE") == 0) {
        rc = bo_write_baseline(opts->baseline, &found);
        if (rc)
            return rc;
        if (fprintf(out, "[%s] baseline UPDATED: %s\n", k_bo_gate,
                   opts->baseline) < 0)
            return die("z23-lint: write failed\n", "");
        return 0;
    }
    return bo_eval_report(&scan, &found, opts->baseline, opts->mode, out);
}

static int bo_opts_default(struct bo_eval_opts *opts)
{
    int rc = bo_default_roots(opts->roots, 256, &opts->nroots);
    if (rc)
        return rc;
    const char *scan_roots_env = getenv("ZCL_BYTE_ORDER_SCAN_ROOTS");
    if (scan_roots_env && scan_roots_env[0])
        rc = bo_split_ws(scan_roots_env, opts->roots, 256, &opts->nroots);
    if (rc)
        return rc;
    opts->baseline = env_or("ZCL_BYTE_ORDER_BASELINE", k_bo_baseline_default);
    opts->mode = clock_mode();
    const char *floor_env = getenv("ZCL_BYTE_ORDER_FILE_FLOOR");
    opts->floor = floor_env && floor_env[0] ? atoi(floor_env) : 800;
    const char *cov_env = getenv("ZCL_BYTE_ORDER_COVERAGE");
    opts->coverage = !(cov_env && strcmp(cov_env, "0") == 0);
    const char *allow_env = getenv("ZCL_BYTE_ORDER_COVERAGE_ALLOWANCE");
    opts->coverage_allowance = allow_env && allow_env[0] ? atoi(allow_env) : 0;
    return 0;
}

int check_byte_order_codec_single_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    struct bo_eval_opts opts = {0};
    int rc = bo_opts_default(&opts);
    if (rc)
        return rc;
    return bo_eval(&opts, stdout, stderr);
}
