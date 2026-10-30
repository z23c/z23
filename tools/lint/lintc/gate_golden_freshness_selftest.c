/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-golden-freshness
 * (gate_golden_freshness.c). Builds fixture copies of the three generated
 * golden-table files under a scratch dir and drives gf_check_root with the
 * ZCL_GOLDEN_FRESHNESS* env knobs forced per case: env unset SKIP rc 0;
 * placeholder tables (count 0, no ladder rows, dense -1) SKIP rc 0; forced
 * tip under the lag ceiling PASS rc 0; forced tip over the ceiling FAIL
 * rc 1; missing table files SKIP rc 0 (the script's defaults); a
 * non-numeric LAG_MAX rc 2. The live-node path (lcp_run spawn) is not
 * exercised here — ZCL_GOLDEN_FRESHNESS_TIP forces the tip instead.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "lintc_text.h"
#include "gate_golden_freshness_priv.h"

enum { GFS_PATH = 1024 };

static const char k_gfs_sha3_src[] = "core/modules/chain/src/sha3_windows.c";
static const char k_gfs_sha3_hdr[] =
    "core/modules/chain/include/chain/sha3_windows.h";
static const char k_gfs_ladder_src[] =
    "core/modules/chain/src/utxo_root_ladder.c";

enum gfs_fixture { GFS_NONE = 0, GFS_PLACEHOLDER, GFS_FRESH };

struct gfs_case {
    const char *name;
    int enable;    /* 1 sets ZCL_GOLDEN_FRESHNESS=1 */
    int fixture;   /* gfs_fixture */
    const char *tip;
    const char *lag_max;
    int want;
};

/* Order matters: the no-files case runs before any fixture is written, so
 * the scratch root still has no table files when it runs. */
static const struct gfs_case k_gfs_cases[] = {
    { "env unset skips", 0, GFS_NONE, NULL, NULL, 0 },
    { "missing tables skip like the script", 1, GFS_NONE, "11000", "2000", 0 },
    { "placeholder tables skip", 1, GFS_PLACEHOLDER, NULL, NULL, 0 },
    { "lag under the ceiling passes", 1, GFS_FRESH, "11000", "2000", 0 },
    { "lag over the ceiling fails", 1, GFS_FRESH, "90000", "100", 1 },
    { "non-numeric LAG_MAX is fatal", 1, GFS_FRESH, "11000", "abc", 2 },
};

static int gfs_write_rel(const char *root, const char *rel, const char *text)
{
    char path[GFS_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    return csr_write(path, text);
}

static int gfs_write_fixture(const char *root, int fixture)
{
    if (fixture == GFS_NONE)
        return 0;
    const char *cnt = fixture == GFS_PLACEHOLDER
                          ? "const unsigned long g_sha3_windows_count = 0;\n"
                          : "const unsigned long g_sha3_windows_count = 10;\n";
    int rc = gfs_write_rel(root, k_gfs_sha3_src, cnt);
    if (rc == 0)
        rc = gfs_write_rel(root, k_gfs_sha3_hdr,
                           "#define SHA3_WINDOW_SIZE 1000\n");
    if (rc != 0)
        return rc;
    if (fixture == GFS_PLACEHOLDER)
        return gfs_write_rel(root, k_gfs_ladder_src,
                             "const int g_utxo_root_ladder_dense_height = "
                             "-1;\n");
    return gfs_write_rel(root, k_gfs_ladder_src,
                         "const int g_utxo_root_ladder_dense_height = 9000;\n"
                         "{ 9500, \"aa\", \"bb\" },\n");
}

static void gfs_clear_env(void)
{
    unsetenv("ZCL_GOLDEN_FRESHNESS");
    unsetenv("ZCL_GOLDEN_FRESHNESS_LAG_MAX");
    unsetenv("ZCL_GOLDEN_FRESHNESS_TIP");
    unsetenv("ZCL_CLI");
}

static int gfs_run_case(const char *root, const struct gfs_case *c)
{
    gfs_clear_env();
    if (c->enable && setenv("ZCL_GOLDEN_FRESHNESS", "1", 1))
        return die("z23-lint: setenv failed\n", "");
    if (c->tip && setenv("ZCL_GOLDEN_FRESHNESS_TIP", c->tip, 1))
        return die("z23-lint: setenv failed\n", "");
    if (c->lag_max &&
        setenv("ZCL_GOLDEN_FRESHNESS_LAG_MAX", c->lag_max, 1))
        return die("z23-lint: setenv failed\n", "");
    int rc = gfs_write_fixture(root, c->fixture);
    if (rc)
        return rc;
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    int got = gf_check_root(root, sink);
    fclose(sink);
    if (got != c->want) {
        fprintf(stderr, "check-golden-freshness selftest: %s: want rc=%d "
                "got rc=%d\n", c->name, c->want, got);
        return 1;
    }
    printf("  selftest ok: %s (rc=%d)\n", c->name, got);
    return 0;
}

int check_golden_freshness_selftest(void)
{
    char root[GFS_PATH];
    int rc = lct_scratch_dir(root, sizeof root, "golden-freshness");
    if (rc)
        return rc;
    int bad = 0;
    for (size_t i = 0; i < sizeof k_gfs_cases / sizeof k_gfs_cases[0]; i++)
        bad |= gfs_run_case(root, &k_gfs_cases[i]) != 0;
    gfs_clear_env();
    rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check_golden_freshness selftest\n", stderr);
    return st_ok(bad, "check-golden-freshness selftest: OK\n");
}
