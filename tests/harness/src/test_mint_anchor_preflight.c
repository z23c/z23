/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_mint_anchor_preflight — proves boot_mint_anchor_preflight_run_all()
 * (engine/composition/src/boot_mint_anchor_preflight.c) names EVERY unmet -mint-anchor
 * producer precondition in ONE call instead of the historical one-FATAL-at-
 * a-time surfacing (missing legacy block index -> FATAL on one run; missing
 * bodies -> silent stall on the next).
 *
 *   (a) a fresh empty datadir reports AT LEAST the legacy-block-index and
 *       bodies-present holes in ONE run_all call (both named, both ok=false,
 *       and run_all itself returns false).
 *   (b) a datadir built to satisfy every check returns true with every
 *       table entry ok=true.
 *   (c) every table entry (pass or fail) carries a non-empty remedy string.
 *
 * Uses checkpoints_set_sha3_override_for_test to pin a tiny anchor height (5)
 * so the fixture datadir does not need a multi-million-row block index. */

#include "test/test_core.h"

#include "chain/checkpoints.h"
#include "config/boot.h"
#include "json/json.h"
#include "models/database.h"
#include "services/disk_monitor.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAP_CHECK(name, expr) do { \
    printf("mint_anchor_preflight: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static int mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* Remove the <dir>/blocks subdirectory + <dir>/node.db family +
 * test_cleanup_tmpdir's plain top-level sweep — test_cleanup_tmpdir alone
 * does not descend into subdirectories. */
static void map_cleanup_dir(const char *dir)
{
    char blocks_dir[600], blk[700];
    snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks", dir);
    snprintf(blk, sizeof(blk), "%s/blk00000.dat", blocks_dir);
    unlink(blk);
    rmdir(blocks_dir);
    test_cleanup_tmpdir(dir);
}

static const struct json_value *map_find_check(const struct json_value *report,
                                                const char *name)
{
    const struct json_value *checks = json_get(report, "checks");
    if (!checks)
        return NULL;
    for (size_t i = 0; i < json_size(checks); i++) {
        const struct json_value *row = json_at(checks, i);
        const struct json_value *row_name = row ? json_get(row, "name") : NULL;
        const char *n = row_name ? json_get_str(row_name) : NULL;
        if (n && strcmp(n, name) == 0)
            return row;
    }
    return NULL;
}

static bool map_check_ok(const struct json_value *report, const char *name)
{
    const struct json_value *row = map_find_check(report, name);
    const struct json_value *ok = row ? json_get(row, "ok") : NULL;
    return ok && json_get_bool(ok);
}

static bool map_check_has_remedy(const struct json_value *row)
{
    const struct json_value *remedy = row ? json_get(row, "remedy") : NULL;
    const char *r = remedy ? json_get_str(remedy) : NULL;
    return r && r[0] != '\0';
}

static int test_preflight_fresh_datadir_names_all_holes(void)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "mint_anchor_preflight", "fresh");
    mkdir_p("./test-tmp");
    mkdir_p(dir);

    /* Hermetic: the bodies check falls back to the legacy zclassicd source
     * ($HOME/.zclassic/blocks) which EXISTS on a dev box — point it at an
     * empty dir so "fresh datadir" means fresh everywhere. */
    char empty_legacy[300];
    snprintf(empty_legacy, sizeof(empty_legacy), "%s/empty-legacy", dir);
    mkdir_p(empty_legacy);
    setenv("ZCL_MINT_PREFLIGHT_LEGACY_BLOCKS_DIR", empty_legacy, 1);

    struct json_value report;
    json_init(&report);
    bool all_ok = boot_mint_anchor_preflight_run_all(dir, &report);
    unsetenv("ZCL_MINT_PREFLIGHT_LEGACY_BLOCKS_DIR");
    MAP_CHECK("fresh datadir: run_all returns false", !all_ok);
    MAP_CHECK("fresh datadir: report has all_ok=false",
              json_get(&report, "all_ok") &&
              !json_get_bool(json_get(&report, "all_ok")));
    MAP_CHECK("fresh datadir: legacy_block_index_covers_anchor named and failed",
              map_find_check(&report, "legacy_block_index_covers_anchor") &&
              !map_check_ok(&report, "legacy_block_index_covers_anchor"));
    MAP_CHECK("fresh datadir: bodies_present_sampled named and failed",
              map_find_check(&report, "bodies_present_sampled") &&
              !map_check_ok(&report, "bodies_present_sampled"));
    /* Both holes surfaced in the SAME call — the whole point of run_all. */
    MAP_CHECK("fresh datadir: both holes surfaced together (no short-circuit)",
              !map_check_ok(&report, "legacy_block_index_covers_anchor") &&
              !map_check_ok(&report, "bodies_present_sampled"));

    json_free(&report);
    map_cleanup_dir(dir);
    return failures;
}

/* Build a node.db `blocks` row at height >= the (overridden) anchor and a
 * non-trivial blk00000.dat so every check passes. */
static bool map_build_passing_fixture(const char *dir)
{
    if (mkdir_p("./test-tmp") != 0 || mkdir_p(dir) != 0)
        return false;

    char blocks_dir[600];
    snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks", dir);
    if (mkdir_p(blocks_dir) != 0)
        return false;

    char blk[700];
    snprintf(blk, sizeof(blk), "%s/blk00000.dat", blocks_dir);
    FILE *f = fopen(blk, "wb");
    if (!f)
        return false;
    uint8_t pad[4096] = {0};
    bool wrote = fwrite(pad, 1, sizeof(pad), f) == sizeof(pad);
    fclose(f);
    if (!wrote)
        return false;

    char node_db_path[700];
    snprintf(node_db_path, sizeof(node_db_path), "%s/node.db", dir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, node_db_path))
        return false;
    bool ok = node_db_exec(&ndb,
        "INSERT INTO blocks(hash,height,prev_hash,version,merkle_root,time,"
        "bits,nonce,solution,chain_work) VALUES "
        "(X'01',5,X'00',1,X'00',0,0,X'00',X'00',X'00')");
    node_db_close(&ndb);
    return ok;
}

static int test_preflight_passing_datadir_all_ok(void)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "mint_anchor_preflight", "passing");

    struct sha3_utxo_checkpoint cp;
    memset(&cp, 0, sizeof(cp));
    cp.height = 5;
    cp.utxo_count = 1;
    cp.total_supply = 1;
    checkpoints_set_sha3_override_for_test(&cp);

    MAP_CHECK("passing datadir: fixture builds", map_build_passing_fixture(dir));

    struct json_value report;
    json_init(&report);
    disk_monitor_set_free_bytes_for_test((int64_t)200 << 30);
    bool all_ok = boot_mint_anchor_preflight_run_all(dir, &report);
    disk_monitor_set_free_bytes_for_test(-1);
    MAP_CHECK("passing datadir: run_all returns true", all_ok);
    const struct json_value *checks = json_get(&report, "checks");
    MAP_CHECK("passing datadir: checks array present", checks != NULL);
    bool every_ok = checks != NULL;
    size_t n = checks ? json_size(checks) : 0;
    MAP_CHECK("passing datadir: at least one check ran", n > 0);
    for (size_t i = 0; i < n; i++) {
        const struct json_value *row = json_at(checks, i);
        const struct json_value *ok = row ? json_get(row, "ok") : NULL;
        if (!ok || !json_get_bool(ok))
            every_ok = false;
    }
    MAP_CHECK("passing datadir: every table entry ok=true", every_ok);

    json_free(&report);
    checkpoints_reset_sha3_override_for_test();
    map_cleanup_dir(dir);
    return failures;
}

static int test_preflight_every_entry_has_remedy(void)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "mint_anchor_preflight", "remedy");
    mkdir_p("./test-tmp");
    mkdir_p(dir);

    struct json_value report;
    json_init(&report);
    (void)boot_mint_anchor_preflight_run_all(dir, &report);
    const struct json_value *checks = json_get(&report, "checks");
    MAP_CHECK("remedy: checks array present", checks != NULL);
    size_t n = checks ? json_size(checks) : 0;
    MAP_CHECK("remedy: at least one check ran", n > 0);
    bool all_have_remedy = checks != NULL;
    for (size_t i = 0; i < n; i++) {
        const struct json_value *row = json_at(checks, i);
        if (!map_check_has_remedy(row))
            all_have_remedy = false;
    }
    MAP_CHECK("remedy: every table entry (pass or fail) has a non-empty remedy",
              all_have_remedy);

    json_free(&report);
    map_cleanup_dir(dir);
    return failures;
}

static int test_preflight_dumpstate_reflects_last_run(void)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "mint_anchor_preflight", "dumpstate");
    mkdir_p("./test-tmp");
    mkdir_p(dir);

    (void)boot_mint_anchor_preflight_run_all(dir, NULL);

    struct json_value state;
    json_init(&state);
    bool dumped = boot_mint_anchor_preflight_dump_state_json(&state, NULL);
    MAP_CHECK("dumpstate: dump function succeeds", dumped);
    const struct json_value *have_report = json_get(&state, "have_report");
    MAP_CHECK("dumpstate: have_report is true after a run",
              have_report && json_get_bool(have_report));
    MAP_CHECK("dumpstate: reflects the failing last run (all_ok=false)",
              json_get(&state, "all_ok") &&
              !json_get_bool(json_get(&state, "all_ok")));
    MAP_CHECK("dumpstate: checks array present",
              json_get(&state, "checks") != NULL);

    json_free(&state);
    map_cleanup_dir(dir);
    return failures;
}

int test_mint_anchor_preflight(void);
int test_mint_anchor_preflight(void)
{
    int failures = 0;
    printf("\n=== test_mint_anchor_preflight: ONE preflight names ALL unmet "
           "-mint-anchor preconditions ===\n");

    failures += test_preflight_fresh_datadir_names_all_holes();
    failures += test_preflight_passing_datadir_all_ok();
    failures += test_preflight_every_entry_has_remedy();
    failures += test_preflight_dumpstate_reflects_last_run();

    printf("=== test_mint_anchor_preflight complete: %d failure(s) ===\n",
           failures);
    return failures;
}
