/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_mint_anchor_preflight — proves boot_mint_anchor_preflight_run_all()
 * (engine/composition/src/boot_mint_anchor_preflight.c) names every unmet -mint-anchor
 * producer precondition in one call.
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
#include "config/mint_anchor_progress.h"
#include "services/disk_monitor.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sqlite3.h>
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


#if !defined(_WIN32)

/* ---- normal-boot producer preflight: live read-only path ---------------- */

struct map_file_state {
    bool exists;
    struct stat st;
    uint64_t hash;
};

static uint64_t map_hash_file(const char *path)
{
    uint64_t h = 1469598103934665603ull;
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    uint8_t buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        for (size_t i = 0; i < n; i++)
            h = (h ^ buf[i]) * 1099511628211ull;
    fclose(f);
    return h;
}

static void map_capture(const char *dir, const char *suffix, struct map_file_state *out)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/consensus.db%s", dir, suffix);
    out->exists = lstat(path, &out->st) == 0;
    out->hash = out->exists ? map_hash_file(path) : 0;
}

static bool map_state_same(const struct map_file_state *a, const struct map_file_state *b)
{
    if (a->exists != b->exists)
        return false;
    return !a->exists ||
           (a->hash == b->hash && a->st.st_ino == b->st.st_ino && a->st.st_size == b->st.st_size &&
            a->st.st_mtim.tv_sec == b->st.st_mtim.tv_sec && a->st.st_mtim.tv_nsec == b->st.st_mtim.tv_nsec &&
            a->st.st_ctim.tv_sec == b->st.st_ctim.tv_sec && a->st.st_ctim.tv_nsec == b->st.st_ctim.tv_nsec);
}

static sqlite3 *map_open_kernel(const char *dir, bool autocheckpoint)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/consensus.db", dir);
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK ||
        sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_exec(db, autocheckpoint ? "PRAGMA wal_autocheckpoint=1000" : "PRAGMA wal_autocheckpoint=0", NULL, NULL,
                     NULL) != SQLITE_OK ||
        sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS progress_meta(key TEXT PRIMARY KEY,value BLOB NOT NULL)", NULL, NULL,
                     NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return NULL;
    }
    return db;
}

static bool map_put_marker(sqlite3 *db, const char *key, const char *hex_value)
{
    char sql[300];
    snprintf(sql, sizeof(sql), "INSERT OR REPLACE INTO progress_meta(key,value) VALUES('%s',X'%s')", key, hex_value);
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

/* Run the preflight and report whether every family file kept its exact
 * bytes, inode, size and mtime/ctime, and no file appeared. */
static bool map_preflight_untouched(const char *dir, bool *verdict)
{
    static const char *const suffixes[] = {"", "-wal", "-shm", "-journal"};
    struct map_file_state before[4], after[4];
    for (size_t i = 0; i < 4; i++)
        map_capture(dir, suffixes[i], &before[i]);
    *verdict = boot_mint_anchor_normal_boot_preflight(dir);
    bool same = true;
    for (size_t i = 0; i < 4; i++) {
        map_capture(dir, suffixes[i], &after[i]);
        same = same && map_state_same(&before[i], &after[i]);
    }
    return same;
}

static int test_normal_preflight_live_verdicts(void)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "mint_anchor_preflight", "live_verdicts");
    mkdir_p("./test-tmp");
    mkdir_p(dir);
    bool verdict = false;

    /* Clean: checkpointed, closed, no -wal/-shm left behind. */
    sqlite3 *db = map_open_kernel(dir, true);
    MAP_CHECK("live: clean fixture builds", db && map_put_marker(db, "ordinary_serving_marker", "01"));
    if (db)
        sqlite3_close(db);
    MAP_CHECK("live: clean datadir is allowed and no byte/mtime changes",
              map_preflight_untouched(dir, &verdict) && verdict);

    /* Empty -wal beside a clean main file takes the live path too. */
    char wal[600];
    snprintf(wal, sizeof(wal), "%s/consensus.db-wal", dir);
    int fd = open(wal, O_CREAT | O_WRONLY, 0600);
    MAP_CHECK("live: empty wal fixture", fd >= 0);
    if (fd >= 0)
        close(fd);
    MAP_CHECK("live: empty wal is allowed and untouched", map_preflight_untouched(dir, &verdict) && verdict);
    unlink(wal);

    /* Marker checkpointed into the main file. */
    db = map_open_kernel(dir, true);
    MAP_CHECK("live: in-progress marker written", db && map_put_marker(db, MINT_ANCHOR_IN_PROGRESS_KEY, "5a414d31"));
    if (db)
        sqlite3_close(db);
    MAP_CHECK("live: in-progress marker is refused and nothing changes",
              map_preflight_untouched(dir, &verdict) && !verdict);

    /* Lane binding instead of the marker. */
    db = map_open_kernel(dir, true);
    MAP_CHECK("live: marker removed, lane bound",
              db && sqlite3_exec(db, "DELETE FROM progress_meta WHERE key='" MINT_ANCHOR_IN_PROGRESS_KEY "'", NULL, NULL,
                                 NULL) == SQLITE_OK &&
                  map_put_marker(db, MINT_ANCHOR_PRODUCER_LANE_KEY, "02"));
    if (db)
        sqlite3_close(db);
    MAP_CHECK("live: bound producer lane is refused and nothing changes",
              map_preflight_untouched(dir, &verdict) && !verdict);

    /* Orphan WAL without a main database (no consensus.db, so the kernel name
     * resolves to the legacy progress.kv family). */
    char main_path[600], orphan[600];
    snprintf(main_path, sizeof(main_path), "%s/consensus.db", dir);
    snprintf(orphan, sizeof(orphan), "%s/progress.kv-wal", dir);
    unlink(main_path);
    unlink(wal);
    fd = open(orphan, O_CREAT | O_WRONLY, 0600);
    MAP_CHECK("live: orphan wal fixture", fd >= 0);
    if (fd >= 0)
        close(fd);
    MAP_CHECK("live: orphan wal without main db is refused", !boot_mint_anchor_normal_boot_preflight(dir));
    unlink(orphan);
    map_cleanup_dir(dir);
    return failures;
}

/* The case that makes the live read-only open unsafe without its guard: the
 * marker is committed only in the -wal (autocheckpoint off, connection still
 * open, so -wal and -shm both exist and the main file has not seen it). */
static int test_normal_preflight_marker_only_in_wal(void)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "mint_anchor_preflight", "wal_only");
    mkdir_p("./test-tmp");
    mkdir_p(dir);
    bool verdict = true;

    sqlite3 *db = map_open_kernel(dir, false);
    bool seeded = db && sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)", NULL, NULL, NULL) == SQLITE_OK &&
                  map_put_marker(db, MINT_ANCHOR_IN_PROGRESS_KEY, "5a414d31");
    MAP_CHECK("wal-only: marker committed to the WAL", seeded);
    struct map_file_state wal_state;
    map_capture(dir, "-wal", &wal_state);
    MAP_CHECK("wal-only: -wal holds frames, main file does not have the marker", wal_state.exists && wal_state.st.st_size > 0);
    MAP_CHECK("wal-only: marker seen in the WAL is refused, nothing changes",
              map_preflight_untouched(dir, &verdict) && !verdict);
    if (db)
        sqlite3_close(db);
    map_cleanup_dir(dir);
    return failures;
}


#endif /* !_WIN32 */

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
#if !defined(_WIN32)
    failures += test_normal_preflight_live_verdicts();
    failures += test_normal_preflight_marker_only_in_wal();
#endif

    printf("=== test_mint_anchor_preflight complete: %d failure(s) ===\n",
           failures);
    return failures;
}
