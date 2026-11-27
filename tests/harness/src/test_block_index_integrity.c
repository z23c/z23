/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the block_index_integrity service.
 *
 * Each test spins up a throw-away datadir, writes a mock block_index.bin body,
 * commits it with bii_write_sidecar, and drives bii_verify through the seven
 * verdicts. The quarantine rename is checked too: a delete would lose forensic
 * data.
 */

#include "test/test_core.h"
#include "test/test_block_map.h"
#include "json/json.h"

#include "services/block_index_integrity.h"
#include "config/boot.h"
#include "config/boot_blkidx_ladder.h"
#include "config/boot_cursor_state.h"
#include "config/runtime.h"
#include "validation/main_state.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "models/block.h"
#include "models/database.h"
#include "primitives/block.h"
#include "coins/coins_view.h"
#include "event/event.h"
#include "sha3/sha3.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <fcntl.h>
#include "storage/sha3_sidecar_io.h"
#include <stdlib.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ── Event counter for EV_BLOCK_INDEX_CORRUPT ──────────────── */

static _Atomic int g_bii_ev_corrupt;

static void bii_ev_observer(enum event_type type, uint32_t peer_id,
                             const void *payload, uint32_t payload_len,
                             void *ctx)
{
    (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    if (type == EV_BLOCK_INDEX_CORRUPT)
        atomic_fetch_add(&g_bii_ev_corrupt, 1);
}

static void bii_install_observer(void)
{
    event_clear_observers(EV_BLOCK_INDEX_CORRUPT);
    atomic_store(&g_bii_ev_corrupt, 0);
    event_observe(EV_BLOCK_INDEX_CORRUPT, bii_ev_observer, NULL);
}

#define BII_RUN(name, expr) do { \
    printf("%s... ", (name));    \
    bool _ok = (expr);           \
    if (_ok) printf("OK\n");     \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Test datadir harness ───────────────────────────────────── */

static bool bii_make_tmpdir(char *out, size_t cap)
{
    /* Unique suffix via a counter so parallel tests don't collide;
     * path-build + stale-cleanup + mkdir delegate to the shared helper. */
    static _Atomic int seq = 0;
    int s = atomic_fetch_add(&seq, 1);
    char tag[16];
    snprintf(tag, sizeof(tag), "%d", s);
    test_make_tmpdir(out, cap, "bii", tag);
    return true;
}

static bool bii_write_body(const char *datadir,
                           const void *bytes, size_t len)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/block_index.bin", datadir);
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fwrite(bytes, 1, len, f) == len;
    fclose(f);
    return ok;
}

static bool bii_sidecar_exists(const char *datadir)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/block_index.bin.sha3", datadir);
    struct stat st;
    return stat(path, &st) == 0;
}

static void bii_tear_down(const char *datadir)
{
    test_cleanup_tmpdir(datadir);
}

/* ── 1. Happy path: write sidecar, verify passes ───────────── */

static int t_happy_path(void)
{
    int failures = 0;
    char dir[256];
    bii_make_tmpdir(dir, sizeof(dir));

    const char body[] = "ZCLI" "\x00\x00\x00\x00" "block_index_body_placeholder_payload";
    bool body_ok = bii_write_body(dir, body, sizeof(body) - 1);
    bool side_ok = bii_write_sidecar(dir).ok;
    bool sidecar_present = bii_sidecar_exists(dir);

    char err[256];
    enum bii_verdict v = bii_verify(dir, NULL, NULL, err, sizeof(err));

    bool ok = body_ok && side_ok && sidecar_present && v == BII_OK;
    BII_RUN("bii: happy path write+verify returns OK", ok);

    bii_tear_down(dir);
    return failures;
}

/* ── 2. Missing sidecar returns SIDECAR_MISSING ──────────── */

static int t_sidecar_missing(void)
{
    int failures = 0;
    char dir[256];
    bii_make_tmpdir(dir, sizeof(dir));

    const char body[] = "body-no-sidecar";
    bii_write_body(dir, body, sizeof(body) - 1);

    char err[256];
    enum bii_verdict v = bii_verify(dir, NULL, NULL, err, sizeof(err));
    bool ok = v == BII_SIDECAR_MISSING;
    BII_RUN("bii: missing sidecar returns SIDECAR_MISSING", ok);

    bii_tear_down(dir);
    return failures;
}

/* ── 3. Body missing returns BODY_MISSING ──────────────────── */

static int t_body_missing(void)
{
    int failures = 0;
    char dir[256];
    bii_make_tmpdir(dir, sizeof(dir));

    char err[256];
    enum bii_verdict v = bii_verify(dir, NULL, NULL, err, sizeof(err));
    bool ok = v == BII_BODY_MISSING;
    BII_RUN("bii: missing body returns BODY_MISSING", ok);

    bii_tear_down(dir);
    return failures;
}

/* ── 4. Stale sidecar (body size changed after write) ─────── */

static int t_sidecar_stale(void)
{
    int failures = 0;
    char dir[256];
    bii_make_tmpdir(dir, sizeof(dir));

    const char body1[] = "original-body-bytes";
    bii_write_body(dir, body1, sizeof(body1) - 1);
    (void)bii_write_sidecar(dir);

    /* Grow the body; sidecar's body_size is now stale. */
    const char body2[] = "original-body-bytes-EXTRA-EXTRA";
    bii_write_body(dir, body2, sizeof(body2) - 1);

    char err[256];
    enum bii_verdict v = bii_verify(dir, NULL, NULL, err, sizeof(err));
    bool ok = v == BII_SIDECAR_STALE;
    BII_RUN("bii: size drift returns SIDECAR_STALE", ok);

    bii_tear_down(dir);
    return failures;
}

/* ── 5. Hash mismatch (same size, different bytes) ─────────── */

static int t_hash_mismatch(void)
{
    int failures = 0;
    char dir[256];
    bii_make_tmpdir(dir, sizeof(dir));

    const char body1[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    bii_write_body(dir, body1, sizeof(body1) - 1);
    (void)bii_write_sidecar(dir);

    /* Same length, different bytes → size check passes but hash
     * check fires. */
    const char body2[] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    bii_write_body(dir, body2, sizeof(body2) - 1);

    char err[256];
    enum bii_verdict v = bii_verify(dir, NULL, NULL, err, sizeof(err));
    bool ok = v == BII_HASH_MISMATCH && strstr(err, "sha3") != NULL;
    BII_RUN("bii: equal-size corruption returns HASH_MISMATCH", ok);

    bii_tear_down(dir);
    return failures;
}

/* ── 6. Bad magic in sidecar ────────────────────────────────── */

static int t_sidecar_bad_magic(void)
{
    int failures = 0;
    char dir[256];
    bii_make_tmpdir(dir, sizeof(dir));

    const char body[] = "body-for-bad-magic";
    bii_write_body(dir, body, sizeof(body) - 1);
    (void)bii_write_sidecar(dir);

    /* Corrupt the magic in-place. */
    char side_path[1024];
    snprintf(side_path, sizeof(side_path), "%s/block_index.bin.sha3", dir);
    FILE *f = fopen(side_path, "r+b");
    if (f) {
        fwrite("XXXX", 1, 4, f);
        fclose(f);
    }

    char err[256];
    enum bii_verdict v = bii_verify(dir, NULL, NULL, err, sizeof(err));
    bool ok = v == BII_SIDECAR_BAD_MAGIC;
    BII_RUN("bii: corrupt sidecar magic returns SIDECAR_BAD_MAGIC", ok);

    bii_tear_down(dir);
    return failures;
}

/* ── 7. SQLite cross-check — tip missing in SQL ────────────── */

static int t_tip_missing_in_sql(void)
{
    int failures = 0;
    char dir[256];
    bii_make_tmpdir(dir, sizeof(dir));

    const char body[] = "body-for-tip-check";
    bii_write_body(dir, body, sizeof(body) - 1);
    (void)bii_write_sidecar(dir);

    /* Open an in-memory node_db (empty blocks table). Build a
     * declared_tip that points at a hash the DB doesn't know. */
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    node_db_open(&ndb, ":memory:");

    struct uint256 hash = {{0}};
    hash.data[0] = 0xAB; hash.data[1] = 0xCD;
    struct block_index tip = {0};
    tip.phashBlock = &hash;
    tip.nHeight = 12345;

    char err[256];
    enum bii_verdict v = bii_verify(dir, &ndb, &tip, err, sizeof(err));
    bool ok = v == BII_TIP_MISSING_IN_SQL;
    BII_RUN("bii: declared tip absent from SQLite returns TIP_MISSING_IN_SQL", ok);

    node_db_close(&ndb);
    bii_tear_down(dir);
    return failures;
}

/* ── 8. SQLite cross-check — tip present but height drifted ── */

static int t_tip_height_mismatch(void)
{
    int failures = 0;
    char dir[256];
    bii_make_tmpdir(dir, sizeof(dir));

    const char body[] = "body-for-height-check";
    bii_write_body(dir, body, sizeof(body) - 1);
    (void)bii_write_sidecar(dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    node_db_open(&ndb, ":memory:");

    /* Insert a blocks row with height=999 for a specific hash.
     * All NOT NULL columns must be supplied to satisfy the schema
     * at engine/modules/engine/models/src/database.c. */
    struct uint256 hash = {{0}};
    hash.data[0] = 0x11; hash.data[31] = 0xEE;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(ndb.db,
        "INSERT INTO blocks("
        "hash,height,prev_hash,version,merkle_root,"
        "time,bits,nonce,solution,chain_work) "
        "VALUES(?,?,?,0,?,0,0,?,?,?)",
        -1, &st, NULL);
    if (rc == SQLITE_OK && st) {
        static const uint8_t zero32[32] = {0};
        static const uint8_t dummy_solution[4] = {0};
        sqlite3_bind_blob(st, 1, hash.data, 32, SQLITE_STATIC);
        sqlite3_bind_int64(st, 2, 999);
        sqlite3_bind_blob(st, 3, zero32, 32, SQLITE_STATIC);
        sqlite3_bind_blob(st, 4, zero32, 32, SQLITE_STATIC);  /* merkle_root */
        sqlite3_bind_blob(st, 5, zero32, 32, SQLITE_STATIC);  /* nonce */
        sqlite3_bind_blob(st, 6, dummy_solution, sizeof(dummy_solution), SQLITE_STATIC);
        sqlite3_bind_blob(st, 7, zero32, 32, SQLITE_STATIC);  /* chain_work */
        int step_rc = sqlite3_step(st);
        if (step_rc != SQLITE_DONE) {
            fprintf(stderr, "bii test: blocks insert failed: %s\n",
                    sqlite3_errmsg(ndb.db));
        }
        sqlite3_finalize(st);
    } else {
        fprintf(stderr, "bii test: blocks insert prepare failed: %s\n",
                sqlite3_errmsg(ndb.db));
    }

    struct block_index tip = {0};
    tip.phashBlock = &hash;
    tip.nHeight = 12345;  /* DISAGREES with SQLite */

    char err[256];
    enum bii_verdict v = bii_verify(dir, &ndb, &tip, err, sizeof(err));
    bool ok = v == BII_TIP_HEIGHT_MISMATCH;
    BII_RUN("bii: declared tip height ≠ SQLite height returns TIP_HEIGHT_MISMATCH", ok);

    node_db_close(&ndb);
    bii_tear_down(dir);
    return failures;
}

/* ── 9. Quarantine renames both files and emits event ──────── */

static int t_quarantine_renames(void)
{
    int failures = 0;
    bii_install_observer();

    char dir[256];
    bii_make_tmpdir(dir, sizeof(dir));

    const char body[] = "to-be-quarantined";
    bii_write_body(dir, body, sizeof(body) - 1);
    (void)bii_write_sidecar(dir);

    bii_quarantine_corrupt(dir, BII_HASH_MISMATCH);

    /* Neither original file should exist anymore. */
    char body_path[1024], side_path[1024];
    snprintf(body_path, sizeof(body_path), "%s/block_index.bin", dir);
    snprintf(side_path, sizeof(side_path), "%s/block_index.bin.sha3", dir);
    struct stat st;
    bool body_gone = stat(body_path, &st) != 0;
    bool side_gone = stat(side_path, &st) != 0;

    /* But a .corrupt.<ts> sibling should now exist for each. */
    DIR *d = opendir(dir);
    int corrupt_count = 0;
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (strstr(e->d_name, ".corrupt.")) corrupt_count++;
        }
        closedir(d);
    }

    bool ok = body_gone && side_gone && corrupt_count == 2 &&
              atomic_load(&g_bii_ev_corrupt) == 1;
    BII_RUN("bii: quarantine renames both files and emits event", ok);

    bii_tear_down(dir);
    event_clear_observers(EV_BLOCK_INDEX_CORRUPT);
    return failures;
}

/* ── 10. Quarantine is idempotent and safe when files absent ── */

static int t_quarantine_missing_is_noop(void)
{
    int failures = 0;
    bii_install_observer();

    char dir[256];
    bii_make_tmpdir(dir, sizeof(dir));

    /* No files written. Quarantine must not crash. */
    bii_quarantine_corrupt(dir, BII_SIDECAR_STALE);

    /* Still emits the event — the caller decided there was
     * corruption and the event is their audit trail. */
    bool ok = atomic_load(&g_bii_ev_corrupt) == 1;
    BII_RUN("bii: quarantine on empty dir is a safe no-op + event", ok);

    bii_tear_down(dir);
    event_clear_observers(EV_BLOCK_INDEX_CORRUPT);
    return failures;
}

/* ── 11. Verdict names cover every value ───────────────────── */

static int t_verdict_names(void)
{
    int failures = 0;
    bool ok = strcmp(bii_verdict_name(BII_OK), "ok") == 0 &&
              strcmp(bii_verdict_name(BII_SIDECAR_MISSING), "sidecar_missing") == 0 &&
              strcmp(bii_verdict_name(BII_SIDECAR_STALE), "sidecar_stale") == 0 &&
              strcmp(bii_verdict_name(BII_HASH_MISMATCH), "hash_mismatch") == 0 &&
              strcmp(bii_verdict_name(BII_TIP_HEIGHT_MISMATCH), "tip_height_mismatch") == 0 &&
              strcmp(bii_verdict_name(BII_TIP_MISSING_IN_SQL), "tip_missing_in_sql") == 0 &&
              strcmp(bii_verdict_name(BII_BODY_MISSING), "body_missing") == 0 &&
              strcmp(bii_verdict_name(BII_BODY_UNREADABLE), "body_unreadable") == 0 &&
              strcmp(bii_verdict_name(BII_SIDECAR_BAD_MAGIC), "sidecar_bad_magic") == 0 &&
              strcmp(bii_verdict_name(BII_SIDECAR_UNSUPPORTED), "sidecar_unsupported") == 0;
    BII_RUN("bii: verdict names are stable strings", ok);
    return failures;
}

static int t_recovery_status(void)
{
    int failures = 0;

    bii_record_recovery_status(BII_TIP_MISSING_IN_SQL,
                               BII_RECOVERY_RECONCILE_REQUIRED,
                               "tip h=123: tip_missing_in_sql",
                               true, false);

    struct bii_recovery_status st;
    memset(&st, 0, sizeof(st));
    bii_get_recovery_status(&st);

    bool ok = st.verdict == BII_TIP_MISSING_IN_SQL &&
              st.action == BII_RECOVERY_RECONCILE_REQUIRED &&
              st.degraded &&
              !st.unsafe_override &&
              st.unix_time > 0 &&
              strcmp(st.reason, "tip h=123: tip_missing_in_sql") == 0 &&
              strcmp(bii_recovery_action_name(BII_RECOVERY_RECONCILE_REQUIRED),
                     "reconcile_required") == 0;
    BII_RUN("bii: recovery status records degraded reconciliation", ok);
    return failures;
}

/* ── 11b. dump_state_json (`z23 dumpstate block_index_integrity`) ── */

static int t_dump_state_json(void)
{
    int failures = 0;

    bii_record_recovery_status(BII_HASH_MISMATCH,
                               BII_RECOVERY_QUARANTINED,
                               "body sha3 mismatch",
                               true, false);

    struct json_value v = {0};
    json_set_object(&v);
    bool ok = block_index_integrity_dump_state_json(&v, NULL);
    const struct json_value *verdict = json_get(&v, "verdict");
    const struct json_value *action = json_get(&v, "action");
    const struct json_value *degraded = json_get(&v, "degraded");
    const struct json_value *reason = json_get(&v, "reason");
    bool shape_ok = ok && verdict &&
                    strcmp(json_get_str(verdict), "hash_mismatch") == 0 &&
                    action &&
                    strcmp(json_get_str(action), "quarantined") == 0 &&
                    degraded && json_get_bool(degraded) == true &&
                    reason &&
                    strcmp(json_get_str(reason), "body sha3 mismatch") == 0;
    json_free(&v);
    BII_RUN("bii: dump_state_json reports verdict/action/degraded/reason",
            shape_ok);
    return failures;
}

/* ── 12. Bulk height repair fixes scrambled heights ──────────── */

static int t_height_repair(void)
{
    int failures = 0;

    /* Build a small block index with a chain of 10 blocks.
     * Scramble the heights, then call repair and verify. */
    struct main_state ms;
    main_state_init(&ms);

    enum { CHAIN_LEN = 10 };
    struct block_index blocks[CHAIN_LEN];
    struct uint256 hashes[CHAIN_LEN];

    for (int i = 0; i < CHAIN_LEN; i++) {
        memset(&blocks[i], 0, sizeof(blocks[i]));
        memset(&hashes[i], 0, sizeof(hashes[i]));
        hashes[i].data[0] = (uint8_t)(i + 1);
        blocks[i].phashBlock = &hashes[i];
        blocks[i].pprev = (i > 0) ? &blocks[i - 1] : NULL;
        /* Scramble heights: give wrong values */
        blocks[i].nHeight = (i * 37) % 100;
        blocks[i].nBits = 0x2007ffff;  /* valid difficulty for GetBlockProof */
        test_block_map_insert(&ms.map_block_index, &hashes[i], &blocks[i]);
    }

    /* The root must be the REAL genesis (by hash): repair only anchors
     * height 0 — and only propagates fixes — from the true genesis. */
    hashes[0] = chain_params_get()->consensus.hashGenesisBlock;

    /* Genesis should have height 0 but we scrambled it */
    blocks[0].nHeight = 42;

    int repaired = block_index_repair_heights(&ms);

    /* Verify all heights are correct */
    bool heights_ok = true;
    for (int i = 0; i < CHAIN_LEN; i++) {
        if (blocks[i].nHeight != i) {
            fprintf(stderr, "  height[%d] = %d (expected %d)\n",
                    i, blocks[i].nHeight, i);
            heights_ok = false;
        }
    }

    /* Verify chain work is monotonically increasing */
    bool work_ok = true;
    for (int i = 1; i < CHAIN_LEN; i++) {
        if (arith_uint256_compare(&blocks[i].nChainWork,
                                   &blocks[i-1].nChainWork) <= 0) {
            fprintf(stderr, "  chain_work[%d] not > chain_work[%d]\n", i, i-1);
            work_ok = false;
        }
    }

    bool flag_ok = block_index_heights_repaired();

    BII_RUN("bii: height repair fixes scrambled heights",
            heights_ok && repaired > 0);
    BII_RUN("bii: height repair recomputes chain work", work_ok);
    BII_RUN("bii: heights_repaired flag is set after repair", flag_ok);

    main_state_free(&ms);
    return failures;
}

/* ── 13. Height repair on empty block map is a no-op ─────────── */

static int t_height_repair_empty(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);

    int repaired = block_index_repair_heights(&ms);
    BII_RUN("bii: height repair on empty map returns 0", repaired == 0);

    main_state_free(&ms);
    return failures;
}

/* ── 14. Height repair with pprev cycle does not infinite loop ──── */

static int t_height_repair_cycle(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);

    /* Build 5 blocks, then create a cycle: block[4].pprev = block[1],
     * block[1].pprev = block[4]. The repair must not loop forever. */
    enum { N = 5 };
    struct block_index blocks[N];
    struct uint256 hashes[N];

    for (int i = 0; i < N; i++) {
        memset(&blocks[i], 0, sizeof(blocks[i]));
        memset(&hashes[i], 0, sizeof(hashes[i]));
        hashes[i].data[0] = (uint8_t)(i + 10);
        blocks[i].phashBlock = &hashes[i];
        blocks[i].pprev = (i > 0) ? &blocks[i - 1] : NULL;
        blocks[i].nHeight = i * 5; /* wrong heights */
        blocks[i].nBits = 0x2007ffff;
        test_block_map_insert(&ms.map_block_index, &hashes[i], &blocks[i]);
    }

    /* Create cycle: block[4]->block[3]->block[2]->block[1]->block[4] */
    blocks[1].pprev = &blocks[4];

    /* This should terminate without hanging. The repair function
     * should handle the cycle gracefully (visited set or depth limit). */
    int repaired = block_index_repair_heights(&ms);

    /* We don't assert specific heights because a cycle makes them
     * undefined. We just assert it terminated and didn't crash. */
    BII_RUN("bii: height repair with pprev cycle terminates safely",
            repaired >= 0);

    main_state_free(&ms);
    return failures;
}

/* ── 15. Height repair on single genesis block ─────────────────── */

static int t_height_repair_single(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);

    struct block_index genesis;
    struct uint256 hash;
    memset(&genesis, 0, sizeof(genesis));
    hash = chain_params_get()->consensus.hashGenesisBlock;
    genesis.phashBlock = &hash;
    genesis.pprev = NULL;
    genesis.nHeight = 99; /* wrong */
    genesis.nBits = 0x2007ffff;
    test_block_map_insert(&ms.map_block_index, &hash, &genesis);

    /* A parentless NON-genesis entry must keep its stored height: it is
     * a detached root, not genesis (a positional-only genesis test can
     * otherwise relabel the whole index by an offset). */
    struct block_index stray;
    struct uint256 stray_hash;
    memset(&stray, 0, sizeof(stray));
    memset(&stray_hash, 0, sizeof(stray_hash));
    stray_hash.data[0] = 0x77;
    stray.phashBlock = &stray_hash;
    stray.pprev = NULL;
    stray.nHeight = 1234;
    stray.nBits = 0x2007ffff;
    test_block_map_insert(&ms.map_block_index, &stray_hash, &stray);

    int repaired = block_index_repair_heights(&ms);

    BII_RUN("bii: single genesis block repaired to height 0",
            genesis.nHeight == 0 && repaired >= 0);
    BII_RUN("bii: detached non-genesis root keeps its stored height",
            stray.nHeight == 1234);

    main_state_free(&ms);
    return failures;
}

/* ── 15b. Detached-root subtree is never re-anchored ─────────────
 * If an early header's pprev link is lost, stamping the detached root to
 * height 0 would relabel every descendant by an offset. The repair must leave
 * the canonical descendant labels alone until pprev repair relinks the root,
 * after which a re-run heals the root's own label. */

static int t_height_repair_detached_subtree(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);

    struct block_index g, h1, h2, h3, h4;
    struct uint256 gh, h1h, h2h, h3h, h4h;
    memset(&g, 0, sizeof(g));   memset(&h1, 0, sizeof(h1));
    memset(&h2, 0, sizeof(h2)); memset(&h3, 0, sizeof(h3));
    memset(&h4, 0, sizeof(h4));
    gh = chain_params_get()->consensus.hashGenesisBlock;
    memset(&h1h, 0, sizeof(h1h)); h1h.data[0] = 0xA1;
    memset(&h2h, 0, sizeof(h2h)); h2h.data[0] = 0xA2;
    memset(&h3h, 0, sizeof(h3h)); h3h.data[0] = 0xA3;
    memset(&h4h, 0, sizeof(h4h)); h4h.data[0] = 0xA4;

    g.phashBlock = &gh;   g.nHeight = 0; g.nBits = 0x2007ffff;
    h1.phashBlock = &h1h; h1.pprev = &g;  h1.nHeight = 1;
    h1.nBits = 0x2007ffff;
    /* h2: detached root persisted at 0 (the corrupted flat-save state);
     * its TRUE height is 2 and its descendants carry canonical labels. */
    h2.phashBlock = &h2h; h2.pprev = NULL; h2.nHeight = 0;
    h2.nBits = 0x2007ffff;
    h3.phashBlock = &h3h; h3.pprev = &h2; h3.nHeight = 3;
    h3.nBits = 0x2007ffff;
    h4.phashBlock = &h4h; h4.pprev = &h3; h4.nHeight = 4;
    h4.nBits = 0x2007ffff;

    test_block_map_insert(&ms.map_block_index, &gh, &g);
    test_block_map_insert(&ms.map_block_index, &h1h, &h1);
    test_block_map_insert(&ms.map_block_index, &h2h, &h2);
    test_block_map_insert(&ms.map_block_index, &h3h, &h3);
    test_block_map_insert(&ms.map_block_index, &h4h, &h4);

    (void)block_index_repair_heights(&ms);
    BII_RUN("bii: detached subtree keeps canonical descendant labels",
            h2.nHeight == 0 && h3.nHeight == 3 && h4.nHeight == 4 &&
            g.nHeight == 0 && h1.nHeight == 1);

    /* pprev repair relinks the root (simulated); the boot sequence then
     * re-runs the height repair, which must heal ONLY the root label. */
    h2.pprev = &h1;
    int repaired = block_index_repair_heights(&ms);
    BII_RUN("bii: relinked root heals to its canonical height",
            repaired > 0 && h2.nHeight == 2 &&
            h3.nHeight == 3 && h4.nHeight == 4);

    main_state_free(&ms);
    return failures;
}

/* ── Post-activation anchor repair ─
 *
 * NULL-input-only test: the input validation is exercised here and the happy
 * path by the boot sequence (a full fixture needs a backing coins_view, a
 * node_db and an on-disk block file). */

static int t_anchor_repair_null_inputs(void)
{
    int failures = 0;

    int rc_null_ms = bii_repair_post_activation_anchor(NULL,
                                                        (void *)1,
                                                        "/tmp", NULL);
    int rc_null_coins = bii_repair_post_activation_anchor(
        (void *)1, NULL, "/tmp", NULL);
    int rc_null_dd = bii_repair_post_activation_anchor(
        (void *)1, (void *)1, NULL, NULL);
    BII_RUN("bii: anchor repair NULL inputs return -1",
            rc_null_ms == -1 && rc_null_coins == -1 && rc_null_dd == -1);
    return failures;
}

static int t_anchor_repair_oom(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);
    struct uint256 gh = chain_params_get()->consensus.hashGenesisBlock;
    struct uint256 ah = {0};
    ah.data[0] = 0xA1;
    struct block_index genesis = {0};
    genesis.phashBlock = &gh;
    genesis.nHeight = 7;
    genesis.nBits = 0x2007ffff;
    struct block_index anchor = {0};
    anchor.phashBlock = &ah;
    anchor.nHeight = 100001;
    anchor.nBits = 0x2007ffff;
    test_block_map_insert(&ms.map_block_index, &gh, &genesis);
    test_block_map_insert(&ms.map_block_index, &ah, &anchor);
    struct coins_view backing;
    struct coins_view_cache cache;
    memset(&backing, 0, sizeof(backing));
    coins_view_cache_init(&cache, &backing);
    coins_view_cache_set_best_block(&cache, &ah);
    block_index_heights_repaired_reset_for_test();
    int primed = block_index_repair_heights(&ms);
    bool gate_was_set = primed >= 0 && block_index_heights_repaired();
    genesis.nHeight = 7;
    struct bii_post_activation_result result;
    zcl_alloc_fault_fail_nth("height_repair_mark", 1);
    int rc = bii_repair_post_activation_anchor(&ms, &cache,
                                               "/nonexistent-anchor", &result);
    zcl_alloc_fault_clear();
    BII_RUN("bii: post-activation OOM refuses restoration and the repaired gate",
            rc == -1 && result.heights_repropagated == -1 &&
            result.tip_restore_refused && !result.tip_restored &&
            gate_was_set && !block_index_heights_repaired());
    main_state_free(&ms);
    return failures;
}

/* ── Aggregator ─────────────────────────────────────────────── */

/* ── 19. pprev repair skips work the fast-boot cursor already covers ────
 *
 * --importblockindex stamps a "repaired-through" cursor, so a normal boot must
 * not re-walk the whole index. min_height at the tip selects nothing, so the
 * function returns 0 without reading any block file (proven with a bogus
 * datadir) while still reporting the true max height. */
static int t_pprev_repair_cursor_skip(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);

    enum { N = 8 };
    struct block_index blocks[N];
    struct uint256 hashes[N];
    for (int i = 0; i < N; i++) {
        memset(&blocks[i], 0, sizeof(blocks[i]));
        memset(&hashes[i], 0, sizeof(hashes[i]));
        hashes[i].data[0] = (uint8_t)(i + 1);
        blocks[i].phashBlock = &hashes[i];
        blocks[i].pprev = (i > 0) ? &blocks[i - 1] : NULL;
        blocks[i].nHeight = i;
        blocks[i].nBits = 0x2007ffff;
        blocks[i].nStatus = BLOCK_HAVE_DATA;  /* would be selected but for the cursor */
        blocks[i].nFile = 0;
        blocks[i].nDataPos = 8;
        test_block_map_insert(&ms.map_block_index, &hashes[i], &blocks[i]);
    }

    /* Cursor at the tip (min_height = N-1): every block is already covered. */
    int max_out = -999;
    int fixed = block_index_repair_pprev(&ms, "/nonexistent-fastboot-datadir",
                                         N - 1, &max_out);
    BII_RUN("bii: pprev repair skips (returns 0) when cursor covers the tip",
            fixed == 0);
    BII_RUN("bii: pprev repair reports max height so boot advances the cursor",
            max_out == N - 1);

    main_state_free(&ms);
    return failures;
}

/* ── OS-S2 boot O(delta) cursors (engine/composition/src/boot_cursor_state.c) ──────── */

/* Build a correct genesis-rooted chain of N blocks into `ms`. Caller owns the
 * backing storage. hashes[0] is set to the real genesis so repair anchors it. */
static void bcs_build_chain(struct main_state *ms, struct block_index *blocks,
                            struct uint256 *hashes, int n)
{
    for (int i = 0; i < n; i++) {
        memset(&blocks[i], 0, sizeof(blocks[i]));
        memset(&hashes[i], 0, sizeof(hashes[i]));
        hashes[i].data[0] = (uint8_t)(i + 1);
        blocks[i].phashBlock = &hashes[i];
        blocks[i].pprev = (i > 0) ? &blocks[i - 1] : NULL;
        blocks[i].nHeight = i;
        blocks[i].nBits = 0x2007ffff;
        blocks[i].nTx = 1;
        blocks[i].nChainTx = (unsigned)(i + 1);
        test_block_map_insert(&ms->map_block_index, &hashes[i], &blocks[i]);
    }
    hashes[0] = chain_params_get()->consensus.hashGenesisBlock;
}

static int t_bcs_fingerprint(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);
    enum { N = 12 };
    struct block_index blocks[N];
    struct uint256 hashes[N];
    bcs_build_chain(&ms, blocks, hashes, N);

    uint64_t fp1 = boot_block_index_fingerprint(&ms);
    uint64_t fp2 = boot_block_index_fingerprint(&ms);
    BII_RUN("bcs: fingerprint is stable across identical reads", fp1 == fp2);
    BII_RUN("bcs: fingerprint is nonzero for a populated map", fp1 != 0);

    blocks[5].nHeight = 999;   /* perturb one navigation field */
    uint64_t fp3 = boot_block_index_fingerprint(&ms);
    BII_RUN("bcs: fingerprint changes when a height changes", fp3 != fp1);

    main_state_free(&ms);
    return failures;
}

static int t_bcs_repair_heights_range_cursor(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);
    enum { N = 10 };
    struct block_index blocks[N];
    struct uint256 hashes[N];
    bcs_build_chain(&ms, blocks, hashes, N);

    /* (a) Clean chain + cursor mid: nothing is wrong, so the O(delta) path
     * returns 0 without touching heights, and reports the true max height. */
    int out_max = -1;
    int fixed_clean = block_index_repair_heights_range(&ms, 5, &out_max);
    BII_RUN("bcs: range repair returns 0 on a clean chain (fast path)",
            fixed_clean == 0);
    BII_RUN("bcs: range repair reports max height for cursor advance",
            out_max == N - 1);

    /* (b) Corrupt the tip to a HIGH value (reads as above the cursor); the
     * range repair counts + fixes it via genesis-rooted propagation. */
    blocks[N - 1].nHeight = 4242;
    int fixed = block_index_repair_heights_range(&ms, N - 2, &out_max);
    BII_RUN("bcs: range repair fixes a wrong height above the cursor",
            fixed > 0 && blocks[N - 1].nHeight == N - 1);

    /* (c) Corrupt an entry to a value AT/BELOW the cursor: the gate excludes
     * it (nHeight not > min_height), so it is NOT counted and survives —
     * proving the cursor skips already-verified below-cursor work. */
    blocks[3].nHeight = 1;   /* 1 <= cursor 5 → excluded */
    int fixed_below = block_index_repair_heights_range(&ms, 5, NULL);
    BII_RUN("bcs: range repair skips a wrong height at/below the cursor",
            fixed_below == 0 && blocks[3].nHeight == 1);

    /* Full (-1) re-derives everything — the un-cursored entry point. */
    int full = block_index_repair_heights_range(&ms, -1, NULL);
    BII_RUN("bcs: full range (-1) repairs the below-cursor wrong height",
            full > 0 && blocks[3].nHeight == 3);

    main_state_free(&ms);
    return failures;
}

static int t_bcs_clamp_on_reorg(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:")) {
        printf("bcs: clamp — node_db_open(:memory:) FAILED\n");
        return 1;
    }

    node_db_state_set_int(&ndb, BOOT_CUR_HEIGHTS, 100);
    node_db_state_set_int(&ndb, BOOT_CUR_HEIGHTS_CNT, 500);
    node_db_state_set_int(&ndb, BOOT_CUR_NCHAINTX, 100);
    node_db_state_set_int(&ndb, BOOT_CUR_WALLET, 100);

    /* Reorg at fork height 50 → every int cursor clamps to 49, count zeroed. */
    boot_cursor_clamp_on_reorg(&ndb, 50);
    int64_t h = -1, cnt = -1, nct = -1, wal = -1;
    node_db_state_get_int(&ndb, BOOT_CUR_HEIGHTS, &h);
    node_db_state_get_int(&ndb, BOOT_CUR_HEIGHTS_CNT, &cnt);
    node_db_state_get_int(&ndb, BOOT_CUR_NCHAINTX, &nct);
    node_db_state_get_int(&ndb, BOOT_CUR_WALLET, &wal);
    BII_RUN("bcs: clamp lowers heights/nchaintx/wallet cursors to fork-1",
            h == 49 && nct == 49 && wal == 49);
    BII_RUN("bcs: clamp zeros the heights-count guard so #1 re-derives",
            cnt == 0);

    /* A fork ABOVE the cursors is a no-op (min-only). */
    boot_cursor_clamp_on_reorg(&ndb, 200);
    node_db_state_get_int(&ndb, BOOT_CUR_HEIGHTS, &h);
    BII_RUN("bcs: clamp is min-only (fork above cursor is a no-op)", h == 49);

    node_db_close(&ndb);
    return failures;
}

static int t_bcs_repair_heights_wrapper(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:")) {
        printf("bcs: wrapper — node_db_open(:memory:) FAILED\n");
        return 1;
    }
    struct main_state ms;
    main_state_init(&ms);
    enum { N = 200 };  /* > 100 so the size gate in boot.c would engage */
    static struct block_index blocks[N];
    static struct uint256 hashes[N];
    bcs_build_chain(&ms, blocks, hashes, N);

    /* First call: no cursor → full repair + stamp. */
    (void)boot_cursor_repair_heights(&ms, &ndb);
    int64_t upto = -1, cnt = -1;
    node_db_state_get_int(&ndb, BOOT_CUR_HEIGHTS, &upto);
    node_db_state_get_int(&ndb, BOOT_CUR_HEIGHTS_CNT, &cnt);
    BII_RUN("bcs: wrapper stamps high-water + count after first pass",
            upto == N - 1 && cnt == (int64_t)ms.map_block_index.size);

    /* Second call: count matches size + high-water set → fast-skip. Corrupt a
     * height first; the skip must LEAVE it (proving the O(1) path ran). */
    blocks[N - 1].nHeight = 5150;
    int repaired = boot_cursor_repair_heights(&ms, &ndb);
    BII_RUN("bcs: wrapper fast-skips when the count-guarded cursor covers all",
            repaired == 0 && blocks[N - 1].nHeight == 5150);

    main_state_free(&ms);
    node_db_close(&ndb);
    return failures;
}

/* ── Verified-body memo: one full hash per process and unchanged file ── */

static bool bii_memo_emit(FILE *f, void *ctx, uint64_t *size, uint8_t sha3[32])
{
    uint8_t seed = ctx ? *(const uint8_t *)ctx : 7u;
    uint8_t payload[4096];
    for (size_t i = 0; i < sizeof(payload); i++)
        payload[i] = (uint8_t)(i * 31u + seed);
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    sha3_256_write(&h, payload, sizeof(payload));
    sha3_256_finalize(&h, sha3);
    *size = sizeof(payload);
    return fwrite(payload, 1, sizeof(payload), f) == sizeof(payload);
}

static bool bii_memo_set_mtime(const char *dir, long seconds)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/block_index.bin", dir);
    struct timespec ts[2] = {{.tv_sec = seconds}, {.tv_sec = seconds}};
    return utimensat(AT_FDCWD, path, ts, 0) == 0;
}

static bool bii_memo_flip_payload_byte(const char *dir)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/block_index.bin", dir);
    FILE *f = fopen(path, "r+b");
    if (!f) return false;
    uint8_t b = 0;
    bool ok = fseek(f, 100, SEEK_SET) == 0 && fread(&b, 1, 1, f) == 1;
    b ^= 0x5a;
    ok = ok && fseek(f, 100, SEEK_SET) == 0 && fwrite(&b, 1, 1, f) == 1;
    fclose(f);
    return ok;
}

static int t_verified_stream_identity(void)
{
    int failures = 0;
    char a[256], b[256], path[1024];
    if (!bii_make_tmpdir(a, sizeof(a))) return 1;
    if (!bii_make_tmpdir(b, sizeof(b))) {
        bii_tear_down(a);
        return 1;
    }
    uint8_t seed = 23;
    bool written = bii_write_embedded(a, bii_memo_emit, NULL).ok &&
                   bii_write_embedded(b, bii_memo_emit, &seed).ok;
    struct ssio_sidecar_header a_header = {0}, b_header = {0}, actual = {0};
    bool paths_ok = written && bii_verify_embedded(a, &a_header, NULL) == 0 &&
                    bii_verify_embedded(b, &b_header, NULL) == 0;
    snprintf(path, sizeof(path), "%s/block_index.bin", a);
    FILE *stream = fopen(path, "rb");
    bool stream_ok = stream && bii_verify_embedded_stream(b, stream, &actual, NULL) == 0;
    BII_RUN("memo: stream selects A and never memoizes unrelated B",
            paths_ok && stream_ok &&
            memcmp(&a_header, &b_header, sizeof(a_header)) != 0 &&
            memcmp(&actual, &a_header, sizeof(actual)) == 0 &&
            !bii_verified_body_current(b, NULL).ok);
    if (stream) fclose(stream);
    bii_verified_body_forget();
    bii_tear_down(a);
    bii_tear_down(b);
    return failures;
}

static int t_verified_stream_refusals(void)
{
    int failures = 0;
    char b[256];
    if (!bii_make_tmpdir(b, sizeof(b))) return 1;
    BII_RUN("memo: refusal fixture written",
            bii_write_embedded(b, bii_memo_emit, NULL).ok);
    BII_RUN("memo: invalid stream refuses and clears memo",
            bii_verify_embedded(b, NULL, NULL) == 0 &&
            bii_verified_body_current(b, NULL).ok &&
            bii_verify_embedded_stream(b, NULL, NULL, NULL) == SSIO_READ_UNREADABLE &&
            !bii_verified_body_current(b, NULL).ok);
    char long_path[1100];
    memset(long_path, 'x', sizeof(long_path) - 1);
    long_path[sizeof(long_path) - 1] = '\0';
    bool memo_ready = bii_verify_embedded(b, NULL, NULL) == 0 &&
                      bii_verified_body_current(b, NULL).ok;
    uint64_t count = bii_full_hash_count();
    BII_RUN("memo: overlong path refuses and clears memo",
            memo_ready && bii_verify_embedded(long_path, NULL, NULL) ==
                SSIO_READ_UNREADABLE && bii_full_hash_count() == count + 1 &&
            !bii_verified_body_current(b, NULL).ok);
    bii_verified_body_forget();
    bii_tear_down(b);
    return failures;
}

static int t_verified_stream_matching_path(void)
{
    int failures = 0;
    char dir[256];
    if (!bii_make_tmpdir(dir, sizeof(dir))) return 1;
    bii_verified_body_forget();
    BII_RUN("memo: matching fixture written",
            bii_write_embedded(dir, bii_memo_emit, NULL).ok);
    {
        char path[1024];
        snprintf(path, sizeof(path), "%s/block_index.bin", dir);
        FILE *stream = fopen(path, "rb");
        struct ssio_sidecar_header path_header, fd_header;
        uint64_t path_offset = 0, fd_offset = 0;
        bool path_ok = bii_verify_embedded(dir, &path_header, &path_offset) == 0;
        uint64_t count = bii_full_hash_count();
        bool fd_ok = stream && bii_verify_embedded_stream(
            dir, stream, &fd_header, &fd_offset) == 0;
        BII_RUN("memo: open-file verifier matches path and publishes memo",
                path_ok && fd_ok && fd_offset == path_offset &&
                memcmp(&fd_header, &path_header, sizeof(fd_header)) == 0 &&
                bii_full_hash_count() == count + 1 &&
                bii_verified_body_current(dir, NULL).ok &&
                bii_full_hash_count() == count + 1);
        if (stream) fclose(stream);
    }
    bii_verified_body_forget();
    bii_tear_down(dir);
    return failures;
}

static int t_verified_memo(void)
{
    int failures = 0;
    char dir[256];
    bii_make_tmpdir(dir, sizeof(dir));
    char err[256];
    bii_verified_body_forget();

    BII_RUN("memo: embedded body written",
            bii_write_embedded(dir, bii_memo_emit, NULL).ok);
    uint64_t base = bii_full_hash_count();
    BII_RUN("memo: loader-side verification hashes once and passes",
            bii_verify_embedded(dir, NULL, NULL) == 0 &&
            bii_full_hash_count() == base + 1);
    BII_RUN("memo: gate on the unchanged file accepts it without a hash",
            bii_verify(dir, NULL, NULL, err, sizeof(err)) == BII_OK &&
            bii_full_hash_count() == base + 1);
    BII_RUN("memo: gate in another datadir path does not use the memo",
            bii_verify("/nonexistent-bii-memo", NULL, NULL, err,
                       sizeof(err)) != BII_OK &&
            bii_full_hash_count() == base + 1);

    bii_verified_body_forget();
    BII_RUN("memo: forgotten memo means the gate hashes",
            bii_verify(dir, NULL, NULL, err, sizeof(err)) == BII_OK &&
            bii_full_hash_count() == base + 2);

    bii_verified_body_forget();
    (void)bii_verify_embedded(dir, NULL, NULL);
    uint64_t c = bii_full_hash_count();
    BII_RUN("memo: touched mtime with identical bytes takes the full hash",
            bii_memo_set_mtime(dir, 1000000000L) &&
            bii_verify(dir, NULL, NULL, err, sizeof(err)) == BII_OK &&
            bii_full_hash_count() == c + 1);

    bii_verified_body_forget();
    (void)bii_verify_embedded(dir, NULL, NULL);
    c = bii_full_hash_count();
    BII_RUN("memo: changed payload byte and mtime is detected by the hash",
            bii_memo_flip_payload_byte(dir) &&
            bii_memo_set_mtime(dir, 1000000123L) &&
            bii_verify(dir, NULL, NULL, err, sizeof(err)) != BII_OK &&
            bii_full_hash_count() == c + 1);

    BII_RUN("memo: rewritten body (new inode, new size) takes the full hash",
            bii_write_embedded(dir, bii_memo_emit, NULL).ok &&
            bii_verify_embedded(dir, NULL, NULL) == 0);
    c = bii_full_hash_count();
    {
        char path[1024];
        snprintf(path, sizeof(path), "%s/block_index.bin", dir);
        FILE *f = fopen(path, "ab");
        bool grew = f && fwrite("x", 1, 1, f) == 1;
        if (f) fclose(f);
        BII_RUN("memo: appended byte (size changed) takes the full hash and fails",
                grew && bii_verify(dir, NULL, NULL, err, sizeof(err)) != BII_OK &&
                bii_full_hash_count() == c + 1);
    }
    bii_verified_body_forget();
    bii_tear_down(dir);
    return failures;
}

/* ── Mutation-gap tests ───────────────────────────────────────
 * Assertions aimed at survivors the mutation sweep measured: verdict and
 * action names, status reset, the dump-state shape, the pprev-repair scan
 * set / read order / limit / per-entry repair, and the height-repair
 * verdicts and exact counts. */

static _Atomic int g_bii_ev_repair;

static void bii_repair_observer(enum event_type type, uint32_t peer_id,
                                const void *payload, uint32_t payload_len,
                                void *ctx)
{
    (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    if (type == EV_BLOCK_INDEX_REPAIR)
        atomic_fetch_add(&g_bii_ev_repair, 1);
}

static void bii_repair_observer_install(void)
{
    event_clear_observers(EV_BLOCK_INDEX_REPAIR);
    atomic_store(&g_bii_ev_repair, 0);
    event_observe(EV_BLOCK_INDEX_REPAIR, bii_repair_observer, NULL);
}

static bool bii_streq(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

static int t_mg_names(void)
{
    int failures = 0;
    bool verdicts = bii_streq(bii_verdict_name((enum bii_verdict)9999),
                              "unknown");
    bool actions =
        bii_streq(bii_recovery_action_name(BII_RECOVERY_NONE), "none") &&
        bii_streq(bii_recovery_action_name(BII_RECOVERY_ACCEPTED),
                  "accepted") &&
        bii_streq(bii_recovery_action_name(BII_RECOVERY_QUARANTINED),
                  "quarantined") &&
        bii_streq(bii_recovery_action_name(BII_RECOVERY_OVERRIDE),
                  "override") &&
        bii_streq(bii_recovery_action_name((enum bii_recovery_action)9999),
                  "unknown");
    BII_RUN("bii: an out-of-range verdict is named unknown", verdicts);
    BII_RUN("bii: every recovery action has its own name", actions);
    return failures;
}

/* A later record replaces the whole status: no reason, flags back off. */
static int t_mg_status_replaced(void)
{
    int failures = 0;
    bii_repair_observer_install();
    bii_record_recovery_status(BII_HASH_MISMATCH, BII_RECOVERY_OVERRIDE,
                               "first reason", true, true);
    struct bii_recovery_status first;
    memset(&first, 0, sizeof(first));
    bii_get_recovery_status(&first);

    bii_record_recovery_status(BII_OK, BII_RECOVERY_NONE, NULL,
                               false, false);
    struct bii_recovery_status second;
    memset(&second, 0, sizeof(second));
    bii_get_recovery_status(&second);

    bool first_ok = first.unsafe_override && first.degraded &&
                    bii_streq(first.reason, "first reason");
    bool second_ok = second.verdict == BII_OK &&
                     second.action == BII_RECOVERY_NONE &&
                     !second.degraded && !second.unsafe_override &&
                     second.reason[0] == '\0';
    bool events_ok = atomic_load(&g_bii_ev_repair) == 2;
    event_clear_observers(EV_BLOCK_INDEX_REPAIR);
    BII_RUN("bii: status keeps the override flag and reason it was given",
            first_ok);
    BII_RUN("bii: a later status clears the earlier reason and flags",
            second_ok);
    BII_RUN("bii: each recorded status emits a repair event", events_ok);
    return failures;
}

/* The dump must build its own object, refuse a NULL target, and carry
 * every field, including the ones the first dump test never read. */
static int t_mg_dump_fields(void)
{
    int failures = 0;
    bii_record_recovery_status(BII_SIDECAR_STALE, BII_RECOVERY_OVERRIDE,
                               "stale body", true, true);
    BII_RUN("bii: dump_state_json refuses a NULL target",
            !block_index_integrity_dump_state_json(NULL, NULL));

    struct json_value v = {0};
    bool ok = block_index_integrity_dump_state_json(&v, NULL);
    const struct json_value *verdict = json_get(&v, "verdict");
    const struct json_value *unsafe = json_get(&v, "unsafe_override");
    const struct json_value *when = json_get(&v, "unix_time");
    const struct json_value *rep = json_get(&v, "heights_repaired");
    bool shape = ok && verdict && unsafe && when && rep;
    bool values = shape &&
                  bii_streq(json_get_str(verdict), "sidecar_stale") &&
                  json_get_bool(unsafe) && json_get_int(when) > 0 &&
                  json_get_bool(rep) == block_index_heights_repaired();
    json_free(&v);
    BII_RUN("bii: dump_state_json fills a fresh object with every field",
            values);
    return failures;
}

/* ── pprev-repair fixture ───────────────────────────────────── */

enum { PP_MAX = 64 };

struct pp_fx {
    struct main_state ms;
    struct block_index b[PP_MAX];
    struct uint256 h[PP_MAX];
    char dir[256];
    int n;
};

static void pp_free(struct pp_fx *fx)
{
    main_state_free(&fx->ms);
    if (fx->dir[0])
        bii_tear_down(fx->dir);
}

/* Chain of n blocks, genesis first, heights/links/work-inputs correct, every
 * block flagged HAVE_DATA at (file 0, 100 + 40 i). No disk records yet. */
static bool pp_init(struct pp_fx *fx, int n)
{
    memset(fx, 0, sizeof(*fx));
    fx->n = n;
    main_state_init(&fx->ms);
    if (!bii_make_tmpdir(fx->dir, sizeof(fx->dir)))
        return false;
    char blocks[300];
    snprintf(blocks, sizeof(blocks), "%s/blocks", fx->dir);
    if (mkdir(blocks, 0755) != 0 && errno != EEXIST)
        return false;
    for (int i = 0; i < n; i++) {
        struct block_index *bi = &fx->b[i];
        fx->h[i].data[0] = (uint8_t)(i + 1);
        fx->h[i].data[1] = 0x5A;
        fx->h[i].data[31] = (uint8_t)(0xB0 + (i & 7));
        if (i == 0)
            fx->h[0] = chain_params_get()->consensus.hashGenesisBlock;
        bi->phashBlock = &fx->h[i];
        bi->pprev = i ? &fx->b[i - 1] : NULL;
        bi->nHeight = i;
        bi->nBits = 0x2007ffff;
        bi->nTx = 1;
        bi->nChainTx = (unsigned)(i + 1);
        bi->nStatus = BLOCK_HAVE_DATA;
        bi->nFile = 0;
        bi->nDataPos = (unsigned)(100 + 40 * i);
        test_block_map_insert(&fx->ms.map_block_index, &fx->h[i], bi);
    }
    return true;
}

/* Write `len` (<= 36) bytes of a header record (nVersion + prev hash). */
static bool pp_put(const struct pp_fx *fx, int file, long pos,
                   const struct uint256 *prev, size_t len)
{
    char path[320];
    snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat", fx->dir, file);
    FILE *f = fopen(path, "r+b");
    if (!f)
        f = fopen(path, "w+b");
    if (!f)
        return false;
    uint8_t rec[36] = {0};
    memcpy(rec + 4, prev->data, 32);
    bool ok = fseek(f, pos, SEEK_SET) == 0 && fwrite(rec, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

/* Record for each block i >= 1 at its own position, naming block i-1. */
static bool pp_put_default(const struct pp_fx *fx)
{
    for (int i = 1; i < fx->n; i++) {
        if (!pp_put(fx, fx->b[i].nFile, (long)fx->b[i].nDataPos,
                    &fx->h[i - 1], 36))
            return false;
    }
    return true;
}

static void pp_detach_all(struct pp_fx *fx)
{
    for (int i = 1; i < fx->n; i++)
        fx->b[i].pprev = NULL;
}

static int pp_linked(const struct pp_fx *fx)
{
    int c = 0;
    for (int i = 1; i < fx->n; i++)
        if (fx->b[i].pprev)
            c++;
    return c;
}

/* True iff b->nChainWork is k times the block's own proof. */
static bool work_is(const struct block_index *b, int k)
{
    struct arith_uint256 proof = GetBlockProof(b);
    struct arith_uint256 sum = {0};
    for (int j = 0; j < k; j++) {
        struct arith_uint256 next;
        arith_uint256_add(&next, &sum, &proof);
        sum = next;
    }
    return arith_uint256_compare(&sum, &b->nChainWork) == 0;
}

static bool work_is_chain(const struct block_index *b, int n)
{
    for (int i = 0; i < n; i++)
        if (!work_is(&b[i], i + 1))
            return false;
    return true;
}

enum { BII_BOOT_N = 101 };

struct bii_boot_fx {
    struct main_state ms;
    struct block_index blocks[BII_BOOT_N];
    struct uint256 hashes[BII_BOOT_N];
    struct node_db ndb;
    struct app_context ctx;
    char repair_dir[256];
};

static bool bii_boot_init(struct bii_boot_fx *fx)
{
    memset(fx, 0, sizeof(*fx));
    main_state_init(&fx->ms);
    bcs_build_chain(&fx->ms, fx->blocks, fx->hashes, BII_BOOT_N);
    fx->ctx.datadir = "/nonexistent-pprev-repair";
    bii_make_tmpdir(fx->repair_dir, sizeof(fx->repair_dir));
    if (!node_db_open(&fx->ndb, ":memory:"))
        return false;
    for (int i = 0; i < BII_BOOT_N; i++)
        fx->blocks[i].nStatus = 0;
    fx->blocks[BII_BOOT_N - 1].nHeight = 1000;
    return node_db_state_set_int(&fx->ndb, BOOT_CUR_HEIGHTS, -2) &&
           node_db_state_set_int(&fx->ndb, BOOT_CUR_HEIGHTS_CNT, -2) &&
           node_db_state_set_int(&fx->ndb, "pprev_repaired_height", -2);
}

static void bii_boot_free(struct bii_boot_fx *fx)
{
    if (fx->ndb.tx_open)
        node_db_rollback(&fx->ndb);
    if (fx->ndb.open)
        node_db_close(&fx->ndb);
    main_state_free(&fx->ms);
    if (fx->repair_dir[0])
        (void)test_rm_rf_recursive(fx->repair_dir);
}

static bool bii_boot_cursors_are(struct bii_boot_fx *fx, int64_t heights,
                                 int64_t count, int64_t pprev)
{
    int64_t got_heights = 0, got_count = 0, got_pprev = 0;
    bool read = node_db_state_get_int(&fx->ndb, BOOT_CUR_HEIGHTS, &got_heights) &&
           node_db_state_get_int(&fx->ndb, BOOT_CUR_HEIGHTS_CNT, &got_count) &&
           node_db_state_get_int(&fx->ndb, "pprev_repaired_height", &got_pprev);
    printf("[read=%d cursors=%lld,%lld,%lld expected=%lld,%lld,%lld] ", read,
           (long long)got_heights, (long long)got_count, (long long)got_pprev,
           (long long)heights, (long long)count, (long long)pprev);
    return read &&
           got_heights == heights && got_count == count && got_pprev == pprev;
}

static bool bii_boot_oom_case(struct bii_boot_fx *fx)
{
    int out = -999;
    zcl_alloc_fault_fail_nth("pprev_repair_all", 1);
    bool refused = !boot_blkidx_repair_block_index(&fx->ctx, &fx->ms,
                                                   &fx->ndb, fx->repair_dir, &out);
    zcl_alloc_fault_clear();
    return refused && out == -999 && !fx->ndb.tx_open &&
           bii_boot_cursors_are(fx, -2, -2, -2);
}

static bool bii_boot_read_error_case(struct bii_boot_fx *fx)
{
    char blocks[300], path[320];

    snprintf(blocks, sizeof(blocks), "%s/blocks", fx->repair_dir);
    snprintf(path, sizeof(path), "%s/blocks/blk00000.dat", fx->repair_dir);
    if ((mkdir(blocks, 0755) != 0 && errno != EEXIST))
        return false;
    FILE *file = fopen(path, "w+b");
    if (!file)
        return false;
    uint8_t record[36] = {0};
    memcpy(record + 4, fx->hashes[1].data, 32);
    bool wrote = fseek(file, 140, SEEK_SET) == 0 &&
                 fwrite(record, 1, sizeof(record), file) == sizeof(record);
    memcpy(record + 4, fx->hashes[0].data, 32);
    wrote = fseek(file, 174, SEEK_SET) == 0 &&
            fwrite(record, 1, 35, file) == 35 && wrote;
    wrote = fclose(file) == 0 && wrote;
    fx->blocks[1].nStatus = BLOCK_HAVE_DATA;
    fx->blocks[1].nDataPos = 174;
    fx->blocks[2].nStatus = BLOCK_HAVE_DATA;
    fx->blocks[2].nDataPos = 140;
    fx->blocks[2].pprev = NULL;
    fx->blocks[BII_BOOT_N - 1].nHeight = BII_BOOT_N - 1;
    int out = -999;
    bool refused = wrote && !boot_blkidx_repair_block_index(
        &fx->ctx, &fx->ms, &fx->ndb, fx->repair_dir, &out);
    return refused && out == -999 && !fx->ndb.tx_open &&
           bii_boot_cursors_are(fx, -2, -2, -2);
}

static bool bii_boot_height_oom_case(struct bii_boot_fx *fx)
{
    int out = -999;
    zcl_alloc_fault_fail_nth("height_repair_mark", 1);
    bool refused = !boot_blkidx_repair_block_index(&fx->ctx, &fx->ms,
                                                   &fx->ndb, fx->repair_dir, &out);
    zcl_alloc_fault_clear();
    return refused && out == -999 && !fx->ndb.tx_open &&
           bii_boot_cursors_are(fx, -2, -2, -2);
}

static bool bii_boot_repair_short_record(struct bii_boot_fx *fx)
{
    char path[320];
    snprintf(path, sizeof(path), "%s/blocks/blk00000.dat", fx->repair_dir);
    FILE *file = fopen(path, "r+b");
    if (file) {
        uint8_t record[36] = {0};
        memcpy(record + 4, fx->hashes[0].data, 32);
        if (fseek(file, 174, SEEK_SET) != 0 ||
            fwrite(record, 1, sizeof(record), file) != sizeof(record)) {
            fclose(file);
            return false;
        }
        if (fclose(file) != 0)
            return false;
    }
    return true;
}

static bool bii_boot_retry_case(struct bii_boot_fx *fx)
{
    if (!bii_boot_repair_short_record(fx))
        return false;
    for (int i = 0; i < BII_BOOT_N; i++)
        memset(&fx->blocks[i].nChainWork, 0,
               sizeof(fx->blocks[i].nChainWork));
    fx->blocks[BII_BOOT_N - 1].nHeight = 1000;
    int out = -999;
    bool retried = boot_blkidx_repair_block_index(&fx->ctx, &fx->ms,
                                                  &fx->ndb, fx->repair_dir, &out);
    bool work = work_is_chain(fx->blocks, BII_BOOT_N);
    bool cursors = bii_boot_cursors_are(fx, BII_BOOT_N - 1, BII_BOOT_N,
                                        BII_BOOT_N - 1);
    printf("[retried=%d out=%d cursors=%d work=%d] ", retried, out,
           cursors, work);
    return retried && out == 1 && work && cursors;
}

static bool bii_boot_read_retry_case(struct bii_boot_fx *fx)
{
    if (!bii_boot_repair_short_record(fx))
        return false;
    int out = -999;
    bool retried = boot_blkidx_repair_block_index(&fx->ctx, &fx->ms,
                                                  &fx->ndb, fx->repair_dir, &out);
    return retried && out == 0 && work_is_chain(fx->blocks, BII_BOOT_N) &&
           bii_boot_cursors_are(fx, BII_BOOT_N - 1, BII_BOOT_N,
                                BII_BOOT_N - 1);
}

static bool bii_boot_foreign_tx_case(struct bii_boot_fx *fx)
{
    if (!node_db_begin(&fx->ndb))
        return false;
    int out = -999;
    bool refused = !boot_blkidx_repair_block_index(&fx->ctx, &fx->ms,
                                                   &fx->ndb, fx->repair_dir, &out);
    bool kept = refused && fx->ndb.tx_open && out == -999;
    if (fx->ndb.tx_open)
        node_db_rollback(&fx->ndb);
    return kept && !fx->ndb.tx_open;
}

static int t_mg_boot_pprev_read_error(void)
{
    int failures = 0;
    struct bii_boot_fx fx;
    if (!bii_boot_init(&fx)) {
        BII_RUN("bii: boot pprev read-error fixture setup", false);
        bii_boot_free(&fx);
        return failures;
    }
    int out = -999;
    BII_RUN("bii: absent block-body directory refuses repair before cursor mutation",
            !boot_blkidx_repair_block_index(&fx.ctx, &fx.ms, &fx.ndb, NULL, &out) &&
            !boot_blkidx_repair_block_index(&fx.ctx, &fx.ms, &fx.ndb, "", &out) &&
            out == -999 && !fx.ndb.tx_open && bii_boot_cursors_are(&fx, -2, -2, -2));
    BII_RUN("bii: boot pprev read error rolls back repair cursors",
            bii_boot_read_error_case(&fx));
    BII_RUN("bii: boot no-op retry after record repair preserves valid work",
            bii_boot_read_retry_case(&fx));
    bii_boot_free(&fx);
    return failures;
}

static int t_mg_boot_pprev_oom_rolls_back_cursors(void)
{
    int failures = 0;
    struct bii_boot_fx fx;
    if (!bii_boot_init(&fx)) {
        BII_RUN("bii: boot pprev fixture setup", false);
        bii_boot_free(&fx);
        return failures;
    }
    BII_RUN("bii: boot height OOM rolls back repair cursors",
            bii_boot_height_oom_case(&fx));
    BII_RUN("bii: boot pprev OOM rolls back height and pprev cursors",
            bii_boot_oom_case(&fx));
    BII_RUN("bii: boot retry after OOM repairs stale flat work and stamps cursors",
            bii_boot_retry_case(&fx));
    BII_RUN("bii: boot repair refuses a foreign transaction without rolling it back",
            bii_boot_foreign_tx_case(&fx));
    bii_boot_free(&fx);
    return failures;
}

static bool heights_are_index(const struct block_index *b, int n)
{
    for (int i = 0; i < n; i++)
        if (b[i].nHeight != i)
            return false;
    return true;
}

/* Which entries the scan selects: height above the cursor, flagged data,
 * a real file position (0 and 1 are the boundary), never the genesis. */
static bool pp_scan_a_links(const struct pp_fx *fx)
{
    return fx->b[3].pprev == &fx->b[2] && fx->b[4].pprev == &fx->b[3] &&
           fx->b[6].pprev == &fx->b[5] && !fx->b[1].pprev &&
           !fx->b[2].pprev && !fx->b[5].pprev && !fx->b[7].pprev;
}

static bool pp_scan_b_links(const struct pp_fx *fx)
{
    return fx->b[1].pprev == &fx->b[0] && fx->b[2].pprev == &fx->b[1] &&
           !fx->b[5].pprev && !fx->b[7].pprev;
}

static bool pp_scan_setup(struct pp_fx *fx)
{
    pp_detach_all(fx);
    fx->b[3].nDataPos = 1;       /* smallest real position: scanned */
    fx->b[5].nStatus = 0;        /* no data: never scanned */
    fx->b[7].nFile = 1;          /* own file, so its record cannot overlap */
    fx->b[7].nDataPos = 0;       /* no position: never scanned */
    return pp_put_default(fx) &&
           pp_put(fx, 0, 1, &fx->h[2], 36) &&
           pp_put(fx, 1, 0, &fx->h[6], 36) &&
           pp_put(fx, 0, (long)fx->b[0].nDataPos, &fx->h[4], 36);
}

static int t_mg_pprev_scan_set(void)
{
    int failures = 0;
    struct pp_fx fx;
    if (!pp_init(&fx, 8)) {
        BII_RUN("bii: pprev scan fixture setup", false);
        pp_free(&fx);
        return failures;
    }
    bool wrote = pp_scan_setup(&fx);

    int out = -999;
    int ra = wrote ? block_index_repair_pprev(&fx.ms, fx.dir, 2, &out) : -1;
    BII_RUN("bii: pprev scan above cursor relinks exactly the entries "
            "past it with data and a position",
            wrote && ra == 3 && pp_scan_a_links(&fx));
    BII_RUN("bii: pprev scan reports the highest height", out == 7);

    int rb = wrote ? block_index_repair_pprev(&fx.ms, fx.dir, -1, &out) : -1;
    BII_RUN("bii: pprev scan from the start picks up the rest",
            rb == 2 && pp_scan_b_links(&fx));
    BII_RUN("bii: pprev scan never relinks the genesis", !fx.b[0].pprev);
    pp_free(&fx);
    return failures;
}

/* ZCL_PPREV_REPAIR_MAX_READS: a count of entries to read, 0 when unset or
 * not a plain non-negative integer. */
static bool pp_env_case(const char *val, int n, int expect)
{
    struct pp_fx fx;
    bool ok = false;
    if (val)
        setenv("ZCL_PPREV_REPAIR_MAX_READS", val, 1);
    else
        unsetenv("ZCL_PPREV_REPAIR_MAX_READS");
    if (pp_init(&fx, n) && pp_put_default(&fx)) {
        pp_detach_all(&fx);
        int r = block_index_repair_pprev(&fx.ms, fx.dir, -1, NULL);
        ok = r == expect && pp_linked(&fx) == expect;
    }
    pp_free(&fx);
    unsetenv("ZCL_PPREV_REPAIR_MAX_READS");
    return ok;
}

static int t_mg_pprev_max_reads_env(void)
{
    int failures = 0;
    BII_RUN("bii: pprev max-reads unset reads every entry",
            pp_env_case(NULL, 12, 11));
    BII_RUN("bii: pprev max-reads empty reads every entry",
            pp_env_case("", 12, 11));
    BII_RUN("bii: pprev max-reads 1 reads one entry",
            pp_env_case("1", 12, 1));
    BII_RUN("bii: pprev max-reads 10 is decimal and reads ten",
            pp_env_case("10", 12, 10));
    BII_RUN("bii: pprev max-reads with trailing junk is ignored",
            pp_env_case("3x", 12, 11));
    BII_RUN("bii: pprev max-reads that is not a number is ignored",
            pp_env_case("abc", 12, 11));
    BII_RUN("bii: pprev max-reads negative is ignored",
            pp_env_case("-1", 12, 11));
    BII_RUN("bii: pprev max-reads 0 means no limit",
            pp_env_case("0", 12, 11));
    return failures;
}

/* Reads go in (file, position) order: each height is taken from the parent
 * as it stands, so a child read before its parent keeps a stale height. */
static int t_mg_pprev_disk_order(void)
{
    int failures = 0;
    struct pp_fx fx;
    bool wrote = pp_init(&fx, 31);
    for (int i = 1; wrote && i < 31; i++) {
        struct block_index *bi = &fx.b[i];
        bi->nHeight = 100;
        bi->nFile = (i - 1) / 10;
        bi->nDataPos = (unsigned)(100 + 40 * ((i - 1) % 10));
        wrote = pp_put(&fx, bi->nFile, (long)bi->nDataPos, &fx.h[i - 1], 36);
    }
    int r = wrote ? block_index_repair_pprev(&fx.ms, fx.dir, -1, NULL) : -1;
    bool skips = true;
    for (int i = 1; i < 31; i++)
        skips = skips && fx.b[i].pskip != NULL;
    BII_RUN("bii: pprev heights follow disk order across files",
            wrote && r == 30 && heights_are_index(fx.b, 31));
    BII_RUN("bii: pprev repair rebuilds the skip pointer of a moved entry",
            skips);
    BII_RUN("bii: pprev repair recomputes chain work parents first",
            work_is_chain(fx.b, 31));
    pp_free(&fx);
    return failures;
}

static bool pp_detail_links(const struct pp_fx *fx)
{
    return fx->b[1].pprev == &fx->b[0] && fx->b[3].pprev == &fx->b[2] &&
           heights_are_index(fx->b, 7) &&
           fx->b[2].pskip == &fx->b[0] && fx->b[3].pskip == &fx->b[1];
}

static bool pp_detail_tx(const struct pp_fx *fx)
{
    return fx->b[1].nChainTx == 2 && fx->b[2].nChainTx == 3 &&
           fx->b[3].nChainTx == 4 && fx->b[4].nChainTx == 5 &&
           fx->b[5].nChainTx == 0 && fx->b[6].nChainTx == 888;
}

/* One fix per kind: missing link, wrong height, both, already right, then
 * the chain-tx rules (no tx or no parent total leaves the stored total). */
static int t_mg_pprev_fix_details(void)
{
    int failures = 0;
    struct pp_fx fx;
    bool ok = pp_init(&fx, 7) && pp_put_default(&fx);
    fx.b[1].pprev = NULL;
    fx.b[2].nHeight = 50;
    fx.b[3].pprev = &fx.b[0];
    fx.b[3].nHeight = 77;
    fx.b[1].nChainTx = 0;
    fx.b[2].nChainTx = fx.b[3].nChainTx = fx.b[4].nChainTx = 999;
    fx.b[5].nTx = 0;
    fx.b[5].nChainTx = 0;
    fx.b[6].nChainTx = 888;
    int r = ok ? block_index_repair_pprev(&fx.ms, fx.dir, -1, NULL) : -1;
    BII_RUN("bii: pprev repair counts each fixed link and height once",
            ok && r == 4);
    BII_RUN("bii: pprev repair fixes links, heights and skip pointers",
            pp_detail_links(&fx));
    BII_RUN("bii: pprev repair recomputes chain tx only with tx and a parent "
            "total", pp_detail_tx(&fx));
    BII_RUN("bii: pprev repair recomputes chain work after a relink",
            work_is_chain(fx.b, 7));
    pp_free(&fx);
    return failures;
}

static void pp_recompute_work_from(struct pp_fx *fx, int first)
{
    for (int i = first; i < fx->n; i++) {
        struct arith_uint256 proof = GetBlockProof(&fx->b[i]);
        if (fx->b[i].pprev)
            arith_uint256_add(&fx->b[i].nChainWork,
                              &fx->b[i].pprev->nChainWork, &proof);
        else
            fx->b[i].nChainWork = proof;
    }
}

static int t_mg_pprev_allocation_refusal(void)
{
    int failures = 0;
    struct pp_fx fx;
    bool ok = pp_init(&fx, 5) && pp_put_default(&fx);
    if (ok) {
        pp_recompute_work_from(&fx, 0);
        fx.b[2].pprev = &fx.b[0];
        pp_recompute_work_from(&fx, 2);
    }
    struct arith_uint256 stale_work = fx.b[2].nChainWork;
    zcl_alloc_fault_fail_nth("pprev_repair_all", 1);
    int r = ok ? block_index_repair_pprev(&fx.ms, fx.dir, -1, NULL) : -2;
    bool refused = ok && r == -1 && fx.b[2].pprev == &fx.b[0] &&
                   arith_uint256_compare(&fx.b[2].nChainWork,
                                         &stale_work) == 0;
    BII_RUN("bii: pprev work-array OOM refuses before relinking", refused);
    zcl_alloc_fault_clear();
    r = ok ? block_index_repair_pprev(&fx.ms, fx.dir, -1, NULL) : -2;
    BII_RUN("bii: pprev retry after OOM repairs links and cumulative work",
            refused && r == 1 && fx.b[2].pprev == &fx.b[1] &&
            work_is_chain(fx.b, 5));
    pp_free(&fx);
    return failures;
}

static int t_mg_pprev_scan_allocation_refusal(void)
{
    int failures = 0;
    struct pp_fx fx;
    bool ok = pp_init(&fx, 3) && pp_put_default(&fx);
    if (ok)
        fx.b[1].pprev = NULL;
    zcl_alloc_fault_fail_nth("pprev_repair_arr", 1);
    int r = ok ? block_index_repair_pprev(&fx.ms, fx.dir, -1, NULL) : -2;
    BII_RUN("bii: pprev scan-array OOM is an explicit refusal without mutation",
            ok && r == -1 && !fx.b[1].pprev);
    zcl_alloc_fault_clear();
    pp_free(&fx);
    return failures;
}

/* A record shorter than the 36-byte header is a read error, not a parent;
 * a record that ends exactly at end of file is read whole. */
static int t_mg_pprev_short_record(void)
{
    int failures = 0;
    struct pp_fx fx;
    bool ok = pp_init(&fx, 3);
    fx.b[1].pprev = NULL;
    fx.b[2].pprev = NULL;
    fx.b[2].nFile = 1;
    fx.b[2].nDataPos = 1;
    ok = ok && pp_put(&fx, 0, (long)fx.b[1].nDataPos, &fx.h[0], 35) &&
         pp_put(&fx, 1, 1, &fx.h[1], 36);
    int r = ok ? block_index_repair_pprev(&fx.ms, fx.dir, -1, NULL) : -1;
    BII_RUN("bii: pprev short record is not read as a parent",
            ok && !fx.b[1].pprev);
    BII_RUN("bii: pprev record ending at end of file is read whole",
            fx.b[2].pprev == &fx.b[1] && r == -1);
    BII_RUN("bii: pprev read error recomputes the valid child before refusal",
            work_is(&fx.b[2], 2));
    bool repaired_file = pp_put(&fx, 0, (long)fx.b[1].nDataPos,
                                &fx.h[0], 36);
    r = repaired_file ? block_index_repair_pprev(&fx.ms, fx.dir, -1, NULL) : -2;
    BII_RUN("bii: pprev retry after record repair restores complete chainwork",
            repaired_file && r == 1 && work_is_chain(fx.b, 3));
    pp_free(&fx);
    return failures;
}

static int t_mg_pprev_edges(void)
{
    int failures = 0;
    int out = -999;
    BII_RUN("bii: pprev NULL state returns 0 and -1",
            block_index_repair_pprev(NULL, "/nonexistent-dir", -1, &out) == 0 &&
            out == -1);
    struct pp_fx fx;
    bool ok = pp_init(&fx, 4);
    out = -999;
    BII_RUN("bii: pprev NULL datadir returns 0 and -1",
            ok && block_index_repair_pprev(&fx.ms, NULL, -1, &out) == 0 &&
            out == -1);
    pp_free(&fx);

    struct main_state empty;
    main_state_init(&empty);
    out = -999;
    BII_RUN("bii: pprev on an empty index returns 0",
            block_index_repair_pprev(&empty, "/nonexistent-dir", -1, &out) == 0);
    main_state_free(&empty);

    /* One entry whose parent is absent: nothing to fix, max still reported. */
    ok = pp_init(&fx, 2);
    fx.b[1].nHeight = 7;
    fx.b[1].pprev = NULL;
    fx.b[1].nStatus = 0;
    fx.b[0].nStatus = 0;
    out = -999;
    int r = ok ? block_index_repair_pprev(&fx.ms, fx.dir, -1, &out) : -1;
    BII_RUN("bii: pprev with nothing to scan still reports the max height",
            ok && r == 0 && out == 7);
    pp_free(&fx);

    /* Exactly one fixable entry is still scanned. */
    ok = pp_init(&fx, 2) && pp_put_default(&fx);
    fx.b[1].pprev = NULL;
    r = ok ? block_index_repair_pprev(&fx.ms, fx.dir, -1, NULL) : -1;
    BII_RUN("bii: pprev with one fixable entry fixes it",
            ok && r == 1 && fx.b[1].pprev == &fx.b[0]);
    pp_free(&fx);
    return failures;
}

static void pp_sql_header(struct block_header *h, const struct uint256 *prev,
                          unsigned height, struct uint256 *hash)
{
    block_header_init(h);
    h->nVersion = 4;
    h->hashPrevBlock = *prev;
    h->hashMerkleRoot.data[0] = (uint8_t)height;
    h->nTime = height;
    h->nBits = 0x2007ffff;
    h->nNonce.data[0] = (uint8_t)height;
    h->nSolution[0] = (uint8_t)height;
    h->nSolutionSize = 1;
    block_header_get_hash(h, hash);
}

static bool pp_sql_save(struct node_db *ndb, const struct block_header *h,
                        const struct uint256 *hash, int height)
{
    struct db_block row = {0};
    memcpy(row.hash, hash->data, 32);
    row.height = height;
    memcpy(row.prev_hash, h->hashPrevBlock.data, 32);
    row.version = h->nVersion;
    memcpy(row.merkle_root, h->hashMerkleRoot.data, 32);
    row.time = h->nTime;
    row.bits = h->nBits;
    memcpy(row.nonce, h->nNonce.data, 32);
    row.solution = (uint8_t *)h->nSolution;
    row.solution_len = h->nSolutionSize;
    row.status = 3;
    row.num_tx = 1;
    return db_block_save_canonical(ndb, &row);
}

static int t_mg_pprev_sqlite_header_fallback(void)
{
    int failures = 0;
    enum { N = 3 };
    struct block_header headers[N - 1];
    struct uint256 hashes[N];
    struct block_index blocks[N];
    struct main_state ms;
    struct node_db ndb = {0};
    struct db_service dbsvc;
    struct app_runtime_context runtime = {0};
    memset(&dbsvc, 0, sizeof(dbsvc));
    main_state_init(&ms);
    hashes[0] = chain_params_get()->consensus.hashGenesisBlock;
    memset(&blocks[0], 0, sizeof(blocks[0]));
    blocks[0].phashBlock = &hashes[0];
    blocks[0].nBits = 0x2007ffff;
    test_block_map_insert(&ms.map_block_index, &hashes[0], &blocks[0]);
    db_service_init(&dbsvc);
    bool ok = node_db_open(&ndb, ":memory:") && db_service_attach(&dbsvc, &ndb) &&
              db_service_start(&dbsvc);
    for (int i = 1; ok && i < N; i++) {
        pp_sql_header(&headers[i - 1], &hashes[i - 1], (unsigned)i, &hashes[i]);
        ok = pp_sql_save(&ndb, &headers[i - 1], &hashes[i], i);
        memset(&blocks[i], 0, sizeof(blocks[i]));
        blocks[i].phashBlock = &hashes[i];
        blocks[i].nHeight = i;
        blocks[i].nBits = 0x2007ffff;
        blocks[i].nStatus = BLOCK_HAVE_DATA;
        blocks[i].nDataPos = 8;
        blocks[i].nTx = 1;
        test_block_map_insert(&ms.map_block_index, &hashes[i], &blocks[i]);
    }
    runtime.db_service = &dbsvc;
    app_runtime_set_current(&runtime);
    int r = ok ? block_index_repair_pprev(&ms, "/nonexistent-sqlite-fallback", -1,
                                          NULL) : -2;
    BII_RUN("bii: missing body files fall back to hash-bound SQLite headers",
            ok && r == 2 && blocks[1].pprev == &blocks[0] &&
            blocks[2].pprev == &blocks[1] && work_is_chain(blocks, N));

    blocks[2].pprev = NULL;
    ok = node_db_exec(&ndb, "UPDATE blocks SET prev_hash=zeroblob(32) WHERE height=2");
    r = ok ? block_index_repair_pprev(&ms, "/nonexistent-sqlite-fallback", -1,
                                      NULL) : -2;
    BII_RUN("bii: a SQLite header that does not hash-bind still refuses repair",
            ok && r == -1 && !blocks[2].pprev);
    app_runtime_set_current(NULL);
    db_service_stop(&dbsvc);
    node_db_close(&ndb);
    main_state_free(&ms);
    return failures;
}

/* ── height-repair verdicts and exact counts ────────────────── */

static bool work_all_zero(const struct block_index *b, int n)
{
    for (int i = 0; i < n; i++)
        if (!work_is(&b[i], 0))
            return false;
    return true;
}

/* A clean index plus parentless non-genesis entries is NOT wrong: the repair
 * leaves heights and chain work untouched. */
static int t_mg_hr_clean_stubs(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);
    enum { N = 6 };
    struct block_index blocks[N];
    struct uint256 hashes[N];
    bcs_build_chain(&ms, blocks, hashes, N);

    struct block_index s[3];
    struct uint256 sh[3];
    memset(s, 0, sizeof(s));
    memset(sh, 0, sizeof(sh));
    for (int i = 0; i < 3; i++) {
        sh[i].data[0] = (uint8_t)(0xC1 + i);
        s[i].phashBlock = &sh[i];
        s[i].nBits = 0x2007ffff;
    }
    s[0].nHeight = 9;  s[0].nStatus = BLOCK_HAVE_DATA;  /* detached root */
    s[1].nHeight = 5;  s[1].phashBlock = NULL;          /* no hash at all */
    s[2].nHeight = 0;  s[2].nStatus = 0;                /* empty stub */
    for (int i = 0; i < 3; i++)
        test_block_map_insert(&ms.map_block_index, &sh[i], &s[i]);

    int out = -999;
    int r = block_index_repair_heights_range(&ms, -1, &out);
    BII_RUN("bii: parentless non-genesis entries are not wrong heights",
            r == 0 && out == 9 && s[1].nHeight == 5 && s[0].nHeight == 9);
    BII_RUN("bii: a clean index keeps its stored chain work",
            work_all_zero(blocks, N) && work_all_zero(s, 3));
    main_state_free(&ms);
    return failures;
}

/* The cursor: an entry AT min_height is covered by the prior run. */
static int t_mg_hr_cursor_edge(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);
    enum { N = 5 };
    struct block_index blocks[N];
    struct uint256 hashes[N];
    bcs_build_chain(&ms, blocks, hashes, N);
    blocks[3].nHeight = 7;

    int at = block_index_repair_heights_range(&ms, 7, NULL);
    BII_RUN("bii: height at the cursor is covered, not repaired",
            at == 0 && blocks[3].nHeight == 7 && blocks[4].nHeight == 4);
    int below = block_index_repair_heights_range(&ms, 6, NULL);
    BII_RUN("bii: height above the cursor is repaired and counted once",
            below == 1 && heights_are_index(blocks, N));
    BII_RUN("bii: height repair recomputes chain work from the genesis",
            work_is_chain(blocks, N));
    main_state_free(&ms);
    return failures;
}

/* A wrong genesis counts once and a wrong follower counts once. */
static int t_mg_hr_exact_counts(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);
    enum { N = 5 };
    struct block_index blocks[N];
    struct uint256 hashes[N];
    bcs_build_chain(&ms, blocks, hashes, N);
    blocks[0].nHeight = 4;
    blocks[4].nHeight = 9;
    int r = block_index_repair_heights_range(&ms, -1, NULL);
    BII_RUN("bii: height repair returns the number of heights fixed",
            r == 2 && heights_are_index(blocks, N));
    BII_RUN("bii: a correct genesis at height 0 is not counted",
            block_index_repair_heights_range(&ms, -1, NULL) == 0);
    main_state_free(&ms);
    return failures;
}

static bool hr_untouched(const struct block_index *b, int h, uint32_t work)
{
    return b->nHeight == h && b->nChainWork.pn[0] == work;
}

/* Detached roots, their children, and an entry whose parent left the map
 * keep their stored work and heights; only genesis-rooted work is rebuilt. */
static int t_mg_hr_detached_work(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);
    enum { N = 3 };
    struct block_index blocks[N];
    struct uint256 hashes[N];
    bcs_build_chain(&ms, blocks, hashes, N);
    blocks[2].nHeight = 9;

    struct block_index d[3], outside;
    struct uint256 dh[3];
    memset(d, 0, sizeof(d));
    memset(dh, 0, sizeof(dh));
    memset(&outside, 0, sizeof(outside));
    outside.nHeight = 2;
    for (int i = 0; i < 3; i++) {
        dh[i].data[0] = (uint8_t)(0xD1 + i);
        d[i].phashBlock = &dh[i];
        d[i].nBits = 0x2007ffff;
        d[i].nChainWork.pn[0] = 0x1234;
    }
    d[0].nHeight = 7;  d[0].nStatus = BLOCK_HAVE_DATA;  /* detached root */
    d[1].nHeight = 8;  d[1].pprev = &d[0];              /* its child */
    d[2].nHeight = 3;  d[2].pprev = &outside;           /* parent unmapped */
    for (int i = 0; i < 3; i++)
        test_block_map_insert(&ms.map_block_index, &dh[i], &d[i]);

    int r = block_index_repair_heights_range(&ms, -1, NULL);
    BII_RUN("bii: height repair fixes the genesis-rooted height once",
            r == 1 && blocks[2].nHeight == 2);
    BII_RUN("bii: detached entries keep stored heights and chain work",
            hr_untouched(&d[0], 7, 0x1234) && hr_untouched(&d[1], 8, 0x1234) &&
            hr_untouched(&d[2], 3, 0x1234));
    main_state_free(&ms);
    return failures;
}

static int t_mg_hr_lone_entries(void)
{
    int failures = 0;
    int out = -999;
    BII_RUN("bii: height repair NULL state returns 0 and -1",
            block_index_repair_heights_range(NULL, -1, &out) == 0 &&
            out == -1);

    struct main_state ms;
    main_state_init(&ms);
    struct block_index g;
    struct uint256 gh = chain_params_get()->consensus.hashGenesisBlock;
    memset(&g, 0, sizeof(g));
    g.phashBlock = &gh;
    g.nHeight = 7;
    g.nBits = 0x2007ffff;
    test_block_map_insert(&ms.map_block_index, &gh, &g);
    out = -999;
    int r = block_index_repair_heights_range(&ms, -1, &out);
    BII_RUN("bii: a lone wrong genesis reports its corrected max",
            r == 1 && g.nHeight == 0 && out == 0 && work_is(&g, 1));
    main_state_free(&ms);

    main_state_init(&ms);
    struct block_index s;
    struct uint256 sh = {0};
    memset(&s, 0, sizeof(s));
    sh.data[0] = 0xE1;
    s.phashBlock = &sh;
    s.nHeight = -1;
    test_block_map_insert(&ms.map_block_index, &sh, &s);
    out = -999;
    r = block_index_repair_heights_range(&ms, -1, &out);
    BII_RUN("bii: a lone unset-height entry reports max -1",
            r == 0 && out == -1);
    main_state_free(&ms);
    return failures;
}

/* A chain whose stored heights are all offset: propagation must walk it in
 * height order (one pass), not in map order (more passes than allowed). */
static int t_mg_hr_long_offset_chain(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);
    enum { N = 60 };
    struct block_index blocks[N];
    struct uint256 hashes[N];
    bcs_build_chain(&ms, blocks, hashes, N);
    for (int i = 0; i < N; i++)
        blocks[i].nHeight = 100 + i;
    bii_repair_observer_install();
    int r = block_index_repair_heights_range(&ms, -1, NULL);
    BII_RUN("bii: an offset long chain is fully repaired",
            r == N && heights_are_index(blocks, N));
    BII_RUN("bii: height repair emits one repair event",
            atomic_load(&g_bii_ev_repair) == 1);
    BII_RUN("bii: an offset long chain gets cumulative work",
            work_is_chain(blocks, N));
    event_clear_observers(EV_BLOCK_INDEX_REPAIR);
    main_state_free(&ms);
    return failures;
}

static bool hr_oom_case(const char *label)
{
    enum { N = 6 };
    struct main_state ms;
    main_state_init(&ms);
    struct block_index blocks[N];
    struct uint256 hashes[N];
    bcs_build_chain(&ms, blocks, hashes, N);
    blocks[N - 1].nHeight = 999;
    zcl_alloc_fault_fail_nth(label, 1);
    int refused = block_index_repair_heights_range(&ms, -1, NULL);
    zcl_alloc_fault_clear();
    bool preserved = blocks[N - 1].nHeight == 999;
    int repaired = block_index_repair_heights_range(&ms, -1, NULL);
    bool ok = refused == -1 && preserved && repaired == 1 &&
              heights_are_index(blocks, N);
    main_state_free(&ms);
    return ok;
}

static bool hr_genesis_oom_case(void)
{
    struct main_state ms;
    main_state_init(&ms);
    struct uint256 hash = chain_params_get()->consensus.hashGenesisBlock;
    struct block_index genesis = {0};
    genesis.phashBlock = &hash;
    genesis.nHeight = 7;
    genesis.nBits = 0x2007ffff;
    test_block_map_insert(&ms.map_block_index, &hash, &genesis);
    block_index_heights_repaired_reset_for_test();
    zcl_alloc_fault_fail_nth("height_repair_stack", 1);
    int refused = block_index_repair_heights(&ms);
    zcl_alloc_fault_clear();
    bool preserved = genesis.nHeight == 7 && work_is(&genesis, 0) &&
                     !block_index_heights_repaired();
    int repaired = block_index_repair_heights(&ms);
    bool ok = refused == -1 && preserved && repaired == 1 &&
              genesis.nHeight == 0 && work_is(&genesis, 1);
    main_state_free(&ms);
    return ok;
}

static int t_mg_hr_allocation_refusal(void)
{
    int failures = 0;
    static const char *const labels[] = {
        "block_map_snapshot_indices", "height_repair_byptr",
        "height_repair_mark", "height_repair_stack"
    };
    for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++)
        BII_RUN("bii: height-repair OOM refuses and retries", hr_oom_case(labels[i]));
    BII_RUN("bii: stack OOM leaves wrong genesis height and work untouched",
            hr_genesis_oom_case());
    return failures;
}

static bool hr_cursor_state(struct node_db *ndb, int64_t want_height,
                            int64_t want_count)
{
    int64_t height = 0, count = 0;
    return node_db_state_get_int(ndb, BOOT_CUR_HEIGHTS, &height) &&
           node_db_state_get_int(ndb, BOOT_CUR_HEIGHTS_CNT, &count) &&
           height == want_height && count == want_count;
}

static int t_mg_hr_cursor_allocation_refusal(void)
{
    int failures = 0;
    enum { N = 6 };
    struct main_state ms;
    main_state_init(&ms);
    struct block_index blocks[N];
    struct uint256 hashes[N];
    bcs_build_chain(&ms, blocks, hashes, N);
    blocks[N - 1].nHeight = 999;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, ":memory:") &&
              node_db_state_set_int(&ndb, BOOT_CUR_HEIGHTS, -2) &&
              node_db_state_set_int(&ndb, BOOT_CUR_HEIGHTS_CNT, -2);
    zcl_alloc_fault_fail_nth("height_repair_mark", 1);
    int refused = ok ? boot_cursor_repair_heights(&ms, &ndb) : -2;
    zcl_alloc_fault_clear();
    bool preserved = hr_cursor_state(&ndb, -2, -2);
    int repaired = ok ? boot_cursor_repair_heights(&ms, &ndb) : -2;
    bool committed = hr_cursor_state(&ndb, N - 1, N);
    BII_RUN("bii: cursor height-repair OOM preserves and retry stamps high-water",
            ok && refused == -1 && preserved && repaired == 1 && committed && heights_are_index(blocks, N));
    if (ndb.open)
        node_db_close(&ndb);
    main_state_free(&ms);
    return failures;
}

static int bii_mutant_gap_tests(void)
{
    int failures = 0;
    failures += t_mg_names();
    failures += t_mg_boot_pprev_oom_rolls_back_cursors();
    failures += t_mg_boot_pprev_read_error();
    failures += t_mg_status_replaced();
    failures += t_mg_dump_fields();
    failures += t_mg_pprev_scan_set();
    failures += t_mg_pprev_max_reads_env();
    failures += t_mg_pprev_disk_order();
    failures += t_mg_pprev_fix_details();
    failures += t_mg_pprev_allocation_refusal();
    failures += t_mg_pprev_scan_allocation_refusal();
    failures += t_mg_pprev_short_record();
    failures += t_mg_pprev_edges();
    failures += t_mg_hr_clean_stubs();
    failures += t_mg_hr_cursor_edge();
    failures += t_mg_hr_exact_counts();
    failures += t_mg_hr_detached_work();
    failures += t_mg_hr_lone_entries();
    failures += t_mg_hr_long_offset_chain();
    failures += t_mg_hr_allocation_refusal();
    failures += t_mg_hr_cursor_allocation_refusal();
    return failures;
}

/* ── Index repair gaps: pskip after a link-only fix, deep reverse chains,
 *    and heights after a pprev repair that read a child before its parent ── */

/* Write blocks/blk00000.dat holding one 36-byte header prefix (nVersion +
 * hashPrevBlock) per entry; record k starts at byte 8 + 36 * k. */
static bool bii_gap_write_blk(const char *datadir,
                              const struct uint256 *const *prevs, size_t n)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/blocks", datadir);
    (void)mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/blocks/blk00000.dat", datadir);
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    uint8_t pad[8] = {0};
    uint8_t ver[4] = {0};
    bool ok = fwrite(pad, 1, sizeof(pad), f) == sizeof(pad);
    for (size_t k = 0; ok && k < n; k++)
        ok = fwrite(ver, 1, sizeof(ver), f) == sizeof(ver) &&
             fwrite(prevs[k]->data, 1, 32, f) == 32;
    fclose(f);
    return ok;
}

static void bii_gap_cleanup(const char *datadir)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/blocks/blk00000.dat", datadir);
    (void)unlink(path);
    snprintf(path, sizeof(path), "%s/blocks", datadir);
    (void)rmdir(path);
    bii_tear_down(datadir);
}

static void bii_gap_init(struct block_index *b, struct uint256 *h,
                         uint8_t tag, int height)
{
    memset(b, 0, sizeof(*b));
    memset(h, 0, sizeof(*h));
    h->data[0] = tag;
    b->phashBlock = h;
    b->nHeight = height;
    b->nBits = 0x2007ffff;
}

static void bii_gap_mark_disk(struct block_index *b, size_t k)
{
    b->nStatus = BLOCK_HAVE_DATA;
    b->nFile = 0;
    b->nDataPos = (unsigned)(8 + 36 * k);
}

/* Link fixed, height already right: pskip must follow the corrected link. */
static int t_pprev_repair_rebuilds_skip_on_link_only_fix(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);
    char dir[256];
    bii_make_tmpdir(dir, sizeof(dir));

    struct block_index b[4];
    struct uint256 h[4];
    for (int i = 0; i < 4; i++) {
        bii_gap_init(&b[i], &h[i], (uint8_t)(i + 1), i);
        test_block_map_insert(&ms.map_block_index, &h[i], &b[i]);
    }
    h[0] = chain_params_get()->consensus.hashGenesisBlock;
    b[1].pprev = &b[0];
    b[2].pprev = &b[1];
    /* b[3] names b[1] as its parent but its disk header names b[2]; its
     * height 3 is already right, so only the link differs. */
    b[3].pprev = &b[1];
    b[3].pskip = &b[0]; /* stale: the true skip target at height 3 is 1 */
    bii_gap_mark_disk(&b[3], 0);
    const struct uint256 *prevs[1] = {&h[2]};
    bool wrote = bii_gap_write_blk(dir, prevs, 1);

    int fixed = block_index_repair_pprev(&ms, dir, -1, NULL);
    BII_RUN("bii: pprev link-only fix: block file written", wrote);
    BII_RUN("bii: pprev link-only fix: link corrected, height untouched",
            fixed == 1 && b[3].pprev == &b[2] && b[3].nHeight == 3);
    BII_RUN("bii: pprev link-only fix: pskip rebuilt for the new link",
            b[3].pskip == &b[1]);
    BII_RUN("bii: pprev link-only fix: ancestor lookup lands on the right block",
            block_index_get_ancestor(&b[3], 1) == &b[1]);

    bii_gap_cleanup(dir);
    main_state_free(&ms);
    return failures;
}

/* Stored heights in reverse chain order need one propagation pass per link. */
static int t_height_repair_deep_reverse_order(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);

    enum { DEPTH = 64 };
    struct block_index b[DEPTH];
    struct uint256 h[DEPTH];
    for (int i = 0; i < DEPTH; i++) {
        bii_gap_init(&b[i], &h[i], (uint8_t)(i + 1),
                     i == 0 ? 0 : 1000 - i);
        b[i].pprev = (i > 0) ? &b[i - 1] : NULL;
        test_block_map_insert(&ms.map_block_index, &h[i], &b[i]);
    }
    h[0] = chain_params_get()->consensus.hashGenesisBlock;

    (void)block_index_repair_heights(&ms);
    int wrong = 0;
    for (int i = 0; i < DEPTH; i++)
        if (b[i].nHeight != i)
            wrong++;
    BII_RUN("bii: height repair converges on a 64-deep reverse-ordered chain",
            wrong == 0);
    BII_RUN("bii: reverse-ordered chain gets strictly increasing chain work",
            arith_uint256_compare(&b[DEPTH - 1].nChainWork,
                                  &b[DEPTH - 2].nChainWork) > 0);

    main_state_free(&ms);
    return failures;
}

/* A child read before its parent keeps a stale height out of the pprev pass;
 * the boot sequence reruns the height repair, which must settle it. */
static int t_pprev_then_height_repair_settles_child_order(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);
    char dir[256];
    bii_make_tmpdir(dir, sizeof(dir));

    struct block_index b[4];
    struct uint256 h[4];
    for (int i = 0; i < 4; i++) {
        bii_gap_init(&b[i], &h[i], (uint8_t)(i + 1), i == 0 ? 0 : 7);
        test_block_map_insert(&ms.map_block_index, &h[i], &b[i]);
    }
    h[0] = chain_params_get()->consensus.hashGenesisBlock;
    b[1].pprev = &b[0];
    b[1].nHeight = 1;
    /* b[2] is detached (stale label 7); b[3] hangs off it. b[3] sits first
     * on disk, so it is read while b[2] still carries the stale label. */
    b[3].pprev = &b[2];
    bii_gap_mark_disk(&b[3], 0);
    bii_gap_mark_disk(&b[2], 1);
    const struct uint256 *prevs[2] = {&h[2], &h[1]};
    bool wrote = bii_gap_write_blk(dir, prevs, 2);

    int fixed = block_index_repair_pprev(&ms, dir, -1, NULL);
    BII_RUN("bii: pprev repair on child-before-parent order reports work",
            wrote && fixed > 0 && b[2].pprev == &b[1]);
    if (fixed > 0)
        (void)block_index_repair_heights(&ms);
    BII_RUN("bii: height rerun settles the child read before its parent",
            b[2].nHeight == 2 && b[3].nHeight == 3);
    BII_RUN("bii: chain work follows the settled heights",
            arith_uint256_compare(&b[3].nChainWork, &b[2].nChainWork) > 0 &&
            arith_uint256_compare(&b[2].nChainWork, &b[1].nChainWork) > 0);

    bii_gap_cleanup(dir);
    main_state_free(&ms);
    return failures;
}


/* ── pskip of descendants after a repair ─────────────────────────────── */

/* Rebuild every skip pointer in the order given (callers pass height order). */
static void bii_gap_build_all_skips(struct block_index *const *order, int n)
{
    for (int i = 0; i < n; i++)
        block_index_build_skip(order[i]);
}

/* Two branches share genesis. Entry E (height 4) is linked to the wrong
 * branch's height-3 block but its disk header names the right one, and its
 * height already fits. a7's skip jumps from 7 to 1, across the fixed link, and
 * was built through the old link at load. */
static int t_pprev_repair_rebuilds_descendant_skips(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);
    char dir[256];
    bii_make_tmpdir(dir, sizeof(dir));

    enum { NA = 8, NB = 4 };
    struct block_index a[NA], b[NB];
    struct uint256 ha[NA], hb[NB];
    struct block_index *order[NA + NB - 1];
    int no = 0;
    for (int i = 0; i < NA; i++) {
        bii_gap_init(&a[i], &ha[i], (uint8_t)(i + 1), i);
        test_block_map_insert(&ms.map_block_index, &ha[i], &a[i]);
    }
    ha[0] = chain_params_get()->consensus.hashGenesisBlock;
    for (int i = 1; i < NB; i++) {
        bii_gap_init(&b[i], &hb[i], (uint8_t)(0x40 + i), i);
        test_block_map_insert(&ms.map_block_index, &hb[i], &b[i]);
    }
    for (int i = 1; i < NA; i++)
        a[i].pprev = &a[i - 1];
    for (int i = 1; i < NB; i++)
        b[i].pprev = (i == 1) ? &a[0] : &b[i - 1];
    a[4].pprev = &b[3]; /* the corrupt link; a[3] is the real parent */

    order[no++] = &a[0];
    for (int i = 1; i < NB; i++) {
        order[no++] = &a[i];
        order[no++] = &b[i];
    }
    for (int i = NB; i < NA; i++)
        order[no++] = &a[i];
    bii_gap_build_all_skips(order, no); /* load-time skips through the bad link */

    bii_gap_mark_disk(&a[4], 0);
    const struct uint256 *prevs[1] = {&ha[3]};
    bool wrote = bii_gap_write_blk(dir, prevs, 1);

    (void)block_index_repair_pprev(&ms, dir, -1, NULL);
    BII_RUN("bii: descendant skip: block file written and link fixed",
            wrote && a[4].pprev == &a[3]);
    BII_RUN("bii: descendant skip: lookup across the fixed link stays on the branch",
            block_index_get_ancestor(&a[7], 1) == &a[1] &&
            block_index_get_ancestor(&a[7], 3) == &a[3]);
    BII_RUN("bii: descendant skip: pskip matches a fresh rebuild",
            a[7].pskip == &a[1] && a[5].pskip == &a[1]);

    bii_gap_cleanup(dir);
    main_state_free(&ms);
    return failures;
}

/* Height repair: skips that were built from scrambled labels are rebuilt. */
static int t_height_repair_rebuilds_skips(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);

    enum { N = 9 };
    struct block_index a[N];
    struct uint256 h[N];
    for (int i = 0; i < N; i++) {
        bii_gap_init(&a[i], &h[i], (uint8_t)(i + 1), i == 0 ? 0 : 100 - i);
        a[i].pprev = (i > 0) ? &a[i - 1] : NULL;
        a[i].pskip = (i > 1) ? &a[0] : NULL; /* stale */
        test_block_map_insert(&ms.map_block_index, &h[i], &a[i]);
    }
    h[0] = chain_params_get()->consensus.hashGenesisBlock;

    (void)block_index_repair_heights(&ms);
    BII_RUN("bii: height repair skip: heights corrected",
            a[8].nHeight == 8 && a[7].nHeight == 7);
    BII_RUN("bii: height repair skip: lookup lands on the right ancestor",
            block_index_get_ancestor(&a[7], 1) == &a[1] &&
            block_index_get_ancestor(&a[8], 3) == &a[3]);
    BII_RUN("bii: height repair skip: pskip matches a fresh rebuild",
            a[7].pskip == &a[1] && a[6].pskip == &a[4]);

    main_state_free(&ms);
    return failures;
}

/* A pprev cycle, and a child hanging off it, are not genesis-rooted: they keep
 * their stored labels while the rooted chain is corrected. */
static int t_height_repair_cycle_keeps_labels(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);

    struct block_index g, r1, r2, x, y, w;
    struct uint256 hg, hr1, hr2, hx, hy, hw;
    bii_gap_init(&g, &hg, 1, 0);
    bii_gap_init(&r1, &hr1, 2, 9);
    bii_gap_init(&r2, &hr2, 3, 9);
    bii_gap_init(&x, &hx, 4, 50);
    bii_gap_init(&y, &hy, 5, 51);
    bii_gap_init(&w, &hw, 6, 52);
    hg = chain_params_get()->consensus.hashGenesisBlock;
    r1.pprev = &g;
    r2.pprev = &r1;
    x.pprev = &y;
    y.pprev = &x;
    w.pprev = &x;
    test_block_map_insert(&ms.map_block_index, &hg, &g);
    test_block_map_insert(&ms.map_block_index, &hr1, &r1);
    test_block_map_insert(&ms.map_block_index, &hr2, &r2);
    test_block_map_insert(&ms.map_block_index, &hx, &x);
    test_block_map_insert(&ms.map_block_index, &hy, &y);
    test_block_map_insert(&ms.map_block_index, &hw, &w);

    (void)block_index_repair_heights(&ms);
    BII_RUN("bii: cycle beside a rooted chain: rooted heights corrected",
            r1.nHeight == 1 && r2.nHeight == 2);
    BII_RUN("bii: cycle and its child keep their stored labels",
            x.nHeight == 50 && y.nHeight == 51 && w.nHeight == 52);

    main_state_free(&ms);
    return failures;
}


/* A long chain labeled in reverse order is repaired by one linear walk; this
 * only has to finish (the old pass loop cost one pass per link). */
static int t_height_repair_deep_reverse_heap(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);

    enum { DEPTH = 200000 };
    struct block_index *b = calloc(DEPTH, sizeof(*b));
    struct uint256 *h = calloc(DEPTH, sizeof(*h));
    if (!b || !h) {
        free(b);
        free(h);
        main_state_free(&ms);
        BII_RUN("bii: deep reverse chain: allocation", false);
        return failures;
    }
    for (int i = 0; i < DEPTH; i++) {
        bii_gap_init(&b[i], &h[i], 0, i == 0 ? 0 : 2000000 - i);
        h[i].data[1] = (uint8_t)(i & 0xff);
        h[i].data[2] = (uint8_t)((i >> 8) & 0xff);
        h[i].data[3] = (uint8_t)((i >> 16) & 0xff);
        h[i].data[0] = 0xd0;
        b[i].pprev = (i > 0) ? &b[i - 1] : NULL;
        test_block_map_insert(&ms.map_block_index, &h[i], &b[i]);
    }
    h[0] = chain_params_get()->consensus.hashGenesisBlock;

    (void)block_index_repair_heights(&ms);
    int wrong = 0;
    for (int i = 0; i < DEPTH; i++)
        if (b[i].nHeight != i)
            wrong++;
    BII_RUN("bii: 200000-deep reverse-ordered chain fully repaired", wrong == 0);
    BII_RUN("bii: deep chain skip pointer follows the corrected heights",
            block_index_get_ancestor(&b[DEPTH - 1], 1000) == &b[1000]);

    main_state_free(&ms);
    free(b);
    free(h);
    return failures;
}


int test_block_index_integrity(void)
{
    printf("\n=== block_index_integrity tests ===\n");
    int failures = 0;
    failures += t_happy_path();
    failures += t_sidecar_missing();
    failures += t_body_missing();
    failures += t_sidecar_stale();
    failures += t_hash_mismatch();
    failures += t_sidecar_bad_magic();
    failures += t_tip_missing_in_sql();
    failures += t_tip_height_mismatch();
    failures += t_quarantine_renames();
    failures += t_quarantine_missing_is_noop();
    failures += t_verdict_names();
    failures += t_recovery_status();
    failures += t_dump_state_json();
    failures += t_verified_stream_identity();
    failures += t_verified_stream_refusals();
    failures += t_verified_stream_matching_path();
    failures += t_verified_memo();
    failures += t_height_repair();
    failures += t_height_repair_empty();
    failures += t_height_repair_cycle();
    failures += t_height_repair_single();
    failures += t_height_repair_detached_subtree();
    failures += t_anchor_repair_null_inputs();
    failures += t_anchor_repair_oom();
    failures += t_pprev_repair_cursor_skip();
    failures += t_mg_pprev_sqlite_header_fallback();
    failures += t_bcs_fingerprint();
    failures += t_bcs_repair_heights_range_cursor();
    failures += t_bcs_clamp_on_reorg();
    failures += t_bcs_repair_heights_wrapper();
    failures += bii_mutant_gap_tests();
    failures += t_pprev_repair_rebuilds_skip_on_link_only_fix();
    failures += t_height_repair_deep_reverse_order();
    failures += t_pprev_then_height_repair_settles_child_order();
    failures += t_pprev_repair_rebuilds_descendant_skips();
    failures += t_height_repair_rebuilds_skips();
    failures += t_height_repair_cycle_keeps_labels();
    failures += t_height_repair_deep_reverse_heap();
    return failures;
}
