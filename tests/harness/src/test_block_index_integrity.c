/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the block_index_integrity service.
 *
 * Each test spins up a throw-away datadir, writes a mock block_index.bin
 * body, calls bii_write_sidecar to commit the bytes, and then drives
 * bii_verify through the seven verdicts the service can return. The
 * quarantine rename is checked too — important because an accidental
 * delete would lose operator forensic data.
 */

#include "test/test_core.h"
#include "json/json.h"

#include "services/block_index_integrity.h"
#include "config/boot_cursor_state.h"
#include "validation/main_state.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "models/database.h"
#include "event/event.h"

#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
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
        block_map_insert(&ms.map_block_index, &hashes[i], &blocks[i]);
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
        block_map_insert(&ms.map_block_index, &hashes[i], &blocks[i]);
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
    block_map_insert(&ms.map_block_index, &hash, &genesis);

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
    block_map_insert(&ms.map_block_index, &stray_hash, &stray);

    int repaired = block_index_repair_heights(&ms);

    BII_RUN("bii: single genesis block repaired to height 0",
            genesis.nHeight == 0 && repaired >= 0);
    BII_RUN("bii: detached non-genesis root keeps its stored height",
            stray.nHeight == 1234);

    main_state_free(&ms);
    return failures;
}

/* ── 15b. Detached-root subtree is never re-anchored ─────────────
 * If an early header's pprev link is lost, stamping that detached root to
 * height 0 and forward-propagating relabels every descendant by an
 * offset — internally consistent, so every later pass reports "correct",
 * every new network block fails bad-cb-height, and the tip freezes. The
 * repair must leave
 * the (canonical) descendant labels alone until pprev repair relinks
 * the root, after which a re-run heals the root's own label. */

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

    block_map_insert(&ms.map_block_index, &gh, &g);
    block_map_insert(&ms.map_block_index, &h1h, &h1);
    block_map_insert(&ms.map_block_index, &h2h, &h2);
    block_map_insert(&ms.map_block_index, &h3h, &h3);
    block_map_insert(&ms.map_block_index, &h4h, &h4);

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

/* ── Post-activation anchor repair — Round 4 Part 5 regression ─
 *
 * NULL-input-only test. Constructing a coins_view_cache fixture that
 * survives bii_repair_post_activation_anchor's full path requires
 * wiring a backing coins_view, a node_db, and an on-disk block file —
 * that's a heavier integration setup than this regression deserves.
 * The NULL paths exercise the input validation; the happy path is
 * exercised live by the boot sequence. */

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

/* ── Aggregator ─────────────────────────────────────────────── */

/* ── 19. pprev repair skips work the fast-boot cursor already covers ────
 *
 * The --importblockindex path writes authoritative pprev pointers + per-block
 * shielded deltas straight from the source CDiskBlockIndex and stamps a
 * "repaired-through" cursor, so a normal boot must NOT re-walk the whole index
 * (the O(chain) disk read that used to delay RPC bind by minutes). Passing
 * min_height at the tip selects nothing, so the function returns 0 WITHOUT
 * reading any block file — proven here with a deliberately bogus datadir — while
 * still reporting the true max height so boot can advance the persisted cursor. */
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
        block_map_insert(&ms.map_block_index, &hashes[i], &blocks[i]);
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
        block_map_insert(&ms->map_block_index, &hashes[i], &blocks[i]);
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
    failures += t_height_repair();
    failures += t_height_repair_empty();
    failures += t_height_repair_cycle();
    failures += t_height_repair_single();
    failures += t_height_repair_detached_subtree();
    failures += t_anchor_repair_null_inputs();
    failures += t_pprev_repair_cursor_skip();
    failures += t_bcs_fingerprint();
    failures += t_bcs_repair_heights_range_cursor();
    failures += t_bcs_clamp_on_reorg();
    failures += t_bcs_repair_heights_wrapper();
    return failures;
}
