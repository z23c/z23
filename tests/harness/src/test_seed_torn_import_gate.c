/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test for the bless-time forward-evidence gate
 * (import-gate-spec.md PART A) in
 * engine/services/src/block_index_loader_rebuild.c:
 * block_index_loader_seed_stages_from_cold_import.
 *
 * THE TEAR: a faithful-looking cold-import trusted base
 * at seed height H whose count token MATCHES the live (torn) count, but
 * whose coin set is MISSING a canonical coinbase below H. The active chain
 * spends that coin at H, so forward validation has already recorded a
 * durable `ok=0 prevout_unresolved` row in script_validate_log at a height
 * inside (compiled_anchor, H].
 *
 * What this proves
 * ----------------
 *   TORN:  the loader REFUSES to bless (returns its no-bless 0), raises a
 *          typed PERMANENT "seed.torn_import" blocker, emits
 *          EV_OPERATOR_NEEDED naming the hole, and stamps NOTHING —
 *          coins_applied_height is NOT advanced to H+1, no tip_finalize
 *          anchor is written, and H* stays pinned at the compiled anchor.
 *          The genuine-tear cases also seed coin_backfill's durable refusal
 *          marker ('coin_backfill.refused.<h>.<hash>'), which the DURABILITY
 *          GUARD requires before firing.
 *   CLEAN: an identical fixture with NO ok=0 hole below H — the gate is a
 *          strict no-op: no blocker, no event (zero false-reject).
 *
 * DURABILITY GUARD (Cases 5 & 6) — the verdict fires ONLY on a
 * genuinely-unrecoverable tear, never on a transient/in-flight ok=0 row:
 *   Case 5 (internal_error): an in-window durable ok=0 row with
 *          status='internal_error' (script_validate's TRANSIENT, resurrectable
 *          infra failure — sapling-ctx-init / sighash; re-attempted by repair).
 *          NO fire: the status filter excludes it.
 *   Case 6 (not-yet-refused): an in-window ok=0 status='prevout_unresolved'
 *          row WITHOUT a coin_backfill.refused marker. NO fire: refusal latency
 *          — the gate WAITS for coin_backfill to confirm the hole unprovable.
 *
 * Scratch files live under ./test-tmp/torn_import_<pid>/ per the project's
 * no-/tmp convention.
 */

#include "test/test_core.h"

#include "services/block_index_loader.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "storage/progress_store.h"
#include "storage/repair_marker.h"
#include "storage/coins_kv.h"
#include "models/database.h"
#include "core/uint256.h"
#include "event/event.h"
#include "util/blocker.h"
#include "jobs/reducer_frontier.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define STIG_CHECK(name, expr) do {                       \
    printf("seed_torn_import_gate: %s... ", (name));      \
    if (expr) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }                \
} while (0)

/* The compiled trusted anchor (SHA3 checkpoint) the loader pins H* to. */
#define STIG_ANCHOR REDUCER_FRONTIER_TRUSTED_ANCHOR  /* 3,056,758 */

/* Event observer: count EV_OPERATOR_NEEDED emissions. */
static _Atomic int g_op_needed;

static void stig_ev_observer(enum event_type type, uint32_t peer_id,
                             const void *payload, uint32_t payload_len,
                             void *ctx)
{
    (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    if (type == EV_OPERATOR_NEEDED)
        atomic_fetch_add(&g_op_needed, 1);
}

/* Unique synthetic block hash for a height. */
static void stig_hash_for(int h, struct uint256 *out)
{
    memset(out->data, 0, 32);
    out->data[0] = (uint8_t)(h & 0xFF);
    out->data[1] = (uint8_t)((h >> 8) & 0xFF);
    out->data[2] = (uint8_t)((h >> 16) & 0xFF);
    out->data[31] = 0x5e;
}

/* Insert one in-memory block index entry at `height` with the synthetic
 * hash so block_map_find resolves the durable anchor (loader step 2). */
static struct block_index *stig_insert_anchor(struct main_state *ms,
                                              const struct uint256 *hash,
                                              int height)
{
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!bi)
        return NULL;
    bi->nHeight = height;
    bi->nBits = 0x2000ffffu;
    bi->nTime = 1700000000u + (uint32_t)height;
    bi->nVersion = 4;
    bi->nStatus = BLOCK_VALID_TREE;
    bi->nTx = 0;
    bi->nFile = -1;
    bi->nDataPos = 0;
    return bi;
}

/* Create the production-shape script_validate_log + tip_finalize_log tables
 * on progress.kv (the latter so reducer_frontier_compute_hstar can read its
 * trusted-anchor floor in the post-refusal assertion). */
static bool stig_create_svl(sqlite3 *db)
{
    if (sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        " height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
        " ok INTEGER NOT NULL, tx_count INTEGER NOT NULL,"
        " input_count INTEGER NOT NULL, first_failure_txid BLOB,"
        " first_failure_vin INTEGER, first_failure_serror INTEGER,"
        " validated_at INTEGER NOT NULL, block_hash BLOB)",
        NULL, NULL, NULL) != SQLITE_OK)
        return false;
    return sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        " height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        " tip_hash BLOB)",
        NULL, NULL, NULL) == SQLITE_OK;
}

/* Insert one ok=0 row at `height` with `hash` and an explicit `status`
 * (production tokens: 'prevout_unresolved', 'block_decode_failed',
 * 'internal_error' — see script_validate_stage.c:352-361 and
 * script_validate_contextual.c:112-116). */
static bool stig_insert_hole_status(sqlite3 *db, int height,
                                    const struct uint256 *hash,
                                    const char *status)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO script_validate_log("
            " height, status, ok, tx_count, input_count, validated_at,"
            " block_hash) VALUES(?, ?, 0, 1, 1, 0, ?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_text(st, 2, status, -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, hash->data, 32, SQLITE_STATIC);
    int rc = sqlite3_step(st);  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

/* Insert one ok=0 prevout_unresolved row at `height` with `hash`. */
static bool stig_insert_hole(sqlite3 *db, int height,
                             const struct uint256 *hash)
{
    return stig_insert_hole_status(db, height, hash, "prevout_unresolved");
}

/* Seed coin_backfill's durable refusal of the hole at (height, hash): the
 * 'coin_backfill.refused.<h>.<holehash-hex>' progress.kv marker, byte-identical
 * to the producer (coin_backfill_key_h_hash builds "<prefix>.<height>.<hex>"
 * via uint256_get_hex; value "spent:v2", a real-path terminal-linkage-proven
 * REFUSED_SPENT value). The
 * loader's durability guard requires this marker before firing the verdict.
 *
 * These gate-side cases hand-seed the marker to exercise the gate's READER at
 * the production height scale (the gate's window check needs H above the
 * compiled SHA3 checkpoint). The end-to-end proof that the gate fires on a
 * marker written by the REAL coin_backfill WRITER (txindex_miss terminal path)
 * with a byte-identical key lives in test_stage_repair_coin_backfill.c
 * (cb_case_gate_fires_on_real_marker), where the writer's full chain/txindex
 * fixture exists. */
static bool stig_seed_backfill_refused(sqlite3 *db, int height,
                                       const struct uint256 *hash)
{
    if (!repair_marker_table_ensure(db))
        return false;
    return repair_marker_note(db, REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED,
                              height, hash->data, "spent:v2", 8);
}

/* Seed coins_kv with `n` synthetic live outputs so the canonical
 * coins_kv count token has something to match (the torn live count). */
static bool stig_seed_coins(sqlite3 *db, int n)
{
    if (!coins_kv_ensure_schema(db))
        return false;
    for (int i = 0; i < n; i++) {
        uint8_t txid[32];
        memset(txid, 0, 32);
        txid[0] = (uint8_t)(i & 0xFF);
        txid[1] = (uint8_t)((i >> 8) & 0xFF);
        uint8_t script[1] = {0x51};  /* OP_TRUE */
        if (!coins_kv_add(db, txid, 0, (int64_t)(i + 1) * 1000,
                          STIG_ANCHOR + 1, false, script, sizeof(script)))
            return false;
    }
    return true;
}

/* Stamp the durable cold-import seed keys so the loader reaches the gate:
 *   anchor_height = H, anchor_hash = <hash at H>, leveldb_utxo_migrated = 1,
 *   cold_import_seed_coins_kv_count = live coins_kv count (matched token). */
static bool stig_stamp_seed_keys(struct node_db *ndb, int H,
                                 const struct uint256 *hash,
                                 int64_t coins_kv_count_token)
{
    if (!node_db_state_set_int(ndb, "cold_import_seed_anchor_height", H))
        return false;
    if (!node_db_state_set(ndb, "cold_import_seed_anchor_hash",
                           hash->data, 32))
        return false;
    uint8_t one = 1;
    if (!node_db_state_set(ndb, "leveldb_utxo_migrated", &one, 1))
        return false;
    if (!node_db_state_set_int(ndb, "cold_import_seed_coins_kv_count",
                               coins_kv_count_token))
        return false;
    return true;
}

/* Stamp the durable utxo_apply coins frontier (the forward-apply ceiling the
 * retargeted gate uses as its window top). next_cursor follows the utxo_apply
 * convention: applied-through H means coins_applied_height == H+1, so a node
 * BLOCKED trying to apply block B has coins_applied_height == B. */
static bool stig_set_applied(sqlite3 *db, int32_t next_cursor)
{
    if (!progress_meta_table_ensure(db))
        return false;
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    bool ok = coins_kv_set_applied_height_in_tx(db, next_cursor);
    const char *finish = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(db, finish, NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    /* Stamp the migration-complete rung so coins_kv_is_proven_authority returns
     * true (stig_seed_coins already added the coins rows; stig_set_applied set
     * the applied_height above). compute_hstar's phantom-anchor guard otherwise
     * drops the floor to 0 when the store is not proven authority — correct for
     * a fresh datadir, but these gate fixtures model a seeded one. */
    if (ok) {
        uint8_t one = 1;
        ok = progress_meta_set(db, COINS_KV_MIGRATION_COMPLETE_KEY, &one, 1);
    }
    return ok;
}

/* Read the persisted coins_applied_height (progress_meta). Absent == -1. */
static int64_t stig_coins_applied(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int64_t v = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT value FROM progress_meta WHERE key='coins_applied_height'",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW &&  // raw-sql-ok:test-readback
        sqlite3_column_bytes(st, 0) >= 4) {
        const uint8_t *b = sqlite3_column_blob(st, 0);
        if (b) v = (int64_t)((uint32_t)b[0] | ((uint32_t)b[1] << 8) |
                             ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24));
    }
    sqlite3_finalize(st);
    return v;
}

int test_seed_torn_import_gate(void)
{
    test_reset_shared_globals();   /* monolith isolation: see test_helpers.c */
    printf("\n=== seed_torn_import_gate tests ===\n");
    int failures = 0;

    /* event_emit short-circuits until the ring is initialized; required so
     * the EV_OPERATOR_NEEDED observer fires in an isolated ZCL_TEST_ONLY run
     * (idempotent — the full suite already init'd it). */
    event_log_init();
    blocker_module_init();

    /* ── Case 1: TORN, SEED-RANGE — ok=0 hole AT the apply frontier == H
     *           → REFUSE. The defensive seed-range shape: the hole sits at H
     *           itself, with the apply frontier (coins_applied_height) AT H
     *           (the wedge where the seed height IS the blocked spending
     *           block). Window ceiling = forward-apply frontier covers it. */
    {
        char dir[256];
        snprintf(dir, sizeof(dir), "./test-tmp/torn_import_%d_torn",
                 (int)getpid());
        mkdir("./test-tmp", 0755);
        mkdir(dir, 0755);

        blocker_reset_for_testing();
        event_clear_observers(EV_OPERATOR_NEEDED);
        atomic_store(&g_op_needed, 0);
        event_observe(EV_OPERATOR_NEEDED, stig_ev_observer, NULL);

        /* H well above the compiled anchor — the live tear height region. */
        const int H = STIG_ANCHOR + 88837;   /* 3,145,595 */
        const int HOLE_H = H;                 /* spending block records ok=0 */

        progress_store_close();
        bool pk_ok = progress_store_open(dir);
        STIG_CHECK("torn: progress store opens", pk_ok);
        sqlite3 *pk = progress_store_db();

        bool fixt = pk && stig_create_svl(pk) && stig_seed_coins(pk, 8);
        int64_t live_ck = pk ? coins_kv_count(pk) : -1;
        STIG_CHECK("torn: coins_kv seeded", fixt && live_ck == 8);

        /* The apply frontier sits at the blocked hole (== H here). Forward
         * validation could only have recorded the ok=0 row by reaching this
         * height, so the coins cursor is at it — model that honestly. */
        STIG_CHECK("torn: coins_applied_height stamped to the blocked cursor",
                   pk && stig_set_applied(pk, HOLE_H));

        struct uint256 hole_hash;
        stig_hash_for(HOLE_H, &hole_hash);
        STIG_CHECK("torn: ok=0 prevout_unresolved row inserted",
                   pk && stig_insert_hole(pk, HOLE_H, &hole_hash));

        /* coin_backfill DURABLY REFUSED this hole as unprovable — the durable
         * proof the guard requires (a genuinely-unrecoverable tear). */
        STIG_CHECK("torn: coin_backfill.refused marker seeded",
                   pk && stig_seed_backfill_refused(pk, HOLE_H, &hole_hash));

        struct node_db ndb;
        STIG_CHECK("torn: node_db opens", node_db_open(&ndb, ":memory:"));

        struct uint256 anchor_hash;
        stig_hash_for(H, &anchor_hash);
        /* Token MATCHES the (torn) live count — defeats the count
         * cross-check exactly like the real tear. */
        STIG_CHECK("torn: seed keys stamped",
                   stig_stamp_seed_keys(&ndb, H, &anchor_hash, live_ck));

        struct main_state ms;
        main_state_init(&ms);
        struct block_index *anchor = stig_insert_anchor(&ms, &anchor_hash, H);
        STIG_CHECK("torn: anchor in index at H", anchor != NULL);

        int rc = block_index_loader_seed_stages_from_cold_import(&ms, &ndb, pk);

        STIG_CHECK("torn: loader REFUSES to bless (returns 0)", rc == 0);
        STIG_CHECK("torn: PERMANENT seed.torn_import blocker raised",
                   blocker_exists("seed.torn_import") &&
                   blocker_class_for("seed.torn_import") == BLOCKER_PERMANENT);
        STIG_CHECK("torn: EV_OPERATOR_NEEDED emitted",
                   atomic_load(&g_op_needed) >= 1);
        STIG_CHECK("torn: coins_applied_height NOT advanced to H+1",
                   stig_coins_applied(pk) != (int64_t)(H + 1));

        /* H* stays pinned at the compiled anchor (never floated over ok=0). */
        int32_t hstar = -1, served = -1;
        progress_store_tx_lock();
        bool hs = reducer_frontier_compute_hstar(pk, &hstar, &served);
        progress_store_tx_unlock();
        STIG_CHECK("torn: H* pinned at compiled anchor",
                   hs && hstar == STIG_ANCHOR);

        event_clear_observers(EV_OPERATOR_NEEDED);
        main_state_free(&ms);
        node_db_close(&ndb);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── Case 2: CLEAN — no ok=0 hole → gate is a strict no-op. ───── */
    {
        char dir[256];
        snprintf(dir, sizeof(dir), "./test-tmp/torn_import_%d_clean",
                 (int)getpid());
        mkdir("./test-tmp", 0755);
        mkdir(dir, 0755);

        blocker_reset_for_testing();
        event_clear_observers(EV_OPERATOR_NEEDED);
        atomic_store(&g_op_needed, 0);
        event_observe(EV_OPERATOR_NEEDED, stig_ev_observer, NULL);

        /* H just above the anchor so the H* gap stays within the trigger
         * window (H - H* <= 1000) → the loader returns 0 at the gap check
         * with NO blocker, proving MY gate did not fire. */
        const int H = STIG_ANCHOR + 200;

        progress_store_close();
        bool pk_ok = progress_store_open(dir);
        STIG_CHECK("clean: progress store opens", pk_ok);
        sqlite3 *pk = progress_store_db();

        bool fixt = pk && stig_create_svl(pk) && stig_seed_coins(pk, 8);
        int64_t live_ck = pk ? coins_kv_count(pk) : -1;
        STIG_CHECK("clean: coins_kv seeded (no ok=0 row)",
                   fixt && live_ck == 8);
        /* A completed clean seed stamps proven authority (applied frontier +
         * migration). Without it compute_hstar's phantom-anchor guard would
         * drop H* to 0, blowing the loader's H-H*<=trigger gap check below. */
        STIG_CHECK("clean: coins_applied + migration stamped",
                   pk && stig_set_applied(pk, H + 1));

        struct node_db ndb;
        STIG_CHECK("clean: node_db opens", node_db_open(&ndb, ":memory:"));

        struct uint256 anchor_hash;
        stig_hash_for(H, &anchor_hash);
        STIG_CHECK("clean: seed keys stamped",
                   stig_stamp_seed_keys(&ndb, H, &anchor_hash, live_ck));

        struct main_state ms;
        main_state_init(&ms);
        struct block_index *anchor = stig_insert_anchor(&ms, &anchor_hash, H);
        STIG_CHECK("clean: anchor in index at H", anchor != NULL);

        int rc = block_index_loader_seed_stages_from_cold_import(&ms, &ndb, pk);

        /* No false-reject: MY gate must not fire — no blocker, no event.
         * The loader returns 0 here (not wedged: H - H* <= trigger gap),
         * which is the normal no-op return, NOT a torn-import refusal. */
        STIG_CHECK("clean: no seed.torn_import blocker (no false-reject)",
                   !blocker_exists("seed.torn_import"));
        STIG_CHECK("clean: no EV_OPERATOR_NEEDED emitted",
                   atomic_load(&g_op_needed) == 0);
        STIG_CHECK("clean: loader returns a non-error code", rc >= 0);

        event_clear_observers(EV_OPERATOR_NEEDED);
        main_state_free(&ms);
        node_db_close(&ndb);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── Case 3: TORN, FORWARD-REGION (the LIVE/fixture wedge shape). ──
     *
     * THE DECISIVE shape the seed-range-only gate MISSES. Example:
     * seed anchor H=3,145,457; the durable ok=0 prevout_unresolved row is at
     * h=3,145,595 == coins_applied_height — 138 blocks ABOVE H, in the
     * FORWARD-APPLIED region. And because the active tip (h=3,145,594) is
     * already >= H, block_index_loader_seed_stages_from_cold_import hits its
     * FORWARD-ONLY early-return BEFORE the old (2e) seed-range gate ever runs.
     * So the hole is both (a) above the old window (checkpoint, H] and (b)
     * unreachable past the forward-only guard. The retargeted gate must run on
     * THIS wedged-boot path and fire on a hole in (checkpoint, apply-frontier].
     */
    {
        char dir[256];
        snprintf(dir, sizeof(dir), "./test-tmp/torn_import_%d_fwd",
                 (int)getpid());
        mkdir("./test-tmp", 0755);
        mkdir(dir, 0755);

        blocker_reset_for_testing();
        event_clear_observers(EV_OPERATOR_NEEDED);
        atomic_store(&g_op_needed, 0);
        event_observe(EV_OPERATOR_NEEDED, stig_ev_observer, NULL);

        /* seed H below the hole; the apply cursor / active tip are ABOVE H. */
        const int H        = STIG_ANCHOR + 88699;  /* 3,145,457 (seed) */
        const int ACTIVE_T = H + 137;               /* 3,145,594 (live tip) */
        const int HOLE_H   = H + 138;               /* 3,145,595 (blocked) */
        const int APPLIED  = HOLE_H;                /* coins_applied_height */

        progress_store_close();
        bool pk_ok = progress_store_open(dir);
        STIG_CHECK("fwd: progress store opens", pk_ok);
        sqlite3 *pk = progress_store_db();

        bool fixt = pk && stig_create_svl(pk) && stig_seed_coins(pk, 8);
        int64_t live_ck = pk ? coins_kv_count(pk) : -1;
        STIG_CHECK("fwd: coins_kv seeded", fixt && live_ck == 8);

        /* The forward-apply ceiling: utxo_apply BLOCKED at HOLE_H. */
        STIG_CHECK("fwd: coins_applied_height stamped to the blocked cursor",
                   pk && stig_set_applied(pk, APPLIED));

        /* The durable forward evidence: ok=0 prevout_unresolved at the
         * spending block, 138 blocks ABOVE the seed anchor H. */
        struct uint256 hole_hash;
        stig_hash_for(HOLE_H, &hole_hash);
        STIG_CHECK("fwd: ok=0 prevout_unresolved row above H inserted",
                   pk && stig_insert_hole(pk, HOLE_H, &hole_hash));

        /* coin_backfill DURABLY REFUSED this hole — the genuinely-unrecoverable
         * tear the guard fires on. */
        STIG_CHECK("fwd: coin_backfill.refused marker seeded",
                   pk && stig_seed_backfill_refused(pk, HOLE_H, &hole_hash));

        struct node_db ndb;
        STIG_CHECK("fwd: node_db opens", node_db_open(&ndb, ":memory:"));

        struct uint256 anchor_hash;
        stig_hash_for(H, &anchor_hash);
        STIG_CHECK("fwd: seed keys stamped",
                   stig_stamp_seed_keys(&ndb, H, &anchor_hash, live_ck));

        struct main_state ms;
        main_state_init(&ms);
        struct block_index *anchor = stig_insert_anchor(&ms, &anchor_hash, H);
        STIG_CHECK("fwd: anchor in index at H", anchor != NULL);

        /* Install the active tip ABOVE H — the wedged-boot precondition that
         * trips the loader's forward-only early-return (cur_h > H). */
        struct uint256 tip_hash;
        stig_hash_for(ACTIVE_T, &tip_hash);
        struct block_index *tip = stig_insert_anchor(&ms, &tip_hash, ACTIVE_T);
        bool tip_set = tip &&
            active_chain_install_tip_slot(&ms.chain_active, tip);
        STIG_CHECK("fwd: active tip installed ABOVE H (wedged-boot shape)",
                   tip_set && active_chain_height(&ms.chain_active) == ACTIVE_T);

        int rc = block_index_loader_seed_stages_from_cold_import(&ms, &ndb, pk);

        STIG_CHECK("fwd: loader REFUSES to bless (returns 0)", rc == 0);
        STIG_CHECK("fwd: PERMANENT seed.torn_import blocker raised",
                   blocker_exists("seed.torn_import") &&
                   blocker_class_for("seed.torn_import") == BLOCKER_PERMANENT);
        STIG_CHECK("fwd: EV_OPERATOR_NEEDED emitted",
                   atomic_load(&g_op_needed) >= 1);
        STIG_CHECK("fwd: coins_applied_height NOT advanced to H+1",
                   stig_coins_applied(pk) != (int64_t)(H + 1));

        /* H* stays pinned at the compiled anchor (never floated over ok=0). */
        int32_t hstar = -1, served = -1;
        progress_store_tx_lock();
        bool hs = reducer_frontier_compute_hstar(pk, &hstar, &served);
        progress_store_tx_unlock();
        STIG_CHECK("fwd: H* pinned at compiled anchor",
                   hs && hstar == STIG_ANCHOR);

        event_clear_observers(EV_OPERATOR_NEEDED);
        main_state_free(&ms);
        node_db_close(&ndb);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── Case 4: CLEAN, FORWARD-REGION (no false-fire mid-IBD). ────────
     *
     * Identical wedged-boot shape (active tip ABOVE H, an apply frontier) but
     * NO durable ok=0 hole — exactly a healthy node mid-IBD that simply has
     * not yet hit a torn prevout. script_validate writes NO ok=0 row for a
     * not-yet-fetched body (it returns JOB_IDLE), so a faithful import has no
     * forward evidence and the retargeted gate MUST be a strict no-op. */
    {
        char dir[256];
        snprintf(dir, sizeof(dir), "./test-tmp/torn_import_%d_fwdclean",
                 (int)getpid());
        mkdir("./test-tmp", 0755);
        mkdir(dir, 0755);

        blocker_reset_for_testing();
        event_clear_observers(EV_OPERATOR_NEEDED);
        atomic_store(&g_op_needed, 0);
        event_observe(EV_OPERATOR_NEEDED, stig_ev_observer, NULL);

        const int H        = STIG_ANCHOR + 88699;
        const int ACTIVE_T = H + 137;
        const int APPLIED  = H + 138;

        progress_store_close();
        bool pk_ok = progress_store_open(dir);
        STIG_CHECK("fwd-clean: progress store opens", pk_ok);
        sqlite3 *pk = progress_store_db();

        bool fixt = pk && stig_create_svl(pk) && stig_seed_coins(pk, 8);
        int64_t live_ck = pk ? coins_kv_count(pk) : -1;
        STIG_CHECK("fwd-clean: coins_kv seeded (no ok=0 row)",
                   fixt && live_ck == 8);
        STIG_CHECK("fwd-clean: coins_applied_height stamped (forward frontier)",
                   pk && stig_set_applied(pk, APPLIED));

        struct node_db ndb;
        STIG_CHECK("fwd-clean: node_db opens", node_db_open(&ndb, ":memory:"));

        struct uint256 anchor_hash;
        stig_hash_for(H, &anchor_hash);
        STIG_CHECK("fwd-clean: seed keys stamped",
                   stig_stamp_seed_keys(&ndb, H, &anchor_hash, live_ck));

        struct main_state ms;
        main_state_init(&ms);
        struct block_index *anchor = stig_insert_anchor(&ms, &anchor_hash, H);
        STIG_CHECK("fwd-clean: anchor in index at H", anchor != NULL);

        struct uint256 tip_hash;
        stig_hash_for(ACTIVE_T, &tip_hash);
        struct block_index *tip = stig_insert_anchor(&ms, &tip_hash, ACTIVE_T);
        bool tip_set = tip &&
            active_chain_install_tip_slot(&ms.chain_active, tip);
        STIG_CHECK("fwd-clean: active tip installed ABOVE H",
                   tip_set && active_chain_height(&ms.chain_active) == ACTIVE_T);

        int rc = block_index_loader_seed_stages_from_cold_import(&ms, &ndb, pk);

        STIG_CHECK("fwd-clean: NO seed.torn_import blocker (no false-reject)",
                   !blocker_exists("seed.torn_import"));
        STIG_CHECK("fwd-clean: NO EV_OPERATOR_NEEDED emitted",
                   atomic_load(&g_op_needed) == 0);
        STIG_CHECK("fwd-clean: loader returns a non-error code", rc >= 0);

        event_clear_observers(EV_OPERATOR_NEEDED);
        main_state_free(&ms);
        node_db_close(&ndb);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── Case 5: internal_error NO-FIRE (status-filter guard). ─────────
     *
     * Identical wedged-boot tear shape (active tip ABOVE H, an apply frontier,
     * a durable in-window ok=0 row) BUT the row's status is 'internal_error' —
     * script_validate's TRANSIENT, RESURRECTABLE infra failure (sapling-
     * verification-ctx-init-failed / error-computing-signature-hash;
     * script_validate_contextual.c:112-116), re-attempted by the stale-script-
     * hole repair. A healthy node that hit a transient blip and rebooted before
     * re-validation must NOT be handed a PERMANENT 'wipe + re-import' verdict.
     * The status filter excludes internal_error → strict no-op. (No refusal
     * marker either — coin_backfill NEVER refuses internal_error.) */
    {
        char dir[256];
        snprintf(dir, sizeof(dir), "./test-tmp/torn_import_%d_internal",
                 (int)getpid());
        mkdir("./test-tmp", 0755);
        mkdir(dir, 0755);

        blocker_reset_for_testing();
        event_clear_observers(EV_OPERATOR_NEEDED);
        atomic_store(&g_op_needed, 0);
        event_observe(EV_OPERATOR_NEEDED, stig_ev_observer, NULL);

        const int H        = STIG_ANCHOR + 88699;
        const int ACTIVE_T = H + 137;
        const int HOLE_H   = H + 138;
        const int APPLIED  = HOLE_H;

        progress_store_close();
        bool pk_ok = progress_store_open(dir);
        STIG_CHECK("internal: progress store opens", pk_ok);
        sqlite3 *pk = progress_store_db();

        bool fixt = pk && stig_create_svl(pk) && stig_seed_coins(pk, 8);
        int64_t live_ck = pk ? coins_kv_count(pk) : -1;
        STIG_CHECK("internal: coins_kv seeded", fixt && live_ck == 8);
        STIG_CHECK("internal: coins_applied_height stamped",
                   pk && stig_set_applied(pk, APPLIED));

        /* In-window durable ok=0 row, but TRANSIENT status='internal_error'. */
        struct uint256 hole_hash;
        stig_hash_for(HOLE_H, &hole_hash);
        STIG_CHECK("internal: ok=0 internal_error row inserted",
                   pk && stig_insert_hole_status(pk, HOLE_H, &hole_hash,
                                                 "internal_error"));

        struct node_db ndb;
        STIG_CHECK("internal: node_db opens", node_db_open(&ndb, ":memory:"));

        struct uint256 anchor_hash;
        stig_hash_for(H, &anchor_hash);
        STIG_CHECK("internal: seed keys stamped",
                   stig_stamp_seed_keys(&ndb, H, &anchor_hash, live_ck));

        struct main_state ms;
        main_state_init(&ms);
        struct block_index *anchor = stig_insert_anchor(&ms, &anchor_hash, H);
        STIG_CHECK("internal: anchor in index at H", anchor != NULL);

        struct uint256 tip_hash;
        stig_hash_for(ACTIVE_T, &tip_hash);
        struct block_index *tip = stig_insert_anchor(&ms, &tip_hash, ACTIVE_T);
        bool tip_set = tip &&
            active_chain_install_tip_slot(&ms.chain_active, tip);
        STIG_CHECK("internal: active tip installed ABOVE H",
                   tip_set && active_chain_height(&ms.chain_active) == ACTIVE_T);

        int rc = block_index_loader_seed_stages_from_cold_import(&ms, &ndb, pk);

        STIG_CHECK("internal: NO seed.torn_import blocker (transient excluded)",
                   !blocker_exists("seed.torn_import"));
        STIG_CHECK("internal: NO EV_OPERATOR_NEEDED emitted",
                   atomic_load(&g_op_needed) == 0);
        STIG_CHECK("internal: loader returns a non-error code", rc >= 0);

        event_clear_observers(EV_OPERATOR_NEEDED);
        main_state_free(&ms);
        node_db_close(&ndb);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── Case 6: not-yet-refused NO-FIRE (refusal-latency guard). ──────
     *
     * The full genuine-tear shape — wedged boot, active tip ABOVE H, apply
     * frontier, a durable in-window ok=0 status='prevout_unresolved' row — but
     * coin_backfill has NOT (yet) recorded its 'coin_backfill.refused' marker.
     * That hole is still being worked (fetch/repair not exhausted); the gate
     * must WAIT for coin_backfill to confirm it unprovable rather than racing a
     * not-yet-confirmed hole into a PERMANENT verdict. NO fire until refused. */
    {
        char dir[256];
        snprintf(dir, sizeof(dir), "./test-tmp/torn_import_%d_unrefused",
                 (int)getpid());
        mkdir("./test-tmp", 0755);
        mkdir(dir, 0755);

        blocker_reset_for_testing();
        event_clear_observers(EV_OPERATOR_NEEDED);
        atomic_store(&g_op_needed, 0);
        event_observe(EV_OPERATOR_NEEDED, stig_ev_observer, NULL);

        const int H        = STIG_ANCHOR + 88699;
        const int ACTIVE_T = H + 137;
        const int HOLE_H   = H + 138;
        const int APPLIED  = HOLE_H;

        progress_store_close();
        bool pk_ok = progress_store_open(dir);
        STIG_CHECK("unrefused: progress store opens", pk_ok);
        sqlite3 *pk = progress_store_db();

        bool fixt = pk && stig_create_svl(pk) && stig_seed_coins(pk, 8);
        int64_t live_ck = pk ? coins_kv_count(pk) : -1;
        STIG_CHECK("unrefused: coins_kv seeded", fixt && live_ck == 8);
        STIG_CHECK("unrefused: coins_applied_height stamped",
                   pk && stig_set_applied(pk, APPLIED));

        /* Genuine tear-class row, but NO coin_backfill.refused marker. */
        struct uint256 hole_hash;
        stig_hash_for(HOLE_H, &hole_hash);
        STIG_CHECK("unrefused: ok=0 prevout_unresolved row inserted (no refusal)",
                   pk && stig_insert_hole(pk, HOLE_H, &hole_hash));

        struct node_db ndb;
        STIG_CHECK("unrefused: node_db opens", node_db_open(&ndb, ":memory:"));

        struct uint256 anchor_hash;
        stig_hash_for(H, &anchor_hash);
        STIG_CHECK("unrefused: seed keys stamped",
                   stig_stamp_seed_keys(&ndb, H, &anchor_hash, live_ck));

        struct main_state ms;
        main_state_init(&ms);
        struct block_index *anchor = stig_insert_anchor(&ms, &anchor_hash, H);
        STIG_CHECK("unrefused: anchor in index at H", anchor != NULL);

        struct uint256 tip_hash;
        stig_hash_for(ACTIVE_T, &tip_hash);
        struct block_index *tip = stig_insert_anchor(&ms, &tip_hash, ACTIVE_T);
        bool tip_set = tip &&
            active_chain_install_tip_slot(&ms.chain_active, tip);
        STIG_CHECK("unrefused: active tip installed ABOVE H",
                   tip_set && active_chain_height(&ms.chain_active) == ACTIVE_T);

        int rc = block_index_loader_seed_stages_from_cold_import(&ms, &ndb, pk);

        STIG_CHECK("unrefused: NO seed.torn_import blocker (refusal latency)",
                   !blocker_exists("seed.torn_import"));
        STIG_CHECK("unrefused: NO EV_OPERATOR_NEEDED emitted",
                   atomic_load(&g_op_needed) == 0);
        STIG_CHECK("unrefused: loader returns a non-error code", rc >= 0);

        event_clear_observers(EV_OPERATOR_NEEDED);
        main_state_free(&ms);
        node_db_close(&ndb);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    blocker_reset_for_testing();
    return failures;
}
