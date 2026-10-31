/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the state-seal REWIND CONSUMER (jobs/seal_rewind.h +
 * storage/seal_kv.h seal_kv_nearest_rewind_base).
 *
 * The seal ring persists a self-verified coins_sha3 every ~1000 blocks; these
 * tests exercise the executable consumer that rewinds the reducer to one:
 *   (A) NEAREST-BASE SELECTION: highest self-valid seal <= H; none below all.
 *   (B) SELF-VERIFIED RE-FOLD: unwind the retained inverse deltas to the seal,
 *       recompute the commitment, prove it reproduces the seal, reset cursors.
 *   (C) TORN-SEAL REFUSAL: a self-valid seal whose coins_sha3 does NOT reproduce
 *       is refused and the reducer is left byte-for-byte untouched.
 *   (D) FINALITY FLOOR: a seal below the passed floor is refused.
 *
 * The fixture folds a tiny synthetic chain: block h ADDs one coin C_h (no
 * spends) and persists the matching add-only inverse delta, so unwinding [G, C)
 * exactly restores the coins set the seal at G committed to. */

#include "test/test_core.h"

#include "jobs/seal_rewind.h"
#include "jobs/stage_repair_internal.h"   /* stage_repair_force_stage_cursor */
#include "jobs/stage_helpers.h"           /* stage_cursor_persisted */
#include "jobs/utxo_apply_delta.h"        /* utxo_apply_ensure_delta_schema */
#include "storage/seal_kv.h"
#include "services/seal_service.h"        /* seal_candidate_hook_in_tx */
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/main_logic.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "core/utiltime.h"
#include "crypto/sha3.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/anchor_kv.h"
#include "storage/progress_store.h"
#include "util/stage.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define SW_CHECK(name, expr) do {                                       \
    if (expr) { printf("  seal_rewind: %s... OK\n", (name)); }          \
    else { printf("  seal_rewind: %s... FAIL\n", (name)); failures++; } \
} while (0)

static void sw_put_u32_le(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xff);
}

/* Deterministic distinct txid for the coin created by block h. */
static void sw_txid(int h, uint8_t out[32])
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[2] = 0x9C;               /* distinct salt for rewind tests */
    out[31] = (uint8_t)(h + 1);
}

/* Persist an add-only inverse delta at `height`: added=[txid|vout], no spends.
 * Runs inside the caller's open txn. */
static void sw_insert_delta_add(sqlite3 *db, int height,
                                const uint8_t txid[32], uint32_t vout)
{
    uint8_t added[36];
    memcpy(added, txid, 32);
    sw_put_u32_le(added + 32, vout);
    uint8_t branch[32];
    memset(branch, 0xB0, 32);
    branch[0] = (uint8_t)height;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_delta"
            "(height, branch_hash, spent_blob, added_blob) VALUES(?,?,?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_int (st, 1, height);
    sqlite3_bind_blob(st, 2, branch, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, "", 0, SQLITE_STATIC);      /* empty spent set */
    sqlite3_bind_blob(st, 4, added, 36, SQLITE_STATIC);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

/* Apply block h: add coin C_h, persist its delta, advance cursor +
 * coins_applied_height to h+1 — all atomically, mirroring the stage. */
static void sw_apply_block(sqlite3 *db, int h)
{
    uint8_t txid[32];
    sw_txid(h, txid);
    uint8_t script[4] = { 0x76, 0xa9, (uint8_t)h, 0x88 };

    progress_store_tx_lock();
    sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    coins_kv_add(db, txid, 0, 1000 + (int64_t)h, h, false, script, sizeof(script));
    sw_insert_delta_add(db, h, txid, 0);
    stage_repair_force_stage_cursor(db, "utxo_apply", h + 1);
    coins_kv_set_applied_height_in_tx(db, h + 1);
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    progress_store_tx_unlock();
}

/* Insert a candidate seal at grid point G capturing the LIVE coins commitment
 * (block G applied, coins_applied_height == G + 1, when called). */
static void sw_seal_at(sqlite3 *db, int G)
{
    struct seal_record r;
    memset(&r, 0, sizeof(r));
    r.height = G;
    r.sealed_at = 1234567;
    coins_kv_commitment(db, r.coins_sha3);
    int64_t num = 0;
    coins_kv_setinfo(db, &num, &r.utxo_count, &r.supply);

    progress_store_tx_lock();
    sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    seal_kv_insert_candidate_in_tx(db, &r);
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    progress_store_tx_unlock();
}

/* Insert a TORN seal at G: self-valid record whose coins_sha3 deliberately does
 * NOT match the coins set at G (one flipped byte). */
static void sw_seal_torn_at(sqlite3 *db, int G)
{
    struct seal_record r;
    memset(&r, 0, sizeof(r));
    r.height = G;
    r.sealed_at = 7654321;
    coins_kv_commitment(db, r.coins_sha3);
    r.coins_sha3[0] ^= 0xFF;             /* lie about the committed set */
    int64_t num = 0;
    coins_kv_setinfo(db, &num, &r.utxo_count, &r.supply);

    progress_store_tx_lock();
    sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    seal_kv_insert_candidate_in_tx(db, &r);
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    progress_store_tx_unlock();
}

static void sw_setup_schema(sqlite3 *db)
{
    coins_kv_ensure_schema(db);
    seal_kv_ensure_schema(db);
    stage_table_ensure(db);
    utxo_apply_ensure_delta_schema(db);
    nullifier_kv_ensure_schema(db);
    anchor_kv_ensure_schema(db);
    /* utxo_apply_log is created by the stage in production (private header in
     * engine/jobs/src); the rewind's row-delete pass needs it present. A minimal
     * height-keyed table is enough for the DELETE range. */
    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS utxo_apply_log("
        "height INTEGER PRIMARY KEY, ok INTEGER)",
        NULL, NULL, NULL);
}

/* Fold blocks [0, last] and drop candidate seals at every grid height in
 * `grids` (right after block G is applied). */
static void sw_fold(sqlite3 *db, int last, const int *grids, int ngrids)
{
    for (int h = 0; h <= last; h++) {
        sw_apply_block(db, h);
        int G = h;   /* seal G commits the set THROUGH block G (checkpoint convention) */
        for (int i = 0; i < ngrids; i++)
            if (grids[i] == G) sw_seal_at(db, G);
    }
}

static int sw_test_select_nearest_base(const int *grids, int ngrids)
{
    /* ── (A) NEAREST-BASE SELECTION ─────────────────────────────────────── */
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "seal_rewind", "select");
    SW_CHECK("select: store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    sw_setup_schema(db);
    sw_fold(db, 24, grids, ngrids);

    struct seal_record base;
    bool found = false;
    SW_CHECK("select: H=17 finds base G=15",
             seal_kv_nearest_rewind_base(db, 17, &base, &found) &&
             found && base.height == 15);
    SW_CHECK("select: H=20 finds base G=20 (exact)",
             seal_kv_nearest_rewind_base(db, 20, &base, &found) &&
             found && base.height == 20);
    SW_CHECK("select: H=1000 finds highest G=20",
             seal_kv_nearest_rewind_base(db, 1000, &base, &found) &&
             found && base.height == 20);
    SW_CHECK("select: H=10 finds exact G=10",
             seal_kv_nearest_rewind_base(db, 10, &base, &found) &&
             found && base.height == 10);
    SW_CHECK("select: H=4 (below all seals) → none",
             seal_kv_nearest_rewind_base(db, 4, &base, &found) && !found);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

static int sw_test_refold_to_seal(const int *grids, int ngrids)
{
    /* ── (B) SELF-VERIFIED RE-FOLD ──────────────────────────────────────── */
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "seal_rewind", "rewind");
    SW_CHECK("rewind: store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    sw_setup_schema(db);
    sw_fold(db, 24, grids, ngrids);

    /* Pre-state: 25 coins applied, cursor 25. */
    SW_CHECK("rewind: pre coins count == 25", coins_kv_count(db) == 25);
    SW_CHECK("rewind: pre cursor == 25",
             stage_cursor_persisted(db, "utxo_apply", "t") == 25);

    struct seal_record base15;
    bool bf = false;
    seal_kv_nearest_rewind_base(db, 17, &base15, &bf);

    struct seal_rewind_result rr;
    bool ok = seal_rewind_to_nearest(db, 17, /*floor=*/0, &rr);
    SW_CHECK("rewind: call returns true", ok);
    SW_CHECK("rewind: rewound == true", rr.rewound);
    SW_CHECK("rewind: refusal == OK", rr.refusal == SEAL_REWIND_OK);
    SW_CHECK("rewind: seal_height == 15", rr.seal_height == 15);
    SW_CHECK("rewind: cursor_before == 25", rr.cursor_before == 25);
    SW_CHECK("rewind: unwound 9 heights [16,24]", rr.unwound_heights == 9);
    SW_CHECK("rewind: coins_verified", rr.coins_verified);

    /* Post-state: exactly the coins set the seal at 15 committed to. */
    SW_CHECK("rewind: post coins count == 16 (blocks 0..15)", coins_kv_count(db) == 16);
    SW_CHECK("rewind: post utxo_apply cursor == 16",
             stage_cursor_persisted(db, "utxo_apply", "t") == 16);
    SW_CHECK("rewind: post tip_finalize cursor == 16",
             stage_cursor_persisted(db, "tip_finalize", "t") == 16);
    int32_t applied = -1; bool af = false;
    coins_kv_get_applied_height(db, &applied, &af);
    SW_CHECK("rewind: post coins_applied_height == 16", af && applied == 16);

    uint8_t now[32];
    SW_CHECK("rewind: recomputed commitment == seal_15.coins_sha3",
             coins_kv_commitment(db, now) == 0 && bf &&
             memcmp(now, base15.coins_sha3, 32) == 0);

    /* Idempotent-ish: a second rewind to 17 now no-ops (seal 15 is at the
     * frontier, nothing above it to unwind). */
    struct seal_rewind_result rr2;
    seal_rewind_to_nearest(db, 17, 0, &rr2);
    SW_CHECK("rewind: second call refuses ABOVE_FRONTIER",
             !rr2.rewound && rr2.refusal == SEAL_REWIND_ABOVE_FRONTIER);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

static int sw_test_refuse_torn_seal(const int *grids, int ngrids)
{
    /* ── (C) TORN-SEAL REFUSAL (state unchanged) ────────────────────────── */
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "seal_rewind", "torn");
    SW_CHECK("torn: store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    sw_setup_schema(db);
    sw_fold(db, 24, grids, ngrids);
    /* A self-valid seal at 22 that LIES about its coins_sha3. */
    sw_seal_torn_at(db, 22);

    struct seal_record picked;
    bool pf = false;
    SW_CHECK("torn: nearest base for H=23 is the torn seal G=22",
             seal_kv_nearest_rewind_base(db, 23, &picked, &pf) &&
             pf && picked.height == 22);

    uint8_t before[32];
    coins_kv_commitment(db, before);
    int64_t count_before = coins_kv_count(db);

    struct seal_rewind_result rr;
    bool ok = seal_rewind_to_nearest(db, 23, /*floor=*/0, &rr);
    SW_CHECK("torn: call returns true", ok);
    SW_CHECK("torn: rewound == false", !rr.rewound);
    SW_CHECK("torn: refusal == COMMITMENT_MISMATCH",
             rr.refusal == SEAL_REWIND_COMMITMENT_MISMATCH);
    SW_CHECK("torn: coins_verified == false", !rr.coins_verified);

    /* The reducer must be byte-for-byte as it was — the failed unwind rolled
     * back atomically. */
    uint8_t after[32];
    coins_kv_commitment(db, after);
    SW_CHECK("torn: coins count unchanged", coins_kv_count(db) == count_before);
    SW_CHECK("torn: coins commitment unchanged",
             memcmp(before, after, 32) == 0);
    SW_CHECK("torn: cursor unchanged (== 25)",
             stage_cursor_persisted(db, "utxo_apply", "t") == 25);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

static int sw_test_refuse_below_floor(const int *grids, int ngrids)
{
    /* ── (D) FINALITY-FLOOR REFUSAL ─────────────────────────────────────── */
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "seal_rewind", "floor");
    SW_CHECK("floor: store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    sw_setup_schema(db);
    sw_fold(db, 24, grids, ngrids);

    /* Nearest base for H=17 is G=15; a floor of 16 forbids crossing it. */
    struct seal_rewind_result rr;
    seal_rewind_to_nearest(db, 17, /*floor=*/16, &rr);
    SW_CHECK("floor: seal below floor refused BELOW_FLOOR",
             !rr.rewound && rr.refusal == SEAL_REWIND_BELOW_FLOOR);
    SW_CHECK("floor: state untouched (cursor == 25)",
             stage_cursor_persisted(db, "utxo_apply", "t") == 25);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Chain of block_index entries [0..n-1], window tip published at n-1. The tip
 * is made to look synced (huge work, current time) so the production hook's
 * IBD gate does not suppress the emit. */
static bool sw_build_chain(struct main_state *ms, struct block_index **out,
                           struct uint256 *hashes, int n)
{
    struct block_index *prev = NULL;
    for (int h = 0; h < n; h++) {
        memset(&hashes[h], 0, sizeof(hashes[h]));
        hashes[h].data[0] = (uint8_t)(h & 0xFF);
        hashes[h].data[1] = (uint8_t)((h >> 8) & 0xFF);
        hashes[h].data[2] = 0x5D;
        struct block_index *pi =
            chainstate_insert_block_index((struct chainstate *)ms, &hashes[h]);
        if (!pi) return false;
        pi->nHeight = h;
        pi->nBits = 0x1f07ffff;
        pi->nTime = (uint32_t)GetTime();
        pi->nVersion = 4;
        pi->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        pi->nTx = 1;
        pi->nChainTx = (uint32_t)(h + 1);
        memset(&pi->nChainWork, 0xFF, sizeof(pi->nChainWork));
        pi->pprev = prev;
        out[h] = pi;
        prev = pi;
    }
    return active_chain_move_window_tip(&ms->chain_active, out[n - 1]);
}

static int sw_test_production_hook_height(void)
{
    /* ── (E) PRODUCTION HOOK KEYS THE SEAL BY THE APPLIED HEIGHT ──────────
     * utxo_apply_stage calls seal_candidate_hook_in_tx(db, ms, w->next_h)
     * inside the txn that applied block next_h. The stored seal must carry
     * height == that block, block_hash == that block's hash, and a commitment
     * of the set THROUGH that block (not through the block before it). */
    int failures = 0;
    enum { G = 1000 };
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "seal_rewind", "hook");
    SW_CHECK("hook: store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    sw_setup_schema(db);

    struct main_state ms;
    main_state_init(&ms);
    static struct block_index *b[G + 1];
    static struct uint256 hashes[G + 1];
    bool chain_ok = sw_build_chain(&ms, b, hashes, G + 1);
    SW_CHECK("hook: chain built", chain_ok);
    bool ibd_free = chain_ok && !is_initial_block_download(&ms);
    SW_CHECK("hook: not IBD", ibd_free);
    if (!ibd_free) {
        main_state_free(&ms);
        progress_store_close();
        test_cleanup_tmpdir(dir);
        return failures;
    }

    uint8_t through_prev[32], through_g[32];
    for (int h = 0; h < G; h++) sw_apply_block(db, h);
    coins_kv_commitment(db, through_prev);
    sw_apply_block(db, G);
    coins_kv_commitment(db, through_g);
    SW_CHECK("hook: sets through G-1 and G differ",
             memcmp(through_prev, through_g, 32) != 0);

    /* Exactly the stage's call: inside the txn, after block G's coins landed. */
    progress_store_tx_lock();
    sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    seal_candidate_hook_in_tx(db, &ms, G);
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    progress_store_tx_unlock();

    struct seal_record r = { 0 };
    bool found = false;
    SW_CHECK("hook: seal stored", seal_kv_newest(db, &r, &found) && found);
    SW_CHECK("hook: seal height == applied height", r.height == G);
    SW_CHECK("hook: block_hash == hash of the applied block",
             memcmp(r.block_hash, b[G]->hashBlock.data, 32) == 0);
    SW_CHECK("hook: commitment == set applied THROUGH G",
             memcmp(r.coins_sha3, through_g, 32) == 0);
    SW_CHECK("hook: commitment != set through G-1",
             memcmp(r.coins_sha3, through_prev, 32) != 0);

    main_state_free(&ms);
    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

static int sw_test_refuse_v1_record(void)
{
    /* ── (F) A VERSION-1 SEAL IS NEVER A REWIND BASE ──────────────────────
     * v1 keyed the set through G-1. Rewrite a genuine seal as a v1 record
     * with a CORRECT self_sha3 (so only the version distinguishes it). */
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "seal_rewind", "v1");
    SW_CHECK("v1: store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    sw_setup_schema(db);
    const int grids[1] = { 10 };
    sw_fold(db, 14, grids, 1);

    struct seal_record base = { 0 };
    bool found = false;
    int slot = -1;
    SW_CHECK("v1: v2 seal at 10 is a base before downgrade",
             seal_kv_nearest_rewind_base(db, 12, &base, &found) && found &&
             base.height == 10);
    SW_CHECK("v1: slot located",
             seal_kv_get_at_height(db, 10, &base, &found, &slot) && found);

    uint8_t buf[SEAL_RECORD_BYTES] = { 0 };
    SW_CHECK("v1: serialize", seal_serialize(&base, buf));
    buf[0] = 1u;                                        /* version 1 */
    sha3_256(buf, SEAL_RECORD_BYTES - 32, buf + SEAL_RECORD_BYTES - 32);
    char key[24];
    snprintf(key, sizeof(key), "%s%d", SEAL_SLOT_KEY_PREFIX, slot);
    SW_CHECK("v1: write v1 record into slot", slot >= 0 &&
             progress_meta_set(db, key, buf, sizeof(buf)));

    struct seal_record parsed;
    bool self_ok = true;
    SW_CHECK("v1: deserialize refuses the v1 record",
             !seal_deserialize(buf, sizeof(buf), &parsed, &self_ok) && !self_ok);
    SW_CHECK("v1: never selected as a rewind base",
             seal_kv_nearest_rewind_base(db, 12, &base, &found) && !found);

    struct seal_rewind_result rr;
    seal_rewind_to_nearest(db, 12, 0, &rr);
    SW_CHECK("v1: rewind refuses NO_BASE",
             !rr.rewound && rr.refusal == SEAL_REWIND_NO_BASE);
    SW_CHECK("v1: reducer untouched (cursor == 15)",
             stage_cursor_persisted(db, "utxo_apply", "t") == 15);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_seal_rewind(void);
int test_seal_rewind(void)
{
    printf("\n=== seal_rewind (rolling-anchor rewind consumer) tests ===\n");
    int failures = 0;
    const int grids[4] = { 5, 10, 15, 20 };

    failures += sw_test_select_nearest_base(grids, 4);
    failures += sw_test_refold_to_seal(grids, 4);
    failures += sw_test_refuse_torn_seal(grids, 4);
    failures += sw_test_refuse_below_floor(grids, 4);
    failures += sw_test_production_hook_height();
    failures += sw_test_refuse_v1_record();

    printf("=== seal_rewind tests complete: %d failure(s) ===\n", failures);
    return failures;
}
