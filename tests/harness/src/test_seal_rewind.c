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
 * (coins_applied_height must be == G when called). */
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
 * `grids` (as coins_applied_height reaches each). */
static void sw_fold(sqlite3 *db, int last, const int *grids, int ngrids)
{
    for (int h = 0; h <= last; h++) {
        sw_apply_block(db, h);
        int G = h + 1;
        for (int i = 0; i < ngrids; i++)
            if (grids[i] == G) sw_seal_at(db, G);
    }
}

int test_seal_rewind(void);
int test_seal_rewind(void)
{
    printf("\n=== seal_rewind (rolling-anchor rewind consumer) tests ===\n");
    int failures = 0;
    const int grids[4] = { 5, 10, 15, 20 };

    /* ── (A) NEAREST-BASE SELECTION ─────────────────────────────────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "seal_rewind", "select");
        SW_CHECK("select: store opens", progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        sw_setup_schema(db);
        sw_fold(db, 24, grids, 4);

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
    }

    /* ── (B) SELF-VERIFIED RE-FOLD ──────────────────────────────────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "seal_rewind", "rewind");
        SW_CHECK("rewind: store opens", progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        sw_setup_schema(db);
        sw_fold(db, 24, grids, 4);

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
        SW_CHECK("rewind: unwound 10 heights [15,24]", rr.unwound_heights == 10);
        SW_CHECK("rewind: coins_verified", rr.coins_verified);

        /* Post-state: exactly the coins set the seal at 15 committed to. */
        SW_CHECK("rewind: post coins count == 15", coins_kv_count(db) == 15);
        SW_CHECK("rewind: post utxo_apply cursor == 15",
                 stage_cursor_persisted(db, "utxo_apply", "t") == 15);
        SW_CHECK("rewind: post tip_finalize cursor == 15",
                 stage_cursor_persisted(db, "tip_finalize", "t") == 15);
        int32_t applied = -1; bool af = false;
        coins_kv_get_applied_height(db, &applied, &af);
        SW_CHECK("rewind: post coins_applied_height == 15", af && applied == 15);

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
    }

    /* ── (C) TORN-SEAL REFUSAL (state unchanged) ────────────────────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "seal_rewind", "torn");
        SW_CHECK("torn: store opens", progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        sw_setup_schema(db);
        sw_fold(db, 24, grids, 4);
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
    }

    /* ── (D) FINALITY-FLOOR REFUSAL ─────────────────────────────────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "seal_rewind", "floor");
        SW_CHECK("floor: store opens", progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        sw_setup_schema(db);
        sw_fold(db, 24, grids, 4);

        /* Nearest base for H=17 is G=15; a floor of 16 forbids crossing it. */
        struct seal_rewind_result rr;
        seal_rewind_to_nearest(db, 17, /*floor=*/16, &rr);
        SW_CHECK("floor: seal below floor refused BELOW_FLOOR",
                 !rr.rewound && rr.refusal == SEAL_REWIND_BELOW_FLOOR);
        SW_CHECK("floor: state untouched (cursor == 25)",
                 stage_cursor_persisted(db, "utxo_apply", "t") == 25);

        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    printf("=== seal_rewind tests complete: %d failure(s) ===\n", failures);
    return failures;
}
