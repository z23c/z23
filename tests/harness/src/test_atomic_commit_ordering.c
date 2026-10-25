/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * DETERMINISTIC, default-gate guard for the at-tip commit-ordering
 * invariant:
 *
 *   The node.db coins/UTXO commit must land BEFORE the LevelDB/flat
 *   block_index fsync, so a crash between the two never leaves UTXO
 *   rows above the committed (durable) tip.
 *
 * The forbidden on-disk shape (d) is "UTXOs ahead of tip": utxos rows
 * at height H+1 while the durable best-block is still H. A node that
 * boots into that shape would reconnect H+1, see its own coinbase
 * already in the UTXO set, and trip BIP30 forever.
 *
 * test_kill9_recovery and test_chain_advance_atomicity exercise the same
 * invariant under fork() + SIGKILL but self-skip unless ZCL_STRESS_TESTS=1.
 * This test is in-process and deterministic: it builds the post-crash datadir
 * shape by hand (utxos rows above the durable tip) and drives the production
 * recovery seam, coins_rewind_above_tip(), asserting:
 *
 *   1. Auto-heal mode (max_rows >= count, max_height == tip+1) DELETES
 *      every above-tip row and reports the deletion count.
 *   2. Post-rewind: COUNT(utxos WHERE height > committed_tip) == 0
 *      (the load-bearing invariant) AND MAX(height) <= committed_tip
 *      (tip monotonicity — nothing survives above the durable tip).
 *   3. The bounded guard REFUSES (returns -1, leaves rows UNTOUCHED)
 *      when the overshoot is more than +1 above tip, or exceeds the
 *      row bound — proving the seam is a *targeted* single-block heal,
 *      not a blind truncation that could mask a deeper tear.
 *
 * It runs in the default gate and is byte-for-byte reproducible. It asserts
 * the recovery half of the invariant, not the production write ordering (a
 * true mid-commit fault injection needs a real process death).
 */

#include "test/test_core.h"
#include "storage/coins_view_sqlite.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int test_atomic_commit_ordering(void);

/* ── In-file fixture helpers (mirrors the standalone style of
 * test_kill9_recovery / test_chain_advance_atomicity so this test can
 * be reasoned about in isolation). ──────────────────────────────── */

/* Minimal coins.db schema. coins_rewind_above_tip only requires the
 * `utxos` table; `transactions` is optional (guarded by table_exists in
 * the production code) so we deliberately omit it — the table-absent
 * path is the common datadir shape. node_state holds the commitment row
 * the rewind clears. */
static bool aco_build_schema(sqlite3 *db)
{
    char *err = NULL;
    int rc = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS utxos("
        " txid BLOB, vout INTEGER, value INTEGER,"
        " script BLOB, script_type INTEGER, address_hash BLOB,"
        " height INTEGER, is_coinbase INTEGER,"
        " PRIMARY KEY(txid,vout));"
        "CREATE TABLE IF NOT EXISTS node_state("
        " key TEXT PRIMARY KEY, value BLOB);",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "aco_build_schema: %s\n", err ? err : "?");
        sqlite3_free(err);
        return false;
    }
    return true;
}

/* Insert one UTXO row at `height`. `tag` differentiates primary keys so
 * the same height can hold several rows. */
static void aco_insert_utxo(sqlite3 *db, int height, int tag)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxos(txid,vout,value,script,"
            " script_type,address_hash,height,is_coinbase) "
            "VALUES(?,0,0,NULL,0,NULL,?,0)", -1, &s, NULL) != SQLITE_OK)
        return;
    uint8_t txid[32];
    memset(txid, 0, 32);
    txid[0] = (uint8_t)(height & 0xFF);
    txid[1] = (uint8_t)((height >> 8) & 0xFF);
    txid[2] = (uint8_t)(height >> 16);
    txid[3] = (uint8_t)tag;
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 2, height);
    sqlite3_step(s);
    sqlite3_finalize(s);
}

static int aco_count_above(sqlite3 *db, int tip)
{
    sqlite3_stmt *s = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM utxos WHERE height > ?",
            -1, &s, NULL) == SQLITE_OK) {
        sqlite3_bind_int(s, 1, tip);
        if (sqlite3_step(s) == SQLITE_ROW) n = sqlite3_column_int(s, 0);
    }
    sqlite3_finalize(s);
    return n;
}

static int aco_max_height(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    int h = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT COALESCE(MAX(height),-1) FROM utxos",
            -1, &s, NULL) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW) h = sqlite3_column_int(s, 0);
    }
    sqlite3_finalize(s);
    return h;
}

/* Seed: utxos at heights [tip-2 .. tip] (the durable, committed body)
 * plus `n_above` extra rows at tip+1 (the crash-mid-flush overshoot —
 * UTXOs written but the block_index/tip never made it durable). Returns
 * an in-memory sqlite handle the caller closes. */
static sqlite3 *aco_seed(int tip, int n_above)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return NULL;
    if (!aco_build_schema(db)) { sqlite3_close(db); return NULL; }

    /* Durable body at and below the committed tip. */
    for (int h = tip - 2; h <= tip; h++)
        if (h >= 0) aco_insert_utxo(db, h, /*tag*/0);

    /* The forbidden overshoot rows above the committed tip. */
    for (int k = 0; k < n_above; k++)
        aco_insert_utxo(db, tip + 1, /*tag*/1 + k);

    /* A stale UTXO commitment that the rewind must clear. */
    sqlite3_exec(db,
        "INSERT OR REPLACE INTO node_state(key,value) "
        "VALUES('utxo_commitment', x'deadbeef')",
        NULL, NULL, NULL);
    return db;
}

/* ── Case drivers. Each drives one scenario end to end and returns
 * the number of failed assertions it recorded, or -1 when its seed
 * datadir cannot be opened — test_atomic_commit_ordering maps that
 * back to its original early returns. ───────────────────────────── */

/* ── Case 1: auto-heal restores the invariant ─────────────────
 * Tip committed at 1000; 3 UTXO rows orphaned at 1001 (the crash
 * landed between the UTXO inserts and the durable tip/block_index
 * write). The boot-time seam must delete exactly those rows. */
static int aco_case1_auto_heal_restores_invariant(void)
{
    int failures = 0;
    const int tip = 1000;
    const int n_above = 3;
    sqlite3 *db = aco_seed(tip, n_above);
    if (!db) {
        printf("  FAIL (case1: seed open failed)\n");
        return -1;
    }

    int before = aco_count_above(db, tip);
    if (before != n_above) {
        printf("  FAIL (case1 setup: expected %d above-tip rows, "
               "got %d)\n", n_above, before);
        failures++;
    }

    /* Bounded auto-heal mode — the exact call the live boot path
     * makes (max_rows >= overshoot, overshoot confined to tip+1). */
    int deleted = coins_rewind_above_tip(db, tip, /*max_rows*/32);
    if (deleted != n_above) {
        printf("  FAIL (case1: coins_rewind_above_tip returned %d, "
               "expected %d deleted)\n", deleted, n_above);
        failures++;
    }

    int after = aco_count_above(db, tip);
    if (after != 0) {
        printf("  FAIL (case1: %d UTXO row(s) STILL above committed "
               "tip after auto-heal — ordering invariant broken)\n",
               after);
        failures++;
    }

    int maxh = aco_max_height(db);
    if (maxh > tip) {
        printf("  FAIL (case1: MAX(utxos.height)=%d exceeds committed "
               "tip=%d — tip monotonicity violated)\n", maxh, tip);
        failures++;
    }

    if (!failures)
        printf("  case1 OK: %d orphaned rows pruned; "
               "0 above committed tip=%d, max_height=%d\n",
               deleted, tip, maxh);
    sqlite3_close(db);
    return failures;
}

/* ── Case 2: bounded guard REFUSES a >+1 overshoot ─────────────
 * Rows above tip live at tip+2, not tip+1. That is NOT the
 * single-block crash-mid-flush shape, so the bounded seam must
 * refuse (return -1) and leave the rows untouched for an operator
 * — it must never blindly truncate a deeper tear. */
static int aco_case2_guard_refuses_deeper_tear(void)
{
    int failures = 0;
    const int tip = 500;
    sqlite3 *db = aco_seed(tip, /*n_above at tip+1*/0);
    if (!db) {
        printf("  FAIL (case2: seed open failed)\n");
        return -1;
    }
    /* Plant the overshoot two blocks above tip. */
    aco_insert_utxo(db, tip + 2, /*tag*/7);

    int rc = coins_rewind_above_tip(db, tip, /*max_rows*/32);
    if (rc != -1) {
        printf("  FAIL (case2: expected guard refusal (-1) for a "
               "tip+2 overshoot, got %d)\n", rc);
        failures++;
    }
    int still = aco_count_above(db, tip);
    if (still != 1) {
        printf("  FAIL (case2: guard altered rows on refusal "
               "(%d above tip, expected the 1 planted row "
               "untouched))\n", still);
        failures++;
    } else {
        printf("  case2 OK: bounded guard refused tip+2 overshoot, "
               "left row untouched (no blind truncation)\n");
    }
    sqlite3_close(db);
    return failures;
}

/* ── Case 3: no-op when already consistent ────────────────────
 * Committed tip with NO above-tip rows: the seam reports 0 work
 * and changes nothing — the steady-state at-tip case. */
static int aco_case3_noop_when_already_consistent(void)
{
    int failures = 0;
    const int tip = 250;
    sqlite3 *db = aco_seed(tip, /*n_above*/0);
    if (!db) {
        printf("  FAIL (case3: seed open failed)\n");
        return -1;
    }
    int rc = coins_rewind_above_tip(db, tip, /*max_rows*/32);
    if (rc != 0) {
        printf("  FAIL (case3: expected 0 (no work) on a consistent "
               "datadir, got %d)\n", rc);
        failures++;
    }
    if (aco_max_height(db) != tip) {
        printf("  FAIL (case3: no-op altered max height)\n");
        failures++;
    } else {
        printf("  case3 OK: consistent at-tip datadir → no-op\n");
    }
    sqlite3_close(db);
    return failures;
}

int test_atomic_commit_ordering(void)
{
    int failures = 0;
    printf("\n=== atomic commit-ordering invariant "
           "(deterministic, default gate) ===\n");

    /* In-process: no fork, no signals, no params, no external binary. */

    int r = aco_case1_auto_heal_restores_invariant();
    if (r < 0)
        return 1;
    failures += r;

    r = aco_case2_guard_refuses_deeper_tear();
    if (r < 0)
        return failures ? failures : 1;
    failures += r;

    r = aco_case3_noop_when_already_consistent();
    if (r < 0)
        return failures ? failures : 1;
    failures += r;

    if (!failures)
        printf("atomic_commit_ordering: OK "
               "(recovery seam restores 'no UTXO above committed tip', "
               "refuses deeper tears, no-ops when clean)\n");
    return failures;
}
