/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fault injection for the "contaminated coin ABOVE the anchor" class: a coin
 * folded into coins_kv (coins_applied_height advanced) above the height the
 * success-checked utxo_apply_log proves clean. Both halves are asserted off
 * one in-memory progress.kv:
 *
 *   HALF A: reducer_frontier_compute_hstar (a pure SELECT fold) must not
 *     raise H* to the contaminated coin at A+5; H* is the MIN over logs'
 *     contiguous ok=1 prefix, clamped at the anchor A. hstar < coins_applied.
 *
 *   HALF B: invariant_sentinel_sweep_once fires I4.4 (coin tear) and, after
 *     the two-sweep confirmation gate, raises the PERMANENT `window.consistency`
 *     blocker + EV_OPERATOR_NEEDED naming the exact heights
 *     (coins_applied=A+5 > utxo_apply ok=1 prefix=A+2 + 1).
 *
 * Fixture: utxo_apply ok=1 prefix == A+2 (hole at A+3); the cursor is set so
 *   ua_log_frontier == cursor-1, isolating I4.4 from I4.3.
 *
 * Scratch files live under ./test-tmp/<name>_<pid>/.
 */

#include "test/test_core.h"

#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "services/invariant_sentinel.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "validation/chain_linkage_check.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CCA_CHECK(name, expr) do {                                 \
    printf("contaminated_coin_above_anchor: %s... ", (name));      \
    if (expr) printf("OK\n");                                      \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

/* The compiled trusted anchor (SHA3 checkpoint) the algorithm clamps to. */
#define A REDUCER_FRONTIER_TRUSTED_ANCHOR  /* 3,056,758 */

/* Event observer: count EV_OPERATOR_NEEDED emissions. */
static _Atomic int g_op_needed;

static void cca_ev_observer(enum event_type type, uint32_t peer_id,
                            const void *payload, uint32_t payload_len,
                            void *ctx)
{
    (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    if (type == EV_OPERATOR_NEEDED)
        atomic_fetch_add(&g_op_needed, 1);
}

/* Build the production-shape stage logs + stage_cursor + progress_meta on the
 * progress.kv handle. Mirrors stig_create_svl (test_seed_torn_import_gate.c)
 * for script_validate_log / tip_finalize_log and build_schema
 * (test_reducer_frontier.c) for the rest. */
static bool cca_build_schema(sqlite3 *db)
{
    static const char *const ddl =
        "CREATE TABLE IF NOT EXISTS stage_cursor (name TEXT PRIMARY KEY,"
        "  cursor INTEGER NOT NULL, updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS progress_meta (key TEXT PRIMARY KEY,"
        "  value BLOB);"
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
        "  fail_reason TEXT, validated_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  tx_count INTEGER NOT NULL, input_count INTEGER NOT NULL,"
        "  first_failure_txid BLOB, first_failure_vin INTEGER,"
        "  first_failure_serror INTEGER, validated_at INTEGER NOT NULL,"
        "  block_hash BLOB);"
        "CREATE TABLE IF NOT EXISTS body_persist_log ("
        "  height INTEGER PRIMARY KEY, source TEXT, ok INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  spent_count INTEGER, added_count INTEGER);"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  tip_hash BLOB);";
    return sqlite3_exec(db, ddl, NULL, NULL, NULL) == SQLITE_OK;  // raw-sql-ok:test-seed
}

static bool cca_set_cursor(sqlite3 *db, const char *name, int64_t cursor)
{
    sqlite3_stmt *st = NULL;
    /* Production stage_cursor has updated_at NOT NULL; write all three columns
     * or the cursor stays 0 and the I4.4 `cur_utxo_apply > 0` guard is unarmed. */
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at)"
            " VALUES(?,?,0)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

/* Insert one ok=1 utxo_apply_log row at `height`. */
static bool cca_put_ua_row(sqlite3 *db, int32_t height)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_log(height,status,ok) "
            "VALUES(?,'verified',1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

/* Stamp coins_applied_height via the EXISTING public helper, wrapped in a
 * BEGIN IMMEDIATE/COMMIT (mirrors stig_set_applied). */
static bool cca_set_applied(sqlite3 *db, int32_t height)
{
    if (!progress_meta_table_ensure(db))
        return false;
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    bool ok = coins_kv_set_applied_height_in_tx(db, height);
    const char *finish = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(db, finish, NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    /* Stamp the migration-complete rung so coins_kv_is_proven_authority is
     * true; otherwise compute_hstar drops its floor to 0 (fresh datadir). */
    if (ok) {
        uint8_t one = 1;
        ok = progress_meta_set(db, COINS_KV_MIGRATION_COMPLETE_KEY, &one, 1);
    }
    return ok;
}

/* Fixture setup (2): build the schema, add the contaminated coin above the
 * anchor and stamp coins_applied to A+5. Returns the CCA_CHECK failure count. */
static int cca_check_schema_and_contaminated_coin(sqlite3 *pk)
{
    int failures = 0;
    bool schema_ok = pk && cca_build_schema(pk) && coins_kv_ensure_schema(pk);
    CCA_CHECK("schema built", schema_ok);

    /* (2) THE CONTAMINATED COIN: a live output at ANCHOR+5, above the last
     * verified height; coins_applied stamped to ANCHOR+5. */
    uint8_t txid[32];
    memset(txid, 0, 32);
    txid[0] = 0xDE; txid[1] = 0xAD; txid[31] = 0x5e;
    uint8_t script[1] = {0x51};  /* OP_TRUE */
    CCA_CHECK("contaminated coin added at A+5",
              pk && coins_kv_add(pk, txid, 0, 1000, A + 5, false,
                                 script, sizeof(script)));
    CCA_CHECK("coins_applied stamped to A+5", pk && cca_set_applied(pk, A + 5));
    return failures;
}

/* Fixture setup (3): the utxo_apply ok=1 prefix hole and the stage cursors
 * that isolate I4.4 from I4.3/I4.1. Returns the CCA_CHECK failure count. */
static int cca_check_prefix_hole_and_cursors(sqlite3 *pk)
{
    int failures = 0;
    /* (3) THE HOLE: utxo_apply_log ok=1 run only A+1..A+2 (hole at A+3), so
     * coins_applied (A+5) is 3 heights above the verified prefix. */
    bool ua_rows = pk && cca_put_ua_row(pk, A + 1) && cca_put_ua_row(pk, A + 2);
    CCA_CHECK("utxo_apply ok=1 prefix A+1..A+2 (hole at A+3)", ua_rows);

    /* utxo_apply cursor = A+3 so ua_log_frontier (A+2) == cursor-1: keeps I4.3
     * quiet while coins_applied=A+5 trips I4.4 (as test_invariant_sentinel.c).
     * script_validate/tip_finalize cursors >= utxo_apply keep I4.1 quiet. */
    bool cursors = pk
        && cca_set_cursor(pk, "utxo_apply", A + 3)
        && cca_set_cursor(pk, "script_validate", A + 3)
        && cca_set_cursor(pk, "tip_finalize", A + 3)
        && cca_set_cursor(pk, "body_fetch", A + 3)
        && cca_set_cursor(pk, "validate_headers", A + 3);
    CCA_CHECK("cursors set (I4.3/I4.1 quiet, I4.4 armed)", cursors);
    return failures;
}

/* ── HALF A: H* never reports above its provable prefix ────────────────── */
static int cca_check_half_a_hstar(sqlite3 *pk)
{
    int failures = 0;
    int32_t hstar = -1, served = -1;
    progress_store_tx_lock();
    bool hs = pk && reducer_frontier_compute_hstar(pk, &hstar, &served);
    progress_store_tx_unlock();
    /* a1: compute returns true. */
    CCA_CHECK("HALF A: compute_hstar returns true", hs);
    /* a2: pinned at the anchor (MIN over logs == A; clamp guard holds). The
     * decisive negative facts: hstar != A+5 and hstar < coins_applied. */
    CCA_CHECK("HALF A: hstar == A (MIN-over-logs anchor pin)", hstar == A);
    CCA_CHECK("HALF A: hstar != A+5 (did not float to contaminated coin)",
              hstar != A + 5);
    CCA_CHECK("HALF A: hstar < coins_applied (A+5)", hstar < A + 5);
    /* a3: hard guard — never below the finality anchor. */
    CCA_CHECK("HALF A: hstar >= TRUSTED_ANCHOR", hstar >= A);
    return failures;
}

/* ── HALF B: node halts with a NAMED blocker, not silently ─────────────── */
static int cca_check_half_b_sweeps(void)
{
    int failures = 0;
    /* b1: FIRST sweep returns true; the two-sweep gate WITHHOLDS the blocker
     * on the first observation. */
    bool s1 = invariant_sentinel_sweep_once();
    CCA_CHECK("HALF B: first sweep returns true", s1);
    CCA_CHECK("HALF B: no blocker yet (two-sweep gate withholds)",
              !blocker_exists("window.consistency"));

    /* b2: SECOND sweep crosses the confirmation gate -> PERMANENT blocker +
     * EV_OPERATOR_NEEDED. */
    bool s2 = invariant_sentinel_sweep_once();
    CCA_CHECK("HALF B: second sweep returns true", s2);
    CCA_CHECK("HALF B: window.consistency PERMANENT blocker raised",
              blocker_exists("window.consistency") &&
              blocker_class_for("window.consistency") == BLOCKER_PERMANENT);
    CCA_CHECK("HALF B: EV_OPERATOR_NEEDED paged",
              atomic_load(&g_op_needed) >= 1);
    return failures;
}

/* Snapshot the blockers and check the window.consistency reason text names
 * I4.4 with the exact heights. Returns the CCA_CHECK failure count. */
static int cca_check_half_b_reason_text(void)
{
    int failures = 0;
    /* b3: NAMED-with-exact-height — the blocker reason names I4.4, the
     * "coin tear" detail, and carries the prefix value A+2 (format:
     * "coin tear: coins_applied=<A+5> > utxo_apply ok=1 prefix=<A+2>+1"). */
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    const char *reason = NULL;
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, "window.consistency") == 0) {
            reason = snaps[i].reason;
            break;
        }
    }
    char want_prefix[32];
    snprintf(want_prefix, sizeof(want_prefix), "prefix=%d", A + 2);
    CCA_CHECK("HALF B: reason names I4.4 + coin tear + exact heights",
              reason != NULL &&
              strstr(reason, "I4.4") != NULL &&
              strstr(reason, "coin tear") != NULL &&
              strstr(reason, want_prefix) != NULL);
    return failures;
}

/* ── Optional pure-function cross-check: isolate the I4.4 verdict logic ── */
static int cca_check_pure_i44_evaluation(void)
{
    int failures = 0;
    struct invariant_sweep_inputs in;
    struct invariant_sweep_verdict v;
    memset(&in, 0, sizeof(in));
    in.cur_tip_finalize = A + 3;
    in.cur_utxo_apply = A + 3;
    in.cur_script_validate = A + 3;
    in.ua_log_frontier = A + 2;
    in.ua_log_frontier_known = true;
    in.coins_applied = A + 5;
    in.coins_applied_found = true;
    in.prev_cur_tip_finalize = -1;
    invariant_sentinel_sweep_evaluate(&in, &v);
    CCA_CHECK("pure: evaluate yields I4.4 violated at first_bad_h == A+3",
              v.violated && strcmp(v.invariant, "I4.4") == 0 &&
              v.first_bad_h == A + 3);
    return failures;
}

int test_contaminated_coin_above_anchor(void);
int test_contaminated_coin_above_anchor(void)
{
    test_reset_shared_globals();   /* monolith isolation */
    printf("\n=== contaminated_coin_above_anchor tests ===\n");
    int failures = 0;

    event_log_init();
    blocker_module_init();
    blocker_reset_for_testing();
    invariant_sentinel_reset_for_testing();
    chain_linkage_reset_for_testing();

    char dir[256];
    snprintf(dir, sizeof(dir), "./test-tmp/cca_above_anchor_%d", (int)getpid());
    mkdir("./test-tmp", 0755);
    mkdir(dir, 0755);

    /* ── fixture: ONE in-memory progress.kv via the public store ───────────── */
    progress_store_close();
    bool store_ok = progress_store_open(dir);
    CCA_CHECK("progress store opens", store_ok);
    sqlite3 *pk = progress_store_db();
    CCA_CHECK("progress db handle", pk != NULL);

    failures += cca_check_schema_and_contaminated_coin(pk);
    failures += cca_check_prefix_hole_and_cursors(pk);

    /* Observe EV_OPERATOR_NEEDED. */
    event_clear_observers(EV_OPERATOR_NEEDED);
    atomic_store(&g_op_needed, 0);
    event_observe(EV_OPERATOR_NEEDED, cca_ev_observer, NULL);

    failures += cca_check_half_a_hstar(pk);
    failures += cca_check_half_b_sweeps();
    failures += cca_check_half_b_reason_text();
    failures += cca_check_pure_i44_evaluation();

    /* ── teardown ──────────────────────────────────────────────────────────── */
    event_clear_observers(EV_OPERATOR_NEEDED);
    progress_store_close();
    test_cleanup_tmpdir(dir);
    blocker_reset_for_testing();
    invariant_sentinel_reset_for_testing();
    chain_linkage_reset_for_testing();
    return failures;
}
