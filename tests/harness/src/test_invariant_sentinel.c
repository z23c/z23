/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the fail-loud validation pack invariant_sentinel
 * (engine/services/src/invariant_sentinel.c):
 *
 *   check 3 (authority-pair self-check):
 *     - empty blocks projection -> pass (unknown hash is publishable);
 *     - matching (height, hash) -> pass;
 *     - hash resolving to a DIFFERENT height -> REFUSED + PERMANENT
 *       blocker authority.pair_self_check (crash-only: just a false
 *       return, process alive);
 *     - NULL ndb -> pass (early boot / unit-test shape);
 *     - height < 0 (tip reset) -> pass silently.
 *
 *   check 4 (window sweep verdict — pure function):
 *     - healthy pipeline -> no violation (incl. fresh-datadir zeros and
 *       anchor-stamped equal cursors, the cold-import shape);
 *     - I4.1 ordering violation names the cursor pair;
 *     - I4.3 utxo_apply log hole names the first hole height;
 *     - I4.4 coin tear (Invariant B re-assertion) names the heights;
 *     - I4.5 tip_finalize oscillation at an unmoving cursor fires at the
 *       threshold, not below it. */

#include "test/test_core.h"

#include "models/database.h"
#include "services/invariant_sentinel.h"
#include "coins/utxo_commitment.h"
#include "util/blocker.h"
#include "validation/chain_linkage_check.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define ISN_CHECK(name, expr) do {                  \
    printf("invariant_sentinel: %s... ", (name));   \
    if (expr) printf("OK\n");                         \
    else { printf("FAIL\n"); failures++; }            \
} while (0)

static bool isn_insert_block(struct node_db *ndb, const uint8_t hash[32],
                             int height)
{
    sqlite3_stmt *st = NULL;
    const char *sql =
        "INSERT OR REPLACE INTO blocks"
        "(hash,height,prev_hash,version,merkle_root,time,bits,nonce,"
        " solution,chain_work,status,num_tx)"
        " VALUES(?,?,?,4,?,?,0,?,?,?,3,0)";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    static const uint8_t zeros[32] = {0};
    static const uint8_t solution[1] = {0};
    sqlite3_bind_blob(st, 1, hash, 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, height);
    sqlite3_bind_blob(st, 3, zeros, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 4, zeros, 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 5, 1700000000 + height);
    sqlite3_bind_blob(st, 6, zeros, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 7, solution, sizeof(solution), SQLITE_STATIC);
    sqlite3_bind_blob(st, 8, zeros, 32, SQLITE_STATIC);
    int rc = sqlite3_step(st);  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

static bool isn_insert_utxo(struct node_db *ndb, int salt)
{
    sqlite3_stmt *st = NULL;
    const char *sql =
        "INSERT OR REPLACE INTO utxos"
        "(txid,vout,value,script,script_type,address_hash,height,is_coinbase)"
        " VALUES(?,?,?,?,0,?,?,0)";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    uint8_t txid[32];
    memset(txid, (uint8_t)(0x10 + salt), 32);
    static const uint8_t script[4] = { 0x76, 0xa9, 0x14, 0x00 };
    static const uint8_t addr[20] = {0};
    sqlite3_bind_blob(st, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, 0);
    sqlite3_bind_int64(st, 3, 50000 + salt);
    sqlite3_bind_blob(st, 4, script, sizeof(script), SQLITE_STATIC);
    sqlite3_bind_blob(st, 5, addr, sizeof(addr), SQLITE_STATIC);
    sqlite3_bind_int64(st, 6, 1000 + salt);
    int rc = sqlite3_step(st);  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

static void isn_healthy_inputs(struct invariant_sweep_inputs *in)
{
    memset(in, 0, sizeof(*in));
    in->cur_tip_finalize = 3143000;
    in->cur_utxo_apply = 3143010;
    in->cur_script_validate = 3143020;
    in->cur_body_fetch = 3143030;
    in->cur_validate_headers = 3143100;
    in->ua_log_frontier = 3143009;       /* == cursor-1: no hole */
    in->ua_log_frontier_known = true;
    in->coins_applied = 3143010;         /* == cursor: no tear */
    in->coins_applied_found = true;
    in->reorg_detected_total = 100;
    in->prev_reorg_detected_total = 100;
    in->prev_cur_tip_finalize = 3142990; /* cursor moved since last sweep */
}

int test_invariant_sentinel(void)
{
    printf("\n=== invariant_sentinel tests ===\n");
    int failures = 0;

    blocker_module_init();
    blocker_reset_for_testing();
    chain_linkage_reset_for_testing();
    invariant_sentinel_reset_for_testing();

    /* ── check 3: authority-pair self-check ───────────────────────── */
    {
        struct node_db ndb;
        bool dbok = node_db_open(&ndb, ":memory:");
        ISN_CHECK("fixture: in-memory node_db opens", dbok);
        if (dbok) {
            uint8_t hash_a[32]; memset(hash_a, 0xA1, 32);
            uint8_t hash_b[32]; memset(hash_b, 0xB2, 32);

            /* empty projection: unknown hash passes (fresh datadir /
             * cold-import non-fire proof) */
            bool ok = invariant_sentinel_check_pair(&ndb, hash_a, 100,
                                                    "test_empty");
            ISN_CHECK("pair: unknown hash passes (empty projection)", ok);

            /* matching pair passes */
            ok = isn_insert_block(&ndb, hash_a, 100) &&
                 invariant_sentinel_check_pair(&ndb, hash_a, 100,
                                               "test_match");
            ISN_CHECK("pair: matching (height,hash) passes", ok);
            ISN_CHECK("pair: no blocker after passes",
                      !blocker_exists("authority.pair_self_check"));

            /* mismatch refuses + blocker (crash-only) */
            ok = isn_insert_block(&ndb, hash_b, 200);
            bool refused = !invariant_sentinel_check_pair(&ndb, hash_b, 206,
                                                          "test_mismatch");
            ISN_CHECK("pair: +6 mismatch REFUSED", ok && refused);
            ISN_CHECK("pair: PERMANENT blocker registered",
                      blocker_exists("authority.pair_self_check") &&
                      blocker_class_for("authority.pair_self_check") ==
                          BLOCKER_PERMANENT);

            /* tip reset (height -1) passes silently */
            ok = invariant_sentinel_check_pair(&ndb, hash_b, -1,
                                               "test_reset");
            ISN_CHECK("pair: height -1 (tip reset) passes", ok);

            blocker_clear("authority.pair_self_check");
            node_db_close(&ndb);
        }
        /* NULL ndb passes (unit tests / early boot) */
        uint8_t hash_c[32]; memset(hash_c, 0xC3, 32);
        ISN_CHECK("pair: NULL ndb passes",
                  invariant_sentinel_check_pair(NULL, hash_c, 5, "t"));
    }

    /* ── check 4: sweep verdict (pure) ────────────────────────────── */
    {
        struct invariant_sweep_inputs in;
        struct invariant_sweep_verdict v;

        /* healthy steady-state pipeline */
        isn_healthy_inputs(&in);
        invariant_sentinel_sweep_evaluate(&in, &v);
        ISN_CHECK("sweep: healthy pipeline -> no violation", !v.violated);

        /* fresh datadir: all zeros, nothing known */
        memset(&in, 0, sizeof(in));
        in.prev_cur_tip_finalize = -1;
        invariant_sentinel_sweep_evaluate(&in, &v);
        ISN_CHECK("sweep: fresh datadir (all zeros) -> no violation",
                  !v.violated);

        /* anchor-stamped cold-import: all cursors equal, frontier ==
         * cursor-1 (the anchor row) */
        isn_healthy_inputs(&in);
        in.cur_tip_finalize = in.cur_utxo_apply = in.cur_script_validate =
            in.cur_body_fetch = in.cur_validate_headers = 3056759;
        in.ua_log_frontier = 3056758;
        in.coins_applied = 3056759;
        invariant_sentinel_sweep_evaluate(&in, &v);
        ISN_CHECK("sweep: anchor-stamped cold-import -> no violation",
                  !v.violated);

        /* I4.1: tip_finalize cursor ahead of utxo_apply */
        isn_healthy_inputs(&in);
        in.cur_tip_finalize = in.cur_utxo_apply + 5;
        invariant_sentinel_sweep_evaluate(&in, &v);
        ISN_CHECK("sweep: I4.1 ordering violation fires + named",
                  v.violated && strcmp(v.invariant, "I4.1") == 0 &&
                  strstr(v.detail, "tip_finalize") != NULL);

        /* I4.3: hole below the utxo_apply cursor (the 3142977 shape) */
        isn_healthy_inputs(&in);
        in.ua_log_frontier = (int32_t)(in.cur_utxo_apply - 30);
        invariant_sentinel_sweep_evaluate(&in, &v);
        ISN_CHECK("sweep: I4.3 log hole fires + names first hole h",
                  v.violated && strcmp(v.invariant, "I4.3") == 0 &&
                  v.first_bad_h == (int)(in.cur_utxo_apply - 29));

        /* I4.4: coin tear — coins_applied above utxo_apply's own ok=1
         * prefix + 1 (Invariant B) */
        isn_healthy_inputs(&in);
        in.cur_utxo_apply = in.ua_log_frontier + 1; /* keep I4.3 quiet */
        in.coins_applied = in.ua_log_frontier + 7;
        invariant_sentinel_sweep_evaluate(&in, &v);
        ISN_CHECK("sweep: I4.4 coin tear fires",
                  v.violated && strcmp(v.invariant, "I4.4") == 0);

        /* legitimate pipeline depth is NOT a tear: coins_applied ==
         * frontier+1 while tip_finalize lags far behind */
        isn_healthy_inputs(&in);
        in.cur_tip_finalize = in.cur_utxo_apply - 500;
        invariant_sentinel_sweep_evaluate(&in, &v);
        ISN_CHECK("sweep: pipeline depth (tip_finalize lag) -> no tear",
                  !v.violated);

        /* I4.5: oscillation at an unmoving cursor — fires at threshold */
        isn_healthy_inputs(&in);
        in.prev_cur_tip_finalize = in.cur_tip_finalize; /* unmoved */
        in.prev_reorg_detected_total = 100;
        in.reorg_detected_total = 109; /* below threshold of 10 */
        invariant_sentinel_sweep_evaluate(&in, &v);
        bool below_quiet = !v.violated;
        in.reorg_detected_total = 110; /* at threshold */
        invariant_sentinel_sweep_evaluate(&in, &v);
        ISN_CHECK("sweep: I4.5 oscillation fires at threshold only",
                  below_quiet && v.violated &&
                  strcmp(v.invariant, "I4.5") == 0);

        /* moving cursor: same reorg burst is normal reorg handling */
        isn_healthy_inputs(&in);
        in.prev_cur_tip_finalize = in.cur_tip_finalize - 3; /* moved */
        in.prev_reorg_detected_total = 100;
        in.reorg_detected_total = 150;
        invariant_sentinel_sweep_evaluate(&in, &v);
        ISN_CHECK("sweep: reorg burst at a MOVING cursor -> quiet",
                  !v.violated);
    }

    /* ── two-sweep confirmation gate ──────────────────────────────── */
    {
        invariant_sentinel_reset_for_testing();
        struct invariant_sweep_verdict v;
        memset(&v, 0, sizeof(v));
        v.violated = true;
        snprintf(v.invariant, sizeof(v.invariant), "I4.1");
        v.first_bad_h = 100;
        snprintf(v.detail, sizeof(v.detail), "t");

        ISN_CHECK("confirm: first observation does NOT raise "
                  "(reorg-unwind window cover)",
                  !invariant_sentinel_confirm_violation(&v));
        ISN_CHECK("confirm: same violation on the next sweep raises",
                  invariant_sentinel_confirm_violation(&v));

        /* a moved boundary is a different violation: restart the count */
        v.first_bad_h = 200;
        ISN_CHECK("confirm: changed first_bad_h restarts the count",
                  !invariant_sentinel_confirm_violation(&v));

        /* a clean sweep resets the pending state */
        struct invariant_sweep_verdict clean;
        memset(&clean, 0, sizeof(clean));
        clean.first_bad_h = -1;
        ISN_CHECK("confirm: clean verdict resets pending",
                  !invariant_sentinel_confirm_violation(&clean));
        v.first_bad_h = 200;
        ISN_CHECK("confirm: post-clean re-observation starts at one",
                  !invariant_sentinel_confirm_violation(&v));
    }

    /* ── check 5: commitment audit — DECOUPLED, streak-gated, self-clearing.
     * The `utxos` table is a rebuildable projection of the coins_kv authority
     * and the checkpoint is a frozen out-of-band cache, so a mismatch is a
     * benign skew, not chain corruption: it must NEVER raise a chain_linkage
     * HOLD (decoupled — that HOLD rolling
     * back a PoW-proven tip_finalize is itself a wedge), needs 2 CONSECUTIVE candidate verdicts to
     * fire (swallow the mirror-rebuild torn-scan race), and self-clears on a
     * growth resync or via the auto-terminating owner. ───────────────────── */
    {
        invariant_sentinel_reset_for_testing();
        blocker_reset_for_testing();
        chain_linkage_reset_for_testing();
        struct node_db ndb;
        bool dbok = node_db_open(&ndb, ":memory:");
        ISN_CHECK("fixture: audit node_db opens", dbok);
        if (dbok) {
            invariant_sentinel_set_node_db_for_testing(&ndb);

            for (int i = 0; i < 8; i++)
                if (!isn_insert_utxo(&ndb, i))
                    dbok = false;
            ISN_CHECK("fixture: 8 utxos seeded", dbok);

            struct utxo_commitment uc;
            utxo_commitment_compute_db(ndb.db, &uc);
            bool saved = utxo_commitment_save_checkpoint(ndb.db, &uc);
            ISN_CHECK("fixture: checkpoint saved (count=8)",
                      saved && uc.count == 8);

            /* matching set -> clean, no blocker, no hold */
            bool ran = invariant_sentinel_commitment_audit_once();
            ISN_CHECK("audit: matching set -> clean (no blocker, no hold)",
                      ran && !blocker_exists("coins.commitment_spot_check") &&
                      !chain_linkage_hold_active());

            /* GROWTH (computed > saved): no fire, and EDIT 1 RESYNCS the
             * checkpoint to the grown set (count 8 -> 10). */
            bool grew = isn_insert_utxo(&ndb, 100) &&
                        isn_insert_utxo(&ndb, 101);
            ran = invariant_sentinel_commitment_audit_once();
            struct utxo_commitment ck;
            bool loaded = utxo_commitment_load_checkpoint(ndb.db, &ck);
            ISN_CHECK("audit: growth -> no fire + checkpoint resynced to 10",
                      grew && ran &&
                      !blocker_exists("coins.commitment_spot_check") &&
                      !chain_linkage_hold_active() &&
                      loaded && ck.count == 10);

            /* SHRINK below the (now count=10) checkpoint. */
            bool truncated = sqlite3_exec(ndb.db,
                "DELETE FROM utxos WHERE rowid IN "
                "(SELECT rowid FROM utxos LIMIT 4)",
                NULL, NULL, NULL) == SQLITE_OK;
            /* STREAK GATE: a single shrink audit must NOT fire. */
            ran = invariant_sentinel_commitment_audit_once();
            ISN_CHECK("audit: single shrink does NOT fire (streak gate)",
                      truncated && ran &&
                      !blocker_exists("coins.commitment_spot_check") &&
                      !chain_linkage_hold_active());

            /* DECOUPLE: a 2nd consecutive shrink fires the NON-FATAL diagnostic
             * blocker but NEVER a chain_linkage hold. */
            ran = invariant_sentinel_commitment_audit_once();
            ISN_CHECK("audit: 2nd shrink FIRES non-fatal blocker, NO HOLD",
                      ran &&
                      blocker_exists("coins.commitment_spot_check") &&
                      blocker_class_for("coins.commitment_spot_check") ==
                          BLOCKER_PERMANENT &&
                      !chain_linkage_hold_active());

            /* OWNER: the auto-terminating owner hook (called by the
             * state_window_inconsistent remedy) releases the diagnostic with no
             * node.db access. */
            invariant_sentinel_clear_commitment_blocker();
            ISN_CHECK("owner: clear_commitment_blocker releases blocker + hold",
                      !blocker_exists("coins.commitment_spot_check") &&
                      !chain_linkage_hold_active());

            /* LIVE-WEDGE SELF-HEAL: re-latch (2 shrinks), then a GROWTH audit
             * clears the latched blocker via resync — the exact 3164076 cure. */
            (void)invariant_sentinel_commitment_audit_once(); /* streak 1 */
            (void)invariant_sentinel_commitment_audit_once(); /* streak 2 -> fire */
            ISN_CHECK("setup: blocker re-latched on sustained shrink",
                      blocker_exists("coins.commitment_spot_check"));
            bool regrew = isn_insert_utxo(&ndb, 200) &&
                          isn_insert_utxo(&ndb, 201) &&
                          isn_insert_utxo(&ndb, 202) &&
                          isn_insert_utxo(&ndb, 203) &&
                          isn_insert_utxo(&ndb, 204); /* above the 10-checkpoint */
            ran = invariant_sentinel_commitment_audit_once();
            ISN_CHECK("audit: growth resync clears a latched blocker (3164076 self-heal)",
                      regrew && ran &&
                      !blocker_exists("coins.commitment_spot_check") &&
                      !chain_linkage_hold_active());

            blocker_clear("coins.commitment_spot_check");
            chain_linkage_hold_clear("commitment_audit");
            node_db_close(&ndb);
        }
    }

    /* crash-only sanity: everything above ran in-process; reaching here
     * IS the no-FATAL proof. */
    blocker_reset_for_testing();
    chain_linkage_reset_for_testing();
    invariant_sentinel_reset_for_testing();
    return failures;
}
