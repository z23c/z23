/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_repair_coin_backfill — orchestration for the guarded frontier coin
 * backfill. Repairs the lowest `prevout_unresolved` reducer hole by
 * re-deriving the missing coin(s) from the raw creating block (hash-verified
 * on the active chain) and inserting them ONLY after the chain-bound
 * no-spend scan (G9, the sibling stage_repair_coin_backfill_scan.c TU)
 * returns CLEAN. Guard ladder G0-G10 (see the per-guard comments below);
 * refusals are whole-set and every refusal status pages directly (typed
 * blocker + EV_OPERATOR_NEEDED, once-latched per (H,holehash,status) — see
 * stage_repair_coin_backfill_util.c).
 *
 * The ONLY consensus mutation is the coins_kv insert transaction
 * (coin_backfill_insert_tx below): no cursor, no *_log row, no
 * coins_applied_height, never tip_finalize_log. */

#include "jobs/stage_repair_coin_backfill.h"
#include "base/format_attribute.h"
#include "stage_repair_coin_backfill_internal.h"
#include "stage_repair_coin_backfill_util.h"

#include "jobs/stage_repair_internal.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "storage/repair_marker.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Chunked scan budget per remedy tick (design §3: ~8k blocks / 1.5 s). */
#define COIN_BACKFILL_SCAN_CHUNK_BLOCKS  8192
#define COIN_BACKFILL_SCAN_CHUNK_WALL_MS 1500

ZCL_PRINTF_LIKE(4, 5)
static bool refuse(struct coin_backfill_result *r,
                   enum coin_backfill_status st,
                   const struct uint256 *hole_hash, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->refuse_reason, sizeof(r->refuse_reason), fmt, ap);
    va_end(ap);
    r->status = st;
    /* The reconcile dry-run re-refuses every ~5 s tick forever on the live
     * default (owner ack unset) — this WARN rides the page latch so it
     * prints once per (H,holehash,status), not per tick. */
    if (coin_backfill_page_refusal(st, r->hole_height, hole_hash,
                                   r->refuse_reason))
        LOG_WARN("coin_backfill",
                 "[coin_backfill] refused h=%d status=%s reason=%s",
                 r->hole_height, coin_backfill_status_name(st),
                 r->refuse_reason);
    return true; /* refusals are a handled outcome, not an infra error */
}

/* The single write transaction (§2 steps 1-8) under the caller's
 * progress_store_tx_lock. Step 1 re-binds the CLEAN scan proof to the
 * insert-time active chain. Returns 1 committed, 0 recheck-failed
 * (rolled back — retry next tick, G10), -1 infra error. Touches NOTHING
 * but coins_kv + progress_meta markers: no cursor, no *_log row, never
 * tip_finalize_log. */
static int coin_backfill_insert_tx(sqlite3 *db,
                                   const struct coin_backfill_io *io,
                                   int hole_height,
                                   const struct uint256 *hole_hash,
                                   const struct coin_backfill_outpoint *set,
                                   int n, int32_t *out_round, char fail[64])
{
    fail[0] = '\0';
    *out_round = 0;

    /* Read the CLEAN scan record BEFORE BEGIN (the load helper is own-tx by
     * contract); the caller's progress_store_tx_lock serializes the window
     * between this read and the COMMIT. */
    struct coin_backfill_scan_record rec;
    bool rec_found = false;
    if (!coin_backfill_scan_record_load(db, hole_height, hole_hash, &rec,
                                        &rec_found))
        LOG_RETURN(-1, "coin_backfill",
                   "[coin_backfill] insert scan record read failed h=%d",
                   hole_height);
    if (!rec_found || !rec.clean) {
        snprintf(fail, 64, "scan_record_not_clean");
        return 0;
    }

    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("coin_backfill",
                 "[coin_backfill] insert BEGIN failed h=%d: %s",
                 hole_height, err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return -1;  // raw-return-ok:begin-failure-logged-above
    }

    int rc = 0;
    do {
        /* 1a + 1b: hole row unchanged AND the ACTIVE block at H still
         * hash-matches it */
        bool row_ok = false;
        if (!coin_backfill_hole_row_matches_unlocked(db, hole_height,
                                                     hole_hash, &row_ok)) {
            rc = -1;
            break;
        }
        if (!row_ok) {
            snprintf(fail, 64, "hole_row_changed");
            break;
        }
        struct block blk;
        struct uint256 got;
        block_init(&blk);
        bool ok = io->read_block(io->user, hole_height, &blk, &got) &&
                  uint256_cmp(&got, hole_hash) == 0;
        block_free(&blk);
        if (!ok) {
            snprintf(fail, 64, "active_hole_hash_mismatch");
            break;
        }
        /* 1c: active hash at scan_top == the CLEAN record's top_hash */
        int scan_top = rec.frontier_at_start - 1;
        block_init(&blk);
        ok = io->read_block(io->user, scan_top, &blk, &got) &&
             memcmp(got.data, rec.top_hash, 32) == 0;
        block_free(&blk);
        if (!ok) {
            snprintf(fail, 64, "scan_top_hash_mismatch h=%d", scan_top);
            break;
        }
        /* 1d: frontier unchanged since the scan started */
        int32_t fr = -1;
        bool found = false;
        if (!coins_kv_get_applied_height(db, &fr, &found)) {
            rc = -1;
            break;
        }
        if (!found || fr != rec.frontier_at_start) {
            snprintf(fail, 64, "frontier_moved %d!=%d", fr,
                     rec.frontier_at_start);
            break;
        }

        int32_t rounds = 0;
        if (!coin_backfill_rounds_read(db, hole_height, hole_hash, &rounds)) {
            rc = -1;
            break;
        }
        char hole_hex[65];
        uint256_get_hex(hole_hash, hole_hex);

        /* steps 2-4: absence check, insert, outpoint-keyed one-shot marker */
        bool step_failed = false;
        for (int k = 0; k < n && !step_failed; k++) {
            if (coins_kv_exists(db, set[k].txid, set[k].vout)) {
                snprintf(fail, 64, "coin_already_present idx=%d", k);
                step_failed = true;
                break;
            }
            if (!coins_kv_add(db, set[k].txid, set[k].vout, set[k].value,
                              set[k].creator_height, set[k].is_coinbase,
                              set[k].script_len ? set[k].script : NULL,
                              set[k].script_len)) {
                LOG_WARN("coin_backfill",
                         "[coin_backfill] coins_kv_add failed idx=%d h=%d",
                         k, hole_height);
                rc = -1;
                step_failed = true;
                break;
            }
            char okey[160], val[128];
            if (!coin_backfill_outpoint_marker_key(okey, set[k].txid,
                                                   set[k].vout)) {
                rc = -1;
                step_failed = true;
                break;
            }
            int m = snprintf(val, sizeof(val), "%d:%s:%d",
                             hole_height, hole_hex, (int)(rounds + 1));
            if (m <= 0 || m >= (int)sizeof(val)) {
                LOG_WARN("coin_backfill",
                         "[coin_backfill] marker value overflow h=%d",
                         hole_height);
                rc = -1;
                step_failed = true;
                break;
            }
            if (!progress_meta_set_in_tx(db, okey, val, (size_t)m)) {
                LOG_WARN("coin_backfill",
                         "[coin_backfill] marker write failed key=%s", okey);
                rc = -1;
                step_failed = true;
                break;
            }
        }
        if (step_failed || fail[0])
            break;

        /* steps 5-7: round counter, scan record delete. STEP 3: the
         * stale-script replay no longer uses a write-once marker (termination is
         * the body-vs-row delta), so there is no replay marker to clear here —
         * once this backfill inserts the missing coin, the next reconcile's
         * dry-run resolves the prevout and the rewind re-derives ok=1. */
        uint8_t le[4];
        coin_backfill_le32_put(le, rounds + 1);
        if (!repair_marker_note_in_tx(db,
                REPAIR_MARKER_KIND_COIN_BACKFILL_ROUNDS, hole_height,
                hole_hash->data, le, sizeof(le)) ||
            !repair_marker_forget_in_tx(db,
                REPAIR_MARKER_KIND_COIN_BACKFILL_SCAN, hole_height,
                hole_hash->data)) {
            LOG_WARN("coin_backfill",
                     "[coin_backfill] round/scan bookkeeping failed h=%d",
                     hole_height);
            rc = -1;
            break;
        }
        if (sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
            LOG_WARN("coin_backfill",
                     "[coin_backfill] insert COMMIT failed h=%d: %s",
                     hole_height, err ? err : "(no message)");
            if (err) sqlite3_free(err);
            rc = -1;
            break;
        }
        *out_round = rounds + 1;
        return 1;
    } while (0);

    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    return rc;
}

/* Core flow: guards G1-G8 re-run on EVERY call (normative contract), the
 * scan (G9) and insert (G10) only when apply=true. Returns false only on
 * infrastructure error. */
static bool backfill_run(sqlite3 *db, struct main_state *ms,
                         const struct coin_backfill_io *io, bool apply,
                         struct coin_backfill_outpoint *set,
                         struct coin_backfill_result *r)
{
    int script_cursor = -1, utxo_cursor = -1, hole_h = -1;
    int32_t frontier = -1;
    bool frontier_found = false, hash_found = false;
    char hole_status[32];
    struct uint256 hole_hash;
    uint256_set_null(&hole_hash);

    progress_store_tx_lock();
    bool ok = stage_repair_cursor_at_unlocked(db, "script_validate",
                                              &script_cursor) &&
              stage_repair_cursor_at_unlocked(db, "utxo_apply",
                                              &utxo_cursor) &&
              coins_kv_get_applied_height(db, &frontier, &frontier_found) &&
              find_lowest_prevout_unresolved_hole_unlocked(
                  db, script_cursor, "prevout_unresolved", &hole_h,
                  hole_status, &hole_hash, &hash_found);
    progress_store_tx_unlock();
    if (!ok)
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] cursor/hole snapshot read failed");

    r->hole_height = hole_h;
    /* G2: repairs the lowest prevout_unresolved hole. internal_error/decode
     * holes (transient / re-attempted) are owned by the separate stale-script
     * replay path, so scanning for prevout_unresolved here means a lower
     * internal_error can no longer mask a higher genuine coin tear. */
    /* Admit hole_h == script_cursor (the STEP-2A frozen-cursor case): when
     * script_validate HOLDS on a prevout_unresolved it does NOT advance, so the
     * held hole sits AT the cursor, not below it. The repair must be able to act
     * on the held outpoint while the cursor is frozen there; a strict `>=` would
     * forever skip the very hole the HOLD is waiting on. hole_h > script_cursor
     * (above the live frontier — not yet a settled verdict) is still skipped. */
    if (hole_h < 0 || script_cursor <= 0 || hole_h > script_cursor)
        return true;
    if (strcmp(hole_status, "prevout_unresolved") != 0)
        return true;

    /* G3: failing block hash-verified on the active chain AND equal to the
     * hole row's own hash (a NULL legacy row cannot bind → refuse) */
    if (!hash_found)
        return refuse(r, COIN_BACKFILL_REFUSED_UNPROVABLE, NULL,
                      "hole_hash_missing");
    struct block blk;
    struct uint256 got;
    block_init(&blk);
    if (!io->read_block(io->user, hole_h, &blk, &got)) {
        block_free(&blk);
        return refuse(r, COIN_BACKFILL_REFUSED_UNPROVABLE, &hole_hash,
                      "hole_block_unreadable");
    }
    if (uint256_cmp(&got, &hole_hash) != 0) {
        block_free(&blk);
        return refuse(r, COIN_BACKFILL_REFUSED_UNPROVABLE, &hole_hash,
                      "hole_hash_mismatch");
    }

    /* G4 */
    if (!frontier_found || frontier < 0) {
        block_free(&blk);
        return refuse(r, COIN_BACKFILL_REFUSED_UNPROVABLE, &hole_hash,
                      "frontier_unknown");
    }
    if (frontier > hole_h) {
        block_free(&blk);
        return refuse(r, COIN_BACKFILL_REFUSED_UNPROVABLE, &hole_hash,
                      "frontier_above_hole f=%d", (int)frontier);
    }
    r->scan_top_height = frontier - 1;

    /* G5: enumeration + outpoint markers + refusal marker + round cap,
     * one consistent locked section */
    int n = 0;
    int32_t rounds = 0;
    char ereason[64];
    char marker_hit[96];
    bool refused_marker = false;
    bool legacy_spent_marker = false;
    bool legacy_txindex_miss_marker = false;
    ereason[0] = '\0';
    marker_hit[0] = '\0';

    progress_store_tx_lock();
    ok = coin_backfill_enumerate_unresolved_prevouts(
        db, &blk, hole_h, frontier, set, &n, ereason);
    if (ok && !ereason[0] && n > 0) {
        for (int k = 0; k < n && ok && !marker_hit[0]; k++) {
            char okey[160];
            bool present = false;
            ok = coin_backfill_outpoint_marker_key(okey, set[k].txid,
                                                   set[k].vout) &&
                 coin_backfill_meta_present(db, okey, &present);
            if (ok && present) {
                char hex[65];
                coin_backfill_txid_hex(set[k].txid, hex);
                snprintf(marker_hit, sizeof(marker_hit),
                         "relost %.16s:%u", hex, set[k].vout);
            }
        }
        if (ok)
            ok = coin_backfill_refusal_marker_read(db, hole_h, &hole_hash,
                                                   &refused_marker,
                                                   &legacy_spent_marker,
                                                   &legacy_txindex_miss_marker);
        if (ok)
            ok = coin_backfill_rounds_read(db, hole_h, &hole_hash, &rounds);
    }
    progress_store_tx_unlock();
    block_free(&blk);
    if (!ok)
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] enumeration/marker read failed h=%d",
                 hole_h);
    if (legacy_spent_marker) {
        if (!repair_marker_forget(db, REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED,
                                  hole_h, hole_hash.data))
            LOG_WARN("coin_backfill",
                     "[coin_backfill] legacy spent marker delete failed h=%d "
                     "(continuing with v2 re-proof)", hole_h);
        else
            LOG_WARN("coin_backfill",
                     "[coin_backfill] ignored legacy spent marker h=%d; "
                     "re-proving with terminal-bound scan", hole_h);
    }
    if (legacy_txindex_miss_marker) {
        if (!repair_marker_forget(db, REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED,
                                  hole_h, hole_hash.data))
            LOG_WARN("coin_backfill",
                     "[coin_backfill] legacy txindex_miss marker delete "
                     "failed h=%d (continuing with v2 re-proof)", hole_h);
        else
            LOG_WARN("coin_backfill",
                     "[coin_backfill] ignored legacy txindex_miss marker h=%d; "
                     "re-proving against active-chain block data", hole_h);
    }

    r->unresolved_count = n;
    if (ereason[0]) {
        /* coin_present_unusable (metadata height tear) / too_many_unresolved
         * are deterministic properties of the hole block — terminal. */
        coin_backfill_persist_terminal_refusal(db, io, hole_h, &hole_hash,
                                 COIN_BACKFILL_TC_TERMINAL,
                                 COIN_BACKFILL_UNPROVABLE_MARKER);
        return refuse(r, COIN_BACKFILL_REFUSED_UNPROVABLE, &hole_hash, "%s",
                      ereason);
    }
    if (n == 0)
        return true; /* all prevouts resolve now → existing replay owns it */
    if (marker_hit[0]) {
        /* A previously-backfilled outpoint lost AGAIN is a proven repeated
         * tear, never retryable. Persist the durable refusal marker the boot
         * torn-gate reads (condition 3), mirroring the unprovable/round_cap
         * terminal persists — otherwise refuse() raises only the in-memory
         * blocker, which is gone after a reboot and the boot gate stays silent. */
        coin_backfill_persist_terminal_refusal(db, io, hole_h, &hole_hash,
                                 COIN_BACKFILL_TC_TERMINAL,
                                 COIN_BACKFILL_RELOST_MARKER);
        return refuse(r, COIN_BACKFILL_MARKER_SEEN, &hole_hash, "%s",
                      marker_hit);
    }
    if (refused_marker)
        return refuse(r, COIN_BACKFILL_REFUSED_SPENT, &hole_hash,
                      "refusal_marker_present");
    if (rounds >= COIN_BACKFILL_MAX_ROUNDS) {
        /* repair exhausted its retry budget for this hole — terminal. */
        coin_backfill_persist_terminal_refusal(db, io, hole_h, &hole_hash,
                                 COIN_BACKFILL_TC_TERMINAL,
                                 COIN_BACKFILL_ROUND_CAP_MARKER);
        return refuse(r, COIN_BACKFILL_REFUSED_UNPROVABLE, &hole_hash,
                      "round_cap rounds=%d", (int)rounds);
    }

    /* G6 owner gate — the refusal already carries owner_ack_missing and the
     * page's escape text names the ack env var; no extra per-tick WARN */
    if (!coin_backfill_owner_ack())
        return refuse(r, COIN_BACKFILL_OWNER_REFUSED, &hole_hash,
                      "owner_ack_missing");

    /* G7 + G8 — the delta-horizon walk (up to 262144 lock-held steps) runs
     * only once the owner gate has passed. The horizon remains observability
     * for old-hole geometry, not a refusal boundary: a creator inside the
     * recent delta window is still safe to re-derive if the active-chain
     * creator proof and terminal-bound no-spend scan both pass. */
    int horizon = -1;
    progress_store_tx_lock();
    ok = utxo_apply_log_contiguous_floor(db, utxo_cursor, &horizon);
    progress_store_tx_unlock();
    if (!ok)
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] delta horizon walk failed h=%d", hole_h);
    if (horizon < 0)
        return refuse(r, COIN_BACKFILL_REFUSED_UNPROVABLE, &hole_hash,
                      "delta_horizon_walk_capped");
    r->delta_horizon = horizon;
    int creator_floor = -1;
    char creason[64];
    enum coin_backfill_terminal_class creator_tc = COIN_BACKFILL_TC_RETRYABLE;
    coin_backfill_resolve_creator(io, hole_h, frontier, horizon, set, n,
                                  &creator_floor, creason, &creator_tc);
    if (creason[0]) {
        /* txindex_miss persists ONLY when txindex is complete (guarded inside
         * the helper); the corrupt creator_* classes persist unconditionally;
         * node_db_unavailable stays RETRYABLE. */
        coin_backfill_persist_terminal_refusal(db, io, hole_h, &hole_hash, creator_tc,
                                 creator_tc ==
                                     COIN_BACKFILL_TC_TERMINAL_IF_TXINDEX_COMPLETE
                                     ? COIN_BACKFILL_TXINDEX_MISS_MARKER_V2
                                     : COIN_BACKFILL_UNPROVABLE_MARKER);
        return refuse(r, COIN_BACKFILL_REFUSED_UNPROVABLE, &hole_hash, "%s",
                      creason);
    }
    r->creator_floor = creator_floor;

    if (!apply) {
        /* detect: enumeration + guards only — no scan, no writes */
        struct coin_backfill_scan_record rec;
        bool rec_found = false;
        r->status = COIN_BACKFILL_SCANNING;
        r->scan_next_height = creator_floor;
        if (coin_backfill_scan_record_load(db, hole_h, &hole_hash, &rec,
                                           &rec_found) && rec_found)
            r->scan_next_height = rec.next_height;
        return true;
    }

    /* G9: chunked resumable chain-bound no-spend scan (scan TU) */
    int next = -1, spent_h = -1;
    uint8_t spender[32] = {0};
    enum coin_backfill_scan_verdict v = coin_backfill_scan_step(
        db, ms, io, hole_h, &hole_hash, set, (size_t)n, creator_floor,
        frontier - 1, frontier, COIN_BACKFILL_SCAN_CHUNK_BLOCKS,
        COIN_BACKFILL_SCAN_CHUNK_WALL_MS, &next, &spent_h, spender);
    r->scan_next_height = next;
    switch (v) {
    case COIN_SCAN_IN_PROGRESS:
        r->status = COIN_BACKFILL_SCANNING;
        LOG_INFO("coin_backfill",
                 "[coin_backfill] scan progress h=%d next_height=%d top=%d "
                 "set=%d", hole_h, next, frontier - 1, n);
        return true;
    case COIN_SCAN_CHAIN_REBOUND:
        coin_backfill_stats_note_rebind();
        r->status = COIN_BACKFILL_SCANNING;
        snprintf(r->refuse_reason, sizeof(r->refuse_reason), "chain_rebound");
        LOG_WARN("coin_backfill",
                 "[coin_backfill] scan chain_rebound h=%d: lineage prev-link "
                 "broke (reorg); restarted from floor=%d", hole_h,
                 creator_floor);
        return true;
    case COIN_SCAN_GAP:
        /* RETRYABLE, NOT terminal: scan_gap fires when a deep block body is
         * simply UNREADABLE (not yet fetched) — it resumes to CLEAN once the
         * body appears (stage_repair_coin_backfill_scan.c:454-468, proven by
         * cb_case_scan_gap). Persisting a durable marker here would latch a
         * transient missing-body into a permanent refusal and BLOCK the resume
         * (the refused_marker check above would then REFUSED_SPENT it). Do NOT
         * persist. (The design's class list mislabeled this; the live scan
         * semantics + the resume test are authoritative.) */
        return refuse(r, COIN_BACKFILL_REFUSED_UNPROVABLE, &hole_hash,
                      "scan_gap h=%d", next);
    case COIN_SCAN_WINDOW_OVER_BUDGET:
        /* TG-F1: the terminal window [frontier..H] must complete in ONE
         * chunk (mid-window checkpoints clamp back to the frontier); a
         * window larger than the budget would pin SCANNING forever. This is
         * a budget artifact, NOT a coin-unprovability verdict — RETRYABLE,
         * so do NOT persist the durable terminal marker. */
        return refuse(r, COIN_BACKFILL_REFUSED_UNPROVABLE, &hole_hash,
                      "terminal_window_exceeds_budget w=%d cap=%d",
                      hole_h - frontier + 1, COIN_BACKFILL_SCAN_CHUNK_BLOCKS);
    case COIN_SCAN_SPENT_FOUND: {
        char shex[65];
        coin_backfill_txid_hex(spender, shex);
        /* refusal marker: a PROVEN spend means the failing block double-
         * spends or local history is torn — never rescan, never guess */
        if (!repair_marker_note(db, REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED,
                                hole_h, hole_hash.data,
                                COIN_BACKFILL_SPENT_MARKER_V2,
                                strlen(COIN_BACKFILL_SPENT_MARKER_V2)))
            LOG_WARN("coin_backfill",
                     "[coin_backfill] refusal marker write failed h=%d "
                     "(refusing anyway)", hole_h);
        return refuse(r, COIN_BACKFILL_REFUSED_SPENT, &hole_hash,
                      "spent h=%d tx=%.16s", spent_h, shex);
    }
    case COIN_SCAN_CLEAN:
        break;
    }

    /* G10: the single write transaction */
    char fail[64];
    int32_t round = 0;
    progress_store_tx_lock();
    int irc = coin_backfill_insert_tx(db, io, hole_h, &hole_hash, set, n,
                                      &round, fail);
    progress_store_tx_unlock();
    if (irc < 0)
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] insert tx infrastructure failure h=%d",
                 hole_h);
    if (irc == 0) {
        /* recheck failed: rolled back, retry next tick (guards + scan
         * record re-validate; a moved frontier restarts the scan) */
        r->status = COIN_BACKFILL_SCANNING;
        snprintf(r->refuse_reason, sizeof(r->refuse_reason),
                 "insert_recheck:%s", fail);
        LOG_WARN("coin_backfill",
                 "[coin_backfill] insert rolled back h=%d (%s); retrying "
                 "next tick", hole_h, fail);
        return true;
    }

    r->status = COIN_BACKFILL_REPAIRED;
    r->inserted_count = n;
    coin_backfill_stats_note_repaired(n);
    for (int k = 0; k < n; k++) {
        char hex[65];
        coin_backfill_txid_hex(set[k].txid, hex);
        LOG_WARN("coin_backfill",
                 "[coin_backfill] inserted outpoint %s:%u value=%lld "
                 "creator=%d coinbase=%d (hole h=%d round=%d)",
                 hex, set[k].vout, (long long)set[k].value,
                 set[k].creator_height, (int)set[k].is_coinbase, hole_h,
                 (int)round);
    }
    LOG_WARN("coin_backfill",
             "[coin_backfill] backfilled %d coin(s) for hole h=%d round=%d; "
             "the next reconcile dry-run can now resolve the prevout and "
             "re-derive ok=1",
             n, hole_h, (int)round);
    return true;
}

bool stage_repair_coin_backfill_try(struct sqlite3 *db, struct main_state *ms,
                                    const struct coin_backfill_io *io,
                                    bool apply,
                                    struct coin_backfill_result *out)
{
    /* G0 — io->ndb is deliberately NOT here: node.db is legitimately absent
     * in unit fixtures and txindex-less runs, and the dispatcher must keep
     * running the OTHER repairs. A real hole that needs creator resolution
     * without ndb refuses as REFUSED_UNPROVABLE in
     * coin_backfill_resolve_creator. */
    if (!db || !ms || !io || !io->read_block || !out)
        LOG_FAIL("coin_backfill",
                 "[coin_backfill] NULL input db=%p ms=%p io=%p out=%p",
                 (void *)db, (void *)ms, (const void *)io, (void *)out);
    memset(out, 0, sizeof(*out));
    out->status = COIN_BACKFILL_NOT_APPLICABLE;
    out->hole_height = -1;
    out->scan_next_height = -1;
    out->scan_top_height = -1;
    out->creator_floor = -1;
    out->delta_horizon = -1;

    /* The U set: ONE heap allocation (~644 KB), never stack — the condition
     * tick runs on the self_heal supervisor thread. */
    struct coin_backfill_outpoint *set = zcl_malloc(
        (size_t)COIN_BACKFILL_MAX_OUTPOINTS * sizeof(*set),
        "coin_backfill_set");
    if (!set)
        LOG_FAIL("coin_backfill", "[coin_backfill] U set allocation failed");

    coin_backfill_stats_note_call();
    bool ok = backfill_run(db, ms, io, apply, set, out);
    free(set);
    coin_backfill_publish_result(out);
    return ok;
}
