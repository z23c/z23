/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Retained reducer-frontier script/proof replay helpers. Deliberately not
 * named stage_repair_*: these paths are retained crash/reorg recovery
 * machinery, not a new repair rung. */

#include "stage_repair_reducer_frontier_internal.h"
#include "reducer_frontier_replay_tx.h"
#include "jobs/reducer_frontier.h"
#include "jobs/script_validate_stage.h"
#include "jobs/stage_repair.h"
#include "jobs/stage_repair_internal.h"
#include "primitives/block.h"
#include "script_validate_log_store.h"
#include "storage/coins_kv.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "storage/repair_marker.h"
#include "core/uint256.h"
#include "event/event.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Body torn-read repair note/quarantine/blocker (lane E3): see
 * reducer_frontier_body_read_note.c; recorded below from the read path. */

/* Lowest failed-row height strictly below `cursor` for `sql` (which takes a
 * single trailing int bind); no hole is success with *out_height == -1.
 * Caller holds the progress_store tx lock. */
bool stage_reducer_frontier_log_hole_below_unlocked(sqlite3 *db,
                                                    const char *sql,
                                                    const char *what,
                                                    int cursor,
                                                    int *out_height)
{
    *out_height = -1;
    if (cursor <= 0)
        return true;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("stage_repair",
                 "[stage_repair] %s hole prepare failed: %s",
                 what, sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int(st, 1, cursor);

    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *out_height = sqlite3_column_int(st, 0);
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "[stage_repair] %s hole step failed rc=%d: %s",
                 what, rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_finalize(st);
    return true;
}

static bool stale_script_hole_unlocked(sqlite3 *db, int cursor,
                                       int *out_height)
{
    return stage_reducer_frontier_log_hole_below_unlocked(db,
        "SELECT height FROM script_validate_log "
        "WHERE ok = 0 "
        "  AND status IN ('internal_error', 'prevout_unresolved', "
        "                 'block_decode_failed') "
        "  AND height < ? "
        "ORDER BY height LIMIT 1",
        "stale script", cursor, out_height);
}

/* Lowest proof_validate_log internal_error row strictly below `cursor`.
 *
 * An internal_error from proof_validate is "could not determine validity"
 * (a transient infra failure — the Groth16/PHGR13/binding-sig verifier could
 * not run), NOT "proof_invalid" (a consensus verdict). It must be re-derived
 * on retry, never persisted as a terminal ok=0. This is the proof-stage twin
 * of stale_script_hole_unlocked, restoring Law-7 symmetry: the healer must not
 * treat "couldn't tell" as "invalid" on EITHER validator stage.
 *
 * Unlike the script hole this filters to status='internal_error' ONLY.
 * proof_validate's other ok=0 statuses are 'proof_invalid' (a genuine
 * consensus reject — keep it terminal) and 'upstream_failed' (owned by the
 * script/upstream rewind, not a proof-stage transient). Caller holds the
 * progress_store tx lock. */
static bool stale_proof_hole_unlocked(sqlite3 *db, int cursor,
                                      int *out_height)
{
    return stage_reducer_frontier_log_hole_below_unlocked(db,
        "SELECT height FROM proof_validate_log "
        "WHERE ok = 0 "
        "  AND status = 'internal_error' "
        "  AND height < ? "
        "ORDER BY height LIMIT 1",
        "stale proof", cursor, out_height);
}

/* Lowest height strictly below `cursor` where validate_headers and
 * script_validate recorded DIFFERENT block hashes (both ok=1, both 32-byte) —
 * the hash_split / validate-script-hash-mismatch class. script_validate passed
 * a NON-canonical body here (its block_hash differs from the canonical header
 * validate_headers re-derived), so apply_hash_agreement (reducer_frontier.c)
 * caps H* at height-1. The script verdict is STALE, not invalid: the cure is
 * the SAME one-shot stale_script_replay_tx (delete the stale script+proof rows,
 * rewind script/proof/tip cursors, re-derive against the canonical active
 * block). The twin detector to stale_script_hole_unlocked, except it matches an
 * ok=1 wrong-hash row instead of an ok=0 status hole. Before this existed the
 * split had NO repair owner: the existing reconcile only rewound the
 * validate_headers cursor (which re-derives the SAME canonical hash and leaves
 * the stale script row untouched), so the split could sit forever as a silent
 * operator-needed wedge. Caller holds the progress_store tx lock. */
static bool stale_script_hash_split_unlocked(sqlite3 *db, int cursor,
                                             int *out_height)
{
    return stage_reducer_frontier_log_hole_below_unlocked(db,
        "SELECT v.height FROM validate_headers_log v "
        "JOIN script_validate_log s ON s.height = v.height "
        "WHERE v.height < ? AND v.ok = 1 AND s.ok = 1 "
        "  AND length(v.hash) = 32 AND length(s.block_hash) = 32 "
        "  AND v.hash <> s.block_hash "
        "ORDER BY v.height LIMIT 1",
        "validate-script hash split", cursor, out_height);
}

/* Detector signature shared by the ok=0 stale-script-hole path, the ok=1
 * hash-split path and the row-ABSENT rowless-hole path so
 * maybe_replay_stale_script_via runs ONE body for all three. Declared in the
 * internal header (the absent-hole match lives in the dispatch TU). */

bool stage_repair_read_active_block_checked(struct main_state *ms, int height,
                                            struct block *blk,
                                            struct uint256 *block_hash)
{
    if (!ms || !blk || !block_hash)
        LOG_FAIL("stage_repair", "read_active_block_checked: NULL input");

    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    bool have = false;

    zcl_mutex_lock(&ms->cs_main);
    struct block_index *bi = active_chain_at(&ms->chain_active, height);
    if (bi && bi->phashBlock && (bi->nStatus & BLOCK_HAVE_DATA) &&
        bi->nFile >= 0) {
        *block_hash = *bi->phashBlock;
        pos.nFile = bi->nFile;
        pos.nPos = bi->nDataPos;
        have = true;
    }
    zcl_mutex_unlock(&ms->cs_main);

    if (!have) {
        LOG_WARN("stage_repair",
                 "[stage_repair] read_active_block_checked: h=%d not readable "
                 "from active chain (missing entry / no BLOCK_HAVE_DATA / no "
                 "file) — repair defers", height);
        return false;
    }

    char datadir[2048];
    GetDataDir(true, datadir, sizeof(datadir));
    struct reducer_frontier_body_read_note note_before_read;
    bool had_note = reducer_frontier_body_read_note_snapshot(
        &note_before_read);
    if (!read_block_from_disk_pread(blk, &pos, datadir)) {
        /* Arm the off-lock HAVE_DATA drop + peer refetch (lane E3) — not a
         * side-channel write under the caller's progress lock. */
        reducer_frontier_body_read_note_record(
            height, pos.nFile, (int64_t)pos.nPos,
            REDUCER_FRONTIER_BODY_READ_DISK, block_hash);
        LOG_WARN("stage_repair",
                 "[stage_repair] read_active_block_checked: disk read failed "
                 "h=%d (nFile=%d pos=%d) — HAVE_DATA drop + refetch armed",
                 height, pos.nFile, pos.nPos);
        return false;
    }

    struct uint256 got;
    block_get_hash(blk, &got);
    if (uint256_cmp(&got, block_hash) != 0) {
        char want_hex[65];
        char got_hex[65];
        uint256_get_hex(block_hash, want_hex);
        uint256_get_hex(&got, got_hex);
        /* Wrong block under HAVE_DATA: same route as a torn read (lane E3). */
        reducer_frontier_body_read_note_record(
            height, pos.nFile, (int64_t)pos.nPos,
            REDUCER_FRONTIER_BODY_READ_WRONG, block_hash);
        LOG_WARN("stage_repair",
                 "[stage_repair] repair read wrong block h=%d want=%s got=%s "
                 "— HAVE_DATA drop + refetch armed",
                 height, want_hex, got_hex);
        return false;
    }
    /* Read + hash-verified: retire any stale torn-read note (+ blocker). */
    if (had_note && note_before_read.height == height &&
        uint256_eq(&note_before_read.block_hash, block_hash))
        (void)reducer_frontier_body_read_note_clear_if(&note_before_read);
    return true;
}

/* In-memory canonical active HEADER hash at `height` — phashBlock of the
 * active-chain block_index, NO disk read, NO BLOCK_HAVE_DATA gate. Used to
 * DISCRIMINATE a validate/script hash_split (which stored hash matches the
 * most-work header chain) without depending on whether the canonical BODY is
 * on disk; routing must never stall on a not-yet-fetched body. Returns false
 * only when the active chain has no entry / no phashBlock at `height`. */
static bool stage_repair_active_header_hash(struct main_state *ms, int height,
                                            struct uint256 *out_hash)
{
    if (!ms || !out_hash)
        return false;
    bool have = false;
    zcl_mutex_lock(&ms->cs_main);
    struct block_index *bi = active_chain_at(&ms->chain_active, height);
    if (bi && bi->phashBlock) {
        *out_hash = *bi->phashBlock;
        have = true;
    }
    zcl_mutex_unlock(&ms->cs_main);
    return have;
}

enum rf_hash_split_side stage_repair_classify_hash_split(
    struct main_state *ms, sqlite3 *db, int height, bool *out_err)
{
    if (out_err)
        *out_err = false;
    if (!ms || !db || height < 0)
        return RF_SPLIT_INDETERMINATE;

    uint8_t vh_hash[32];
    uint8_t sv_hash[32];
    bool vh_found = false;
    bool sv_found = false;
    if (!reducer_frontier_log_hash_at(db, "validate_headers_log", "hash",
                                      height, vh_hash, &vh_found) ||
        !reducer_frontier_log_hash_at(db, "script_validate_log", "block_hash",
                                      height, sv_hash, &sv_found)) {
        if (out_err)
            *out_err = true;
        return RF_SPLIT_INDETERMINATE;
    }

    struct uint256 active_hash;
    if (!stage_repair_active_header_hash(ms, height, &active_hash) ||
        !vh_found || !sv_found)
        return RF_SPLIT_INDETERMINATE;

    bool vh_eq_active = memcmp(vh_hash, active_hash.data, 32) == 0;
    bool sv_eq_active = memcmp(sv_hash, active_hash.data, 32) == 0;
    /* A genuine stale HEADER: validate disagrees with the canonical active
     * header while script already matches it. Anything else with script !=
     * active (incl. both-stale) is the dual replay's. */
    if (!vh_eq_active && sv_eq_active)
        return RF_SPLIT_VALIDATE_SIDE;
    return RF_SPLIT_SCRIPT_SIDE;
}

/* Shared body for the two stale-script replay paths. `detect` picks the lowest
 * height to re-derive (an ok=0 status hole, or an ok=1 hash split).
 * `rewind_headers` is true ONLY for the hash-split path: it additionally drops
 * the validate_headers verdict over the replay span so both validators re-derive
 * the hash from the SAME canonical body. Termination is by the body-vs-row delta
 * (STEP 3) — there is NO write-once marker; the rewind + STEP-1's dry==real
 * guarantee make each pass end as progress (rewind/rewrite) XOR named
 * escalation. */
bool maybe_replay_stale_script_via(
    sqlite3 *db,
    struct main_state *ms,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out,
    stale_script_detector_fn detect,
    bool rewind_headers)
{
    int script_cursor = -1;
    int proof_cursor = -1;
    int utxo_cursor = -1;
    int tip_cursor = -1;
    int body_cursor = -1;
    int height = -1;
    int32_t coins_frontier = -1;
    bool coins_found = false;

    /* Held from this snapshot through stale_script_replay_tx's COMMIT: the
     * rewind below is keyed to these cursors, and a drain advancing
     * utxo_apply/coins in an unlock gap would commit a stale rewind that
     * re-tears coins vs frontier. The one disk block read this covers is a
     * bounded hash-checked pread; the dry-run already reads blocks under
     * this lock. */
    progress_store_tx_lock();
    bool ok = stage_repair_cursor_at_unlocked(db, "script_validate",
                                              &script_cursor) &&
              stage_repair_cursor_at_unlocked(db, "proof_validate",
                                              &proof_cursor) &&
              stage_repair_cursor_at_unlocked(db, "utxo_apply",
                                              &utxo_cursor) &&
              stage_repair_cursor_at_unlocked(db, "tip_finalize",
                                              &tip_cursor) &&
              stage_repair_cursor_at_unlocked(db, "body_persist",
                                              &body_cursor) &&
              coins_kv_get_applied_height(db, &coins_frontier,
                                           &coins_found) &&
              detect(db, script_cursor, &height);
    if (!ok) {
        progress_store_tx_unlock();
        return false;
    }

    int replay_first = (coins_found && coins_frontier >= 0 &&
                        coins_frontier < height)
                           ? coins_frontier
                           : height;
    out->stale_script_repair_height = height;
    out->stale_script_cursor_before = script_cursor;
    out->stale_script_cursor_after = script_cursor;
    out->stale_script_utxo_cursor_before = utxo_cursor;
    out->stale_script_tip_cursor_before = tip_cursor;
    out->stale_script_backfill_first = replay_first;
    out->stale_script_backfill_last = body_cursor > 0 ? body_cursor - 1 : -1;
    if (height < 0 || script_cursor <= 0 || height >= script_cursor ||
        proof_cursor <= height || body_cursor <= height || !coins_found) {
        progress_store_tx_unlock();
        return true;
    }
    if (!apply) {
        /* PROBE: signal the reconcile_light condition that a stale-script hole
         * is present so detect fires (reducer_frontier_reconcile_light.c reads
         * rr.repaired). The real body-vs-row delta runs below in apply mode;
         * a genuinely-invalid / irreducible hole is resolved there (rewrite /
         * named escalation), never by this probe. */
        out->repaired = true;
        progress_store_tx_unlock();
        return true;
    }

    struct block blk;
    struct uint256 block_hash;
    block_init(&blk);
    if (!stage_repair_read_active_block_checked(ms, height, &blk,
                                                &block_hash)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] stale script repair refused: cannot read "
                 "canonical block h=%d",
                 height);
        progress_store_tx_unlock();
        block_free(&blk);
        return true;
    }

    out->stale_script_repair_attempted = true;

    /* STEP 1 + STEP 3 — the body-vs-row DELTA. Re-derive the verdict against the
     * canonical body via the SAME public dry-run the real fold uses (so dry.ok
     * PROVABLY implies the real fold writes ok=1). Three outcomes, each
     * self-terminating with NO write-once marker:
     *   - dry.ok               -> the stored ok=0 / wrong-hash row is stale: rewind
     *                             (delete + cursor-rewind) so the forward re-fold
     *                             writes ok=1; the detector stops matching at once.
     *   - genuinely invalid    -> rewrite the row to the terminal genuine reject
     *                             (status='script_invalid', ok=0) so the transient
     *                             detector stops matching; a real reject stays real.
     *   - irreducibly undeter- -> NAME one permanent blocker + page the operator;
     *     mined (internal_err)    no churn, no silent skip. */
    struct script_validate_dry_run_report dry;
    int backfill_top = body_cursor - 1;
    if (!reducer_frontier_replay_dry_run_stale_script(
            db, ms, height, replay_first, utxo_cursor, backfill_top, &blk,
            &dry)) {
        progress_store_tx_unlock();
        block_free(&blk);
        return false;
    }
    if (!dry.ok && !dry.internal_error) {
        /* The body genuinely fails script verification. Record the terminal
         * genuine verdict (the SAME ok=0 'script_invalid' row the real fold
         * would write) so the transient-class detector stops matching and the
         * reject stays a real reject — consensus verdict unchanged. */
        out->stale_script_repair_genuinely_invalid = true;
        bool wrote = script_validate_log_insert(
            db, height, "script_invalid", false, dry.tx_count, dry.input_count,
            &dry.first_failure_txid, dry.first_failure_vin,
            dry.first_failure_serror, &block_hash);
        progress_store_tx_unlock();
        block_free(&blk);
        if (!wrote)
            LOG_RETURN(false, "stage_repair",
                       "[stage_repair] stale script repair: failed to record "
                       "terminal genuine reject h=%d", height);
        LOG_WARN("stage_repair",
                 "[stage_repair] stale script repair: H genuinely invalid "
                 "height=%d status=%s — recorded terminal script_invalid",
                 height, dry.status);
        return true;
    }
    if (!dry.ok && dry.internal_error) {
        /* The body still cannot be re-derived (prevout truly missing / body
         * undecodable) even after backfill: this is an IRREDUCIBLE blocker, not
         * a retryable transient (STEP 2A holds genuine transients at the stage,
         * so a row that reaches the repair as internal_error is stuck). Name it
         * and page the operator ONCE — never a silent skip, never a rewind that
         * cannot make progress. */
        char txhex[65];
        uint256_get_hex(&dry.first_failure_txid, txhex);
        char reason[BLOCKER_REASON_MAX];
        snprintf(reason, sizeof(reason),
                 "stale script hole height=%d %s: body could not be re-derived "
                 "(tx=%s vin=%d) — H* cannot advance",
                 height, dry.status, txhex, dry.first_failure_vin);
        struct blocker_record b;
        if (blocker_init(&b, "reducer_frontier.script_undetermined",
                         "stage_repair", BLOCKER_PERMANENT, reason)) {
            b.retry_budget = -1;
            if (blocker_set(&b) == 0) /* fresh (not rate-limited) -> page once */
                event_emitf(EV_OPERATOR_NEEDED, 0,
                            "reducer_frontier script_undetermined height=%d "
                            "tx=%s vin=%d status=%s",
                            height, txhex, dry.first_failure_vin, dry.status);
        }
        out->stale_script_repair_genuinely_invalid = false;
        progress_store_tx_unlock();
        block_free(&blk);
        LOG_WARN("stage_repair",
                 "[stage_repair] stale script repair: irreducible "
                 "internal_error height=%d status=%s — named blocker + "
                 "operator paged",
                 height, dry.status);
        return true;
    }

    ok = reducer_frontier_replay_stale_script_tx(
        db, ms, height, replay_first, script_cursor, proof_cursor,
        utxo_cursor, tip_cursor, backfill_top, rewind_headers);
    progress_store_tx_unlock();
    block_free(&blk);
    if (!ok)
        return false;
    /* Wave A2 (D4): created_outputs backfill (TX2) on the projection store,
     * after the kernel lock release (LOCK ORDER LAW); best-effort. */
    (void)reducer_frontier_replay_backfill_created_outputs_projection(
        ms, replay_first, backfill_top);
    out->stale_script_repaired = true;
    out->stale_script_cursor_after = replay_first;
    out->refused_coin_tear = false;
    out->repaired = true;
    LOG_WARN("stage_repair", "[stage_repair] stale script rewound to h=%d "
             "(hole h=%d; co %d..%d)", replay_first, height, replay_first,
             backfill_top);
    return true;
}

/* ok=0 status hole (internal_error / prevout_unresolved / block_decode_failed):
 * a "couldn't determine validity" verdict frozen as terminal — re-derive it. */
bool stage_reducer_frontier_try_stale_script_replay(
    sqlite3 *db,
    struct main_state *ms,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    return maybe_replay_stale_script_via(db, ms, apply, out,
                                         stale_script_hole_unlocked,
                                         /*rewind_headers=*/false);
}

/* ok=1 hash split (validate_headers.hash != script_validate.block_hash): a stale
 * script verdict for a NON-canonical body that caps H* with no other repair
 * owner. Re-derive against the canonical active block so the split clears and
 * H* climbs. The body-vs-row delta makes it auto-terminating WITHOUT a marker:
 * the rewind (STEP 3, rewind_headers=true) drops the stale validate_headers AND
 * script_validate verdicts over the span so both re-derive from the SAME
 * canonical body (v.hash==s.block_hash by construction); the condition re-polls
 * every tick so a not-yet-fetched canonical body just retries, never wedges. */
bool stage_reducer_frontier_try_validate_script_hash_split_replay(
    sqlite3 *db,
    struct main_state *ms,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    /* Probe + DISCRIMINATE before descending into the shared body. Two reasons:
     * (1) maybe_replay_stale_script_via shares the out->stale_script_* result
     *     fields with the ok=0 stale-script step earlier in the ladder; a pass
     *     that does not own a repair here must not overwrite a stale-script hole
     *     that step already reported into *out.
     * (2) This is the SCRIPT-side cure. A split (validate_headers.hash !=
     *     script_validate.block_hash) is owned by the coins-rewinding DUAL
     *     replay by DEFAULT: rewind_headers=true drops BOTH the validate_headers
     *     AND script verdicts over the span so both re-derive from the SAME
     *     canonical body (v.hash == s.block_hash by construction). The routing
     *     decision is HASH-ONLY (the most-work header verdict + the in-memory
     *     active header) and must NOT gate on body-readability: when the coins
     *     writer leads H*, active_chain_at(H) still references the very block
     *     script validated, so the old active_chain_at == sv_hash test
     *     mis-classified a script-side split as validate-side and the script
     *     verdict was never re-derived (livelock). The ONLY validate-side
     *     early-out is a GENUINE stale header (validate_headers != active header
     *     AND script == active header); there the validate-cursor rewind in
     *     reconcile_refill_cursors re-derives the authoritative header. */
    int split_height = -1;
    int script_cursor = -1;
    progress_store_tx_lock();
    bool ok = stage_repair_cursor_at_unlocked(db, "script_validate",
                                              &script_cursor) &&
              stale_script_hash_split_unlocked(db, script_cursor,
                                               &split_height);
    progress_store_tx_unlock();
    if (!ok)
        return false;
    if (split_height < 0)
        return true; /* no split — leave *out untouched */

    if (out && out->stale_script_repair_height >= 0 &&
        out->stale_script_repair_height <= split_height) {
        /* The ok=0 stale-script replay step earlier in the dispatch ladder
         * already reported an equal/lower owner into the shared stale_script_*
         * result fields. Do not let a later hash-split probe overwrite the
         * next height the replay ladder must address first. */
        return true;
    }

    /* HASH-ONLY discrimination (no body-readability gate). Default: the dual
     * replay owns the split; ONLY a genuine stale header (RF_SPLIT_VALIDATE_SIDE)
     * is left to the validate-cursor clamp. INDETERMINATE (active header
     * unavailable) routes to the replay, whose dry-run names a blocker if the
     * body is absent — never a silent skip. A DB read error fails closed. */
    bool classify_err = false;
    if (stage_repair_classify_hash_split(ms, db, split_height, &classify_err) ==
            RF_SPLIT_VALIDATE_SIDE)
        return true; /* genuine stale header — validate-cursor clamp owns it */
    if (classify_err)
        return false;

    return maybe_replay_stale_script_via(db, ms, apply, out,
                                         stale_script_hash_split_unlocked,
                                         /*rewind_headers=*/true);
}

/* Core proof internal_error one-shot rewind, parameterized by the block_hash
 * used for the marker key. Holds the progress lock across the snapshot and the
 * rewind COMMIT (same contract as maybe_replay_stale_script_via: a drain
 * advancing utxo_apply/coins in an unlock gap would commit a stale rewind).
 * Detects the lowest proof-only internal_error hole (script ok=1 there),
 * confirms it is not already owned by an upstream/script hole, and — unless
 * the one-shot marker is present — drops the proof verdict(s) so proof_validate
 * re-derives them. Sets out->stale_script_* fields (the heal is symmetric; the
 * result surface is shared). *out_repaired / *out_height report the witness for
 * tests. */
static bool replay_stale_proof_core(
    sqlite3 *db,
    bool apply,
    const struct uint256 *block_hash,
    struct stage_reducer_frontier_reconcile_result *out,
    bool *out_repaired,
    int *out_height)
{
    int script_cursor = -1;
    int proof_cursor = -1;
    int utxo_cursor = -1;
    int height = -1;
    int script_ok = -1;

    progress_store_tx_lock();
    bool ok = stage_repair_cursor_at_unlocked(db, "script_validate",
                                              &script_cursor) &&
              stage_repair_cursor_at_unlocked(db, "proof_validate",
                                              &proof_cursor) &&
              stage_repair_cursor_at_unlocked(db, "utxo_apply",
                                              &utxo_cursor) &&
              stale_proof_hole_unlocked(db, proof_cursor, &height);
    if (!ok) {
        progress_store_tx_unlock();
        return false;
    }

    if (out_height) *out_height = height;
    if (out) {
        out->stale_script_repair_height = height;
        out->stale_script_cursor_before = proof_cursor;
        out->stale_script_cursor_after = proof_cursor;
        out->stale_script_utxo_cursor_before = utxo_cursor;
    }

    /* No transient proof hole, or it sits at/above the cursor: nothing to do.
     * Also require script PASSED at the hole — a script hole at the same
     * height is the script path's domain (it deletes proof_validate_log down
     * to its own replay_first in the same tx), so the proof path must not
     * double-own it. script_validate must have advanced past the hole too. */
    if (height < 0 || proof_cursor <= 0 || height >= proof_cursor ||
        script_cursor <= height) {
        progress_store_tx_unlock();
        return true;
    }
    if (!reducer_frontier_replay_script_ok_at_unlocked(
            db, height, &script_ok)) {
        progress_store_tx_unlock();
        return false;
    }
    if (script_ok != 1) {
        /* script failed / has no verdict at the hole: the script-stage rewind
         * owns this height. Leave it to stage_reducer_frontier_try_stale_script_replay. */
        progress_store_tx_unlock();
        return true;
    }

    if (out) out->stale_script_repair_attempted = true;
    if (!apply) {
        if (out) out->repaired = true;
        if (out_repaired) *out_repaired = true;
        progress_store_tx_unlock();
        return true;
    }

    /* A proof verdict gates no coin SET (utxo_apply is the state transition;
     * proofs only authorize shielded value). A transient proof internal_error
     * should leave utxo_apply pinned at the hole, so replay_first == height
     * with no coins rewind in the common case; the rewind logic below still
     * handles utxo_cursor > height defensively (identical to the script path). */
    int replay_first = height;

    bool marker_seen = false;
    if (!stage_reducer_frontier_repair_marker_seen(
            db, REPAIR_MARKER_KIND_RF_PROOF_REPLAY, height, block_hash,
            "stale proof", &marker_seen)) {
        progress_store_tx_unlock();
        return false;
    }
    if (marker_seen) {
        if (out) out->stale_script_repair_marker_seen = true;
        LOG_WARN("stage_repair",
                 "[stage_repair] stale proof repair skipped h=%d: "
                 "one-shot marker already present",
                 height);
        progress_store_tx_unlock();
        return true;
    }

    ok = reducer_frontier_replay_stale_proof_tx(
        db, height, replay_first, proof_cursor, utxo_cursor, block_hash);
    progress_store_tx_unlock();
    if (!ok)
        return false;

    if (out) {
        out->stale_script_repaired = true;
        out->stale_script_cursor_after = replay_first;
        out->refused_coin_tear = false;
        out->repaired = true;
    }
    if (out_repaired) *out_repaired = true;
    LOG_WARN("stage_repair",
             "[stage_repair] stale proof repair rewound proof/utxo/tip cursors "
             "to h=%d for transient proof internal_error hole h=%d "
             "(proof=%d utxo=%d) — one-shot re-validation",
             replay_first, height, proof_cursor, utxo_cursor);
    return true;
}

/* Production proof internal_error symmetry: read the canonical block at the
 * hole (for the reorg-bound marker hash) and run the one-shot rewind. */
bool stage_reducer_frontier_try_stale_proof_replay(
    sqlite3 *db,
    struct main_state *ms,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    /* Peek the hole height first (lock-free read is fine for the marker block
     * read; replay_stale_proof_core re-snapshots under the lock and is
     * authoritative). */
    int proof_cursor = -1;
    int height = -1;
    progress_store_tx_lock();
    bool ok = stage_repair_cursor_at_unlocked(db, "proof_validate",
                                              &proof_cursor) &&
              stale_proof_hole_unlocked(db, proof_cursor, &height);
    progress_store_tx_unlock();
    if (!ok)
        return false;
    if (height < 0 || proof_cursor <= 0 || height >= proof_cursor)
        return true;

    struct block blk;
    struct uint256 block_hash;
    block_init(&blk);
    if (!stage_repair_read_active_block_checked(ms, height, &blk,
                                                &block_hash)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] stale proof repair refused: cannot read "
                 "canonical block h=%d",
                 height);
        block_free(&blk);
        return true;
    }
    block_free(&blk);

    return replay_stale_proof_core(db, apply, &block_hash, out, NULL, NULL);
}

#ifdef ZCL_TESTING
bool stage_repair_proof_internal_error_rewind_for_testing(
    sqlite3 *db, bool *repaired, int *out_height)
{
    if (repaired) *repaired = false;
    if (out_height) *out_height = -1;
    struct uint256 zero_hash;
    memset(&zero_hash, 0, sizeof(zero_hash));
    return replay_stale_proof_core(db, /*apply=*/true, &zero_hash, NULL,
                                   repaired, out_height);
}

/* Test-only detect for the hash_split class: returns the lowest height (below
 * the script_validate cursor) where validate_headers and script_validate
 * recorded different block hashes, or -1 if none. Pure progress-store read. */
bool stage_repair_validate_script_hash_split_detect_for_testing(
    sqlite3 *db, int *out_height)
{
    if (out_height) *out_height = -1;
    progress_store_tx_lock();
    int script_cursor = -1, height = -1;
    bool ok = stage_repair_cursor_at_unlocked(db, "script_validate",
                                              &script_cursor) &&
              stale_script_hash_split_unlocked(db, script_cursor, &height);
    progress_store_tx_unlock();
    if (ok && out_height)
        *out_height = height;
    return ok;
}

/* Test-only witness for the hash_split repair. Detects the lowest split, then
 * applies the coins-NOT-advanced subset of stale_script_replay_tx: delete the
 * stale script+proof verdicts at/above the split and rewind script/proof/tip so
 * the forward stages re-derive against the canonical body. Pure progress-store
 * ops (no main_state, no disk block read, no coins rewind) — production uses
 * the full replay_tx with the block-read dry-run + coins/backfill safety. STEP
 * 3: marker-free — the rewind deletes the split row and rewinds the cursor, so
 * a second call's detector finds no split and is a clean no-op (termination is
 * the body-vs-row delta). Returns false only on a store error; *repaired /
 * *out_height report whether and where a rewind fired. */
bool stage_repair_validate_script_hash_split_rewind_for_testing(
    sqlite3 *db, bool *repaired, int *out_height)
{
    if (repaired) *repaired = false;
    if (out_height) *out_height = -1;

    progress_store_tx_lock();
    int script_cursor = -1, proof_cursor = -1, tip_cursor = -1, height = -1;
    bool ok = stage_repair_cursor_at_unlocked(db, "script_validate",
                                              &script_cursor) &&
              stage_repair_cursor_at_unlocked(db, "proof_validate",
                                              &proof_cursor) &&
              stage_repair_cursor_at_unlocked(db, "tip_finalize",
                                              &tip_cursor) &&
              stale_script_hash_split_unlocked(db, script_cursor, &height);
    if (!ok) {
        progress_store_tx_unlock();
        return false;
    }
    if (height < 0) {
        progress_store_tx_unlock();
        return true; /* no split: success no-op */
    }

    /* STEP 3: marker-free. The rewind deletes the split row and rewinds the
     * cursor, so a SECOND call's detector finds no split (both ok=1 wrong-hash
     * rows are gone) and is a clean no-op — termination is by the body-vs-row
     * delta, not a one-shot guard. */
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        return false;
    }
    if (!reducer_frontier_replay_delete_log_range(
            db, "script_validate_log", height, script_cursor) ||
        !reducer_frontier_replay_delete_log_range(
            db, "proof_validate_log", height, proof_cursor) ||
        !stage_repair_force_stage_cursor(db, "script_validate", height) ||
        !stage_repair_force_stage_cursor(db, "proof_validate", height) ||
        !stage_repair_force_stage_cursor(db, "tip_finalize", height)) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        return false;
    }
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        return false;
    }
    progress_store_tx_unlock();

    if (repaired) *repaired = true;
    if (out_height) *out_height = height;
    return true;
}
#endif
