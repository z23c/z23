// one-result-type-ok:seal-best-effort-semantics
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * seal_service — implementation. See services/seal_service.h.
 *
 * Return types are intentionally bare (void / bool / int), NOT struct
 * zcl_result: the seal is OBSERVE-ONLY and BEST-EFFORT. The candidate hook
 * returns void because a seal failure MUST NOT fail the block (a zcl_result
 * would invite the caller to branch on it — the opposite of the mandate);
 * the emitter returns bool only so direct unit tests can assert success; the
 * ratifier returns the count ratified (0/1). A failure here is logged
 * (LOG_WARN) and dropped, never propagated as a fallible service result.
 *
 * Two entry points host the state-seal lifecycle:
 *   - seal_candidate_emit_in_tx: runs in the utxo_apply step_apply txn at a
 *     grid point G, scans coins_kv, captures the active-chain hash at G, and
 *     inserts a ratified=0 candidate co-committed with the coin mutation.
 *   - seal_ratify_tick: runs on the rolling_anchor 60s tick, promotes the
 *     newest candidate to ratified once it is buried by finality, the input
 *     prefix covers it, and the active chain still holds its block.
 *
 * LOCK ORDER (lock-order law, §4d defect-c): neither path takes csr->lock or
 * touches chain_evidence machinery. The candidate emitter runs entirely on
 * the progress.kv handle (held open by the caller). The block-hash read uses
 * active_chain_at, a LOCK-FREE in-memory chain-index read (the chain[] slot is
 * a never-freed atomic pointer; see validation/chainstate.h) — no lock is
 * acquired here at all. The ratifier opens only its own progress.kv
 * BEGIN IMMEDIATE. */

#include "services/seal_service.h"
#include "services/rolling_anchor_service.h"

#include "platform/time_compat.h"
#include "storage/seal_kv.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "chain/chain.h"
#include "chain/sha3_windows.h"
#include "core/uint256.h"
#include "event/event.h"
#include "json/json.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_logic.h"
#include "validation/main_state.h"
#include "validation/sync_evidence_policy.h"

#include <sqlite3.h>
#include <string.h>
#include <time.h>

static int64_t seal_wall_now_s(void)
{
    struct timespec ts;
    platform_time_realtime_timespec(&ts);
    return (int64_t)ts.tv_sec;
}

bool seal_service_init(struct sqlite3 *db)
{
    if (!db) return false;
    return seal_kv_ensure_schema(db);
}

void seal_candidate_hook_in_tx(struct sqlite3 *db, struct main_state *ms,
                               int32_t next_cursor)
{
    if (!db || !ms) return;
    /* The stage advances one height at a time, so the only grid point a single
     * step can cross is G = next_cursor when it lands on a multiple of 1000. G
     * is the coins_applied_height value, consistent with the cursor convention
     * the ratify gate compares against. The IBD gate keeps the ~1s coins SHA3
     * scan off the cold-sync path. Best-effort — never fails the block. */
    if (next_cursor % (int32_t)SHA3_WINDOW_SIZE != 0) return;
    if (is_initial_block_download(ms)) return;
    (void)seal_candidate_emit_in_tx(db, ms, next_cursor);
}

bool seal_candidate_emit_in_tx(struct sqlite3 *db, struct main_state *ms,
                               int32_t G)
{
    if (!db || !ms) return false;

    struct seal_record r;
    memset(&r, 0, sizeof(r));
    r.height = G;
    r.sealed_at = seal_wall_now_s();

    /* coins_kv_commitment returns 0 on success. The ~1s O(n) SHA3 scan runs
     * INSIDE the caller's stage txn so the seal co-commits with the coins set
     * it commits to — acceptable at this cadence (one grid point per ~41h in
     * steady-state) ONLY because the IBD gate keeps it off the cold-sync path
     * (utxo_apply_stage.c). */
    if (coins_kv_commitment(db, r.coins_sha3) != 0) {
        LOG_WARN("seal", "[seal] candidate commitment failed G=%d", G);
        return false;
    }

    int64_t num_txs = 0;
    if (!coins_kv_setinfo(db, &num_txs, &r.utxo_count, &r.supply)) {
        LOG_WARN("seal", "[seal] candidate setinfo failed G=%d", G);
        return false;
    }

    /* nullifier_sha3 stays all-zero in M1 — the nullifier set is incomplete on
     * every cold-synced datadir (nullifier_kv.h:33-44 ACTIVATION GAP), so it is
     * NOT a ratify gate; the field exists for a future from-genesis tightening. */

    /* block_hash: the active-chain hash at G captures "this seal is for THIS
     * block". active_chain_at is a lock-free in-memory read (chainstate.h). The
     * ratifier later re-checks the active chain STILL holds this hash at G. */
    struct block_index *bi = active_chain_at(&ms->chain_active, (int)G);
    if (bi) memcpy(r.block_hash, bi->hashBlock.data, 32);

    /* anchor_window_sha3 (informational, NOT ratify-gated): the rolling_anchor
     * window ending at G-1 ties the INPUT seal to this OUTPUT seal at the same
     * grid. Best-effort — zero if no such window is committed yet. */
    (void)rolling_anchor_window_hash_ending_at(G - 1, r.anchor_window_sha3);

    if (!seal_kv_insert_candidate_in_tx(db, &r)) {
        LOG_WARN("seal", "[seal] candidate insert failed G=%d", G);
        return false;
    }
    return true;
}

int seal_ratify_tick(struct main_state *ms)
{
    if (!ms) return 0;
    struct sqlite3 *db = progress_store_db();
    if (!db) return 0;

    struct seal_record r;
    bool found = false;
    if (!seal_kv_newest(db, &r, &found)) {
        LOG_WARN("seal", "[seal] ratify: newest read failed");
        return 0;
    }
    if (!found || r.ratified)
        return 0; /* nothing to ratify */

    /* Gate 1 — depth: the tip must have buried G by the finality depth. */
    int tip = active_chain_height(&ms->chain_active);
    if (tip < 0) return 0;
    int immutable = zcl_immutable_height(tip);
    if (immutable < 0 || r.height > immutable)
        return 0; /* candidate too young — normal, waits */

    /* Gate 2 — input coverage: the block bytes that produced this state must
     * themselves be sealed (the rolling_anchor INPUT prefix must cover G). */
    int prefix_end = rolling_anchor_effective_prefix_end();
    if (r.height > prefix_end)
        return 0; /* input prefix not yet sealed past G — normal, waits */

    /* Gate 3 — active-chain agreement: the chain still contains the block this
     * seal was computed against (no reorg replaced G). active_chain_at is a
     * lock-free read. */
    struct block_index *bi = active_chain_at(&ms->chain_active, r.height);
    if (!bi || memcmp(bi->hashBlock.data, r.block_hash, 32) != 0)
        return 0; /* chain moved off the sealed block — wait/supersede */

    /* All gates pass — locate the candidate's slot and ratify it in its own
     * BEGIN IMMEDIATE. */
    struct seal_record at;
    bool at_found = false;
    int slot = -1;
    if (!seal_kv_get_at_height(db, r.height, &at, &at_found, &slot) ||
        !at_found || slot < 0) {
        LOG_WARN("seal", "[seal] ratify: candidate vanished G=%d", r.height);
        return 0;
    }

    progress_store_tx_lock();
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        LOG_WARN("seal", "[seal] ratify: BEGIN failed G=%d", r.height);
        return 0;
    }
    bool ok = seal_kv_mark_ratified_in_tx(db, slot, &at);
#if SEAL_PRUNE_ENABLED
    /* Seal advance IS retention: drop the now-sealed history below G. LANDS
     * DARK in M1 (SEAL_PRUNE_ENABLED == 0) — this branch does not compile, so
     * the first land deletes nothing and proves itself by accumulation. */
    if (ok && !seal_prune_below_in_tx(db, at.height))
        ok = false;
#endif
    if (sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, &err)
            != SQLITE_OK) {
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        LOG_WARN("seal", "[seal] ratify: COMMIT/ROLLBACK failed G=%d", r.height);
        return 0;
    }
    progress_store_tx_unlock();
    if (!ok) {
        LOG_WARN("seal", "[seal] ratify: mark failed G=%d", r.height);
        return 0;
    }

    /* Informational — NOT EV_OPERATOR_NEEDED. A ratified seal is good news. */
    event_emitf(EV_SYNC_STATE_CHANGE, 0,
                "seal ratified G=%d count=%lld", r.height,
                (long long)at.utxo_count);
    return 1;
}

bool seal_dump_state_json(struct json_value *out, const char *key)
{
    return seal_kv_dump_state_json(out, key);
}
