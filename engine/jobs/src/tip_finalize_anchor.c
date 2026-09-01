/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_finalize_anchor — trusted anchor/seed cursor alignment for the
 * tip_finalize stage, extracted from tip_finalize_stage.c (E1 file-size
 * ceiling). See tip_finalize_anchor_internal.h for the cross-TU seam.
 *
 * Both jump sites here are FIX-3 guarded: a trusted re-anchor or seed may
 * only advance the finalize cursor across heights its own tip_finalize_log
 * covers (stage_anchor_cap_target_at_log_frontier) — cursor jumps past
 * rowless heights are the manufacturing site of the log-hole wedge class.
 * The seed exemption is ALWAYS a pre-insert verdict: both sites write the
 * anchor row before the cursor write, so a post-insert "log empty" probe
 * can never be true (see stage_anchor.h, prong 2). */

#include "jobs/tip_finalize_stage.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_anchor.h"
#include "jobs/stage_helpers.h"
#include "tip_finalize_anchor_internal.h"
#include "tip_finalize_log_store.h"
#include "utxo_apply_log_store.h"
#include "jobs/stage_row_itag.h"

#include "config/runtime.h"
#include "core/uint256.h"
#include "services/invariant_sentinel.h"
#include "services/seed_integrity_gate.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "util/stage.h"
#include "platform/time_compat.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

#define STAGE_NAME "tip_finalize"

static bool ensure_authority_anchor_row(sqlite3 *db, int height,
                                        const uint8_t hash[32])
{
    struct finalized_tip_row row;
    if (!finalized_tip_row_at(db, height, &row))
        return false;
    if (row.found && row.ok && row.has_tip_hash &&
        memcmp(row.tip_hash.data, hash, 32) == 0)
        return true;
    /* Never downgrade a finalized ok=1 row into an anchor row. The
     * finalized row at `height` proves the height→height+1 transition and
     * carries the SUCCESSOR's hash (the only durable source
     * tip_finalize_stage_block_hash_at has for height+1's own hash); a
     * stale authority re-commit of tip `height` adds no information — the
     * pair (height, hash(height)) is already derivable from the finalized
     * row at height-1. log_insert is INSERT OR REPLACE, so without this
     * guard the richer row would be destroyed. */
    if (row.found && row.ok && !row.is_anchor)
        return true;

    struct uint256 tip_hash;
    memcpy(tip_hash.data, hash, 32);
    return log_insert(db, height, "anchor", true, NULL, 0, 0, &tip_hash);
}

static bool authority_coin_frontier_allows(sqlite3 *db, int height,
                                           const char *reason, bool *allowed)
{
    if (!allowed) {
        LOG_WARN("tip_finalize",
                 "[tip_finalize] authority anchor coin-frontier guard missing "
                 "out param h=%d reason=%s",
                 height, reason ? reason : "");
        return false;
    }
    *allowed = true;
    if (!db || height < 0)
        return true;

    int32_t applied = -1;
    bool found = false;
    if (!coins_kv_get_applied_height(db, &applied, &found)) {
        /* De-stormed: a persistent read fault re-fires every reducer pass
         * until it clears. */
        static struct log_throttle coin_frontier_read_throttle =
            LOG_THROTTLE_INIT;
        int64_t now = platform_time_wall_unix();
        uint64_t reps = 0;
        if (log_throttle_should_emit(&coin_frontier_read_throttle, 1, now,
                                      300, &reps))
            LOG_WARN("tip_finalize",
                     "[tip_finalize] authority anchor coin-frontier read "
                     "failed h=%d reason=%s repeated=%llu",
                     height, reason ? reason : "", (unsigned long long)reps);
        return false;
    }
    if (!found)
        return true;  /* legacy/pre-coins-kv datadir: do not change behavior */

    /* coins_applied_height is the NEXT height to apply. A served tip at H
     * requires coins applied through H, i.e. applied >= H+1. */
    if (applied > height)
        return true;

    {
        /* De-stormed: coins lagging finalize can persist across many
         * reducer passes during catchup, re-hitting the same (height,
         * applied) pair every tick until coins catch up. */
        static struct log_throttle anchor_skipped_throttle = LOG_THROTTLE_INIT;
        uint64_t key = ((uint64_t)(uint32_t)height << 32) | (uint32_t)applied;
        int64_t now = platform_time_wall_unix();
        uint64_t reps = 0;
        if (log_throttle_should_emit(&anchor_skipped_throttle, key, now, 300,
                                      &reps))
            LOG_WARN("tip_finalize",
                     "[tip_finalize] authority anchor skipped h=%d "
                     "coins_applied_height=%d reason=%s (finalized>coins) "
                     "repeated=%llu",
                     height, applied, reason ? reason : "",
                     (unsigned long long)reps);
    }
    *allowed = false;
    return true;
}

bool tip_finalize_anchor_cursor_to_authority(sqlite3 *db, int height,
                                             const uint8_t hash[32],
                                             bool anchor_upstream,
                                             bool require_prior_progress,
                                             const char *reason)
{
    stage_t *stage = tip_finalize_stage_handle();
    if (!db || !stage || height < 0 || !hash)
        return true;

    /* Fail-loud validation pack, check 3(c): the (height, hash) authority
     * pair must self-resolve in the blocks projection before it is
     * persisted as the finalize anchor. An unknown hash passes; a hash the
     * projection resolves to a DIFFERENT height is exactly the published-
     * pair poison the splice class rode in on — refuse the write. */
    if (!invariant_sentinel_check_pair(app_runtime_node_db(), hash, height,
                                       "tip_finalize_anchor")) {
        LOG_WARN("tip_finalize",
                 "[tip_finalize] authority anchor REFUSED h=%d reason=%s "
                 "(pair self-check)", height, reason ? reason : "");
        return false;
    }
    bool coin_allowed = true;
    if (!authority_coin_frontier_allows(db, height, reason, &coin_allowed)) {
        LOG_WARN("tip_finalize",
                 "[tip_finalize] authority anchor coin-frontier guard failed "
                 "h=%d reason=%s",
                 height, reason ? reason : "");
        return false;
    }
    if (!coin_allowed)
        return true;

    /* The cursor floor is the authority tip's OWN height — never height+1.
     * Cursor C means "transitions through C-1→C are finalized; C→C+1 is
     * pending". An authority committing tip H proves exactly C=H; stamping
     * H+1 claims the H→H+1 transition that nothing finalized, and SKIPS it
     * forever (the cursor is monotonic). That skip manifests as the
     * served-tip-trails-by-one-block defect: every finalize advance is
     * followed by a trusted_tip re-anchor of the just-published tip, so
     * each new block could only be published once ITS successor arrived.
     * Boot/restore readers resolve the durable tip via
     * tip_finalize_stage_resolve_durable_tip, which handles both this
     * convention and the legacy +1 lattice. */
    uint64_t target = (uint64_t)height;
    uint64_t cursor = stage_cursor_persisted(db, STAGE_NAME, STAGE_NAME);
    /* PRE-INSERT row count: the FIX-3 seed-exemption discriminator for the
     * frontier cap below. Must be read BEFORE ensure_authority_anchor_row —
     * after the insert, "log empty" can never be true (stage_anchor.h). */
    int64_t rows = stage_log_row_count(db, STAGE_NAME, "tip_finalize_log");
    if (require_prior_progress && cursor == 0 && rows <= 0)
        return true;
    if (!ensure_authority_anchor_row(db, height, hash))
        return false;
    if (anchor_upstream &&
        !stage_anchor_upstream_cursors_to(db, target, STAGE_NAME, reason,
                                          false /* runtime re-anchor */))
        return false;
    /* FIX-3 jump site 2: never advance the finalize cursor past a rowless
     * height. A healthy restart is unchanged — the scan over
     * [cursor, height) ends below the just-ensured anchor row at `height`;
     * a held/rowless span caps the jump so the stage re-finalizes forward
     * (slower, never wrong). */
    if (!stage_anchor_cap_target_at_log_frontier(db, "tip_finalize_log",
                                                 cursor, target,
                                                 rows <= 0, &target))
        return false;
    if (cursor >= target)
        return true;
    if (!stage_set_cursor(stage, db, target)) {
        LOG_WARN("tip_finalize",
                 "[tip_finalize] authority anchor cursor failed from=%llu to=%llu reason=%s",
                 (unsigned long long)cursor, (unsigned long long)target, reason ? reason : "");
        return false;
    }
    LOG_INFO("tip_finalize",
             "[tip_finalize] authority anchor cursor from=%llu to=%llu reason=%s",
             (unsigned long long)cursor, (unsigned long long)target, reason ? reason : "");
    return true;
}

void tip_finalize_stage_set_authoritative_tip(int height,
                                              const uint8_t hash[32])
{
    sqlite3 *db = progress_store_db();
    if (db && tip_finalize_stage_handle()) {
        progress_store_tx_lock();
        bool anchored = tip_finalize_anchor_cursor_to_authority(
            db, height, hash, false, false, "trusted_tip");
        if (anchored) {
            int accepted = -1;
            uint8_t accepted_hash[32];
            if (tip_finalize_stage_resolve_durable_tip(db, &accepted,
                                                       accepted_hash)) {
                tip_finalize_publish_last_advance(accepted, accepted_hash);
            }
            /* Republish H* so getblockcount reflects the freshly-anchored tip.
             * Unlike step_finalize (which republishes the provable-tip cache on
             * every advance), this authority-anchor path advanced the finalize
             * cursor WITHOUT refreshing the cache — so the served tip trailed the
             * true H* by one block: the regtest last-generate-block AND at-tip-
             * follower getblockcount lag (this path fires for every on-demand /
             * fMineBlocksOnDemand ingest, self-mined or P2P-received). Only when
             * the store handle is in a committed (autocommit) context — matching
             * the seed_anchor publish guard — so a mid-cutover caller never
             * exposes a pair a later rollback would revert. compute_hstar runs
             * under the progress lock held above; the set is a lock-free atomic. */
            if (sqlite3_get_autocommit(db) != 0) {
                int32_t hs = 0, sf = 0;
                if (reducer_frontier_compute_hstar(db, &hs, &sf))
                    reducer_frontier_provable_tip_set(hs);
            }
        }
        progress_store_tx_unlock();
        return;
    }
    tip_finalize_publish_last_advance(height, hash);
}

bool tip_finalize_stage_seed_anchor(int height, const uint8_t hash[32],
                                    bool trusted_seed)
{
    if (height < 0 || !hash)
        return false;

    /* Fail-loud validation pack, check 7 (+ check 5 post-import): verify
     * the seed pair + prev_hash linkage labels (and, for trusted seeds, the
     * stored utxo_sha3 commitment) BEFORE any cursor is stamped — a
     * poisoned import fails at birth, loudly, instead of becoming "our"
     * chain. Crash-only: refusal returns false (all seed callers handle
     * it); never FATAL. Runs before the progress lock — the gate reads
     * node.db only. */
    if (!seed_integrity_gate_check(height, hash, trusted_seed))
        return false;

    sqlite3 *db = progress_store_db();
    if (!db) {
        /* Not wired (very early boot, or unit tests without a progress
         * store). The cold-start seed is best-effort until the stage is
         * available. */
        return false;
    }
    progress_store_tx_lock();
    if (!ensure_log_schema(db)) {
        progress_store_tx_unlock();
        return false;
    }

    /* Durable trusted-base declaration, RAISE-ONLY (see the key's contract in
     * reducer_frontier.h). Two guards run BEFORE the pipeline-owned anchor row
     * so a poisoned local authority fails with ZERO new durable side effects:
     *   1. Range/format validation (belt-and-suspenders) — the canonical reader
     *      fails closed on a malformed BLOB OR a value beyond INT32_MAX (a
     *      height can never exceed it; a huge floor is corrupt authority).
     *   2. progress_meta_raise_u64_in_tx IS the raise-only write: it re-reads
     *      the (now range-validated) floor with exact-BLOB semantics and writes
     *      only when `height` strictly exceeds it. The hash is written only when
     *      the height actually raised, keeping the (height,hash) pair consistent.
     * The declaration must live in a meta key the pipeline cannot consume: the
     * anchor ROW is replaced by the first forward step's 'finalized' row, which
     * would otherwise starve reducer_trusted_anchor back to the compiled
     * checkpoint over a cold-import datadir's log-less region (I4.3 HOLD-wedge). */
    int32_t prev_trusted_height = 0;
    bool prev_trusted_found = false;
    if (!reducer_frontier_trusted_base_height_read(db, &prev_trusted_height,
                                                   &prev_trusted_found)) {
        LOG_WARN("tip_finalize",
                 "[tip_finalize] trusted-base height read failed h=%d", height);
        progress_store_tx_unlock();
        return false;
    }
    (void)prev_trusted_height;
    (void)prev_trusted_found;
    bool trusted_raised = false;
    if (!progress_meta_raise_u64_in_tx(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY,
                                       (uint64_t)height, &trusted_raised,
                                       NULL) ||
        (trusted_raised &&
         !progress_meta_set_in_tx(db, REDUCER_TRUSTED_BASE_HASH_KEY,
                                  hash, 32))) {
        LOG_WARN("tip_finalize",
                 "[tip_finalize] seed trusted-base write failed h=%d",
                 height);
        progress_store_tx_unlock();
        return false;
    }

    /* PRE-INSERT state for the FIX-3 seed-exemption verdict: a trusted
     * (SHA3-verified snapshot) seed is caller-declared; a fresh datadir is
     * recognised by the log being empty BEFORE the anchor row below is
     * written (stage_anchor.h, prong 2). */
    uint64_t cursor = stage_cursor_persisted(db, STAGE_NAME, STAGE_NAME);
    int64_t pre_insert_rows =
        stage_log_row_count(db, STAGE_NAME, "tip_finalize_log");
    bool seed_exempt = trusted_seed || pre_insert_rows == 0;

    struct uint256 tip_hash;
    memcpy(tip_hash.data, hash, 32);

    /* Snapshot/trusted anchors have no per-block work or UTXO delta. The
     * trusted-base raise above already fail-closed on a malformed floor, so no
     * durable side effect precedes this anchor row on that path. */
    if (!log_insert(db, height, "anchor", true, NULL, 0, 0, &tip_hash)) {
        progress_store_tx_unlock();
        return false;
    }

    /* The UPSTREAM reducer cursors keep the height+1 ("next height to
     * process") convention — those stages co-commit coins_applied_height ==
     * cursor, so a served tip at H means upstream has processed through H and
     * the next height is H+1. reducer_anchor_candidate_ok(H) is calibrated to
     * that: it requires every upstream cursor >= H+1. ONLY the tip_finalize
     * cursor uses the served-tip convention (cursor C == served tip at C). */
    if (!stage_anchor_upstream_cursors_to(db, (uint64_t)height + 1u,
                                          STAGE_NAME, "seed_anchor",
                                          trusted_seed)) {
        progress_store_tx_unlock();
        return false;
    }

    /* The first forward step consumes the utxo_apply verdict AT the served
     * height: step_finalize at cursor C reads utxo_apply_log row C to
     * finalize the C→C+1 transition. On a cold import nothing ever writes
     * row H — the import itself IS block H's apply authority (its coins
     * arrived inside the verified chainstate), and utxo_apply starts at
     * H+1 — so without this stamp the stage idles forever on
     * TF_BLOCKED_UV_ROW_MISSING at the seed.
     * Same trust model as the anchor row above; INSERT OR IGNORE so a real
     * verdict row is never clobbered. Zero deltas are safe: the
     * utxo-count divergence check is a test-only seam (no production
     * counter is wired) and the sums are COALESCE'd. MUST run AFTER the
     * upstream cursor stamps: stage_anchor_cap_target_at_log_frontier's
     * empty-log seed prong (FIX-3, prong 2) reads utxo_apply_log emptiness,
     * and a pre-stamp row would cap an untrusted fresh-datadir seed at 0. */
    {
        if (!utxo_apply_log_ensure_schema(db)) {
            progress_store_tx_unlock();
            return false;
        }
        /* Tag the seed anchor row like every other utxo_apply_log write so the
         * reducer fold can integrity-check it (status='anchor' IS folded in —
         * utxo_apply_log is status-covered). See stage_row_itag.h. */
        uint8_t seed_itag[STAGE_ROW_ITAG_LEN];
        stage_row_itag_compute("utxo_apply_log", (int64_t)height, 1,
                               "anchor", 6, seed_itag);
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db,
                "INSERT OR IGNORE INTO utxo_apply_log"
                "(height,status,ok,spent_count,added_count,"
                " total_value_delta,applied_at,itag) "
                "VALUES(?,'anchor',1,0,0,0,0,?)",
                -1, &st, NULL) != SQLITE_OK) {
            LOG_WARN("tip_finalize",
                     "[tip_finalize] seed utxo_apply anchor row prepare "
                     "failed: %s", sqlite3_errmsg(db));
            progress_store_tx_unlock();
            return false;
        }
        sqlite3_bind_int(st, 1, height);
        sqlite3_bind_blob(st, 2, seed_itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
        int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) {
            LOG_WARN("tip_finalize",
                     "[tip_finalize] seed utxo_apply anchor row insert "
                     "failed: %s", sqlite3_errmsg(db));
            progress_store_tx_unlock();
            return false;
        }
    }

    /* FIX-3 jump site 3: cap the self-stamp at the tip_finalize_log
     * frontier. The just-written anchor row covers `height`, so an at-tip
     * ingest re-seed stays a benign no-op-or-contiguous stamp; a stamp
     * across a rowless span is capped so the reducer re-finalizes forward
     * instead of manufacturing a hole behind the cursor.
     *
     * The tip_finalize cursor floor is the seeded tip's OWN height — never
     * height+1 (unifying the +1 conventions with the authority-anchor
     * convention). Cursor C means "served tip at C; the
     * C→C+1 transition is pending"; stamping H+1 claims the H→H+1 transition
     * that the seed never finalized and SKIPS it forever (the cursor is
     * monotonic), which is one late block per cold-import/snapshot seed:
     * block H+1 could only publish when H+2 arrived. The resolver's
     * cursor-then-cursor-1 fold tolerates BOTH the legacy +1 lattice and
     * this convention, so boot readers are unaffected. */
    uint64_t stamp = (uint64_t)height;
    if (!stage_anchor_cap_target_at_log_frontier(db, "tip_finalize_log",
                                                 cursor, stamp, seed_exempt,
                                                 &stamp)) {
        progress_store_tx_unlock();
        return false;
    }

    /* Stamp the served-tip cursor == anchor height. The boot resolver
     * (tip_finalize_stage_resolve_durable_tip) reads the anchor at cursor
     * first, then cursor-1, so a capped re-anchor that lands BELOW height is
     * still tolerated (the reducer re-finalizes forward from the frontier —
     * slower, never wrong). */
    stage_t *stage = tip_finalize_stage_handle();
    /* Monotonic guard (mirrors the authority path's cursor>=target check):
     * a re-anchor at or below the current served cursor must NEVER rewind it,
     * and we must not republish a lower tip. The forward reducer owns
     * advancement from the existing frontier. The upstream H+1 cursors were
     * stamped earlier (separate from this served-tip cursor) and are
     * untouched here. */
    if (stage && cursor >= stamp) {
        progress_store_tx_unlock();
        return true;
    }
    if (stage && !stage_set_cursor(stage, db, stamp)) {
        LOG_WARN("tip_finalize",
                 "[tip_finalize] anchor seed: cursor stamp to %llu failed",
                 (unsigned long long)stamp);
        progress_store_tx_unlock();
        return false;
    }

    /* Publish immediately only when this function owns a committed context.
     * Snapshot activation intentionally calls us inside a larger cutover
     * transaction; publishing before that transaction commits would expose a
     * runtime authority pair that a later failure rolls back on disk. The
     * terminal installer exits after commit and normal boot reconstructs the
     * runtime projection from this durable row. */
    if (sqlite3_get_autocommit(db) != 0)
        tip_finalize_publish_last_advance(height, hash);
    progress_store_tx_unlock();
    return true;
}
