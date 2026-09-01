/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Private transaction mechanics for retained reducer-frontier replay.
 *
 * reducer_frontier_replay.c decides whether a stale script/proof/hash-split
 * replay owns a height. This helper owns the progress-store transaction body
 * once the owning height and cursors have been proven. */

#ifndef ZCL_JOBS_REDUCER_FRONTIER_REPLAY_TX_H
#define ZCL_JOBS_REDUCER_FRONTIER_REPLAY_TX_H

#include <stdbool.h>
#include <stdint.h>

struct block;
struct main_state;
struct script_validate_dry_run_report;
struct sqlite3;
struct uint256;

bool reducer_frontier_replay_delete_log_range(struct sqlite3 *db,
                                              const char *table,
                                              int first_h,
                                              int cursor);

/* LCC-safe coins inverse-rewind of [first_h, cursor): verifies each
 * utxo_apply_log row is rewindable (ok=1 ⇒ inverse delta present) and emits the
 * inverse delta, undoing coin mutations back to first_h. Refuses (false) rather
 * than manufacture a hole when an inverse image is missing. Caller holds
 * progress_store_tx_lock() and an open transaction. Shared by the stale-script
 * replay and stage_rederive_range (Law 2 — one coins-rewind path). */
bool reducer_frontier_replay_inverse_delta_range_checked(struct sqlite3 *db,
                                                         int first_h,
                                                         int cursor);

bool reducer_frontier_replay_script_ok_at_unlocked(struct sqlite3 *db,
                                                   int height,
                                                   int *out_ok);

bool reducer_frontier_replay_dry_run_stale_script(
    struct sqlite3 *db,
    struct main_state *ms,
    int height,
    int replay_first,
    int utxo_cursor,
    int backfill_top,
    const struct block *blk,
    struct script_validate_dry_run_report *dry);

bool reducer_frontier_replay_stale_script_tx(
    struct sqlite3 *db,
    struct main_state *ms,
    int height,
    int replay_first,
    int script_cursor,
    int proof_cursor,
    int utxo_cursor,
    int tip_cursor,
    int backfill_top,
    bool rewind_headers);

bool reducer_frontier_replay_stale_proof_tx(struct sqlite3 *db,
                                            int height,
                                            int replay_first,
                                            int proof_cursor,
                                            int utxo_cursor,
                                            const struct uint256 *block_hash);

/* Wave A2 (D4) TX2: the created_outputs backfill of the stale-script reorg
 * unwind, on the projection_store handle + projection tx lock. Runs STRICTLY
 * AFTER the kernel TX1 has committed and the caller has released the kernel
 * progress lock (LOCK ORDER LAW) — never nested inside it. Best-effort: a
 * failure is logged and returns false; the forward re-fold (body_persist)
 * repopulates created_outputs either way. Stamps the projection commit seq on
 * success. No-op returning true when [replay_first, backfill_top] is empty. */
bool reducer_frontier_replay_backfill_created_outputs_projection(
    struct main_state *ms, int replay_first, int backfill_top);

/* Lane A1 ordering proof (test observability). Returns the monotonic sequence
 * numbers stamped at the last committed kernel-authoritative rewind (TX1) and
 * the last committed projection-side created_outputs backfill (TX2) of the
 * stale-script reorg unwind. A projection commit ALWAYS carries a strictly
 * greater sequence than the kernel commit it follows: proof that the projection
 * tx never precedes the kernel tx. Either pointer may be NULL. */
void reducer_frontier_replay_tx_commit_seqs(uint64_t *kernel_out,
                                            uint64_t *projection_out);

#endif /* ZCL_JOBS_REDUCER_FRONTIER_REPLAY_TX_H */
