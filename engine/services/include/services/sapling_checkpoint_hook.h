/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sapling_checkpoint_hook — bind the flat-file Sapling checkpoint
 * (validation/process_block.h: sapling_tree_flat_checkpoint_note) to the
 * REDUCER FOLD CURSOR, not the wallet/explorer node_db catchup lane's own
 * pace.
 *
 * WHY: the flat-file checkpoint's only prior writer was
 * node_db_catchup_service.c, whose loop height walks the HEADER chain tip
 * (gated only on BLOCK_HAVE_DATA), independent of and often ahead of the
 * reducer's own utxo_apply cursor (which is throttled behind script/proof
 * validation). A checkpoint stamped ahead of the reducer's applied frontier
 * is useless to (a) the empty-frontier healer
 * (conditions/sapling_anchor_frontier_unavailable.c tier1, which requires
 * ckpt_h < stall_height = H*+1) and (b) boot.c's own load-verify path
 * (which compares the checkpoint's root against hashFinalSaplingRoot at the
 * coins-applied endpoint and spuriously mismatches — triggering a needless
 * full rebuild — when the checkpoint is stamped past that endpoint).
 *
 * CONTRACT (OBSERVE-ONLY, BEST-EFFORT — same class as
 * services/anchor_selfmint.h's anchor_selfmint_hook_in_tx, which this runs
 * beside in the same utxo_apply step_apply transaction):
 *   - This NEVER changes any consensus predicate or the fold result. It
 *     only PERSISTS a checkpoint of the already-durable Sapling anchor
 *     frontier (anchor_kv, storage/anchor_kv.h) at the height the reducer
 *     just applied.
 *   - void return: a write/lookup failure MUST NOT fail the block. Best
 *     effort, silently dropped (sapling_tree_flat_checkpoint_note already
 *     logs its own failures).
 *   - Rate-limited to its own periodic cadence (every
 *     SAPLING_CHECKPOINT_BLOCK_INTERVAL — validation/process_block.h —
 *     successfully-applied blocks), checked via a cheap atomic counter
 *     BEFORE any DB read, so the hot per-block reducer path pays no more
 *     than one atomic increment on all but one call in
 *     SAPLING_CHECKPOINT_BLOCK_INTERVAL. Never fetches/deserializes the
 *     Sapling anchor tree on the hot path.
 *   - A no-op whenever no Sapling frontier exists yet in anchor_kv
 *     (pre-activation, or the birth-defect empty-table window the healer
 *     exists to cure) — mirrors utxo_apply_anchors.c's fold_sapling gate,
 *     never checkpoints a frontier that isn't there.
 *   - The actual write still goes through sapling_tree_flat_checkpoint_note,
 *     which independently refuses any height beyond the reducer's own
 *     applied frontier (defense in depth — see that function's doc). */
#ifndef ZCL_SERVICES_SAPLING_CHECKPOINT_HOOK_H
#define ZCL_SERVICES_SAPLING_CHECKPOINT_HOOK_H

#include <stdint.h>

struct sqlite3;

/* Call from the utxo_apply step_apply txn, right after the cursor +
 * coins_applied_height are stamped (beside anchor_selfmint_hook_in_tx /
 * seal_candidate_hook_in_tx). `db` is the progress.kv handle (the same one
 * the caller's stage transaction is already open on). `height` is the
 * height just durably applied (== coins_applied_height - 1 the moment this
 * transaction commits). `block_hash` is that block's own hash (32 bytes);
 * a NULL block_hash is a safe no-op. */
void sapling_checkpoint_hook_in_tx(struct sqlite3 *db, int64_t height,
                                   const uint8_t block_hash[32]);

#ifdef ZCL_TESTING
/* Force the NEXT call to sapling_checkpoint_hook_in_tx past the internal
 * interval gate (as if SAPLING_CHECKPOINT_BLOCK_INTERVAL calls had already
 * elapsed) so a test can exercise the write path without looping. */
void sapling_checkpoint_hook_test_force_next(void);
#endif

#endif /* ZCL_SERVICES_SAPLING_CHECKPOINT_HOOK_H */
