/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * process_block_invalidate — the operator recovery lever.
 *
 * Mirrors Bitcoin Core's `InvalidateBlock` / `ReconsiderBlock`
 * (validation.cpp). A deterministic, hash-addressed way to drop a stale
 * fork so the node reorgs to the next-best fully-valid chain — and the
 * exact inverse to undo a mistaken invalidation.
 *
 * Why this exists
 * ---------------
 * `process_block_revalidate` clears a FAILED bit, but only on ≥2-oracle
 * (or local-authority) evidence at a *height*, and only in the
 * clear direction. There is no lever to say "this specific block hash is
 * bad, drop it and reorg". When the live node is stuck connecting a
 * stale data-bearing block that the evidence controller correctly
 * rejects, the operator needs `invalidateblock <hash>`.
 *
 * The consensus-safety contract
 * -----------------------------
 * invalidateblock NEVER connects a block. It only:
 *   1. marks the target pindex BLOCK_FAILED_VALID,
 *   2. propagates BLOCK_FAILED_CHILD to its descendants,
 *   3. persists the status flip before any reducer kick,
 *   4. moves the active-chain cursor back below the target (if the target
 *      is on the active chain) through the reducer stage-unwind path, and
 *   5. kicks the reducer so the next-best chain drains through the
 *      stage pipeline — every applied block runs the FULL `connect_block`
 *      validator (Equihash + scripts + Sapling). No consensus rule changes,
 *      no validation skipping.
 *
 * reconsiderblock is the inverse: it clears BLOCK_FAILED_VALID/CHILD on
 * the target and its descendants, persists, and kicks activation so the
 * cleared chain becomes eligible for selection again (and is fully
 * re-validated by connect_block if it is chosen).
 */

#ifndef ZCL_VALIDATION_PROCESS_BLOCK_INVALIDATE_H
#define ZCL_VALIDATION_PROCESS_BLOCK_INVALIDATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct main_state;
struct uint256;
struct block_index;
struct coins_view_cache;
struct chain_params;
struct validation_state;

/* Result enum — every attempt returns exactly one value. Names are stable for
 * logging, native commands, and RPC consumers. */
enum invalidate_result {
    INVALIDATE_NOT_ATTEMPTED   = 0,  /* prereqs unmet (NULL ms/hash) */
    INVALIDATE_BLOCK_NOT_FOUND = 1,  /* no pindex with that hash */
    INVALIDATE_IS_GENESIS      = 2,  /* refusing to invalidate genesis */
    INVALIDATE_DISCONNECT_FAIL = 3,  /* could not roll the active chain back */
    INVALIDATE_PERSIST_FAILED  = 4,  /* status flip didn't reach disk */
    INVALIDATE_OK              = 5,  /* marked + (if needed) disconnected;
                                        activation kicked */
};

enum reconsider_result {
    RECONSIDER_NOT_ATTEMPTED   = 0,  /* prereqs unmet */
    RECONSIDER_BLOCK_NOT_FOUND = 1,  /* no pindex with that hash */
    RECONSIDER_NO_FAILURE      = 2,  /* block + descendants carried no
                                        failure mark; nothing to clear */
    RECONSIDER_PERSIST_FAILED  = 3,  /* status clear didn't reach disk */
    RECONSIDER_OK              = 4,  /* cleared; activation kicked */
};

const char *invalidate_result_name(enum invalidate_result r);
const char *reconsider_result_name(enum reconsider_result r);

/* App-owned post-unwind bridge.  Validation names the exact disconnected
 * active segment; boot owns block-file reads, mempool policy, and network
 * relay.  The hook runs only after the reducer kick has durably unwound coins.
 * Failure never reverses the operator's invalidation; it is reported loudly
 * and leaves transactions absent rather than admitting them unchecked. */
struct process_block_mempool_restore_result {
    size_t blocks_read;
    size_t txs_attempted;
    size_t txs_accepted;
    size_t txs_removed;
    size_t txs_relayed;
    size_t txs_rejected;
};

enum process_block_mempool_segment_action {
    PROCESS_BLOCK_MEMPOOL_RESTORE_DISCONNECTED = 0,
    PROCESS_BLOCK_MEMPOOL_REMOVE_RECONNECTED,
};

typedef bool (*process_block_mempool_restore_fn)(
    void *ctx,
    struct block_index *first_disconnected,
    struct block_index *old_active_tip,
    enum process_block_mempool_segment_action action,
    struct process_block_mempool_restore_result *out);

void process_block_set_mempool_restore_hook(
    process_block_mempool_restore_fn fn, void *ctx);

/* ── Pure, side-effect-bounded core (no activation kick) ──────────
 *
 * These operate purely on the in-memory block_map + active_chain and
 * are the unit-test surface. They do NOT persist to disk and do NOT
 * kick activation — the orchestrators below layer those on. Safe to
 * call from a test with a hand-built main_state.
 */

/* Mark `target` BLOCK_FAILED_VALID and every descendant BLOCK_FAILED_CHILD.
 * `*marked_children_out` (may be NULL) receives the descendant count.
 * No-op-safe if already marked. Does not touch the active chain. */
void process_block_mark_invalid(struct main_state *ms,
                                struct block_index *target,
                                size_t *marked_children_out);

/* Clear BLOCK_FAILED_VALID/CHILD on `target` and every descendant.
 * `*cleared_out` (may be NULL) receives the total entries cleared
 * (including the target). */
void process_block_clear_invalid(struct main_state *ms,
                                 struct block_index *target,
                                 size_t *cleared_out);

/* While the active chain contains the hash-addressed `target`, move the
 * active-chain cursor to the active object's parent. Same-hash/different-
 * pointer block_index objects are treated as the same block. The helper does
 * not kick the reducer; the orchestrator owns that single side effect.
 * Returns false if the cursor move fails and true (no-op) when the active
 * chain does not contain target's hash. */
bool process_block_disconnect_to_parent(struct validation_state *state,
                                         struct main_state *ms,
                                         struct coins_view_cache *coins_tip,
                                         const struct chain_params *params,
                                         struct block_index *target,
                                         const char *datadir);

/* ── Orchestrators (hash-addressed; persist + kick activation) ──── */

/* invalidateblock <hash>. See header preamble for the contract.
 * Resolves coins_tip/params/datadir from the activation controller.
 * `out_hash` (may be NULL) is filled with the resolved pindex hash. */
enum invalidate_result process_block_invalidate(struct main_state *ms,
                                                const struct uint256 *hash,
                                                struct uint256 *out_hash);

/* reconsiderblock <hash>. The inverse of process_block_invalidate. */
enum reconsider_result process_block_reconsider(struct main_state *ms,
                                                const struct uint256 *hash,
                                                struct uint256 *out_hash);

#endif /* ZCL_VALIDATION_PROCESS_BLOCK_INVALIDATE_H */
