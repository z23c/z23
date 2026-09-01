/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_shielded_seed — legacy USS v3 current-state import adapter used by
 * -load-snapshot-at-own-height. This is not the sovereign history cure.
 *
 * The v3 UTXO snapshot carries current Sapling/Sprout commitment-tree frontiers
 * and nullifier rows (storage/snapshot_shielded.h), but no independently proven
 * complete history. These helpers install the useful current state while
 * retaining positive anchor/nullifier history-gap cursors. ZClassic headers
 * bind the Sapling frontier root only; they do not bind UTXOs, old anchors,
 * Sprout state, or nullifiers.
 */

#ifndef CONFIG_BOOT_SHIELDED_SEED_H
#define CONFIG_BOOT_SHIELDED_SEED_H

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;
struct main_state;
struct uss_handle;

/* Capture the shielded section from an OPEN, SHA3-verified snapshot handle into
 * heap copies (the caller frees). v2 copies ONLY the Sapling frontier (leaving
 * *shielded_v3 false, so the current-state adapter does not engage). v3 copies
 * the Sapling +
 * Sprout frontiers + the nullifier set and, on a full capture, sets
 * *shielded_v3 = true. Sapling is only copied when *sapling is still NULL. On
 * OOM the partial v3 copies are freed and *shielded_v3 stays false (the caller
 * falls back to the cursor-reset / block-replay path). No-op for v1. */
void boot_capture_shielded(struct uss_handle *h, bool load_ok,
                           uint8_t **sapling, uint32_t *sapling_len,
                           bool *shielded_v3,
                           uint8_t **sprout, uint32_t *sprout_len,
                           uint8_t **nfs, uint64_t *nf_count);

/* Before an assisted snapshot may clear/reseed coins, durably clear stale
 * shielded rows and publish a positive unknown-history boundary. This owns its
 * transaction, so any later interruption leaves conservative provenance. */
bool boot_shielded_prepare_assisted_boundary(struct sqlite3 *rpdb, int seed_h);

#ifdef ZCL_TESTING
void boot_shielded_interrupt_after_boundary_for_test(bool enabled);
bool boot_shielded_consume_boundary_interrupt_for_test(void);
#endif

/* In the caller's ALREADY-OPEN progress.kv transaction, either:
 *   - when a v3 shielded section was captured AND its Sapling frontier
 *     ALREADY root-verified against hashFinalSaplingRoot (sapling_verified):
 *     retain seed_h as the incomplete-history cursor, install the root-verified
 *     current Sapling frontier (fail-closed on mismatch), optionally add the
 *     current Sprout frontier, bulk-add supplied nullifier rows, and persist a
 *     positive nullifier gap marker; or
 *   - (default) reset anchor and nullifier adoption cursors to seed_h over
 *     empty state (HISTORY_INCOMPLETE until a body replay backfills).
 * Returns true on success, false (caller rolls back + fails closed) on any
 * error — INCLUDING a Sapling root-verify failure: an unverified/partial
 * shielded state is never seeded. */
bool boot_shielded_cure_or_reset_in_tx(
    struct sqlite3 *rpdb, struct main_state *ms, int seed_h,
    bool sapling_verified, bool shielded_v3,
    const uint8_t *sapling, uint32_t sapling_len,
    const uint8_t *sprout, uint32_t sprout_len,
    const uint8_t *nfs, uint64_t nf_count);

#endif /* CONFIG_BOOT_SHIELDED_SEED_H */
