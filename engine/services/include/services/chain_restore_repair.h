/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain Restore Repair — post-restore active-chain and block-index repair. */

#ifndef ZCL_CHAIN_RESTORE_REPAIR_H
#define ZCL_CHAIN_RESTORE_REPAIR_H

#include <stdbool.h>

#include "util/result.h"

struct main_state;
struct block_index;
struct uint256;

/* After an anchor-restore / snapshot-restore / block-file-scan path
 * completes, repair the two state shapes that the normal validation path
 * would have established: active_chain slots and persisted nBits values. */
int chain_restore_rebuild_active_chain(struct main_state *ms,
                                       struct block_index *tip,
                                       const char *datadir);

/* Tier-2 P2 fast restart: when set, chain_restore_rebuild_active_chain treats
 * its `datadir` as NULL — it installs the tip and populates active_chain[0..tip]
 * by an in-memory pprev walk of the (verified-clean, SHA3-checked) block index
 * WITHOUT re-reading every block header from disk. Set true ONLY after the
 * clean-shutdown bindings verify; the integrity check still runs afterward and
 * falls the node to DEGRADED self-heal on any hole, so it is fail-safe. The
 * dirty path (flag false, the default) is bit-identical to today. */
void chain_restore_set_trust_index_fastpath(bool on);
bool chain_restore_trust_index_fastpath(void);

int chain_restore_backfill_nbits_from_disk(struct main_state *ms,
                                           const char *datadir);

/* Clear BLOCK_FAILED_VALID + BLOCK_FAILED_CHILD on entries strictly
 * above the active tip. After a body-pull / direct-import path writes
 * new blocks past a previously-stuck tip, stale FAILED flags from old
 * IBD attempts prevent find_most_work_chain from selecting through them.
 * Re-validation under evidence-mode is cheap; genuinely-invalid blocks get
 * re-flagged by the next reducer validation pass. Returns the number of
 * entries cleared. */
int chain_restore_clear_failed_above_tip(struct main_state *ms);

bool chain_restore_block_is_consensus_backed(const struct block_index *tip);

bool chain_restore_block_is_consensus_backed_on_disk(
    const struct block_index *tip,
    const char *datadir);

/* Cold-import-seed-anchor-aware variant of the on-disk backed check.
 *
 * A cold-import UTXO-snapshot seed anchor is a legitimate non-genesis root:
 * its pprev chain to genesis is absent because it was a snapshot base, not
 * a P2P-downloaded block. The plain backed check rejects it at the
 * pprev-presence test, so the coins-best restore refuses and the tip drops
 * to genesis on a restart that forward-synced past the seed.
 *
 * When `seed_anchor_hash`/`seed_anchor_height` identify a block AND the
 * candidate IS that exact (hash, height), this SKIPS ONLY the
 * pprev-presence check and the disk prev-hash comparison; EVERY other gate
 * (not-FAILED, HAVE_DATA, file/pos present, on-disk self-hash match, merkle
 * match, nBits match) is kept verbatim. Pass `seed_anchor_hash=NULL` /
 * `seed_anchor_height < 0` for the identical behaviour of the non-variant
 * function — a torn/orphan root whose hash != the persisted seed anchor is
 * STILL refused. */
bool chain_restore_block_is_consensus_backed_on_disk_seeded(
    const struct block_index *tip,
    const char *datadir,
    const struct uint256 *seed_anchor_hash,
    int seed_anchor_height);

struct block_index *chain_restore_nearest_consensus_backed_ancestor(
    struct block_index *tip);

struct block_index *chain_restore_nearest_consensus_backed_ancestor_on_disk(
    struct block_index *tip,
    const char *datadir);

/* Seed-anchor-aware nearest-ancestor walk — same contract as
 * chain_restore_nearest_consensus_backed_ancestor_on_disk, but the
 * provenance-matched cold-import seed anchor qualifies as backed (see the
 * _seeded predicate above). Pass NULL/-1 for identical behaviour. */
struct block_index *chain_restore_nearest_consensus_backed_ancestor_on_disk_seeded(
    struct block_index *tip,
    const char *datadir,
    const struct uint256 *seed_anchor_hash,
    int seed_anchor_height);

struct zcl_result chain_restore_finalize(struct main_state *ms, const char *datadir);

#endif
