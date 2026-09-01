/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_anchors -- reducer-owned shielded anchor validation/fold.
 *
 * The writer runs inside utxo_apply's stage transaction.  It validates every
 * transaction against the pre-block active-chain anchor set, advances Sprout
 * and Sapling frontiers only after the whole block passes, cross-checks the
 * Sapling frontier against the header, and inserts the new roots atomically
 * with coins/nullifiers/log/cursor. */

#ifndef ZCL_JOBS_UTXO_APPLY_ANCHORS_H
#define ZCL_JOBS_UTXO_APPLY_ANCHORS_H

#include <stdbool.h>
#include <stdint.h>

struct block;
struct delta_summary;
struct sqlite3;

#define UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID \
    "utxo_apply.anchor_backfill_gap"

/* The condition that owns the auto-terminating remedy for the empty-table
 * variant of this gap (a nonzero adoption cursor over an anchor table with no
 * seeded initial frontier).  Named in the gap blocker's reason so
 * Native blocker/condition diagnostics surface the remedy owner. MUST equal the .name
 * of the condition in engine/conditions/src/sapling_anchor_frontier_unavailable.c. */
#define SAPLING_ANCHOR_FRONTIER_CONDITION_NAME \
    "sapling_anchor_frontier_unavailable"

/* Store error => false (caller rolls back/fatals).  Consensus failure or an
 * incomplete historical frontier => true with summary->ok=false and a
 * distinct status/failure_kind. */
bool utxo_apply_check_and_insert_anchors(struct sqlite3 *db,
                                         const struct block *blk,
                                         int height,
                                         struct delta_summary *summary);

/* Reindex-only variant for a bounded shielded_history_begin_full_replay()
 * session.  It is identical to the normal consensus predicate except that an
 * explicitly session-proven, never-yet-populated pool may start from its
 * protocol empty frontier while the public completeness marker stays
 * positive.  Exact next-height session evidence is mandatory; no normal
 * reducer caller may use this entry point. */
bool utxo_apply_check_and_insert_anchors_full_replay(
    struct sqlite3 *db, const struct block *blk, int height,
    struct delta_summary *summary);

/* Register/clear the durable history-gap blocker from anchor_state. */
void utxo_apply_anchor_gap_blocker_refresh(struct sqlite3 *db);

struct node_db;

/* ── bind guard (boot-time detection, no auto-repair) ──────────────────────
 *
 * A height-mismatched -import-complete-shielded bind (the frontier row keyed
 * BELOW the coins island root, both activation cursors flipped to 0) used to
 * sail past every boot gate: the cursors claim complete history, so the gap
 * blocker cleared and the fold livelocked at the first Sapling-commitment
 * block above the island (sapling_frontier_mismatch, utxo_apply.apply_failed,
 * H* pinned) — a silent-consensus-cause wedge retried forever.
 *
 * Pure detection predicate for that shape. Returns true iff ALL hold:
 *   - both anchor activation cursors are present and 0 (complete-history
 *     claim — a positive cursor is the safe wedge the backfill blocker owns);
 *   - a proven coins authority derives (coins island root `coins_h`);
 *   - the latest Sapling frontier row sits at `frontier_h` < `coins_h`; AND
 *   - the header-committed hashFinalSaplingRoot at `coins_h` (node.db
 *     blocks.sapling_root) DIFFERS from that frontier row's root — proof the
 *     tree moved over blocks the frontier never saw.
 *
 * The root comparison is what keeps the guard silent on healthy datadirs: a
 * from-genesis fold's latest anchor legitimately lags the coins tip whenever
 * recent blocks carry no Sapling outputs, but the header root cannot have
 * moved in that case (roots only change on commitment blocks). A NULL ndb, a
 * missing header row, or an all-zero sapling_root column (old header import)
 * means "no evidence" and yields false — the fold's own fail-closed root
 * check remains the backstop. Heights are reported via the out-params. */
bool utxo_apply_anchor_bind_mismatch(struct sqlite3 *db, struct node_db *ndb,
                                     int64_t *frontier_h_out,
                                     int32_t *coins_h_out);

/* As utxo_apply_anchor_gap_blocker_refresh, but the bind-guard probe reads
 * the header chain through the caller's `ndb` instead of the runtime handle —
 * the test seam (production callers use the refresh, which probes via
 * app_runtime_node_db()). */
void utxo_apply_anchor_gap_blocker_refresh_with_ndb(struct sqlite3 *db,
                                                    struct node_db *ndb);

#endif /* ZCL_JOBS_UTXO_APPLY_ANCHORS_H */
