/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * nullifier_kv — the reducer's consensus shielded-nullifier set as a
 * `nullifiers` table IN progress.kv (C-3).
 *
 * WHY: zclassicd's ConnectBlock rejects any transaction whose Sprout or
 * Sapling nullifier was already revealed (HaveShieldedRequirements,
 * main.cpp:2627 -> "bad-txns-joinsplit-requirements-not-met"; nullifier
 * lookup in coins.cpp:166-180). The reducer connect path (utxo_apply) had no
 * durable nullifier set, so a shielded double-spend that zclassicd rejects
 * would have been accepted here — an opposite-verdict hard fork. This table
 * is the durable set; utxo_apply checks-then-inserts inside its own stage
 * transaction (stage_run_once's BEGIN IMMEDIATE), so nullifiers commit or
 * roll back atomically with coins + cursor + log row, exactly like coins_kv.
 *
 * POOLS: `pool` 0 = Sprout, 1 = Sapling — SEPARATE namespaces. zclassicd
 * keeps DISTINCT nullifier maps per pool (CCoinsViewCache::GetNullifier,
 * coins.cpp:166-180), so the same 32 bytes may legally appear once in EACH
 * pool. A single-column nf primary key would reject that legal cross-pool
 * byte-reuse — the opposite-direction fork risk. Hence PRIMARY KEY(nf,pool).
 *
 * REWIND INVARIANT (load-bearing): every cursor rewind must delete nullifier
 * rows in the rewound range in the same txn — a rewind path that skips this
 * produces stale rows and false shielded_double_spend rejects on re-apply.
 * utxo_apply_delete_rows_above (the shared rewind primitive) deletes
 * nullifiers alongside utxo_apply_log/utxo_apply_delta, which covers the
 * reorg unwind, the value_overflow repair, and the stale-script replay;
 * stage_repair_rewind's downstream delete list includes it belt-and-braces.
 *
 * PERMANENCE: like coins, the nullifier set is permanent consensus state —
 * it is NEVER pruned below finality (unlike utxo_apply_delta rows).
 *
 * ACTIVATION GAP: the set is populated only by blocks applied AFTER the table
 * is created. On a datadir whose
 * utxo_apply cursor was already past genesis at activation (the live node and
 * legacy coins-only snapshot/import paths; v3 may carry nullifiers but must
 * not be called complete unless its installer proves and preserves them),
 * every nullifier revealed below the positive
 * `nullifier_kv.activation_cursor` marker is absent, so a double-spend of
 * a pre-activation note cannot be proven fresh. The live reducer therefore
 * holds every Sprout JoinSplit/Sapling spend before any coin write while this
 * marker is positive; transparent-only blocks remain processable. The raw
 * writer stays available to the owner-gated backfill service. Stage init
 * surfaces the gap as the PERMANENT blocker
 * `utxo_apply.nullifier_backfill_gap` (`z23 dumpstate blocker`) every
 * boot until a shielded-history backfill walker (or a snapshot-format
 * nullifier extension) lands. Malformed/unreadable completeness evidence fails
 * closed; an absent marker is unknown, never implicit cursor zero. First
 * adoption creates the table and explicit marker in one transaction.
 *
 * Every function operates on the passed progress.kv handle and therefore
 * participates in whatever transaction the caller already holds open. Raw
 * sqlite3_step calls carry // raw-sql-ok:progress-kv-kernel-store, the
 * sanctioned hatch for the kernel store (same convention as coins_kv.c). */
#ifndef STORAGE_NULLIFIER_KV_H
#define STORAGE_NULLIFIER_KV_H

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;

/* `pool` column values. Must never be renumbered: rows are durable. */
#define NULLIFIER_POOL_SPROUT  0
#define NULLIFIER_POOL_SAPLING 1

/* Durable bounded-replay session keys. They are public so an atomic state
 * generation replacement can cancel a superseded session in the same txn. */
#define SHIELDED_REPLAY_TARGET_KEY "shielded_history.full_replay.target"
#define SHIELDED_REPLAY_NEXT_KEY "shielded_history.full_replay.next"
#define SHIELDED_REPLAY_SPROUT_STARTED_KEY \
    "shielded_history.full_replay.sprout_started"
#define SHIELDED_REPLAY_SAPLING_STARTED_KEY \
    "shielded_history.full_replay.sapling_started"

/* CREATE TABLE IF NOT EXISTS nullifiers(...) + height index. Idempotent. */
bool nullifier_kv_ensure_schema(struct sqlite3 *db);

/* Atomically ensure the schema and its durable completeness marker.  On first
 * adoption, stores `activation_cursor`: zero explicitly proves a from-genesis
 * store, while a positive value records the unknown historical prefix.
 * Existing markers are never overwritten.  If the caller has an open
 * transaction this joins it; otherwise it owns BEGIN IMMEDIATE..COMMIT. */
bool nullifier_kv_initialize_history(struct sqlite3 *db,
                                     int64_t activation_cursor);

/* Strictly read the durable adoption cursor. Missing is reported with
 * *found_out=false; malformed, overflowing, or non-canonical bytes are an
 * error, never coerced to the complete value zero. */
bool nullifier_kv_activation_cursor(struct sqlite3 *db,
                                    int64_t *cursor_out, bool *found_out);

/* Reset primitives — clear the complete nullifier set and stamp its adoption
 * cursor in the caller's ALREADY-OPEN transaction (autocommit is refused).
 * The cursor value selects one of two OPPOSITE completeness semantics, so the
 * choice is named at the call site rather than encoded in a bare integer.
 * Co-writing the marker with the DELETE in one txn is load-bearing: a DELETE
 * without it can preserve a stale explicit zero and make an empty set look
 * complete.
 *
 * mark_complete: adoption cursor 0 — a from-genesis COMPLETE history. Every
 * revealed nullifier is durably present, so a double-spend of ANY note is
 * provable fresh and no historical prefix is claimed unknown. */
bool nullifier_kv_reset_mark_complete_in_tx(struct sqlite3 *db);

/* mark_empty_below: adoption cursor `below_height` — the historical prefix is
 * UNKNOWN below `below_height` (the marker every above-genesis seed/refold/
 * replay installs). Every nullifier revealed below the cursor is absent, so a
 * pre-activation double-spend cannot be proven fresh; the reducer holds every
 * shielded input and surfaces the PERMANENT `utxo_apply.nullifier_backfill_gap`
 * blocker until a body replay backfills [0, below_height). `below_height` must
 * be >= 0 (a negative height is refused); passing 0 is accepted and is
 * equivalent to mark_complete. */
bool nullifier_kv_reset_mark_empty_below_in_tx(struct sqlite3 *db,
                                               int64_t below_height);

/* Flip the durable nullifier activation marker from `expected_boundary` to zero
 * in the caller's ALREADY-OPEN transaction, WITHOUT clearing the rows — the
 * mirror of anchor_kv_publish_full_replay_complete_in_tx for the nullifier set,
 * so a complete-history importer can publish anchor + nullifier completeness
 * together in one atomic transaction. Refuses (leaving the positive marker in
 * place) unless the current marker exists and still equals the positive
 * `expected_boundary`; re-reads and verifies zero before returning true. */
bool nullifier_kv_publish_full_replay_complete_in_tx(
    struct sqlite3 *db, int64_t expected_boundary);

/* Delete every bounded full-replay session marker in the caller's open
 * transaction. Missing keys are success. */
bool shielded_history_cancel_full_replay_in_tx(struct sqlite3 *db);

/* Start a bounded genesis-through-target replay.  Owns one transaction that
 * clears both anchor tables and the nullifier set, writes the same positive
 * target+1 incompleteness boundary for all three, and initializes an exact
 * durable next-height session at zero.  No public completeness marker is zero
 * while the replay is partial. */
bool shielded_history_begin_full_replay(struct sqlite3 *db,
                                        int64_t target_height);

/* Read/verify the bounded replay session.  `expect_next` is a read-only gate
 * used by the replay-only anchor folder; `advance_in_tx` requires the caller's
 * block transaction and advances exactly height -> height+1.  It also records
 * whether each pool has ever emitted a non-empty frontier so an unexpectedly
 * emptied table can never be mistaken for the initial empty tree. */
bool shielded_history_full_replay_expect_next(struct sqlite3 *db,
                                              int64_t height);
bool shielded_history_full_replay_advance_in_tx(struct sqlite3 *db,
                                                int64_t height,
                                                int64_t target_height);
bool shielded_history_full_replay_empty_frontier_allowed(
    struct sqlite3 *db, int pool, int64_t height);
bool shielded_history_full_replay_mark_pool_started_in_tx(
    struct sqlite3 *db, int pool, int64_t height);

/* Publish Sprout, Sapling, and nullifier marker zero in ONE transaction, only
 * when the durable replay session proves an exact [0,target] walk and all
 * three markers still equal target+1.  The replay-session rows are removed in
 * that same commit.  A failure leaves every marker positive. */
bool shielded_history_publish_full_replay_complete(
    struct sqlite3 *db, int64_t target_height);

/* Own one BEGIN IMMEDIATE and reset BOTH anchor and nullifier history to the
 * same strictly POSITIVE adoption boundary. Used by assisted snapshot
 * activation before any reducer cursor/tip promotion. Either both provenance
 * records and cleared sets commit, or neither does. Marker zero is deliberately
 * unreachable here: only shielded_history_publish_full_replay_complete() may
 * publish complete history after its exact bounded replay proof. */
bool shielded_history_reset_to_boundary(struct sqlite3 *db,
                                        int64_t activation_cursor);

/* True iff the `nullifiers` table already exists. Diagnostic/test probe only;
 * table existence is never completeness evidence. */
bool nullifier_kv_table_exists(struct sqlite3 *db);

/* Durable row count of revealed nullifiers in `pool` (0=Sprout, 1=Sapling).
 * Diagnostic-only: an operator/dumper's observable proof of HOW MANY
 * historical nullifiers a completed import
 * (shielded_history_import_service.c) or a from-genesis fold has actually
 * written, independent of and cross-checkable against the activation
 * cursor. Returns false on store error and leaves *count_out at 0. */
bool nullifier_kv_row_count(struct sqlite3 *db, int pool, int64_t *count_out);

/* Point-read one nullifier in one pool. Returns false only on a store error;
 * *found reports presence, *height_out (optional) the revealing height. */
bool nullifier_kv_get(struct sqlite3 *db, const uint8_t nf[32], int pool,
                      bool *found, int64_t *height_out);

/* INSERT OR REPLACE one revealed nullifier at `height`. */
bool nullifier_kv_add(struct sqlite3 *db, const uint8_t nf[32], int pool,
                      int64_t height);

/* DELETE every nullifier revealed in [first_h .. last_h] (both pools) —
 * the rewind primitive (see the rewind invariant above). */
bool nullifier_kv_delete_range(struct sqlite3 *db, int64_t first_h,
                               int64_t last_h);

#endif /* STORAGE_NULLIFIER_KV_H */
