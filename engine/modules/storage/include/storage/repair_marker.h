/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * repair_marker — ONE durable table for "have I already done repair X at
 * (height, block_hash)?" idempotency markers, living in the consensus kernel
 * store (consensus.db, alongside progress_meta / stage_cursor). It replaces
 * four independent, never-GC'd, string-keyed progress_meta namespaces that all
 * encoded the same shape by hand:
 *
 *   1. utxo_apply.<kind>_repair.<height>.<hash>   (value-overflow rewind marker)
 *   2. reducer_frontier.<name>_repair.<height>.<hash> (stale-replay / tipfin
 *      span one-shot markers)
 *   3. coin_backfill.rounds/.refused/.scan.<height>.<hash> (round counter,
 *      durable terminal refusal, resumable scan progress blob)
 *   4. tipfin_backfill.progress                    (singleton resume witness)
 *
 * Each marker is keyed by (kind, height, hash). `payload` is an opaque blob the
 * caller owns (NULL/empty for a pure presence marker; a small binary record for
 * the coin-backfill scan/rounds/refused and the tipfin witness). The singleton
 * witness has no natural (height, hash) coordinate, so it uses a fixed
 * (REPAIR_MARKER_TIPFIN_HEIGHT, all-zero hash) — see the kind constants below.
 *
 * ── The `_in_tx` convention (this convention has burned us — read it) ──
 * Every `*_in_tx` entry point REQUIRES the caller to ALREADY own an open
 * transaction on `db` (a BEGIN IMMEDIATE, or a nested savepoint). It issues NO
 * BEGIN/COMMIT of its own — the write enrolls in the caller's transaction and
 * commits / rolls back atomically with it (the saga-atomicity contract shared
 * with progress_meta_set_in_tx). The non-`_in_tx` variants wrap the same op in
 * their OWN batch-aware transaction (a bare BEGIN IMMEDIATE, or a nested
 * SAVEPOINT when the connection is already mid-transaction) and are for own-tx
 * call sites that must NOT be inside a caller transaction. Calling an `_in_tx`
 * variant with no open transaction silently auto-commits per statement
 * (defeating the atomicity the caller expects); calling a non-`_in_tx` variant
 * inside an open transaction nests a savepoint. Match the convention honestly.
 *
 * Threading: every entry point runs SQL on the singleton consensus.db handle,
 * so it needs progress_store_tx_lock(). The `_in_tx` writers assume the caller
 * already holds it (recursive); the own-tx variants and the readers take it
 * internally (recursive — safe from inside a stage transaction). */

#ifndef ZCL_STORAGE_REPAIR_MARKER_H
#define ZCL_STORAGE_REPAIR_MARKER_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Canonical marker kinds ──
 * THE single source of truth shared by the app-level writers/readers AND the
 * one-time migration below. For the three per-(height,hash) namespaces the
 * kind string IS the legacy key prefix (everything before ".<height>.<hash>").
 * The reducer-frontier namespace (2) has a per-repair NAME, so its kind is
 * built dynamically as "reducer_frontier.<name>_repair"; the two names in use
 * are spelled out here for the GC enumeration. */
#define REPAIR_MARKER_KIND_UTXO_VALUE_OVERFLOW   "utxo_apply.value_overflow_repair"
#define REPAIR_MARKER_KIND_COIN_BACKFILL_ROUNDS  "coin_backfill.rounds"
#define REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED "coin_backfill.refused"
#define REPAIR_MARKER_KIND_COIN_BACKFILL_SCAN    "coin_backfill.scan"
#define REPAIR_MARKER_KIND_RF_PROOF_REPLAY   "reducer_frontier.proof_replay_repair"
#define REPAIR_MARKER_KIND_RF_TIPFIN_BACKFILL \
    "reducer_frontier.tipfin_backfill_repair"

/* The singleton tipfin resume witness: fixed (height, hash) coordinate. */
#define REPAIR_MARKER_KIND_TIPFIN_PROGRESS "tipfin_backfill.progress"
#define REPAIR_MARKER_TIPFIN_HEIGHT ((int64_t)0)

/* GC retention margin below H*: markers strictly below (H* - this) are settled
 * (the provable frontier has advanced well past their heights) and safe to
 * reclaim. Conservative so a live near-frontier marker is never touched. */
#define REPAIR_MARKER_GC_RETENTION 1000

/* CREATE TABLE IF NOT EXISTS the repair_marker table. Idempotent; called at
 * store open (progress_store_open). Returns false (logged) on a create error. */
bool repair_marker_table_ensure(sqlite3 *db);

/* One-time, idempotent migration of the four legacy progress_meta marker
 * namespaces into repair_marker: every matching progress_meta row is copied
 * into the table (payload preserved byte-for-byte) and its old key deleted, in
 * bounded transactional batches. Re-running on a half-migrated store converges
 * (INSERT OR REPLACE + delete of any still-present old key). A fresh store with
 * none of the old keys is a clean no-op. Requires the table to exist (call
 * repair_marker_table_ensure first). Own-tx; returns false (logged) on error. */
bool repair_marker_migrate_from_progress_meta(sqlite3 *db);

/* Record (INSERT OR REPLACE) a marker keyed (kind, height, hash). `payload` may
 * be NULL with payload_len 0 for a pure presence marker. `hash32` MUST point at
 * exactly 32 bytes. created_at is stamped to wall-clock seconds. */
bool repair_marker_note_in_tx(sqlite3 *db, const char *kind, int64_t height,
                              const uint8_t hash32[32],
                              const void *payload, size_t payload_len);
bool repair_marker_note(sqlite3 *db, const char *kind, int64_t height,
                        const uint8_t hash32[32],
                        const void *payload, size_t payload_len);

/* Delete one marker. A missing marker is a successful no-op. */
bool repair_marker_forget_in_tx(sqlite3 *db, const char *kind, int64_t height,
                                const uint8_t hash32[32]);
bool repair_marker_forget(sqlite3 *db, const char *kind, int64_t height,
                          const uint8_t hash32[32]);

/* Presence + optional payload read. *out_have := the marker exists. When
 * `payload_out` != NULL and the marker exists, up to `payload_cap` bytes are
 * copied into it and *payload_len is set to the FULL stored payload length
 * (which MAY exceed payload_cap — the caller must check for truncation, exactly
 * like progress_meta_get). An absent marker is a successful read with
 * *out_have=false (and *payload_len=0). Takes the store lock internally.
 * Returns false (logged) only on an infrastructure error. */
bool repair_marker_have(sqlite3 *db, const char *kind, int64_t height,
                        const uint8_t hash32[32], bool *out_have,
                        void *payload_out, size_t payload_cap,
                        size_t *payload_len);

/* Delete every marker of `kind` with height strictly below `below`. Returns the
 * number of rows deleted (>= 0), or -1 (logged) on error. Own-tx. Use ONLY for
 * per-(height, hash) idempotency kinds — NEVER the singleton tipfin witness
 * (its fixed height=0 would be swept away mid-repair). */
int repair_marker_gc_below(sqlite3 *db, const char *kind, int64_t below);

/* GC every per-(height,hash) idempotency kind below the provable-frontier
 * retention margin (`hstar` - REPAIR_MARKER_GC_RETENTION): the six kinds are
 * settled once the frontier has advanced well past their heights. The singleton
 * tipfin witness is deliberately excluded (it self-deletes and its height=0
 * would sit below every margin). A no-op returning 0 when hstar <= the margin.
 * Returns the total rows reclaimed (>= 0), or -1 (logged) on any GC error. */
int repair_marker_gc_settled(sqlite3 *db, int64_t hstar);

#endif /* ZCL_STORAGE_REPAIR_MARKER_H */
