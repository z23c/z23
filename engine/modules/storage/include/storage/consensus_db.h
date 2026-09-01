/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * consensus_db — the dedicated on-disk home for the reducer's consensus
 * kernel: the tables that MUST commit atomically with each other on the
 * reducer batch-commit path (coins / sprout_anchors / sapling_anchors /
 * anchor_state / nullifiers) together with the progress-cursor rows they
 * are committed with (stage_cursor / progress_meta).
 *
 * WHY A SEPARATE FILE. Today every one of those tables lives in progress.kv,
 * the SAME SQLite file that the projection co-writers (address_index,
 * txindex, created_outputs, census, topology, …) also write. Because a WAL
 * database serialises all writers on ONE journal, a projection fold and the
 * reducer's fsync-bearing batch commit contend for the same write lock — the
 * writer-contention incident class. consensus.db gives the reducer its own
 * WAL so its commit/fsync path stops sharing a journal with the lagging
 * projection writers.
 *
 * KEY INVARIANT (the whole reason the atomic set is enumerated as ONE list):
 * SQLite WAL mode does NOT guarantee cross-database atomicity for a
 * transaction spanning ATTACHed files. Every transaction that must be atomic
 * therefore lives entirely in ONE file. The five kernel tables plus the two
 * progress-cursor tables are the reducer's single atomic set, so they move as
 * ONE unit into consensus.db — never split across files.
 *
 * This module owns the one-time, O(state) (never O(chain)) migration that
 * copies that atomic set out of an existing progress.kv into a fresh
 * consensus.db and PROVES the copy before anyone trusts it: row counts on
 * every kernel table AND the canonical SHA3-256 UTXO commitment over `coins`
 * must match byte-for-byte. On ANY mismatch it refuses — it removes the
 * partial consensus.db and returns false with a typed message — so boot can
 * never proceed on half-migrated consensus state (fail fast, never silently
 * proceed). It is idempotent: a no-op once consensus.db exists, and a clean
 * success when there is no populated progress.kv to migrate (a fresh node,
 * where boot creates consensus.db from scratch). */

#ifndef ZCL_STORAGE_CONSENSUS_DB_H
#define ZCL_STORAGE_CONSENSUS_DB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct sqlite3;

/* THE name for the dedicated consensus-kernel store. No version suffix. */
#define CONSENSUS_DB_FILENAME "consensus.db"

/* The kernel atomic set: the exact tables that commit atomically together on
 * the reducer batch-commit path. Order is stable and used by
 * consensus_db_kernel_stats::table_rows. */
#define CONSENSUS_DB_KERNEL_TABLE_COUNT 7

/* Integrity fingerprint of the consensus kernel in one open database:
 *   coins_commit — the canonical SHA3-256 UTXO commitment over `coins`
 *                  (utxo_commitment.h serialisation; bit-identical to
 *                  coins_kv_commitment).
 *   table_rows   — durable row count of each kernel table, indexed by the
 *                  stable CONSENSUS_DB_KERNEL_TABLE_COUNT ordering. */
struct consensus_db_kernel_stats {
    uint8_t coins_commit[32];
    int64_t table_rows[CONSENSUS_DB_KERNEL_TABLE_COUNT];
};

/* Read the kernel fingerprint of `db`. Requires the `coins` table to exist
 * (the marker of an initialised kernel store); returns false if it does not.
 * A missing OPTIONAL kernel table counts as 0 rows. `db` must NOT have the
 * coins_ram overlay bound (this reads the on-disk `coins` table directly, as
 * it does at boot before the overlay is allocated). errbuf may be NULL. */
bool consensus_db_read_kernel_stats(struct sqlite3 *db,
                                    struct consensus_db_kernel_stats *out,
                                    char *errbuf, size_t errcap);

/* Byte-for-byte equality of two kernel fingerprints. On mismatch returns
 * false and, when errbuf is non-NULL, writes a message naming the diverging
 * component (contains "sha3" for the coins commitment and/or "count" plus the
 * table name for a row count). */
bool consensus_db_kernel_stats_match(const struct consensus_db_kernel_stats *a,
                                     const struct consensus_db_kernel_stats *b,
                                     char *errbuf, size_t errcap);

/* The projection (Class C) tables that STAY in progress.kv — they are written
 * through projection_store (the SECOND handle to progress.kv), NOT the kernel
 * handle, so they must NOT move into consensus.db. Everything else in
 * progress.kv is reached through the kernel handle (progress_store) and MOVES
 * with the flip. Keeping this as the definitive STAY set (rather than an
 * explicit MOVE list) makes the migration completeness-safe: it CANNOT silently
 * miss a kernel table, because "move = every source table not in STAY". */
#define CONSENSUS_DB_PROJECTION_STAY_COUNT 4
#define CONSENSUS_DB_PROJECTION_STAY_NAMES \
    "address_index",                         \
    "address_index_state",                   \
    "txindex",                               \
    "txindex_state"
extern const char *const consensus_db_projection_stay[
    CONSENSUS_DB_PROJECTION_STAY_COUNT];

/* THE dedicated marker key (in consensus.db's progress_meta) that records the
 * kernel store has been physically split into consensus.db. Its presence is the
 * durable "the flip completed" signal. */
#define CONSENSUS_DB_SCHEMA_VERSION_KEY "consensus_schema_version"
#define CONSENSUS_DB_SCHEMA_VERSION     1

/* One-time, O(state) migration of the consensus kernel out of
 * `<datadir>/progress.kv` into a fresh `<datadir>/consensus.db`.
 *
 *   - Idempotent: returns true immediately if consensus.db already exists.
 *   - Fresh node: returns true (no consensus.db created) if there is no
 *     progress.kv, or the progress.kv present has no `coins` table (nothing
 *     to migrate — boot creates consensus.db from scratch).
 *   - Otherwise copies EVERY source table that is not a projection (Class C)
 *     table into consensus.db.tmp: the 7 fingerprinted kernel tables PLUS the
 *     Class B/D tables written inside kernel txs (the stage *_log journals,
 *     utxo_apply_delta, the producer session/receipt rows, …). It then verifies
 *     the copied 7-table fingerprint EQUALS the source AND that every copied
 *     table's row count matches the source, and only then renames it into
 *     place.
 *   - On ANY integrity mismatch (or copy/verify failure) it removes the
 *     partial consensus.db.tmp, leaves progress.kv untouched, and returns
 *     false with a typed message. It NEVER leaves a half-migrated
 *     consensus.db behind.
 *
 * progress.kv is left fully intact — this call only PRODUCES consensus.db;
 * dropping the migrated tables from progress.kv is consensus_db_drop_migrated_
 * from_progress(), run only AFTER the kernel handle has been repointed onto
 * consensus.db. errbuf may be NULL. */
bool consensus_db_migrate_from_progress(const char *datadir,
                                        char *errbuf, size_t errcap);

/* Second half of the flip: idempotently DROP from `<datadir>/progress.kv` every
 * table that was migrated into consensus.db (every table present in BOTH files
 * that is not a projection STAY table), then leave only the Class C projections
 * behind. Crash-safe: DROP TABLE IF EXISTS inside one transaction, re-runs
 * clean. Refuses (returns false) unless a populated consensus.db exists — the
 * kernel authority must already live in consensus.db before its old copy is
 * dropped from progress.kv, so a crash can never leave the kernel homeless.
 *
 * A missing progress.kv (fresh node) is a clean no-op success. errbuf may be
 * NULL. */
bool consensus_db_drop_migrated_from_progress(const char *datadir,
                                              char *errbuf, size_t errcap);

/* Stamp the durable "flip completed" marker (CONSENSUS_DB_SCHEMA_VERSION under
 * CONSENSUS_DB_SCHEMA_VERSION_KEY) into consensus.db's progress_meta. `cdb` is
 * the open consensus.db handle (i.e. progress_store_db() after the repoint).
 * Idempotent (INSERT OR REPLACE). errbuf may be NULL. */
bool consensus_db_write_schema_marker(struct sqlite3 *cdb,
                                      char *errbuf, size_t errcap);

/* True when `cdb`'s durable schema marker names a version NEWER than this
 * binary's CONSENSUS_DB_SCHEMA_VERSION — i.e. this binary is older than the
 * one that last wrote consensus.db (a binary downgrade against a newer
 * datadir). False on a missing/unreadable marker (nothing to compare, not a
 * downgrade) or when the marker is <= the current version (the normal
 * not-yet-flipped or already-flipped cases). `out_marker_version`, if
 * non-NULL, is always set to the marker read (0 if absent/unreadable). On a
 * true return, errbuf (if non-NULL) names both versions and the remedy (run
 * the newer binary). This is a read-only check — it never mutates cdb or
 * progress.kv. */
bool consensus_db_schema_is_downgrade(struct sqlite3 *cdb,
                                      uint32_t *out_marker_version,
                                      char *errbuf, size_t errcap);

/* Second half of the boot flip in one call, run AFTER progress_store has opened
 * consensus.db: drop the migrated tables from progress.kv
 * (consensus_db_drop_migrated_from_progress) then stamp the schema marker into
 * consensus.db (consensus_db_write_schema_marker). Both steps are idempotent +
 * crash-safe and NON-fatal — returns false (with a typed message) on the first
 * failing step so the caller can log-and-continue; consensus.db stays the sole
 * authority regardless. The one EXCEPTION is a downgrade marker
 * (consensus_db_schema_is_downgrade): that is checked FIRST and, if true,
 * this refuses immediately (false + a typed message) WITHOUT touching
 * progress.kv or the marker. In practice a downgrade never reaches this
 * function at all — progress_store_open() (storage/progress_store.h) runs
 * the SAME predicate right after opening consensus.db and refuses the open
 * outright, which boot's existing boot_snapshot_install_gate_boot() FATALs
 * on; this function's own check is defense-in-depth for any other caller.
 * `cdb` is progress_store_db(). errbuf may be NULL. */
bool consensus_db_finalize_flip(const char *datadir, struct sqlite3 *cdb,
                                char *errbuf, size_t errcap);

/* THE filename of the kernel store. After the flip this is consensus.db; a
 * caller that resolves the kernel file by PATH (rather than through the
 * progress_store handle) must use consensus_db_kernel_store_path() so it
 * follows the flip instead of hardcoding progress.kv. */
#define CONSENSUS_DB_LEGACY_KERNEL_FILENAME "progress.kv"

/* Resolve the datadir's kernel store path into out[cap]: `<datadir>/consensus.db`
 * when that file exists, else the legacy `<datadir>/progress.kv`. This is the
 * thin compatibility shim for direct-path kernel readers during the A4 window,
 * so a reader picks up consensus.db post-flip and still works on a
 * pre-flip / legacy datadir. Returns false (out[0]='\0') on a sizing error. */
bool consensus_db_kernel_store_path(const char *datadir, char *out, size_t cap);

#ifdef ZCL_TESTING
/* Test-only instrumentation of the drop path: incremented once each time
 * consensus_db_drop_migrated_from_progress opens progress.kv (the open+ATTACH
 * cycle) and once each time it takes a BEGIN IMMEDIATE write transaction. Lets a
 * test assert that a steady-state consensus_db_finalize_flip short-circuits (no
 * open) and that an already-drained drop takes no write txn (ndrop==0). */
extern _Atomic unsigned long g_consensus_db_drop_pdb_opens;
extern _Atomic unsigned long g_consensus_db_drop_txn_begins;
#endif

#endif /* ZCL_STORAGE_CONSENSUS_DB_H */
