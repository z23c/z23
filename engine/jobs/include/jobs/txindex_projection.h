/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * txindex_projection — a rebuildable transaction-location PROJECTION.
 *
 * Answers "where does transaction T live" (its height, block hash, and index
 * within the block) without a full-chain scan, so a getrawtransaction-class
 * lookup can jump straight to the block. One row per transaction:
 *
 *   (txid) -> {height, block_hash, tx_n}
 *
 * Projection discipline (docs/HOW_THE_NODE_WORKS.md): it is derived from the
 * L0-L2 machine (verified persisted block bodies below the tip_finalize
 * frontier H*), rebuildable from scratch (drop-and-rederive), carries its own
 * cursor + running SHA3 digest, and is NEVER authoritative for consensus. It is
 * folded strictly in ascending height order. INSERT OR IGNORE keeps the first
 * (lowest-height) occurrence on a duplicate txid — a deterministic tie-break
 * under the ascending fold — while the running digest folds EVERY appearance,
 * so a full rebuild reproduces the exact same digest.
 *
 * Storage: raw SQLite over the shared progress.kv kernel store, mirroring the
 * address_index / created_outputs_index idiom. The caller serializes every DB
 * touch with progress_store_tx_lock()/trylock() (the singleton-handle
 * contract).
 */
#ifndef ZCL_JOBS_TXINDEX_PROJECTION_H
#define ZCL_JOBS_TXINDEX_PROJECTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct block;
typedef struct sqlite3 sqlite3;

/* -txindex gate (matches address_index's -addressindex pattern). Cached after
 * first read. OMNISCIENCE default TRUE: a plain boot builds the tx-location
 * catalog. Opt OUT with -txindex=0, which registers NO service and writes NO
 * projection rows (the legacy node.db tx_index build is a separate mechanism). */
bool txindex_projection_enabled(void);

/* Test-only: clear the cached -txindex decision so a test can flip the arg (via
 * ParseParameters) and re-observe the gate. Safe to call anytime. */
void txindex_projection_enabled_reset_for_test(void);

/* Create the txindex tables + secondary index if absent. Idempotent. Returns
 * false on a real SQLite error. Caller holds the tx lock. */
bool txindex_projection_ensure_schema(sqlite3 *db);

/* Drop-and-rederive: delete both tables so a fresh fold from height 0 rebuilds
 * the whole projection. Returns false on a real SQLite error. */
bool txindex_projection_drop(sqlite3 *db);

/* Fold one block at `height`: INSERT OR IGNORE a location row for every
 * transaction (preserving any earlier row on a re-fold / duplicate txid), and
 * advance the running digest `digest` (32 bytes, in/out) by chaining the
 * block's deterministic content hash (height + block_hash + each txid + index).
 * `block_hash` is the 32-byte block identity stored alongside each row.
 * rows_added_out (nullable) receives the number of rows actually written.
 * Returns false on a real SQLite error (caller -> reset/stall). Caller holds the
 * tx lock and typically wraps a batch of blocks in one transaction. */
bool txindex_projection_put_block(sqlite3 *db, const struct block *blk,
                                  int height, const uint8_t block_hash[32],
                                  uint8_t digest[32], int *rows_added_out);

/* Cursor = highest CONTIGUOUS height fully folded, or -1 when nothing indexed.
 * Returns false on a real SQLite error (missing key is a clean cursor=-1). */
bool txindex_projection_get_cursor(sqlite3 *db, int64_t *cursor_out);

/* Atomically persist cursor + running digest (both in txindex_state). Caller
 * wraps this in the same transaction as the block's row writes. */
bool txindex_projection_set_cursor(sqlite3 *db, int64_t cursor,
                                   const uint8_t digest[32]);

/* Load the running digest (32 bytes). *found=false (and a zero digest) when the
 * projection has never been folded. Returns false on a real SQLite error. */
bool txindex_projection_get_digest(sqlite3 *db, uint8_t digest[32], bool *found);

/* Total transaction-location rows. -1 on error. */
int64_t txindex_projection_row_count(sqlite3 *db);

/* Locate one transaction by txid. Returns 1 and fills the (nullable) outputs
 * when a row exists, 0 when no row exists, -1 on a real SQLite error. Caller
 * holds the tx lock. `txid` is the internal (little-endian) 32-byte hash, the
 * same representation carried in struct transaction::hash. */
int txindex_projection_lookup(sqlite3 *db, const uint8_t txid[32],
                              int64_t *height_out, uint8_t block_hash_out[32],
                              int64_t *tx_n_out);

#endif /* ZCL_JOBS_TXINDEX_PROJECTION_H */
