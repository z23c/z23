/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * address_index — a rebuildable script-appearance PROJECTION.
 *
 * Answers "everything script S ever did" without a full-chain scan. Keyed by
 * the canonical script-hash sha3_256(scriptPubKey) so it catalogs EVERY output
 * uniformly — P2PKH, P2SH, multisig, OP_RETURN (ZNAM / ZSLP), and nonstandard
 * scripts alike, not only the extractable-address subset the explorer
 * `addresses` balance table covers. One row per created output:
 *
 *   (scripthash, txid, vout) -> {height, value, script_type,
 *                                spent_by_txid?, spent_height?}
 *
 * Projection discipline (docs/HOW_THE_NODE_WORKS.md): it is derived from the
 * L0-L2 machine (verified persisted block bodies below the tip_finalize
 * frontier), rebuildable from scratch (drop-and-rederive), carries its own
 * cursor + running SHA3 digest, and is NEVER authoritative for consensus. It is
 * folded strictly in ascending height order, so when a block's spends are
 * applied every output it references (from an equal-or-lower height, including
 * earlier in the same block) is already present — spent-links are always exact.
 *
 * Storage: raw SQLite over the shared progress.kv kernel store, mirroring the
 * created_outputs_index idiom. The caller serializes every DB touch with
 * progress_store_tx_lock()/trylock() (the singleton-handle contract).
 */
#ifndef ZCL_JOBS_ADDRESS_INDEX_H
#define ZCL_JOBS_ADDRESS_INDEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct block;
struct json_value;
typedef struct sqlite3 sqlite3;

/* -addressindex gate (matches -txindex's pattern). Cached after first read.
 * OMNISCIENCE default TRUE: a plain boot builds the script-appearance catalog.
 * Opt OUT with -addressindex=0, which registers NO service and writes NO rows. */
bool address_index_enabled(void);

/* Test-only: clear the cached -addressindex decision so a test can flip the arg
 * (via ParseParameters) and re-observe the gate. Safe to call anytime. */
void address_index_enabled_reset_for_test(void);

/* Canonical appearance key: sha3_256 over the raw scriptPubKey bytes. Total
 * function — every output maps to exactly one 32-byte scripthash. */
void address_index_scripthash(const uint8_t *script, size_t len,
                              uint8_t out[32]);

/* Create the address_index tables + secondary indexes if absent. Idempotent.
 * Returns false on a real SQLite error. Caller holds the tx lock. */
bool address_index_ensure_schema(sqlite3 *db);

/* Drop-and-rederive: delete both tables so a fresh fold from height 0 rebuilds
 * the whole projection. Returns false on a real SQLite error. */
bool address_index_drop(sqlite3 *db);

/* Fold one block at `height`: INSERT OR IGNORE a creation row for every output
 * (preserving any spent link already recorded on a re-fold), then mark every
 * non-coinbase input's referenced output spent. Advances the running digest
 * `digest` (32 bytes, in/out) by chaining the block's deterministic content
 * hash. rows_added_out (nullable) receives the number of creation rows written.
 * Returns false on a real SQLite error (caller -> reset/stall). Caller holds
 * the tx lock and typically wraps a batch of blocks in one transaction. */
bool address_index_put_block(sqlite3 *db, const struct block *blk, int height,
                             uint8_t digest[32], int *rows_added_out);

/* Cursor = highest CONTIGUOUS height fully folded, or -1 when nothing indexed.
 * Returns false on a real SQLite error (missing key is a clean cursor=-1). */
bool address_index_get_cursor(sqlite3 *db, int64_t *cursor_out);

/* Atomically persist cursor + running digest (both in address_index_state).
 * Caller wraps this in the same transaction as the block's row writes. */
bool address_index_set_cursor(sqlite3 *db, int64_t cursor,
                              const uint8_t digest[32]);

/* Load the running digest (32 bytes). *found=false (and a zero digest) when the
 * projection has never been folded. Returns false on a real SQLite error. */
bool address_index_get_digest(sqlite3 *db, uint8_t digest[32], bool *found);

/* Total appearance rows. -1 on error. */
int64_t address_index_row_count(sqlite3 *db);

/* Appearances for one scripthash with height >= from_height, ascending, capped
 * at `limit` rows (bounded). Appends one object per row to `out_arr` (caller
 * inits the array). *balance_out (nullable) receives the confirmed unspent
 * balance across ALL of the scripthash's appearances (not just this page).
 * Returns rows appended, or -1 on error. Caller holds the tx lock. */
int address_index_query_appearances(sqlite3 *db, const uint8_t scripthash[32],
                                    int64_t from_height, int limit,
                                    struct json_value *out_arr,
                                    int64_t *balance_out);

/* Bounded-row cap enforced by the query surface (dumpstate pagination). */
#define ADDRESS_INDEX_QUERY_MAX_ROWS 200

#endif /* ZCL_JOBS_ADDRESS_INDEX_H */
