/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_DB_MODEL_BLOCK_H
#define ZCL_DB_MODEL_BLOCK_H

#include "models/database.h"
#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>

struct block_header;

struct db_block {
    uint8_t hash[32];
    int height;
    uint8_t prev_hash[32];
    int32_t version;
    uint8_t merkle_root[32];
    uint32_t time;
    uint32_t bits;
    uint8_t nonce[32];
    uint8_t *solution;
    size_t solution_len;
    uint8_t chain_work[32];
    int status;
    int file_num;
    int data_pos;
    int undo_pos;
    int num_tx;
    uint8_t sapling_root[32];
    uint8_t sprout_root[32];
    int64_t sapling_value;
    int64_t sprout_value;
};

/* Callbacks — register before/after save/destroy hooks */
struct ar_callbacks *db_block_callbacks(void);

/* Validate — runs before save, returns true if valid */
bool db_block_validate(const struct db_block *b, struct ar_errors *errors);

bool db_block_save(struct node_db *ndb, const struct db_block *b);
bool db_block_save_canonical(struct node_db *ndb, const struct db_block *b);
bool db_block_find_by_hash(struct node_db *ndb, const uint8_t hash[32],
                           struct db_block *out);
bool db_block_find_by_height(struct node_db *ndb, int height,
                             struct db_block *out);

/* Load just the Equihash solution BLOB for a connected (status>=3) block
 * at `height` into `out` (up to `max` bytes), setting *out_len. The full
 * read helpers above deliberately drop the solution bytes (only the
 * length is recorded); this is the narrow accessor that materialises the
 * real solution for header re-validation.
 *
 * Returns false on: closed db, no matching connected row, an empty/NULL
 * solution column, or a solution larger than `max`. A false return MUST
 * be treated as "no usable solution" — callers must NOT fabricate or skip
 * Equihash verification on false. */
bool db_block_load_solution_by_height(struct node_db *ndb, int height,
                                      unsigned char *out, size_t *out_len,
                                      size_t max);

/* Load the complete canonical header for a connected (status>=3) block at
 * exactly `(height, hash)`, including the Equihash solution. The loader
 * recomputes the serialized header hash and returns false if the row's
 * header fields do not hash back to `hash`; callers can therefore treat a
 * true return as hash-bound source bytes, not merely a height match. */
bool db_block_load_header_by_hash_height(struct node_db *ndb, int height,
                                         const uint8_t hash[32],
                                         struct block_header *out);

/* Quarantine evidence read: load the RAW stored header (fixed fields + the
 * Equihash solution) for the `blocks` row addressed by `hash` (…_by_hash) or by
 * `height` (…_by_height), with NO status filter and NO hash-bind gate. Unlike
 * db_block_load_header_by_hash_height above — which returns false the moment a
 * row fails to hash-bind and so HIDES the very poison the caller needs to see —
 * these return the header exactly as stored so the caller can run
 * block_row_verify() itself and OBSERVE a hash-bind / PoW / Equihash failure.
 * Used by the runtime poisoned-row quarantine (jobs/stage_repair_row_quarantine).
 *
 * Returns true iff a row exists at that key AND its fixed header fields plus the
 * Equihash solution are structurally usable (solution present, 0 < len <=
 * MAX_SOLUTION_SIZE); false on a closed db, no row, or an empty/oversize
 * solution. …_by_height writes the row's own `hash` column to `out_stored_hash`
 * (zeroed on every non-row path) so the caller can tell a wrong-block row from
 * the canonical one. */
bool db_block_load_raw_header_by_hash(struct node_db *ndb,
                                      const uint8_t hash[32],
                                      struct block_header *out);
bool db_block_load_raw_header_by_height(struct node_db *ndb, int height,
                                        struct block_header *out,
                                        uint8_t out_stored_hash[32]);

bool db_block_delete(struct node_db *ndb, const uint8_t hash[32]);

/* Delete a `blocks` row by height, for the pathological case where the row's
 * `hash` PRIMARY KEY column is itself missing/short so db_block_delete (keyed
 * on a 32-byte hash) cannot address it. Used by the blocks-hydrate per-row
 * quarantine (services/block_index_loader.c) to purge a poisoned header-only
 * row that has no usable hash. Runs through the AR destroy lifecycle. Returns
 * true when the DELETE executed (including the "no such row" case). */
bool db_block_delete_by_height(struct node_db *ndb, int height);
int db_block_max_height(struct node_db *ndb);
/* Max stored block height regardless of block status (no status>=3 filter).
 * The block explorer uses this for its native chain-height fallback when no
 * main_state is attached (e.g. the standalone GTK browser): it wants the
 * highest height present in the `blocks` table irrespective of validation
 * status. Returns -1 when the db is closed or the table is empty, so callers
 * can treat "< 1" as "no chain". */
int db_block_max_height_any_status(struct node_db *ndb);
/* Find the first missing connected block height in the blocks projection up to
 * max_height. A connected row is status>=3, matching db_block_max_height().
 * Returns true for a successful read; *height_out is -1 when no hole exists. */
bool db_block_first_missing_connected_height(struct node_db *ndb,
                                             int max_height,
                                             int *height_out);
int db_block_count(struct node_db *ndb);
bool db_block_update_sapling_tree_data(struct node_db *ndb,
                                       const uint8_t hash[32],
                                       const uint8_t *tree_data,
                                       size_t tree_data_len);

/* Connected-tip height + block time in one read (status>=3), each
 * COALESCE'd to 0 so an empty chain yields 0/0 rather than NULL. Used by
 * the API wallet panel for confirmation/now display. Returns false only
 * when the db is closed; *_out are zeroed on every non-row path. */
bool db_block_tip_height_and_time(struct node_db *ndb,
                                  int64_t *height_out, int64_t *time_out);

/* Prepare a block-file-position scan ordered for sequential blk*.dat I/O.
 * The tx-index job owns file parsing; the Block model owns the blocks-table
 * query shape. Caller finalizes *stmt_out. */
bool db_block_prepare_file_position_scan(sqlite3 *db,
                                         sqlite3_stmt **stmt_out);

/* ── Relationships ─────────────────────────────────────────────── */

/* has_many :transactions — find all txids in this block */
struct db_tx_index;
int db_block_transactions(struct node_db *ndb, const uint8_t hash[32],
                          struct db_tx_index *out, size_t max);

/* has_many :utxos — find UTXOs created in this block */
struct db_utxo;


/* belongs_to :prev_block — find the parent block */
bool db_block_prev(struct node_db *ndb, const struct db_block *b,
                   struct db_block *out);

/* has_one :next_block — find the block at height+1 */
bool db_block_next(struct node_db *ndb, const struct db_block *b,
                   struct db_block *out);

/* scope :hashes_in_range — block hashes for a height range (ASC order).
 * Returns count of hashes written to hashes_out (up to max). */
int db_block_hashes_in_range(struct node_db *ndb,
                             int start_height, int end_height,
                             uint8_t (*hashes_out)[32], size_t max);

#endif
