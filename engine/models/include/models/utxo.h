/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_DB_MODEL_UTXO_H
#define ZCL_DB_MODEL_UTXO_H

#include "models/database.h"
#include "models/activerecord.h"
#include "script/standard.h"
#include <stdbool.h>
#include <stdint.h>

struct db_utxo {
    uint8_t txid[32];
    uint32_t vout;
    int64_t value;
    uint8_t *script;
    size_t script_len;
    enum script_type script_type;
    uint8_t address_hash[20];
    bool has_address;
    int height;
    bool is_coinbase;
};

/* Callbacks and validation */
struct ar_callbacks *db_utxo_callbacks(void);
bool db_utxo_validate(const struct db_utxo *u, struct ar_errors *errors);

bool db_utxo_save(struct node_db *ndb, const struct db_utxo *u);
bool db_utxo_find(struct node_db *ndb, const uint8_t txid[32], uint32_t vout,
                  struct db_utxo *out);
bool db_utxo_exists(struct node_db *ndb, const uint8_t txid[32], uint32_t vout);
bool db_utxo_delete(struct node_db *ndb, const uint8_t txid[32], uint32_t vout);

/* Free malloc'd fields (script) after db_utxo_find(). */
void db_utxo_free(struct db_utxo *u);

/* Sum all UTXO values for an address hash. */
int64_t db_utxo_balance_for_address(struct node_db *ndb,
                                     const uint8_t address_hash[20]);

/* List UTXOs for an address. Returns count, fills array up to max. */
int db_utxo_list_for_address(struct node_db *ndb,
                             const uint8_t address_hash[20],
                             struct db_utxo *out, size_t max);

/* Has this address ever appeared on the chain THIS database holds?
 *
 * The "used" oracle behind the BIP44 gap-limit scan a wallet recovery runs
 * (wallet_derive_gap_limited, wallet/wallet.h). Two indexed EXISTS probes,
 * LIMIT 1 each: an unspent output in `utxos`, or any output ever, spent or
 * not, in `tx_outputs`. Both columns are indexed on address_hash, so this
 * is a b-tree seek per address, not a scan.
 *
 * FALSE MEANS "NOT FOUND HERE", NOT "NEVER USED". A datadir with no chain
 * synced, or one whose tx_outputs index was never built, answers false for
 * every address — which is why the gap scan carries an unconditional floor
 * and why its caller reports whether a chain was actually consulted. This
 * function must not be read as proof an address is unused. */
bool db_address_has_chain_history(struct node_db *ndb,
                                  const uint8_t address_hash[20]);

/* Is there any address-indexed chain data here at all — i.e. can
 * db_address_has_chain_history() distinguish "unused" from "unknown"?
 *
 * Asked BEFORE a gap scan so a caller can say which of the two it is
 * working with. On an empty datadir this is false, every address probe
 * would answer false for the same uninformative reason, and the honest
 * report is "no chain consulted", not "no history found". */
bool db_address_index_populated(struct node_db *ndb);

/* Count total UTXOs in the set. */
int64_t db_utxo_count(struct node_db *ndb);

/* Highest height present in the UTXO set, or -1 when the db is closed.
 * Mirrors db_block_max_height(): an empty table yields 0 (the "no utxos yet"
 * floor). Single source of truth for "SELECT MAX(height) FROM utxos". */
int db_utxo_max_height(struct node_db *ndb);

/* Sum total UTXO value in zatoshis. Returns -1 on unavailable DB. */
int64_t db_utxo_total_value(struct node_db *ndb);

/* Count UTXO rows and the distinct creating transaction IDs. */
bool db_utxo_count_rows_and_distinct_txids(struct node_db *ndb,
                                           int64_t *rows_out,
                                           int64_t *distinct_txids_out);

/* Count UTXOs whose imported height could not be decoded but whose value
 * proves they are real spendable outputs. */
int64_t db_utxo_count_missing_heights(struct node_db *ndb);

/* Repair missing imported UTXO heights from the transaction index.
 * Returns sqlite3_changes() on success, or -1 on failure. */
int db_utxo_repair_missing_heights_from_tx_index(struct node_db *ndb);

/* Rebuild derived wallet_utxos and addresses caches from the current UTXO set.
 * Used after bulk chainstate import where the UTXO model is the source of
 * truth and the wallet/explorer tables are read models. */
bool db_utxo_rebuild_wallet_and_address_caches(struct node_db *ndb);
/* Same rebuild statements, but the caller already owns an open node.db
 * transaction. Used when mirror rows, caches, commitment, and cursor must
 * become visible at one commit boundary. */
bool db_utxo_rebuild_wallet_and_address_caches_in_txn(struct node_db *ndb);

/* Re-derive the addresses + wallet_utxos cache rows for a SINGLE address_hash
 * from the authoritative `utxos` table. Used by the incremental (delta) mirror
 * path so that only the addresses touched by a block delta are refreshed,
 * instead of a full-table GROUP BY over every UTXO. Idempotent and always
 * consistent with `utxos` (delete-then-rederive, never +/- arithmetic).
 * MUST be called inside an already-open node.db write transaction. */
bool db_utxo_refresh_caches_for_address(struct node_db *ndb,
                                        const uint8_t address_hash[20]);

/* ── Iteration ─────────────────────────────────────────────────── */

/* Callback for db_utxo_each(). Return true to continue, false to stop.
 * The db_utxo pointer is valid only for the duration of the callback;
 * script points into SQLite's internal buffer (do not free). */
typedef bool (*db_utxo_each_fn)(const struct db_utxo *u, void *ctx);

/* Iterate all UTXOs in canonical (txid, vout) order.
 * Calls fn for each UTXO. Returns number of UTXOs visited.
 * Uses a single cursor on ndb — no separate connection. */
int64_t db_utxo_each(struct node_db *ndb, db_utxo_each_fn fn, void *ctx);

/* ── Bulk Import (fast path for snapshot sync) ────────────────── */

/* Insert a UTXO with no validation, no callbacks, no events.
 * Uses the pre-prepared stmt_utxo_insert. Caller must wrap in
 * BEGIN/COMMIT and set turbo mode. For snapshot bulk import only. */
bool db_utxo_insert_raw(struct node_db *ndb, const struct db_utxo *u);

/* ── Snapshot Serialization ────────────────────────────────────── */

/* Serialize all UTXOs to a binary snapshot file in wire format.
 * File format: sequence of chunks, each: entry_count(4LE) + entries.
 * Each entry: txid(32) + vout(4) + value(8) + height(4) + compact_size + script.
 * Uses db_utxo_each() internally. Returns total UTXOs written.
 * chunk_size = UTXOs per chunk (default 500).
 * If sha3_out is non-NULL, computes SHA3-256 commitment during the same pass
 * to guarantee the hash matches the serialized file contents. */
int64_t db_utxo_serialize_snapshot(struct node_db *ndb,
                                    const char *path, uint32_t chunk_size,
                                    uint8_t sha3_out[32]);

/* ── Relationships ─────────────────────────────────────────────── */

/* belongs_to :transaction — find the tx that created this UTXO */
struct db_tx_index;
bool db_utxo_transaction(struct node_db *ndb, const struct db_utxo *u,
                         struct db_tx_index *out);

#endif
