/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_DB_MODEL_TX_H
#define ZCL_DB_MODEL_TX_H

#include "models/database.h"
#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>

struct db_tx_index {
    uint8_t txid[32];
    uint8_t block_hash[32];
    int block_height;
    int tx_index;
    int file_num;
    int file_pos;
    bool is_coinbase;
};

/* Callbacks and validation */
struct ar_callbacks *db_tx_callbacks(void);
bool db_tx_validate(const struct db_tx_index *t, struct ar_errors *errors);

bool db_tx_save(struct node_db *ndb, const struct db_tx_index *t);
bool db_tx_find(struct node_db *ndb, const uint8_t txid[32],
                struct db_tx_index *out);
bool db_tx_find_native_or_reversed(struct node_db *ndb,
                                   const uint8_t txid[32],
                                   struct db_tx_index *out,
                                   bool *used_reversed);
bool db_tx_delete(struct node_db *ndb, const uint8_t txid[32]);
int db_tx_count(struct node_db *ndb);
bool db_tx_delete_all(struct node_db *ndb);
bool db_tx_prepare_bulk_load(struct node_db *ndb);
bool db_tx_finalize_bulk_load(struct node_db *ndb);
bool db_tx_configure_additive_build(struct node_db *ndb);

/* Find all txids in a block. Returns count, fills out array up to max. */
int db_tx_find_by_block(struct node_db *ndb, const uint8_t block_hash[32],
                        struct db_tx_index *out, size_t max);

/* Look up the value (zatoshis) of a previously-indexed transaction output
 * by its (txid, vout). Reads the tx_index `tx_outputs` table — the block
 * explorer uses it to label a transaction input with the value of the
 * output it spends. Returns true and writes *out_value when a matching
 * row exists; returns false (leaving *out_value untouched) otherwise. */
bool db_tx_output_value(struct node_db *ndb, const uint8_t txid[32],
                        uint32_t vout, int64_t *out_value);

/* ── Relationships ─────────────────────────────────────────────── */

/* belongs_to :block — find the block this tx is in */
struct db_block;
bool db_tx_block(struct node_db *ndb, const struct db_tx_index *t,
                 struct db_block *out);

#endif
