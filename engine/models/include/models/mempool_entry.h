/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_DB_MODEL_MEMPOOL_H
#define ZCL_DB_MODEL_MEMPOOL_H

#include "models/database.h"
#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>

struct db_mempool_entry {
    uint8_t txid[32];
    uint8_t *raw_tx;
    size_t raw_tx_len;
    int64_t fee;
    int size;
    int64_t time_added;
    int height_added;
    bool spends_coinbase;
};

/* Callbacks and validation */
struct ar_callbacks *db_mempool_callbacks(void);
bool db_mempool_validate(const struct db_mempool_entry *e,
                         struct ar_errors *errors);

bool db_mempool_save(struct node_db *ndb, const struct db_mempool_entry *e);

bool db_mempool_delete(struct node_db *ndb, const uint8_t txid[32]);
int db_mempool_count(struct node_db *ndb);
int64_t db_mempool_total_fee(struct node_db *ndb);

/* Remove all mempool entries (on reorg). */
bool db_mempool_clear(struct node_db *ndb);

/* Check if an outpoint is spent by a mempool tx. */
bool db_mempool_is_spent(struct node_db *ndb,
                         const uint8_t txid[32], uint32_t vout);

/* Record that a mempool tx spends an outpoint. */
bool db_mempool_add_spend(struct node_db *ndb,
                          const uint8_t spending_txid[32],
                          const uint8_t spent_txid[32], uint32_t spent_vout);

/* Remove spend records for a mempool tx. */
bool db_mempool_remove_spends(struct node_db *ndb, const uint8_t txid[32]);

/* Load all mempool entries via callback. */
typedef void (*mempool_entry_cb)(const struct db_mempool_entry *e, void *ctx);
int db_mempool_each(struct node_db *ndb, mempool_entry_cb cb, void *ctx);

#endif
