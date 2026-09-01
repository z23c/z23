/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_RUNTIME_H
#define ZCL_RUNTIME_H

#include "config/db_service.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;
struct snapshot_sync_service;
struct tx_mempool;
struct wallet;
struct main_state;
struct coins_view_cache;

struct app_runtime_context {
    struct db_service *db_service;
    struct snapshot_sync_service *snapshot_sync;
    struct tx_mempool *mempool;
    struct wallet *wallet;
    struct main_state *main_state;
    struct coins_view_cache *coins_tip;
};

struct app_runtime_tx_index_hit {
    uint8_t block_hash[32];
    int block_height;
    int tx_index;
    bool used_reversed;
};

/* Runtime registry lifecycle:
 * - boot/config code sets the current runtime during service startup
 * - long-lived consumers may read it while the node is running
 * - shutdown clears it before owned resources are freed
 */
void app_runtime_set_current(struct app_runtime_context *runtime);

struct db_service *app_runtime_db_service(void);
struct node_db *app_runtime_node_db(void);
bool app_runtime_node_db_handle_open(const struct node_db *ndb);
bool app_runtime_node_db_state_set(struct node_db *ndb,
                                   const char *key,
                                   const void *value,
                                   size_t len);
void app_runtime_node_db_sync_flush_if_needed(struct node_db *ndb);
bool app_runtime_node_db_wal_checkpoint(struct node_db *ndb);
int app_runtime_node_db_utxo_max_height(struct node_db *ndb);
bool app_runtime_node_db_tx_index_find(struct node_db *ndb,
                                       const uint8_t txid[32],
                                       struct app_runtime_tx_index_hit *out);
sqlite3 *app_runtime_query_db(void);
struct snapshot_sync_service *app_runtime_snapshot_sync(void);
struct tx_mempool *app_runtime_mempool(void);
struct wallet *app_runtime_wallet(void);
struct main_state *app_runtime_main_state(void);
struct coins_view_cache *app_runtime_coins_tip(void);

#endif
