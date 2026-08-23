/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "config/runtime.h"
#include "jobs/stage_repair.h"
#include "models/block.h"
#include "models/database.h"
#include "models/tx_index.h"
#include "services/chain_activation_service.h"
#include "storage/block_index_projection.h"
#include "storage/node_db_runtime.h"
#include "storage/progress_store.h"
#include "util/ar_step_readonly.h"
#include "validation/process_block.h"
#include <limits.h>
#include <string.h>
#include <stddef.h>

static struct app_runtime_context *g_current_runtime = NULL;

void app_runtime_set_current(struct app_runtime_context *runtime)
{
    g_current_runtime = runtime;
}

struct db_service *app_runtime_db_service(void)
{
    if (!g_current_runtime)
        return NULL;
    return g_current_runtime->db_service;
}

struct node_db *app_runtime_node_db(void)
{
    struct db_service *svc = app_runtime_db_service();
    return db_service_node_db(svc);
}

bool app_runtime_node_db_handle_open(const struct node_db *ndb)
{
    return ndb && ndb->open;
}

struct app_runtime_state_set_ctx {
    const char *key;
    const void *value;
    size_t len;
    bool ok;
};

static bool app_runtime_node_db_state_set_write(struct node_db *ndb,
                                                void *ctx)
{
    struct app_runtime_state_set_ctx *s = ctx;
    if (!app_runtime_node_db_handle_open(ndb) || !s || !s->key || !s->value)
        return false;
    if (ndb->sync_in_batch && !node_db_sync_flush(ndb))
        return false;
    s->ok = node_db_state_set(ndb, s->key, s->value, s->len);
    return s->ok;
}

bool app_runtime_node_db_state_set(struct node_db *ndb,
                                   const char *key,
                                   const void *value,
                                   size_t len)
{
    if (!app_runtime_node_db_handle_open(ndb))
        return false;

    struct app_runtime_state_set_ctx ctx = {
        .key = key,
        .value = value,
        .len = len,
        .ok = false,
    };
    struct db_service *svc = app_runtime_db_service();
    if (svc && db_service_is_started(svc) &&
        db_service_node_db(svc) == ndb)
        return db_service_run_write(
            svc, app_runtime_node_db_state_set_write, &ctx) && ctx.ok;
    return app_runtime_node_db_state_set_write(ndb, &ctx);
}

void app_runtime_node_db_sync_flush_if_needed(struct node_db *ndb)
{
    if (app_runtime_node_db_handle_open(ndb) && ndb->sync_in_batch)
        (void)node_db_sync_flush(ndb);
}

bool app_runtime_node_db_wal_checkpoint(struct node_db *ndb)
{
    if (!app_runtime_node_db_handle_open(ndb))
        return false;
    return node_db_wal_checkpoint(ndb);
}

int app_runtime_node_db_utxo_max_height(struct node_db *ndb)
{
    if (!app_runtime_node_db_handle_open(ndb) || !ndb->db)
        return 0;

    sqlite3_stmt *st = NULL;
    int max_height = 0;
    if (sqlite3_prepare_v2(ndb->db, "SELECT MAX(height) FROM utxos",
                           -1, &st, NULL) == SQLITE_OK && st) {
        if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW) {
            sqlite3_int64 h = sqlite3_column_int64(st, 0);
            if (h > INT_MAX)
                max_height = INT_MAX;
            else if (h > 0)
                max_height = (int)h;
        }
        sqlite3_finalize(st);
    }
    return max_height;
}

static bool app_runtime_projection_header_by_hash_height(
    int height, const uint8_t hash[32], struct block_header *out)
{
    block_index_projection_t *projection =
        block_index_projection_singleton();
    if (!projection)
        return false;

    struct disk_block_index disk;
    disk_block_index_init(&disk);
    if (!block_index_projection_get(projection, hash, &disk) ||
        disk.nHeight != height || disk.nSolutionSize == 0 ||
        disk.nSolutionSize > sizeof(out->nSolution))
        return false;

    block_header_init(out);
    out->nVersion = disk.nVersion;
    out->hashPrevBlock = disk.hashPrev;
    out->hashMerkleRoot = disk.hashMerkleRoot;
    out->hashFinalSaplingRoot = disk.hashFinalSaplingRoot;
    out->nTime = disk.nTime;
    out->nBits = disk.nBits;
    out->nNonce = disk.nNonce;
    memcpy(out->nSolution, disk.nSolution, disk.nSolutionSize);
    out->nSolutionSize = disk.nSolutionSize;

    struct uint256 computed;
    block_header_get_hash(out, &computed);
    return memcmp(computed.data, hash, sizeof(computed.data)) == 0;
}

/* node_db_runtime_port.load_header_by_hash_height — the composition root's
 * side of the complete-header read port. A snapshot may intentionally omit
 * old block bodies and node.db rows, while the reducer's hash-bound repair
 * table or the append-only event projection still retains the exact header.
 * Try each existing durable authority without making lib/net depend upward on
 * jobs/config. Every successful source recomputes the serialized header hash.
 *
 * The consensus store is shared with the reducer. Serving is subordinate, so
 * it uses trylock and falls through immediately rather than delaying a reducer
 * transaction. A later peer retry can use the row after contention clears. */
static bool app_runtime_load_header_by_hash_height(
    int height, const uint8_t hash[32], struct block_header *out)
{
    if (!hash || !out || height < 0)
        return false;

    if (db_block_load_header_by_hash_height(app_runtime_node_db(),
                                            height, hash, out))
        return true;

    if (progress_store_tx_trylock()) {
        /* Read the singleton only after taking its lifetime/transaction lock:
         * shutdown exchanges the pointer to NULL under this same lock. */
        sqlite3 *progress_db = progress_store_db();
        struct uint256 expected;
        memcpy(expected.data, hash, sizeof(expected.data));
        bool loaded = progress_db && stage_repair_header_solution_load(
            progress_db, height, &expected, out);
        progress_store_tx_unlock();
        if (loaded)
            return true;
    }

    return app_runtime_projection_header_by_hash_height(height, hash, out);
}

bool app_runtime_node_db_tx_index_find(struct node_db *ndb,
                                       const uint8_t txid[32],
                                       struct app_runtime_tx_index_hit *out)
{
    if (!app_runtime_node_db_handle_open(ndb) || !txid || !out)
        return false;

    struct db_tx_index dbtx;
    memset(&dbtx, 0, sizeof(dbtx));
    bool used_reversed = false;
    if (!db_tx_find_native_or_reversed(ndb, txid, &dbtx, &used_reversed))
        return false;

    memset(out, 0, sizeof(*out));
    memcpy(out->block_hash, dbtx.block_hash, sizeof(out->block_hash));
    out->block_height = dbtx.block_height;
    out->tx_index = dbtx.tx_index;
    out->used_reversed = used_reversed;
    return true;
}

sqlite3 *app_runtime_query_db(void)
{
    struct db_service *svc = app_runtime_db_service();
    return db_service_query_db(svc);
}

struct snapshot_sync_service *app_runtime_snapshot_sync(void)
{
    if (!g_current_runtime)
        return NULL;
    return g_current_runtime->snapshot_sync;
}

struct tx_mempool *app_runtime_mempool(void)
{
    if (!g_current_runtime)
        return NULL;
    return g_current_runtime->mempool;
}

struct wallet *app_runtime_wallet(void)
{
    if (!g_current_runtime)
        return NULL;
    return g_current_runtime->wallet;
}

struct main_state *app_runtime_main_state(void)
{
    if (!g_current_runtime)
        return NULL;
    return g_current_runtime->main_state;
}

struct coins_view_cache *app_runtime_coins_tip(void)
{
    if (!g_current_runtime)
        return NULL;
    return g_current_runtime->coins_tip;
}

/* ── downward wiring for lib/ ────────────────────────────────────────────
 * lib/storage and lib/validation need the live node.db handle and the
 * boot-owned chain-activation controller. config/ composes the process and
 * therefore sits ABOVE lib/; calling back down is fine, being called up by
 * name is not. Each lib/ module declares a port, and this file fills it in
 * with the very functions those call sites used to name directly, so the
 * behaviour is unchanged.
 *
 * A constructor rather than an app_init step: the node and the test runner
 * then get identical wiring with no start-order question, matching what
 * direct calls to these functions already guaranteed. */

static const struct node_db_runtime_port g_node_db_runtime_port = {
    .handle = app_runtime_node_db,
    .handle_open = app_runtime_node_db_handle_open,
    .state_set = app_runtime_node_db_state_set,
    .utxo_max_height = app_runtime_node_db_utxo_max_height,
    .load_header_by_hash_height = app_runtime_load_header_by_hash_height,
};

__attribute__((constructor))
static void app_runtime_register_lib_ports(void)
{
    node_db_runtime_port_set(&g_node_db_runtime_port);
    process_block_set_activation_controller(boot_activation_controller);
}
