/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Wallet-key and mempool persistence helpers for the sync controller. */

#include "controllers/sync_controller.h"
#include "sync_controller_internal.h"

#include "models/mempool_entry.h"
#include "primitives/transaction.h"
#include "validation/accept_to_mempool.h"
#include "validation/txmempool.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* NOTE: there is deliberately NO wallet-key sync here. node.db's
 * wallet_keys / wallet_sapling_keys / wallet_seed secret columns have a
 * single writer — the encryption-aware wallet_sqlite layer
 * (contexts/wallet/modules/wallet/src/wallet_sqlite.c). The old plaintext mirror
 * (node_db_sync_wallet_keys) was removed: it planted unencrypted key
 * material even when the operator set a passphrase. */

struct mempool_save_ctx {
    const struct tx_mempool *mempool;
    int count;
};

static bool node_db_sync_mempool_save_write(struct node_db *ndb, void *ctx)
{
    struct mempool_save_ctx *save = ctx;
    const struct tx_mempool *mempool = save ? save->mempool : NULL;

    if (!ndb->open || !mempool)
        return true;

    int count = 0;
    bool tx_open = false;
    bool ok = true;
    if (!node_db_begin(ndb))
        LOG_FAIL("sync", "mempool_save_write: BEGIN failed");
    tx_open = true;

    for (size_t i = 0; i < mempool->num_entries; i++) {
        const struct mempool_entry *me = &mempool->entries[i];

        size_t raw_len = 0;
        uint8_t *raw = serialize_tx(&me->tx, &raw_len);
        if (!raw) continue;

        struct db_mempool_entry e;
        memset(&e, 0, sizeof(e));
        memcpy(e.txid, me->tx.hash.data, 32);
        e.raw_tx = raw;
        e.raw_tx_len = raw_len;
        e.fee = me->fee;
        e.size = (int)raw_len;
        e.time_added = me->time;
        e.height_added = (int)me->height;
        e.spends_coinbase = me->spends_coinbase;

        if (db_mempool_save(ndb, &e)) {
            count++;
        } else {
            ok = false;
        }
        free(raw);
        if (!ok)
            break;
    }

    if (!ok) {
        if (tx_open)
            node_db_rollback(ndb);
        LOG_FAIL("sync", "mempool_save_write: save failed (count=%d)", count);
    }

    if (!node_db_commit(ndb)) {
        if (tx_open)
            node_db_rollback(ndb);
        LOG_FAIL("sync", "mempool_save_write: COMMIT failed (count=%d)", count);
    }
    if (save)
        save->count = count;
    return true;
}

int node_db_sync_mempool_save(struct node_db *ndb,
                              const struct tx_mempool *mempool)
{
    struct mempool_save_ctx ctx = {.mempool = mempool, .count = 0};

    if (!ndb->open || !mempool) return 0;

    if (!sync_run_write(ndb, node_db_sync_mempool_save_write, &ctx)) {
        LOG_WARN("sync", "SQLite: mempool save failed");
        return 0;
    }

    if (ctx.count > 0)
        printf("SQLite: saved %d mempool transactions\n", ctx.count);
    return ctx.count;
}

struct mempool_load_ctx {
    struct tx_mempool *pool;
    struct coins_view_cache *coins_tip;
    struct main_state *main_state;
    const struct chain_params *params;
    int loaded;
    int rejected;
};

static void mempool_load_cb(const struct db_mempool_entry *e, void *ctx)
{
    struct mempool_load_ctx *lc = (struct mempool_load_ctx *)ctx;

    struct transaction tx;
    transaction_init(&tx);

    struct byte_stream s;
    stream_init_from_data(&s, e->raw_tx, e->raw_tx_len);
    if (!transaction_deserialize(&tx, &s)) {
        transaction_free(&tx);
        return;
    }
    transaction_compute_hash(&tx);

    enum mempool_accept_result ar = accept_to_mempool(
        lc->pool, lc->coins_tip, lc->main_state, lc->params, &tx);
    if (ar == MEMPOOL_ACCEPT_OK)
        lc->loaded++;
    else
        lc->rejected++;

    transaction_free(&tx);
}

int node_db_sync_mempool_load(struct node_db *ndb,
                              struct tx_mempool *mempool,
                              struct coins_view_cache *coins_tip,
                              struct main_state *main_state,
                              const struct chain_params *params)
{
    if (!ndb || !ndb->open || !mempool || !coins_tip || !main_state ||
        !params) {
        LOG_WARN("sync", "mempool_load: incomplete validation context");
        return 0;
    }

    struct mempool_load_ctx ctx = {
        .pool = mempool,
        .coins_tip = coins_tip,
        .main_state = main_state,
        .params = params,
        .loaded = 0,
        .rejected = 0,
    };
    db_mempool_each(ndb, mempool_load_cb, &ctx);

    if (ctx.loaded > 0)
        printf("SQLite: loaded %d mempool transactions\n", ctx.loaded);
    if (ctx.rejected > 0)
        LOG_WARN("sync", "mempool_load: dropped %d stale or invalid rows",
                 ctx.rejected);

    db_mempool_clear(ndb);

    return ctx.loaded;
}
