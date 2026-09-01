/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* sync_controller_writers: small, transactional SQLite writers — one
 * per consensus event (wallet-tx, mempool add/remove, sapling note/
 * spend, peer, peer-score, tip set). Each entry point packages its arguments
 * into a context struct, then routes through sync_run_write() for db-service
 * serialization.
 *
 * See sync_controller_internal.h for cross-file glue. */

#include "platform/time_compat.h"
#include "controllers/sync_controller.h"
#include "sync_controller_internal.h"
#include "services/invariant_sentinel.h"
#include "services/recovery_policy.h"
#include "models/db_txn.h"
#include "models/wallet_key.h"
#include "models/wallet_tx.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "chain/chain.h"
#include "wallet/wallet.h"
#include "wallet/keystore.h"
#include "wallet/sapling_keys.h"
#include "keys/key.h"
#include "core/hash.h"
#include "core/serialize.h"
#include "core/utiltime.h"
#include "script/standard.h"
#include "storage/disk_block_io.h"
#include "storage/dbwrapper.h"
#include "storage/coins_db.h"
#include "coins/undo.h"
#include "validation/chainstate.h"
#include "validation/txmempool.h"
#include "sapling/incremental_merkle_tree.h"
#include "sapling/sapling.h"
#include "sapling/note_encryption.h"
#include "support/cleanse.h"
#include "event/event.h"
#include "config/runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#include <pthread.h>
#include <signal.h>
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#define SYNC_PROJECTION_TIP_HASH_KEY   "sync_projection_tip_hash"
#define SYNC_PROJECTION_TIP_HEIGHT_KEY "sync_projection_tip_height"

/* classify_script: use shared utxo_classify_script() from script/standard.h */
#define classify_script utxo_classify_script

struct mempool_add_ctx {
    const struct transaction *tx;
    int64_t fee;
    int height;
    bool ok;
};

struct mempool_remove_ctx {
    const uint8_t *txid;
    bool ok;
};

struct peer_sync_ctx {
    uint8_t ip[16];
    uint16_t port;
    uint64_t services;
    int64_t last_seen;
    bool ok;
};

struct peer_score_ctx {
    uint8_t ip[16];
    uint16_t port;
    uint32_t bandwidth_score;
    bool is_zcl23;
    bool ok;
};

struct tip_set_ctx {
    uint8_t hash[32];
    int height;
    bool ok;
};

struct sapling_note_sync_ctx {
    struct db_sapling_note note;
    bool ok;
};

struct sapling_spend_sync_ctx {
    uint8_t nullifier[32];
    uint8_t spending_txid[32];
    bool ok;                              /* legacy: true iff an indexed note */
    enum db_mark_spent_result result;     /* tri-state for catchup callers    */
};

struct wallet_tx_confirmed_async_ctx {
    struct transaction tx;
    const struct wallet *wallet;
    int block_height;
    uint8_t block_hash[32];
    int64_t block_time;
    bool copied;
};


bool node_db_sync_wallet_tx_local(struct node_db *ndb,
                                  const struct transaction *tx,
                                  const struct wallet *w,
                                  int block_height,
                                  const uint8_t block_hash[32],
                                  int64_t block_time,
                                  bool *is_ours_out)
{
    if (!ndb || !ndb->open || !tx || !w)
        LOG_FAIL("sync", "wallet_tx_local: invalid args (ndb=%p, tx=%p, w=%p)",
                 (void *)ndb, (void *)tx, (void *)w);

    bool is_ours = false;
    bool from_me = false;
    bool write_ok = true;
    int64_t debit = 0;

    /* Track outputs that belong to us */
    for (size_t i = 0; i < tx->num_vout; i++) {
        const struct tx_out *out = &tx->vout[i];
        uint8_t addr_hash[20];
        bool has_addr = false;
        enum script_type stype = classify_script(
            out->script_pub_key.data,
            out->script_pub_key.size,
            addr_hash, &has_addr);

        if (!has_addr) continue;

        /* Check ownership: P2PKH checks keys, P2SH checks scripts */
        bool owned = false;
        struct key_id kid;
        memcpy(kid.id.data, addr_hash, 20);
        if (stype == SCRIPT_P2PKH)
            owned = keystore_have_key(&w->keystore, &kid);
        else if (stype == SCRIPT_P2SH) {
            struct uint160 sh;
            memcpy(sh.data, addr_hash, 20);
            owned = keystore_have_cscript(&w->keystore, &sh);
        }
        if (!owned) continue;

        is_ours = true;

        struct db_wallet_utxo wu;
        memset(&wu, 0, sizeof(wu));
        memcpy(wu.txid, tx->hash.data, 32);
        wu.vout = (uint32_t)i;
        wu.value = out->value;
        memcpy(wu.address_hash, addr_hash, 20);
        wu.script = (uint8_t *)out->script_pub_key.data;
        wu.script_len = out->script_pub_key.size;
        wu.height = block_height;
        wu.is_coinbase = (tx->num_vin == 1 &&
            tx->vin[0].prevout.n == 0xFFFFFFFF);

        if (!db_wallet_utxo_save(ndb, &wu))
            write_ok = false;
    }

    /* Mark inputs that spend our UTXOs.
     * Only mark spent if the UTXO actually exists in wallet_utxos —
     * otherwise we'd silently set is_ours on non-wallet UTXOs. */
    for (size_t i = 0; i < tx->num_vin; i++) {
        struct db_wallet_utxo spent;
        if (db_wallet_utxo_find(ndb,
                tx->vin[i].prevout.hash.data,
                tx->vin[i].prevout.n,
                &spent)) {
            debit += spent.value;
            from_me = true;
            free(spent.script);

            if (!db_wallet_utxo_mark_spent(ndb,
                    tx->vin[i].prevout.hash.data,
                    tx->vin[i].prevout.n,
                    tx->hash.data, (int)i)) {
                write_ok = false;
            }
            is_ours = true;
        }
    }

    /* A pure z->z/z->t transaction has no wallet-owned transparent input or
     * output, but its Sapling nullifier still makes it a wallet transaction.
     * The caller reserves/marks owned notes before invoking this projection. */
    for (size_t i = 0; i < tx->num_shielded_spend && !from_me; i++) {
        if (wallet_sapling_nullifier_is_spent(
                w, tx->v_shielded_spend[i].nullifier.data)) {
            from_me = true;
            is_ours = true;
        }
    }

    /* Only save the full tx if it involves our wallet */
    if (is_ours) {
        size_t raw_len = 0;
        uint8_t *raw = serialize_tx(tx, &raw_len);
        if (raw) {
            struct db_wallet_tx wtx;
            memset(&wtx, 0, sizeof(wtx));
            memcpy(wtx.txid, tx->hash.data, 32);
            wtx.raw_tx = raw;
            wtx.raw_tx_len = raw_len;
            wtx.has_block = (block_height > 0);
            wtx.block_height = block_height;
            if (wtx.has_block) {
                if (block_hash) {
                    memcpy(wtx.block_hash, block_hash, 32);
                    wtx.time_received = block_time > 0
                        ? block_time
                        : (int64_t)platform_time_wall_time_t();
                } else {
                    struct db_block blk;
                    if (db_block_find_by_height(ndb, block_height, &blk)) {
                        memcpy(wtx.block_hash, blk.hash, 32);
                        wtx.time_received = (int64_t)blk.time;
                    } else {
                        wtx.time_received =
                            (int64_t)platform_time_wall_time_t();
                    }
                }
            } else {
                wtx.time_received = (int64_t)platform_time_wall_time_t();
            }
            wtx.from_me = from_me;
            if (from_me) {
                int64_t value_out = transaction_get_value_out(tx);
                wtx.fee = debit > value_out ? (debit - value_out) : 0;
            }
            if (!db_wallet_tx_save(ndb, &wtx))
                write_ok = false;
            free(raw);
        }
    }

    if (is_ours_out)
        *is_ours_out = is_ours;
    return write_ok;
}

bool node_db_sync_wallet_tx_write(struct node_db *ndb, void *ctx)
{
    struct wallet_tx_sync_ctx *sync = ctx;

    if (!sync || !sync->tx || !sync->wallet)
        LOG_FAIL("sync", "wallet_tx_write: invalid ctx (sync=%p)", (void *)sync);
    sync->ok = node_db_sync_wallet_tx_local(ndb,
                                           sync->tx,
                                           sync->wallet,
                                           sync->block_height,
                                           sync->block_hash,
                                           sync->block_time,
                                           &sync->is_ours);
    return true;
}

bool node_db_sync_wallet_tx(struct node_db *ndb,
                            const struct transaction *tx,
                            const struct wallet *w,
                            int block_height)
{
    struct wallet_tx_sync_ctx ctx = {
        .tx = tx,
        .wallet = w,
        .block_height = block_height,
        .block_hash = NULL,
        .block_time = 0,
        .is_ours = false,
        .ok = false,
    };

    if (!ndb || !ndb->open || !tx || !w)
        LOG_FAIL("sync", "sync_wallet_tx: invalid args (ndb=%p, tx=%p, w=%p)",
                 (void *)ndb, (void *)tx, (void *)w);
    return sync_run_write(ndb, node_db_sync_wallet_tx_write, &ctx) &&
           ctx.ok && ctx.is_ours;
}

static bool node_db_sync_wallet_tx_confirmed_async_write(
    struct node_db *ndb, void *opaque)
{
    struct wallet_tx_confirmed_async_ctx *ctx = opaque;
    bool is_ours = false;

    if (!ctx || !ctx->copied || !ctx->wallet)
        LOG_FAIL("sync", "confirmed wallet async write: invalid context");
    return node_db_sync_wallet_tx_local(
        ndb, &ctx->tx, ctx->wallet, ctx->block_height, ctx->block_hash,
        ctx->block_time, &is_ours) && is_ours;
}

static void node_db_sync_wallet_tx_confirmed_async_free(void *opaque)
{
    struct wallet_tx_confirmed_async_ctx *ctx = opaque;

    if (!ctx)
        return;
    if (ctx->copied)
        transaction_free(&ctx->tx);
    free(ctx);
}

bool node_db_sync_wallet_tx_confirmed_async(
    struct node_db *ndb, const struct transaction *tx, const struct wallet *w,
    int block_height, const uint8_t block_hash[32], int64_t block_time)
{
    struct db_service *dbsvc = sync_db_service_for(ndb);
    struct wallet_tx_confirmed_async_ctx *ctx;

    if (!ndb || !ndb->open || !tx || !w || block_height <= 0 ||
        !block_hash)
        LOG_FAIL("sync", "confirmed wallet async enqueue: invalid arguments");
    if (!dbsvc)
        LOG_FAIL("sync", "confirmed wallet async enqueue: DB service unavailable");

    ctx = zcl_calloc(1, sizeof(*ctx), "confirmed wallet async ctx");
    if (!ctx)
        return false;
    transaction_init(&ctx->tx);
    if (!transaction_copy(&ctx->tx, tx)) {
        free(ctx);
        return false;
    }
    ctx->wallet = w;
    ctx->block_height = block_height;
    memcpy(ctx->block_hash, block_hash, sizeof(ctx->block_hash));
    ctx->block_time = block_time;
    ctx->copied = true;

    return db_service_enqueue_write(
        dbsvc, node_db_sync_wallet_tx_confirmed_async_write, ctx,
        node_db_sync_wallet_tx_confirmed_async_free);
}

static bool node_db_sync_mempool_add_local(struct node_db *ndb,
                                           const struct transaction *tx,
                                           int64_t fee, int height)
{
    size_t raw_len = 0;
    uint8_t *raw = NULL;
    struct db_mempool_entry e;

    if (!ndb || !tx || !ndb->open)
        LOG_FAIL("sync", "mempool_add_local: invalid args (ndb=%p, tx=%p)", (void *)ndb, (void *)tx);

    raw = serialize_tx(tx, &raw_len);
    if (!raw)
        LOG_FAIL("sync", "mempool_add_local: serialize_tx returned NULL");

    memset(&e, 0, sizeof(e));
    memcpy(e.txid, tx->hash.data, 32);
    e.raw_tx = raw;
    e.raw_tx_len = raw_len;
    e.fee = fee;
    e.size = (int)raw_len;
    e.time_added = (int64_t)platform_time_wall_time_t();
    e.height_added = height;
    e.spends_coinbase = false;

    {
        bool ok = db_mempool_save(ndb, &e);

        for (size_t i = 0; i < tx->num_vin; i++) {
            db_mempool_add_spend(ndb, tx->hash.data,
                tx->vin[i].prevout.hash.data,
                tx->vin[i].prevout.n);
        }

        free(raw);
        return ok;
    }
}

static bool node_db_sync_mempool_add_write(struct node_db *ndb, void *ctx)
{
    struct mempool_add_ctx *add = ctx;

    if (!add)
        LOG_FAIL("sync", "mempool_add_write: ctx is NULL");
    add->ok = node_db_sync_mempool_add_local(ndb, add->tx,
                                             add->fee, add->height);
    return add->ok;
}

bool node_db_sync_mempool_add(struct node_db *ndb,
                              const struct transaction *tx,
                              int64_t fee, int height)
{
    struct mempool_add_ctx ctx = {
        .tx = tx,
        .fee = fee,
        .height = height,
        .ok = false,
    };

    return sync_run_write(ndb, node_db_sync_mempool_add_write, &ctx) && ctx.ok;
}

static bool node_db_sync_mempool_remove_write(struct node_db *ndb, void *ctx)
{
    struct mempool_remove_ctx *remove = ctx;

    if (!remove || !remove->txid)
        LOG_FAIL("sync", "mempool_remove_write: invalid ctx (remove=%p)", (void *)remove);
    remove->ok = db_mempool_delete(ndb, remove->txid);
    return remove->ok;
}

bool node_db_sync_mempool_remove(struct node_db *ndb,
                                 const uint8_t txid[32])
{
    struct mempool_remove_ctx ctx = {
        .txid = txid,
        .ok = false,
    };

    return sync_run_write(ndb, node_db_sync_mempool_remove_write, &ctx) &&
           ctx.ok;
}

static bool node_db_sync_sapling_note_write(struct node_db *ndb, void *ctx)
{
    struct sapling_note_sync_ctx *note = ctx;

    if (!note)
        LOG_FAIL("sync", "sapling_note_write: ctx is NULL");
    note->ok = db_sapling_note_save(ndb, &note->note);
    return note->ok;
}

bool node_db_sync_sapling_note(struct node_db *ndb,
                               const uint8_t txid[32],
                               uint32_t output_index,
                               int64_t value,
                               const uint8_t rcm[32],
                               const uint8_t memo[512],
                               size_t memo_len,
                               const uint8_t ivk[32],
                               const uint8_t diversifier[11],
                               const uint8_t pk_d[32],
                               const uint8_t cm[32],
                               const uint8_t nullifier[32],
                               int block_height)
{
    struct sapling_note_sync_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    memcpy(ctx.note.txid, txid, 32);
    ctx.note.output_index = output_index;
    ctx.note.value = value;
    memcpy(ctx.note.rcm, rcm, 32);
    if (memo && memo_len > 0) {
        size_t ml = memo_len < 512 ? memo_len : 512;
        memcpy(ctx.note.memo, memo, ml);
        ctx.note.memo_len = ml;
    }
    memcpy(ctx.note.ivk, ivk, 32);
    memcpy(ctx.note.diversifier, diversifier, 11);
    memcpy(ctx.note.pk_d, pk_d, 32);
    memcpy(ctx.note.cm, cm, 32);
    memcpy(ctx.note.nullifier, nullifier, 32);
    ctx.note.block_height = block_height;
    return sync_run_write(ndb, node_db_sync_sapling_note_write, &ctx) && ctx.ok;
}

static bool node_db_sync_sapling_spend_write(struct node_db *ndb, void *ctx)
{
    struct sapling_spend_sync_ctx *spend = ctx;
    sqlite3_stmt *s;

    if (!spend || !ndb || !ndb->open)
        LOG_FAIL("sync", "sapling_spend_write: invalid args (spend=%p, ndb=%p)",
                 (void *)spend, (void *)ndb);

    s = ndb->stmt_nullifier_insert;
    if (!s)
        LOG_FAIL("sync", "sapling_spend_write: nullifier insert stmt missing");
    if (sqlite3_reset(s) != SQLITE_OK)
        LOG_FAIL("sync", "sapling_spend_write: reset failed: %s",
                 sqlite3_errmsg(ndb->db));
    if (sqlite3_bind_blob(s, 1,
                          spend->nullifier,
                          sizeof(spend->nullifier),
                          SQLITE_STATIC) != SQLITE_OK)
        LOG_FAIL("sync", "sapling_spend_write: bind failed: %s",
                 sqlite3_errmsg(ndb->db));
    if (AR_STEP_WRITE(s) != SQLITE_DONE)
        LOG_FAIL("sync", "sapling_spend_write: nullifier insert failed: %s",
                 sqlite3_errmsg(ndb->db));

    spend->result = db_sapling_note_mark_spent(ndb,
                                                  spend->nullifier,
                                                  spend->spending_txid);
    spend->ok = (spend->result == DB_MARK_SPENT_OK);
    /* The write callback succeeds (transaction stays committable) for both
     * OK and the BENIGN not-in-our-index miss. Only a real DB write error
     * fails the callback. The catchup driver inspects ctx.result to decide
     * whether to count a wallet hit; it must NOT abort on NOT_FOUND. */
    return spend->result != DB_MARK_SPENT_ERROR;
}

enum db_mark_spent_result node_db_sync_sapling_spend(
                                struct node_db *ndb,
                                const uint8_t nullifier[32],
                                const uint8_t spending_txid[32])
{
    struct sapling_spend_sync_ctx ctx;

    if (!nullifier || !spending_txid)
        LOG_FAIL("sync", "sapling_spend: nullifier=%p spending_txid=%p",
                 (void *)nullifier, (void *)spending_txid);
    memset(&ctx, 0, sizeof(ctx));
    ctx.result = DB_MARK_SPENT_ERROR;
    memcpy(ctx.nullifier, nullifier, sizeof(ctx.nullifier));
    memcpy(ctx.spending_txid, spending_txid, sizeof(ctx.spending_txid));
    if (!sync_run_write(ndb, node_db_sync_sapling_spend_write, &ctx))
        return DB_MARK_SPENT_ERROR;
    return ctx.result;
}

bool node_db_sync_sapling_spend_bool_compat(struct node_db *ndb,
                                const uint8_t nullifier[32],
                                const uint8_t spending_txid[32])
{
    return node_db_sync_sapling_spend(ndb, nullifier, spending_txid)
           == DB_MARK_SPENT_OK;
}

struct wallet_sapling_spends_ctx {
    const struct transaction *tx;
    size_t marked;
};

static bool node_db_sync_wallet_sapling_spends_write(
    struct node_db *ndb, void *ctx)
{
    struct wallet_sapling_spends_ctx *batch = ctx;
    if (!ndb || !ndb->open || !batch || !batch->tx)
        LOG_FAIL("sync", "wallet_sapling_spends_write: invalid context");

    DB_TXN_SCOPE(txn, ndb, "wallet.sapling_note_reserve");
    if (!txn)
        LOG_FAIL("sync", "wallet_sapling_spends_write: transaction begin failed");

    for (size_t i = 0; i < batch->tx->num_shielded_spend; i++) {
        const uint8_t *nf =
            batch->tx->v_shielded_spend[i].nullifier.data;
        enum db_mark_spent_result r = db_sapling_note_reserve_spend(
            ndb, nf, batch->tx->hash.data);
        /* Every spend in a wallet-authored shielded transaction came from the
         * unspent-note query immediately before construction. NOT_FOUND here
         * is therefore a race/stale selection, not a benign projection miss. */
        if (r != DB_MARK_SPENT_OK)
            LOG_FAIL("sync",
                     "wallet_sapling_spends_write: note %zu mark failed (%d)",
                     i, (int)r);
        batch->marked++;
    }
    if (!db_txn_commit(txn))
        LOG_FAIL("sync", "wallet_sapling_spends_write: transaction commit failed");
    return true;
}

bool node_db_sync_wallet_sapling_spends(
    struct node_db *ndb, const struct transaction *tx)
{
    if (!ndb || !ndb->open || !tx || tx->num_shielded_spend == 0)
        LOG_FAIL("sync", "wallet_sapling_spends: invalid args or no spends");
    struct wallet_sapling_spends_ctx ctx = {
        .tx = tx,
        .marked = 0,
    };
    if (!sync_run_write(ndb, node_db_sync_wallet_sapling_spends_write, &ctx))
        LOG_FAIL("sync", "wallet_sapling_spends: atomic write failed");
    if (ctx.marked != tx->num_shielded_spend)
        LOG_FAIL("sync", "wallet_sapling_spends: marked=%zu expected=%zu",
                 ctx.marked, tx->num_shielded_spend);
    return true;
}

struct wallet_tx_delete_ctx {
    const uint8_t *txid;
    bool ok;
};

static bool node_db_sync_wallet_tx_delete_write(struct node_db *ndb, void *ctx)
{
    struct wallet_tx_delete_ctx *del = ctx;

    if (!ndb || !ndb->open || !del || !del->txid)
        LOG_FAIL("sync", "wallet_tx_delete_write: invalid context");
    if (ndb->sync_in_batch && !node_db_sync_flush(ndb))
        LOG_FAIL("sync", "wallet_tx_delete_write: pending batch flush failed");
    del->ok = db_sapling_note_release_reservation(ndb, del->txid) &&
              db_wallet_tx_delete(ndb, del->txid);
    if (!del->ok)
        LOG_FAIL("sync", "wallet_tx_delete_write: model delete failed");
    return true;
}

bool node_db_sync_wallet_tx_delete(struct node_db *ndb,
                                   const uint8_t txid[32])
{
    struct wallet_tx_delete_ctx ctx = {
        .txid = txid,
        .ok = false,
    };

    if (!ndb || !ndb->open || !txid)
        LOG_FAIL("sync", "wallet_tx_delete: invalid args");
    return sync_run_write(ndb, node_db_sync_wallet_tx_delete_write, &ctx) &&
           ctx.ok;
}

static bool node_db_sync_peer_write(struct node_db *ndb, void *ctx)
{
    struct peer_sync_ctx *peer = ctx;
    struct db_peer p;

    if (!peer)
        LOG_FAIL("sync", "sync_peer_write: ctx is NULL");
    memset(&p, 0, sizeof(p));
    memcpy(p.ip, peer->ip, 16);
    p.port = peer->port;
    p.services = peer->services;
    p.last_seen = peer->last_seen;
    peer->ok = db_peer_save(ndb, &p);
    return peer->ok;
}

bool node_db_sync_peer(struct node_db *ndb,
                       const uint8_t ip[16], uint16_t port,
                       uint64_t services, int64_t last_seen)
{
    struct peer_sync_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    memcpy(ctx.ip, ip, 16);
    ctx.port = port;
    ctx.services = services;
    ctx.last_seen = last_seen;
    return sync_run_write(ndb, node_db_sync_peer_write, &ctx) && ctx.ok;
}

static bool node_db_sync_peer_score_write(struct node_db *ndb, void *ctx)
{
    struct peer_score_ctx *score = ctx;

    if (!score || !ndb || !ndb->open)
        LOG_FAIL("sync", "peer_score_write: invalid args (score=%p, ndb=%p)",
                 (void *)score, (void *)ndb);
    score->ok = db_peer_update_score(ndb, score->ip, score->port,
                                     score->bandwidth_score,
                                     score->is_zcl23);
    return score->ok;
}

bool node_db_sync_peer_score(struct node_db *ndb,
                              const uint8_t ip[16], uint16_t port,
                              uint32_t bandwidth_score, bool is_zcl23)
{
    struct peer_score_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    memcpy(ctx.ip, ip, 16);
    ctx.port = port;
    ctx.bandwidth_score = bandwidth_score;
    ctx.is_zcl23 = is_zcl23;
    return sync_run_write(ndb, node_db_sync_peer_score_write, &ctx) && ctx.ok;
}

int node_db_sync_get_tip_height(struct node_db *ndb)
{
    int64_t h = -1;

    if (!ndb || !ndb->open)
        LOG_ERR("sync", "get_tip_height: ndb invalid (ndb=%p)", (void *)ndb);

    node_db_state_get_int(ndb, SYNC_PROJECTION_TIP_HEIGHT_KEY, &h);
    return (int)h;
}

bool node_db_sync_get_tip_hash(struct node_db *ndb, uint8_t hash_out[32])
{
    size_t len = 0;

    if (!ndb || !hash_out || !ndb->open)
        LOG_FAIL("sync", "get_tip_hash: invalid args (ndb=%p, hash_out=%p)",
                 (void *)ndb, (void *)hash_out);
    if (!node_db_state_get(ndb, SYNC_PROJECTION_TIP_HASH_KEY,
                           hash_out, 32, &len))
        LOG_FAIL("sync", "get_tip_hash: node_db_state_get failed for projection tip hash");
    return len == 32;
}

static bool node_db_sync_set_tip_write(struct node_db *ndb, void *ctx)
{
    struct tip_set_ctx *tip = ctx;

    if (!tip)
        LOG_FAIL("sync", "set_tip_write: ctx is NULL");
    tip->ok = node_db_state_set(ndb, SYNC_PROJECTION_TIP_HASH_KEY,
                                tip->hash, sizeof(tip->hash)) &&
              node_db_state_set_int(ndb, SYNC_PROJECTION_TIP_HEIGHT_KEY,
                                    (int64_t)tip->height);
    return tip->ok;
}

bool node_db_sync_set_tip(struct node_db *ndb,
                          const uint8_t hash[32], int height)
{
    struct tip_set_ctx ctx;

    if (!hash)
        LOG_FAIL("sync", "sync_set_tip: hash is NULL");

    /* Fail-loud validation pack, check 3(b): the served-tip authority pair
     * must self-resolve in the blocks projection before it is persisted.
     * Unknown hash passes (snapshot/import tips land before projection
     * rows); a hash resolving to a DIFFERENT height refuses the write —
     * the blocker + page already fired inside the check. Crash-only. */
    if (!invariant_sentinel_check_pair(ndb, hash, height, "sync_set_tip"))
        return false; // raw-return-ok:invariant_sentinel_check_pair already pages+logs internally

    memset(&ctx, 0, sizeof(ctx));
    memcpy(ctx.hash, hash, sizeof(ctx.hash));
    ctx.height = height;
    return sync_run_write(ndb, node_db_sync_set_tip_write, &ctx) && ctx.ok;
}

static bool node_db_sync_reset_tip_write(struct node_db *ndb, void *ctx)
{
    bool *ok = ctx;
    /* Height sentinel -1 → get_tip_height returns -1 → catchup start = 0
     * (re-walk from genesis). The stale hash blob is harmless; the height
     * key is the authority the catchup driver reads. */
    *ok = node_db_state_set_int(ndb, SYNC_PROJECTION_TIP_HEIGHT_KEY, -1);
    return *ok;
}

bool node_db_sync_reset_tip(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("sync", "sync_reset_tip: ndb invalid (ndb=%p)", (void *)ndb);
    bool ok = false;
    return sync_run_write(ndb, node_db_sync_reset_tip_write, &ok) && ok;
}
