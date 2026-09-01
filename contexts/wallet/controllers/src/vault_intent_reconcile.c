/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: reconcile durable transaction intents with chain and expiry state. */
// repair-rung-ok:test_wallet_funds_safety

#include "controllers/vault_intent_controller.h"

#include "controllers/sync_controller.h"
#include "controllers/wallet_helpers.h"
#include "chain/chain.h"
#include "core/serialize.h"
#include "models/vault_intent.h"
#include "primitives/block.h"
#include "storage/disk_block_io.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "validation/contextual_check_tx.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"

#include <string.h>

enum vi_shielded_chain_result {
    VI_SHIELDED_CHAIN_NONE = 0,
    VI_SHIELDED_CHAIN_CONFIRMED,
    VI_SHIELDED_CHAIN_CONFLICTED,
    VI_SHIELDED_CHAIN_UNAVAILABLE
};

/* A fully shielded transaction may have no transparent coins row, and the
 * txindex projection is allowed to lag.  In that case wallet_get_tx() cannot
 * prove confirmation even though the consensus nullifier set names the exact
 * block that consumed the note.  Resolve that height through the canonical
 * nullifier ledger, then scan the active block body for the exact durable
 * txid.  Nullifier presence alone is NOT confirmation: a different
 * transaction can spend the same note, so an absent exact txid is a conflict.
 */
static enum vi_shielded_chain_result vi_shielded_chain_evidence(
    struct wallet_rpc_context *ctx, const struct vault_intent_row *row,
    int32_t *height_out, uint8_t hash_out[32], struct wallet_tx *decoded_out)
{
    if (!ctx || !ctx->node_db || !ctx->main_state || !ctx->datadir || !row ||
        !row->has_txid || !height_out || !hash_out || !decoded_out)
        return VI_SHIELDED_CHAIN_UNAVAILABLE;

    uint8_t *raw = zcl_malloc(VAULT_INTENT_RAW_MAX,
                              "intent_reconcile_raw_tx");
    if (!raw)
        return VI_SHIELDED_CHAIN_UNAVAILABLE;
    size_t raw_len = 0;
    memset(decoded_out, 0, sizeof(*decoded_out));
    struct byte_stream stream;
    bool loaded = vault_intent_load_raw(ctx->node_db, row->plan_id, raw,
                                        VAULT_INTENT_RAW_MAX, &raw_len);
    stream_init_from_data(&stream, raw, raw_len);
    bool decoded = loaded &&
        transaction_deserialize(&decoded_out->tx, &stream) &&
        stream_remaining(&stream) == 0;
    stream_free(&stream);
    free(raw);
    if (!decoded) {
        transaction_free(&decoded_out->tx);
        return VI_SHIELDED_CHAIN_UNAVAILABLE;
    }
    transaction_compute_hash(&decoded_out->tx);
    if (memcmp(decoded_out->tx.hash.data, row->txid, sizeof(row->txid)) != 0) {
        LOG_ERROR("vault_intent",
                  "durable raw txid mismatch during shielded reconciliation");
        transaction_free(&decoded_out->tx);
        return VI_SHIELDED_CHAIN_UNAVAILABLE;
    }
    if (decoded_out->tx.num_shielded_spend == 0) {
        transaction_free(&decoded_out->tx);
        return VI_SHIELDED_CHAIN_NONE;
    }

    sqlite3 *db = progress_store_db();
    bool any_found = false;
    bool lookup_ok = db != NULL;
    int64_t candidate_height = -1;
    progress_store_tx_lock();
    for (size_t i = 0; i < decoded_out->tx.num_shielded_spend; i++) {
        bool found = false;
        int64_t height = -1;
        if (!lookup_ok || !nullifier_kv_get(db,
                decoded_out->tx.v_shielded_spend[i].nullifier.data,
                NULLIFIER_POOL_SAPLING, &found, &height)) {
            lookup_ok = false;
            break;
        }
        if (!found)
            continue;
        any_found = true;
        if (candidate_height < 0)
            candidate_height = height;
        else if (candidate_height != height) {
            lookup_ok = false;
            break;
        }
    }
    progress_store_tx_unlock();
    if (!lookup_ok) {
        transaction_free(&decoded_out->tx);
        return VI_SHIELDED_CHAIN_UNAVAILABLE;
    }
    if (!any_found) {
        transaction_free(&decoded_out->tx);
        return VI_SHIELDED_CHAIN_NONE;
    }
    if (candidate_height < 0 || candidate_height > INT32_MAX) {
        transaction_free(&decoded_out->tx);
        return VI_SHIELDED_CHAIN_UNAVAILABLE;
    }

    zcl_mutex_lock(&ctx->main_state->cs_main);
    struct block_index *bi = active_chain_at(
        &ctx->main_state->chain_active, (int)candidate_height);
    zcl_mutex_unlock(&ctx->main_state->cs_main);
    struct block block;
    block_init(&block);
    if (!bi || !read_block_from_disk_index(&block, bi, ctx->datadir)) {
        block_free(&block);
        transaction_free(&decoded_out->tx);
        return VI_SHIELDED_CHAIN_UNAVAILABLE;
    }
    bool exact = false;
    for (size_t i = 0; i < block.num_vtx; i++) {
        transaction_compute_hash(&block.vtx[i]);
        if (memcmp(block.vtx[i].hash.data, row->txid,
                   sizeof(row->txid)) == 0) {
            exact = true;
            break;
        }
    }
    struct uint256 block_hash;
    block_header_get_hash(&block.header, &block_hash);
    *height_out = (int32_t)candidate_height;
    memcpy(hash_out, block_hash.data, 32);
    block_free(&block);
    if (!exact) {
        transaction_free(&decoded_out->tx);
        return VI_SHIELDED_CHAIN_CONFLICTED;
    }
    decoded_out->used = true;
    decoded_out->from_me = true;
    return VI_SHIELDED_CHAIN_CONFIRMED;
}

void vault_intent_refresh_state(struct wallet_rpc_context *ctx,
                                struct vault_intent_row *row, int64_t now)
{
    if (!ctx || !row || !row->has_txid)
        return;
    struct uint256 txid;
    memcpy(txid.data, row->txid, sizeof(row->txid));
    const struct wallet_tx *wtx = wallet_get_tx(ctx->wallet, &txid);
    int32_t height = -1;
    int32_t confirmations = 0;
    if (wtx && !uint256_is_null(&wtx->hash_block) &&
        vault_intent_chain_confirmation(ctx->main_state,
            wtx->hash_block.data, &height, &confirmations)) {
        enum vault_intent_state state = confirmations >= 6
            ? VAULT_INTENT_FINALIZED : VAULT_INTENT_CONFIRMED;
        if (vault_intent_set_confirmation(ctx->node_db, row->plan_id, state,
                height, wtx->hash_block.data, now))
            (void)vault_intent_find(ctx->node_db, row->plan_id, row);
        return;
    }

    /* Fully shielded transactions are not discoverable through the
     * transparent-coins fallback when txindex lags.  Recover the exact body
     * proof from the canonical nullifier height before considering expiry. */
    uint8_t evidence_hash[32];
    struct wallet_tx evidence_tx;
    enum vi_shielded_chain_result evidence = vi_shielded_chain_evidence(
        ctx, row, &height, evidence_hash, &evidence_tx);
    if (evidence == VI_SHIELDED_CHAIN_CONFIRMED &&
        vault_intent_chain_confirmation(ctx->main_state, evidence_hash,
                                        &height, &confirmations)) {
        enum vault_intent_state state = confirmations >= 6
            ? VAULT_INTENT_FINALIZED : VAULT_INTENT_CONFIRMED;
        if (!node_db_sync_confirmed_sapling_spends(
                ctx->node_db, &evidence_tx.tx)) {
            LOG_ERROR("vault_intent",
                      "canonical shielded spend reconciliation failed; "
                      "intent state retained");
            transaction_free(&evidence_tx.tx);
            return;
        }
        transaction_free(&evidence_tx.tx);
        if (vault_intent_set_confirmation(ctx->node_db, row->plan_id, state,
                height, evidence_hash, now))
            (void)vault_intent_find(ctx->node_db, row->plan_id, row);
        return;
    }
    if (evidence == VI_SHIELDED_CHAIN_CONFIRMED)
        transaction_free(&evidence_tx.tx);
    if (evidence == VI_SHIELDED_CHAIN_CONFLICTED &&
        vault_intent_chain_confirmation(ctx->main_state, evidence_hash,
                                        &height, &confirmations) &&
        row->state == VAULT_INTENT_MEMPOOL_ACCEPTED) {
        /* The chain consumed at least one deterministic nullifier in a block
         * that does not contain these exact bytes.  Remove the invalid local
         * mempool/wallet projection before releasing its reservation. */
        uint8_t *raw = zcl_malloc(VAULT_INTENT_RAW_MAX,
                                  "intent_conflict_raw_tx");
        size_t raw_len = 0;
        struct wallet_tx conflict;
        memset(&conflict, 0, sizeof(conflict));
        bool loaded = raw && vault_intent_load_raw(ctx->node_db, row->plan_id,
            raw, VAULT_INTENT_RAW_MAX, &raw_len);
        struct byte_stream s;
        bool decoded = false;
        if (loaded) {
            stream_init_from_data(&s, raw, raw_len);
            decoded = transaction_deserialize(&conflict.tx, &s) &&
                      stream_remaining(&s) == 0;
            stream_free(&s);
        }
        free(raw);
        if (!decoded) {
            LOG_ERROR("vault_intent",
                      "shielded conflict decode failed; reservation retained");
            transaction_free(&conflict.tx);
            return;
        }
        transaction_compute_hash(&conflict.tx);
        conflict.used = true;
        conflict.from_me = true;
        struct zcl_result rolled =
            wallet_rollback_persisted_commit(ctx, &conflict);
        transaction_free(&conflict.tx);
        if (!rolled.ok) {
            LOG_ERROR("vault_intent",
                      "shielded conflict rollback failed (code=%d): %s",
                      rolled.code, rolled.message);
            return;
        }
        if (vault_intent_set_state(ctx->node_db, row->plan_id,
                VAULT_INTENT_CONFLICTED, row->txid,
                "SHIELDED_NULLIFIER_CONFLICT", now))
            (void)vault_intent_find(ctx->node_db, row->plan_id, row);
        return;
    }
    if (wtx && row->state == VAULT_INTENT_MEMPOOL_ACCEPTED &&
        is_expired_tx(&wtx->tx,
            active_chain_height(&ctx->main_state->chain_active) + 1)) {
        struct wallet_tx expired;
        memset(&expired, 0, sizeof(expired));
        transaction_init(&expired.tx);
        if (!transaction_copy(&expired.tx, &wtx->tx)) {
            LOG_ERROR("vault_intent",
                      "expired transaction copy failed; reservation retained");
            transaction_free(&expired.tx);
            return;
        }
        expired.used = true;
        struct zcl_result rolled =
            wallet_rollback_persisted_commit(ctx, &expired);
        transaction_free(&expired.tx);
        if (!rolled.ok) {
            LOG_ERROR("vault_intent",
                      "expired transaction rollback failed (code=%d): %s",
                      rolled.code, rolled.message);
            return;
        }
        if (vault_intent_set_state(ctx->node_db, row->plan_id,
                VAULT_INTENT_EXPIRED, row->txid,
                "TX_EXPIRED_UNCONFIRMED", now))
            (void)vault_intent_find(ctx->node_db, row->plan_id, row);
        return;
    }
    if (row->state == VAULT_INTENT_CONFIRMED ||
        row->state == VAULT_INTENT_FINALIZED) {
        if (vault_intent_set_state(ctx->node_db, row->plan_id,
                VAULT_INTENT_REORGED, row->txid,
                "CONFIRMATION_REORGED", now))
            (void)vault_intent_find(ctx->node_db, row->plan_id, row);
    }
}
