/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Exact wallet/active-chain lookup while repairable projections catch up. */

#include "controllers/transaction_controller_internal.h"
#include "models/wallet_tx.h"
#include "wallet/wallet.h"

bool rawtx_find_in_wallet_db(struct rawtx_context *ctx,
                             const struct uint256 *hash,
                             struct transaction *tx,
                             struct uint256 *hash_block)
{
    struct node_db *ndb = rawtx_node_db();
    struct db_wallet_tx row;
    memset(&row, 0, sizeof(row));
    if (!ctx || !hash || !tx || !hash_block || !ctx->main_state ||
        !ndb || !ndb->open || !db_wallet_tx_find(ndb, hash->data, &row))
        return false;
    bool active = false;
    if (row.has_block && row.block_height >= 0) {
        zcl_mutex_lock(&ctx->main_state->cs_main);
        struct block_index *bi = active_chain_at(
            &ctx->main_state->chain_active, row.block_height);
        active = bi && bi->phashBlock &&
            memcmp(bi->phashBlock->data, row.block_hash, 32) == 0;
        zcl_mutex_unlock(&ctx->main_state->cs_main);
    }
    struct transaction decoded;
    transaction_init(&decoded);
    struct byte_stream stream;
    stream_init_from_data(&stream, row.raw_tx, row.raw_tx_len);
    bool exact = active && row.raw_tx && row.raw_tx_len > 0 &&
        transaction_deserialize(&decoded, &stream) &&
        stream_remaining(&stream) == 0;
    stream_free(&stream);
    if (exact) {
        transaction_compute_hash(&decoded);
        exact = uint256_eq(&decoded.hash, hash);
    }
    if (exact) {
        transaction_free(tx);
        *tx = decoded;
        decoded.vin = NULL; decoded.vout = NULL;
        decoded.v_shielded_spend = NULL; decoded.v_shielded_output = NULL;
        decoded.v_joinsplit = NULL;
        memcpy(hash_block->data, row.block_hash, 32);
    }
    transaction_free(&decoded);
    db_wallet_tx_free(&row);
    return exact;
}

bool rawtx_find_by_wallet_note(struct rawtx_context *ctx,
                               const struct uint256 *hash,
                               struct transaction *tx,
                               struct uint256 *hash_block)
{
    struct node_db *ndb = rawtx_node_db();
    struct db_sapling_note note;
    memset(&note, 0, sizeof(note));
    if (!ctx || !hash || !tx || !hash_block || !ctx->main_state ||
        !ctx->datadir || !ndb || !ndb->open ||
        db_wallet_tx_notes(ndb, hash->data, &note, 1) != 1)
        return false;
    bool found = false;
    struct block_index *bi = NULL;
    if (note.block_height >= 0) {
        zcl_mutex_lock(&ctx->main_state->cs_main);
        bi = active_chain_at(&ctx->main_state->chain_active,
                             note.block_height);
        zcl_mutex_unlock(&ctx->main_state->cs_main);
    }
    if (bi) {
        struct block blk;
        block_init(&blk);
        if (read_block_from_disk_index(&blk, bi, ctx->datadir)) {
            struct uint256 body_hash;
            block_header_get_hash(&blk.header, &body_hash);
            zcl_mutex_lock(&ctx->main_state->cs_main);
            struct block_index *active = active_chain_at(
                &ctx->main_state->chain_active, note.block_height);
            bool body_is_active = active && active->phashBlock &&
                uint256_eq(active->phashBlock, &body_hash);
            zcl_mutex_unlock(&ctx->main_state->cs_main);
            for (size_t i = 0; body_is_active && i < blk.num_vtx; i++) {
                if (!uint256_eq(&blk.vtx[i].hash, hash))
                    continue;
                transaction_free(tx); transaction_init(tx);
                transaction_copy(tx, &blk.vtx[i]);
                *hash_block = body_hash; found = true; break;
            }
        }
        block_free(&blk);
    }
    db_sapling_note_free(&note);
    memory_cleanse(&note, sizeof(note));
    return found;
}

enum { RAWTX_RECENT_SCAN_BLOCKS = 16 };

bool rawtx_find_in_recent_chain(struct rawtx_context *ctx,
                                const struct uint256 *hash,
                                struct transaction *tx,
                                struct uint256 *hash_block)
{
    if (!ctx || !hash || !tx || !hash_block || !ctx->main_state ||
        !ctx->datadir)
        return false;
    zcl_mutex_lock(&ctx->main_state->cs_main);
    int tip = active_chain_height(&ctx->main_state->chain_active);
    zcl_mutex_unlock(&ctx->main_state->cs_main);
    int floor = tip - RAWTX_RECENT_SCAN_BLOCKS + 1;
    if (floor < 0) floor = 0;
    for (int height = tip; height >= floor; height--) {
        struct block_index *bi = NULL;
        struct uint256 expected_hash;
        uint256_set_null(&expected_hash);
        zcl_mutex_lock(&ctx->main_state->cs_main);
        bi = active_chain_at(&ctx->main_state->chain_active, height);
        if (bi && bi->phashBlock) expected_hash = *bi->phashBlock;
        zcl_mutex_unlock(&ctx->main_state->cs_main);
        if (!bi || uint256_is_null(&expected_hash)) continue;
        struct block blk;
        struct uint256 body_hash;
        block_init(&blk); uint256_set_null(&body_hash);
        bool body_matches = read_block_from_disk_index(
            &blk, bi, ctx->datadir);
        if (body_matches) {
            block_header_get_hash(&blk.header, &body_hash);
            body_matches = uint256_eq(&body_hash, &expected_hash);
        }
        for (size_t i = 0; body_matches && i < blk.num_vtx; i++) {
            if (!uint256_eq(&blk.vtx[i].hash, hash)) continue;
            zcl_mutex_lock(&ctx->main_state->cs_main);
            struct block_index *active = active_chain_at(
                &ctx->main_state->chain_active, height);
            bool still_active = active && active->phashBlock &&
                uint256_eq(active->phashBlock, &body_hash);
            zcl_mutex_unlock(&ctx->main_state->cs_main);
            if (still_active) {
                transaction_free(tx); transaction_init(tx);
                transaction_copy(tx, &blk.vtx[i]);
                *hash_block = body_hash; block_free(&blk); return true;
            }
            break;
        }
        block_free(&blk);
    }
    return false;
}

bool rawtx_find_in_wallet(struct rawtx_context *ctx,
                          const struct uint256 *hash,
                          struct transaction *tx,
                          struct uint256 *hash_block)
{
    struct wallet *wallet = wallet_rpc_wallet();
    struct wallet_tx owned;
    memset(&owned, 0, sizeof(owned));
    if (!ctx || !ctx->main_state || !wallet ||
        !wallet_get_tx_copy(wallet, hash, &owned))
        return false;
    transaction_compute_hash(&owned.tx);
    bool exact = uint256_eq(&owned.tx.hash, hash) &&
        !uint256_is_null(&owned.hash_block);
    if (exact) {
        zcl_mutex_lock(&ctx->main_state->cs_main);
        struct block_index *bi = block_map_find(
            &ctx->main_state->map_block_index, &owned.hash_block);
        exact = bi && active_chain_contains(&ctx->main_state->chain_active, bi);
        zcl_mutex_unlock(&ctx->main_state->cs_main);
    }
    if (exact) {
        transaction_free(tx); *tx = owned.tx;
        transaction_init(&owned.tx); *hash_block = owned.hash_block;
    }
    transaction_free(&owned.tx);
    return exact;
}

int64_t rawtx_confirmations(struct rawtx_context *ctx,
                            const struct uint256 *hash_block)
{
    if (!ctx || !ctx->main_state || !hash_block || uint256_is_null(hash_block))
        return 0;
    int64_t confirmations = 0;
    zcl_mutex_lock(&ctx->main_state->cs_main);
    struct block_index *bi = block_map_find(
        &ctx->main_state->map_block_index, hash_block);
    if (bi && active_chain_contains(&ctx->main_state->chain_active, bi)) {
        int tip = active_chain_height(&ctx->main_state->chain_active);
        if (tip >= bi->nHeight) confirmations = (int64_t)tip - bi->nHeight + 1;
    }
    zcl_mutex_unlock(&ctx->main_state->cs_main);
    return confirmations;
}
