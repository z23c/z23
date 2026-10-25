/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Exact wallet/active-chain lookup while repairable projections catch up. */

#include "controllers/transaction_controller_internal.h"
#include "models/wallet_tx.h"
#include "wallet/wallet.h"

static bool rawtx_wallet_db_row_missing(struct rawtx_context *ctx,
                                        const struct uint256 *hash,
                                        const struct transaction *tx,
                                        const struct uint256 *hash_block,
                                        struct node_db *ndb,
                                        struct db_wallet_tx *row)
{
    return !ctx || !hash || !tx || !hash_block || !ctx->main_state ||
        !ndb || !ndb->open || !db_wallet_tx_find(ndb, hash->data, row);
}

static bool rawtx_wallet_db_row_is_active(struct rawtx_context *ctx,
                                          const struct db_wallet_tx *row)
{
    bool active = false;
    if (row->has_block && row->block_height >= 0) {
        zcl_mutex_lock(&ctx->main_state->cs_main);
        struct block_index *bi = active_chain_at(
            &ctx->main_state->chain_active, row->block_height);
        active = bi && bi->phashBlock &&
            memcmp(bi->phashBlock->data, row->block_hash, 32) == 0;
        zcl_mutex_unlock(&ctx->main_state->cs_main);
    }
    return active;
}

static bool rawtx_wallet_db_decode_exact(const struct db_wallet_tx *row,
                                         bool active,
                                         const struct uint256 *hash,
                                         struct transaction *decoded)
{
    struct byte_stream stream;
    stream_init_from_data(&stream, row->raw_tx, row->raw_tx_len);
    bool exact = active && row->raw_tx && row->raw_tx_len > 0 &&
        transaction_deserialize(decoded, &stream) &&
        stream_remaining(&stream) == 0;
    stream_free(&stream);
    if (exact) {
        transaction_compute_hash(decoded);
        exact = uint256_eq(&decoded->hash, hash);
    }
    return exact;
}

bool rawtx_find_in_wallet_db(struct rawtx_context *ctx,
                             const struct uint256 *hash,
                             struct transaction *tx,
                             struct uint256 *hash_block)
{
    struct node_db *ndb = rawtx_node_db();
    struct db_wallet_tx row;
    memset(&row, 0, sizeof(row));
    if (rawtx_wallet_db_row_missing(ctx, hash, tx, hash_block, ndb, &row))
        return false;
    bool active = rawtx_wallet_db_row_is_active(ctx, &row);
    struct transaction decoded;
    transaction_init(&decoded);
    bool exact = rawtx_wallet_db_decode_exact(&row, active, hash, &decoded);
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

static bool rawtx_wallet_note_missing(struct rawtx_context *ctx,
                                      const struct uint256 *hash,
                                      const struct transaction *tx,
                                      const struct uint256 *hash_block,
                                      struct node_db *ndb,
                                      struct db_sapling_note *note)
{
    return !ctx || !hash || !tx || !hash_block || !ctx->main_state ||
        !ctx->datadir || !ndb || !ndb->open ||
        db_wallet_tx_notes(ndb, hash->data, note, 1) != 1;
}

static struct block_index *rawtx_note_block_index(struct rawtx_context *ctx,
                                                  int block_height)
{
    struct block_index *bi = NULL;
    if (block_height >= 0) {
        zcl_mutex_lock(&ctx->main_state->cs_main);
        bi = active_chain_at(&ctx->main_state->chain_active, block_height);
        zcl_mutex_unlock(&ctx->main_state->cs_main);
    }
    return bi;
}

static bool rawtx_note_block_scan(struct rawtx_context *ctx,
                                  int block_height,
                                  struct block_index *bi,
                                  const struct uint256 *hash,
                                  struct transaction *tx,
                                  struct uint256 *hash_block)
{
    bool found = false;
    struct block blk;
    block_init(&blk);
    if (read_block_from_disk_index(&blk, bi, ctx->datadir)) {
        struct uint256 body_hash;
        block_header_get_hash(&blk.header, &body_hash);
        zcl_mutex_lock(&ctx->main_state->cs_main);
        struct block_index *active = active_chain_at(
            &ctx->main_state->chain_active, block_height);
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
    return found;
}

bool rawtx_find_by_wallet_note(struct rawtx_context *ctx,
                               const struct uint256 *hash,
                               struct transaction *tx,
                               struct uint256 *hash_block)
{
    struct node_db *ndb = rawtx_node_db();
    struct db_sapling_note note;
    memset(&note, 0, sizeof(note));
    if (rawtx_wallet_note_missing(ctx, hash, tx, hash_block, ndb, &note))
        return false;
    bool found = false;
    struct block_index *bi = rawtx_note_block_index(ctx, note.block_height);
    if (bi)
        found = rawtx_note_block_scan(ctx, note.block_height, bi, hash, tx,
                                      hash_block);
    db_sapling_note_free(&note);
    memory_cleanse(&note, sizeof(note));
    return found;
}

enum { RAWTX_RECENT_SCAN_BLOCKS = 16 };

static bool rawtx_recent_args_missing(struct rawtx_context *ctx,
                                      const struct uint256 *hash,
                                      const struct transaction *tx,
                                      const struct uint256 *hash_block)
{
    return !ctx || !hash || !tx || !hash_block || !ctx->main_state ||
        !ctx->datadir;
}

static int rawtx_recent_chain_tip(struct rawtx_context *ctx)
{
    zcl_mutex_lock(&ctx->main_state->cs_main);
    int tip = active_chain_height(&ctx->main_state->chain_active);
    zcl_mutex_unlock(&ctx->main_state->cs_main);
    return tip;
}

static struct block_index *rawtx_recent_block_index(
    struct rawtx_context *ctx, int height, struct uint256 *expected_hash)
{
    uint256_set_null(expected_hash);
    zcl_mutex_lock(&ctx->main_state->cs_main);
    struct block_index *bi = active_chain_at(&ctx->main_state->chain_active,
                                             height);
    if (bi && bi->phashBlock) *expected_hash = *bi->phashBlock;
    zcl_mutex_unlock(&ctx->main_state->cs_main);
    return bi;
}

static bool rawtx_recent_block_read(struct rawtx_context *ctx,
                                    struct block_index *bi,
                                    const struct uint256 *expected_hash,
                                    struct block *blk,
                                    struct uint256 *body_hash)
{
    block_init(blk); uint256_set_null(body_hash);
    bool body_matches = read_block_from_disk_index(blk, bi, ctx->datadir);
    if (body_matches) {
        block_header_get_hash(&blk->header, body_hash);
        body_matches = uint256_eq(body_hash, expected_hash);
    }
    return body_matches;
}

static bool rawtx_recent_block_scan(struct rawtx_context *ctx,
                                    int height,
                                    struct block *blk,
                                    const struct uint256 *body_hash,
                                    const struct uint256 *hash,
                                    struct transaction *tx,
                                    struct uint256 *hash_block)
{
    for (size_t i = 0; i < blk->num_vtx; i++) {
        if (!uint256_eq(&blk->vtx[i].hash, hash)) continue;
        zcl_mutex_lock(&ctx->main_state->cs_main);
        struct block_index *active = active_chain_at(
            &ctx->main_state->chain_active, height);
        bool still_active = active && active->phashBlock &&
            uint256_eq(active->phashBlock, body_hash);
        zcl_mutex_unlock(&ctx->main_state->cs_main);
        if (still_active) {
            transaction_free(tx); transaction_init(tx);
            transaction_copy(tx, &blk->vtx[i]);
            *hash_block = *body_hash; return true;
        }
        break;
    }
    return false;
}

bool rawtx_find_in_recent_chain(struct rawtx_context *ctx,
                                const struct uint256 *hash,
                                struct transaction *tx,
                                struct uint256 *hash_block)
{
    if (rawtx_recent_args_missing(ctx, hash, tx, hash_block))
        return false;
    int tip = rawtx_recent_chain_tip(ctx);
    int floor = tip - RAWTX_RECENT_SCAN_BLOCKS + 1;
    if (floor < 0) floor = 0;
    for (int height = tip; height >= floor; height--) {
        struct uint256 expected_hash;
        struct block_index *bi = rawtx_recent_block_index(ctx, height,
                                                          &expected_hash);
        if (!bi || uint256_is_null(&expected_hash)) continue;
        struct block blk;
        struct uint256 body_hash;
        bool body_matches = rawtx_recent_block_read(ctx, bi, &expected_hash,
                                                    &blk, &body_hash);
        bool found = body_matches &&
            rawtx_recent_block_scan(ctx, height, &blk, &body_hash, hash, tx,
                                    hash_block);
        block_free(&blk);
        if (found)
            return true;
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
