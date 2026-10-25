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
#include "services/chain_nullifier_evidence_service.h"
#include "storage/disk_block_io.h"
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

/* Phase outcomes used by vi_shielded_chain_evidence and its helpers below.
 * The helpers only report which outcome applies; vi_shielded_chain_evidence
 * keeps every log call and owns the decoded transaction cleanup. */
enum vi_intent_decode_result {
    VI_INTENT_DECODE_ALLOC_FAILED = 0,
    VI_INTENT_DECODE_FAILED,
    VI_INTENT_DECODE_TXID_MISMATCH,
    VI_INTENT_DECODE_NO_SHIELDED_SPEND,
    VI_INTENT_DECODE_OK
};

enum vi_nullifier_lookup_result {
    VI_NULLIFIER_LOOKUP_UNAVAILABLE = 0,
    VI_NULLIFIER_LOOKUP_NOT_CONSUMED,
    VI_NULLIFIER_LOOKUP_CONSUMED
};

enum vi_block_scan_result {
    VI_BLOCK_SCAN_UNAVAILABLE = 0,
    VI_BLOCK_SCAN_TX_ABSENT,
    VI_BLOCK_SCAN_TX_PRESENT
};

static bool vi_shielded_evidence_args_present(
    const struct wallet_rpc_context *ctx, const struct vault_intent_row *row,
    const int32_t *height_out, const uint8_t *hash_out,
    const struct wallet_tx *decoded_out)
{
    return ctx && ctx->node_db && ctx->main_state && ctx->datadir && row &&
        row->has_txid && height_out && hash_out && decoded_out;
}

/* Load and decode the durable raw transaction.  Allocation failure leaves
 * *decoded_out untouched; every other path has it zeroed at least. */
static enum vi_intent_decode_result vi_decode_durable_intent_tx(
    struct wallet_rpc_context *ctx, const struct vault_intent_row *row,
    struct wallet_tx *decoded_out)
{
    uint8_t *raw = zcl_malloc(VAULT_INTENT_RAW_MAX,
                              "intent_reconcile_raw_tx");
    if (!raw)
        return VI_INTENT_DECODE_ALLOC_FAILED;
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
    if (!decoded)
        return VI_INTENT_DECODE_FAILED;
    transaction_compute_hash(&decoded_out->tx);
    if (memcmp(decoded_out->tx.hash.data, row->txid, sizeof(row->txid)) != 0)
        return VI_INTENT_DECODE_TXID_MISMATCH;
    if (decoded_out->tx.num_shielded_spend == 0)
        return VI_INTENT_DECODE_NO_SHIELDED_SPEND;
    return VI_INTENT_DECODE_OK;
}

/* Resolve the chain height at which the nullifiers spent by a decoded
 * transaction were consumed, per the canonical nullifier ledger. */
static enum vi_nullifier_lookup_result vi_nullifier_consumption_height(
    struct wallet_tx *decoded, int64_t *height_out)
{
    struct chain_nullifier_query *queries = zcl_calloc(
        decoded->tx.num_shielded_spend, sizeof(*queries),
        "intent_reconcile_nullifier_queries");
    if (!queries)
        return VI_NULLIFIER_LOOKUP_UNAVAILABLE;
    for (size_t i = 0; i < decoded->tx.num_shielded_spend; i++) {
        queries[i].bytes =
            decoded->tx.v_shielded_spend[i].nullifier.data;
    }
    struct chain_nullifier_set_evidence observed;
    struct zcl_result read = chain_nullifier_evidence_lookup_set(
        queries, decoded->tx.num_shielded_spend,
        CHAIN_NULLIFIER_POOL_SAPLING, &observed);
    free(queries);
    if (!read.ok || !observed.heights_consistent)
        return VI_NULLIFIER_LOOKUP_UNAVAILABLE;
    if (!observed.any_found)
        return VI_NULLIFIER_LOOKUP_NOT_CONSUMED;
    int64_t candidate_height = observed.height;
    if (candidate_height < 0 || candidate_height > INT32_MAX)
        return VI_NULLIFIER_LOOKUP_UNAVAILABLE;
    *height_out = candidate_height;
    return VI_NULLIFIER_LOOKUP_CONSUMED;
}

/* Read the active chain block at the consumed height and scan it for the
 * exact durable txid.  On a readable block the height and hash outputs are
 * always populated, even when the txid is absent. */
static enum vi_block_scan_result vi_scan_active_block_for_exact_tx(
    struct wallet_rpc_context *ctx, int64_t candidate_height,
    const struct vault_intent_row *row, int32_t *height_out,
    uint8_t hash_out[32])
{
    zcl_mutex_lock(&ctx->main_state->cs_main);
    struct block_index *bi = active_chain_at(
        &ctx->main_state->chain_active, (int)candidate_height);
    zcl_mutex_unlock(&ctx->main_state->cs_main);
    struct block block;
    block_init(&block);
    if (!bi || !read_block_from_disk_index(&block, bi, ctx->datadir)) {
        block_free(&block);
        return VI_BLOCK_SCAN_UNAVAILABLE;
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
    return exact ? VI_BLOCK_SCAN_TX_PRESENT : VI_BLOCK_SCAN_TX_ABSENT;
}

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
    if (!vi_shielded_evidence_args_present(ctx, row, height_out, hash_out,
                                           decoded_out))
        return VI_SHIELDED_CHAIN_UNAVAILABLE;

    enum vi_intent_decode_result decoded =
        vi_decode_durable_intent_tx(ctx, row, decoded_out);
    if (decoded == VI_INTENT_DECODE_ALLOC_FAILED)
        return VI_SHIELDED_CHAIN_UNAVAILABLE;
    if (decoded == VI_INTENT_DECODE_FAILED) {
        transaction_free(&decoded_out->tx);
        return VI_SHIELDED_CHAIN_UNAVAILABLE;
    }
    if (decoded == VI_INTENT_DECODE_TXID_MISMATCH) {
        LOG_ERROR("vault_intent",
                  "durable raw txid mismatch during shielded reconciliation");
        transaction_free(&decoded_out->tx);
        return VI_SHIELDED_CHAIN_UNAVAILABLE;
    }
    if (decoded == VI_INTENT_DECODE_NO_SHIELDED_SPEND) {
        transaction_free(&decoded_out->tx);
        return VI_SHIELDED_CHAIN_NONE;
    }

    int64_t candidate_height = 0;
    enum vi_nullifier_lookup_result consumed =
        vi_nullifier_consumption_height(decoded_out, &candidate_height);
    if (consumed == VI_NULLIFIER_LOOKUP_UNAVAILABLE) {
        transaction_free(&decoded_out->tx);
        return VI_SHIELDED_CHAIN_UNAVAILABLE;
    }
    if (consumed == VI_NULLIFIER_LOOKUP_NOT_CONSUMED) {
        transaction_free(&decoded_out->tx);
        return VI_SHIELDED_CHAIN_NONE;
    }

    enum vi_block_scan_result scan = vi_scan_active_block_for_exact_tx(
        ctx, candidate_height, row, height_out, hash_out);
    if (scan == VI_BLOCK_SCAN_UNAVAILABLE) {
        transaction_free(&decoded_out->tx);
        return VI_SHIELDED_CHAIN_UNAVAILABLE;
    }
    if (scan == VI_BLOCK_SCAN_TX_ABSENT) {
        transaction_free(&decoded_out->tx);
        return VI_SHIELDED_CHAIN_CONFLICTED;
    }
    decoded_out->used = true;
    decoded_out->from_me = true;
    return VI_SHIELDED_CHAIN_CONFIRMED;
}

static bool vi_refresh_request_valid(const struct wallet_rpc_context *ctx,
                                     const struct vault_intent_row *row)
{
    return ctx && row && row->has_txid;
}

/* True when the wallet projection anchors the tx to a block the active
 * chain still confirms; fills height and confirmations on success. */
static bool vi_wallet_confirms_intent(struct wallet_rpc_context *ctx,
                                      const struct wallet_tx *wtx,
                                      int32_t *height, int32_t *confirmations)
{
    return wtx && !uint256_is_null(&wtx->hash_block) &&
        vault_intent_chain_confirmation(ctx->main_state, wtx->hash_block.data,
                                        height, confirmations);
}

/* Persist the confirmation (or finalization) of an intent and reload the
 * row. */
static void vi_commit_intent_confirmation(struct wallet_rpc_context *ctx,
                                          struct vault_intent_row *row,
                                          int32_t height, int32_t confirmations,
                                          const uint8_t *block_hash,
                                          int64_t now)
{
    enum vault_intent_state state = confirmations >= 6
        ? VAULT_INTENT_FINALIZED : VAULT_INTENT_CONFIRMED;
    if (vault_intent_set_confirmation(ctx->node_db, row->plan_id, state,
            height, block_hash, now))
        (void)vault_intent_find(ctx->node_db, row->plan_id, row);
}

static bool vi_shielded_evidence_confirms_intent(
    struct wallet_rpc_context *ctx, enum vi_shielded_chain_result evidence,
    const uint8_t *evidence_hash, int32_t *height, int32_t *confirmations)
{
    return evidence == VI_SHIELDED_CHAIN_CONFIRMED &&
        vault_intent_chain_confirmation(ctx->main_state, evidence_hash,
                                        height, confirmations);
}

/* vi_shielded_chain_evidence leaves the decoded transaction allocated only
 * when it reports CONFIRMED; release it in that case. */
static void vi_release_shielded_evidence_tx(
    enum vi_shielded_chain_result evidence, struct wallet_tx *evidence_tx)
{
    if (evidence == VI_SHIELDED_CHAIN_CONFIRMED)
        transaction_free(&evidence_tx->tx);
}

/* True when a shielded conflict is proven on the active chain and the
 * intent is still in the local mempool projection. */
static bool vi_shielded_conflict_pending(
    struct wallet_rpc_context *ctx, enum vi_shielded_chain_result evidence,
    const uint8_t *evidence_hash, const struct vault_intent_row *row,
    int32_t *height, int32_t *confirmations)
{
    return evidence == VI_SHIELDED_CHAIN_CONFLICTED &&
        vault_intent_chain_confirmation(ctx->main_state, evidence_hash,
                                        height, confirmations) &&
        row->state == VAULT_INTENT_MEMPOOL_ACCEPTED;
}

/* Decode the durable raw tx for conflict cleanup and flag it as our own
 * spend so the rollback path recognizes it. */
static bool vi_decode_conflict_tx(struct wallet_rpc_context *ctx,
                                  const struct vault_intent_row *row,
                                  struct wallet_tx *conflict)
{
    uint8_t *raw = zcl_malloc(VAULT_INTENT_RAW_MAX,
                              "intent_conflict_raw_tx");
    size_t raw_len = 0;
    memset(conflict, 0, sizeof(*conflict));
    bool loaded = raw && vault_intent_load_raw(ctx->node_db, row->plan_id,
        raw, VAULT_INTENT_RAW_MAX, &raw_len);
    struct byte_stream s;
    bool decoded = false;
    if (loaded) {
        stream_init_from_data(&s, raw, raw_len);
        decoded = transaction_deserialize(&conflict->tx, &s) &&
                  stream_remaining(&s) == 0;
        stream_free(&s);
    }
    free(raw);
    if (!decoded)
        return false;
    transaction_compute_hash(&conflict->tx);
    conflict->used = true;
    conflict->from_me = true;
    return true;
}

/* Roll the wallet projection back, then release the decoded copy. */
static struct zcl_result vi_rollback_wallet_projection(
    struct wallet_rpc_context *ctx, struct wallet_tx *tx)
{
    struct zcl_result rolled = wallet_rollback_persisted_commit(ctx, tx);
    transaction_free(&tx->tx);
    return rolled;
}

/* Persist a terminal state transition and reload the row. */
static void vi_transition_intent_state(struct wallet_rpc_context *ctx,
                                       struct vault_intent_row *row,
                                       enum vault_intent_state state,
                                       const char *reason, int64_t now)
{
    if (vault_intent_set_state(ctx->node_db, row->plan_id, state, row->txid,
                               reason, now))
        (void)vault_intent_find(ctx->node_db, row->plan_id, row);
}

/* True when the wallet still holds the tx as mempool-accepted and the next
 * height would expire it. */
static bool vi_intent_expiry_pending(struct wallet_rpc_context *ctx,
                                     const struct wallet_tx *wtx,
                                     const struct vault_intent_row *row)
{
    return wtx && row->state == VAULT_INTENT_MEMPOOL_ACCEPTED &&
        is_expired_tx(&wtx->tx,
            active_chain_height(&ctx->main_state->chain_active) + 1);
}

static bool vi_intent_reorg_pending(const struct vault_intent_row *row)
{
    return row->state == VAULT_INTENT_CONFIRMED ||
        row->state == VAULT_INTENT_FINALIZED;
}

void vault_intent_refresh_state(struct wallet_rpc_context *ctx,
                                struct vault_intent_row *row, int64_t now)
{
    if (!vi_refresh_request_valid(ctx, row))
        return;
    struct uint256 txid;
    memcpy(txid.data, row->txid, sizeof(row->txid));
    const struct wallet_tx *wtx = wallet_get_tx(ctx->wallet, &txid);
    int32_t height = -1;
    int32_t confirmations = 0;
    if (vi_wallet_confirms_intent(ctx, wtx, &height, &confirmations)) {
        vi_commit_intent_confirmation(ctx, row, height, confirmations,
                                      wtx->hash_block.data, now);
        return;
    }

    /* Fully shielded transactions are not discoverable through the
     * transparent-coins fallback when txindex lags.  Recover the exact body
     * proof from the canonical nullifier height before considering expiry. */
    uint8_t evidence_hash[32];
    struct wallet_tx evidence_tx;
    enum vi_shielded_chain_result evidence = vi_shielded_chain_evidence(
        ctx, row, &height, evidence_hash, &evidence_tx);
    if (vi_shielded_evidence_confirms_intent(ctx, evidence, evidence_hash,
                                             &height, &confirmations)) {
        if (!node_db_sync_confirmed_sapling_spends(
                ctx->node_db, &evidence_tx.tx)) {
            LOG_ERROR("vault_intent",
                      "canonical shielded spend reconciliation failed; "
                      "intent state retained");
            transaction_free(&evidence_tx.tx);
            return;
        }
        transaction_free(&evidence_tx.tx);
        vi_commit_intent_confirmation(ctx, row, height, confirmations,
                                      evidence_hash, now);
        return;
    }
    vi_release_shielded_evidence_tx(evidence, &evidence_tx);
    if (vi_shielded_conflict_pending(ctx, evidence, evidence_hash, row,
                                     &height, &confirmations)) {
        /* The chain consumed at least one deterministic nullifier in a block
         * that does not contain these exact bytes.  Remove the invalid local
         * mempool/wallet projection before releasing its reservation. */
        struct wallet_tx conflict;
        if (!vi_decode_conflict_tx(ctx, row, &conflict)) {
            LOG_ERROR("vault_intent",
                      "shielded conflict decode failed; reservation retained");
            transaction_free(&conflict.tx);
            return;
        }
        struct zcl_result rolled =
            vi_rollback_wallet_projection(ctx, &conflict);
        if (!rolled.ok) {
            LOG_ERROR("vault_intent",
                      "shielded conflict rollback failed (code=%d): %s",
                      rolled.code, rolled.message);
            return;
        }
        vi_transition_intent_state(ctx, row, VAULT_INTENT_CONFLICTED,
                                   "SHIELDED_NULLIFIER_CONFLICT", now);
        return;
    }
    if (vi_intent_expiry_pending(ctx, wtx, row)) {
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
            vi_rollback_wallet_projection(ctx, &expired);
        if (!rolled.ok) {
            LOG_ERROR("vault_intent",
                      "expired transaction rollback failed (code=%d): %s",
                      rolled.code, rolled.message);
            return;
        }
        vi_transition_intent_state(ctx, row, VAULT_INTENT_EXPIRED,
                                   "TX_EXPIRED_UNCONFIRMED", now);
        return;
    }
    if (vi_intent_reorg_pending(row))
        vi_transition_intent_state(ctx, row, VAULT_INTENT_REORGED,
                                   "CONFIRMATION_REORGED", now);
}
