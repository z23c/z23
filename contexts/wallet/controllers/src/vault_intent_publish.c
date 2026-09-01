/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: restart-safe publication of a prepared vault-intent transaction. */

#include "controllers/vault_intent_publish.h"

#include "controllers/sync_controller.h"
#include "controllers/vault_intent_controller.h"
#include "controllers/wallet_helpers.h"
#include "core/serialize.h"
#include "json/json.h"
#include "models/database.h"
#include "models/vault_intent.h"
#include "models/wallet_tx.h"
#include "net/connman.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "validation/accept_to_mempool.h"
#include "validation/txmempool.h"
#include "wallet/wallet.h"

#include <string.h>

const char *vault_intent_mempool_error_code(int result_code,
                                             const char *message)
{
    /* Detailed tokens originate in accept_to_mempool_detailed() and contain
     * no transaction material.  Preserve the useful shielded/script cases
     * before falling back to the stable result enum. */
    if (message) {
        if (strstr(message, "shielded-requirements-missing"))
            return "SHIELDED_REQUIREMENTS_MISSING";
        if (strstr(message, "transparent-script-invalid"))
            return "TRANSPARENT_SCRIPT_INVALID";
        if (strstr(message, "input-value-invalid"))
            return "INPUT_VALUE_INVALID";
        if (strstr(message, "value-balance-invalid"))
            return "VALUE_BALANCE_INVALID";
    }

    switch (result_code) {
    case -100 - MEMPOOL_ACCEPT_INVALID:        return "MEMPOOL_INVALID";
    case -100 - MEMPOOL_ACCEPT_DUPLICATE:      return "MEMPOOL_DUPLICATE";
    case -100 - MEMPOOL_ACCEPT_CONFLICT:       return "MEMPOOL_CONFLICT";
    case -100 - MEMPOOL_ACCEPT_BELOW_FEE:      return "MEMPOOL_BELOW_FEE";
    case -100 - MEMPOOL_ACCEPT_MISSING_INPUTS: return "MEMPOOL_MISSING_INPUTS";
    case -100 - MEMPOOL_ACCEPT_NONFINAL:       return "MEMPOOL_NONFINAL";
    case -100 - MEMPOOL_ACCEPT_EXPIRING_SOON:  return "MEMPOOL_EXPIRING_SOON";
    case -100 - MEMPOOL_ACCEPT_INTERNAL_ERROR: return "MEMPOOL_INTERNAL_ERROR";
    default:                                   return "MEMPOOL_REJECTED";
    }
}

static void vipub_error(struct json_value *out, const char *code,
                        const char *message)
{
    vault_intent_error_response(out, code, message);
}

static bool vipub_preflight_sapling_notes(struct wallet_rpc_context *ctx,
                                          const uint8_t id[32],
                                          const struct wallet_tx *wtx,
                                          int64_t now,
                                          struct json_value *result)
{
    for (size_t i = 0; i < wtx->tx.num_shielded_spend; i++) {
        enum db_sapling_note_reservation_state state =
            db_sapling_note_reservation_probe(
                ctx->node_db, wtx->tx.v_shielded_spend[i].nullifier.data,
                wtx->tx.hash.data);
        if (state == DB_NOTE_RESERVATION_AVAILABLE ||
            state == DB_NOTE_RESERVATION_SAME_TX)
            continue;
        if (state == DB_NOTE_RESERVATION_MISSING) {
            (void)vault_intent_set_state(ctx->node_db, id,
                VAULT_INTENT_FAILED, wtx->tx.hash.data,
                "PREPARED_NOTE_MISMATCH", now);
            vipub_error(result, "PREPARED_NOTE_MISMATCH",
                "prepared transaction names no current wallet note; create a fresh plan");
            return false;
        }
        if (state == DB_NOTE_RESERVATION_CONFLICT) {
            (void)vault_intent_set_state(ctx->node_db, id,
                VAULT_INTENT_CONFLICTED, wtx->tx.hash.data,
                "PREPARED_NOTE_CONFLICT", now);
            vipub_error(result, "PREPARED_NOTE_CONFLICT",
                "prepared transaction note is reserved by another transaction");
            return false;
        }
        vipub_error(result, "NOTE_RESERVATION_FAILED",
                    "shielded-note reservation state is temporarily unreadable");
        return false;
    }
    return true;
}

bool vault_intent_publish_prepared(struct wallet_rpc_context *ctx,
                                   const uint8_t id[32],
                                   struct wallet_tx *wtx, int64_t now,
                                   struct json_value *result)
{
    if (wtx->tx.num_shielded_spend > 0 &&
        !vipub_preflight_sapling_notes(ctx, id, wtx, now, result))
        return false;
    bool already_durable = wallet_get_tx(ctx->wallet, &wtx->tx.hash) != NULL;
    bool already_admitted = ctx->mempool &&
        tx_mempool_exists(ctx->mempool, &wtx->tx.hash);
    if (!already_durable || !already_admitted) {
        struct zcl_result r = already_durable
            ? wallet_reaccept_from_context(ctx, wtx)
            : wallet_commit_from_context(ctx, wtx);
        if (!r.ok) {
            const char *error_code =
                vault_intent_mempool_error_code(r.code, r.message);
            LOG_ERROR("vault_intent",
                      "prepared transaction mempool admission failed "
                      "(code=%d status=%s): %s",
                      r.code, error_code, r.message);
            /* A first admission failure is terminal. A restart reaccept
             * failure keeps the already-broadcast intent durable so a later
             * current tip/anchor can retry the same bytes. */
            if (!already_durable)
                (void)vault_intent_set_state(ctx->node_db, id,
                    VAULT_INTENT_FAILED, NULL, error_code, now);
            vipub_error(result, error_code, r.message);
            return false;
        }
        if (already_durable)
            LOG_INFO("vault_intent",
                     "restored exact durable transaction to mempool");
        else
            r = wallet_persist_commit_before_relay(ctx, wtx);
        if (!r.ok) {
            (void)vault_intent_set_state(ctx->node_db, id,
                VAULT_INTENT_FAILED, NULL, "PERSISTENCE_FAILED", now);
            vipub_error(result, "PERSISTENCE_FAILED", r.message);
            return false;
        }
    }

    /* A prepared Sapling spend is not publishable until its nullifiers are
     * reserved durably. This runs on retries too: a crash after wallet
     * persistence but before intent-state update resumes the same raw tx. */
    if (wtx->tx.num_shielded_spend > 0 &&
        !node_db_sync_wallet_sapling_spends(ctx->node_db, &wtx->tx)) {
        if (!already_durable) {
            struct zcl_result compensated =
                wallet_rollback_persisted_commit(ctx, wtx);
            if (!compensated.ok)
                LOG_ERROR("vault_intent", "Sapling reservation compensation "
                          "failed (code=%d): %s", compensated.code,
                          compensated.message);
        }
        (void)vault_intent_set_state(ctx->node_db, id, VAULT_INTENT_PROVING,
            wtx->tx.hash.data, "NOTE_RESERVATION_FAILED", now);
        vipub_error(result, "NOTE_RESERVATION_FAILED",
                    "prepared transaction remains durable but shielded notes could not be reserved; retry the same plan");
        return false;
    }
    if (wtx->tx.num_shielded_spend > 0)
        wallet_mark_sapling_nullifiers_spent(ctx->wallet, &wtx->tx);

    if (wallet_ctx_db_ready(ctx) &&
        !node_db_sync_wallet_tx(ctx->node_db, &wtx->tx, ctx->wallet, 0))
        LOG_WARN("vault_intent", "wallet projection write failed for prepared tx");
    if (ctx->connman)
        connman_relay_transaction(ctx->connman, &wtx->tx.hash);
    if (!vault_intent_set_state(ctx->node_db, id,
            VAULT_INTENT_MEMPOOL_ACCEPTED, wtx->tx.hash.data, "", now)) {
        vipub_error(result, "INTENT_STATE_FAILED",
                    "transaction is durable but intent state update failed; retry the same plan");
        return false;
    }
    return true;
}

bool vault_intent_republish_durable(struct wallet_rpc_context *ctx,
                                    const uint8_t id[32], int64_t now,
                                    struct json_value *result)
{
    struct vault_intent_row row;
    if (!ctx || !ctx->node_db || !id ||
        !vault_intent_find(ctx->node_db, id, &row) ||
        row.state != VAULT_INTENT_MEMPOOL_ACCEPTED || !row.has_txid) {
        vipub_error(result, "INTENT_NOT_REPUBLISHABLE",
                    "only a durable mempool-accepted intent can be restored");
        return false;
    }
    struct uint256 expected_txid;
    memcpy(expected_txid.data, row.txid, sizeof(row.txid));
    if (ctx->mempool && tx_mempool_exists(ctx->mempool, &expected_txid))
        return true;

    uint8_t *raw = zcl_malloc(VAULT_INTENT_RAW_MAX,
                              "intent_republish_raw_tx");
    if (!raw) {
        vipub_error(result, "OUT_OF_MEMORY",
                    "durable transaction recovery allocation failed");
        return false;
    }
    size_t raw_len = 0;
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    bool loaded = vault_intent_load_raw(ctx->node_db, id, raw,
                                        VAULT_INTENT_RAW_MAX, &raw_len);
    struct byte_stream stream;
    stream_init_from_data(&stream, raw, raw_len);
    bool decoded = loaded && transaction_deserialize(&wtx.tx, &stream) &&
                   stream_remaining(&stream) == 0;
    stream_free(&stream);
    free(raw);
    if (!decoded) {
        transaction_free(&wtx.tx);
        vipub_error(result, "RAW_TX_CORRUPT",
                    "durable transaction bytes failed to decode");
        return false;
    }
    transaction_compute_hash(&wtx.tx);
    if (memcmp(wtx.tx.hash.data, row.txid, sizeof(row.txid)) != 0) {
        transaction_free(&wtx.tx);
        vipub_error(result, "TXID_MISMATCH",
                    "durable transaction bytes do not match the intent txid");
        return false;
    }
    wtx.time_received = now;
    wtx.from_me = true;
    wtx.used = true;
    bool ok = vault_intent_publish_prepared(ctx, id, &wtx, now, result);
    transaction_free(&wtx.tx);
    return ok;
}
