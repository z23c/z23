/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * File-market payment reconciliation service. Signed P2P claims are locators;
 * exact locally-decrypted Sapling notes plus the canonical transaction/block
 * projections are the only authority that can unlock a paid chunk. */

#include "services/file_market_payment_service.h"

#include "base/log_macros.h"
#include "chain/chainparams.h"
#include "models/file_offer.h"
#include "sapling/sapling.h"
#include "validation/main_state.h"
#include "wallet/sapling_keys.h"

#include <stdio.h>
#include <string.h>

#define MARKET_PAYMENT_CANDIDATE_MAX 8

static void market_payment_set_status(
    struct market_payment_claim_record *record, const char *status,
    const char *reason, int64_t now_unix)
{
    snprintf(record->status, sizeof(record->status), "%s", status);
    snprintf(record->status_reason, sizeof(record->status_reason), "%s",
             reason);
    record->reconciled_at = now_unix;
    if (strcmp(status, "CONFIRMED") != 0) {
        record->output_index = -1;
        record->block_height = 0;
        record->confirmations = 0;
    }
}

static struct zcl_result market_payment_persist(
    struct node_db *ndb, const struct market_payment_claim_record *record)
{
    if (!db_market_payment_claim_save(ndb, record))
        return ZCL_ERR(-20, "file-market payment claim persistence failed");
    return ZCL_OK;
}

/* An expired offer's claims are settlement evidence only. Drop its
 * non-CONFIRMED rows on the next ingest that touches the offer so unconfirmed
 * locators cannot outlive the offer window and grow the projection without
 * bound; CONFIRMED rows always survive. */
static void market_payment_prune_expired_claims(
    struct node_db *ndb, const struct file_offer *offer, int64_t now_unix)
{
    if (now_unix < offer->expires_unix)
        return;
    int pruned = db_market_payment_claim_prune_unconfirmed_for_offer(
        ndb, offer->offer_id);
    if (pruned > 0)
        LOG_INFO("market", "pruned %d unconfirmed claim(s) of an expired offer",
                 pruned);
}

static struct zcl_result market_payment_reconcile_record(
    struct node_db *ndb, struct main_state *main_state,
    bool chain_current, int wallet_projection_height, int64_t now_unix,
    struct market_payment_claim_record *record)
{
    if (!ndb || !ndb->open || !main_state || !record || now_unix <= 0)
        return ZCL_ERR(-1, "open database, chain state, record, and time required");
    enum file_payment_auth_error auth = file_payment_auth_verify_for_offer(
        &record->payment, &record->offer);
    if (auth != FILE_PAYMENT_AUTH_OK)
        return ZCL_ERR(-2, "payment claim contract invalid: %s",
                       file_payment_auth_error_string(auth));

    const struct chain_params *params = chain_params_get();
    if (!params || memcmp(record->payment.network_genesis,
                          params->consensus.hashGenesisBlock.data, 32) != 0) {
        market_payment_set_status(record, "CONFLICTED",
                                  "claim network does not match this node",
                                  now_unix);
        ZCL_CHECK(market_payment_persist(ndb, record));
        return ZCL_OK;
    }
    if (!chain_current) {
        market_payment_set_status(record, "UNKNOWN",
                                  "chain state is not current", now_unix);
        ZCL_CHECK(market_payment_persist(ndb, record));
        return ZCL_OK;
    }

    struct block_index *tip = active_chain_tip(&main_state->chain_active);
    if (!tip) {
        market_payment_set_status(record, "UNKNOWN",
                                  "active chain tip is unavailable", now_unix);
        ZCL_CHECK(market_payment_persist(ndb, record));
        return ZCL_OK;
    }
    if (wallet_projection_height != tip->nHeight) {
        market_payment_set_status(record, "UNKNOWN",
                                  "wallet projection is not at the active tip",
                                  now_unix);
        ZCL_CHECK(market_payment_persist(ndb, record));
        return ZCL_OK;
    }

    char seller_address[256] = {0};
    if (!sapling_encode_payment_address(
            record->offer.z_addr, record->offer.z_addr + 11,
            params->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
            seller_address, sizeof(seller_address)))
        return ZCL_ERR(-3, "seller Sapling address encoding failed");
    uint8_t memo[FILE_MARKET_PAYMENT_MEMO_BYTES];
    auth = file_payment_memo_encode(&record->payment, memo);
    if (auth != FILE_PAYMENT_AUTH_OK)
        return ZCL_ERR(-4, "payment memo construction failed: %s",
                       file_payment_auth_error_string(auth));

    struct market_payment_authority_observation observed;
    enum market_payment_authority_state state =
        db_market_payment_observe_authority(
            ndb, &record->payment, seller_address, memo, tip->nHeight,
            tip->hashBlock.data, &observed);
    if (state == MARKET_PAYMENT_AUTHORITY_UNKNOWN) {
        market_payment_set_status(record, "UNKNOWN",
                                  "wallet or canonical projection is incomplete",
                                  now_unix);
    } else if (state == MARKET_PAYMENT_AUTHORITY_CONFIRMED) {
        if (observed.block_time < record->offer.issued_unix ||
            observed.block_time >= record->offer.expires_unix) {
            market_payment_set_status(record, "CONFLICTED",
                                      "payment confirmed outside offer window",
                                      now_unix);
        } else {
            market_payment_set_status(record, "CONFIRMED",
                                      "exact canonical Sapling payment confirmed",
                                      now_unix);
            record->output_index = observed.output_index;
            record->block_height = observed.block_height;
            record->confirmations = observed.confirmations;
        }
    } else if (state == MARKET_PAYMENT_AUTHORITY_CONFLICTED ||
               strcmp(record->status, "CONFIRMED") == 0 ||
               strcmp(record->status, "CONFLICTED") == 0) {
        market_payment_set_status(record, "CONFLICTED",
            state == MARKET_PAYMENT_AUTHORITY_CONFLICTED
                ? "canonical transaction lacks the exact payment output"
                : "previously confirmed payment is no longer canonical",
            now_unix);
    } else {
        market_payment_set_status(record, "PENDING",
                                  "exact payment is not yet confirmed",
                                  now_unix);
    }
    ZCL_CHECK(market_payment_persist(ndb, record));
    return ZCL_OK;
}

struct zcl_result market_payment_claim_ingest(
    struct node_db *ndb, struct main_state *main_state,
    bool chain_current, int wallet_projection_height,
    const struct file_payment *payment,
    int64_t now_unix, struct market_payment_claim_record *out)
{
    if (!ndb || !ndb->open || !main_state || !payment || !out ||
        now_unix <= 0)
        return ZCL_ERR(-1, "payment ingest requires database, chain, claim, output, and time");
    memset(out, 0, sizeof(*out));

    struct market_payment_claim_record existing;
    if (db_market_payment_claim_find(ndb, payment->claim_id, &existing)) {
        *out = existing;
        struct zcl_result reconciled = market_payment_reconcile_record(
            ndb, main_state, chain_current, wallet_projection_height,
            now_unix, out);
        if (!reconciled.ok)
            return reconciled;
        /* The stored offer wire dates this claim's offer. Prune after the
         * reconcile so a claim that just confirmed survives as evidence. */
        market_payment_prune_expired_claims(ndb, &existing.offer, now_unix);
        return reconciled;
    }

    struct file_offer offer;
    if (!db_file_offer_find_by_id(ndb, payment->offer_id, &offer))
        return ZCL_ERR(-5, "signed offer is absent, invalid, or expired");
    enum file_payment_auth_error auth =
        file_payment_auth_verify_for_offer(payment, &offer);
    if (auth != FILE_PAYMENT_AUTH_OK)
        return ZCL_ERR(-6, "payment does not match signed offer: %s",
                       file_payment_auth_error_string(auth));
    market_payment_prune_expired_claims(ndb, &offer, now_unix);
    if (now_unix < offer.issued_unix || now_unix >= offer.expires_unix)
        return ZCL_ERR(-7, "new payment claim is outside the signed offer window");
    int stored = db_market_payment_claim_count_for_offer(ndb,
                                                         payment->offer_id);
    if (stored >= MARKET_PAYMENT_CLAIM_OFFER_MAX) {
        LOG_WARN("market",
                 "refusing claim: offer holds %d/%d distinct claim cap",
                 stored, (int)MARKET_PAYMENT_CLAIM_OFFER_MAX);
        return ZCL_ERR(-9, "offer holds %d distinct claims; cap is %d",
                       stored, (int)MARKET_PAYMENT_CLAIM_OFFER_MAX);
    }

    out->payment = *payment;
    out->offer = offer;
    out->output_index = -1;
    out->observed_at = now_unix;
    market_payment_set_status(out, "PENDING",
                              "claim accepted; confirmation not observed",
                              now_unix);
    return market_payment_reconcile_record(
        ndb, main_state, chain_current, wallet_projection_height,
        now_unix, out);
}

struct zcl_result market_payment_claim_reconcile(
    struct node_db *ndb, struct main_state *main_state,
    bool chain_current, int wallet_projection_height,
    const uint8_t claim_id[32],
    int64_t now_unix, struct market_payment_claim_record *out)
{
    if (!ndb || !ndb->open || !main_state || !claim_id || !out ||
        now_unix <= 0)
        return ZCL_ERR(-1, "payment reconcile requires database, chain, claim id, output, and time");
    if (!db_market_payment_claim_find(ndb, claim_id, out))
        return ZCL_ERR(-8, "payment claim not found");
    return market_payment_reconcile_record(
        ndb, main_state, chain_current, wallet_projection_height,
        now_unix, out);
}

struct zcl_result market_payment_authorize_chunk(
    struct node_db *ndb, struct main_state *main_state,
    bool chain_current, int wallet_projection_height,
    const uint8_t offer_id[32],
    const uint8_t buyer_pubkey[32], uint32_t chunk_index,
    int64_t now_unix, struct market_payment_authorization *out)
{
    if (!ndb || !ndb->open || !main_state || !offer_id || !buyer_pubkey ||
        !out || now_unix <= 0)
        return ZCL_ERR(-1, "chunk authorization requires complete inputs");
    memset(out, 0, sizeof(*out));
    snprintf(out->status, sizeof(out->status), "PENDING");
    snprintf(out->reason, sizeof(out->reason),
             "no confirmed claim covers this chunk");

    struct market_payment_claim_record candidates[MARKET_PAYMENT_CANDIDATE_MAX];
    int count = db_market_payment_claim_list_for_chunk(
        ndb, offer_id, buyer_pubkey, chunk_index, candidates,
        MARKET_PAYMENT_CANDIDATE_MAX);
    bool saw_unknown = false;
    bool saw_conflict = false;
    for (int i = 0; i < count; i++) {
        struct zcl_result reconciled = market_payment_reconcile_record(
            ndb, main_state, chain_current, wallet_projection_height,
            now_unix, &candidates[i]);
        if (!reconciled.ok)
            return reconciled;
        if (strcmp(candidates[i].status, "CONFIRMED") == 0) {
            out->authorized = true;
            snprintf(out->status, sizeof(out->status), "CONFIRMED");
            snprintf(out->reason, sizeof(out->reason),
                     "exact canonical payment authorizes this chunk");
            memcpy(out->claim_id, candidates[i].payment.claim_id, 32);
            out->block_height = candidates[i].block_height;
            out->confirmations = candidates[i].confirmations;
            return ZCL_OK;
        }
        saw_unknown |= strcmp(candidates[i].status, "UNKNOWN") == 0;
        saw_conflict |= strcmp(candidates[i].status, "CONFLICTED") == 0;
    }
    if (saw_unknown) {
        snprintf(out->status, sizeof(out->status), "UNKNOWN");
        snprintf(out->reason, sizeof(out->reason),
                 "payment authority is incomplete; unlock refused");
    } else if (saw_conflict) {
        snprintf(out->status, sizeof(out->status), "CONFLICTED");
        snprintf(out->reason, sizeof(out->reason),
                 "payment evidence conflicts with canonical state");
    }
    return ZCL_OK;
}
