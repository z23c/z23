/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: reconcile paid-file claims against wallet and chain authorities. */

#ifndef ZCL_SERVICE_FILE_MARKET_PAYMENT_H
#define ZCL_SERVICE_FILE_MARKET_PAYMENT_H

#include "base/result.h"
#include "models/market_payment_claim.h"

#include <stdbool.h>
#include <stdint.h>

struct main_state;

/* Distinct claims one signed offer may hold. claim_id is content-bound, so
 * fresh buyer keypairs can mint unlimited self-consistent claims; the ingest
 * refuses past this cap instead of evicting, which keeps the claim projection
 * at O(active offers) x cap rather than O(attacker effort). */
#define MARKET_PAYMENT_CLAIM_OFFER_MAX 64

struct market_payment_authorization {
    bool authorized;
    char status[MARKET_PAYMENT_STATUS_MAX];
    char reason[MARKET_PAYMENT_REASON_MAX];
    uint8_t claim_id[32];
    int block_height;
    int confirmations;
};

/* Ingest a verified public claim locator, bind it to the seller's persisted
 * signed offer, and synchronously reconcile it. chain_current must describe
 * the caller's live sync state; false always yields UNKNOWN and no unlock.
 * Distinct claims are capped per offer at MARKET_PAYMENT_CLAIM_OFFER_MAX, and
 * the next ingest touching an expired offer prunes its non-CONFIRMED rows. */
struct zcl_result market_payment_claim_ingest(
    struct node_db *ndb, struct main_state *main_state,
    bool chain_current, int wallet_projection_height,
    const struct file_payment *payment,
    int64_t now_unix, struct market_payment_claim_record *out);

/* Rebuild one claim's status from the current wallet-note + canonical-chain
 * authorities. A previously confirmed claim becomes CONFLICTED if a reorg
 * removes its canonical transaction. */
struct zcl_result market_payment_claim_reconcile(
    struct node_db *ndb, struct main_state *main_state,
    bool chain_current, int wallet_projection_height,
    const uint8_t claim_id[32],
    int64_t now_unix, struct market_payment_claim_record *out);

/* Reconcile every candidate covering this chunk and authorize only a current,
 * confirmed claim for the exact offer and buyer public key. */
struct zcl_result market_payment_authorize_chunk(
    struct node_db *ndb, struct main_state *main_state,
    bool chain_current, int wallet_projection_height,
    const uint8_t offer_id[32],
    const uint8_t buyer_pubkey[32], uint32_t chunk_index,
    int64_t now_unix, struct market_payment_authorization *out);

#endif
