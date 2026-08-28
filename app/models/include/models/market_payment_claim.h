/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: durable, rebuildable file-market payment claim projection. */

#ifndef ZCL_DB_MODEL_MARKET_PAYMENT_CLAIM_H
#define ZCL_DB_MODEL_MARKET_PAYMENT_CLAIM_H

#include "models/activerecord.h"
#include "models/database.h"
#include "net/file_market.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MARKET_PAYMENT_STATUS_MAX 16
#define MARKET_PAYMENT_REASON_MAX 160

struct market_payment_claim_record {
    struct file_payment payment;
    struct file_offer offer;
    char status[MARKET_PAYMENT_STATUS_MAX];
    char status_reason[MARKET_PAYMENT_REASON_MAX];
    int output_index;
    int block_height;
    int confirmations;
    int64_t observed_at;
    int64_t reconciled_at;
};

enum market_payment_authority_state {
    MARKET_PAYMENT_AUTHORITY_UNKNOWN = 0,
    MARKET_PAYMENT_AUTHORITY_PENDING,
    MARKET_PAYMENT_AUTHORITY_CONFIRMED,
    MARKET_PAYMENT_AUTHORITY_CONFLICTED,
};

struct market_payment_authority_observation {
    enum market_payment_authority_state state;
    int output_index;
    int block_height;
    int confirmations;
    int64_t block_time;
};

struct ar_callbacks *db_market_payment_claim_callbacks(void);
bool db_market_payment_claim_validate(
    const struct market_payment_claim_record *record,
    struct ar_errors *errors);
bool db_market_payment_claim_save(
    struct node_db *ndb, const struct market_payment_claim_record *record);
bool db_market_payment_claim_find(
    struct node_db *ndb, const uint8_t claim_id[32],
    struct market_payment_claim_record *out);
int db_market_payment_claim_list_for_buyer(
    struct node_db *ndb, const uint8_t offer_id[32],
    const uint8_t buyer_pubkey[32],
    struct market_payment_claim_record *out, size_t max);
int db_market_payment_claim_list_for_chunk(
    struct node_db *ndb, const uint8_t offer_id[32],
    const uint8_t buyer_pubkey[32], uint32_t chunk_index,
    struct market_payment_claim_record *out, size_t max);
int db_market_payment_claim_count_for_offer(
    struct node_db *ndb, const uint8_t offer_id[32]);

/* Drop this offer's non-CONFIRMED claim rows and return how many went.
 * CONFIRMED rows always survive: they are settlement evidence. */
int db_market_payment_claim_prune_unconfirmed_for_offer(
    struct node_db *ndb, const uint8_t offer_id[32]);

enum market_payment_authority_state db_market_payment_observe_authority(
    struct node_db *ndb, const struct file_payment *payment,
    const char *seller_address,
    const uint8_t memo[FILE_MARKET_PAYMENT_MEMO_BYTES],
    int tip_height, const uint8_t tip_hash[32],
    struct market_payment_authority_observation *out);

#endif
