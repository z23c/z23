/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Internal contract shared by the purchase payment and retrieval services. */

#ifndef ZCL_SERVICES_FILE_MARKET_PURCHASE_INTERNAL_H
#define ZCL_SERVICES_FILE_MARKET_PURCHASE_INTERNAL_H

#include "models/market_download.h"
#include "models/vault_intent.h"
#include "services/file_market_purchase_service.h"

#include <stddef.h>

#define MARKET_PURCHASE_PAYLOAD_MAX 1400u

struct market_purchase_private_payload {
    char source[MARKET_PURCHASE_SOURCE_MAX + 1];
    char seller[256];
    uint8_t offer_id[32];
    uint8_t network_genesis[32];
    uint32_t chunk_start;
    uint32_t chunks_paid;
    int64_t amount_zat;
    int64_t maximum_fee_zat;
    uint8_t buyer_seed[32];
    uint8_t buyer_pubkey[32];
    uint8_t memo[FILE_MARKET_PAYMENT_MEMO_BYTES];
};

struct zcl_result market_purchase_runtime_validate(
    const struct market_purchase_runtime *runtime, bool needs_money,
    bool committing);

struct zcl_result market_purchase_payload_decrypt(
    const struct market_purchase_runtime *runtime,
    const struct vault_intent_row *row,
    struct market_purchase_private_payload *payload,
    uint8_t *plain, size_t *plain_len);

void market_purchase_view_from_row(
    const struct vault_intent_row *row,
    const struct market_purchase_private_payload *payload,
    struct market_purchase_view *out);

void market_purchase_view_add_download(
    const struct market_download_record *download,
    struct market_purchase_view *out);

#endif
