/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Durable, identity-bound ZSLP transaction intents. */

#ifndef ZCL_SERVICES_ZSLP_TRANSACTION_INTENT_SERVICE_H
#define ZCL_SERVICES_ZSLP_TRANSACTION_INTENT_SERVICE_H

#include "models/vault_intent.h"
#include "services/wallet_money_service.h"
#include "util/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;

#define ZSLP_INTENT_APPLICATION "zslp_intent"
#define ZSLP_INTENT_TICKER_MAX 10
#define ZSLP_INTENT_NAME_MAX 64
#define ZSLP_INTENT_ADDRESS_MAX 128

enum zslp_intent_operation {
    ZSLP_INTENT_GENESIS = 1,
    ZSLP_INTENT_MINT = 2,
    ZSLP_INTENT_SEND = 3,
    ZSLP_INTENT_BURN = 4,
};

struct zslp_intent_request {
    char wallet_scope[5];
    enum zslp_intent_operation operation;
    char ticker[ZSLP_INTENT_TICKER_MAX + 1];
    char name[ZSLP_INTENT_NAME_MAX + 1];
    uint8_t decimals;
    uint64_t supply;
    char token_id[65];
    char recipient[ZSLP_INTENT_ADDRESS_MAX + 1];
    uint64_t units;
    char idempotency_key[VAULT_INTENT_IDEMPOTENCY_MAX + 1];
};

typedef struct zcl_result (*zslp_intent_money_fn)(
    void *ctx, const char *wallet_scope, struct wallet_money_snapshot *out);
typedef struct zcl_result (*zslp_intent_prepare_fn)(
    void *ctx, const struct zslp_intent_request *request,
    int64_t maximum_fee_zat, uint8_t *raw_tx, size_t raw_capacity,
    size_t *raw_tx_len, uint8_t txid_out[32], int64_t *actual_fee_zat,
    struct vault_intent_input *inputs, size_t input_capacity,
    size_t *input_count);
typedef struct zcl_result (*zslp_intent_publish_fn)(
    void *ctx, const uint8_t *raw_tx, size_t raw_tx_len,
    const uint8_t expected_txid[32]);

struct zslp_intent_runtime {
    struct node_db *node_db;
    zslp_intent_money_fn read_money;
    void *money_ctx;
    zslp_intent_prepare_fn prepare;
    void *prepare_ctx;
    zslp_intent_publish_fn publish;
    void *publish_ctx;
    int32_t tip_height;
    uint8_t tip_hash[32];
    int64_t maximum_fee_zat;
    int64_t now_unix;
};

struct zslp_intent_result {
    uint8_t plan_id[32];
    char wallet_scope[5];
    char wallet_instance_id[WALLET_INSTANCE_ID_HEX_LEN + 1];
    char network_genesis[WALLET_GENESIS_HEX_LEN + 1];
    enum zslp_intent_operation operation;
    char token_id[65];
    uint64_t units;
    bool has_txid;
    uint8_t txid[32];
    bool broadcast;
    bool idempotent_replay;
    int64_t actual_fee_zat;
    int64_t maximum_fee_zat;
    int64_t reserved_zat;
    int64_t expires_at;
    char state[24];
    uint8_t snapshot_root[32];
    uint8_t plan_digest[32];
};

const char *zslp_intent_operation_name(enum zslp_intent_operation operation);
struct zcl_result zslp_transaction_intent_plan(
    const struct zslp_intent_runtime *runtime,
    const struct zslp_intent_request *request,
    struct zslp_intent_result *out);
struct zcl_result zslp_transaction_intent_commit(
    const struct zslp_intent_runtime *runtime, const char *wallet_scope,
    const uint8_t plan_id[32], struct zslp_intent_result *out);

#endif
