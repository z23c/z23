/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Durable, identity-bound ZNAM transaction intents. */

#ifndef ZCL_SERVICES_ZNAM_TRANSACTION_INTENT_SERVICE_H
#define ZCL_SERVICES_ZNAM_TRANSACTION_INTENT_SERVICE_H

#include "models/vault_intent.h"
#include "services/wallet_money_service.h"
#include "util/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;

#define ZNAM_INTENT_APPLICATION "znam_intent"
#define ZNAM_INTENT_NAME_MAX 63
#define ZNAM_INTENT_VALUE_MAX 128
#define ZNAM_INTENT_OWNER_MAX 63
#define ZNAM_INTENT_KEY_MAX 32

enum znam_intent_operation {
    ZNAM_INTENT_REGISTER = 1,
    ZNAM_INTENT_UPDATE = 2,
    ZNAM_INTENT_TRANSFER = 3,
    ZNAM_INTENT_RENEW = 4,
    ZNAM_INTENT_SET_RECORD = 5,
    ZNAM_INTENT_SET_TEXT = 6,
};

struct znam_intent_request {
    char wallet_scope[5];
    enum znam_intent_operation operation;
    char name[ZNAM_INTENT_NAME_MAX + 1];
    uint8_t target_type;
    char value[ZNAM_INTENT_VALUE_MAX + 1];
    char new_owner[ZNAM_INTENT_OWNER_MAX + 1];
    char key[ZNAM_INTENT_KEY_MAX + 1];
    char idempotency_key[VAULT_INTENT_IDEMPOTENCY_MAX + 1];
};

typedef struct zcl_result (*znam_intent_money_fn)(
    void *ctx, const char *wallet_scope, struct wallet_money_snapshot *out);
typedef struct zcl_result (*znam_intent_prepare_fn)(
    void *ctx, const struct znam_intent_request *request,
    int64_t maximum_fee_zat, uint8_t *raw_tx, size_t raw_capacity,
    size_t *raw_tx_len, uint8_t txid_out[32], int64_t *actual_fee_zat,
    struct vault_intent_input *inputs, size_t input_capacity,
    size_t *input_count);
typedef struct zcl_result (*znam_intent_publish_fn)(
    void *ctx, const uint8_t *raw_tx, size_t raw_tx_len,
    const uint8_t expected_txid[32]);

struct znam_intent_runtime {
    struct node_db *node_db;
    znam_intent_money_fn read_money;
    void *money_ctx;
    znam_intent_prepare_fn prepare;
    void *prepare_ctx;
    znam_intent_publish_fn publish;
    void *publish_ctx;
    int32_t tip_height;
    uint8_t tip_hash[32];
    int64_t maximum_fee_zat;
    int64_t now_unix;
};

struct znam_intent_result {
    uint8_t plan_id[32];
    char wallet_scope[5];
    char wallet_instance_id[WALLET_INSTANCE_ID_HEX_LEN + 1];
    char network_genesis[WALLET_GENESIS_HEX_LEN + 1];
    enum znam_intent_operation operation;
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

const char *znam_intent_operation_name(enum znam_intent_operation operation);
struct zcl_result znam_transaction_intent_plan(
    const struct znam_intent_runtime *runtime,
    const struct znam_intent_request *request,
    struct znam_intent_result *out);
struct zcl_result znam_transaction_intent_commit(
    const struct znam_intent_runtime *runtime, const char *wallet_scope,
    const uint8_t plan_id[32], struct znam_intent_result *out);

#endif
