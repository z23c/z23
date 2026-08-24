/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Durable buyer-side plan/commit workflow for one paid file chunk range. */

#ifndef ZCL_SERVICES_FILE_MARKET_PURCHASE_SERVICE_H
#define ZCL_SERVICES_FILE_MARKET_PURCHASE_SERVICE_H

#include "base/result.h"
#include "net/file_market.h"
#include "net/file_market_delivery.h"
#include "services/wallet_money_service.h"

#include <stdbool.h>
#include <stdint.h>

struct node_db;

#define MARKET_PURCHASE_APPLICATION "market_purchase"
#define MARKET_PURCHASE_SOURCE_MAX 255
/* Leaves one full minute for RPC rendering/cleanup before the fixed
 * five-minute market-delivery watchdog closes the caller connection. */
#define MARKET_PURCHASE_RETRIEVE_BUDGET_MS 240000LL

typedef struct zcl_result (*market_purchase_money_fn)(
    void *ctx, const char *wallet_scope, struct wallet_money_snapshot *out);
typedef struct zcl_result (*market_purchase_source_check_fn)(
    void *ctx, const char *source_address);
typedef struct zcl_result (*market_purchase_send_fn)(
    void *ctx, const char *source_address, const char *seller_address,
    int64_t amount_zat, const uint8_t memo[FILE_MARKET_PAYMENT_MEMO_BYTES],
    uint8_t txid_out[32]);
typedef bool (*market_purchase_notify_fn)(
    void *ctx, const struct file_payment *payment);
typedef enum file_market_delivery_status (*market_purchase_fetch_fn)(
    void *ctx, const uint8_t peer_ip[16], uint16_t peer_port,
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32], int64_t deadline_ms,
    struct file_market_delivery_chunk *out_chunk);
typedef enum file_market_delivery_status (*market_purchase_onion_fetch_fn)(
    void *ctx, const uint8_t seller_onion_pubkey[32],
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32], int64_t deadline_ms,
    struct file_market_delivery_chunk *out_chunk);

/* Ports keep wallet selection/build/broadcast and peer transport in their
 * existing owning layers. The service owns exact workflow ordering and the
 * durable vault-intent lifecycle. */
struct market_purchase_runtime {
    struct node_db *node_db;
    market_purchase_money_fn read_money;
    void *money_ctx;
    market_purchase_source_check_fn check_source;
    void *source_ctx;
    market_purchase_send_fn send;
    void *send_ctx;
    market_purchase_notify_fn notify;
    void *notify_ctx;
    market_purchase_fetch_fn fetch;
    void *fetch_ctx;
    market_purchase_onion_fetch_fn fetch_onion;
    void *fetch_onion_ctx;
    bool onion_transport_ready;
    int32_t tip_height;
    uint8_t tip_hash[32];
    int64_t maximum_fee_zat;
    int64_t now_unix;
};

/* Production transport ports kept beside retrieval orchestration so the RPC
 * controller only supplies runtime ownership/readiness. */
enum file_market_delivery_status market_purchase_fetch_endpoint(
    void *ctx, const uint8_t peer_ip[16], uint16_t peer_port,
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32], int64_t deadline_ms,
    struct file_market_delivery_chunk *out_chunk);
enum file_market_delivery_status market_purchase_fetch_onion_endpoint(
    void *ctx, const uint8_t seller_onion_pubkey[32],
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32], int64_t deadline_ms,
    struct file_market_delivery_chunk *out_chunk);

struct market_purchase_request {
    char wallet_scope[5];
    uint8_t offer_id[32];
    char source_address[MARKET_PURCHASE_SOURCE_MAX + 1];
    uint32_t chunk_start;
    uint32_t chunks_paid;
    char idempotency_key[65];
};

struct market_purchase_view {
    uint8_t plan_id[32];
    uint8_t offer_id[32];
    uint8_t buyer_pubkey[32];
    uint32_t chunk_start;
    uint32_t chunks_paid;
    int64_t amount_zat;
    int64_t maximum_fee_zat;
    int64_t reserved_zat;
    int64_t expires_at;
    char wallet_scope[5];
    char state[24];
    bool idempotent_replay;
    bool has_txid;
    uint8_t txid[32];
    bool has_claim;
    uint8_t claim_id[32];
    /* True means the signed claim was handed to the node's gossip
     * transport. Confirmation and paid-byte delivery remain separate. */
    bool payment_notification_queued;
    bool has_download;
    char download_state[16];
    uint32_t chunks_received;
    uint32_t num_chunks;
    uint64_t bytes_received;
    uint64_t size_bytes;
    bool destination_published;
};

struct zcl_result market_purchase_plan(
    const struct market_purchase_runtime *runtime,
    const struct market_purchase_request *request,
    struct market_purchase_view *out);

/* A commit accepts only the durable plan identity and explicit wallet scope.
 * A PROVING plan without a recorded txid is deliberately COMMIT_UNCERTAIN:
 * never retrying a possibly-broadcast spend is safer than duplicating it. */
struct zcl_result market_purchase_commit(
    const struct market_purchase_runtime *runtime, const char *wallet_scope,
    const uint8_t plan_id[32], struct market_purchase_view *out);

struct zcl_result market_purchase_status(
    const struct market_purchase_runtime *runtime, const uint8_t plan_id[32],
    struct market_purchase_view *out);

/* Retrieve a fully-paid offer from its exact signed endpoint, verify every
 * authenticated chunk and the complete manifest, resume only from fsynced
 * durable progress, then atomically publish to a private owner-supplied
 * destination. Partial-range payment plans deliberately cannot publish a
 * complete file. The destination never enters the public view or logs. */
struct zcl_result market_purchase_retrieve(
    const struct market_purchase_runtime *runtime,
    const uint8_t plan_id[32], const char *destination_path,
    struct market_purchase_view *out);

#endif
