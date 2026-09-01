/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Seller-side plan/commit workflow for one signed, self-authenticating
 * paid file-market offer (zfileoffer.v1). The plan half hashes and prices
 * a private local file without mutating anything; the commit half
 * atomically seals, persists, content-binds, and announces the offer. */

#ifndef ZCL_SERVICES_FILE_MARKET_OFFER_SERVICE_H
#define ZCL_SERVICES_FILE_MARKET_OFFER_SERVICE_H

#include "base/result.h"
#include "net/file_market.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;

/* Ports keep the node's own reachable endpoint, the wallet payee mint, and
 * gossip transport in their existing owning layers. The service owns exact
 * workflow ordering, owner key custody, and the durable offer lifecycle. */
typedef struct zcl_result (*market_offer_endpoint_fn)(
    void *ctx, uint8_t peer_ip[16], uint16_t *peer_port);
typedef struct zcl_result (*market_offer_payee_fn)(
    void *ctx, uint8_t z_addr_out[43]);
typedef bool (*market_offer_announce_fn)(
    void *ctx, const uint8_t *wire, size_t wire_len);
/* The node's own Tor v3 ed25519 identity, for onion-endpoint offers. */
typedef struct zcl_result (*market_offer_onion_endpoint_fn)(
    void *ctx, uint8_t onion_pubkey_out[32]);

struct market_offer_runtime {
    struct node_db *node_db;
    market_offer_endpoint_fn endpoint;
    void *endpoint_ctx;
    market_offer_payee_fn payee;
    void *payee_ctx;
    market_offer_announce_fn announce;
    void *announce_ctx;
    market_offer_onion_endpoint_fn onion_endpoint;
    void *onion_endpoint_ctx;
    /* Endpoint preference, decided by the wiring layer (the declared input
     * schema zcl.app_market_offer.input.v1 carries no endpoint field, so
     * the default is node-level: onion when the embedded Tor service is up
     * with a live onion address AND the operator did not set -externalip;
     * clearnet otherwise). When true the commit signs a v2 onion-endpoint
     * offer and refuses ONION_ENDPOINT_UNAVAILABLE if the onion identity is
     * unavailable — it NEVER silently downgrades to clearnet. When false
     * the commit signs exactly the v1 clearnet offer it always has. */
    bool prefer_onion;
    uint8_t network_genesis[32];
    int64_t now_unix;
};

struct market_offer_request {
    const char *filepath;      /* operator-private; never rendered */
    int64_t price_per_mb_zat;  /* must be positive; free files use romseed */
};

struct market_offer_view {
    uint8_t offer_id[32];         /* commit only */
    uint8_t root_hash[32];
    uint8_t seller_pubkey[32];    /* commit only */
    char filename[256];
    uint64_t size_bytes;
    uint32_t num_chunks;
    int64_t price_per_mb;
    int64_t total_zat;
    int64_t expires_unix;
    /* commit only: FILE_MARKET_ENDPOINT_CLEARNET (v1 wire) or
     * FILE_MARKET_ENDPOINT_ONION (v2 wire) */
    uint8_t endpoint_type;
    bool idempotent_replay;
    /* True means the exact signed wire was handed to the node's gossip
     * transport. Propagation and paid delivery remain separate. */
    bool announced;
};

/* Non-mutating preview: canonicalize + hash the file, price it exactly, and
 * report the would-be offer shape. Never touches keys, wallet, database, or
 * network. Refusals: CONTENT_UNAVAILABLE/CONTENT_INVALID/CONTENT_TOO_LARGE/
 * CONTENT_UNSTABLE/PRICE_INVALID. */
struct zcl_result file_market_offer_plan(
    const struct market_offer_runtime *runtime,
    const struct market_offer_request *request,
    struct market_offer_view *out);

/* Atomic commit: manifest, mint-or-load the owner seller key (encrypted
 * under the wallet metadata DEK), endpoint + fresh wallet payee, seal,
 * db_file_offer_save, content binding, in-memory cache, then origin
 * announcement of the exact signed wire. Re-commit of the same live offer
 * (same content, price, endpoint kind, and owner key, still inside its
 * validity window with its content binding intact) replays idempotently.
 * Additional refusals: ENDPOINT_UNKNOWN/ONION_ENDPOINT_UNAVAILABLE/
 * PAYEE_UNAVAILABLE/SELLER_KEY_UNAVAILABLE/
 * SEAL_FAILED/OFFER_SAVE_FAILED/CONTENT_BIND_FAILED/WIRE_FAILED. */
struct zcl_result file_market_offer_commit(
    const struct market_offer_runtime *runtime,
    const struct market_offer_request *request,
    struct market_offer_view *out);

#endif
