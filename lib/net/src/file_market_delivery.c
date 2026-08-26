/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Buyer-authenticated paid-file delivery gate, SERVING side. Payment and
 * hosting-policy authority are both injected from app/services; lib/net
 * verifies the request and enforces moderation-before-authorize-before-read
 * ordering without depending on wallet, database, or chain internals.
 *
 * The buying side lives in file_market_delivery_fetch.c — see
 * file_market_delivery_internal.h for why the split runs along the wire. */

#include "net/file_market_delivery.h"

#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "net/file_market.h"
#include "net/file_market_delivery_internal.h"
#include "net/file_service.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "support/cleanse.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t k_request_magic[8] =
    {'Z','F','G','E','T','V','3','\n'};
static const uint8_t k_reply_magic[8] =
    {'Z','F','R','E','P','V','2','\n'};
static const char k_request_domain[] = "zcl.file.market.delivery.request.v3";
static const char k_session_domain[] = "zcl.file.market.delivery.session.v1";

struct file_market_delivery_handlers {
    bool configured;
    uint8_t network_genesis[32];
    file_market_delivery_authorize_fn authorize;
    file_market_delivery_load_fn load;
    file_market_delivery_moderation_fn moderation;
    void *ctx;
};

static struct file_market_delivery_handlers g_handlers;
static pthread_mutex_t g_handlers_mutex = PTHREAD_MUTEX_INITIALIZER;

static void delivery_chunk_discard(struct file_market_delivery_chunk *chunk)
{
    if (!chunk)
        return;
    if (chunk->data && chunk->size > 0)
        memory_cleanse(chunk->data, chunk->size);
    free(chunk->data);
    memset(chunk, 0, sizeof(*chunk));
}

static enum file_market_delivery_error delivery_fields(
    const struct file_market_delivery_request *request,
    bool require_signature)
{
    if (!request)
        return FILE_MARKET_DELIVERY_ERR_NULL;
    if (request->version != FILE_MARKET_DELIVERY_VERSION)
        return FILE_MARKET_DELIVERY_ERR_VERSION;
    if (!delivery_bytes_nonzero(request->network_genesis, 32))
        return FILE_MARKET_DELIVERY_ERR_NETWORK;
    if (!delivery_bytes_nonzero(request->offer_id, 32))
        return FILE_MARKET_DELIVERY_ERR_OFFER_ID;
    if (!delivery_bytes_nonzero(request->buyer_pubkey, 32))
        return FILE_MARKET_DELIVERY_ERR_BUYER_KEY;
    if (!delivery_bytes_nonzero(request->session_id, 32))
        return FILE_MARKET_DELIVERY_ERR_SESSION;
    if (require_signature &&
        !delivery_bytes_nonzero(request->buyer_signature, 64))
        return FILE_MARKET_DELIVERY_ERR_SIGNATURE;
    if (require_signature && request->issued_unix <= 0)
        return FILE_MARKET_DELIVERY_ERR_EXPIRED;
    return FILE_MARKET_DELIVERY_OK;
}

static enum file_market_delivery_error delivery_body(
    const struct file_market_delivery_request *request,
    uint8_t out[FILE_MARKET_DELIVERY_BODY_BYTES])
{
    enum file_market_delivery_error error = delivery_fields(request, false);
    if (error != FILE_MARKET_DELIVERY_OK || !out)
        return out ? error : FILE_MARKET_DELIVERY_ERR_NULL;
    size_t off = 0;
    memcpy(out + off, k_request_magic, sizeof(k_request_magic));
    off += sizeof(k_request_magic);
    zcl_write_u16_le(out + off, request->version);
    off += 2;
    memcpy(out + off, request->network_genesis, 32);
    off += 32;
    memcpy(out + off, request->offer_id, 32);
    off += 32;
    zcl_write_u32_le(out + off, request->chunk_index);
    off += 4;
    memcpy(out + off, request->buyer_pubkey, 32);
    off += 32;
    memcpy(out + off, request->session_id, 32);
    off += 32;
    zcl_write_u64_le(out + off, (uint64_t)request->issued_unix);
    off += 8;
    return off == FILE_MARKET_DELIVERY_BODY_BYTES
        ? FILE_MARKET_DELIVERY_OK : FILE_MARKET_DELIVERY_ERR_WIRE_SIZE;
}

static enum file_market_delivery_error delivery_body_root(
    const struct file_market_delivery_request *request, uint8_t out[32])
{
    uint8_t body[FILE_MARKET_DELIVERY_BODY_BYTES];
    if (!out)
        return FILE_MARKET_DELIVERY_ERR_NULL;
    enum file_market_delivery_error error = delivery_body(request, body);
    if (error != FILE_MARKET_DELIVERY_OK)
        return error;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)k_request_domain,
                   sizeof(k_request_domain));
    sha3_256_write(&sha, body, sizeof(body));
    sha3_256_finalize(&sha, out);
    return FILE_MARKET_DELIVERY_OK;
}

const char *file_market_delivery_error_string(
    enum file_market_delivery_error error)
{
    switch (error) {
    case FILE_MARKET_DELIVERY_OK: return "ok";
    case FILE_MARKET_DELIVERY_ERR_NULL: return "null-argument";
    case FILE_MARKET_DELIVERY_ERR_VERSION: return "schema-version";
    case FILE_MARKET_DELIVERY_ERR_WIRE_SIZE: return "wire-size";
    case FILE_MARKET_DELIVERY_ERR_WIRE_MAGIC: return "wire-magic";
    case FILE_MARKET_DELIVERY_ERR_NETWORK: return "network-genesis";
    case FILE_MARKET_DELIVERY_ERR_OFFER_ID: return "offer-id";
    case FILE_MARKET_DELIVERY_ERR_BUYER_KEY: return "buyer-key";
    case FILE_MARKET_DELIVERY_ERR_SESSION: return "session-binding";
    case FILE_MARKET_DELIVERY_ERR_SIGNATURE: return "signature";
    case FILE_MARKET_DELIVERY_ERR_KEY_MISMATCH: return "buyer-key-mismatch";
    case FILE_MARKET_DELIVERY_ERR_EXPIRED: return "request-expired";
    }
    return "unknown";
}

void file_market_delivery_session_id(
    const uint8_t network_genesis[32],
    const uint8_t initiator_nonce[32],
    const uint8_t responder_nonce[32], uint8_t out[32])
{
    if (!out)
        return;
    memset(out, 0, 32);
    if (!network_genesis || !initiator_nonce || !responder_nonce)
        return;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)k_session_domain,
                   sizeof(k_session_domain));
    sha3_256_write(&sha, network_genesis, 32);
    sha3_256_write(&sha, initiator_nonce, 32);
    sha3_256_write(&sha, responder_nonce, 32);
    sha3_256_finalize(&sha, out);
}

void file_market_delivery_onion_session_id(
    const uint8_t network_genesis[32],
    const uint8_t offer_id[32],
    const uint8_t buyer_pubkey[32], uint8_t out[32])
{
    static const char k_onion_marker[] = "onion";
    if (!out)
        return;
    memset(out, 0, 32);
    if (!network_genesis || !offer_id || !buyer_pubkey)
        return;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)k_session_domain,
                   sizeof(k_session_domain));
    sha3_256_write(&sha, network_genesis, 32);
    sha3_256_write(&sha, (const uint8_t *)k_onion_marker,
                   sizeof(k_onion_marker));
    sha3_256_write(&sha, offer_id, 32);
    sha3_256_write(&sha, buyer_pubkey, 32);
    sha3_256_finalize(&sha, out);
}

enum file_market_delivery_error file_market_delivery_request_encode(
    const struct file_market_delivery_request *request,
    uint8_t out[FILE_MARKET_DELIVERY_WIRE_BYTES])
{
    if (!out)
        return FILE_MARKET_DELIVERY_ERR_NULL;
    enum file_market_delivery_error error = delivery_fields(request, true);
    if (error != FILE_MARKET_DELIVERY_OK)
        return error;
    error = delivery_body(request, out);
    if (error == FILE_MARKET_DELIVERY_OK)
        memcpy(out + FILE_MARKET_DELIVERY_BODY_BYTES,
               request->buyer_signature, 64);
    return error;
}

enum file_market_delivery_error file_market_delivery_request_decode(
    const uint8_t *wire, size_t wire_len,
    struct file_market_delivery_request *out)
{
    if (!wire || !out)
        return FILE_MARKET_DELIVERY_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != FILE_MARKET_DELIVERY_WIRE_BYTES)
        return FILE_MARKET_DELIVERY_ERR_WIRE_SIZE;
    if (memcmp(wire, k_request_magic, sizeof(k_request_magic)) != 0)
        return FILE_MARKET_DELIVERY_ERR_WIRE_MAGIC;
    size_t off = sizeof(k_request_magic);
    out->version = zcl_read_u16_le(wire + off);
    off += 2;
    memcpy(out->network_genesis, wire + off, 32);
    off += 32;
    memcpy(out->offer_id, wire + off, 32);
    off += 32;
    out->chunk_index = zcl_read_u32_le(wire + off);
    off += 4;
    memcpy(out->buyer_pubkey, wire + off, 32);
    off += 32;
    memcpy(out->session_id, wire + off, 32);
    off += 32;
    out->issued_unix = (int64_t)zcl_read_u64_le(wire + off);
    off += 8;
    memcpy(out->buyer_signature, wire + off, 64);
    off += 64;
    enum file_market_delivery_error error =
        off == FILE_MARKET_DELIVERY_WIRE_BYTES
            ? delivery_fields(out, true)
            : FILE_MARKET_DELIVERY_ERR_WIRE_SIZE;
    if (error != FILE_MARKET_DELIVERY_OK)
        memset(out, 0, sizeof(*out));
    return error;
}

enum file_market_delivery_error file_market_delivery_request_seal(
    struct file_market_delivery_request *request,
    const uint8_t buyer_seed[32])
{
    if (!request || !buyer_seed)
        return FILE_MARKET_DELIVERY_ERR_NULL;
    uint8_t derived_pk[32], secret_copy[32], root[32];
    request->issued_unix = (int64_t)platform_time_wall_time_t();
    ed25519_keypair(derived_pk, secret_copy, buyer_seed);
    if (memcmp(derived_pk, request->buyer_pubkey, 32) != 0) {
        memory_cleanse(secret_copy, sizeof(secret_copy));
        return FILE_MARKET_DELIVERY_ERR_KEY_MISMATCH;
    }
    enum file_market_delivery_error error = delivery_body_root(request, root);
    if (error == FILE_MARKET_DELIVERY_OK)
        ed25519_sign(request->buyer_signature, root, sizeof(root), buyer_seed,
                     request->buyer_pubkey);
    memory_cleanse(secret_copy, sizeof(secret_copy));
    memory_cleanse(root, sizeof(root));
    return error;
}

enum file_market_delivery_error file_market_delivery_request_verify(
    const struct file_market_delivery_request *request,
    const uint8_t expected_network_genesis[32],
    const uint8_t expected_session_id[32])
{
    enum file_market_delivery_error error = delivery_fields(request, true);
    if (error != FILE_MARKET_DELIVERY_OK)
        return error;
    if (!expected_network_genesis ||
        memcmp(request->network_genesis, expected_network_genesis, 32) != 0)
        return FILE_MARKET_DELIVERY_ERR_NETWORK;
    if (!expected_session_id ||
        memcmp(request->session_id, expected_session_id, 32) != 0)
        return FILE_MARKET_DELIVERY_ERR_SESSION;
    /* Freshness closes the bearer hole the onion route opens: vendored
     * dynhost writes every request line (the full signed credential) into
     * tor.log, and a copied onion request used to stay valid for the life
     * of the offer. Reject stamps outside the window in both directions so
     * a forged future stamp cannot outlive it either. */
    int64_t now_unix = (int64_t)platform_time_wall_time_t();
    int64_t age_unix = now_unix - request->issued_unix;
    if (request->issued_unix <= 0 ||
        age_unix < -FILE_MARKET_DELIVERY_MAX_AGE_SECS ||
        age_unix > FILE_MARKET_DELIVERY_MAX_AGE_SECS) {
        LOG_WARN("market",
                 "paid delivery request rejected on freshness: "
                 "issued=%lld now=%lld max_age=%ds",
                 (long long)request->issued_unix, (long long)now_unix,
                 FILE_MARKET_DELIVERY_MAX_AGE_SECS);
        return FILE_MARKET_DELIVERY_ERR_EXPIRED;
    }
    uint8_t root[32];
    error = delivery_body_root(request, root);
    bool signature_ok = error == FILE_MARKET_DELIVERY_OK &&
        ed25519_verify(request->buyer_signature, root, sizeof(root),
                       request->buyer_pubkey);
    memory_cleanse(root, sizeof(root));
    return signature_ok ? FILE_MARKET_DELIVERY_OK
                        : FILE_MARKET_DELIVERY_ERR_SIGNATURE;
}

const char *file_market_delivery_status_string(
    enum file_market_delivery_status status)
{
    switch (status) {
    case FILE_MARKET_DELIVERY_READY: return "READY";
    case FILE_MARKET_DELIVERY_MALFORMED: return "MALFORMED";
    case FILE_MARKET_DELIVERY_UNAUTHENTICATED: return "UNAUTHENTICATED";
    case FILE_MARKET_DELIVERY_PAYMENT_PENDING: return "PENDING";
    case FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN: return "UNKNOWN";
    case FILE_MARKET_DELIVERY_PAYMENT_CONFLICTED: return "CONFLICTED";
    case FILE_MARKET_DELIVERY_PAYMENT_REJECTED: return "REJECTED";
    case FILE_MARKET_DELIVERY_CONTENT_UNAVAILABLE: return "CONTENT_UNAVAILABLE";
    case FILE_MARKET_DELIVERY_RESOURCE_LIMIT: return "RESOURCE_LIMIT";
    case FILE_MARKET_DELIVERY_MODERATION_HIDDEN: return "MODERATION_HIDDEN";
    }
    return "MALFORMED";
}

/* This node's own hosting decision, asked before payment state is even
 * consulted so a declined chunk never reveals it and never reaches a
 * content read. An unwired port is a refusal: a node that cannot ask its
 * own profile hands out nothing. */
static bool delivery_moderation_allows(
    const struct file_market_delivery_handlers *handlers,
    const uint8_t offer_id[32])
{
    if (!handlers || !handlers->moderation)
        return false;
    return handlers->moderation(offer_id, handlers->ctx);
}

bool file_market_delivery_reply_encode(
    const struct file_market_delivery_reply *reply,
    uint8_t out[FILE_MARKET_DELIVERY_REPLY_BYTES])
{
    if (!reply || !out || reply->version != FILE_MARKET_DELIVERY_VERSION ||
        reply->status > FILE_MARKET_DELIVERY_MODERATION_HIDDEN)
        return false;
    size_t off = 0;
    memcpy(out + off, k_reply_magic, sizeof(k_reply_magic));
    off += sizeof(k_reply_magic);
    zcl_write_u16_le(out + off, reply->version);
    off += 2;
    zcl_write_u16_le(out + off, (uint16_t)reply->status);
    off += 2;
    memcpy(out + off, reply->offer_id, 32);
    off += 32;
    zcl_write_u32_le(out + off, reply->chunk_index);
    off += 4;
    zcl_write_u32_le(out + off, reply->size);
    off += 4;
    memcpy(out + off, reply->sha3, 32);
    off += 32;
    return off == FILE_MARKET_DELIVERY_REPLY_BYTES;
}

bool file_market_delivery_reply_decode(
    const uint8_t *wire, size_t wire_len,
    struct file_market_delivery_reply *out)
{
    if (!wire || !out || wire_len != FILE_MARKET_DELIVERY_REPLY_BYTES ||
        memcmp(wire, k_reply_magic, sizeof(k_reply_magic)) != 0)
        return false;
    memset(out, 0, sizeof(*out));
    size_t off = sizeof(k_reply_magic);
    out->version = zcl_read_u16_le(wire + off);
    off += 2;
    out->status = (enum file_market_delivery_status)
        zcl_read_u16_le(wire + off);
    off += 2;
    memcpy(out->offer_id, wire + off, 32);
    off += 32;
    out->chunk_index = zcl_read_u32_le(wire + off);
    off += 4;
    out->size = zcl_read_u32_le(wire + off);
    off += 4;
    memcpy(out->sha3, wire + off, 32);
    off += 32;
    if (off != FILE_MARKET_DELIVERY_REPLY_BYTES ||
        out->version != FILE_MARKET_DELIVERY_VERSION ||
        out->status > FILE_MARKET_DELIVERY_MODERATION_HIDDEN) {
        memset(out, 0, sizeof(*out));
        return false;
    }
    return true;
}

void file_market_delivery_set_handlers(
    const uint8_t expected_network_genesis[32],
    file_market_delivery_authorize_fn authorize,
    file_market_delivery_load_fn load,
    file_market_delivery_moderation_fn moderation, void *ctx)
{
    pthread_mutex_lock(&g_handlers_mutex);
    memset(&g_handlers, 0, sizeof(g_handlers));
    if (expected_network_genesis) {
        memcpy(g_handlers.network_genesis, expected_network_genesis, 32);
        g_handlers.configured = true;
        g_handlers.authorize = authorize;
        g_handlers.load = load;
        g_handlers.moderation = moderation;
        g_handlers.ctx = ctx;
    }
    pthread_mutex_unlock(&g_handlers_mutex);
}

void file_market_delivery_reset_handlers(void)
{
    file_market_delivery_set_handlers(NULL, NULL, NULL, NULL, NULL);
}

bool file_market_delivery_is_request(const uint8_t *payload, uint32_t plen)
{
    return payload && plen >= sizeof(k_request_magic) &&
        memcmp(payload, k_request_magic, sizeof(k_request_magic)) == 0;
}

static enum file_market_delivery_status delivery_auth_status(
    enum file_market_delivery_authorization authorization)
{
    switch (authorization) {
    case FILE_MARKET_DELIVERY_AUTHORIZED:
        return FILE_MARKET_DELIVERY_READY;
    case FILE_MARKET_DELIVERY_PENDING:
        return FILE_MARKET_DELIVERY_PAYMENT_PENDING;
    case FILE_MARKET_DELIVERY_UNKNOWN:
        return FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN;
    case FILE_MARKET_DELIVERY_CONFLICTED:
        return FILE_MARKET_DELIVERY_PAYMENT_CONFLICTED;
    case FILE_MARKET_DELIVERY_REJECTED:
        return FILE_MARKET_DELIVERY_PAYMENT_REJECTED;
    }
    return FILE_MARKET_DELIVERY_PAYMENT_REJECTED;
}

enum file_market_delivery_status file_market_delivery_prepare(
    const struct fs_session *session, const uint8_t *payload, uint32_t plen,
    struct file_market_delivery_reply *out_reply,
    struct file_market_delivery_chunk *out_chunk)
{
    if (!out_reply || !out_chunk)
        return FILE_MARKET_DELIVERY_MALFORMED;
    memset(out_reply, 0, sizeof(*out_reply));
    memset(out_chunk, 0, sizeof(*out_chunk));
    out_reply->version = FILE_MARKET_DELIVERY_VERSION;
    out_reply->status = FILE_MARKET_DELIVERY_MALFORMED;
    if (!session || !payload)
        return out_reply->status;

    struct file_market_delivery_request request;
    if (file_market_delivery_request_decode(payload, plen, &request) !=
        FILE_MARKET_DELIVERY_OK)
        return out_reply->status;
    memcpy(out_reply->offer_id, request.offer_id, 32);
    out_reply->chunk_index = request.chunk_index;

    struct file_market_delivery_handlers handlers;
    pthread_mutex_lock(&g_handlers_mutex);
    handlers = g_handlers;
    pthread_mutex_unlock(&g_handlers_mutex);
    if (!handlers.configured || !handlers.authorize) {
        out_reply->status = FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN;
        return out_reply->status;
    }

    /* Hosting decision first. Asked before authentication and payment so a
     * chunk this node will not host never causes a signature check, a
     * payment lookup, or a content read, and the answer leaks nothing
     * about either. */
    if (!delivery_moderation_allows(&handlers, request.offer_id)) {
        out_reply->status = FILE_MARKET_DELIVERY_MODERATION_HIDDEN;
        return out_reply->status;
    }

    uint8_t session_id[32];
    file_market_delivery_session_id(handlers.network_genesis,
                                    session->peer_nonce, session->our_nonce,
                                    session_id);
    enum file_market_delivery_error verified =
        file_market_delivery_request_verify(
            &request, handlers.network_genesis, session_id);
    memory_cleanse(session_id, sizeof(session_id));
    if (verified != FILE_MARKET_DELIVERY_OK) {
        out_reply->status = FILE_MARKET_DELIVERY_UNAUTHENTICATED;
        return out_reply->status;
    }

    out_reply->status = delivery_auth_status(handlers.authorize(
        request.offer_id, request.buyer_pubkey, request.chunk_index,
        handlers.ctx));
    if (out_reply->status != FILE_MARKET_DELIVERY_READY)
        return out_reply->status;
    if (!handlers.load || !handlers.load(request.offer_id,
                                         request.chunk_index, out_chunk,
                                         handlers.ctx) ||
        !out_chunk->data || out_chunk->size == 0 ||
        out_chunk->size > FILE_MARKET_CHUNK_SIZE) {
        free(out_chunk->data);
        memset(out_chunk, 0, sizeof(*out_chunk));
        out_reply->status = FILE_MARKET_DELIVERY_CONTENT_UNAVAILABLE;
        return out_reply->status;
    }

    uint8_t actual_sha3[32];
    sha3_256(out_chunk->data, out_chunk->size, actual_sha3);
    if (memcmp(actual_sha3, out_chunk->sha3, 32) != 0) {
        free(out_chunk->data);
        memset(out_chunk, 0, sizeof(*out_chunk));
        out_reply->status = FILE_MARKET_DELIVERY_CONTENT_UNAVAILABLE;
        return out_reply->status;
    }
    out_reply->size = out_chunk->size;
    memcpy(out_reply->sha3, actual_sha3, 32);
    return out_reply->status;
}

enum file_market_delivery_status file_market_delivery_prepare_onion(
    const uint8_t *payload, uint32_t plen,
    struct file_market_delivery_reply *out_reply,
    struct file_market_delivery_chunk *out_chunk)
{
    if (!out_reply || !out_chunk)
        return FILE_MARKET_DELIVERY_MALFORMED;
    memset(out_reply, 0, sizeof(*out_reply));
    memset(out_chunk, 0, sizeof(*out_chunk));
    out_reply->version = FILE_MARKET_DELIVERY_VERSION;
    out_reply->status = FILE_MARKET_DELIVERY_MALFORMED;
    if (!payload)
        return out_reply->status;

    struct file_market_delivery_request request;
    if (file_market_delivery_request_decode(payload, plen, &request) !=
        FILE_MARKET_DELIVERY_OK)
        return out_reply->status;
    memcpy(out_reply->offer_id, request.offer_id, 32);
    out_reply->chunk_index = request.chunk_index;

    struct file_market_delivery_handlers handlers;
    pthread_mutex_lock(&g_handlers_mutex);
    handlers = g_handlers;
    pthread_mutex_unlock(&g_handlers_mutex);
    if (!handlers.configured || !handlers.authorize) {
        out_reply->status = FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN;
        return out_reply->status;
    }

    /* Same hosting decision as the clearnet path, asked at the same point.
     * An onion buyer gets exactly the moderation posture a clearnet buyer
     * gets — the transport never widens what this node will host. */
    if (!delivery_moderation_allows(&handlers, request.offer_id)) {
        out_reply->status = FILE_MARKET_DELIVERY_MODERATION_HIDDEN;
        return out_reply->status;
    }

    uint8_t session_id[32];
    file_market_delivery_onion_session_id(handlers.network_genesis,
                                          request.offer_id,
                                          request.buyer_pubkey, session_id);
    enum file_market_delivery_error verified =
        file_market_delivery_request_verify(
            &request, handlers.network_genesis, session_id);
    memory_cleanse(session_id, sizeof(session_id));
    if (verified != FILE_MARKET_DELIVERY_OK) {
        out_reply->status = FILE_MARKET_DELIVERY_UNAUTHENTICATED;
        return out_reply->status;
    }

    out_reply->status = delivery_auth_status(handlers.authorize(
        request.offer_id, request.buyer_pubkey, request.chunk_index,
        handlers.ctx));
    if (out_reply->status != FILE_MARKET_DELIVERY_READY)
        return out_reply->status;
    if (!handlers.load || !handlers.load(request.offer_id,
                                         request.chunk_index, out_chunk,
                                         handlers.ctx) ||
        !out_chunk->data || out_chunk->size == 0 ||
        out_chunk->size > FILE_MARKET_CHUNK_SIZE) {
        free(out_chunk->data);
        memset(out_chunk, 0, sizeof(*out_chunk));
        out_reply->status = FILE_MARKET_DELIVERY_CONTENT_UNAVAILABLE;
        return out_reply->status;
    }

    uint8_t actual_sha3[32];
    sha3_256(out_chunk->data, out_chunk->size, actual_sha3);
    if (memcmp(actual_sha3, out_chunk->sha3, 32) != 0) {
        free(out_chunk->data);
        memset(out_chunk, 0, sizeof(*out_chunk));
        out_reply->status = FILE_MARKET_DELIVERY_CONTENT_UNAVAILABLE;
        return out_reply->status;
    }
    out_reply->size = out_chunk->size;
    memcpy(out_reply->sha3, actual_sha3, 32);
    return out_reply->status;
}

bool file_market_delivery_serve(
    struct fs_session *session, const uint8_t client_ip[16],
    const uint8_t *payload, uint32_t plen)
{
    struct file_market_delivery_reply reply;
    struct file_market_delivery_chunk chunk;
    enum file_market_delivery_status status = file_market_delivery_prepare(
        session, payload, plen, &reply, &chunk);
    if (status == FILE_MARKET_DELIVERY_READY &&
        (!fs_conn_budget_ok(session->bytes_sent,
                            session->start_monotonic_ms,
                            platform_time_monotonic_ms()) ||
         !fs_ip_bytes_charge(client_ip, chunk.size))) {
        delivery_chunk_discard(&chunk);
        memset(&chunk, 0, sizeof(chunk));
        memset(reply.sha3, 0, sizeof(reply.sha3));
        reply.size = 0;
        reply.status = FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
        status = reply.status;
    }
    uint8_t wire[FILE_MARKET_DELIVERY_REPLY_BYTES];
    if (!file_market_delivery_reply_encode(&reply, wire) ||
        !fs_send_frame(session, FS_MARKET_REPLY, wire, sizeof(wire))) {
        delivery_chunk_discard(&chunk);
        return false;
    }
    if (status == FILE_MARKET_DELIVERY_READY &&
        !fs_send_chunk_private(session, chunk.data, chunk.size, chunk.sha3)) {
        delivery_chunk_discard(&chunk);
        return false;
    }
    delivery_chunk_discard(&chunk);
    return true;
}
