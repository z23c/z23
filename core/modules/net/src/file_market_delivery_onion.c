/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: onion-routed paid-file chunk delivery (Phase B5,
 * docs/work/MARKET_ONION_DELIVERY.md). The seller half is the onion-only
 * /market/chunk site-route handler: it decodes the same signed zfileget
 * request the clearnet file service verifies, swaps the fs-handshake
 * session binding for the onion-derived session id, and serves the paid
 * chunk as <=60 KiB slices (the dynhost webserver buffer caps a response
 * at 64 KiB). The buyer half reassembles a chunk from slices with
 * per-slice sha3 verification behind an injectable GET port; production
 * dials through tor_integration_fetch_onion_blocking. */

#include "net/file_market_delivery.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "net/file_market.h"
#include "net/onion_v3_address.h"
#include "net/tor_integration.h"
#include "platform/time_compat.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t k_onion_reply_magic[8] =
    {'Z','F','O','C','K','S','1','\n'};
#define ONION_REPLY_VERSION 1u

/* "/market/chunk/" + 428 lowercase hex chars of the 214-byte signed
 * request, then end-of-path or "?slice=<digits>". */
#define ONION_REQUEST_HEX_CHARS (2u * FILE_MARKET_DELIVERY_WIRE_BYTES)

static size_t onion_http_respond(uint8_t *response, size_t response_max,
                                 int status, const char *reason,
                                 const char *content_type,
                                 const uint8_t *payload, size_t payload_len)
{
    int head = snprintf((char *)response, response_max,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n",
        status, reason, content_type, payload_len);
    if (head <= 0 || (size_t)head + payload_len > response_max)
        return 0;
    if (payload_len > 0)
        memcpy(response + head, payload, payload_len);
    return (size_t)head + payload_len;
}

static size_t onion_http_text(uint8_t *response, size_t response_max,
                              int status, const char *reason,
                              const char *text)
{
    return onion_http_respond(response, response_max, status, reason,
                              "text/plain; charset=utf-8",
                              (const uint8_t *)text, strlen(text));
}

static bool onion_parse_request_hex(const char *p,
    uint8_t wire_out[FILE_MARKET_DELIVERY_WIRE_BYTES], const char **tail)
{
    char hex[ONION_REQUEST_HEX_CHARS + 1];
    size_t hex_len = 0;
    while (p[hex_len] && p[hex_len] != '?' &&
           hex_len < ONION_REQUEST_HEX_CHARS + 1)
        hex_len++;
    if (hex_len != ONION_REQUEST_HEX_CHARS)
        return false;
    memcpy(hex, p, hex_len);
    hex[hex_len] = '\0';
    if (!zcl_hex_decode_lower(hex, wire_out,
                              FILE_MARKET_DELIVERY_WIRE_BYTES))
        return false;
    *tail = p + hex_len;
    return true;
}

static bool onion_parse_slice_query(const char *p, uint32_t *slice_out)
{
    if (*p == '\0')
        return true;
    static const char k_slice_key[] = "?slice=";
    if (strncmp(p, k_slice_key, sizeof(k_slice_key) - 1) != 0)
        return false;
    p += sizeof(k_slice_key) - 1;
    if (*p < '0' || *p > '9')
        return false;
    uint32_t slice = 0;
    while (*p >= '0' && *p <= '9') {
        if (slice > 100000u)
            return false;
        slice = slice * 10u + (uint32_t)(*p - '0');
        p++;
    }
    if (*p != '\0')
        return false;
    *slice_out = slice;
    return true;
}

/* Parse the path tail after the route prefix: exactly the request hex,
 * then end or "?slice=k". Returns false on any deviation. */
static bool onion_parse_path(const char *path,
                             uint8_t wire_out[FILE_MARKET_DELIVERY_WIRE_BYTES],
                             uint32_t *slice_out)
{
    if (!path || !wire_out || !slice_out)
        return false;
    *slice_out = 0;
    const char *p = path + sizeof(FILE_MARKET_ONION_PATH_PREFIX) - 1;
    const char *tail = NULL;
    if (!onion_parse_request_hex(p, wire_out, &tail))
        return false;
    return onion_parse_slice_query(tail, slice_out);
}

static size_t onion_reply_header_write(uint8_t *out,
    enum file_market_delivery_status status,
    const struct file_market_delivery_reply *reply,
    uint32_t slice_index, uint32_t slice_count,
    const uint8_t slice_sha3[32])
{
    size_t off = 0;
    memcpy(out + off, k_onion_reply_magic, sizeof(k_onion_reply_magic));
    off += sizeof(k_onion_reply_magic);
    zcl_write_u16_le(out + off, ONION_REPLY_VERSION);
    off += 2;
    zcl_write_u16_le(out + off, (uint16_t)status);
    off += 2;
    memcpy(out + off, reply->offer_id, 32);
    off += 32;
    zcl_write_u32_le(out + off, reply->chunk_index);
    off += 4;
    zcl_write_u32_le(out + off, reply->size);
    off += 4;
    zcl_write_u32_le(out + off, slice_index);
    off += 4;
    zcl_write_u32_le(out + off, slice_count);
    off += 4;
    memcpy(out + off, reply->sha3, 32);
    off += 32;
    if (slice_sha3)
        memcpy(out + off, slice_sha3, 32);
    else
        memset(out + off, 0, 32);
    off += 32;
    return off; /* == FILE_MARKET_ONION_REPLY_HEADER_BYTES */
}

struct onion_reply_header {
    uint16_t status;
    uint8_t offer_id[32];
    uint32_t chunk_index;
    uint32_t chunk_size;
    uint32_t slice_index;
    uint32_t slice_count;
    uint8_t chunk_sha3[32];
    uint8_t slice_sha3[32];
};

static bool onion_reply_header_parse(const uint8_t *wire, size_t wire_len,
                                     struct onion_reply_header *out)
{
    if (!wire || !out ||
        wire_len < FILE_MARKET_ONION_REPLY_HEADER_BYTES ||
        memcmp(wire, k_onion_reply_magic, sizeof(k_onion_reply_magic)) != 0)
        return false;
    size_t off = sizeof(k_onion_reply_magic);
    uint16_t version = zcl_read_u16_le(wire + off);
    off += 2;
    if (version != ONION_REPLY_VERSION)
        return false;
    out->status = zcl_read_u16_le(wire + off);
    off += 2;
    memcpy(out->offer_id, wire + off, 32);
    off += 32;
    out->chunk_index = zcl_read_u32_le(wire + off);
    off += 4;
    out->chunk_size = zcl_read_u32_le(wire + off);
    off += 4;
    out->slice_index = zcl_read_u32_le(wire + off);
    off += 4;
    out->slice_count = zcl_read_u32_le(wire + off);
    off += 4;
    memcpy(out->chunk_sha3, wire + off, 32);
    off += 32;
    memcpy(out->slice_sha3, wire + off, 32);
    off += 32;
    return off == FILE_MARKET_ONION_REPLY_HEADER_BYTES &&
        out->status <= FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
}

size_t file_market_delivery_onion_handle_request(
    const char *method, const char *path,
    const uint8_t *body, size_t body_len,
    uint8_t *response, size_t response_max)
{
    (void)body;
    (void)body_len;
    if (!method || strcmp(method, "GET") != 0)
        return onion_http_text(response, response_max, 405,
                               "Method Not Allowed", "GET only\n");
    if (!path ||
        strncmp(path, FILE_MARKET_ONION_PATH_PREFIX,
                sizeof(FILE_MARKET_ONION_PATH_PREFIX) - 1) != 0)
        return onion_http_text(response, response_max, 400, "Bad Request",
                               "malformed market chunk path\n");

    uint8_t request_wire[FILE_MARKET_DELIVERY_WIRE_BYTES];
    uint32_t slice_index = 0;
    if (!onion_parse_path(path, request_wire, &slice_index))
        return onion_http_text(response, response_max, 400, "Bad Request",
                               "malformed market chunk request\n");

    struct file_market_delivery_reply reply;
    struct file_market_delivery_chunk chunk;
    enum file_market_delivery_status status =
        file_market_delivery_prepare_onion(request_wire,
                                           sizeof(request_wire),
                                           &reply, &chunk);
    uint8_t payload[FILE_MARKET_ONION_REPLY_MAX];
    const uint8_t *slice_sha3 = NULL;
    uint8_t slice_digest[32];
    size_t payload_len = 0;
    uint32_t slice_count = 0;
    if (status == FILE_MARKET_DELIVERY_READY) {
        slice_count = (reply.size + FILE_MARKET_ONION_SLICE_BYTES - 1) /
                      FILE_MARKET_ONION_SLICE_BYTES;
        if (slice_index >= slice_count) {
            if (chunk.data && chunk.size > 0)
                memory_cleanse(chunk.data, chunk.size);
            free(chunk.data);
            return onion_http_text(response, response_max, 400,
                                   "Bad Request", "slice out of range\n");
        }
        size_t slice_off = (size_t)slice_index * FILE_MARKET_ONION_SLICE_BYTES;
        payload_len = reply.size - slice_off;
        if (payload_len > FILE_MARKET_ONION_SLICE_BYTES)
            payload_len = FILE_MARKET_ONION_SLICE_BYTES;
        sha3_256(chunk.data + slice_off, payload_len, slice_digest);
        slice_sha3 = slice_digest;
    }
    size_t header_len = onion_reply_header_write(
        payload, status, &reply, slice_index, slice_count, slice_sha3);
    if (payload_len > 0)
        memcpy(payload + header_len, chunk.data +
               (size_t)slice_index * FILE_MARKET_ONION_SLICE_BYTES,
               payload_len);
    if (chunk.data && chunk.size > 0)
        memory_cleanse(chunk.data, chunk.size);
    free(chunk.data);
    size_t response_len = onion_http_respond(
        response, response_max, 200, "OK", "application/octet-stream",
        payload, header_len + payload_len);
    memory_cleanse(payload, sizeof(payload));
    return response_len;
}

struct onion_untimed_adapter {
    file_market_delivery_onion_get_fn get;
    void *ctx;
};

static bool onion_untimed_get_with_timeout(
    void *opaque, const char *onion_address, const char *path,
    int timeout_secs, uint8_t *body_out, size_t body_cap, size_t *body_len)
{
    struct onion_untimed_adapter *adapter = opaque;
    (void)timeout_secs;
    return adapter->get(adapter->ctx, onion_address, path,
                        body_out, body_cap, body_len);
}

static bool onion_deadline_timeout(int64_t deadline_ms, int *timeout_secs)
{
    if (deadline_ms == INT64_MAX) {
        *timeout_secs = 60;
        return true;
    }
    int64_t now_ms = platform_time_monotonic_ms();
    if (now_ms <= 0 || now_ms >= deadline_ms)
        return false;
    int64_t remain_ms = deadline_ms - now_ms;
    int64_t seconds = remain_ms / 1000;
    if (seconds == 0)
        return false;
    *timeout_secs = seconds < 60 ? (int)seconds : 60;
    return true;
}

static void onion_assembly_discard(uint8_t *assembled, uint32_t size)
{
    if (assembled && size > 0)
        memory_cleanse(assembled, size);
    free(assembled);
}

struct onion_fetch_state {
    file_market_delivery_onion_timed_get_fn get;
    void *get_ctx;
    int64_t deadline_ms;
    const uint8_t *offer_id;
    uint32_t chunk_index;
    char onion_address[ONION_V3_ADDRESS_LEN + 1];
    char request_hex[ONION_REQUEST_HEX_CHARS + 1];
    uint8_t *assembled;
    uint32_t chunk_size;
    uint32_t slice_count;
    uint8_t chunk_sha3[32];
    uint8_t body[FILE_MARKET_ONION_REPLY_MAX];
};

static bool onion_fetch_args_valid(
    file_market_delivery_onion_timed_get_fn get,
    const uint8_t seller_onion_pubkey[32],
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    const uint8_t buyer_pubkey[32], const uint8_t buyer_seed[32],
    struct file_market_delivery_chunk *out_chunk)
{
    return get != NULL && seller_onion_pubkey != NULL &&
        network_genesis != NULL && offer_id != NULL &&
        buyer_pubkey != NULL && buyer_seed != NULL && out_chunk != NULL;
}

static bool onion_request_hex_build(const uint8_t network_genesis[32],
    const uint8_t offer_id[32], uint32_t chunk_index,
    const uint8_t buyer_pubkey[32], const uint8_t buyer_seed[32],
    char request_hex[ONION_REQUEST_HEX_CHARS + 1])
{
    struct file_market_delivery_request request;
    memset(&request, 0, sizeof(request));
    request.version = FILE_MARKET_DELIVERY_VERSION;
    memcpy(request.network_genesis, network_genesis, 32);
    memcpy(request.offer_id, offer_id, 32);
    request.chunk_index = chunk_index;
    memcpy(request.buyer_pubkey, buyer_pubkey, 32);
    file_market_delivery_onion_session_id(network_genesis, offer_id,
                                          buyer_pubkey, request.session_id);
    if (file_market_delivery_request_seal(&request, buyer_seed) !=
        FILE_MARKET_DELIVERY_OK)
        return false;
    uint8_t request_wire[FILE_MARKET_DELIVERY_WIRE_BYTES];
    if (file_market_delivery_request_encode(&request, request_wire) !=
        FILE_MARKET_DELIVERY_OK)
        return false;
    zcl_hex_encode(request_wire, sizeof(request_wire), request_hex);
    return true;
}

static enum file_market_delivery_status onion_fetch_abort(
    struct onion_fetch_state *st, enum file_market_delivery_status status)
{
    memory_cleanse(st->body, sizeof(st->body));
    onion_assembly_discard(st->assembled, st->chunk_size);
    return status;
}

static enum file_market_delivery_status onion_slice_fetch_once(
    struct onion_fetch_state *st, const char *path, size_t *body_len,
    struct onion_reply_header *header)
{
    int timeout_secs = 0;
    if (!onion_deadline_timeout(st->deadline_ms, &timeout_secs))
        return FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
    if (!st->get(st->get_ctx, st->onion_address, path, timeout_secs,
                 st->body, sizeof(st->body), body_len)) {
        if (!onion_deadline_timeout(st->deadline_ms, &timeout_secs))
            return FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
        return FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN;
    }
    if (!onion_deadline_timeout(st->deadline_ms, &timeout_secs))
        return FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
    if (!onion_reply_header_parse(st->body, *body_len, header) ||
        memcmp(header->offer_id, st->offer_id, 32) != 0 ||
        header->chunk_index != st->chunk_index)
        return FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN;
    return FILE_MARKET_DELIVERY_READY;
}

static bool onion_slice_shape_ok(const struct onion_fetch_state *st,
    size_t slice_len, const struct onion_reply_header *header, uint32_t k)
{
    uint8_t slice_digest[32];
    sha3_256(st->body + FILE_MARKET_ONION_REPLY_HEADER_BYTES, slice_len,
             slice_digest);
    return header->chunk_size > 0 &&
        header->chunk_size <= FILE_MARKET_CHUNK_SIZE &&
        header->slice_count ==
            (header->chunk_size + FILE_MARKET_ONION_SLICE_BYTES - 1) /
                FILE_MARKET_ONION_SLICE_BYTES &&
        header->slice_index == k &&
        memcmp(slice_digest, header->slice_sha3, 32) == 0 &&
        slice_len ==
            (k + 1 == header->slice_count
                 ? header->chunk_size -
                       (size_t)k * FILE_MARKET_ONION_SLICE_BYTES
                 : FILE_MARKET_ONION_SLICE_BYTES);
}

static bool onion_slice_bind(struct onion_fetch_state *st,
                             const struct onion_reply_header *header)
{
    if (st->assembled)
        return header->chunk_size == st->chunk_size &&
            header->slice_count == st->slice_count &&
            memcmp(header->chunk_sha3, st->chunk_sha3, 32) == 0;
    st->chunk_size = header->chunk_size;
    st->slice_count = header->slice_count;
    memcpy(st->chunk_sha3, header->chunk_sha3, 32);
    st->assembled = zcl_malloc(st->chunk_size,
                               "market onion chunk assembly");
    return st->assembled != NULL;
}

static enum file_market_delivery_status onion_fetch_slice(
    struct onion_fetch_state *st, const char *path, uint32_t k)
{
    struct onion_reply_header header;
    size_t body_len = 0;
    enum file_market_delivery_status status =
        onion_slice_fetch_once(st, path, &body_len, &header);
    if (status != FILE_MARKET_DELIVERY_READY)
        return status;
    if (header.status != FILE_MARKET_DELIVERY_READY)
        return (enum file_market_delivery_status)header.status;
    size_t slice_len = body_len - FILE_MARKET_ONION_REPLY_HEADER_BYTES;
    if (!onion_slice_shape_ok(st, slice_len, &header, k))
        return FILE_MARKET_DELIVERY_MALFORMED;
    if (!onion_slice_bind(st, &header))
        return FILE_MARKET_DELIVERY_MALFORMED;
    memcpy(st->assembled + (size_t)k * FILE_MARKET_ONION_SLICE_BYTES,
           st->body + FILE_MARKET_ONION_REPLY_HEADER_BYTES, slice_len);
    memory_cleanse(st->body, sizeof(st->body));
    return FILE_MARKET_DELIVERY_READY;
}

static enum file_market_delivery_status onion_fetch_finish(
    struct onion_fetch_state *st, struct file_market_delivery_chunk *out_chunk)
{
    uint8_t assembled_digest[32];
    int final_timeout_secs = 0;
    if (!onion_deadline_timeout(st->deadline_ms, &final_timeout_secs))
        return FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
    sha3_256(st->assembled, st->chunk_size, assembled_digest);
    if (!onion_deadline_timeout(st->deadline_ms, &final_timeout_secs))
        return FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
    if (memcmp(assembled_digest, st->chunk_sha3, 32) != 0)
        return FILE_MARKET_DELIVERY_MALFORMED;
    out_chunk->data = st->assembled;
    out_chunk->size = st->chunk_size;
    memcpy(out_chunk->sha3, st->chunk_sha3, 32);
    memory_cleanse(st->body, sizeof(st->body));
    memory_cleanse(assembled_digest, sizeof(assembled_digest));
    return FILE_MARKET_DELIVERY_READY;
}

static enum file_market_delivery_status onion_fetch_run(
    struct onion_fetch_state *st, struct file_market_delivery_chunk *out_chunk)
{
    for (uint32_t k = 0; !st->slice_count || k < st->slice_count; k++) {
        char path[sizeof(FILE_MARKET_ONION_PATH_PREFIX) +
                  ONION_REQUEST_HEX_CHARS + 16];
        snprintf(path, sizeof(path), "%s%s?slice=%u",
                 FILE_MARKET_ONION_PATH_PREFIX, st->request_hex, k);
        enum file_market_delivery_status status =
            onion_fetch_slice(st, path, k);
        if (status != FILE_MARKET_DELIVERY_READY)
            return onion_fetch_abort(st, status);
    }
    enum file_market_delivery_status status =
        onion_fetch_finish(st, out_chunk);
    if (status != FILE_MARKET_DELIVERY_READY)
        return onion_fetch_abort(st, status);
    return FILE_MARKET_DELIVERY_READY;
}

static enum file_market_delivery_status onion_fetch_with_deadline(
    file_market_delivery_onion_timed_get_fn get, void *get_ctx,
    int64_t deadline_ms,
    const uint8_t seller_onion_pubkey[32],
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32],
    struct file_market_delivery_chunk *out_chunk)
{
    if (out_chunk)
        memset(out_chunk, 0, sizeof(*out_chunk));
    if (!onion_fetch_args_valid(get, seller_onion_pubkey, network_genesis,
                                offer_id, buyer_pubkey, buyer_seed,
                                out_chunk))
        return FILE_MARKET_DELIVERY_MALFORMED;

    struct onion_fetch_state st;
    memset(&st, 0, sizeof(st));
    st.get = get;
    st.get_ctx = get_ctx;
    st.deadline_ms = deadline_ms;
    st.offer_id = offer_id;
    st.chunk_index = chunk_index;
    if (!onion_v3_address_from_pubkey(seller_onion_pubkey, st.onion_address))
        return FILE_MARKET_DELIVERY_MALFORMED;
    if (!onion_request_hex_build(network_genesis, offer_id, chunk_index,
                                 buyer_pubkey, buyer_seed, st.request_hex))
        return FILE_MARKET_DELIVERY_UNAUTHENTICATED;
    return onion_fetch_run(&st, out_chunk);
}

enum file_market_delivery_status file_market_delivery_fetch_onion_with(
    file_market_delivery_onion_get_fn get, void *get_ctx,
    const uint8_t seller_onion_pubkey[32],
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32],
    struct file_market_delivery_chunk *out_chunk)
{
    if (!get) {
        if (out_chunk)
            memset(out_chunk, 0, sizeof(*out_chunk));
        return FILE_MARKET_DELIVERY_MALFORMED;
    }
    struct onion_untimed_adapter adapter = {.get = get, .ctx = get_ctx};
    return onion_fetch_with_deadline(
        onion_untimed_get_with_timeout, &adapter, INT64_MAX,
        seller_onion_pubkey, network_genesis, offer_id, chunk_index,
        buyer_pubkey, buyer_seed, out_chunk);
}

enum file_market_delivery_status file_market_delivery_fetch_onion_with_deadline(
    file_market_delivery_onion_timed_get_fn get, void *get_ctx,
    int64_t deadline_ms, const uint8_t seller_onion_pubkey[32],
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32],
    struct file_market_delivery_chunk *out_chunk)
{
    return onion_fetch_with_deadline(
        get, get_ctx, deadline_ms, seller_onion_pubkey, network_genesis,
        offer_id, chunk_index, buyer_pubkey, buyer_seed, out_chunk);
}

/* Production GET port: one blocking embedded-Tor fetch per slice. The
 * dynhost layer treats any HTTP status >= 200 as transport-ok, so the 200
 * check happens here. */
static bool onion_tor_get(void *ctx, const char *onion_address,
                          const char *path, int timeout_secs,
                          uint8_t *body_out, size_t body_cap,
                          size_t *body_len)
{
    (void)ctx;
    struct onion_fetch_result result;
    memset(&result, 0, sizeof(result));
    int rc = tor_integration_fetch_onion_blocking(
        onion_address, path, &result, timeout_secs);
    if (rc != 0) {
        if (result.body && result.body_len > 0)
            memory_cleanse(result.body, result.body_len);
        free(result.body);
        return false;
    }
    bool ok = result.status == 200 && result.body_len <= body_cap;
    if (ok && result.body_len > 0 && result.body)
        memcpy(body_out, result.body, result.body_len);
    if (ok)
        *body_len = result.body_len;
    if (result.body && result.body_len > 0)
        memory_cleanse(result.body, result.body_len);
    free(result.body);
    return ok;
}

enum file_market_delivery_status file_market_delivery_fetch_onion_endpoint(
    const uint8_t seller_onion_pubkey[32],
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32],
    struct file_market_delivery_chunk *out_chunk)
{
    return file_market_delivery_fetch_onion_endpoint_until(
        seller_onion_pubkey, network_genesis, offer_id, chunk_index,
        buyer_pubkey, buyer_seed, INT64_MAX, out_chunk);
}

enum file_market_delivery_status file_market_delivery_fetch_onion_endpoint_until(
    const uint8_t seller_onion_pubkey[32],
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32], int64_t deadline_ms,
    struct file_market_delivery_chunk *out_chunk)
{
    return onion_fetch_with_deadline(
        onion_tor_get, NULL, deadline_ms, seller_onion_pubkey,
        network_genesis, offer_id, chunk_index, buyer_pubkey, buyer_seed,
        out_chunk);
}
