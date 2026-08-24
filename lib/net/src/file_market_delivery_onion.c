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

/* "/market/chunk/" + 412 lowercase hex chars of the 206-byte signed
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
    char hex[ONION_REQUEST_HEX_CHARS + 1];
    size_t hex_len = 0;
    while (p[hex_len] && p[hex_len] != '?' &&
           hex_len < ONION_REQUEST_HEX_CHARS + 1)
        hex_len++;
    if (hex_len != ONION_REQUEST_HEX_CHARS)
        return false;
    memcpy(hex, p, hex_len);
    hex[hex_len] = '\0';
    p += hex_len;
    if (!zcl_hex_decode_lower(hex, wire_out,
                              FILE_MARKET_DELIVERY_WIRE_BYTES))
        return false;
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
    if (!get || !seller_onion_pubkey || !network_genesis || !offer_id ||
        !buyer_pubkey || !buyer_seed || !out_chunk)
        return FILE_MARKET_DELIVERY_MALFORMED;

    char onion_address[ONION_V3_ADDRESS_LEN + 1];
    if (!onion_v3_address_from_pubkey(seller_onion_pubkey, onion_address))
        return FILE_MARKET_DELIVERY_MALFORMED;

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
        return FILE_MARKET_DELIVERY_UNAUTHENTICATED;
    uint8_t request_wire[FILE_MARKET_DELIVERY_WIRE_BYTES];
    if (file_market_delivery_request_encode(&request, request_wire) !=
        FILE_MARKET_DELIVERY_OK)
        return FILE_MARKET_DELIVERY_UNAUTHENTICATED;
    char request_hex[ONION_REQUEST_HEX_CHARS + 1];
    zcl_hex_encode(request_wire, sizeof(request_wire), request_hex);

    uint8_t *assembled = NULL;
    uint32_t chunk_size = 0, slice_count = 0;
    uint8_t chunk_sha3[32];
    memset(chunk_sha3, 0, sizeof(chunk_sha3));
    uint8_t body[FILE_MARKET_ONION_REPLY_MAX];
    memset(body, 0, sizeof(body));

    for (uint32_t k = 0; !slice_count || k < slice_count; k++) {
        char path[sizeof(FILE_MARKET_ONION_PATH_PREFIX) +
                  ONION_REQUEST_HEX_CHARS + 16];
        snprintf(path, sizeof(path), "%s%s?slice=%u",
                 FILE_MARKET_ONION_PATH_PREFIX, request_hex, k);
        size_t body_len = 0;
        int timeout_secs = 0;
        if (!onion_deadline_timeout(deadline_ms, &timeout_secs))
            goto resource_limit;
        if (!get(get_ctx, onion_address, path, timeout_secs, body,
                 sizeof(body), &body_len)) {
            if (!onion_deadline_timeout(deadline_ms, &timeout_secs))
                goto resource_limit;
            goto transport_fail;
        }
        if (!onion_deadline_timeout(deadline_ms, &timeout_secs))
            goto resource_limit;
        struct onion_reply_header header;
        if (!onion_reply_header_parse(body, body_len, &header) ||
            memcmp(header.offer_id, offer_id, 32) != 0 ||
            header.chunk_index != chunk_index)
            goto transport_fail;
        if (header.status != FILE_MARKET_DELIVERY_READY) {
            enum file_market_delivery_status status =
                (enum file_market_delivery_status)header.status;
            memory_cleanse(body, sizeof(body));
            onion_assembly_discard(assembled, chunk_size);
            return status;
        }
        size_t slice_len = body_len - FILE_MARKET_ONION_REPLY_HEADER_BYTES;
        uint8_t slice_digest[32];
        sha3_256(body + FILE_MARKET_ONION_REPLY_HEADER_BYTES, slice_len,
                 slice_digest);
        bool shape_ok = header.chunk_size > 0 &&
            header.chunk_size <= FILE_MARKET_CHUNK_SIZE &&
            header.slice_count ==
                (header.chunk_size + FILE_MARKET_ONION_SLICE_BYTES - 1) /
                    FILE_MARKET_ONION_SLICE_BYTES &&
            header.slice_index == k &&
            memcmp(slice_digest, header.slice_sha3, 32) == 0 &&
            slice_len ==
                (k + 1 == header.slice_count
                     ? header.chunk_size -
                           (size_t)k * FILE_MARKET_ONION_SLICE_BYTES
                     : FILE_MARKET_ONION_SLICE_BYTES);
        if (!shape_ok)
            goto malformed;
        if (!assembled) {
            chunk_size = header.chunk_size;
            slice_count = header.slice_count;
            memcpy(chunk_sha3, header.chunk_sha3, 32);
            assembled = zcl_malloc(chunk_size,
                                   "market onion chunk assembly");
            if (!assembled)
                goto malformed;
        } else if (header.chunk_size != chunk_size ||
                   header.slice_count != slice_count ||
                   memcmp(header.chunk_sha3, chunk_sha3, 32) != 0) {
            goto malformed;
        }
        memcpy(assembled + (size_t)k * FILE_MARKET_ONION_SLICE_BYTES,
               body + FILE_MARKET_ONION_REPLY_HEADER_BYTES, slice_len);
        memory_cleanse(body, sizeof(body));
    }

    uint8_t assembled_digest[32];
    int final_timeout_secs = 0;
    if (!onion_deadline_timeout(deadline_ms, &final_timeout_secs))
        goto resource_limit;
    sha3_256(assembled, chunk_size, assembled_digest);
    if (!onion_deadline_timeout(deadline_ms, &final_timeout_secs))
        goto resource_limit;
    if (memcmp(assembled_digest, chunk_sha3, 32) != 0)
        goto malformed;
    out_chunk->data = assembled;
    out_chunk->size = chunk_size;
    memcpy(out_chunk->sha3, chunk_sha3, 32);
    memory_cleanse(body, sizeof(body));
    memory_cleanse(assembled_digest, sizeof(assembled_digest));
    return FILE_MARKET_DELIVERY_READY;

transport_fail:
    memory_cleanse(body, sizeof(body));
    onion_assembly_discard(assembled, chunk_size);
    return FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN;
resource_limit:
    memory_cleanse(body, sizeof(body));
    onion_assembly_discard(assembled, chunk_size);
    return FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
malformed:
    memory_cleanse(body, sizeof(body));
    onion_assembly_discard(assembled, chunk_size);
    return FILE_MARKET_DELIVERY_MALFORMED;
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
