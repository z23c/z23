/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: characterization pins for the onion chunk transport in
 * core/modules/net/src/file_market_delivery_onion.c, written before its
 * split. The request-path parser (onion_parse_path) is driven through
 * file_market_delivery_onion_handle_request; the buyer slice loop
 * (onion_fetch_with_deadline) through
 * file_market_delivery_fetch_onion_with_deadline over a scripted GET port.
 * Every expectation is the literal behaviour the code has today. Nothing
 * here opens a socket, a file or Tor. */

#include "test/test_core.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "net/file_market.h"
#include "net/file_market_delivery.h"
#include "net/onion_v3_address.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ONION_HEX_CHARS (2u * FILE_MARKET_DELIVERY_WIRE_BYTES)
#define ONION_PATH_CAP \
    (sizeof(FILE_MARKET_ONION_PATH_PREFIX) + ONION_HEX_CHARS + 64u)
#define ONION_SCRIPT_CALLS 3
#define ONION_TWO_SLICE_BYTES (FILE_MARKET_ONION_SLICE_BYTES + 1u)
#define ONION_FETCH_CHUNK 7u
#define ONION_READY_BYTES 5u
#define ONION_VECTOR_PUBKEY \
    "adadec040be047f9658668b11a504f3155001f231a37f54c4476c07fb4cc139e"

#define ONION_HEAD_200_124 \
    "HTTP/1.1 200 OK\r\n" \
    "Content-Type: engine/application/octet-stream\r\n" \
    "Content-Length: 124\r\n" \
    "Cache-Control: no-store\r\n" \
    "Connection: close\r\n\r\n"
#define ONION_HEAD_200_129 \
    "HTTP/1.1 200 OK\r\n" \
    "Content-Type: engine/application/octet-stream\r\n" \
    "Content-Length: 129\r\n" \
    "Cache-Control: no-store\r\n" \
    "Connection: close\r\n\r\n"
#define ONION_E405 \
    "HTTP/1.1 405 Method Not Allowed\r\n" \
    "Content-Type: text/plain; charset=utf-8\r\n" \
    "Content-Length: 9\r\n" \
    "Cache-Control: no-store\r\n" \
    "Connection: close\r\n\r\n" \
    "GET only\n"
#define ONION_E400_PATH \
    "HTTP/1.1 400 Bad Request\r\n" \
    "Content-Type: text/plain; charset=utf-8\r\n" \
    "Content-Length: 28\r\n" \
    "Cache-Control: no-store\r\n" \
    "Connection: close\r\n\r\n" \
    "malformed market chunk path\n"
#define ONION_E400_REQ \
    "HTTP/1.1 400 Bad Request\r\n" \
    "Content-Type: text/plain; charset=utf-8\r\n" \
    "Content-Length: 31\r\n" \
    "Cache-Control: no-store\r\n" \
    "Connection: close\r\n\r\n" \
    "malformed market chunk request\n"
#define ONION_E400_SLICE \
    "HTTP/1.1 400 Bad Request\r\n" \
    "Content-Type: text/plain; charset=utf-8\r\n" \
    "Content-Length: 19\r\n" \
    "Cache-Control: no-store\r\n" \
    "Connection: close\r\n\r\n" \
    "slice out of range\n"

#define ONION_CHECK(label, condition) do {                          \
    printf("file_market_delivery_onion: %s... ", (label));          \
    if (condition) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

static const uint8_t k_reply_magic[8] = {'Z','F','O','C','K','S','1','\n'};
static const uint8_t k_zero32[32] = {0};

struct onion_script {
    int calls;
    int timeouts[ONION_SCRIPT_CALLS];
    uint32_t slice_asked[ONION_SCRIPT_CALLS];
    bool address_ok[ONION_SCRIPT_CALLS];
    bool get_ok[ONION_SCRIPT_CALLS];
    size_t body_len[ONION_SCRIPT_CALLS];
    uint8_t body[ONION_SCRIPT_CALLS][FILE_MARKET_ONION_REPLY_MAX];
};

struct reply_spec {
    uint16_t version;
    uint16_t status;
    uint8_t offer_id[32];
    uint32_t chunk_index;
    uint32_t chunk_size;
    uint32_t slice_index;
    uint32_t slice_count;
    uint8_t chunk_sha3[32];
    uint8_t slice_sha3[32];
};

struct onion_handler_cfg {
    enum file_market_delivery_authorization authorization;
    bool hidden;
    int authorize_calls;
    int load_calls;
    int moderation_calls;
};

struct slice_row {
    const char *label;
    const char *suffix;
    uint32_t slice;
};

static uint8_t g_genesis[32];
static uint8_t g_offer[32];
static uint8_t g_seed[32];
static uint8_t g_buyer_pub[32];
static uint8_t g_seller_pub[32];
static char g_seller_address[ONION_V3_ADDRESS_LEN + 1];
static char g_hex[ONION_HEX_CHARS + 1];
static uint8_t g_chunk[ONION_TWO_SLICE_BYTES];
static uint8_t g_resp[FILE_MARKET_ONION_REPLY_MAX + 512];
static struct onion_script g_script;
static struct onion_handler_cfg g_cfg;
static int64_t g_fake_now_us;
static struct platform_clock_source g_clock;

static int64_t onion_fake_monotonic(void *opaque)
{
    (void)opaque;
    return g_fake_now_us;
}

static int64_t onion_fake_wall(void *opaque)
{
    (void)opaque;
    return 1;
}

static void clock_fake_set(int64_t now_us)
{
    g_fake_now_us = now_us;
    g_clock.monotonic_us = onion_fake_monotonic;
    g_clock.wall_unix = onion_fake_wall;
    g_clock.user = NULL;
    platform_clock_set_source(&g_clock);
}

static void clock_fake_clear(void)
{
    platform_clock_clear_source();
}

static enum file_market_delivery_authorization onion_cfg_authorize(
    const uint8_t offer_id[32], const uint8_t buyer_pubkey[32],
    uint32_t chunk_index, void *ctx)
{
    struct onion_handler_cfg *cfg = ctx;
    (void)offer_id;
    (void)buyer_pubkey;
    (void)chunk_index;
    cfg->authorize_calls++;
    return cfg->authorization;
}

static bool onion_cfg_load(const uint8_t offer_id[32], uint32_t chunk_index,
                           struct file_market_delivery_chunk *out, void *ctx)
{
    struct onion_handler_cfg *cfg = ctx;
    (void)offer_id;
    (void)chunk_index;
    cfg->load_calls++;
    out->data = zcl_malloc(ONION_READY_BYTES, "onion_test_chunk");
    if (!out->data)
        return false;
    memcpy(out->data, g_chunk, ONION_READY_BYTES);
    out->size = ONION_READY_BYTES;
    sha3_256(out->data, ONION_READY_BYTES, out->sha3);
    return true;
}

static bool onion_cfg_moderation(const uint8_t offer_id[32], void *ctx)
{
    struct onion_handler_cfg *cfg = ctx;
    (void)offer_id;
    cfg->moderation_calls++;
    return !cfg->hidden;
}

static bool onion_wire_make(uint32_t chunk_index,
                            uint8_t wire[FILE_MARKET_DELIVERY_WIRE_BYTES],
                            char hex[ONION_HEX_CHARS + 1])
{
    struct file_market_delivery_request request;
    memset(&request, 0, sizeof(request));
    request.version = FILE_MARKET_DELIVERY_VERSION;
    memcpy(request.network_genesis, g_genesis, 32);
    memcpy(request.offer_id, g_offer, 32);
    request.chunk_index = chunk_index;
    memcpy(request.buyer_pubkey, g_buyer_pub, 32);
    file_market_delivery_onion_session_id(g_genesis, g_offer, g_buyer_pub,
                                          request.session_id);
    if (file_market_delivery_request_seal(&request, g_seed) !=
        FILE_MARKET_DELIVERY_OK)
        return false;
    if (file_market_delivery_request_encode(&request, wire) !=
        FILE_MARKET_DELIVERY_OK)
        return false;
    zcl_hex_encode(wire, FILE_MARKET_DELIVERY_WIRE_BYTES, hex);
    return true;
}

static bool onion_fixture_init(void)
{
    uint8_t secret[32];
    uint8_t wire[FILE_MARKET_DELIVERY_WIRE_BYTES];
    memset(g_genesis, 0x47, sizeof(g_genesis));
    memset(g_offer, 0x5a, sizeof(g_offer));
    memset(g_seed, 0x21, sizeof(g_seed));
    ed25519_keypair(g_buyer_pub, secret, g_seed);
    memset(secret, 0, sizeof(secret));
    for (size_t i = 0; i < sizeof(g_chunk); i++)
        g_chunk[i] = (uint8_t)(i * 7u + 3u);
    return zcl_hex_decode(ONION_VECTOR_PUBKEY, g_seller_pub, 32) &&
        onion_v3_address_from_pubkey(g_seller_pub, g_seller_address) &&
        onion_wire_make(ONION_FETCH_CHUNK, wire, g_hex);
}

static void path_make(char *out, size_t cap, const char *hex, size_t hex_len,
                      const char *suffix)
{
    snprintf(out, cap, "%s%.*s%s", FILE_MARKET_ONION_PATH_PREFIX,
             (int)hex_len, hex, suffix);
}

static size_t onion_get(const char *path)
{
    return file_market_delivery_onion_handle_request(
        "GET", path, NULL, 0, g_resp, sizeof(g_resp));
}

static bool resp_is(const uint8_t *resp, size_t len, const char *want)
{
    size_t n = strlen(want);
    return len == n && memcmp(resp, want, n) == 0;
}

/* Returns the bytes after `head` when the response starts with exactly
 * that head literal, else NULL. */
static const uint8_t *resp_body_after(const uint8_t *resp, size_t len,
                                      const char *head, size_t *body_len)
{
    size_t hn = strlen(head);
    if (len < hn || memcmp(resp, head, hn) != 0)
        return NULL;
    *body_len = len - hn;
    return resp + hn;
}

static bool reply_decode(const uint8_t *body, size_t len,
                         struct reply_spec *r)
{
    if (!body || len < FILE_MARKET_ONION_REPLY_HEADER_BYTES ||
        memcmp(body, k_reply_magic, sizeof(k_reply_magic)) != 0)
        return false;
    memset(r, 0, sizeof(*r));
    r->version = zcl_read_u16_le(body + 8);
    r->status = zcl_read_u16_le(body + 10);
    memcpy(r->offer_id, body + 12, 32);
    r->chunk_index = zcl_read_u32_le(body + 44);
    r->chunk_size = zcl_read_u32_le(body + 48);
    r->slice_index = zcl_read_u32_le(body + 52);
    r->slice_count = zcl_read_u32_le(body + 56);
    memcpy(r->chunk_sha3, body + 60, 32);
    memcpy(r->slice_sha3, body + 92, 32);
    return true;
}

static void reply_encode(uint8_t *out, const struct reply_spec *r)
{
    memcpy(out, k_reply_magic, sizeof(k_reply_magic));
    zcl_write_u16_le(out + 8, r->version);
    zcl_write_u16_le(out + 10, r->status);
    memcpy(out + 12, r->offer_id, 32);
    zcl_write_u32_le(out + 44, r->chunk_index);
    zcl_write_u32_le(out + 48, r->chunk_size);
    zcl_write_u32_le(out + 52, r->slice_index);
    zcl_write_u32_le(out + 56, r->slice_count);
    memcpy(out + 60, r->chunk_sha3, 32);
    memcpy(out + 92, r->slice_sha3, 32);
}

/* A well-formed READY reply for slice `slice_index` of a chunk of
 * `chunk_size` bytes taken from g_chunk. */
static void spec_default(struct reply_spec *r, uint32_t chunk_size,
                         uint32_t slice_index, uint32_t slice_count,
                         const uint8_t *slice, size_t slice_len)
{
    memset(r, 0, sizeof(*r));
    r->version = 1;
    r->status = (uint16_t)FILE_MARKET_DELIVERY_READY;
    memcpy(r->offer_id, g_offer, 32);
    r->chunk_index = ONION_FETCH_CHUNK;
    r->chunk_size = chunk_size;
    r->slice_index = slice_index;
    r->slice_count = slice_count;
    sha3_256(g_chunk, chunk_size, r->chunk_sha3);
    sha3_256(slice, slice_len, r->slice_sha3);
}

static void script_reset(void)
{
    memset(&g_script, 0, sizeof(g_script));
}

static void script_arm(int i, const struct reply_spec *r,
                       const uint8_t *slice, size_t slice_len)
{
    reply_encode(g_script.body[i], r);
    if (slice_len > 0)
        memcpy(g_script.body[i] + FILE_MARKET_ONION_REPLY_HEADER_BYTES,
               slice, slice_len);
    g_script.body_len[i] = FILE_MARKET_ONION_REPLY_HEADER_BYTES + slice_len;
    g_script.get_ok[i] = true;
}

static bool onion_script_get(void *ctx, const char *onion_address,
                             const char *path, int timeout_secs,
                             uint8_t *body_out, size_t body_cap,
                             size_t *body_len)
{
    struct onion_script *s = ctx;
    if (s->calls >= ONION_SCRIPT_CALLS) {
        s->calls++;
        return false;
    }
    int i = s->calls++;
    s->timeouts[i] = timeout_secs;
    s->address_ok[i] = strcmp(onion_address, g_seller_address) == 0;
    const char *eq = strrchr(path, '=');
    s->slice_asked[i] = eq ? (uint32_t)strtoul(eq + 1, NULL, 10)
                           : UINT32_MAX;
    if (!s->get_ok[i] || s->body_len[i] > body_cap)
        return false;
    memcpy(body_out, s->body[i], s->body_len[i]);
    *body_len = s->body_len[i];
    return true;
}

static enum file_market_delivery_status fetch_probe(
    const uint8_t *seller, const uint8_t *genesis, const uint8_t *offer,
    const uint8_t *buyer, const uint8_t *seed, int64_t deadline_ms,
    struct file_market_delivery_chunk *out)
{
    memset(out, 0xA5, sizeof(*out));
    return file_market_delivery_fetch_onion_with_deadline(
        onion_script_get, &g_script, deadline_ms, seller, genesis, offer,
        ONION_FETCH_CHUNK, buyer, seed, out);
}

static enum file_market_delivery_status fetch_good(
    int64_t deadline_ms, struct file_market_delivery_chunk *out)
{
    return fetch_probe(g_seller_pub, g_genesis, g_offer, g_buyer_pub,
                       g_seed, deadline_ms, out);
}

static bool chunk_is_empty(const struct file_market_delivery_chunk *c)
{
    return c->data == NULL && c->size == 0 &&
        memcmp(c->sha3, k_zero32, sizeof(k_zero32)) == 0;
}

static bool chunk_matches_fixture(const struct file_market_delivery_chunk *c,
                                  uint32_t size)
{
    return c->data != NULL && c->size == size &&
        memcmp(c->data, g_chunk, size) == 0;
}

static void onion_handler_authorize_arm(
    enum file_market_delivery_authorization authorization, bool hidden)
{
    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.authorization = authorization;
    g_cfg.hidden = hidden;
    file_market_delivery_set_handlers(g_genesis, onion_cfg_authorize,
                                      onion_cfg_load, onion_cfg_moderation,
                                      &g_cfg);
}

/* ── Request-path parser, through the public handler ── */

static int onion_run_method_checks(void)
{
    int failures = 0;
    size_t n = file_market_delivery_onion_handle_request(
        NULL, "/market/chunk/", NULL, 0, g_resp, sizeof(g_resp));
    ONION_CHECK("null method is refused as not GET",
        resp_is(g_resp, n, ONION_E405));
    n = file_market_delivery_onion_handle_request(
        "POST", "/market/chunk/", NULL, 0, g_resp, sizeof(g_resp));
    ONION_CHECK("POST is refused before the path is read",
        resp_is(g_resp, n, ONION_E405));
    n = file_market_delivery_onion_handle_request(
        "get", "/market/chunk/", NULL, 0, g_resp, sizeof(g_resp));
    ONION_CHECK("lowercase get is refused (method match is exact)",
        resp_is(g_resp, n, ONION_E405));
    n = file_market_delivery_onion_handle_request(
        "POST", "/market/chunk/", NULL, 0, g_resp, 10);
    ONION_CHECK("refusal into a 10-byte buffer writes nothing",
        n == 0);
    return failures;
}

static int onion_run_prefix_checks(void)
{
    int failures = 0;
    char path[ONION_PATH_CAP];
    size_t n = onion_get(NULL);
    ONION_CHECK("null path is a malformed market chunk path",
        resp_is(g_resp, n, ONION_E400_PATH));
    n = onion_get("");
    ONION_CHECK("empty path is a malformed market chunk path",
        resp_is(g_resp, n, ONION_E400_PATH));
    n = onion_get("/market/chunk");
    ONION_CHECK("prefix without trailing slash is refused",
        resp_is(g_resp, n, ONION_E400_PATH));
    snprintf(path, sizeof(path), "/market/chunks/%s", g_hex);
    n = onion_get(path);
    ONION_CHECK("near-miss prefix chunks is refused",
        resp_is(g_resp, n, ONION_E400_PATH));
    snprintf(path, sizeof(path), "market/chunk/%s", g_hex);
    n = onion_get(path);
    ONION_CHECK("prefix without leading slash is refused",
        resp_is(g_resp, n, ONION_E400_PATH));
    return failures;
}

static int onion_run_accept_checks(void)
{
    int failures = 0;
    static const struct slice_row rows[] = {
        {"onion path accepts bare request hex (no slice)", "", 0},
        {"onion path accepts ?slice=0", "?slice=0", 0},
        {"onion path accepts ?slice=2", "?slice=2", 2},
        {"onion path accepts ?slice=100000 (boundary)", "?slice=100000",
         100000u},
        {"onion path accepts ?slice=100001", "?slice=100001", 100001u},
        {"onion path accepts ?slice=1000000 (seven digits)",
         "?slice=1000000", 1000000u},
    };
    char path[ONION_PATH_CAP];
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        path_make(path, sizeof(path), g_hex, ONION_HEX_CHARS,
                  rows[i].suffix);
        size_t n = onion_get(path);
        size_t bl = 0;
        const uint8_t *body = resp_body_after(g_resp, n, ONION_HEAD_200_124,
                                              &bl);
        struct reply_spec r = {0};
        bool ok = body != NULL && bl == FILE_MARKET_ONION_REPLY_HEADER_BYTES &&
            reply_decode(body, bl, &r) &&
            r.status == (uint16_t)FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN;
        ok = ok && r.slice_index == rows[i].slice && r.slice_count == 0 &&
            r.chunk_size == 0 && r.chunk_index == ONION_FETCH_CHUNK &&
            memcmp(r.offer_id, g_offer, 32) == 0;
        ONION_CHECK(rows[i].label, ok);
    }
    return failures;
}

static int onion_run_refuse_suffix_checks(void)
{
    int failures = 0;
    static const struct slice_row rows[] = {
        {"onion path refuses bare ?slice= with no digits", "?slice=", 0},
        {"onion path refuses ?slice=1x (trailing junk)", "?slice=1x", 0},
        {"onion path refuses ?slice=-1", "?slice=-1", 0},
        {"onion path refuses ?slice=+1", "?slice=+1", 0},
        {"onion path refuses ?slice=10000000 (eight digits)",
         "?slice=10000000", 0},
        {"onion path refuses ?slice=99999999999", "?slice=99999999999", 0},
        {"onion path refuses an unknown query key", "?page=1", 0},
        {"onion path refuses & instead of ?", "&slice=1", 0},
        {"onion path refuses a second query parameter", "?slice=1&x=1", 0},
        {"onion path refuses a stray tail after the hex", "x", 0},
    };
    char path[ONION_PATH_CAP];
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        path_make(path, sizeof(path), g_hex, ONION_HEX_CHARS,
                  rows[i].suffix);
        size_t n = onion_get(path);
        ONION_CHECK(rows[i].label, resp_is(g_resp, n, ONION_E400_REQ));
    }
    return failures;
}

static int onion_run_refuse_hex_checks(void)
{
    int failures = 0;
    char path[ONION_PATH_CAP];
    char mut[ONION_HEX_CHARS + 1];
    size_t n;
    path_make(path, sizeof(path), g_hex, ONION_HEX_CHARS - 1, "");
    n = onion_get(path);
    ONION_CHECK("onion path refuses 427 hex chars",
        resp_is(g_resp, n, ONION_E400_REQ));
    path_make(path, sizeof(path), g_hex, ONION_HEX_CHARS, "0");
    n = onion_get(path);
    ONION_CHECK("onion path refuses 429 hex chars",
        resp_is(g_resp, n, ONION_E400_REQ));
    path_make(path, sizeof(path), g_hex, 0, "");
    n = onion_get(path);
    ONION_CHECK("onion path refuses empty hex",
        resp_is(g_resp, n, ONION_E400_REQ));
    path_make(path, sizeof(path), g_hex, 0, "?slice=1");
    n = onion_get(path);
    ONION_CHECK("onion path refuses a query with no hex",
        resp_is(g_resp, n, ONION_E400_REQ));
    memcpy(mut, g_hex, sizeof(mut));
    mut[0] = 'G';
    path_make(path, sizeof(path), mut, ONION_HEX_CHARS, "");
    n = onion_get(path);
    ONION_CHECK("onion path refuses a non-hex character",
        resp_is(g_resp, n, ONION_E400_REQ));
    mut[0] = 'A';
    path_make(path, sizeof(path), mut, ONION_HEX_CHARS, "");
    n = onion_get(path);
    ONION_CHECK("onion path refuses uppercase hex (lower-only decode)",
        resp_is(g_resp, n, ONION_E400_REQ));
    return failures;
}

static int onion_run_slice_checks(void)
{
    int failures = 0;
    failures += onion_run_accept_checks();
    failures += onion_run_refuse_suffix_checks();
    failures += onion_run_refuse_hex_checks();
    return failures;
}

static int onion_run_path_checks(void)
{
    int failures = 0;
    failures += onion_run_prefix_checks();
    failures += onion_run_slice_checks();
    return failures;
}

/* ── Handler-configured path: READY, slice range, refusals ── */

static int onion_run_ready_checks(void)
{
    int failures = 0;
    char path[ONION_PATH_CAP];
    size_t n;
    size_t bl = 0;
    struct reply_spec r = {0};
    uint8_t want[32];
    onion_handler_authorize_arm(FILE_MARKET_DELIVERY_AUTHORIZED, false);
    path_make(path, sizeof(path), g_hex, ONION_HEX_CHARS, "?slice=0");
    n = onion_get(path);
    const uint8_t *body = resp_body_after(g_resp, n, ONION_HEAD_200_129,
                                          &bl);
    bool ok = body != NULL && bl == FILE_MARKET_ONION_REPLY_HEADER_BYTES +
        ONION_READY_BYTES && reply_decode(body, bl, &r);
    ONION_CHECK("handler-backed slice 0 is a 200 with READY header", ok);
    ok = ok && r.status == (uint16_t)FILE_MARKET_DELIVERY_READY &&
        r.chunk_size == ONION_READY_BYTES && r.slice_index == 0 &&
        r.slice_count == 1;
    ONION_CHECK("READY header carries size 5, slice 0 of 1", ok);
    sha3_256(g_chunk, ONION_READY_BYTES, want);
    ok = ok && memcmp(r.chunk_sha3, want, 32) == 0 &&
        memcmp(r.slice_sha3, want, 32) == 0 &&
        memcmp(body + FILE_MARKET_ONION_REPLY_HEADER_BYTES, g_chunk,
               ONION_READY_BYTES) == 0;
    ONION_CHECK("READY payload is the chunk bytes with matching digests",
        ok && g_cfg.load_calls == 1);

    path_make(path, sizeof(path), g_hex, ONION_HEX_CHARS, "?slice=1");
    n = onion_get(path);
    ONION_CHECK("slice 1 of a one-slice chunk is out of range",
        resp_is(g_resp, n, ONION_E400_SLICE));
    file_market_delivery_reset_handlers();
    return failures;
}

static int onion_run_ready_refusal_checks(void)
{
    int failures = 0;
    char path[ONION_PATH_CAP];
    size_t n;
    size_t bl = 0;
    struct reply_spec r = {0};
    path_make(path, sizeof(path), g_hex, ONION_HEX_CHARS, "?slice=0");
    onion_handler_authorize_arm(FILE_MARKET_DELIVERY_AUTHORIZED, true);
    n = onion_get(path);
    const uint8_t *body = resp_body_after(g_resp, n, ONION_HEAD_200_124,
                                          &bl);
    ONION_CHECK("hidden chunk reports MODERATION_HIDDEN in the header",
        body != NULL && reply_decode(body, bl, &r) &&
        r.status == (uint16_t)FILE_MARKET_DELIVERY_MODERATION_HIDDEN);
    ONION_CHECK("hidden chunk never reaches the content reader",
        g_cfg.load_calls == 0 && g_cfg.moderation_calls == 1);

    onion_handler_authorize_arm(FILE_MARKET_DELIVERY_PENDING, false);
    n = onion_get(path);
    body = resp_body_after(g_resp, n, ONION_HEAD_200_124, &bl);
    ONION_CHECK("pending payment reports PAYMENT_PENDING in the header",
        body != NULL && reply_decode(body, bl, &r) &&
        r.status == (uint16_t)FILE_MARKET_DELIVERY_PAYMENT_PENDING);
    ONION_CHECK("pending payment never reaches the content reader",
        g_cfg.load_calls == 0 && g_cfg.authorize_calls == 1);
    file_market_delivery_reset_handlers();
    return failures;
}

static int onion_run_ready_checks_all(void)
{
    int failures = 0;
    failures += onion_run_ready_checks();
    failures += onion_run_ready_refusal_checks();
    return failures;
}

/* ── Buyer fetch loop, through the deadline entry point ── */

static int onion_run_fetch_guard_checks(void)
{
    int failures = 0;
    struct file_market_delivery_chunk out;
    enum file_market_delivery_status status;
    script_reset();
    memset(&out, 0xA5, sizeof(out));
    status = file_market_delivery_fetch_onion_with_deadline(
        NULL, NULL, INT64_MAX, g_seller_pub, g_genesis, g_offer,
        ONION_FETCH_CHUNK, g_buyer_pub, g_seed, &out);
    ONION_CHECK("null GET port is MALFORMED and zeroes the out chunk",
        status == FILE_MARKET_DELIVERY_MALFORMED && chunk_is_empty(&out));
    status = file_market_delivery_fetch_onion_with_deadline(
        onion_script_get, &g_script, INT64_MAX, g_seller_pub, g_genesis,
        g_offer, ONION_FETCH_CHUNK, g_buyer_pub, g_seed, NULL);
    ONION_CHECK("null out chunk is MALFORMED with no GET",
        status == FILE_MARKET_DELIVERY_MALFORMED && g_script.calls == 0);
    return failures;
}

static bool fetch_refused_no_get(const uint8_t *seller,
                                 const uint8_t *genesis,
                                 const uint8_t *offer,
                                 const uint8_t *buyer, const uint8_t *seed)
{
    struct file_market_delivery_chunk out;
    script_reset();
    enum file_market_delivery_status status = fetch_probe(
        seller, genesis, offer, buyer, seed, INT64_MAX, &out);
    return status == FILE_MARKET_DELIVERY_MALFORMED &&
        g_script.calls == 0 && chunk_is_empty(&out);
}

static int onion_run_fetch_argument_checks(void)
{
    int failures = 0;
    uint8_t zero_seller[32] = {0};
    uint8_t wrong_buyer[32];
    struct file_market_delivery_chunk out;
    memcpy(wrong_buyer, g_buyer_pub, sizeof(wrong_buyer));
    wrong_buyer[0] ^= 1;
    ONION_CHECK("null seller pubkey is MALFORMED with no GET",
        fetch_refused_no_get(NULL, g_genesis, g_offer, g_buyer_pub, g_seed));
    ONION_CHECK("null network genesis is MALFORMED with no GET",
        fetch_refused_no_get(g_seller_pub, NULL, g_offer, g_buyer_pub,
                             g_seed));
    ONION_CHECK("null offer id is MALFORMED with no GET",
        fetch_refused_no_get(g_seller_pub, g_genesis, NULL, g_buyer_pub,
                             g_seed));
    ONION_CHECK("null buyer pubkey is MALFORMED with no GET",
        fetch_refused_no_get(g_seller_pub, g_genesis, g_offer, NULL,
                             g_seed));
    ONION_CHECK("null buyer seed is MALFORMED with no GET",
        fetch_refused_no_get(g_seller_pub, g_genesis, g_offer, g_buyer_pub,
                             NULL));
    ONION_CHECK("all-zero seller pubkey has no onion address (MALFORMED)",
        fetch_refused_no_get(zero_seller, g_genesis, g_offer, g_buyer_pub,
                             g_seed));
    script_reset();
    enum file_market_delivery_status status = fetch_probe(
        g_seller_pub, g_genesis, g_offer, wrong_buyer, g_seed, INT64_MAX,
        &out);
    ONION_CHECK("buyer pubkey not derived from the seed is UNAUTHENTICATED",
        status == FILE_MARKET_DELIVERY_UNAUTHENTICATED &&
        g_script.calls == 0 && chunk_is_empty(&out));
    return failures;
}

static int onion_run_fetch_clock_checks(void)
{
    int failures = 0;
    struct file_market_delivery_chunk out;
    enum file_market_delivery_status status;
    script_reset();
    status = fetch_probe(g_seller_pub, g_genesis, g_offer, g_buyer_pub,
                         g_seed, 0, &out);
    ONION_CHECK("deadline 0 on the real clock is RESOURCE_LIMIT, no GET",
        status == FILE_MARKET_DELIVERY_RESOURCE_LIMIT &&
        g_script.calls == 0 && chunk_is_empty(&out));

    clock_fake_set(1000000);
    script_reset();
    status = fetch_good(1000, &out);
    ONION_CHECK("deadline equal to now stops before the first GET",
        status == FILE_MARKET_DELIVERY_RESOURCE_LIMIT &&
        g_script.calls == 0 && chunk_is_empty(&out));
    script_reset();
    status = fetch_good(1500, &out);
    ONION_CHECK("sub-second remaining budget stops before the first GET",
        status == FILE_MARKET_DELIVERY_RESOURCE_LIMIT &&
        g_script.calls == 0);
    script_reset();
    status = fetch_good(3500, &out);
    ONION_CHECK("2.5 s remaining gives the first GET a 2 s timeout",
        status == FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN &&
        g_script.calls == 1 && g_script.timeouts[0] == 2);
    script_reset();
    status = fetch_good(90000, &out);
    ONION_CHECK("89 s remaining clamps the GET timeout to 60 s",
        status == FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN &&
        g_script.calls == 1 && g_script.timeouts[0] == 60);
    clock_fake_clear();

    clock_fake_set(0);
    script_reset();
    status = fetch_good(5000, &out);
    ONION_CHECK("a non-positive clock reading is RESOURCE_LIMIT, no GET",
        status == FILE_MARKET_DELIVERY_RESOURCE_LIMIT &&
        g_script.calls == 0);
    clock_fake_clear();
    return failures;
}

static int onion_run_fetch_ready_checks(void)
{
    int failures = 0;
    struct reply_spec r;
    struct file_market_delivery_chunk out;
    enum file_market_delivery_status status;
    script_reset();
    spec_default(&r, ONION_READY_BYTES, 0, 1, g_chunk, ONION_READY_BYTES);
    script_arm(0, &r, g_chunk, ONION_READY_BYTES);
    status = fetch_good(INT64_MAX, &out);
    ONION_CHECK("one-slice fetch returns READY with the chunk bytes",
        status == FILE_MARKET_DELIVERY_READY &&
        chunk_matches_fixture(&out, ONION_READY_BYTES) &&
        memcmp(out.sha3, r.chunk_sha3, 32) == 0);
    ONION_CHECK("one-slice fetch uses one GET for ?slice=0 at 60 s",
        g_script.calls == 1 && g_script.timeouts[0] == 60 &&
        g_script.slice_asked[0] == 0 && g_script.address_ok[0]);
    free(out.data);

    script_reset();
    spec_default(&r, ONION_TWO_SLICE_BYTES, 0, 2, g_chunk,
                 FILE_MARKET_ONION_SLICE_BYTES);
    script_arm(0, &r, g_chunk, FILE_MARKET_ONION_SLICE_BYTES);
    spec_default(&r, ONION_TWO_SLICE_BYTES, 1, 2, g_chunk +
                 FILE_MARKET_ONION_SLICE_BYTES, 1);
    script_arm(1, &r, g_chunk + FILE_MARKET_ONION_SLICE_BYTES, 1);
    status = fetch_good(INT64_MAX, &out);
    ONION_CHECK("two-slice fetch reassembles the chunk byte for byte",
        status == FILE_MARKET_DELIVERY_READY &&
        chunk_matches_fixture(&out, ONION_TWO_SLICE_BYTES));
    ONION_CHECK("two-slice fetch asks for ?slice=0 then ?slice=1",
        g_script.calls == 2 && g_script.slice_asked[0] == 0 &&
        g_script.slice_asked[1] == 1);
    free(out.data);
    return failures;
}

static bool fetch_one_slice_refused(struct reply_spec *r, uint32_t slice_len,
                                    enum file_market_delivery_status want,
                                    struct file_market_delivery_chunk *out)
{
    script_reset();
    script_arm(0, r, g_chunk, slice_len);
    enum file_market_delivery_status status = fetch_good(INT64_MAX, out);
    return status == want && g_script.calls == 1 && chunk_is_empty(out);
}

static int onion_run_fetch_shape_checks(void)
{
    int failures = 0;
    struct reply_spec r;
    struct file_market_delivery_chunk out;
    spec_default(&r, ONION_READY_BYTES, 0, 1, g_chunk, ONION_READY_BYTES);
    r.chunk_sha3[0] ^= 0xff;
    ONION_CHECK("whole-chunk digest mismatch is MALFORMED",
        fetch_one_slice_refused(&r, ONION_READY_BYTES,
            FILE_MARKET_DELIVERY_MALFORMED, &out));
    spec_default(&r, ONION_READY_BYTES, 0, 1, g_chunk, ONION_READY_BYTES);
    r.slice_sha3[0] ^= 0xff;
    ONION_CHECK("slice digest mismatch is MALFORMED",
        fetch_one_slice_refused(&r, ONION_READY_BYTES,
            FILE_MARKET_DELIVERY_MALFORMED, &out));
    spec_default(&r, ONION_READY_BYTES, 1, 1, g_chunk, ONION_READY_BYTES);
    ONION_CHECK("reply for slice 1 when slice 0 was asked is MALFORMED",
        fetch_one_slice_refused(&r, ONION_READY_BYTES,
            FILE_MARKET_DELIVERY_MALFORMED, &out));
    spec_default(&r, ONION_READY_BYTES, 0, 2, g_chunk, ONION_READY_BYTES);
    ONION_CHECK("slice_count disagreeing with chunk size is MALFORMED",
        fetch_one_slice_refused(&r, ONION_READY_BYTES,
            FILE_MARKET_DELIVERY_MALFORMED, &out));
    spec_default(&r, ONION_READY_BYTES, 0, 1, g_chunk, ONION_READY_BYTES);
    r.chunk_size = 0;
    ONION_CHECK("zero chunk size is MALFORMED",
        fetch_one_slice_refused(&r, ONION_READY_BYTES,
            FILE_MARKET_DELIVERY_MALFORMED, &out));
    spec_default(&r, ONION_READY_BYTES, 0, 1, g_chunk, ONION_READY_BYTES);
    r.chunk_size = FILE_MARKET_CHUNK_SIZE + 1;
    ONION_CHECK("chunk size above the protocol maximum is MALFORMED",
        fetch_one_slice_refused(&r, ONION_READY_BYTES,
            FILE_MARKET_DELIVERY_MALFORMED, &out));
    spec_default(&r, ONION_TWO_SLICE_BYTES, 0, 2, g_chunk, 10);
    ONION_CHECK("short first slice of a two-slice chunk is MALFORMED",
        fetch_one_slice_refused(&r, 10, FILE_MARKET_DELIVERY_MALFORMED,
                                &out));
    return failures;
}

static int onion_run_fetch_header_checks(void)
{
    int failures = 0;
    struct reply_spec r;
    struct file_market_delivery_chunk out;
    spec_default(&r, ONION_READY_BYTES, 0, 1, g_chunk, ONION_READY_BYTES);
    script_reset();
    script_arm(0, &r, g_chunk, ONION_READY_BYTES);
    g_script.body_len[0] = 10;
    enum file_market_delivery_status status = fetch_good(INT64_MAX, &out);
    ONION_CHECK("reply shorter than the header is PAYMENT_UNKNOWN",
        status == FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN &&
        chunk_is_empty(&out));
    script_reset();
    script_arm(0, &r, g_chunk, ONION_READY_BYTES);
    g_script.body[0][0] ^= 1;
    status = fetch_good(INT64_MAX, &out);
    ONION_CHECK("reply with bad magic is PAYMENT_UNKNOWN",
        status == FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN);
    spec_default(&r, ONION_READY_BYTES, 0, 1, g_chunk, ONION_READY_BYTES);
    r.version = 2;
    ONION_CHECK("reply with an unknown version is PAYMENT_UNKNOWN",
        fetch_one_slice_refused(&r, ONION_READY_BYTES,
            FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN, &out));
    spec_default(&r, ONION_READY_BYTES, 0, 1, g_chunk, ONION_READY_BYTES);
    r.status = (uint16_t)(FILE_MARKET_DELIVERY_RESOURCE_LIMIT + 1);
    ONION_CHECK("reply status past the enum is PAYMENT_UNKNOWN",
        fetch_one_slice_refused(&r, ONION_READY_BYTES,
            FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN, &out));
    spec_default(&r, ONION_READY_BYTES, 0, 1, g_chunk, ONION_READY_BYTES);
    r.offer_id[0] ^= 1;
    ONION_CHECK("reply for another offer is PAYMENT_UNKNOWN",
        fetch_one_slice_refused(&r, ONION_READY_BYTES,
            FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN, &out));
    spec_default(&r, ONION_READY_BYTES, 0, 1, g_chunk, ONION_READY_BYTES);
    r.chunk_index = ONION_FETCH_CHUNK + 1;
    ONION_CHECK("reply for another chunk index is PAYMENT_UNKNOWN",
        fetch_one_slice_refused(&r, ONION_READY_BYTES,
            FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN, &out));
    return failures;
}

static int onion_run_fetch_transport_checks(void)
{
    int failures = 0;
    struct reply_spec r;
    struct file_market_delivery_chunk out;
    enum file_market_delivery_status status;
    script_reset();
    status = fetch_good(INT64_MAX, &out);
    ONION_CHECK("failed GET with no reply is PAYMENT_UNKNOWN",
        status == FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN &&
        g_script.calls == 1 && g_script.timeouts[0] == 60 &&
        chunk_is_empty(&out));
    spec_default(&r, ONION_READY_BYTES, 0, 1, g_chunk, ONION_READY_BYTES);
    r.status = (uint16_t)FILE_MARKET_DELIVERY_PAYMENT_PENDING;
    script_reset();
    script_arm(0, &r, NULL, 0);
    status = fetch_good(INT64_MAX, &out);
    ONION_CHECK("non-READY header status is returned as the fetch status",
        status == FILE_MARKET_DELIVERY_PAYMENT_PENDING &&
        g_script.calls == 1 && chunk_is_empty(&out));
    return failures;
}

static int onion_run_fetch_stream_checks(void)
{
    int failures = 0;
    struct reply_spec r0;
    struct reply_spec r1;
    struct file_market_delivery_chunk out;
    enum file_market_delivery_status status;
    spec_default(&r0, ONION_TWO_SLICE_BYTES, 0, 2, g_chunk,
                 FILE_MARKET_ONION_SLICE_BYTES);
    spec_default(&r1, ONION_TWO_SLICE_BYTES, 1, 2,
                 g_chunk + FILE_MARKET_ONION_SLICE_BYTES, 1);
    r1.chunk_sha3[0] ^= 1;
    script_reset();
    script_arm(0, &r0, g_chunk, FILE_MARKET_ONION_SLICE_BYTES);
    script_arm(1, &r1, g_chunk + FILE_MARKET_ONION_SLICE_BYTES, 1);
    status = fetch_good(INT64_MAX, &out);
    ONION_CHECK("second slice naming another chunk digest is MALFORMED",
        status == FILE_MARKET_DELIVERY_MALFORMED && g_script.calls == 2 &&
        chunk_is_empty(&out));

    spec_default(&r1, ONION_TWO_SLICE_BYTES, 1, 2,
                 g_chunk + FILE_MARKET_ONION_SLICE_BYTES, 1);
    script_reset();
    script_arm(0, &r0, g_chunk, FILE_MARKET_ONION_SLICE_BYTES);
    status = fetch_good(INT64_MAX, &out);
    ONION_CHECK("second slice GET failing is PAYMENT_UNKNOWN after two GETs",
        status == FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN &&
        g_script.calls == 2 && chunk_is_empty(&out));
    return failures;
}

static int onion_run_fetch_checks(void)
{
    int failures = 0;
    failures += onion_run_fetch_guard_checks();
    failures += onion_run_fetch_argument_checks();
    failures += onion_run_fetch_clock_checks();
    failures += onion_run_fetch_ready_checks();
    failures += onion_run_fetch_shape_checks();
    failures += onion_run_fetch_header_checks();
    failures += onion_run_fetch_transport_checks();
    failures += onion_run_fetch_stream_checks();
    return failures;
}

int test_file_market_delivery_onion(void)
{
    int failures = 0;
    if (!onion_fixture_init()) {
        printf("file_market_delivery_onion: fixture init... FAIL\n");
        return 1;
    }
    file_market_delivery_reset_handlers();
    failures += onion_run_method_checks();
    failures += onion_run_path_checks();
    failures += onion_run_ready_checks_all();
    failures += onion_run_fetch_checks();
    file_market_delivery_reset_handlers();
    printf("\n%d file_market_delivery_onion test(s) failed\n", failures);
    return failures;
}
