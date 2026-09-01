/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "rpc/legacy_header_client.h"

#include "core/serialize.h"
#include "encoding/utilstrencodings.h"
#include "primitives/block.h"
#include "rpc/legacy_rpc_client.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LHC_MAX_HEADER_BYTES (BLOCK_HEADER_SIZE + MAX_SOLUTION_SIZE + 8)

static void lhc_build_rpc_body_int(char *body, size_t body_sz,
                                   const char *method, int64_t param)
{
    snprintf(body, body_sz,
        "{\"jsonrpc\":\"1.0\",\"id\":\"zcl-hp\","
        "\"method\":\"%s\",\"params\":[%lld]}",
        method, (long long)param);
}

static void lhc_build_getblockheader_body(char *body, size_t body_sz,
                                          const char *hash_hex)
{
    snprintf(body, body_sz,
        "{\"jsonrpc\":\"1.0\",\"id\":\"zcl-hp\","
        "\"method\":\"getblockheader\",\"params\":[\"%s\",false]}",
        hash_hex);
}

static void lhc_build_getblockcount_body(char *body, size_t body_sz)
{
    snprintf(body, body_sz,
        "{\"jsonrpc\":\"1.0\",\"id\":\"zcl-hp\","
        "\"method\":\"getblockcount\",\"params\":[]}");
}

static bool lhc_deserialize_header_hex(const char *hex,
                                       struct block_header *out_hdr,
                                       const char *err_prefix,
                                       char *err, size_t err_sz)
{
    size_t hex_len = hex ? strlen(hex) : 0;
    if (hex_len < 280 || (hex_len % 2) != 0) {
        snprintf(err, err_sz, "%sbad hex length %zu",
                 err_prefix ? err_prefix : "", hex_len);
        return false;
    }

    unsigned char *bytes = zcl_malloc(hex_len / 2, "lhc_hdr_bytes");
    if (!bytes) {
        snprintf(err, err_sz, "%soom decode",
                 err_prefix ? err_prefix : "");
        return false;
    }
    size_t nbytes = ParseHex(hex, bytes, hex_len / 2);
    if (nbytes < BLOCK_HEADER_SIZE) {
        free(bytes);
        snprintf(err, err_sz, "%sshort decoded len %zu",
                 err_prefix ? err_prefix : "", nbytes);
        return false;
    }

    struct byte_stream s;
    stream_init_from_data(&s, bytes, nbytes);
    block_header_init(out_hdr);
    bool deser_ok = block_header_deserialize(out_hdr, &s);
    stream_free(&s);
    free(bytes);
    if (!deser_ok) {
        snprintf(err, err_sz, "%sdeserialize failed",
                 err_prefix ? err_prefix : "");
        return false;
    }
    return true;
}

bool legacy_header_rpc_fetch_remote_tip(const char *host, int port,
                                        const char *user, const char *pass,
                                        int *out_height,
                                        char *err, size_t err_sz)
{
    if (!out_height) {
        snprintf(err, err_sz, "bad height output pointer");
        return false;
    }

    char body[128];
    char *resp = NULL;
    lhc_build_getblockcount_body(body, sizeof(body));
    if (!legacy_rpc_call(host, port, user, pass, body, &resp,
                         err, err_sz)) {
        return false;
    }

    int64_t h = 0;
    bool parsed = legacy_rpc_parse_result_int(resp, &h, err, err_sz);
    free(resp);
    if (!parsed || h < 0 || h > 0x7fffffff)
        return false;
    *out_height = (int)h;
    return true;
}

bool legacy_header_rpc_fetch_one(const char *host, int port,
                                 const char *user, const char *pass,
                                 int height,
                                 struct block_header *out_hdr,
                                 char *err, size_t err_sz)
{
    if (!out_hdr || height < 0) {
        snprintf(err, err_sz, "bad header fetch args");
        return false;
    }

    char body[256];
    char *resp = NULL;
    lhc_build_rpc_body_int(body, sizeof(body), "getblockhash", height);
    if (!legacy_rpc_call(host, port, user, pass, body, &resp,
                         err, err_sz)) {
        return false;
    }

    char hash_hex[80] = {0};
    bool ok = legacy_rpc_parse_result_string(resp, hash_hex,
                                             sizeof(hash_hex),
                                             err, err_sz);
    free(resp);
    if (!ok)
        return false;
    if (strlen(hash_hex) != 64) {
        snprintf(err, err_sz, "hash not 64 hex chars");
        return false;
    }

    resp = NULL;
    lhc_build_getblockheader_body(body, sizeof(body), hash_hex);
    if (!legacy_rpc_call(host, port, user, pass, body, &resp,
                         err, err_sz)) {
        return false;
    }

    size_t hex_cap = LHC_MAX_HEADER_BYTES * 2 + 16;
    char *hex = zcl_malloc(hex_cap, "lhc_hdr_hex");
    if (!hex) {
        free(resp);
        snprintf(err, err_sz, "oom hex");
        return false;
    }
    ok = legacy_rpc_parse_result_string(resp, hex, hex_cap, err, err_sz);
    free(resp);
    if (ok)
        ok = lhc_deserialize_header_hex(hex, out_hdr, "", err, err_sz);
    free(hex);
    return ok;
}

bool legacy_header_rpc_fetch_batch(const char *host, int port,
                                   const char *user, const char *pass,
                                   int from_h, int n,
                                   struct block_header *out,
                                   int *out_count,
                                   char *err, size_t err_sz)
{
    if (out_count) *out_count = 0;
    if (!out || !out_count || from_h < 0 ||
        n <= 0 || n > LEGACY_HEADER_RPC_BATCH_MAX) {
        snprintf(err, err_sz, "bad batch args");
        return false;
    }

    size_t body1_cap = (size_t)n * 96 + 16;
    char *body1 = zcl_malloc(body1_cap, "lhc_batch_body1");
    if (!body1) {
        snprintf(err, err_sz, "oom body1");
        return false;
    }
    size_t off = 0;
    body1[off++] = '[';
    for (int i = 0; i < n; i++) {
        int w = snprintf(body1 + off, body1_cap - off,
            "%s{\"jsonrpc\":\"1.0\",\"id\":%d,\"method\":\"getblockhash\","
            "\"params\":[%d]}",
            i ? "," : "", i, from_h + i);
        if (w < 0 || (size_t)w >= body1_cap - off) {
            free(body1);
            snprintf(err, err_sz, "body1 overflow at i=%d", i);
            return false;
        }
        off += (size_t)w;
    }
    if (off + 2 >= body1_cap) {
        free(body1);
        snprintf(err, err_sz, "body1 trailer overflow");
        return false;
    }
    body1[off++] = ']';
    body1[off] = '\0';

    char *resp1 = NULL;
    if (!legacy_rpc_call(host, port, user, pass, body1, &resp1,
                         err, err_sz)) {
        free(body1);
        return false;
    }
    free(body1);

    enum { LHC_HASH_SLOT = 80 };
    char *hashes = zcl_calloc((size_t)n, LHC_HASH_SLOT, "lhc_batch_hashes");
    if (!hashes) {
        free(resp1);
        snprintf(err, err_sz, "oom hashes");
        return false;
    }
    bool ok = legacy_rpc_parse_result_string_array(resp1, n, hashes,
                                                   LHC_HASH_SLOT,
                                                   err, err_sz);
    free(resp1);
    if (!ok) {
        free(hashes);
        return false;
    }
    for (int i = 0; i < n; i++) {
        const char *h_str = hashes + (size_t)i * LHC_HASH_SLOT;
        if (strlen(h_str) != 64) {
            snprintf(err, err_sz,
                     "hash[%d] not 64 hex chars (got %zu)",
                     i, strlen(h_str));
            free(hashes);
            return false;
        }
    }

    size_t body2_cap = (size_t)n * 200 + 16;
    char *body2 = zcl_malloc(body2_cap, "lhc_batch_body2");
    if (!body2) {
        free(hashes);
        snprintf(err, err_sz, "oom body2");
        return false;
    }
    off = 0;
    body2[off++] = '[';
    for (int i = 0; i < n; i++) {
        const char *h_str = hashes + (size_t)i * LHC_HASH_SLOT;
        int w = snprintf(body2 + off, body2_cap - off,
            "%s{\"jsonrpc\":\"1.0\",\"id\":%d,"
            "\"method\":\"getblockheader\","
            "\"params\":[\"%s\",false]}",
            i ? "," : "", i, h_str);
        if (w < 0 || (size_t)w >= body2_cap - off) {
            free(hashes);
            free(body2);
            snprintf(err, err_sz, "body2 overflow at i=%d", i);
            return false;
        }
        off += (size_t)w;
    }
    free(hashes);
    if (off + 2 >= body2_cap) {
        free(body2);
        snprintf(err, err_sz, "body2 trailer overflow");
        return false;
    }
    body2[off++] = ']';
    body2[off] = '\0';

    char *resp2 = NULL;
    if (!legacy_rpc_call(host, port, user, pass, body2, &resp2,
                         err, err_sz)) {
        free(body2);
        return false;
    }
    free(body2);

    const size_t hex_slot = (size_t)LHC_MAX_HEADER_BYTES * 2 + 16;
    char *hexes = zcl_calloc((size_t)n, hex_slot, "lhc_batch_hexes");
    if (!hexes) {
        free(resp2);
        snprintf(err, err_sz, "oom hexes");
        return false;
    }
    ok = legacy_rpc_parse_result_string_array(resp2, n, hexes, hex_slot,
                                              err, err_sz);
    free(resp2);
    if (!ok) {
        free(hexes);
        return false;
    }

    int parsed = 0;
    for (int i = 0; i < n; i++) {
        const char *hex = hexes + (size_t)i * hex_slot;
        char prefix[32];
        snprintf(prefix, sizeof(prefix), "header[%d]: ", i);
        if (!lhc_deserialize_header_hex(hex, &out[i], prefix,
                                        err, err_sz)) {
            break;
        }
        parsed++;
    }
    free(hexes);
    *out_count = parsed;
    return true;
}
