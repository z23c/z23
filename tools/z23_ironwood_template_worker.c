/* purpose: Solve an unchanged, coinbase-only private Ironwood template. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "chain/chainparams.h"
#include "core/serialize.h"
#include "json/json.h"
#include "mining/miner.h"
#include "primitives/block.h"
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { TEMPLATE_LIMIT = 4000000, TX_HEX_LIMIT = 400000 };
volatile sig_atomic_t g_shutdown_requested = 0;

static bool read_template(const char *path, struct json_value *json)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    char *buf = zcl_malloc(TEMPLATE_LIMIT + 1, "template JSON");
    if (!buf) { fclose(f); return false; }
    size_t n = fread(buf, 1, TEMPLATE_LIMIT + 1, f);
    bool ok = n <= TEMPLATE_LIMIT && !ferror(f) && feof(f);
    if (fclose(f)) ok = false;
    if (ok) ok = json_read(json, buf, n);
    free(buf);
    return ok;
}

static bool decode_coinbase(const char *hex, struct transaction *tx)
{
    if (!hex) return false;
    size_t n = strlen(hex);
    if (!n || n % 2 || n > TX_HEX_LIMIT) return false;
    uint8_t *raw = zcl_malloc(n / 2, "template coinbase");
    if (!raw) return false;
    bool ok = zcl_hex_decode(hex, raw, n / 2);
    struct byte_stream in, out;
    stream_init_from_data(&in, raw, n / 2);
    stream_init(&out, 256);
    if (ok) ok = transaction_deserialize(tx, &in) && !in.error && !stream_remaining(&in);
    if (ok) ok = transaction_serialize(tx, &out) && !out.error && out.size == n / 2 &&
        !memcmp(out.data, raw, out.size) && transaction_is_coinbase(tx) && tx->num_vout > 0;
    stream_free(&out);
    free(raw);
    return ok;
}

static bool hex_hash(const char *s, struct uint256 *out)
{
    uint8_t check[32];
    if (!s || strlen(s) != 64 || !zcl_hex_decode(s, check, sizeof check)) return false;
    uint256_set_hex(out, s);
    return true;
}

static bool integer(const struct json_value *obj, const char *key, int64_t min,
                    int64_t max, int64_t *out)
{
    const struct json_value *v = json_get(obj, key);
    if (!v || v->type != JSON_INT || v->val.i < min || v->val.i > max) return false;
    *out = v->val.i;
    return true;
}

static bool template_header(const struct json_value *obj, struct block *block, int *height)
{
    int64_t h, version, time;
    const char *bits = json_get_str(json_get(obj, "bits"));
    if (!integer(obj, "height", 1, INT_MAX, &h) ||
        !integer(obj, "version", 4, 4, &version) ||
        !integer(obj, "curtime", 0, UINT32_MAX, &time) || !bits || strlen(bits) != 8 ||
        !hex_hash(json_get_str(json_get(obj, "previousblockhash")), &block->header.hashPrevBlock) ||
        !hex_hash(json_get_str(json_get(obj, "finalsaplingroothash")), &block->header.hashFinalSaplingRoot)) return false;
    uint8_t check[4];
    if (!zcl_hex_decode(bits, check, sizeof check)) return false;
    errno = 0;
    char *end = NULL;
    unsigned long nbits = strtoul(bits, &end, 16);
    if (errno || !end || *end || nbits > UINT32_MAX) return false;
    block->header.nVersion = (int32_t)version;
    block->header.nTime = (uint32_t)time;
    block->header.nBits = (uint32_t)nbits;
    *height = (int)h;
    return true;
}

static bool template_block(const struct json_value *json, struct block *block, int *height)
{
    const struct json_value *obj = json_get(json, "result");
    const struct json_value *txs = json_get(obj, "transactions");
    const struct json_value *cb = json_get(obj, "coinbasetxn");
    if (!obj || obj->type != JSON_OBJ || !txs || txs->type != JSON_ARR || json_size(txs) != 0 ||
        !cb || cb->type != JSON_OBJ || !template_header(obj, block, height)) return false;
    block->vtx = zcl_calloc(1, sizeof *block->vtx, "template transaction");
    if (!block->vtx) return false;
    block->num_vtx = 1;
    transaction_init(&block->vtx[0]);
    if (!decode_coinbase(json_get_str(json_get(cb, "data")), &block->vtx[0])) return false;
    return transaction_hash_serialized(&block->vtx[0], &block->header.hashMerkleRoot);
}

static bool write_block(const struct block *block, int height)
{
    struct byte_stream out;
    stream_init(&out, 1024);
    bool ok = block_serialize(block, &out) && !out.error;
    if (ok) {
        for (size_t i = 0; i < out.size; ++i) if (printf("%02x", out.data[i]) < 0) { ok = false; break; }
        if (putchar('\n') == EOF || fflush(stdout)) ok = false;
    }
    if (ok) {
        struct uint256 hash;
        char hex[65];
        block_header_get_hash(&block->header, &hash);
        uint256_get_hex(&hash, hex);
        fprintf(stderr, "height=%d hash=%s bytes=%zu\n", height, hex, out.size);
    }
    stream_free(&out);
    return ok;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: z23_ironwood_template_worker TEMPLATE.json\n"); return 2; }
    struct json_value json = {0};
    struct block block;
    block_init(&block);
    int height = 0;
    bool ok = read_template(argv[1], &json) && template_block(&json, &block, &height) &&
        chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD) &&
        mine_block_pow(&block, height, chain_params_get(), 0) && write_block(&block, height);
    if (!ok) fprintf(stderr, "Ironwood template worker: invalid template or solve failed\n");
    block_free(&block);
    json_free(&json);
    return ok ? 0 : 1;
}
