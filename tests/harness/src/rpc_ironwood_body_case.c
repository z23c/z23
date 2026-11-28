/* purpose: Check both getblock renderings against the solved H145 reward fixture. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef _WIN32
#include "base/hex.h"
#include "base/serialize_le.h"
#include "chain/chainparams.h"
#include "controllers/blockchain_controller.h"
#include "jobs/reducer_frontier.h"
#include "validation/main_state.h"
#include <stdio.h>
#include <string.h>

/* Exact H145 Equihash header, transaction count and v4 coinbase. */
static const char prefix[] =
    "04000000a61ade91f7ff656f25eb7e216fb4673987904636cfd11d864f4ff2d0d29b7a0e7082924b"
    "e7976767ae7d2a0c396ea54bb31c56ac6cd91e79e8a654fb4ed00ce2fbc2f4300c01f0b7820d00e3"
    "347c8da4ee614674376cbc45359daa54f9b5493ed7920a6b070f0f20270000000000000000000000"
    "00000000000000000000000000000000000000002403fa4e78764fce53aa147e1dfb9215cca29026"
    "bb1b8f0585ed63743da7567324732e8556020400008085202f890100000000000000000000000000"
    "00000000000000000000000000000000000000ffffffff0402910000ffffffff01807c814a000000"
    "000000000000000000000000000000000000000000";
enum { PREFIX_SIZE = (sizeof(prefix) - 1) / 2, WIRE_SIZE = PREFIX_SIZE + 9313 };
static bool load_body(uint8_t wire[WIRE_SIZE], const char *path, size_t len)
{
    if (len > WIRE_SIZE - PREFIX_SIZE || !zcl_hex_decode(prefix, wire, PREFIX_SIZE)) return false;
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    bool ok = fread(wire + PREFIX_SIZE, 1, len, f) == len && fgetc(f) == EOF && !ferror(f);
    return fclose(f) == 0 && ok;
}
static bool write_frame(const char *path, const uint8_t *wire, uint32_t len)
{
    uint8_t frame[8];
    memcpy(frame, chain_params_get()->pchMessageStart, 4);
    zcl_write_u32_le(frame + 4, len);
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fwrite(frame, 1, sizeof(frame), f) == sizeof(frame) &&
        fwrite(wire, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}
static bool body_reply(struct rpc_table *table, bool expect_body, bool verbose, const char *raw)
{
    static const char hash[] = "09cd934128729844050259a9ecd8561a15e788dc109437e9c84996d8ea870a80";
    static const char txid[] = "9b9eac775e6a0f7b5eef6d946dbb1ca9dcc338124b507c9ef53729b6ab41545a";
    struct json_value params = {0}, key = {0}, mode = {0}, result = {0};
    json_set_array(&params); json_set_str(&key, hash); json_set_bool(&mode, verbose);
    bool ok = json_push_back(&params, &key) && json_push_back(&params, &mode);
    if (ok) {
        bool called = rpc_table_execute(table, "getblock", &params, &result);
        const char *s = json_get_str(&result);
        if (!expect_body) ok = !called && s && !strcmp(s, "Block serialization failed");
        else if (!verbose) ok = called && s && !strcmp(s, raw);
        else {
            const char *id = json_get_str(json_at(json_get(&result, "tx"), 1));
            const char *root = json_get_str(json_get(&result, "computed_auth_data_root_raw"));
            ok = called && id && !strcmp(id, txid) && root &&
                !strcmp(root, "50b38ce9188fc866a5ef69d82b094596bf4f08ba333f03aadff692d13f6ae401") &&
                json_get_int(json_get(&result, "size")) == WIRE_SIZE;
        }
    }
    json_free(&params); json_free(&key); json_free(&mode); json_free(&result);
    return ok;
}
bool rpc_ironwood_body_case(struct main_state *ms, struct rpc_table *table,
                            struct block_index *index, const char *blocks, bool research)
{
    char path[640], raw[2 * WIRE_SIZE + 1];
    uint8_t wire[WIRE_SIZE];
    snprintf(path, sizeof(path), "%s/blk00009.dat", blocks);
    if (!load_body(wire, "tests/fixtures/ironwood/postnu63-h1-reward-spend.v6", 9313) ||
        !write_frame(path, wire, WIRE_SIZE)) return false;
    zcl_hex_encode(wire, WIRE_SIZE, raw);
    block_index_init(index);
    uint256_set_hex(&index->hashBlock, "09cd934128729844050259a9ecd8561a15e788dc109437e9c84996d8ea870a80");
    index->phashBlock = &index->hashBlock;
    index->nHeight = 145;
    block_index_disk_pos_store(index, 9, 8);
    block_index_status_fetch_or(index, BLOCK_HAVE_DATA);
    reducer_frontier_provable_tip_set(145);
    bool ok = block_map_insert(&ms->map_block_index, index->phashBlock, index) &&
        body_reply(table, research, false, raw) && body_reply(table, research, true, raw);
    if (ok && research) {
        ok = load_body(wire, "tests/fixtures/ironwood/postnu63-h1-reward-withdrawal.v6", 9200) &&
            write_frame(path, wire, PREFIX_SIZE + 9200) &&
            body_reply(table, false, false, NULL) && body_reply(table, false, true, NULL);
    }
    reducer_frontier_provable_tip_reset();
    return remove(path) == 0 && ok;
}
#endif
