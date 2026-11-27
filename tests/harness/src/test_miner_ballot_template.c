/* purpose: Test ballot template ownership and exact reserved serialization. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/miner_ballot_template.h"
#include "services/miner_signal_round.h"
#include "base/safe_alloc.h"
#include "chain/chainparams.h"
#include "core/serialize.h"
#include "crypto/equihash.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "validation/main_constants.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BT_CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "miner_ballot_template line %d: %s\n", __LINE__, #x); \
    failures++; goto done; } } while (0)

static bool bt_make(struct block *block, size_t outputs)
{
    block_init(block);
    block->vtx = calloc(1, sizeof(*block->vtx));
    if (!block->vtx) return false;
    block->num_vtx = 1;
    transaction_init(&block->vtx[0]);
    if (!transaction_alloc(&block->vtx[0], 1, outputs)) return false;
    struct transaction *cb = &block->vtx[0];
    outpoint_set_null(&cb->vin[0].prevout);
    cb->vin[0].script_sig.size = 2;
    cb->vin[0].script_sig.data[0] = 1;
    cb->vin[0].script_sig.data[1] = 1;
    for (size_t i = 0; i < outputs; ++i) {
        cb->vout[i].value = (int64_t)i + 42;
        cb->vout[i].script_pub_key.size = 1;
        cb->vout[i].script_pub_key.data[0] = 0x51;
    }
    return true;
}

static size_t bt_serialized_block_bound(struct block *block, size_t width)
{
    struct byte_stream s;
    stream_init(&s, 0);
    size_t old_script = block->vtx[0].vin[0].script_sig.size;
    block->vtx[0].vin[0].script_sig.size = 100;
    memset(block->vtx[0].vin[0].script_sig.data + old_script, 0, 100 - old_script);
    block->header.nSolutionSize = width;
    memset(block->header.nSolution, 0, width);
    bool ok = block_serialize(block, &s) && !s.error;
    size_t result = ok ? s.size : 0;
    block->vtx[0].vin[0].script_sig.size = (uint16_t)old_script;
    block->header.nSolutionSize = 0;
    stream_free(&s);
    return result;
}

int test_miner_ballot_template(void)
{
    int failures = 0;
    struct block block = {0};
    uint8_t catalog[32] = {3}, bitmap[32] = {1}, expected[MINER_SIGNAL_SCRIPT_BYTES];
    const struct chain_params *params;
    size_t reserved = 0, before;
    struct uint256 hash;
    chain_params_select(CHAIN_REGTEST);
    params = chain_params_get();
    miner_signal_ballot_script(catalog, bitmap, expected);
    BT_CHECK(bt_make(&block, 1));
    before = transaction_serialize_size(&block.vtx[0]);
    BT_CHECK(miner_ballot_template_apply(&block, catalog, bitmap, params, 1,
                                         DEFAULT_BLOCK_MAX_SIZE, &reserved).ok);
    BT_CHECK(block.num_vtx == 1 && block.vtx[0].num_vout == 2);
    BT_CHECK(block.vtx[0].vout[0].value == 42 && block.vtx[0].vout[1].value == 0);
    BT_CHECK(block.vtx[0].vout[1].script_pub_key.size == MINER_SIGNAL_SCRIPT_BYTES &&
             memcmp(block.vtx[0].vout[1].script_pub_key.data, expected, sizeof(expected)) == 0);
    BT_CHECK(transaction_serialize_size(&block.vtx[0]) == before + 80);
    BT_CHECK(block.header.nSolutionSize == 0 && block.vtx[0].vin[0].script_sig.size == 2);
    BT_CHECK(transaction_hash_serialized(&block.vtx[0], &hash) &&
             uint256_eq(&hash, &block.vtx[0].hash) && uint256_eq(&hash, &block.header.hashMerkleRoot));
    struct equihash_params ep;
    equihash_params_init(&ep, chain_params_equihash_n(params, 1), chain_params_equihash_k(params, 1));
    BT_CHECK(reserved == bt_serialized_block_bound(&block, ep.solution_width));
    block_free(&block);
    BT_CHECK(bt_make(&block, 1));
    BT_CHECK(miner_ballot_template_apply(&block, catalog, bitmap, params, 1, reserved, &before).ok);
    BT_CHECK(before == reserved);
    block_free(&block);
    BT_CHECK(bt_make(&block, 1));
    before = 999;
    BT_CHECK(!miner_ballot_template_apply(&block, catalog, bitmap, params, 1, reserved - 1, &before).ok);
    BT_CHECK(before == 999);
    block_free(&block);
    BT_CHECK(bt_make(&block, 252));
    before = transaction_serialize_size(&block.vtx[0]);
    BT_CHECK(miner_ballot_template_apply(&block, catalog, bitmap, params, 1,
                                         DEFAULT_BLOCK_MAX_SIZE, &reserved).ok);
    BT_CHECK(block.vtx[0].num_vout == 253 && transaction_serialize_size(&block.vtx[0]) == before + 82);
    for (size_t i = 0; i < 252; ++i) {
        const struct tx_out *payout = &block.vtx[0].vout[i];
        BT_CHECK(payout->value == (int64_t)i + 42);
        BT_CHECK(payout->script_pub_key.size == 1 && payout->script_pub_key.data[0] == 0x51);
    }
    block_free(&block);
    BT_CHECK(bt_make(&block, 1));
    struct tx_out *original_outputs = block.vtx[0].vout;
    zcl_alloc_fault_fail_next("miner ballot outputs");
    struct zcl_result failed = miner_ballot_template_apply(&block, catalog, bitmap, params, 1,
                                                           DEFAULT_BLOCK_MAX_SIZE, &reserved);
    zcl_alloc_fault_clear();
    BT_CHECK(!failed.ok && block.vtx[0].num_vout == 1);
    BT_CHECK(block.vtx[0].vout == original_outputs && original_outputs[0].value == 42);
    block.header.nSolutionSize = 1;
    BT_CHECK(!miner_ballot_template_apply(&block, catalog, bitmap, params, 1,
                                          DEFAULT_BLOCK_MAX_SIZE, &reserved).ok);
    block.header.nSolutionSize = 0;
    block.vtx[0].vin[0].script_sig.size = 101;
    BT_CHECK(!miner_ballot_template_apply(&block, catalog, bitmap, params, 1,
                                          DEFAULT_BLOCK_MAX_SIZE, &reserved).ok);
    puts("miner_ballot_template: size, ownership and boundaries passed");
done:
    block_free(&block);
    chain_params_select(CHAIN_MAIN);
    return failures;
}
