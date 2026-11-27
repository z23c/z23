/* purpose: Test ballot template ownership and exact reserved serialization. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/miner_ballot_template.h"
#include "mining/miner.h"
#include "services/miner_signal_round.h"
#include "base/safe_alloc.h"
#include "bloom/merkle.h"
#include "controllers/mining_controller.h"
#include "consensus/upgrades.h"
#include "sapling/incremental_merkle_tree.h"
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

static bool bt_alias_inputs(struct block *block, const struct chain_params *params)
{
    struct script *payout = &block->vtx[0].vout[0].script_pub_key;
    uint8_t expected[MINER_SIGNAL_SCRIPT_BYTES];
    payout->size = 64;
    memset(payout->data, 0x42, 32);
    memset(payout->data + 32, 0, 32);
    payout->data[32] = 1;
    miner_signal_ballot_script(payout->data, payout->data + 32, expected);
    size_t reserved;
    if (!miner_ballot_template_apply(block, payout->data, payout->data + 32, params, 1,
                                     DEFAULT_BLOCK_MAX_SIZE, &reserved).ok) return false;
    return memcmp(block->vtx[0].vout[1].script_pub_key.data, expected, sizeof(expected)) == 0;
}

static bool bt_merkle_matches(const struct block *block)
{
    struct uint256 *hashes = calloc(block->num_vtx, sizeof(*hashes));
    if (!hashes) return false;
    for (size_t i = 0; i < block->num_vtx; i++) {
        if (!transaction_hash_serialized(&block->vtx[i], &hashes[i])) {
            free(hashes);
            return false;
        }
    }
    bool mutated = false;
    struct uint256 root = merkle_root_mutated_in_place(hashes, block->num_vtx, &mutated);
    free(hashes);
    return !mutated && uint256_eq(&root, &block->header.hashMerkleRoot);
}

static bool bt_attach_sapling(struct transaction *tx, unsigned char marker)
{
    tx->v_shielded_output = calloc(1, sizeof(*tx->v_shielded_output));
    if (!tx->v_shielded_output) return false;
    tx->num_shielded_output = 1;
    tx->overwintered = true;
    tx->version = SAPLING_TX_VERSION;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    memset(tx->v_shielded_output[0].cm.data, marker, 32);
    return true;
}

static bool bt_retained_sapling_root(struct block *block, const struct chain_params *params)
{
    struct chain_params active = *params;
    active.consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight = 0;
    struct incremental_merkle_tree expected_tree;
    sapling_tree_init(&expected_tree);
    incremental_tree_append(&expected_tree, &block->vtx[1].v_shielded_output[0].cm);
    struct uint256 expected, zero;
    incremental_tree_root(&expected_tree, &expected);
    uint256_set_null(&zero);
    return mining_stamp_sapling_final_root(block, 1, &active, &zero, true) &&
        uint256_eq(&block->header.hashFinalSaplingRoot, &expected);
}

static int bt_research_fit_case(size_t count, size_t script_size, bool ballot, bool zero_fee, bool sapling)
{
    int failures = 0;
    struct block_template bt = {0};
    const struct chain_research_descriptor *d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    BT_CHECK(d && bt_make(&bt.block, 1));
    struct transaction cb = bt.block.vtx[0];
    free(bt.block.vtx);
    bt.block.vtx = calloc(count, sizeof(*bt.block.vtx));
    BT_CHECK(bt.block.vtx);
    bt.block.vtx[0] = cb;
    bt.block.num_vtx = 1;
    bt.tx_fees = calloc(count, sizeof(*bt.tx_fees));
    bt.tx_sig_ops = calloc(count, sizeof(*bt.tx_sig_ops));
    BT_CHECK(bt.tx_fees && bt.tx_sig_ops);
    for (size_t i = 1; i < count; i++) {
        struct transaction *tx = &bt.block.vtx[i];
        transaction_init(tx);
        BT_CHECK(transaction_alloc(tx, 1, 1));
        bt.block.num_vtx++;
        tx->lock_time = (uint32_t)i;
        tx->vout[0].value = (int64_t)i;
        tx->vout[0].script_pub_key.size = script_size;
        memset(tx->vout[0].script_pub_key.data, 0x51, script_size);
        bt.tx_fees[i] = zero_fee ? 0 : 1;
    }
    if (sapling) {
        BT_CHECK(bt_attach_sapling(&bt.block.vtx[1], 0x11));
        BT_CHECK(bt_attach_sapling(&bt.block.vtx[count - 1], 0x22));
    }
    bt.num_entries = count;
    bt.tx_fees[0] = zero_fee ? 0 : -(int64_t)(count - 1);
    if (!zero_fee) bt.block.vtx[0].vout[0].value += (int64_t)(count - 1);
    BT_CHECK(miner_research_template_fit(&bt, d->chain, 1, ballot).ok);
    BT_CHECK(bt.block.num_vtx < count && bt.num_entries == bt.block.num_vtx);
    BT_CHECK(bt.block.vtx[0].vout[0].value == 42 + (zero_fee ? 0 : (int64_t)bt.num_entries - 1));
    BT_CHECK(bt.tx_fees[0] == (zero_fee ? 0 : -(int64_t)(bt.num_entries - 1)));
    BT_CHECK(bt_merkle_matches(&bt.block));
    if (sapling) BT_CHECK(bt_retained_sapling_root(&bt.block, d->chain));
    for (size_t i = 1; i < bt.num_entries; i++) BT_CHECK(bt.block.vtx[i].lock_time == i);
    struct equihash_params ep;
    equihash_params_init(&ep, chain_params_equihash_n(d->chain, 1), chain_params_equihash_k(d->chain, 1));
    size_t bound = bt_serialized_block_bound(&bt.block, ep.solution_width);
    BT_CHECK(bound <= 200000);
    if (ballot) {
        uint8_t catalog[32] = {3}, bitmap[32] = {1};
        size_t reserved = 0;
        BT_CHECK(miner_ballot_template_apply(&bt.block, catalog, bitmap, d->chain, 1,
                                              200000, &reserved).ok && reserved <= 200000);
    }
done:
    block_template_free(&bt);
    return failures;
}

int test_miner_ballot_template(void)
{
    int failures = 0;
    failures += bt_research_fit_case(30, 8000, false, false, false);
    failures += bt_research_fit_case(30, 8000, true, false, false);
    failures += bt_research_fit_case(255, 790, false, false, false);
    failures += bt_research_fit_case(30, 8000, false, true, false);
    failures += bt_research_fit_case(30, 8000, false, false, true);
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
    block_free(&block);
    BT_CHECK(bt_make(&block, 1));
    BT_CHECK(bt_alias_inputs(&block, params));
    block_free(&block);
    BT_CHECK(bt_make(&block, 1));
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
