/* purpose: Test ballot template ownership and exact reserved serialization. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/miner_ballot_template.h"
#include "mining/miner.h"
#include "services/miner_signal_round.h"
#include "services/research_rules_tip.h"
#include "services/research_rules.h"
#include "services/research_block_size.h"
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
#include "primitives/transaction_v6_decode.h"
#include "validation/main_constants.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

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

static bool bt_fit_count_matches(size_t limit, size_t actual, size_t count)
{
    return limit == 200000 ? actual < count : actual == count;
}

static bool bt_fit_size_matches(size_t limit, size_t bound)
{
    return limit <= 200000 || bound > 200000;
}

static int bt_tip_binding_child(void)
{
    int failures = 0;
    const struct chain_research_descriptor *d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    struct miner_signal_catalog_pin pin = { .start = 103, .window = 20, .count = 1 };
    BT_CHECK(d && d->chain);
    pin.network_id[0] = 1;
    memcpy(pin.genesis, d->chain->consensus.hashGenesisBlock.data, 32);
    memcpy(pin.entries[0].rule_revision, research_rule_revision[0], 32);
    pin.entries[0].activation = 125;
    struct miner_signal_catalog catalog = { .start = pin.start, .window = pin.window,
                                            .count = pin.count, .entries = pin.entries };
    memcpy(catalog.network_id, pin.network_id, 32);
    memcpy(catalog.genesis, pin.genesis, 32);
    struct miner_signal_schedule schedule;
    BT_CHECK(miner_signal_catalog_select(&catalog, 0, &schedule).ok);
    memcpy(pin.digest, schedule.catalog, 32);
    BT_CHECK(research_rules_install(d->chain, &pin));
    struct research_tip_rules rules = research_rules_tip_for_parent(NULL);
    BT_CHECK(rules.unavailable && rules.freeze && rules.capped);
    /* An undetermined tip leaves mining under the cap: the strictest limit is
     * valid whichever way the rules resolve. */
    struct research_rules_state cap_state = {0};
    cap_state.active[RESEARCH_RULE_BLOCK_CAP] = rules.capped;
    BT_CHECK(research_block_size_limit_for(d->chain, &cap_state) == RESEARCH_BLOCK_SIZE_LIMIT);
    struct block_index parent = { .nHeight = 0 };
    rules = research_rules_tip_for_parent(&parent);
    BT_CHECK(!rules.unavailable && !rules.freeze && !rules.capped);
done:
    return failures;
}

static int bt_tip_refusal(void)
{
    int failures = 0;
    struct transaction deposit = { .value_balance = -1 }, other = {0};
    struct research_tip_rules unavailable = { .freeze = true, .unavailable = true };
    const char *refusal = research_tip_deposit_refusal(unavailable, &deposit);
    BT_CHECK(refusal && strcmp(refusal, "research-rules-unavailable: the research rules active on this chain cannot be determined, so new net deposits into Sapling are refused until they can be") == 0);
    BT_CHECK(!strstr(refusal, "deposit-freeze"));
    refusal = research_tip_deposit_refusal((struct research_tip_rules){ .freeze = true }, &deposit);
    BT_CHECK(refusal && strcmp(refusal, "research-deposit-freeze: new net deposits into Sapling are frozen on this chain") == 0);
    BT_CHECK(!research_tip_deposit_refusal(unavailable, &other));
    BT_CHECK(!research_tip_deposit_refusal(unavailable, NULL));
    BT_CHECK(research_tip_deposit_frozen(unavailable, &deposit));
    /* Installation is once per process; a child leaves the parent's binding intact. */
    pid_t child = fork();
    BT_CHECK(child >= 0);
    if (child == 0) _exit(bt_tip_binding_child() ? 1 : 0);
    int status = 0;
    BT_CHECK(waitpid(child, &status, 0) == child);
    BT_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
done:
    return failures;
}

static int bt_research_fit_case(size_t count, size_t script_size, bool ballot, bool zero_fee, bool sapling,
                                size_t limit)
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
    BT_CHECK(miner_research_template_fit(&bt, d->chain, 1, ballot, limit, false).ok);
    BT_CHECK(bt_fit_count_matches(limit, bt.block.num_vtx, count));
    BT_CHECK(bt.num_entries == bt.block.num_vtx);
    BT_CHECK(bt.block.vtx[0].vout[0].value == 42 + (zero_fee ? 0 : (int64_t)bt.num_entries - 1));
    BT_CHECK(bt.tx_fees[0] == (zero_fee ? 0 : -(int64_t)(bt.num_entries - 1)));
    BT_CHECK(bt_merkle_matches(&bt.block));
    if (sapling) BT_CHECK(bt_retained_sapling_root(&bt.block, d->chain));
    for (size_t i = 1; i < bt.num_entries; i++) BT_CHECK(bt.block.vtx[i].lock_time == i);
    struct equihash_params ep;
    equihash_params_init(&ep, chain_params_equihash_n(d->chain, 1), chain_params_equihash_k(d->chain, 1));
    size_t bound = bt_serialized_block_bound(&bt.block, ep.solution_width);
    BT_CHECK(bound <= limit);
    BT_CHECK(bt_fit_size_matches(limit, bound));
    if (ballot) {
        uint8_t catalog[32] = {3}, bitmap[32] = {1};
        size_t reserved = 0;
        BT_CHECK(miner_ballot_template_apply(&bt.block, catalog, bitmap, d->chain, 1,
                                              limit, &reserved).ok && reserved <= limit);
    }
done:
    block_template_free(&bt);
    return failures;
}

static int bt_freeze_case(bool freeze)
{
    int failures = 0;
    struct block_template bt = {0};
    const struct chain_research_descriptor *d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    BT_CHECK(d && bt_make(&bt.block, 1));
    struct transaction cb = bt.block.vtx[0];
    free(bt.block.vtx);
    bt.block.vtx = calloc(3, sizeof(*bt.block.vtx));
    BT_CHECK(bt.block.vtx);
    bt.block.vtx[0] = cb;
    bt.block.num_vtx = 1;
    bt.tx_fees = calloc(3, sizeof(*bt.tx_fees));
    bt.tx_sig_ops = calloc(3, sizeof(*bt.tx_sig_ops));
    BT_CHECK(bt.tx_fees && bt.tx_sig_ops);
    for (size_t i = 1; i < 3; ++i) {
        transaction_init(&bt.block.vtx[i]);
        BT_CHECK(transaction_alloc(&bt.block.vtx[i], 1, 1));
        bt.block.num_vtx++;
        bt.block.vtx[i].lock_time = (uint32_t)i;
        bt.tx_fees[i] = 1;
    }
    bt.block.vtx[1].value_balance = -1;
    bt.block.vtx[0].vout[0].value += 2;
    bt.tx_fees[0] = -2;
    bt.num_entries = 3;
    BT_CHECK(research_tip_deposit_frozen((struct research_tip_rules){ .freeze = true }, &bt.block.vtx[1]));
    BT_CHECK(!research_tip_deposit_frozen((struct research_tip_rules){0}, &bt.block.vtx[1]));
    BT_CHECK(!research_tip_deposit_frozen((struct research_tip_rules){ .freeze = true }, &bt.block.vtx[2]));
    BT_CHECK(miner_research_template_fit(&bt, d->chain, 1, false, 200000, freeze).ok);
    BT_CHECK(bt.block.num_vtx == (freeze ? 1u : 3u));
    BT_CHECK(bt.num_entries == bt.block.num_vtx);
    BT_CHECK(bt.block.vtx[0].vout[0].value == (freeze ? 42 : 44));
    BT_CHECK(bt.tx_fees[0] == (freeze ? 0 : -2));
    BT_CHECK(bt_merkle_matches(&bt.block));
done:
    block_template_free(&bt);
    return failures;
}

static int bt_legacy_version_six_block(void)
{
    int failures = 0;
    struct block b = {0};
    BT_CHECK(bt_make(&b, 1));
    struct transaction *v = realloc(b.vtx, 2 * sizeof(*v));
    BT_CHECK(v);
    b.vtx = v;
    transaction_init(&v[1]);
    v[1].version = IRONWOOD_TX_VERSION;
    b.num_vtx = 2;
    struct byte_stream legacy, research;
    stream_init(&legacy, 0);
    stream_init(&research, 0);
    bool same = block_serialize(&b, &legacy) && research_block_write_for_size(&b, &research) &&
                legacy.size == research.size && !memcmp(legacy.data, research.data, legacy.size);
    stream_free(&legacy);
    stream_free(&research);
    BT_CHECK(same);
done:
    block_free(&b);
    return failures;
}

static bool bt_v6_fit_guards(struct block_template *bt, const struct chain_params *params)
{
    chain_params_select(CHAIN_MAIN);
    if (miner_research_template_fit(bt, params, 1, false, 200000, false).ok ||
        bt->block.num_vtx != 2 || !chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD)) return false;
    bt->block.vtx[1].ironwood_value_balance ^= 1;
    bool refused = !miner_research_template_fit(bt, params, 1, false, 200000, false).ok;
    bt->block.vtx[1].ironwood_value_balance ^= 1;
    return refused && bt->block.num_vtx == 2 &&
           miner_research_template_fit(bt, params, 1, false, 200000, false).ok &&
           bt->block.num_vtx == 2 && bt->num_entries == 2;
}

static bool bt_v6_merkle_matches(struct block *b)
{
    struct uint256 ids[2];
    if (!transaction_hash_serialized(&b->vtx[0], &ids[0])) return false;
    ids[1] = b->vtx[1].hash;
    bool mutated = false;
    struct uint256 root = merkle_root_mutated_in_place(ids, 2, &mutated);
    return !mutated && uint256_eq(&root, &b->header.hashMerkleRoot);
}

static bool bt_v6_exact_block(struct block *b, const uint8_t *wire, size_t len)
{
    struct byte_stream actual, expected;
    stream_init(&actual, 0);
    stream_init(&expected, 0);
    bool exact = research_block_write_for_size(b, &actual) &&
        block_header_serialize(&b->header, &expected) &&
        stream_write_compact_size(&expected, 2) && transaction_serialize(&b->vtx[0], &expected) &&
        stream_write_bytes(&expected, wire, len) && actual.size == expected.size &&
        !memcmp(actual.data, expected.data, actual.size);
    stream_free(&actual);
    stream_free(&expected);
    return exact;
}

static bool bt_v6_ballot_coinbase(struct block_template *bt, const struct chain_params *params, size_t wire_len)
{
    uint8_t catalog[32] = {3}, bitmap[32] = {1};
    size_t reserved = 0;
    if (!miner_ballot_template_apply(&bt->block, catalog, bitmap, params, 1,
                                      200000, &reserved).ok || reserved <= wire_len ||
        !bt_v6_merkle_matches(&bt->block)) return false;
    struct transaction *cb = &bt->block.vtx[0];
    int32_t version = cb->version;
    bool overwintered = cb->overwintered;
    uint32_t group = cb->version_group_id;
    cb->version = IRONWOOD_TX_VERSION;
    cb->overwintered = true;
    cb->version_group_id = IRONWOOD_VERSION_GROUP_ID;
    size_t outputs_before = cb->num_vout;
    bool refused = !miner_research_template_fit(bt, params, 1, false, 200000, false).ok &&
        !miner_ballot_template_apply(&bt->block, catalog, bitmap, params, 1, 200000, &reserved).ok &&
        cb->num_vout == outputs_before;
    cb->version = version;
    cb->overwintered = overwintered;
    cb->version_group_id = group;
    return refused;
}

static int bt_funded_v6_template(void)
{
    int failures = 0;
    struct block_template bt = {0};
    static uint8_t wire[9313];
    const struct chain_research_descriptor *d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    FILE *f = fopen("tests/fixtures/ironwood/postnu63-h1-reward-spend.v6", "rb");
    bool loaded = f && fread(wire, 1, sizeof wire, f) == sizeof wire && fgetc(f) == EOF && !ferror(f);
    if (f && fclose(f)) loaded = false;
    BT_CHECK(d && loaded && bt_make(&bt.block, 1));
    struct transaction *v = realloc(bt.block.vtx, 2 * sizeof(*v));
    BT_CHECK(v);
    bt.block.vtx = v;
    transaction_init(&v[1]);
    bt.block.num_vtx = 2;
    bt.num_entries = 2;
    bt.tx_fees = calloc(2, sizeof(*bt.tx_fees));
    bt.tx_sig_ops = calloc(2, sizeof(*bt.tx_sig_ops));
    BT_CHECK(bt.tx_fees && bt.tx_sig_ops);
    struct byte_stream input;
    stream_init_from_data(&input, wire, sizeof wire);
    BT_CHECK(transaction_v6_decode_prefix(&v[1], &input, sizeof wire) && !stream_remaining(&input));
    BT_CHECK(bt_v6_fit_guards(&bt, d->chain));
    BT_CHECK(bt_v6_merkle_matches(&bt.block));
    BT_CHECK(bt_v6_exact_block(&bt.block, wire, sizeof wire));
    BT_CHECK(bt_v6_ballot_coinbase(&bt, d->chain, sizeof wire));
done:
    block_template_free(&bt);
    chain_params_select(CHAIN_MAIN);
    return failures;
}

static int bt_size_boundaries(void)
{
    int failures = 0;
    struct block b = {0};
    const struct chain_research_descriptor *d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    BT_CHECK(d);
    b.num_vtx = 253;
    b.vtx = calloc(b.num_vtx, sizeof(*b.vtx));
    BT_CHECK(b.vtx);
    for (size_t i = 0; i < b.num_vtx; ++i) transaction_init(&b.vtx[i]);
    BT_CHECK(transaction_alloc(&b.vtx[0], 0, 25));
    for (size_t i = 0; i < 24; ++i) {
        memset(b.vtx[0].vout[i].script_pub_key.data, 0x51, 8000);
        b.vtx[0].vout[i].script_pub_key.size = 8000;
    }
    struct byte_stream s;
    stream_init(&s, 0);
    bool ok = block_serialize(&b, &s);
    size_t base = s.size;
    stream_free(&s);
    BT_CHECK(ok && base < 199999 && 200001 - base < 10000);
    struct research_rules_state capped = {0}, uncapped = {0};
    capped.active[RESEARCH_RULE_BLOCK_CAP] = true;
    /* Ballot templates follow the research chain's resolved limit and keep
     * the historical mining default on every other network. */
    struct chain_params ordinary = *d->chain;
    ordinary.consensus.hashGenesisBlock.data[0] ^= 1;
    BT_CHECK(research_ballot_template_limit(d->chain, &capped) == RESEARCH_BLOCK_SIZE_LIMIT);
    BT_CHECK(research_ballot_template_limit(d->chain, &uncapped) == MAX_BLOCK_SIZE);
    BT_CHECK(research_ballot_template_limit(&ordinary, &capped) == DEFAULT_BLOCK_MAX_SIZE);
    BT_CHECK(research_ballot_template_limit(&ordinary, &uncapped) == DEFAULT_BLOCK_MAX_SIZE);
    for (size_t size = 200000; size <= 200001; ++size) {
        struct script *script = &b.vtx[0].vout[24].script_pub_key;
        script->size = size - base - 2;
        memset(script->data, 0x51, script->size);
        stream_init(&s, 0);
        ok = block_serialize(&b, &s) && s.size == size;
        stream_free(&s);
        BT_CHECK(ok);
        BT_CHECK(research_block_size_check_under(&b, research_block_size_limit_for(d->chain, &capped)) ==
                 (size == 200000 ? RESEARCH_BLOCK_SIZE_OK : RESEARCH_BLOCK_SIZE_EXCEEDED));
        BT_CHECK(research_block_size_check_under(&b, research_block_size_limit_for(d->chain, &uncapped)) ==
                 RESEARCH_BLOCK_SIZE_OK);
    }
done:
    block_free(&b);
    return failures;
}

int test_miner_ballot_template(void)
{
    int failures = 0;
    failures += bt_legacy_version_six_block();
    failures += bt_funded_v6_template();
    failures += bt_tip_refusal();
    failures += bt_size_boundaries();
    failures += bt_freeze_case(false);
    failures += bt_freeze_case(true);
    failures += bt_research_fit_case(30, 8000, false, false, false, 200000);
    failures += bt_research_fit_case(30, 8000, true, false, false, 200000);
    failures += bt_research_fit_case(255, 790, false, false, false, 200000);
    failures += bt_research_fit_case(30, 8000, false, true, false, 200000);
    failures += bt_research_fit_case(30, 8000, false, false, true, 200000);
    failures += bt_research_fit_case(30, 8000, false, false, false, MAX_BLOCK_SIZE);
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
