/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Drive the published Ironwood profile identity and ballot round. */

#include "services/research_profile.h"
#include "services/miner_signal_catalog.h"
#include "services/miner_signal_round.h"
#include "services/miner_ballot_template.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sha3/sha3.h"
#include "validation/main_constants.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RP_CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "research_profile line %d: %s\n", __LINE__, #expr); return 1; \
} } while (0)

static const char k_transport[] = "Z23/Ironwood/testnet/transport/v1";
static const char k_fork[] = "Z23/Ironwood/testnet/experimental-round/v1";
static const char k_baseline[] = "Z23/Ironwood/testnet/baseline/v1";
static const uint32_t k_easy_target = 0x207fffffu;

static struct research_profile_spec published_spec(const struct chain_research_descriptor *d,
                                                   const uint8_t baseline[32],
                                                   const int32_t *activations,
                                                   size_t count)
{
    struct research_profile_spec spec = {
        .baseline = baseline,
        .start = 1,
        .window = 20,
        .activations = activations,
        .activation_count = count,
        .genesis_wire = d->genesis_wire,
        .genesis_wire_len = d->genesis_wire_len,
        .header_len = 177,
        .rpc_port = (uint16_t)d->base->nRPCPort,
        .datadir = d->base->strDataDir,
        .transport_domain = k_transport
    };
    return spec;
}

static int magic_matches(const struct research_profile_identity *id,
                        const struct chain_research_descriptor *d)
{
    if (id->message_start[0] != 0xd4 || id->message_start[1] != 0x14) return 0;
    if (id->message_start[2] != 0x83 || id->message_start[3] != 0xfa) return 0;
    return memcmp(id->message_start, d->chain->pchMessageStart, 4) == 0;
}

static int bind_published(const struct chain_research_descriptor *d, uint8_t baseline[32],
                          struct research_profile_identity *published)
{
    const int32_t heights[] = {23, 24};
    struct research_profile_spec spec = published_spec(d, baseline, heights, 2);
    RP_CHECK(research_profile_bind(&spec, published).ok);
    printf("genesis_display=%s\n", published->genesis_display);
    printf("rpc_port=%u\n", published->rpc_port);
    printf("datadir=%s\n", published->datadir);
    printf("message_start=%02x%02x%02x%02x\n",
           published->message_start[0], published->message_start[1],
           published->message_start[2], published->message_start[3]);
    printf("state_dir=%s\n", published->state_dir);
    RP_CHECK(strcmp(published->genesis_display,
                    "0eadaa0b42b377b8d05d1a9b313f1795b8ac4553217a5d06b0f66cddff8c78e7") == 0);
    RP_CHECK(published->rpc_port == 28023);
    RP_CHECK(strcmp(published->datadir, "ironwood-research") == 0);
    RP_CHECK(magic_matches(published, d));
    return 0;
}

static int bind_moved(const struct chain_research_descriptor *d, uint8_t baseline[32],
                      const struct research_profile_identity *published,
                      struct research_profile_identity *moved)
{
    const int32_t heights[] = {23, 26};
    struct research_profile_spec spec = published_spec(d, baseline, heights, 2);
    RP_CHECK(research_profile_bind(&spec, moved).ok);
    char first[65], second[65];
    zcl_hex_encode(published->commitment, 32, first);
    zcl_hex_encode(moved->commitment, 32, second);
    printf("commitment=%s\n", first);
    printf("second_commitment=%s\n", second);
    printf("second_state_dir=%s\n", moved->state_dir);
    RP_CHECK(strcmp(first, second) != 0);
    RP_CHECK(strcmp(published->state_dir, moved->state_dir) != 0);
    RP_CHECK(strcmp(moved->genesis_display, published->genesis_display) == 0);
    printf("second_identity_differs=1\n");
    const int32_t early[] = {21};
    spec.activations = early;
    spec.activation_count = 1;
    struct research_profile_identity copy = *published;
    RP_CHECK(!research_profile_bind(&spec, &copy).ok);
    RP_CHECK(memcmp(&copy, published, sizeof(copy)) == 0);
    return 0;
}

static int child_cases(const struct research_profile_identity *published,
                       const struct research_profile_identity *moved)
{
    struct research_profile_child own = {0}, foreign = {0};
    int pow_ok = 0;
    RP_CHECK(research_profile_solve_child(published, k_easy_target, &own).ok);
    struct zcl_result accepted = research_profile_accept_child(published, &own, &pow_ok);
    RP_CHECK(accepted.ok);
    RP_CHECK(pow_ok);
    RP_CHECK(research_profile_solve_child(moved, k_easy_target, &foreign).ok);
    struct zcl_result refused = research_profile_accept_child(published, &foreign, &pow_ok);
    printf("cross-profile child refused pow=%s message=%s\n",
           pow_ok ? "valid" : "invalid", refused.message);
    RP_CHECK(!refused.ok);
    RP_CHECK(pow_ok);
    RP_CHECK(strstr(refused.message, "Cross-profile child refused") != NULL);
    foreign.nonce[0] ^= 0xff;
    foreign.nonce[1] ^= 0xff;
    struct zcl_result bad = research_profile_accept_child(published, &foreign, &pow_ok);
    RP_CHECK(!bad.ok);
    RP_CHECK(!pow_ok);
    return 0;
}

static int fill_rule(struct miner_signal_catalog_entry *entry, const char *hex, int32_t height)
{
    if (!zcl_hex_decode(hex, entry->rule_revision, 32)) return 0;
    entry->activation = height;
    return 1;
}

static int ironwood_catalog(const struct research_profile_identity *published,
                           struct miner_signal_catalog_entry entries[2],
                           struct miner_signal_catalog *catalog)
{
    uint8_t fork[32];
    sha3_256((const uint8_t *)k_fork, sizeof(k_fork) - 1, fork);
    RP_CHECK(fill_rule(&entries[0],
                       "6768eafc3e43a946ac945bdec839f5cdc751e6be73570b53b6101b65616fa286", 23));
    RP_CHECK(fill_rule(&entries[1],
                       "dd9a28179af68e0e8b65831cca98d73c398da03ae66cc0e50f0f810904a664e8", 24));
    catalog->start = 1;
    catalog->window = 20;
    catalog->count = 2;
    catalog->entries = entries;
    memcpy(catalog->network_id, fork, 32);
    memcpy(catalog->genesis, published->genesis_raw, 32);
    return 0;
}

static uint8_t vote_byte(int height)
{
    if (height <= 18) return 0x03;
    if (height == 19) return 0x01;
    return 0;
}

static int tally_one(const struct miner_signal_schedule *schedule, struct miner_signal_tally *tally)
{
    struct tx_in input = {0};
    outpoint_set_null(&input.prevout);
    struct tx_out output = {0};
    struct transaction coinbase = {
        .vin = &input, .num_vin = 1, .vout = &output, .num_vout = 1
    };
    struct uint256 zero = {{0}};
    RP_CHECK(miner_signal_begin(schedule, 0, &zero, tally).ok);
    for (int height = 1; height <= 20; ++height) {
        uint8_t bitmap[32] = {0};
        bitmap[0] = vote_byte(height);
        miner_signal_ballot_script(schedule->catalog, bitmap, output.script_pub_key.data);
        output.script_pub_key.size = MINER_SIGNAL_SCRIPT_BYTES;
        output.value = 0;
        struct uint256 next = {{0}};
        next.data[0] = (uint8_t)height;
        RP_CHECK(miner_signal_connect(tally, height, &tally->parent_hash,
                                      &next, &coinbase, tally).ok);
    }
    return 0;
}

static int report_phases(const struct miner_signal_tally *slot0,
                         const struct miner_signal_tally *slot1)
{
    enum miner_signal_phase phase0 = MINER_SIGNAL_VOTING;
    enum miner_signal_phase phase1 = MINER_SIGNAL_VOTING;
    RP_CHECK(miner_signal_phase_at(slot0, 23, &phase0).ok);
    RP_CHECK(miner_signal_phase_at(slot1, 23, &phase1).ok);
    if (phase0 == MINER_SIGNAL_ACTIVE) printf("slot 0 active for block 23\n");
    else printf("slot 0 inactive for block 23\n");
    if (phase1 == MINER_SIGNAL_EXPIRED) printf("slot 1 expired\n");
    else printf("slot 1 live\n");
    RP_CHECK(phase0 == MINER_SIGNAL_ACTIVE);
    RP_CHECK(phase1 == MINER_SIGNAL_EXPIRED);
    return 0;
}

static int ballot_cases(const struct research_profile_identity *published)
{
    struct miner_signal_catalog_entry entries[2] = {0};
    struct miner_signal_catalog catalog = {0};
    struct miner_signal_schedule slot0 = {0}, slot1 = {0};
    RP_CHECK(ironwood_catalog(published, entries, &catalog) == 0);
    RP_CHECK(miner_signal_catalog_select(&catalog, 0, &slot0).ok);
    RP_CHECK(miner_signal_catalog_select(&catalog, 1, &slot1).ok);
    char digest[65];
    zcl_hex_encode(slot0.catalog, 32, digest);
    printf("catalog_digest=%s\n", digest);
    RP_CHECK(strcmp(digest,
                    "a2eebcca533c2173cea136af4085fe50d7523b5e0d70b2d895ba0b106f70ff73") == 0);
    RP_CHECK(memcmp(slot0.catalog, slot1.catalog, 32) == 0);
    int32_t required = miner_signal_required_votes(slot0.window);
    printf("required_votes=%d\n", required);
    RP_CHECK(required == 19);
    struct miner_signal_tally tallies[2] = {0};
    RP_CHECK(tally_one(&slot0, &tallies[0]) == 0);
    RP_CHECK(tally_one(&slot1, &tallies[1]) == 0);
    printf("slot0_votes=%d\n", tallies[0].votes);
    printf("slot1_votes=%d\n", tallies[1].votes);
    RP_CHECK(tallies[0].votes == 19);
    RP_CHECK(tallies[1].votes == 18);
    return report_phases(&tallies[0], &tallies[1]);
}

static int template_case(const struct chain_research_descriptor *d,
                         const struct research_profile_identity *published)
{
    uint8_t fork[32], bitmap[32] = {0x03};
    sha3_256((const uint8_t *)k_fork, sizeof(k_fork) - 1, fork);
    struct miner_signal_catalog_entry entries[2] = {0};
    RP_CHECK(fill_rule(&entries[0],
                       "6768eafc3e43a946ac945bdec839f5cdc751e6be73570b53b6101b65616fa286", 23));
    RP_CHECK(fill_rule(&entries[1],
                       "dd9a28179af68e0e8b65831cca98d73c398da03ae66cc0e50f0f810904a664e8", 24));
    struct miner_signal_catalog catalog = {
        .start = 1, .window = 20, .count = 2, .entries = entries
    };
    memcpy(catalog.network_id, fork, 32);
    memcpy(catalog.genesis, published->genesis_raw, 32);
    struct miner_signal_schedule selected = {0};
    RP_CHECK(miner_signal_catalog_select(&catalog, 0, &selected).ok);

    struct block block;
    block_init(&block);
    block.vtx = calloc(1, sizeof(*block.vtx));
    RP_CHECK(block.vtx);
    block.num_vtx = 1;
    transaction_init(&block.vtx[0]);
    RP_CHECK(transaction_alloc(&block.vtx[0], 1, 1));
    outpoint_set_null(&block.vtx[0].vin[0].prevout);
    block.vtx[0].vin[0].script_sig.size = 2;
    block.vtx[0].vin[0].script_sig.data[0] = 1;
    block.vtx[0].vin[0].script_sig.data[1] = 1;
    block.vtx[0].vout[0].value = 0;
    block.vtx[0].vout[0].script_pub_key.size = 1;
    block.vtx[0].vout[0].script_pub_key.data[0] = 0x6a;
    size_t reserved = 0;
    struct zcl_result applied = miner_ballot_template_apply(
        &block, selected.catalog, bitmap, d->chain, 1, DEFAULT_BLOCK_MAX_SIZE, &reserved);
    RP_CHECK(applied.ok);
    const struct script *ballot = &block.vtx[0].vout[1].script_pub_key;
    RP_CHECK(ballot->size == MINER_SIGNAL_SCRIPT_BYTES);
    RP_CHECK(memcmp(ballot->data + 7, selected.catalog, 32) == 0);
    RP_CHECK(memcmp(ballot->data + 39, bitmap, 32) == 0);
    RP_CHECK(block.header.nSolutionSize == 0);
    struct uint256 txid = {{0}};
    RP_CHECK(transaction_hash_serialized(&block.vtx[0], &txid));
    RP_CHECK(uint256_eq(&txid, &block.vtx[0].hash));
    RP_CHECK(uint256_eq(&txid, &block.header.hashMerkleRoot));
    printf("ballot_committed_before_txid=1\n");
    printf("merkle_root_matches_txid=1\n");
    printf("proof_of_work=unsolved\n");
    block_free(&block);
    return 0;
}

int test_research_profile(void)
{
    uint8_t baseline[32];
    sha3_256((const uint8_t *)k_baseline, sizeof(k_baseline) - 1, baseline);
    const struct chain_research_descriptor *d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d) {
        fprintf(stderr, "research_profile: published genesis fixture is missing\n");
        return 1;
    }
    struct research_profile_identity published = {0}, moved = {0};
    if (bind_published(d, baseline, &published)) return 1;
    if (bind_moved(d, baseline, &published, &moved)) return 1;
    if (child_cases(&published, &moved)) return 1;
    if (ballot_cases(&published)) return 1;
    if (template_case(d, &published)) return 1;
    printf("research_profile: identity and ballot round passed\n");
    return 0;
}
