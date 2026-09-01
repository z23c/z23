/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove canonical C23 seed and fixture-only shadow elections. */
#include "test/test_core.h"

#include "base/bytes.h"
#include "base/hex.h"
#include "crypto/ed25519.h"
#include "vcs/zcode_seed.h"
#include "vcs/zcode_shadow_election.h"

#include <secp256k1.h>
#include <stdlib.h>
#include <string.h>

#define SEED_FIXTURE_COUNT 6u

static const char seed_fixture_root_hex[] =
    "ce3b43aabcc2a3feedaa489161bc76756d8e8a34fe14d280c0eac9293ec12c93";

static const char *const shadow_election_root_hex[4] = {
    "911bf472f1eb07ee50fa706881aff82d0c56b2daa9c406697f79f4575a1c1610",
    "89e8c26d59957de264063915eead7640ac5da1d6f17bed8125ba0edd27bd1a06",
    "6cc3bbef00ccbd30206ac916beb62648ba223b83e5a6cc2cd2e959c95526f24b",
    "f46912d939cdcfbfd8937429717851cfb771702469caca60cc59666bb418a1ce",
};

static void seed_test_fill(uint8_t root[32], uint8_t value)
{
    memset(root, value, 32);
}

static bool seed_test_fixture(
    struct vcs_c23_seed_v1 *seed, uint8_t index,
    uint8_t zid_secret[32], uint8_t zcl_secret[32])
{
    memset(seed, 0, sizeof(*seed));
    memset(zid_secret, (uint8_t)(0x11u + index), 32);
    memset(zcl_secret, 0, 32);
    zcl_secret[31] = (uint8_t)(index + 1u);
    uint8_t derived_secret[32];
    ed25519_keypair(seed->zid_pubkey, derived_secret, zid_secret);
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;
    secp256k1_pubkey pubkey;
    bool ok = secp256k1_ec_pubkey_create(ctx, &pubkey, zcl_secret) == 1;
    size_t pubkey_len = sizeof(seed->zcl_pubkey);
    if (ok)
        ok = secp256k1_ec_pubkey_serialize(
                 ctx, seed->zcl_pubkey, &pubkey_len, &pubkey,
                 SECP256K1_EC_COMPRESSED) == 1 &&
             pubkey_len == sizeof(seed->zcl_pubkey);
    secp256k1_context_destroy(ctx);
    if (!ok) return false;

    seed->schema_version = VCS_C23_SEED_VERSION;
    seed->flags = VCS_C23_SEED_REQUIRED_FLAGS;
    seed_test_fill(seed->network_genesis_root, 0x21);
    seed_test_fill(seed->contributor_binding_root, (uint8_t)(0x30 + index));
    seed_test_fill(seed->package_root, (uint8_t)(0x40 + index));
    seed_test_fill(seed->release_root, (uint8_t)(0x50 + index));
    seed_test_fill(seed->dependency_lock_root, (uint8_t)(0x60 + index));
    seed_test_fill(seed->license_evidence_root, (uint8_t)(0x70 + index));
    seed_test_fill(seed->semantic_fingerprint_root,
                   (uint8_t)(0x80 + index));
    seed_test_fill(seed->novelty_evidence_root, (uint8_t)(0x90 + index));
    seed_test_fill(seed->target_capsule_root, (uint8_t)(0xa0 + index));
    seed_test_fill(seed->compiler_capsule_roots[0],
                   (uint8_t)(0x10 + index));
    seed_test_fill(seed->compiler_capsule_roots[1],
                   (uint8_t)(0xc0 + index));
    seed_test_fill(seed->build_report_roots[0],
                   (uint8_t)(0xd0 + index));
    seed_test_fill(seed->build_report_roots[1],
                   (uint8_t)(0xe0 + index));
    seed_test_fill(seed->dht_replication_root, (uint8_t)(0xf0 + index));
    seed->challenge_opening_height = 100u + index;
    seed_test_fill(seed->challenge_opening_hash, (uint8_t)(0xb0 + index));
    seed->challenge_opening_mtp = 1000 + index;
    seed->created_unix = 1100 + index;
    seed->sequence = index + 1u;
    return vcs_c23_seed_seal(seed, zid_secret, seed->zid_pubkey,
                             zcl_secret) == VCS_C23_SEED_OK;
}

struct seed_anchor_fixture {
    uint64_t rejected_height;
};

static bool seed_test_anchor(void *opaque, uint64_t height,
                             const uint8_t hash[32])
{
    const struct seed_anchor_fixture *fixture = opaque;
    return zcl_bytes_all_zero((const uint8_t *)hash, 32) == false &&
        (!fixture || fixture->rejected_height != height);
}

static void seed_test_inputs(
    const struct vcs_c23_seed_v1 seeds[SEED_FIXTURE_COUNT],
    struct vcs_c23_shadow_seed_input seed_inputs[SEED_FIXTURE_COUNT],
    struct vcs_c23_shadow_evidence_input evidence[SEED_FIXTURE_COUNT * 2u],
    uint64_t election_epoch)
{
    for (size_t i = 0; i < SEED_FIXTURE_COUNT; i++) {
        seed_inputs[i].seed = &seeds[i];
        for (size_t j = 0; j < 2; j++) {
            size_t at = i * 2u + j;
            seed_test_fill(evidence[at].contribution_root,
                           (uint8_t)(1u + at));
            memcpy(evidence[at].zid_pubkey, seeds[i].zid_pubkey, 32);
            evidence[at].event_epoch = election_epoch - 1u - (at % 8u);
            evidence[at].points = (uint32_t)(26u * (i + 1u) + j);
        }
    }
}

static int test_seed_wire(void)
{
    int failures = 0;
    TEST("c23.seed.v1 is exact, dual-signed and rejects non-creative source classes") {
        struct vcs_c23_seed_v1 seed;
        uint8_t zid_secret[32], zcl_secret[32];
        ASSERT(seed_test_fixture(&seed, 0, zid_secret, zcl_secret));
        ASSERT_EQ(vcs_c23_seed_validate(&seed), VCS_C23_SEED_OK);
        ASSERT_EQ(vcs_c23_seed_verify(&seed), VCS_C23_SEED_OK);
        uint8_t wire[VCS_C23_SEED_WIRE_BYTES];
        uint8_t repeated[VCS_C23_SEED_WIRE_BYTES];
        uint8_t root[32], repeated_root[32];
        ASSERT_EQ(vcs_c23_seed_serialize(&seed, wire), VCS_C23_SEED_OK);
        ASSERT_EQ(vcs_c23_seed_serialize(&seed, repeated), VCS_C23_SEED_OK);
        ASSERT(memcmp(wire, repeated, sizeof(wire)) == 0);
        ASSERT_EQ(vcs_c23_seed_root(&seed, root), VCS_C23_SEED_OK);
        ASSERT_EQ(vcs_c23_seed_root(&seed, repeated_root), VCS_C23_SEED_OK);
        ASSERT(memcmp(root, repeated_root, 32) == 0);
        uint8_t expected_root[32];
        ASSERT(zcl_hex_decode(seed_fixture_root_hex, expected_root,
                              sizeof(expected_root)));
        ASSERT(memcmp(root, expected_root, sizeof(root)) == 0);
        struct vcs_c23_seed_v1 parsed;
        ASSERT_EQ(vcs_c23_seed_parse(wire, sizeof(wire), &parsed),
                  VCS_C23_SEED_OK);
        ASSERT(memcmp(&parsed, &seed, sizeof(seed)) == 0);

        for (size_t n = 0; n < sizeof(wire); n++) {
            memset(&parsed, 0xa5, sizeof(parsed));
            ASSERT(vcs_c23_seed_parse(wire, n, &parsed) != VCS_C23_SEED_OK);
            ASSERT(zcl_bytes_all_zero((const uint8_t *)&parsed, sizeof(parsed)));
        }
        uint8_t trailing[VCS_C23_SEED_WIRE_BYTES + 1u];
        memcpy(trailing, wire, sizeof(wire)); trailing[sizeof(wire)] = 0;
        ASSERT_EQ(vcs_c23_seed_parse(trailing, sizeof(trailing), &parsed),
                  VCS_C23_SEED_ERR_WIRE_SIZE);
        ASSERT(zcl_bytes_all_zero((const uint8_t *)&parsed, sizeof(parsed)));

        struct vcs_c23_seed_v1 invalid = seed;
        invalid.source_flags = VCS_C23_SEED_SOURCE_GENERATED;
        ASSERT_EQ(vcs_c23_seed_validate(&invalid),
                  VCS_C23_SEED_ERR_SOURCE_CLASSIFICATION);
        invalid = seed; invalid.source_flags = VCS_C23_SEED_SOURCE_VENDORED;
        ASSERT_EQ(vcs_c23_seed_validate(&invalid),
                  VCS_C23_SEED_ERR_SOURCE_CLASSIFICATION);
        invalid = seed; invalid.source_flags = VCS_C23_SEED_SOURCE_COPIED;
        ASSERT_EQ(vcs_c23_seed_validate(&invalid),
                  VCS_C23_SEED_ERR_SOURCE_CLASSIFICATION);
        invalid = seed;
        memcpy(invalid.compiler_capsule_roots[0],
               invalid.compiler_capsule_roots[1], 32);
        ASSERT_EQ(vcs_c23_seed_validate(&invalid), VCS_C23_SEED_ERR_ORDER);
        invalid = seed; invalid.flags &= ~VCS_C23_SEED_WARNINGS_FATAL;
        ASSERT_EQ(vcs_c23_seed_validate(&invalid), VCS_C23_SEED_ERR_FLAGS);
        invalid = seed; invalid.zid_signature[0] ^= 1u;
        ASSERT_EQ(vcs_c23_seed_verify(&invalid), VCS_C23_SEED_ERR_SIGNATURE);

        char root_hex[65]; zcl_hex_encode(root, 32, root_hex);
        printf("c23.seed.v1 fixture root=%s wire_bytes=%u\n",
               root_hex, VCS_C23_SEED_WIRE_BYTES);
        PASS();
    } _test_next:;
    return failures;
}

static int test_seed_maturity(void)
{
    int failures = 0;
    TEST("C23 seed maturity requires both boundaries and the active opening anchor") {
        struct vcs_c23_seed_v1 seed;
        uint8_t zid_secret[32], zcl_secret[32];
        ASSERT(seed_test_fixture(&seed, 0, zid_secret, zcl_secret));
        uint64_t maturity_height = seed.challenge_opening_height +
                                   VCS_C23_SEED_CHALLENGE_BLOCKS;
        int64_t maturity_mtp = seed.challenge_opening_mtp +
                               VCS_C23_SEED_CHALLENGE_SECONDS;
        uint64_t observed_height = 99; int64_t observed_mtp = 99;
        struct seed_anchor_fixture anchor = {0};
        ASSERT_EQ(vcs_c23_seed_maturity(
                      &seed, maturity_height - 1u, maturity_mtp,
                      seed_test_anchor, &anchor,
                      &observed_height, &observed_mtp),
                  VCS_C23_SEED_ERR_IMMATURE);
        ASSERT_EQ(observed_height, 0); ASSERT_EQ(observed_mtp, 0);
        ASSERT_EQ(vcs_c23_seed_maturity(
                      &seed, maturity_height, maturity_mtp - 1,
                      seed_test_anchor, &anchor,
                      &observed_height, &observed_mtp),
                  VCS_C23_SEED_ERR_IMMATURE);
        ASSERT_EQ(vcs_c23_seed_maturity(
                      &seed, maturity_height, maturity_mtp,
                      seed_test_anchor, &anchor,
                      &observed_height, &observed_mtp),
                  VCS_C23_SEED_OK);
        ASSERT_EQ(observed_height, maturity_height);
        ASSERT_EQ(observed_mtp, maturity_mtp);
        anchor.rejected_height = seed.challenge_opening_height;
        ASSERT_EQ(vcs_c23_seed_maturity(
                      &seed, maturity_height, maturity_mtp,
                      seed_test_anchor, &anchor,
                      &observed_height, &observed_mtp),
                  VCS_C23_SEED_ERR_REORG);
        PASS();
    } _test_next:;
    return failures;
}

static int test_shadow_elections(void)
{
    int failures = 0;
    TEST("C23 evidence snapshots and four shadow elections are deterministic and non-authoritative") {
        struct vcs_c23_seed_v1 seeds[SEED_FIXTURE_COUNT];
        uint8_t zid_secrets[SEED_FIXTURE_COUNT][32];
        uint8_t zcl_secrets[SEED_FIXTURE_COUNT][32];
        for (size_t i = 0; i < SEED_FIXTURE_COUNT; i++)
            ASSERT(seed_test_fixture(&seeds[i], (uint8_t)i,
                                     zid_secrets[i], zcl_secrets[i]));
        struct vcs_c23_shadow_seed_input seed_inputs[SEED_FIXTURE_COUNT];
        struct vcs_c23_shadow_evidence_input evidence[SEED_FIXTURE_COUNT * 2u];
        uint8_t network[32], policy[32], freeze_hash[32];
        seed_test_fill(network, 0x21); seed_test_fill(policy, 0x22);
        seed_test_fill(freeze_hash, 0x23);
        seed_test_inputs(seeds, seed_inputs, evidence, 30);
        struct seed_anchor_fixture anchor = {0};
        struct vcs_c23_evidence_snapshot_input snapshot_input = {
            .network_genesis_root = network,
            .policy_root = policy,
            .seeds = seed_inputs,
            .seed_count = SEED_FIXTURE_COUNT,
            .evidence = evidence,
            .evidence_count = SEED_FIXTURE_COUNT * 2u,
            .election_epoch = 30,
            .freeze_height = 8500,
            .freeze_hash = freeze_hash,
            .active_height = 9000,
            .active_mtp = 700000,
            .anchor_is_active = seed_test_anchor,
            .anchor_opaque = &anchor,
        };
        struct vcs_c23_evidence_snapshot_row rows[SEED_FIXTURE_COUNT];
        struct vcs_c23_evidence_snapshot_v1 snapshot;
        ASSERT_EQ(vcs_c23_evidence_snapshot_build(
                      &snapshot_input, rows, SEED_FIXTURE_COUNT, &snapshot),
                  VCS_C23_SHADOW_ELECTION_OK);
        ASSERT_EQ(snapshot.candidate_count, SEED_FIXTURE_COUNT);
        ASSERT(snapshot.total_weight > SEED_FIXTURE_COUNT);

        struct vcs_c23_shadow_seed_input reversed_seeds[SEED_FIXTURE_COUNT];
        struct vcs_c23_shadow_evidence_input reversed_evidence[
            SEED_FIXTURE_COUNT * 2u];
        for (size_t i = 0; i < SEED_FIXTURE_COUNT; i++)
            reversed_seeds[i] = seed_inputs[SEED_FIXTURE_COUNT - 1u - i];
        for (size_t i = 0; i < SEED_FIXTURE_COUNT * 2u; i++)
            reversed_evidence[i] =
                evidence[SEED_FIXTURE_COUNT * 2u - 1u - i];
        snapshot_input.seeds = reversed_seeds;
        snapshot_input.evidence = reversed_evidence;
        struct vcs_c23_evidence_snapshot_row reversed_rows[
            SEED_FIXTURE_COUNT];
        struct vcs_c23_evidence_snapshot_v1 reversed_snapshot;
        ASSERT_EQ(vcs_c23_evidence_snapshot_build(
                      &snapshot_input, reversed_rows, SEED_FIXTURE_COUNT,
                      &reversed_snapshot), VCS_C23_SHADOW_ELECTION_OK);
        ASSERT(memcmp(snapshot.snapshot_root,
                      reversed_snapshot.snapshot_root, 32) == 0);
        ASSERT(memcmp(rows, reversed_rows, sizeof(rows)) == 0);
        snapshot_input.seeds = seed_inputs;
        snapshot_input.evidence = evidence;

        uint8_t wrong_network[32];
        seed_test_fill(wrong_network, 0x24);
        snapshot_input.network_genesis_root = wrong_network;
        ASSERT_EQ(vcs_c23_evidence_snapshot_build(
                      &snapshot_input, reversed_rows, SEED_FIXTURE_COUNT,
                      &reversed_snapshot), VCS_C23_SHADOW_ELECTION_NETWORK);
        snapshot_input.network_genesis_root = network;

        struct vcs_c23_seed_v1 bad_signature = seeds[0];
        bad_signature.zid_signature[0] ^= 1u;
        struct vcs_c23_shadow_seed_input bad_seed_inputs[
            SEED_FIXTURE_COUNT];
        memcpy(bad_seed_inputs, seed_inputs, sizeof(bad_seed_inputs));
        bad_seed_inputs[0].seed = &bad_signature;
        snapshot_input.seeds = bad_seed_inputs;
        ASSERT_EQ(vcs_c23_evidence_snapshot_build(
                      &snapshot_input, reversed_rows, SEED_FIXTURE_COUNT,
                      &reversed_snapshot), VCS_C23_SHADOW_ELECTION_EVIDENCE);
        snapshot_input.seeds = seed_inputs;

        uint64_t active_height = snapshot_input.active_height;
        snapshot_input.active_height = snapshot_input.freeze_height - 1u;
        ASSERT_EQ(vcs_c23_evidence_snapshot_build(
                      &snapshot_input, reversed_rows, SEED_FIXTURE_COUNT,
                      &reversed_snapshot), VCS_C23_SHADOW_ELECTION_IMMATURE);
        snapshot_input.active_height = active_height;

        struct vcs_c23_shadow_evidence_input stale_evidence[
            SEED_FIXTURE_COUNT * 2u];
        memcpy(stale_evidence, evidence, sizeof(stale_evidence));
        stale_evidence[0].event_epoch =
            snapshot_input.election_epoch -
            VCS_C23_SHADOW_HISTORY_EPOCHS - 1u;
        snapshot_input.evidence = stale_evidence;
        ASSERT_EQ(vcs_c23_evidence_snapshot_build(
                      &snapshot_input, reversed_rows, SEED_FIXTURE_COUNT,
                      &reversed_snapshot), VCS_C23_SHADOW_ELECTION_EVIDENCE);
        stale_evidence[0].event_epoch = snapshot_input.election_epoch;
        ASSERT_EQ(vcs_c23_evidence_snapshot_build(
                      &snapshot_input, reversed_rows, SEED_FIXTURE_COUNT,
                      &reversed_snapshot), VCS_C23_SHADOW_ELECTION_EVIDENCE);
        snapshot_input.evidence = evidence;

        struct vcs_c23_shadow_seed_input duplicate_seeds[SEED_FIXTURE_COUNT];
        memcpy(duplicate_seeds, seed_inputs, sizeof(duplicate_seeds));
        duplicate_seeds[1] = duplicate_seeds[0];
        snapshot_input.seeds = duplicate_seeds;
        ASSERT_EQ(vcs_c23_evidence_snapshot_build(
                      &snapshot_input, reversed_rows, SEED_FIXTURE_COUNT,
                      &reversed_snapshot), VCS_C23_SHADOW_ELECTION_DUPLICATE);
        snapshot_input.seeds = seed_inputs;
        struct vcs_c23_shadow_evidence_input duplicate_evidence[
            SEED_FIXTURE_COUNT * 2u];
        memcpy(duplicate_evidence, evidence, sizeof(duplicate_evidence));
        memcpy(duplicate_evidence[1].contribution_root,
               duplicate_evidence[0].contribution_root, 32);
        snapshot_input.evidence = duplicate_evidence;
        ASSERT_EQ(vcs_c23_evidence_snapshot_build(
                      &snapshot_input, reversed_rows, SEED_FIXTURE_COUNT,
                      &reversed_snapshot), VCS_C23_SHADOW_ELECTION_DUPLICATE);
        snapshot_input.evidence = evidence;
        anchor.rejected_height = snapshot_input.freeze_height;
        ASSERT_EQ(vcs_c23_evidence_snapshot_build(
                      &snapshot_input, reversed_rows, SEED_FIXTURE_COUNT,
                      &reversed_snapshot), VCS_C23_SHADOW_ELECTION_ANCHOR);
        anchor.rejected_height = 0;

        uint8_t election_roots[4][32];
        for (size_t epoch_offset = 0; epoch_offset < 4; epoch_offset++) {
            uint64_t epoch = 30u + epoch_offset;
            seed_test_inputs(seeds, seed_inputs, evidence, epoch);
            snapshot_input.election_epoch = epoch;
            snapshot_input.freeze_height = 8500u + epoch_offset;
            seed_test_fill(freeze_hash, (uint8_t)(0x23u + epoch_offset));
            ASSERT_EQ(vcs_c23_evidence_snapshot_build(
                          &snapshot_input, rows, SEED_FIXTURE_COUNT,
                          &snapshot), VCS_C23_SHADOW_ELECTION_OK);
            uint8_t blocks[VCS_C23_SHADOW_ELECTION_BLOCKS][32];
            for (size_t i = 0; i < VCS_C23_SHADOW_ELECTION_BLOCKS; i++)
                seed_test_fill(blocks[i],
                    (uint8_t)(1u + ((epoch_offset * 64u + i) % 254u)));
            struct vcs_c23_shadow_election_input election_input = {
                .snapshot = &snapshot,
                .seed_start_height = 9001u + epoch_offset * 64u,
                .seed_block_hashes = blocks,
                .seat_count = 4,
            };
            struct vcs_c23_shadow_election_seat seats[4], repeated_seats[4];
            struct vcs_c23_shadow_election_v1 election, repeated;
            ASSERT_EQ(vcs_c23_shadow_election_build(
                          &election_input, seats, 4, &election),
                      VCS_C23_SHADOW_ELECTION_OK);
            ASSERT_EQ(vcs_c23_shadow_election_build(
                          &election_input, repeated_seats, 4, &repeated),
                      VCS_C23_SHADOW_ELECTION_OK);
            ASSERT(memcmp(election.election_root,
                          repeated.election_root, 32) == 0);
            ASSERT(memcmp(seats, repeated_seats, sizeof(seats)) == 0);
            ASSERT(election.simulation_only);
            ASSERT(!election.authority_conferred);
            ASSERT(election.maximum_weight_ppm > 0);
            ASSERT(election.concentration_ppm > 0);
            for (size_t i = 0; i < election.seat_count; i++)
                for (size_t j = i + 1u; j < election.seat_count; j++)
                    ASSERT(memcmp(seats[i].zid_pubkey,
                                  seats[j].zid_pubkey, 32) != 0);
            memcpy(election_roots[epoch_offset], election.election_root, 32);
            blocks[10][0] ^= 0x80u;
            ASSERT_EQ(vcs_c23_shadow_election_build(
                          &election_input, repeated_seats, 4, &repeated),
                      VCS_C23_SHADOW_ELECTION_OK);
            ASSERT(memcmp(election.election_root,
                          repeated.election_root, 32) != 0);
        }
        for (size_t i = 0; i < 4; i++)
            for (size_t j = i + 1u; j < 4; j++)
                ASSERT(memcmp(election_roots[i], election_roots[j], 32) != 0);
        for (size_t i = 0; i < 4; i++) {
            uint8_t expected_root[32];
            ASSERT(zcl_hex_decode(shadow_election_root_hex[i], expected_root,
                                  sizeof(expected_root)));
            ASSERT(memcmp(election_roots[i], expected_root,
                          sizeof(expected_root)) == 0);
        }
        char roots_hex[4][65];
        for (size_t i = 0; i < 4; i++)
            zcl_hex_encode(election_roots[i], 32, roots_hex[i]);
        printf("c23 shadow elections: e30=%s e31=%s e32=%s e33=%s authority_conferred=false\n",
               roots_hex[0], roots_hex[1], roots_hex[2], roots_hex[3]);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_seed_election(void)
{
    int failures = test_seed_wire() + test_seed_maturity() +
                   test_shadow_elections();
    TEST("C23 seed and shadow election APIs fail closed") {
        struct vcs_c23_seed_v1 seed;
        struct vcs_c23_shadow_election_v1 election;
        ASSERT_EQ(vcs_c23_seed_validate(NULL), VCS_C23_SEED_ERR_NULL);
        ASSERT_EQ(vcs_c23_seed_parse(NULL, 0, &seed),
                  VCS_C23_SEED_ERR_NULL);
        ASSERT_EQ(vcs_c23_shadow_election_build(NULL, NULL, 0, &election),
                  VCS_C23_SHADOW_ELECTION_NULL);
        PASS();
    } _test_next:;
    printf("=== zcode_seed_election: %d failures ===\n", failures);
    return failures;
}
