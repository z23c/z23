/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: Pin v1 and v2 consensus state bundle artifact encoding. */
#include "test/test_core.h"
#include "storage/consensus_state_bundle_codec.h"
#include <string.h>

static const uint8_t golden_v1[32] = {
    0x46, 0xa9, 0x42, 0x31, 0xd7, 0x02, 0x49, 0xeb,
    0x5a, 0x62, 0x56, 0x94, 0xcd, 0xaa, 0x5e, 0xc5,
    0xfc, 0xd7, 0xd0, 0x4e, 0x4d, 0x1c, 0xf5, 0x3f,
    0x74, 0x57, 0x99, 0x87, 0xd4, 0x2b, 0xc9, 0x0d,
};
static const uint8_t golden_v2[32] = {
    0xe0, 0x95, 0xfd, 0x22, 0x28, 0x9f, 0x7b, 0xdf,
    0xc2, 0x9f, 0xc8, 0xb6, 0xc4, 0x7b, 0x6a, 0x0c,
    0x03, 0xfb, 0x1f, 0x41, 0x96, 0x78, 0x6b, 0x20,
    0xac, 0xfb, 0x9a, 0x2c, 0x66, 0xab, 0x2f, 0x1e,
};
static const uint8_t zero_digest[32] = {0};

static struct consensus_state_bundle_manifest codec_fixture(void)
{
    struct consensus_state_bundle_manifest m = {
        .format_version = CONSENSUS_STATE_BUNDLE_V1,
        .height = 42, .history_complete = true, .source_clean = true,
        .validation_profile = CONSENSUS_STATE_VALIDATION_FULL,
        .activation_boundary = -1, .utxo_count = 1, .total_supply = 100,
        .anchor_count = 2, .sprout_frontier_height = 42,
        .sapling_frontier_height = 42, .nullifier_count = 1,
        .sprout_source_cursor = 43, .sapling_source_cursor = 43,
        .nullifier_source_cursor = 43, .source_fold_cursor = 43,
    };
    m.block_hash[0] = 1;
    m.utxo_root[0] = 2;
    m.anchor_digest[0] = 3;
    m.sprout_frontier_root[0] = 4;
    m.sapling_frontier_root[0] = 5;
    m.nullifier_digest[0] = 6;
    m.proof_manifest_digest[0] = 7;
    m.source_digest[0] = 8;
    return m;
}

static int codec_v1(void)
{
    int failures = 0;
    TEST_CASE("v1 artifact golden digest and aliased output") {
        struct consensus_state_bundle_manifest m = codec_fixture();
        uint8_t actual[32];
        consensus_state_bundle_artifact_digest(&m, actual);
        ASSERT(memcmp(actual, golden_v1, 32) == 0);
        consensus_state_bundle_artifact_digest(&m, m.artifact_digest);
        ASSERT(memcmp(m.artifact_digest, golden_v1, 32) == 0);
    } TEST_END
    return failures;
}

static int codec_v2(void)
{
    int failures = 0;
    TEST_CASE("v2 artifact binds both totals and distinguishes known zero") {
        struct consensus_state_bundle_manifest m = codec_fixture();
        uint8_t actual[32];
        m.format_version = CONSENSUS_STATE_BUNDLE_V2;
        m.sprout_pool_total = INT64_C(1316412375709);
        m.sapling_pool_total = INT64_C(3212475963678);
        consensus_state_bundle_artifact_digest(&m, actual);
        ASSERT(memcmp(actual, golden_v2, 32) == 0);
        consensus_state_bundle_artifact_digest(&m, m.artifact_digest);
        ASSERT(memcmp(m.artifact_digest, golden_v2, 32) == 0);
        m.sprout_pool_total++;
        consensus_state_bundle_artifact_digest(&m, actual);
        ASSERT(memcmp(actual, zero_digest, 32) != 0);
        ASSERT(memcmp(actual, golden_v2, 32) != 0);
        m.sprout_pool_total--;
        m.sapling_pool_total++;
        consensus_state_bundle_artifact_digest(&m, actual);
        ASSERT(memcmp(actual, zero_digest, 32) != 0);
        ASSERT(memcmp(actual, golden_v2, 32) != 0);
        m.sprout_pool_total = 0;
        m.sapling_pool_total = 0;
        consensus_state_bundle_artifact_digest(&m, actual);
        ASSERT(memcmp(actual, zero_digest, 32) != 0);
        ASSERT(memcmp(actual, golden_v1, 32) != 0);
    } TEST_END
    return failures;
}

static int codec_refusals(void)
{
    int failures = 0;
    TEST_CASE("invalid formats and negative v2 totals clear output") {
        struct consensus_state_bundle_manifest m = codec_fixture();
        uint8_t actual[32];
        m.format_version = CONSENSUS_STATE_BUNDLE_V2;
        m.sprout_pool_total = -1;
        memset(actual, 1, sizeof(actual));
        consensus_state_bundle_artifact_digest(&m, actual);
        ASSERT(memcmp(actual, zero_digest, 32) == 0);
        m.sprout_pool_total = 0;
        m.sapling_pool_total = -1;
        memset(m.artifact_digest, 1, sizeof(m.artifact_digest));
        consensus_state_bundle_artifact_digest(&m, m.artifact_digest);
        ASSERT(memcmp(m.artifact_digest, zero_digest, 32) == 0);
        m.sapling_pool_total = 0;
        m.format_version = CONSENSUS_STATE_BUNDLE_INVALID;
        memset(actual, 1, sizeof(actual));
        consensus_state_bundle_artifact_digest(&m, actual);
        ASSERT(memcmp(actual, zero_digest, 32) == 0);
        m.format_version = 3;
        memset(actual, 1, sizeof(actual));
        consensus_state_bundle_artifact_digest(&m, actual);
        ASSERT(memcmp(actual, zero_digest, 32) == 0);
    } TEST_END
    return failures;
}

static int codec_schema(void)
{
    int failures = 0;
    TEST_CASE("bundle schema parsing is exact and clears invalid output") {
        uint8_t version = 99;
        const char v1[] = CONSENSUS_STATE_BUNDLE_SCHEMA_V1;
        const char v2[] = CONSENSUS_STATE_BUNDLE_SCHEMA_V2;
        const char v3[] = "zcl.consensus_state_bundle.v3";
        ASSERT(consensus_state_bundle_schema_version(v1, sizeof(v1) - 1, &version));
        ASSERT_EQ(version, CONSENSUS_STATE_BUNDLE_V1);
        ASSERT(consensus_state_bundle_schema_version(v2, sizeof(v2) - 1, &version));
        ASSERT_EQ(version, CONSENSUS_STATE_BUNDLE_V2);
        ASSERT(!consensus_state_bundle_schema_version(v2, sizeof(v2), &version));
        ASSERT_EQ(version, CONSENSUS_STATE_BUNDLE_INVALID);
        version = 99;
        ASSERT(!consensus_state_bundle_schema_version(v2, sizeof(v2) - 2, &version));
        ASSERT_EQ(version, CONSENSUS_STATE_BUNDLE_INVALID);
        version = 99;
        ASSERT(!consensus_state_bundle_schema_version(v3, sizeof(v3) - 1, &version));
        ASSERT_EQ(version, CONSENSUS_STATE_BUNDLE_INVALID);
        version = 99;
        ASSERT(!consensus_state_bundle_schema_version(NULL, 0, &version));
        ASSERT_EQ(version, CONSENSUS_STATE_BUNDLE_INVALID);
        ASSERT(!consensus_state_bundle_schema_version(v1, sizeof(v1) - 1, NULL));
    } TEST_END
    return failures;
}

int test_consensus_state_bundle_codec(void)
{
    return codec_v1() + codec_v2() + codec_refusals() + codec_schema();
}
