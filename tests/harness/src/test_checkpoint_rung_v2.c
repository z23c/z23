/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "test/test_core.h"
#include "storage/checkpoint_rung.h"
#include "storage/checkpoint_ladder.h"
#include "crypto/sha3.h"
#include <string.h>

static const uint8_t root_v1[32] = {
    0x2d,0x25,0xf1,0x1c,0xa7,0xb5,0x96,0x4f,0xc0,0xab,0x1f,0x48,0xbf,0x41,0x09,0xe0,
    0x90,0x7c,0x7d,0x16,0x0f,0x4c,0x01,0x1d,0x28,0x48,0xe3,0x93,0x34,0x4f,0x63,0x07
};
static const uint8_t root_v2[32] = {
    0x6a,0x32,0xf4,0xec,0xff,0xa7,0x0b,0xe7,0x5c,0x76,0xdd,0xf2,0x45,0x52,0x57,0x95,
    0xb8,0x03,0x55,0xf7,0xc7,0xa7,0x4f,0x85,0xbd,0x2b,0xa7,0xcf,0xf1,0x35,0x0e,0xd3
};
static const uint8_t wire_v1[32] = {
    0x7f,0x60,0x27,0xcb,0xc0,0xdf,0xa7,0xe1,0x10,0x55,0x28,0xee,0xf9,0xd6,0xf5,0x91,
    0x1b,0x3e,0x5e,0x79,0x6a,0x53,0x53,0x48,0xfc,0x33,0x07,0xfa,0x71,0xbc,0x23,0x05
};
static const uint8_t wire_v2[32] = {
    0x30,0x85,0xd9,0x52,0x22,0x7a,0xde,0x67,0x73,0x2d,0xd7,0xda,0x70,0x49,0x69,0xf5,
    0x9b,0x29,0x59,0x7c,0x8d,0x0e,0x93,0xd3,0x6c,0x93,0x57,0x7b,0x6c,0x2c,0xc4,0xa4
};

static void wire_hash(const uint8_t *p, size_t n, uint8_t out[32])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, p, n);
    sha3_256_finalize(&c, out);
}

static bool matching_header(void *ctx, int32_t height, uint8_t hash[32])
{
    *(bool *)ctx = true;
    (void)height;
    memset(hash, 0, 32);
    return true;
}

static int rung_wire_goldens(void)
{
    int failures = 0;
    TEST_CASE("rung v1 and v2 independently generated wire and root goldens") {
        struct checkpoint_rung r = { .format_version = CHECKPOINT_RUNG_VERSION_V1 };
        uint8_t wire[CHECKPOINT_RUNG_V2_WIRE_SIZE], digest[32];
        size_t n = 0;
        ASSERT(checkpoint_rung_serialize_sized(&r, wire, sizeof wire, &n));
        ASSERT_EQ(n, CHECKPOINT_RUNG_WIRE_SIZE);
        ASSERT(memcmp(r.rom_state_root, root_v1, 32) == 0);
        wire_hash(wire, n, digest);
        ASSERT(memcmp(digest, wire_v1, 32) == 0);
        r.format_version = CHECKPOINT_RUNG_VERSION_V2;
        r.sprout_pool_total = 1; r.sapling_pool_total = 2;
        ASSERT(checkpoint_rung_serialize_sized(&r, wire, sizeof wire, &n));
        ASSERT_EQ(n, CHECKPOINT_RUNG_V2_WIRE_SIZE);
        ASSERT(memcmp(r.rom_state_root, root_v2, 32) == 0);
        wire_hash(wire, n, digest);
        ASSERT(memcmp(digest, wire_v2, 32) == 0);
        struct checkpoint_rung parsed;
        ASSERT(checkpoint_rung_parse(wire, n, &parsed));
        ASSERT_EQ(parsed.sprout_pool_total, 1);
        ASSERT_EQ(parsed.sapling_pool_total, 2);
        wire[260] ^= 1;
        ASSERT(!checkpoint_rung_parse(wire, n, &parsed));
        wire[260] ^= 1; wire[268] ^= 1;
        ASSERT(!checkpoint_rung_parse(wire, n, &parsed));
        wire[268] ^= 1; wire[12] = 1;
        ASSERT(!checkpoint_rung_parse(wire, n, &parsed));
        wire[12] = 0; wire[CHECKPOINT_RUNG_V2_WIRE_SIZE - 1] = 1;
        ASSERT(!checkpoint_rung_parse(wire, n, &parsed));
        wire[CHECKPOINT_RUNG_V2_WIRE_SIZE - 1] = 0; wire[8] = 3;
        ASSERT(!checkpoint_rung_parse(wire, n, &parsed));
        ASSERT(!checkpoint_rung_serialize_sized(&r, wire, sizeof wire - 1, &n));
        ASSERT_EQ(n, 0);
        ASSERT(!checkpoint_rung_serialize(&r, wire));
        r.sprout_pool_total = -1;
        ASSERT(!checkpoint_rung_serialize_sized(&r, wire, sizeof wire, &n));
        r.sprout_pool_total = 1; r.sapling_pool_total = -1;
        ASSERT(!checkpoint_rung_serialize_sized(&r, wire, sizeof wire, &n));
        r.sapling_pool_total = 2; r.format_version = 0;
        ASSERT(!checkpoint_rung_serialize_sized(&r, wire, sizeof wire, &n));
    } TEST_END
    return failures;
}

static int rung_v2_header(void)
{
    int failures = 0;
    TEST_CASE("v2 header match cannot authenticate recomputed pool totals") {
        struct checkpoint_rung r = { .height = 42,
            .format_version = CHECKPOINT_RUNG_VERSION_V2,
            .sprout_pool_total = 1, .sapling_pool_total = 2 };
        bool called = false;
        struct checkpoint_ladder_hooks hooks = { .ctx = &called, .block_hash_at = matching_header };
        struct checkpoint_ladder_result result;
        bool mismatch = false;
        checkpoint_rung_finalize(&r);
        r.sprout_pool_total++;
        checkpoint_rung_finalize(&r);
        ASSERT_EQ(checkpoint_ladder_verify(&r, 1, &hooks, &result, 1, &mismatch), 1);
        ASSERT(called);
        ASSERT_EQ(result.verdict, CHECKPOINT_RUNG_UNVERIFIABLE);
        ASSERT(!result.bound);
        ASSERT(result.candidate_unbaked);
        ASSERT(!mismatch);
    } TEST_END
    return failures;
}

int test_checkpoint_rung_v2(void)
{
    return rung_wire_goldens() + rung_v2_header();
}
