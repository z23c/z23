/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Strong-id wrapper types (core/zcl_ids.h). Step-0 contract test: proves the
 * 32-byte wrappers are layout-identical to a bare uint8_t[32] (so wire memcpy
 * stays valid) and the eq/copy helpers behave. WF1 lane 1B extends this with
 * the adoption proofs in flyclient.h / snapshot_manifest.h: the new
 * accessors read the SAME bytes a raw memcpy would, and the wire-compat
 * _Static_assert guards in those headers are exercised by simply compiling
 * this file (any layout drift breaks the build, not just this test). */

#include "test/test_core.h"
#include "core/zcl_ids.h"
#include "net/flyclient.h"
#include "services/snapshot_manifest.h"
#include <string.h>

static int test_zcl_ids_sizes(void)
{
    int failures = 0;
    TEST("zcl_ids: 32-byte wrappers are exactly 32 bytes (wire-compatible)") {
        ASSERT(sizeof(struct zcl_block_hash) == 32);
        ASSERT(sizeof(struct zcl_sha3_digest) == 32);
        ASSERT(sizeof(struct zcl_utxo_root) == 32);
        ASSERT(sizeof(struct zcl_mmb_root) == 32);
        ASSERT(sizeof(struct zcl_chunk_root) == 32);
        ASSERT(sizeof(struct zcl_artifact_id) == 32);
        ASSERT(sizeof(struct zcl_chainwork_be256) == 32);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zcl_ids_scalar_sizes(void)
{
    int failures = 0;
    TEST("zcl_ids: scalar wrappers wrap their exact scalar") {
        ASSERT(sizeof(struct zcl_height) == sizeof(int32_t));
        ASSERT(sizeof(struct zcl_byte_count) == sizeof(uint64_t));
        ASSERT(sizeof(struct zcl_chunk_index) == sizeof(uint32_t));
        ASSERT(sizeof(struct zcl_peer_id) == sizeof(uint64_t));
        PASS();
    } _test_next:;
    return failures;
}

static int test_zcl_ids_hash_helpers(void)
{
    int failures = 0;
    TEST("zcl_ids: hash eq/copy round-trip and stay memcpy-compatible") {
        struct zcl_chunk_root a, b;
        for (int i = 0; i < 32; i++) a.bytes[i] = (uint8_t)(i * 7 + 1);
        zcl_chunk_root_copy(&b, &a);
        ASSERT(zcl_chunk_root_eq(&a, &b));
        b.bytes[13] ^= 0xFF;
        ASSERT(!zcl_chunk_root_eq(&a, &b));

        /* Wire boundary: a bare 32-byte memcpy into .bytes still works. */
        uint8_t wire[32];
        memset(wire, 0xAB, sizeof(wire));
        struct zcl_utxo_root r;
        memcpy(r.bytes, wire, 32);
        ASSERT(memcmp(r.bytes, wire, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zcl_ids_scalar_helpers(void)
{
    int failures = 0;
    TEST("zcl_ids: scalar eq/copy behave") {
        struct zcl_height h = { .value = -1 }, h2;
        zcl_height_copy(&h2, h);
        ASSERT(zcl_height_eq(h, h2));
        struct zcl_chunk_index i1 = { .value = 42 }, i2 = { .value = 43 };
        ASSERT(!zcl_chunk_index_eq(i1, i2));
        PASS();
    } _test_next:;
    return failures;
}

static int test_zcl_ids_flyclient_adoption(void)
{
    int failures = 0;
    TEST("zcl_ids: fc_challenge_mmb_root_id reads the same bytes as a raw memcpy") {
        struct fc_challenge c;
        memset(&c, 0, sizeof(c));
        for (int i = 0; i < 32; i++) c.mmb_root[i] = (uint8_t)(i * 3 + 5);

        struct zcl_mmb_root via_accessor = fc_challenge_mmb_root_id(&c);
        struct zcl_mmb_root via_memcpy;
        memcpy(via_memcpy.bytes, c.mmb_root, 32);
        ASSERT(zcl_mmb_root_eq(&via_accessor, &via_memcpy));

        /* The accessor returns a by-value copy, not a live view: mutating
         * the source struct afterward must not retroactively change it. */
        c.mmb_root[0] ^= 0xFF;
        ASSERT(zcl_mmb_root_eq(&via_accessor, &via_memcpy));
        struct zcl_mmb_root via_memcpy_after;
        memcpy(via_memcpy_after.bytes, c.mmb_root, 32);
        ASSERT(!zcl_mmb_root_eq(&via_accessor, &via_memcpy_after));
        PASS();
    } _test_next:;
    return failures;
}

static int test_zcl_ids_snapshot_manifest_adoption(void)
{
    int failures = 0;
    TEST("zcl_ids: snapshot_manifest_*_id accessors match the raw fields") {
        struct snapshot_manifest m;
        memset(&m, 0, sizeof(m));
        m.height = 123456;
        m.total_bytes = 9876543210ULL;
        for (int i = 0; i < 32; i++) {
            m.block_hash[i] = (uint8_t)(i + 1);
            m.utxo_root[i]  = (uint8_t)(i + 2);
            m.mmb_root[i]   = (uint8_t)(i + 3);
            m.chain_work[i] = (uint8_t)(i + 4);
        }

        ASSERT(snapshot_manifest_height_id(&m).value == m.height);
        ASSERT(snapshot_manifest_total_bytes_id(&m).value == m.total_bytes);

        struct zcl_block_hash bh = snapshot_manifest_block_hash_id(&m);
        ASSERT(memcmp(bh.bytes, m.block_hash, 32) == 0);

        struct zcl_utxo_root ur = snapshot_manifest_utxo_root_id(&m);
        ASSERT(memcmp(ur.bytes, m.utxo_root, 32) == 0);

        struct zcl_mmb_root mr = snapshot_manifest_mmb_root_id(&m);
        ASSERT(memcmp(mr.bytes, m.mmb_root, 32) == 0);

        struct zcl_chainwork_be256 cw = snapshot_manifest_chain_work_id(&m);
        ASSERT(memcmp(cw.bytes, m.chain_work, 32) == 0);

        /* Cross-field sanity: a block_hash and utxo_root built from
         * different byte patterns must not compare equal. */
        struct zcl_block_hash bh2;
        memcpy(bh2.bytes, m.utxo_root, 32);
        ASSERT(!zcl_block_hash_eq(&bh, &bh2));
        PASS();
    } _test_next:;
    return failures;
}

int test_zcl_ids(void)
{
    int failures = 0;
    failures += test_zcl_ids_sizes();
    failures += test_zcl_ids_scalar_sizes();
    failures += test_zcl_ids_hash_helpers();
    failures += test_zcl_ids_scalar_helpers();
    failures += test_zcl_ids_flyclient_adoption();
    failures += test_zcl_ids_snapshot_manifest_adoption();
    return failures;
}
