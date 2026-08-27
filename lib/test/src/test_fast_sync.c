/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for fast sync protocol: UTXO snapshots, swarm sync,
 * block swarm, Merkle proofs, integrity verification,
 * and bandwidth-adaptive download manager. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "net/fast_sync.h"
#include "net/download.h"
#include "coins/utxo_commitment.h"
#include "crypto/sha3.h"
#include "validation/chainstate.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "util/safe_alloc.h"

static uint8_t *test_snapshot_one_entry(size_t *size_out,
                                        const char *tag,
                                        uint8_t script_byte)
{
    const size_t size = 4 + 32 + 4 + 8 + 4 + 1 + 1 + 1;
    uint8_t *buf = zcl_malloc(size, tag);
    if (!buf) return NULL;

    size_t pos = 0;
    buf[pos++] = 1; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0;
    memset(buf + pos, 0x42, 32); pos += 32;
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0;
    uint64_t value = 5000;
    for (int i = 0; i < 8; i++)
        buf[pos++] = (uint8_t)(value >> (8 * i));
    uint32_t height = 100;
    for (int i = 0; i < 4; i++)
        buf[pos++] = (uint8_t)(height >> (8 * i));
    buf[pos++] = 1; /* is_coinbase */
    buf[pos++] = 1; /* compact script length */
    buf[pos++] = script_byte;

    if (size_out) *size_out = size;
    return buf;
}

static uint8_t *test_snapshot_entries(size_t *size_out,
                                      const char *tag,
                                      uint32_t entries)
{
    if (entries == 0 || entries > SYNC_CHUNK_SIZE)
        return NULL;
    const size_t entry_size = 32 + 4 + 8 + 4 + 1 + 1 + 1;
    const size_t size = 4 + (size_t)entries * entry_size;
    uint8_t *buf = zcl_malloc(size, tag);
    if (!buf) return NULL;

    size_t pos = 0;
    buf[pos++] = (uint8_t)entries;
    buf[pos++] = (uint8_t)(entries >> 8);
    buf[pos++] = (uint8_t)(entries >> 16);
    buf[pos++] = (uint8_t)(entries >> 24);

    for (uint32_t e = 0; e < entries; e++) {
        memset(buf + pos, (int)(0x40 + (e & 0x3F)), 32);
        pos += 32;
        for (int i = 0; i < 4; i++)
            buf[pos++] = (uint8_t)(e >> (8 * i));
        uint64_t value = 5000 + e;
        for (int i = 0; i < 8; i++)
            buf[pos++] = (uint8_t)(value >> (8 * i));
        uint32_t height = 100 + e;
        for (int i = 0; i < 4; i++)
            buf[pos++] = (uint8_t)(height >> (8 * i));
        buf[pos++] = (uint8_t)(e == 0);
        buf[pos++] = 1;
        buf[pos++] = (uint8_t)(0x51 + (e & 0x0F));
    }

    if (size_out) *size_out = size;
    return buf;
}

/* ── Merkle tree tests ─────────────────────────────────────── */

static int test_merkle_root_single(void)
{
    int failures = 0;
    TEST("fast_sync_merkle_root single hash") {
        uint8_t hash[32];
        memset(hash, 0xAA, 32);
        uint8_t root[32];
        fast_sync_merkle_root((const uint8_t (*)[32])&hash, 1, root);
        ASSERT(memcmp(root, hash, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_merkle_root_empty(void)
{
    int failures = 0;
    TEST("fast_sync_merkle_root empty") {
        uint8_t root[32];
        fast_sync_merkle_root(NULL, 0, root);
        uint8_t zero[32] = {0};
        ASSERT(memcmp(root, zero, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_merkle_root_deterministic(void)
{
    int failures = 0;
    TEST("fast_sync_merkle_root deterministic") {
        uint8_t hashes[4][32];
        for (int i = 0; i < 4; i++)
            memset(hashes[i], (uint8_t)(i + 1), 32);
        uint8_t root1[32], root2[32];
        fast_sync_merkle_root((const uint8_t (*)[32])hashes, 4, root1);
        fast_sync_merkle_root((const uint8_t (*)[32])hashes, 4, root2);
        ASSERT(memcmp(root1, root2, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_merkle_root_order_sensitive(void)
{
    int failures = 0;
    TEST("fast_sync_merkle_root order sensitive") {
        uint8_t hashes_ab[2][32], hashes_ba[2][32];
        memset(hashes_ab[0], 0xAA, 32);
        memset(hashes_ab[1], 0xBB, 32);
        memset(hashes_ba[0], 0xBB, 32);
        memset(hashes_ba[1], 0xAA, 32);
        uint8_t root_ab[32], root_ba[32];
        fast_sync_merkle_root((const uint8_t (*)[32])hashes_ab, 2, root_ab);
        fast_sync_merkle_root((const uint8_t (*)[32])hashes_ba, 2, root_ba);
        ASSERT(memcmp(root_ab, root_ba, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_merkle_root_power_of_two_padding(void)
{
    int failures = 0;
    TEST("fast_sync_merkle_root pads non-power-of-2 correctly") {
        /* 3 leaves should produce same root as 4 leaves where leaf[3]=leaf[2] */
        uint8_t hashes3[3][32], hashes4[4][32];
        for (int i = 0; i < 3; i++) {
            memset(hashes3[i], (uint8_t)(i + 0x10), 32);
            memset(hashes4[i], (uint8_t)(i + 0x10), 32);
        }
        memcpy(hashes4[3], hashes4[2], 32); /* pad with last */
        uint8_t root3[32], root4[32];
        fast_sync_merkle_root((const uint8_t (*)[32])hashes3, 3, root3);
        fast_sync_merkle_root((const uint8_t (*)[32])hashes4, 4, root4);
        ASSERT(memcmp(root3, root4, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Merkle proof tests ───────────────────────────────────── */

static int test_merkle_proof_verify(void)
{
    int failures = 0;
    TEST("fast_sync_build_proof + verify roundtrip") {
        uint8_t hashes[8][32];
        for (int i = 0; i < 8; i++)
            memset(hashes[i], (uint8_t)(i + 0x20), 32);
        uint8_t root[32];
        fast_sync_merkle_root((const uint8_t (*)[32])hashes, 8, root);

        /* Build and verify proof for each leaf */
        for (uint32_t i = 0; i < 8; i++) {
            uint8_t (*proof)[32] = NULL;
            uint32_t plen = fast_sync_build_proof(
                (const uint8_t (*)[32])hashes, 8, i, &proof);
            ASSERT(plen == 3); /* log2(8) = 3 */
            bool ok = fast_sync_verify_chunk_proof(
                i, hashes[i], (const uint8_t (*)[32])proof, plen, root);
            ASSERT(ok);
            free(proof);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_merkle_proof_invalid(void)
{
    int failures = 0;
    TEST("fast_sync_verify_chunk_proof rejects wrong hash") {
        uint8_t hashes[4][32];
        for (int i = 0; i < 4; i++)
            memset(hashes[i], (uint8_t)(i + 0x30), 32);
        uint8_t root[32];
        fast_sync_merkle_root((const uint8_t (*)[32])hashes, 4, root);

        uint8_t (*proof)[32] = NULL;
        uint32_t plen = fast_sync_build_proof(
            (const uint8_t (*)[32])hashes, 4, 0, &proof);

        /* Tamper with the chunk hash */
        uint8_t fake[32];
        memset(fake, 0xFF, 32);
        bool ok = fast_sync_verify_chunk_proof(
            0, fake, (const uint8_t (*)[32])proof, plen, root);
        ASSERT(!ok);
        free(proof);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Chunk hash tests ─────────────────────────────────────── */

static int test_chunk_hash_deterministic(void)
{
    int failures = 0;
    TEST("fast_sync_chunk_hash deterministic") {
        struct utxo_chunk *chunk = zcl_calloc(1, sizeof(struct utxo_chunk), "test_chunk");
        ASSERT(chunk != NULL);
        chunk->chunk_index = 0;
        chunk->num_entries = 2;
        memset(chunk->entries[0].txid, 0x11, 32);
        chunk->entries[0].vout = 0;
        chunk->entries[0].value = 100000;
        chunk->entries[0].height = 1000;
        memset(chunk->entries[1].txid, 0x22, 32);
        chunk->entries[1].vout = 1;
        chunk->entries[1].value = 200000;
        chunk->entries[1].height = 2000;

        uint8_t h1[32], h2[32];
        fast_sync_chunk_hash(chunk, h1);
        fast_sync_chunk_hash(chunk, h2);
        ASSERT(memcmp(h1, h2, 32) == 0);

        /* Different chunk index produces different hash */
        chunk->chunk_index = 1;
        uint8_t h3[32];
        fast_sync_chunk_hash(chunk, h3);
        ASSERT(memcmp(h1, h3, 32) != 0);

        free(chunk);
        PASS();
    } _test_next:;
    return failures;
}

static int test_chunk_verify(void)
{
    int failures = 0;
    TEST("fast_sync_verify_chunk correct/incorrect") {
        struct utxo_chunk *chunk = zcl_calloc(1, sizeof(struct utxo_chunk), "test_chunk");
        ASSERT(chunk != NULL);
        chunk->chunk_index = 5;
        chunk->num_entries = 1;
        memset(chunk->entries[0].txid, 0xCC, 32);
        chunk->entries[0].vout = 0;
        chunk->entries[0].value = 50000;
        chunk->entries[0].height = 500;

        uint8_t expected[32];
        fast_sync_chunk_hash(chunk, expected);

        ASSERT(fast_sync_verify_chunk(chunk, expected));

        /* Tamper */
        chunk->entries[0].value = 99999;
        ASSERT(!fast_sync_verify_chunk(chunk, expected));

        free(chunk);
        PASS();
    } _test_next:;
    return failures;
}

/* ── PoW defense tests ───────────────────────────────────── */

static int test_pow_solve_verify(void)
{
    int failures = 0;
    TEST("fast_sync PoW solve and verify") {
        uint8_t peer_id[32];
        memset(peer_id, 0x42, 32);
        struct fast_sync_pow pow;
        bool solved = fast_sync_solve_pow(peer_id, &pow);
        ASSERT(solved);
        ASSERT(fast_sync_verify_pow(&pow));

        /* Tamper with nonce */
        pow.nonce += 1;
        ASSERT(!fast_sync_verify_pow(&pow));
        PASS();
    } _test_next:;
    return failures;
}

static int test_pow_timestamp_range(void)
{
    int failures = 0;
    TEST("fast_sync PoW rejects stale timestamp") {
        uint8_t peer_id[32];
        memset(peer_id, 0x43, 32);
        struct fast_sync_pow pow;
        fast_sync_solve_pow(peer_id, &pow);
        /* Set timestamp to 10 minutes ago */
        pow.timestamp -= 600;
        ASSERT(!fast_sync_verify_pow(&pow));
        PASS();
    } _test_next:;
    return failures;
}

/* ── Rate limiter tests ──────────────────────────────────── */

static int test_rate_limiter(void)
{
    int failures = 0;
    TEST("fast_sync rate limiter tracks per-IP") {
        struct fast_sync_rate_limiter rl;
        memset(&rl, 0, sizeof(rl));

        uint8_t ip1[16] = {0};
        ip1[0] = 1;
        uint8_t ip2[16] = {0};
        ip2[0] = 2;

        /* First request OK */
        ASSERT(fast_sync_rate_check(&rl, ip1));
        ASSERT(fast_sync_rate_check(&rl, ip2));
        ASSERT(rl.num_entries == 2);

        /* Exhaust ip1's rate limit */
        for (int i = 1; i < FAST_SYNC_MAX_CHUNKS_PER_HOUR; i++)
            ASSERT(fast_sync_rate_check(&rl, ip1));

        /* Next request should fail for ip1 */
        ASSERT(!fast_sync_rate_check(&rl, ip1));

        /* ip2 still has budget */
        ASSERT(fast_sync_rate_check(&rl, ip2));
        PASS();
    } _test_next:;
    return failures;
}

static int test_rate_limiter_n(void)
{
    int failures = 0;
    TEST("fast_sync_rate_check_n honors caller-supplied caps") {
        struct fast_sync_rate_limiter rl;
        memset(&rl, 0, sizeof(rl));

        uint8_t ip1[16] = {0};
        ip1[0] = 1;
        uint8_t ip2[16] = {0};
        ip2[0] = 2;

        /* Block-piece-scale cap: ip1 gets exactly 3 */
        ASSERT(fast_sync_rate_check_n(&rl, ip1, 3, 1000));
        ASSERT(fast_sync_rate_check_n(&rl, ip1, 3, 1000));
        ASSERT(fast_sync_rate_check_n(&rl, ip1, 3, 1000));
        ASSERT(!fast_sync_rate_check_n(&rl, ip1, 3, 1000));

        /* A different cap applies per call site, not per limiter */
        ASSERT(fast_sync_rate_check_n(&rl, ip1, 4, 1000));

        /* Global cap: 1000 - 5 spent leaves room, but a tiny global
         * cap refuses even a fresh IP */
        struct fast_sync_rate_limiter rl2;
        memset(&rl2, 0, sizeof(rl2));
        ASSERT(fast_sync_rate_check_n(&rl2, ip1, 100, 2));
        ASSERT(fast_sync_rate_check_n(&rl2, ip2, 100, 2));
        uint8_t ip3[16] = {0};
        ip3[0] = 3;
        ASSERT(!fast_sync_rate_check_n(&rl2, ip3, 100, 2));
        PASS();
    } _test_next:;
    return failures;
}

static int test_snapshot_cache_publish_reset(void)
{
    int failures = 0;
    TEST("fast_sync snapshot cache publish/get/reset") {
        size_t buf_size = 0;
        uint8_t *buf = test_snapshot_entries(&buf_size,
                                             "test_snapshot_buf",
                                             SYNC_CHUNK_SIZE);
        uint8_t sha3[32];
        uint8_t out[32];
        uint64_t count = 0;
        int64_t size = -1;
        const uint8_t *cached = NULL;

        ASSERT(buf != NULL);
        memset(sha3, 0x5a, sizeof(sha3));

        fast_sync_reset_snapshot_cache();

        ASSERT(fast_sync_publish_snapshot_cache(buf, (int64_t)buf_size,
                                                sha3, SYNC_CHUNK_SIZE));
        cached = fast_sync_get_snapshot_buf(&size);
        ASSERT(cached != NULL);
        ASSERT(size == (int64_t)buf_size);
        ASSERT(cached[0] == (uint8_t)SYNC_CHUNK_SIZE);
        ASSERT(fast_sync_get_snapshot_sha3(out, &count));
        ASSERT(count == SYNC_CHUNK_SIZE);
        ASSERT(memcmp(out, sha3, 32) == 0);

        fast_sync_reset_snapshot_cache();
        ASSERT(!fast_sync_get_snapshot_sha3(out, &count));
        ASSERT(fast_sync_get_snapshot_buf(&size) == NULL);
        ASSERT(size == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_snapshot_cache_versioning(void)
{
    int failures = 0;
    TEST("fast_sync snapshot cache versioning") {
        uint8_t sha1[32], sha2[32];
        memset(sha1, 0x5a, sizeof(sha1));
        memset(sha2, 0x5b, sizeof(sha2));

        size_t buf1_size = 0, buf2_size = 0;
        uint8_t *buf1 = test_snapshot_one_entry(&buf1_size,
                                                "test_snapshot_buf", 0x51);
        uint8_t *buf2 = test_snapshot_one_entry(&buf2_size,
                                                "test_snapshot_buf", 0x52);
        uint8_t *invalid = zcl_malloc(1, "test_snapshot_buf");
        ASSERT(buf1 != NULL);
        ASSERT(buf2 != NULL);
        ASSERT(invalid != NULL);

        fast_sync_reset_snapshot_cache();
        uint64_t v0 = fast_sync_snapshot_cache_version();
        ASSERT(fast_sync_publish_snapshot_cache(buf1, (int64_t)buf1_size,
                                                sha1, 1));
        uint64_t v1 = fast_sync_snapshot_cache_version();
        ASSERT(v1 > v0);

        ASSERT(fast_sync_publish_snapshot_cache(buf2, (int64_t)buf2_size,
                                                sha2, 1));
        uint64_t v2 = fast_sync_snapshot_cache_version();
        ASSERT(v2 > v1);

        /* Invalid republish does not advance version, only successful paths do. */
        ASSERT(!fast_sync_publish_snapshot_cache(invalid, 0, sha2, 125));
        free(invalid);
        ASSERT(fast_sync_snapshot_cache_version() == v2);

        fast_sync_reset_snapshot_cache();
        uint64_t v3 = fast_sync_snapshot_cache_version();
        ASSERT(v3 > v2);
        PASS();
    } _test_next:;
    return failures;
}

static int test_utxo_root_cache_publish_reset(void)
{
    int failures = 0;
    TEST("fast_sync utxo root cache publish/get/reset") {
        uint8_t root[32];
        uint8_t out[32];
        uint64_t count = 0;

        memset(root, 0x7c, sizeof(root));
        memset(out, 0, sizeof(out));

        fast_sync_reset_utxo_root_cache();
        ASSERT(!fast_sync_get_utxo_root_cache(out, &count));
        ASSERT(count == 0);

        ASSERT(!fast_sync_publish_utxo_root_cache(NULL, 7));
        ASSERT(!fast_sync_publish_utxo_root_cache(root, 0));
        ASSERT(fast_sync_publish_utxo_root_cache(root, 7));
        ASSERT(fast_sync_get_utxo_root_cache(out, &count));
        ASSERT(count == 7);
        ASSERT(memcmp(out, root, sizeof(root)) == 0);

        fast_sync_reset_utxo_root_cache();
        memset(out, 0, sizeof(out));
        ASSERT(!fast_sync_get_utxo_root_cache(out, &count));
        ASSERT(count == 7);
        PASS();
    } _test_next:;
    return failures;
}

static int test_utxo_root_cache_versioning(void)
{
    int failures = 0;
    TEST("fast_sync utxo root cache versioning") {
        uint8_t root1[32], root2[32];
        uint64_t v0;
        uint64_t v1;
        uint64_t v2;
        uint64_t v3;
        memset(root1, 0x7c, sizeof(root1));
        memset(root2, 0x7d, sizeof(root2));

        fast_sync_reset_utxo_root_cache();
        v0 = fast_sync_utxo_root_cache_version();

        ASSERT(fast_sync_publish_utxo_root_cache(root1, 7));
        v1 = fast_sync_utxo_root_cache_version();
        ASSERT(v1 > v0);

        ASSERT(fast_sync_publish_utxo_root_cache(root2, 8));
        v2 = fast_sync_utxo_root_cache_version();
        ASSERT(v2 > v1);

        /* Invalid publish does not bump version. */
        ASSERT(!fast_sync_publish_utxo_root_cache(NULL, 9));
        ASSERT(fast_sync_utxo_root_cache_version() == v2);

        fast_sync_reset_utxo_root_cache();
        v3 = fast_sync_utxo_root_cache_version();
        ASSERT(v3 > v2);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Swarm sync coordinator tests ────────────────────────── */

static int test_swarm_init_assign(void)
{
    int failures = 0;
    TEST("swarm_sync init + assign chunks") {
        struct sync_manifest manifest;
        memset(&manifest, 0, sizeof(manifest));
        manifest.num_chunks = 10;
        manifest.chunk_size = 500;
        manifest.chunk_hashes = zcl_calloc(10, 32, "test_chunk_hashes");
        ASSERT(manifest.chunk_hashes != NULL);

        struct swarm_sync ss;
        ASSERT(swarm_sync_init(&ss, &manifest, NULL));
        ASSERT(swarm_sync_progress(&ss) == 0);
        ASSERT(!swarm_sync_is_complete(&ss));

        /* Assign chunks to peers */
        int32_t c1 = swarm_sync_assign_chunk(&ss, 1);
        int32_t c2 = swarm_sync_assign_chunk(&ss, 2);
        int32_t c3 = swarm_sync_assign_chunk(&ss, 1);
        ASSERT(c1 == 0);
        ASSERT(c2 == 1);
        ASSERT(c3 == 2);
        ASSERT(ss.chunks_inflight == 3);

        swarm_sync_free(&ss);
        free(manifest.chunk_hashes);
        PASS();
    } _test_next:;
    return failures;
}

static int test_swarm_timeout_reassign(void)
{
    int failures = 0;
    TEST("swarm_sync timeout reassigns chunks") {
        struct sync_manifest manifest;
        memset(&manifest, 0, sizeof(manifest));
        manifest.num_chunks = 5;
        manifest.chunk_size = 500;
        manifest.chunk_hashes = zcl_calloc(5, 32, "test_chunk_hashes");
        ASSERT(manifest.chunk_hashes != NULL);

        struct swarm_sync ss;
        swarm_sync_init(&ss, &manifest, NULL);

        /* Assign all 5 chunks */
        for (int i = 0; i < 5; i++)
            swarm_sync_assign_chunk(&ss, 1);
        ASSERT(ss.chunks_inflight == 5);

        /* No chunks available now */
        ASSERT(swarm_sync_assign_chunk(&ss, 2) == -1);

        /* Simulate timeout: set request times to the past */
        for (uint32_t i = 0; i < 5; i++)
            ss.chunk_request_time[i] -= 60; /* 60s ago */
        swarm_sync_handle_timeouts(&ss, 30); /* 30s timeout */
        ASSERT(ss.chunks_inflight == 0);

        /* Chunks should be available again */
        int32_t c = swarm_sync_assign_chunk(&ss, 2);
        ASSERT(c >= 0);

        swarm_sync_free(&ss);
        free(manifest.chunk_hashes);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Block swarm tests ───────────────────────────────────── */

static int test_block_swarm_rarest_first(void)
{
    int failures = 0;
    TEST("block_swarm rarest-first piece selection") {
        struct block_piece_manifest manifest;
        memset(&manifest, 0, sizeof(manifest));
        manifest.start_height = 0;
        manifest.end_height = 511; /* 4 pieces of 128 blocks */
        manifest.num_pieces = 4;
        manifest.piece_hashes = zcl_calloc(4, 32, "test_piece_hashes");
        ASSERT(manifest.piece_hashes != NULL);

        struct block_swarm bs;
        ASSERT(block_swarm_init(&bs, &manifest, NULL));

        /* Set availability: piece 0=10, 1=2, 2=5, 3=1 (rarest) */
        bs.piece_availability[0] = 10;
        bs.piece_availability[1] = 2;
        bs.piece_availability[2] = 5;
        bs.piece_availability[3] = 1;

        /* First assignment should pick piece 3 (rarest) */
        int32_t p = block_swarm_assign_piece(&bs, 1, NULL, 0);
        ASSERT(p == 3);

        /* Next should pick piece 1 (next rarest) */
        p = block_swarm_assign_piece(&bs, 2, NULL, 0);
        ASSERT(p == 1);

        block_swarm_free(&bs);
        free(manifest.piece_hashes);
        PASS();
    } _test_next:;
    return failures;
}

static int test_block_swarm_endgame(void)
{
    int failures = 0;
    TEST("block_swarm endgame mode activates") {
        struct block_piece_manifest manifest;
        memset(&manifest, 0, sizeof(manifest));
        manifest.start_height = 0;
        manifest.end_height = 1279; /* 10 pieces */
        manifest.num_pieces = 10;
        manifest.piece_hashes = zcl_calloc(10, 32, "test_piece_hashes");
        ASSERT(manifest.piece_hashes != NULL);

        struct block_swarm bs;
        block_swarm_init(&bs, &manifest, NULL);

        /* Complete 3 pieces, leaving 7 remaining > ENDGAME_THRESHOLD */
        for (uint32_t i = 0; i < 3; i++)
            block_swarm_receive_piece(&bs, i, 1);
        ASSERT(!bs.endgame);

        /* Complete more, leaving exactly ENDGAME_THRESHOLD-1 */
        for (uint32_t i = 3; i < 10 - ENDGAME_THRESHOLD + 1; i++)
            block_swarm_receive_piece(&bs, i, 1);

        /* Next assignment should trigger endgame */
        block_swarm_assign_piece(&bs, 1, NULL, 0);
        ASSERT(bs.endgame);

        block_swarm_free(&bs);
        free(manifest.piece_hashes);
        PASS();
    } _test_next:;
    return failures;
}

static int test_block_swarm_bitmap(void)
{
    int failures = 0;
    TEST("block_swarm bitmap serialize/update") {
        struct block_piece_manifest manifest;
        memset(&manifest, 0, sizeof(manifest));
        manifest.num_pieces = 16;
        manifest.piece_hashes = zcl_calloc(16, 32, "test_piece_hashes");
        ASSERT(manifest.piece_hashes != NULL);

        struct block_swarm bs;
        block_swarm_init(&bs, &manifest, NULL);

        /* Complete pieces 0, 3, 7 */
        block_swarm_receive_piece(&bs, 0, 1);
        block_swarm_receive_piece(&bs, 3, 1);
        block_swarm_receive_piece(&bs, 7, 1);

        /* Serialize bitmap */
        uint8_t bitmap[2];
        uint32_t blen = block_swarm_serialize_bitmap(&bs, bitmap, 2);
        ASSERT(blen == 2);
        /* Bit 0, 3, 7 should be set */
        ASSERT(bitmap[0] & (1 << 0));
        ASSERT(bitmap[0] & (1 << 3));
        ASSERT(bitmap[0] & (1 << 7));
        ASSERT(!(bitmap[0] & (1 << 1)));

        /* Update availability from a peer's bitmap */
        uint8_t peer_bitmap[2] = {0xFF, 0x0F}; /* peer has all 16 pieces */
        block_swarm_update_availability(&bs, peer_bitmap, 2);
        for (uint32_t i = 0; i < 12; i++) /* 0xFF=8bits + 0x0F=4bits */
            ASSERT(bs.piece_availability[i] >= 1);

        block_swarm_free(&bs);
        free(manifest.piece_hashes);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Block piece hash tests ──────────────────────────────── */

static int test_block_piece_hash_deterministic(void)
{
    int failures = 0;
    TEST("block_piece_hash deterministic + index-sensitive") {
        uint8_t hashes[4][32];
        for (int i = 0; i < 4; i++)
            memset(hashes[i], (uint8_t)(i + 0x50), 32);

        uint8_t h1[32], h2[32], h3[32];
        block_piece_hash((const uint8_t (*)[32])hashes, 4, 0, h1);
        block_piece_hash((const uint8_t (*)[32])hashes, 4, 0, h2);
        ASSERT(memcmp(h1, h2, 32) == 0);

        /* Different piece index → different hash */
        block_piece_hash((const uint8_t (*)[32])hashes, 4, 1, h3);
        ASSERT(memcmp(h1, h3, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_block_piece_manifest_active_chain(void)
{
    int failures = 0;
    TEST("block manifest publishes trusted active data and fails closed on a gap") {
        struct active_chain chain;
        active_chain_init(&chain);

        struct block_index idx[4];
        struct uint256 hashes[4];
        memset(idx, 0, sizeof(idx));
        memset(hashes, 0, sizeof(hashes));

        for (int i = 0; i < 4; i++) {
            memset(hashes[i].data, (uint8_t)(0x70 + i), 32);
            block_index_init(&idx[i]);
            idx[i].phashBlock = &hashes[i];
            idx[i].nHeight = i;
            idx[i].nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
            idx[i].pprev = (i > 0) ? &idx[i - 1] : NULL;
        }

        ASSERT(active_chain_move_window_tip(&chain, &idx[3]));

        struct block_piece_manifest m;
        memset(&m, 0, sizeof(m));
        ASSERT(block_piece_manifest_build_active_chain(&chain, 1, 3, &m));
        ASSERT(m.start_height == 1);
        ASSERT(m.end_height == 3);
        ASSERT(m.num_pieces == 1);
        ASSERT(m.piece_hashes != NULL);
        ASSERT(memcmp(m.tip_hash, hashes[3].data, 32) == 0);

        uint8_t expected[1][32];
        uint8_t block_hashes[3][32];
        for (int i = 0; i < 3; i++)
            memcpy(block_hashes[i], hashes[i + 1].data, 32);
        block_piece_hash((const uint8_t (*)[32])block_hashes, 3, 0,
                         expected[0]);
        ASSERT(memcmp(m.piece_hashes[0], expected[0], 32) == 0);

        block_piece_manifest_free(&m);

        idx[2].nStatus &= ~BLOCK_HAVE_DATA;
        ASSERT(!block_piece_manifest_build_active_chain(&chain, 1, 3, &m));
        ASSERT(m.piece_hashes == NULL);
        active_chain_free(&chain);
        PASS();
    } _test_next:;
    return failures;
}

static int test_block_piece_manifest_active_chain_skips_leading_gap(void)
{
    int failures = 0;
    TEST("block_piece_manifest_build_active_chain skips leading missing data") {
        struct active_chain chain;
        active_chain_init(&chain);

        struct block_index idx[4];
        struct uint256 hashes[4];
        memset(idx, 0, sizeof(idx));
        memset(hashes, 0, sizeof(hashes));

        for (int i = 0; i < 4; i++) {
            memset(hashes[i].data, (uint8_t)(0x90 + i), 32);
            block_index_init(&idx[i]);
            idx[i].phashBlock = &hashes[i];
            idx[i].nHeight = i;
            idx[i].nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
            idx[i].pprev = (i > 0) ? &idx[i - 1] : NULL;
        }
        idx[1].nStatus &= ~BLOCK_HAVE_DATA;
        ASSERT(active_chain_move_window_tip(&chain, &idx[3]));

        struct block_piece_manifest m;
        memset(&m, 0, sizeof(m));
        ASSERT(block_piece_manifest_build_active_chain(&chain, 1, 3, &m));
        ASSERT(m.start_height == 2);
        ASSERT(m.end_height == 3);
        ASSERT(m.num_pieces == 1);
        ASSERT(memcmp(m.tip_hash, hashes[3].data, 32) == 0);
        block_piece_manifest_free(&m);
        active_chain_free(&chain);
        PASS();
    } _test_next:;
    return failures;
}

static int test_block_piece_manifest_refresh_after_coverage_expands(void)
{
    int failures = 0;
    TEST("block piece manifest refreshes when contiguous body coverage "
         "expands behind a fresh cached tail") {
        struct active_chain chain;
        struct block_index idx[5];
        struct uint256 hashes[5];
        struct block_piece_manifest cached;

        active_chain_init(&chain);
        memset(idx, 0, sizeof(idx));
        memset(hashes, 0, sizeof(hashes));
        memset(&cached, 0, sizeof(cached));
        for (int i = 0; i < 5; i++) {
            memset(hashes[i].data, (uint8_t)(0xA0 + i), 32);
            block_index_init(&idx[i]);
            idx[i].phashBlock = &hashes[i];
            idx[i].nHeight = i;
            idx[i].nStatus = BLOCK_VALID_TREE;
            idx[i].pprev = i > 0 ? &idx[i - 1] : NULL;
        }
        idx[3].nStatus |= BLOCK_HAVE_DATA;
        idx[4].nStatus |= BLOCK_HAVE_DATA;
        ASSERT(active_chain_move_window_tip(&chain, &idx[4]));

        cached.start_height = 3;
        cached.end_height = 4;
        cached.num_pieces = 1;

        /* The cached tail is honest while height 2 is still absent. */
        ASSERT(!block_piece_manifest_should_refresh(
            &chain, true, &cached, 4, 4, 1000));

        /* Once the predecessor lands, keeping the two-block tail would hide
         * newly serveable history even though its end height is still fresh. */
        idx[2].nStatus |= BLOCK_HAVE_DATA;
        ASSERT(block_piece_manifest_should_refresh(
            &chain, true, &cached, 4, 4, 1000));

        cached.start_height = 1;
        ASSERT(!block_piece_manifest_should_refresh(
            &chain, true, &cached, 4, 4, 1000));
        ASSERT(block_piece_manifest_should_refresh(
            &chain, false, NULL, 0, 4, 1000));
        ASSERT(block_piece_manifest_should_refresh(
            &chain, true, &cached, 4, 1004, 1000));

        active_chain_free(&chain);
        PASS();
    } _test_next:;
    return failures;
}

/* ── UTXO commitment checkpoint tests ────────────────────── */

static int test_commitment_checkpoint_roundtrip(void)
{
    int failures = 0;
    TEST("utxo_commitment serialize/deserialize roundtrip") {
        struct utxo_commitment uc;
        utxo_commitment_init(&uc);

        /* Add some UTXOs */
        uint8_t txid1[32], txid2[32];
        memset(txid1, 0xAA, 32);
        memset(txid2, 0xBB, 32);
        utxo_commitment_add(&uc, txid1, 0, 100000, 1000);
        utxo_commitment_add(&uc, txid2, 1, 200000, 2000);

        /* Serialize */
        uint8_t buf[UTXO_COMMITMENT_SERIALIZED_SIZE];
        utxo_commitment_serialize(&uc, buf);

        /* Deserialize */
        struct utxo_commitment uc2;
        ASSERT(utxo_commitment_deserialize(&uc2, buf, sizeof(buf)));
        ASSERT(utxo_commitment_equal(&uc, &uc2));
        PASS();
    } _test_next:;
    return failures;
}

static int test_commitment_add_remove_identity(void)
{
    int failures = 0;
    TEST("utxo_commitment add+remove = identity") {
        struct utxo_commitment uc;
        utxo_commitment_init(&uc);

        struct utxo_commitment empty;
        utxo_commitment_init(&empty);

        /* Add then remove same UTXO → back to empty */
        uint8_t txid[32];
        memset(txid, 0x55, 32);
        utxo_commitment_add(&uc, txid, 0, 50000, 500);
        ASSERT(!utxo_commitment_equal(&uc, &empty));
        utxo_commitment_remove(&uc, txid, 0, 50000, 500);
        ASSERT(memcmp(uc.accumulator, empty.accumulator, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_commitment_order_independent(void)
{
    int failures = 0;
    TEST("utxo_commitment XOR is order-independent") {
        struct utxo_commitment uc1, uc2;
        utxo_commitment_init(&uc1);
        utxo_commitment_init(&uc2);

        uint8_t txid_a[32], txid_b[32], txid_c[32];
        memset(txid_a, 0x11, 32);
        memset(txid_b, 0x22, 32);
        memset(txid_c, 0x33, 32);

        /* Add in order A, B, C */
        utxo_commitment_add(&uc1, txid_a, 0, 100, 1);
        utxo_commitment_add(&uc1, txid_b, 0, 200, 2);
        utxo_commitment_add(&uc1, txid_c, 0, 300, 3);

        /* Add in order C, A, B */
        utxo_commitment_add(&uc2, txid_c, 0, 300, 3);
        utxo_commitment_add(&uc2, txid_a, 0, 100, 1);
        utxo_commitment_add(&uc2, txid_b, 0, 200, 2);

        ASSERT(utxo_commitment_equal(&uc1, &uc2));
        PASS();
    } _test_next:;
    return failures;
}

static int test_commitment_merge(void)
{
    int failures = 0;
    TEST("utxo_commitment merge combines sets") {
        struct utxo_commitment uc_all, uc_a, uc_b;
        utxo_commitment_init(&uc_all);
        utxo_commitment_init(&uc_a);
        utxo_commitment_init(&uc_b);

        uint8_t txid1[32], txid2[32];
        memset(txid1, 0x44, 32);
        memset(txid2, 0x55, 32);

        utxo_commitment_add(&uc_all, txid1, 0, 100, 1);
        utxo_commitment_add(&uc_all, txid2, 0, 200, 2);

        utxo_commitment_add(&uc_a, txid1, 0, 100, 1);
        utxo_commitment_add(&uc_b, txid2, 0, 200, 2);

        utxo_commitment_merge(&uc_a, &uc_b);
        ASSERT(utxo_commitment_equal(&uc_a, &uc_all));
        PASS();
    } _test_next:;
    return failures;
}

/* ── Bandwidth-adaptive download manager tests ───────────── */

static struct uint256 make_hash_fs(uint8_t v)
{
    struct uint256 h;
    memset(h.data, 0, 32);
    h.data[0] = v;
    h.data[31] = v;
    return h;
}

static int test_dl_bandwidth_scoring(void)
{
    int failures = 0;
    TEST("dl bandwidth scoring: fast peers get higher score") {
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 h1 = make_hash_fs(1);
        struct uint256 h2 = make_hash_fs(2);

        /* Peer 1: fast (100ms delivery) */
        dl_mark_requested(&dm, &h1, 100, 1);
        dl_mark_received(&dm, &h1);
        dl_peer_block_received(&dm, 1, 100000); /* 100ms in us */

        /* Peer 2: slow (2s delivery) */
        dl_mark_requested(&dm, &h2, 101, 2);
        dl_mark_received(&dm, &h2);
        dl_peer_block_received(&dm, 2, 2000000); /* 2s in us */

        /* Fast peer should get larger window */
        size_t w1 = dl_peer_adaptive_window(&dm, 1);
        size_t w2 = dl_peer_adaptive_window(&dm, 2);
        ASSERT(w1 > w2);
        ASSERT(w1 >= 16);
        ASSERT(w2 >= 16);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_adaptive_assignment(void)
{
    int failures = 0;
    TEST("dl adaptive assignment gives fast peers more work") {
        struct download_manager dm;
        dl_init(&dm);

        /* Simulate: peer 1 is 4x faster than peer 2 */
        /* Need to establish bandwidth scores first */
        for (int i = 0; i < 10; i++) {
            struct uint256 h = make_hash_fs((uint8_t)(100 + i));
            dl_mark_requested(&dm, &h, i, 1);
            dl_mark_received(&dm, &h);
        }
        dl_peer_block_received(&dm, 1, 250000); /* 250ms avg */

        for (int i = 0; i < 10; i++) {
            struct uint256 h = make_hash_fs((uint8_t)(200 + i));
            dl_mark_requested(&dm, &h, i, 2);
            dl_mark_received(&dm, &h);
        }
        dl_peer_block_received(&dm, 2, 2000000); /* 2000ms avg */

        /* Queue 256 blocks */
        struct uint256 hashes[256];
        int32_t heights[256];
        for (int i = 0; i < 256; i++) {
            memset(hashes[i].data, 0, 32);
            hashes[i].data[0] = (uint8_t)(i & 0xFF);
            hashes[i].data[1] = (uint8_t)(i >> 8);
            hashes[i].data[2] = 0xFF; /* different from above */
            heights[i] = 1000 + i;
        }
        dl_queue_blocks(&dm, hashes, heights, 256);

        /* Assign to both peers */
        struct uint256 out[256];
        size_t a1 = dl_assign_to_peer(&dm, 1, out, 256);
        size_t a2 = dl_assign_to_peer(&dm, 2, out, 256);

        /* Fast peer should get more (at least 2x) */
        ASSERT(a1 > a2);
        ASSERT(a1 >= 16);
        ASSERT(a2 >= 16);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Integration: full chunk hash → Merkle proof pipeline ── */

static int test_chunk_to_merkle_pipeline(void)
{
    int failures = 0;
    TEST("full pipeline: chunks → hashes → merkle root → proofs") {
        /* Create 4 fake chunks */
        struct utxo_chunk *chunks[4];
        uint8_t chunk_hashes[4][32];
        for (int i = 0; i < 4; i++) {
            chunks[i] = zcl_calloc(1, sizeof(struct utxo_chunk), "test_chunk");
            ASSERT(chunks[i] != NULL);
            chunks[i]->chunk_index = (uint32_t)i;
            chunks[i]->num_entries = 1;
            memset(chunks[i]->entries[0].txid, (uint8_t)(i + 0x60), 32);
            chunks[i]->entries[0].vout = 0;
            chunks[i]->entries[0].value = (int64_t)(i + 1) * 10000;
            chunks[i]->entries[0].height = (i + 1) * 100;
            fast_sync_chunk_hash(chunks[i], chunk_hashes[i]);
        }

        /* Build Merkle root */
        uint8_t root[32];
        fast_sync_merkle_root((const uint8_t (*)[32])chunk_hashes, 4, root);

        /* Verify each chunk can prove itself against the root */
        for (uint32_t i = 0; i < 4; i++) {
            uint8_t (*proof)[32] = NULL;
            uint32_t plen = fast_sync_build_proof(
                (const uint8_t (*)[32])chunk_hashes, 4, i, &proof);
            ASSERT(plen == 2); /* log2(4) = 2 */

            bool ok = fast_sync_verify_chunk_proof(
                i, chunk_hashes[i], (const uint8_t (*)[32])proof, plen, root);
            ASSERT(ok);
            free(proof);
        }

        for (int i = 0; i < 4; i++)
            free(chunks[i]);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Block swarm full lifecycle ──────────────────────────── */

static int test_block_swarm_lifecycle(void)
{
    int failures = 0;
    TEST("block_swarm full lifecycle: init → assign → receive → complete") {
        struct block_piece_manifest manifest;
        memset(&manifest, 0, sizeof(manifest));
        manifest.start_height = 0;
        manifest.end_height = 639; /* 5 pieces */
        manifest.num_pieces = 5;
        manifest.piece_hashes = zcl_calloc(5, 32, "test_piece_hashes");
        ASSERT(manifest.piece_hashes != NULL);

        struct block_swarm bs;
        ASSERT(block_swarm_init(&bs, &manifest, NULL));
        ASSERT(block_swarm_progress(&bs) == 0);

        /* 3 peers each get work */
        int32_t p1 = block_swarm_assign_piece(&bs, 1, NULL, 0);
        int32_t p2 = block_swarm_assign_piece(&bs, 2, NULL, 0);
        int32_t p3 = block_swarm_assign_piece(&bs, 3, NULL, 0);
        ASSERT(p1 >= 0 && p2 >= 0 && p3 >= 0);
        ASSERT(bs.pieces_inflight == 3);

        /* Receive from peers */
        ASSERT(block_swarm_receive_piece(&bs, (uint32_t)p1, 1));
        ASSERT(block_swarm_receive_piece(&bs, (uint32_t)p2, 2));
        ASSERT(block_swarm_receive_piece(&bs, (uint32_t)p3, 3));
        ASSERT(block_swarm_progress(&bs) == 60); /* 3/5 = 60% */

        /* Assign and receive remaining */
        int32_t p4 = block_swarm_assign_piece(&bs, 1, NULL, 0);
        int32_t p5 = block_swarm_assign_piece(&bs, 2, NULL, 0);
        ASSERT(p4 >= 0 && p5 >= 0);
        block_swarm_receive_piece(&bs, (uint32_t)p4, 1);
        block_swarm_receive_piece(&bs, (uint32_t)p5, 2);
        ASSERT(block_swarm_is_complete(&bs));
        ASSERT(block_swarm_progress(&bs) == 100);

        block_swarm_free(&bs);
        free(manifest.piece_hashes);
        PASS();
    } _test_next:;
    return failures;
}

static int test_block_swarm_fail_retry(void)
{
    int failures = 0;
    TEST("block_swarm fail piece and retry") {
        struct block_piece_manifest manifest;
        memset(&manifest, 0, sizeof(manifest));
        manifest.num_pieces = 3;
        manifest.piece_hashes = zcl_calloc(3, 32, "test_piece_hashes");
        ASSERT(manifest.piece_hashes != NULL);

        struct block_swarm bs;
        block_swarm_init(&bs, &manifest, NULL);

        int32_t p = block_swarm_assign_piece(&bs, 1, NULL, 0);
        ASSERT(p >= 0);

        /* Fail the piece (bad hash) */
        block_swarm_fail_piece(&bs, (uint32_t)p);
        ASSERT(bs.pieces_failed == 1);
        ASSERT(bs.piece_states[p] == CHUNK_NEEDED);

        /* Can reassign to different peer */
        int32_t p2 = block_swarm_assign_piece(&bs, 2, NULL, 0);
        ASSERT(p2 == p); /* should get same piece back */

        block_swarm_free(&bs);
        free(manifest.piece_hashes);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Large-scale Merkle proof stress test ────────────────── */

static int test_merkle_proof_large(void)
{
    int failures = 0;
    TEST("merkle proof with 1000 leaves") {
        uint8_t (*hashes)[32] = zcl_calloc(1000, 32, "test_hashes");
        ASSERT(hashes != NULL);

        for (int i = 0; i < 1000; i++) {
            struct sha3_256_ctx ctx;
            sha3_256_init(&ctx);
            sha3_256_write(&ctx, (const uint8_t *)&i, 4);
            sha3_256_finalize(&ctx, hashes[i]);
        }

        uint8_t root[32];
        fast_sync_merkle_root((const uint8_t (*)[32])hashes, 1000, root);

        /* Verify proof for leaf 500 */
        uint8_t (*proof)[32] = NULL;
        uint32_t plen = fast_sync_build_proof(
            (const uint8_t (*)[32])hashes, 1000, 500, &proof);
        ASSERT(plen > 0);
        ASSERT(plen <= 10); /* log2(1024) = 10 */

        bool ok = fast_sync_verify_chunk_proof(
            500, hashes[500], (const uint8_t (*)[32])proof, plen, root);
        ASSERT(ok);

        /* Verify proof for first and last leaves */
        free(proof);
        plen = fast_sync_build_proof(
            (const uint8_t (*)[32])hashes, 1000, 0, &proof);
        ASSERT(fast_sync_verify_chunk_proof(
            0, hashes[0], (const uint8_t (*)[32])proof, plen, root));

        free(proof);
        plen = fast_sync_build_proof(
            (const uint8_t (*)[32])hashes, 1000, 999, &proof);
        ASSERT(fast_sync_verify_chunk_proof(
            999, hashes[999], (const uint8_t (*)[32])proof, plen, root));

        free(proof);
        free(hashes);
        PASS();
    } _test_next:;
    return failures;
}

/* ── MMR-secured snapshot offer ──────────────────────────── */

static int test_snapshot_offer_mmr_field(void)
{
    int failures = 0;
    TEST("snapshot_offer includes MMR root field") {
        /* Verify the struct layout includes the auxiliary mmr_root between
         * utxo_root and num_utxos. This checks serialization, not PoW binding. */
        struct snapshot_offer offer;
        memset(&offer, 0, sizeof(offer));

        /* Set distinct values in each field */
        offer.height = 3000000;
        memset(offer.block_hash, 0xAA, 32);
        memset(offer.utxo_root, 0xBB, 32);
        memset(offer.mmr_root, 0xCC, 32);
        offer.num_utxos = 1354769;
        offer.total_bytes = 1354769 * 80;

        /* Verify fields are distinct and correct */
        ASSERT(offer.height == 3000000);
        ASSERT(offer.block_hash[0] == 0xAA);
        ASSERT(offer.utxo_root[0] == 0xBB);
        ASSERT(offer.mmr_root[0] == 0xCC);
        ASSERT(offer.num_utxos == 1354769);

        /* Verify MMR root is its own field, not overlapping */
        ASSERT(memcmp(offer.utxo_root, offer.mmr_root, 32) != 0);

        /* Verify all-zero MMR root detection (no PoW proof) */
        uint8_t zeros[32] = {0};
        ASSERT(memcmp(offer.mmr_root, zeros, 32) != 0);
        memset(offer.mmr_root, 0, 32);
        ASSERT(memcmp(offer.mmr_root, zeros, 32) == 0);

        PASS();
    } _test_next:;
    return failures;
}

/* ── fast_sync_apply_chunk atomicity ─────────────────
 *
 * A chunk that mixes a valid UTXO with an invalid one must leave no
 * trace in the database. The CHECK(height >= 0) constraint on the
 * utxos table triggers an insert failure for a negative height in
 * the middle of the chunk; the surrounding BEGIN/COMMIT must roll
 * back the entire chunk, including the valid first row.
 * ─────────────────────────────────────────────────────────── */

static int test_apply_chunk_rollback_on_mid_chunk_failure(void)
{
    int failures = 0;
    TEST("fast_sync_apply_chunk: rolls back whole chunk on mid-chunk failure ") {
        char dir[128];
        snprintf(dir, sizeof(dir),
                 "./test-tmp/fast_sync_apply_%d_XXXXXX", (int)getpid());
        mkdir("./test-tmp", 0755);
        char *datadir = mkdtemp(dir);
        ASSERT(datadir != NULL);

        char db_path[256];
        snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);

        /* Set up a minimal utxos schema matching app/models/src/database.c. */
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open_v2(db_path, &db,
                               SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                               NULL) == SQLITE_OK);
        const char *schema =
            "CREATE TABLE utxos ("
            "txid BLOB NOT NULL,vout INTEGER NOT NULL,"
            "value INTEGER NOT NULL CHECK(value >= 0 AND value <= 2100000000000000),"
            "script BLOB NOT NULL,"
            "script_type INTEGER NOT NULL DEFAULT 0,"
            "address_hash BLOB,height INTEGER NOT NULL CHECK(height >= 0),"
            "is_coinbase INTEGER NOT NULL DEFAULT 0,"
            "PRIMARY KEY (txid,vout))";
        char *err = NULL;
        int rc = sqlite3_exec(db, schema, NULL, NULL, &err);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "schema setup failed: %s\n", err ? err : "?");
            if (err) sqlite3_free(err);
        }
        sqlite3_close(db);
        ASSERT(rc == SQLITE_OK);

        /* Build a chunk with two entries: first valid, second has
         * height == -1 which violates the CHECK constraint. */
        struct utxo_chunk chunk;
        memset(&chunk, 0, sizeof(chunk));
        chunk.num_entries = 2;
        chunk.chunk_index = 0;

        memset(chunk.entries[0].txid, 0x11, 32);
        chunk.entries[0].vout = 0;
        chunk.entries[0].value = 5000;
        chunk.entries[0].script[0] = 0x51;
        chunk.entries[0].script_len = 1;
        chunk.entries[0].height = 100;

        memset(chunk.entries[1].txid, 0x22, 32);
        chunk.entries[1].vout = 0;
        chunk.entries[1].value = 5000;
        chunk.entries[1].script[0] = 0x51;
        chunk.entries[1].script_len = 1;
        chunk.entries[1].height = -1; /* triggers CHECK(height >= 0) */

        bool applied = fast_sync_apply_chunk(datadir, &chunk);
        ASSERT(!applied);

        /* Rollback atomicity: COUNT(*) must be 0 — neither the valid
         * first entry nor the rejected second one should persist. */
        ASSERT(sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY,
                               NULL) == SQLITE_OK);
        sqlite3_stmt *s = NULL;
        ASSERT(sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM utxos",
                                  -1, &s, NULL) == SQLITE_OK);
        int count = -1;
        if (sqlite3_step(s) == SQLITE_ROW) // raw-sql-ok:test-fixture-verify
            count = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
        sqlite3_close(db);
        ASSERT(count == 0);

        /* Cleanup. */
        char wal[300], shm[300];
        snprintf(wal, sizeof(wal), "%s-wal", db_path);
        snprintf(shm, sizeof(shm), "%s-shm", db_path);
        unlink(wal);
        unlink(shm);
        unlink(db_path);
        rmdir(datadir);

        PASS();
    } _test_next:;
    return failures;
}

static int test_chunk_roundtrip_preserves_canonical_utxo_fields(void)
{
    int failures = 0;
    TEST("fast_sync chunk roundtrip preserves SHA3 UTXO fields") {
        char src_dir[128], dst_dir[128];
        snprintf(src_dir, sizeof(src_dir),
                 "./test-tmp/fast_sync_src_%d_XXXXXX", (int)getpid());
        snprintf(dst_dir, sizeof(dst_dir),
                 "./test-tmp/fast_sync_dst_%d_XXXXXX", (int)getpid());
        mkdir("./test-tmp", 0755);
        char *src_datadir = mkdtemp(src_dir);
        char *dst_datadir = mkdtemp(dst_dir);
        ASSERT(src_datadir != NULL);
        ASSERT(dst_datadir != NULL);

        char src_db_path[256], dst_db_path[256];
        snprintf(src_db_path, sizeof(src_db_path), "%s/node.db", src_datadir);
        snprintf(dst_db_path, sizeof(dst_db_path), "%s/node.db", dst_datadir);

        const char *schema =
            "CREATE TABLE utxos ("
            "txid BLOB NOT NULL,vout INTEGER NOT NULL,"
            "value INTEGER NOT NULL CHECK(value >= 0 AND value <= 2100000000000000),"
            "script BLOB NOT NULL,"
            "script_type INTEGER NOT NULL DEFAULT 0,"
            "address_hash BLOB,height INTEGER NOT NULL CHECK(height >= 0),"
            "is_coinbase INTEGER NOT NULL DEFAULT 0,"
            "PRIMARY KEY (txid,vout))";

        sqlite3 *src = NULL;
        sqlite3 *dst = NULL;
        ASSERT(sqlite3_open_v2(src_db_path, &src,
                               SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                               NULL) == SQLITE_OK);
        ASSERT(sqlite3_open_v2(dst_db_path, &dst,
                               SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                               NULL) == SQLITE_OK);
        char *err = NULL;
        ASSERT(sqlite3_exec(src, schema, NULL, NULL, &err) == SQLITE_OK);
        ASSERT(sqlite3_exec(dst, schema, NULL, NULL, &err) == SQLITE_OK);

        sqlite3_stmt *ins = NULL;
        ASSERT(sqlite3_prepare_v2(src,
            "INSERT INTO utxos"
            "(txid,vout,value,script,script_type,height,is_coinbase)"
            " VALUES(?,?,?,?,0,?,?)",
            -1, &ins, NULL) == SQLITE_OK);

        uint8_t txid1[32], txid2[32], script1[300], script2[1] = {0x51};
        memset(txid1, 0xA1, sizeof(txid1));
        memset(txid2, 0xB2, sizeof(txid2));
        for (size_t i = 0; i < sizeof(script1); i++)
            script1[i] = (uint8_t)(i & 0xFF);

        sqlite3_bind_blob(ins, 1, txid1, 32, SQLITE_STATIC);
        sqlite3_bind_int(ins, 2, 0);
        sqlite3_bind_int64(ins, 3, 5000000000LL);
        sqlite3_bind_blob(ins, 4, script1, (int)sizeof(script1), SQLITE_STATIC);
        sqlite3_bind_int(ins, 5, 100);
        sqlite3_bind_int(ins, 6, 1);
        ASSERT(sqlite3_step(ins) == SQLITE_DONE); // raw-sql-ok:test-fixture-setup
        sqlite3_reset(ins);
        sqlite3_clear_bindings(ins);

        sqlite3_bind_blob(ins, 1, txid2, 32, SQLITE_STATIC);
        sqlite3_bind_int(ins, 2, 2);
        sqlite3_bind_int64(ins, 3, 7000);
        sqlite3_bind_blob(ins, 4, script2, (int)sizeof(script2), SQLITE_STATIC);
        sqlite3_bind_int(ins, 5, 101);
        sqlite3_bind_int(ins, 6, 0);
        ASSERT(sqlite3_step(ins) == SQLITE_DONE); // raw-sql-ok:test-fixture-setup
        sqlite3_finalize(ins);

        uint8_t src_root[32], dst_root[32];
        uint64_t src_count = 0, dst_count = 0;
        utxo_commitment_sha3_compute(src, src_root, &src_count);

        struct utxo_chunk *chunk =
            zcl_calloc(1, sizeof(struct utxo_chunk), "roundtrip_chunk");
        ASSERT(chunk != NULL);
        ASSERT(fast_sync_serve_chunk_db(src, 0, SYNC_CHUNK_SIZE, chunk));
        ASSERT(chunk->num_entries == 2);
        ASSERT(chunk->entries[0].script_len == sizeof(script1));
        ASSERT(chunk->entries[0].is_coinbase);
        ASSERT(!chunk->entries[1].is_coinbase);

        sqlite3_close(dst);
        dst = NULL;
        ASSERT(fast_sync_apply_chunk(dst_datadir, chunk));
        ASSERT(sqlite3_open_v2(dst_db_path, &dst, SQLITE_OPEN_READONLY,
                               NULL) == SQLITE_OK);
        utxo_commitment_sha3_compute(dst, dst_root, &dst_count);
        ASSERT(src_count == 2 && dst_count == 2);
        ASSERT(memcmp(src_root, dst_root, 32) == 0);

        sqlite3_stmt *q = NULL;
        ASSERT(sqlite3_prepare_v2(dst,
            "SELECT length(script), is_coinbase FROM utxos "
            "WHERE txid=? AND vout=0",
            -1, &q, NULL) == SQLITE_OK);
        sqlite3_bind_blob(q, 1, txid1, 32, SQLITE_STATIC);
        int script_len = -1, is_coinbase = -1;
        if (sqlite3_step(q) == SQLITE_ROW) { // raw-sql-ok:test-fixture-verify
            script_len = sqlite3_column_int(q, 0);
            is_coinbase = sqlite3_column_int(q, 1);
        }
        sqlite3_finalize(q);
        ASSERT(script_len == (int)sizeof(script1));
        ASSERT(is_coinbase == 1);

        free(chunk);
        sqlite3_close(src);
        sqlite3_close(dst);
        unlink(src_db_path);
        unlink(dst_db_path);
        rmdir(src_datadir);
        rmdir(dst_datadir);

        PASS();
    } _test_next:;
    return failures;
}

/* One-entry snapshot-cache buffer with a caller-chosen script length.
 * script_len >= 253 needs the 0xFD two-byte compact form the parser
 * accepts. Ownership passes to fast_sync_publish_snapshot_cache. */
static uint8_t *test_snapshot_script_entry(size_t *size_out, const char *tag,
                                           uint32_t script_len,
                                           uint8_t script_byte)
{
    const size_t len_bytes = script_len < 253 ? 1 : 3;
    const size_t size = 4 + 32 + 4 + 8 + 4 + 1 + len_bytes + script_len;
    uint8_t *buf = zcl_malloc(size, tag);
    if (!buf) return NULL;

    size_t pos = 0;
    buf[pos++] = 1; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0;
    memset(buf + pos, 0x77, 32); pos += 32;
    memset(buf + pos, 0, 4); pos += 4;              /* vout */
    memset(buf + pos, 0, 8); pos += 8;              /* value */
    memset(buf + pos, 0, 4); pos += 4;              /* height */
    buf[pos++] = 0;                                 /* is_coinbase */
    if (script_len < 253) {
        buf[pos++] = (uint8_t)script_len;
    } else {
        buf[pos++] = 0xFD;
        buf[pos++] = (uint8_t)script_len;
        buf[pos++] = (uint8_t)(script_len >> 8);
    }
    memset(buf + pos, script_byte, script_len);

    if (size_out) *size_out = size;
    return buf;
}

/* ── Refuse-don't-truncate: consensus-legal scripts past the 520-byte
 * entry cap must fail the CHUNK on both serve paths. The wire receiver
 * rejects oversize entries outright (msgprocessor_snapshot.c) and the
 * end-of-sync UTXO root is computed over full-fidelity rows, so a
 * silently shortened script could only ever produce state that fails
 * verification — or worse, passes it with corrupted entries when the
 * manifest root falls back to the chunk-derived Merkle root. */
static int test_serve_refuses_oversize_script(void)
{
    int failures = 0;
    TEST("fast_sync serve refuses oversize-script chunks on both the DB "
         "and RAM paths, and still serves full-fidelity scripts at or "
         "under the cap") {
        char dir[128];
        snprintf(dir, sizeof(dir),
                 "./test-tmp/fast_sync_oversize_%d_XXXXXX", (int)getpid());
        mkdir("./test-tmp", 0755);
        char *datadir = mkdtemp(dir);
        ASSERT(datadir != NULL);
        char db_path[256];
        snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);

        const char *schema =
            "CREATE TABLE utxos ("
            "txid BLOB NOT NULL,vout INTEGER NOT NULL,"
            "value INTEGER NOT NULL,script BLOB NOT NULL,"
            "height INTEGER NOT NULL,is_coinbase INTEGER NOT NULL DEFAULT 0,"
            "PRIMARY KEY (txid,vout))";
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open_v2(db_path, &db,
                               SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                               NULL) == SQLITE_OK);
        char *err = NULL;
        ASSERT(sqlite3_exec(db, schema, NULL, NULL, &err) == SQLITE_OK);
        sqlite3_stmt *ins = NULL;
        ASSERT(sqlite3_prepare_v2(db,
            "INSERT INTO utxos(txid,vout,value,script,height,is_coinbase)"
            " VALUES(?,?,?,?,?,?)",
            -1, &ins, NULL) == SQLITE_OK);

        uint8_t txid_ok[32], txid_small[32], txid_big[32];
        uint8_t script_ok[300], script_big[600];
        memset(txid_ok, 0xA1, sizeof(txid_ok));
        memset(txid_small, 0xA2, sizeof(txid_small));
        memset(txid_big, 0xC3, sizeof(txid_big));
        memset(script_ok, 0x76, sizeof(script_ok));
        memset(script_big, 0x63, sizeof(script_big));

        /* Chunk 0: two in-cap rows. Chunk 1: one 600-byte-script row —
         * consensus-legal (MAX_SCRIPT_SIZE is 10000), past the entry
         * struct's 520-byte cap, and exactly what bare large multisig
         * outputs produce. */
        struct { const uint8_t *txid; const uint8_t *script; int slen; }
            rows[3] = {
                { txid_ok, script_ok, (int)sizeof(script_ok) },
                { txid_small, script_big + 350, 1 },   /* in-cap neighbor */
                { txid_big, script_big, (int)sizeof(script_big) },
            };
        for (int r = 0; r < 3; r++) {
            sqlite3_reset(ins);
            sqlite3_clear_bindings(ins);
            sqlite3_bind_blob(ins, 1, rows[r].txid, 32, SQLITE_STATIC);
            sqlite3_bind_int(ins, 2, (int)r);
            sqlite3_bind_int64(ins, 3, 1000 + r);
            sqlite3_bind_blob(ins, 4, rows[r].script, rows[r].slen,
                              SQLITE_STATIC);
            sqlite3_bind_int(ins, 5, 100 + r);
            sqlite3_bind_int(ins, 6, 0);
            ASSERT(sqlite3_step(ins) == SQLITE_DONE);  // raw-sql-ok:test-fixture-setup
        }
        sqlite3_finalize(ins);

        struct utxo_chunk *chunk =
            zcl_calloc(1, sizeof(struct utxo_chunk), "oversize_chunk");
        ASSERT(chunk != NULL);

        /* Control: the in-cap chunk still serves, full fidelity. A chunk
         * size of 2 puts the two in-cap rows in chunk 0 and the oversize
         * row alone in chunk 1. */
        ASSERT(fast_sync_serve_chunk_db(db, 0, 2, chunk));
        ASSERT(chunk->num_entries == 2);
        ASSERT(chunk->entries[0].script_len == sizeof(script_ok));

        /* THE REFUSAL: the oversize chunk fails the serve instead of
         * coming back with entries[0].script_len clamped to 520. */
        ASSERT(!fast_sync_serve_chunk_db(db, 1, 2, chunk));
        sqlite3_close(db);
        db = NULL;

        /* ── RAM cache path: same contract against a full-fidelity
         * snapshot buffer. Remove the database first so the SQLite
         * fallback has nothing to serve and a refusal can only come
         * from the RAM read itself. ── */
        unlink(db_path);
        uint8_t sha3[32];
        memset(sha3, 0x3c, sizeof(sha3));
        fast_sync_reset_snapshot_cache();

        /* In-cap control: 250-byte script serves from RAM untouched. */
        size_t buf_size = 0;
        uint8_t *buf = test_snapshot_script_entry(
            &buf_size, "oversize_ram_ok", 250, 0x52);
        ASSERT(buf != NULL);
        ASSERT(fast_sync_publish_snapshot_cache(buf, (int64_t)buf_size,
                                                sha3, 1));
        ASSERT(fast_sync_serve_chunk(datadir, 0, chunk));
        ASSERT(chunk->num_entries == 1);
        ASSERT(chunk->entries[0].script_len == 250);

        /* The refusal: 601-byte script fails the RAM read (and the
         * fallback finds no database at all). */
        buf = test_snapshot_script_entry(&buf_size, "oversize_ram_big",
                                         601, 0x63);
        ASSERT(buf != NULL);
        ASSERT(fast_sync_publish_snapshot_cache(buf, (int64_t)buf_size,
                                                sha3, 1));
        ASSERT(!fast_sync_serve_chunk(datadir, 0, chunk));

        fast_sync_reset_snapshot_cache();
        free(chunk);
        rmdir(datadir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Batched SHA3-256 consumer parity (sha3-x4-batch lane) ─────────────
 *
 * fast_sync_merkle_root/build_proof combine a layer four pairs at a time via
 * sha3_256_x4, and fast_sync_build_manifest_db batches four chunk hashes on top
 * of fast_sync_serialize_chunk_for_hash. Both must be byte-identical to the
 * scalar per-pair / streaming reference. These two tests are that guard. */

/* Independent scalar Merkle root: per-pair SHA3-256(left||right), pow2 padding
 * with copies of the last leaf — mirrors fast_sync_merkle_root's contract but
 * shares no code with merkle_combine_layer. */
static void ref_merkle_root(const uint8_t (*hashes)[32], uint32_t count,
                            uint8_t root_out[32])
{
    if (count == 0) { memset(root_out, 0, 32); return; }
    if (count == 1) { memcpy(root_out, hashes[0], 32); return; }
    uint32_t padded = 1;
    while (padded < count) padded <<= 1;
    uint8_t (*layer)[32] = malloc((size_t)padded * 32);
    for (uint32_t i = 0; i < padded; i++)
        memcpy(layer[i], hashes[i < count ? i : count - 1], 32);
    uint32_t n = padded;
    while (n > 1) {
        for (uint32_t i = 0; i < n / 2; i++) {
            struct sha3_256_ctx ctx;
            sha3_256_init(&ctx);
            sha3_256_write(&ctx, layer[2 * i], 32);
            sha3_256_write(&ctx, layer[2 * i + 1], 32);
            sha3_256_finalize(&ctx, layer[i]);
        }
        n /= 2;
    }
    memcpy(root_out, layer[0], 32);
    free(layer);
}

static int test_merkle_root_batch_parity(void)
{
    int failures = 0;
    TEST("fast_sync_merkle_root batch-of-4 == scalar per-pair, all counts") {
        /* Counts spanning batch boundaries: <4, exactly 4, tail remainders,
         * multi-layer (each layer re-batches), and odd counts that pad. */
        static const uint32_t counts[] = { 1, 2, 3, 4, 5, 7, 8, 13, 16, 31,
                                           32, 33, 64, 65, 100, 128, 257, 1000 };
        uint64_t seed = 0xfeedface0badc0deULL;
        for (unsigned c = 0; c < sizeof(counts)/sizeof(counts[0]); c++) {
            uint32_t n = counts[c];
            uint8_t (*hashes)[32] = malloc((size_t)n * 32);
            ASSERT(hashes != NULL);
            for (uint32_t i = 0; i < n; i++)
                for (int b = 0; b < 32; b++) {
                    seed ^= seed >> 12; seed ^= seed << 25; seed ^= seed >> 27;
                    hashes[i][b] = (uint8_t)((seed * 0x2545F4914F6CDD1DULL) >> 33);
                }
            uint8_t got[32], want[32];
            fast_sync_merkle_root((const uint8_t (*)[32])hashes, n, got);
            ref_merkle_root((const uint8_t (*)[32])hashes, n, want);
            ASSERT(memcmp(got, want, 32) == 0);
            free(hashes);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_chunk_serialize_parity(void)
{
    int failures = 0;
    TEST("fast_sync_serialize_chunk_for_hash + sha3 == streaming chunk_hash") {
        struct utxo_chunk *chunk = zcl_calloc(1, sizeof(struct utxo_chunk), "ser_chunk");
        uint8_t *buf = zcl_malloc(FAST_SYNC_CHUNK_SER_MAX, "ser_buf");
        ASSERT(chunk != NULL && buf != NULL);
        uint64_t seed = 0x0123456789abcdefULL;
        #define NEXT() (seed ^= seed >> 12, seed ^= seed << 25, seed ^= seed >> 27, \
                        seed * 0x2545F4914F6CDD1DULL)
        for (int trial = 0; trial < 400; trial++) {
            chunk->chunk_index = (uint32_t)NEXT();
            /* Include an empty chunk (0 entries) and varied non-empty sizes. */
            chunk->num_entries = (trial == 0) ? 0 : (uint32_t)(NEXT() % 40) + 1;
            for (uint32_t i = 0; i < chunk->num_entries; i++) {
                for (int b = 0; b < 32; b++) chunk->entries[i].txid[b] = (uint8_t)NEXT();
                chunk->entries[i].vout = (uint32_t)NEXT();
                chunk->entries[i].value = (int64_t)(NEXT() % 2100000000000000ULL);
                /* script_len spans 0, small, and the 520 cap boundary. */
                uint16_t sl = (uint16_t)(NEXT() % 521);
                chunk->entries[i].script_len = sl;
                for (uint16_t b = 0; b < sl; b++) chunk->entries[i].script[b] = (uint8_t)NEXT();
                chunk->entries[i].height = (int32_t)(NEXT() % 4000000);
                chunk->entries[i].is_coinbase = (NEXT() & 1) != 0;
            }
            uint8_t ref[32], got[32];
            fast_sync_chunk_hash(chunk, ref);
            size_t len = fast_sync_serialize_chunk_for_hash(chunk, buf);
            sha3_256(buf, len, got);
            ASSERT(memcmp(ref, got, 32) == 0);
        }
        #undef NEXT
        free(buf);
        free(chunk);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ─────────────────────────────────────────── */

int test_fast_sync(void)
{
    int failures = 0;

    /* Merkle tree */
    failures += test_merkle_root_single();
    failures += test_merkle_root_empty();
    failures += test_merkle_root_deterministic();
    failures += test_merkle_root_order_sensitive();
    failures += test_merkle_root_power_of_two_padding();

    /* Merkle proofs */
    failures += test_merkle_proof_verify();
    failures += test_merkle_proof_invalid();
    failures += test_merkle_proof_large();

    /* Chunk hashing */
    failures += test_chunk_hash_deterministic();
    failures += test_chunk_verify();

    /* PoW defense */
    failures += test_pow_solve_verify();
    failures += test_pow_timestamp_range();

    /* Hardened challenge-bound / adaptive / single-use PoW */

    /* Rate limiting */
    failures += test_rate_limiter();
    failures += test_rate_limiter_n();
    failures += test_snapshot_cache_publish_reset();
    failures += test_snapshot_cache_versioning();
    failures += test_utxo_root_cache_publish_reset();
    failures += test_utxo_root_cache_versioning();

    /* Swarm coordinator */
    failures += test_swarm_init_assign();
    failures += test_swarm_timeout_reassign();

    /* Block swarm */
    failures += test_block_swarm_rarest_first();
    failures += test_block_swarm_endgame();
    failures += test_block_swarm_bitmap();
    failures += test_block_piece_hash_deterministic();
    failures += test_block_piece_manifest_active_chain();
    failures += test_block_piece_manifest_active_chain_skips_leading_gap();
    failures += test_block_piece_manifest_refresh_after_coverage_expands();
    failures += test_block_swarm_lifecycle();
    failures += test_block_swarm_fail_retry();

    /* UTXO commitment */
    failures += test_commitment_checkpoint_roundtrip();
    failures += test_commitment_add_remove_identity();
    failures += test_commitment_order_independent();
    failures += test_commitment_merge();

    /* Batched SHA3-256 consumer parity (sha3-x4-batch lane) */
    failures += test_merkle_root_batch_parity();
    failures += test_chunk_serialize_parity();

    /* Integration */
    failures += test_chunk_to_merkle_pipeline();

    /* Bandwidth-adaptive download */
    failures += test_dl_bandwidth_scoring();
    failures += test_dl_adaptive_assignment();

    /* MMR-secured snapshot */
    failures += test_snapshot_offer_mmr_field();

    /* chunk apply atomicity */
    failures += test_apply_chunk_rollback_on_mid_chunk_failure();
    failures += test_chunk_roundtrip_preserves_canonical_utxo_fields();
    failures += test_serve_refuses_oversize_script();

    return failures;
}
