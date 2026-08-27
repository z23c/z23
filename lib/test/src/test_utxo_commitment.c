/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for the incremental UTXO set commitment (XOR-hash accumulator). */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "coins/utxo_commitment.h"
#include "net/fast_sync.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "util/safe_alloc.h"

int test_utxo_commitment(void)
{
    int failures = 0;

    printf("utxo_commitment: init is zero... ");
    {
        struct utxo_commitment uc;
        utxo_commitment_init(&uc);
        uint8_t zero[32] = {0};
        bool ok = (uc.count == 0 && memcmp(uc.accumulator, zero, 32) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("utxo_commitment: add then remove returns to zero... ");
    {
        struct utxo_commitment uc;
        utxo_commitment_init(&uc);
        uint8_t txid[32];
        memset(txid, 0xAB, 32);
        utxo_commitment_add(&uc, txid, 0, 50000000, 100);

        /* Should be non-zero after add */
        uint8_t zero[32] = {0};
        bool nonzero = (memcmp(uc.accumulator, zero, 32) != 0);

        utxo_commitment_remove(&uc, txid, 0, 50000000, 100);
        bool back_to_zero = (memcmp(uc.accumulator, zero, 32) == 0);
        bool ok = nonzero && back_to_zero && uc.count == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL (nonzero=%d back=%d count=%llu)\n",
                       nonzero, back_to_zero, (unsigned long long)uc.count);
               failures++; }
    }

    printf("utxo_commitment: order independent... ");
    {
        uint8_t txid1[32], txid2[32];
        memset(txid1, 0x11, 32);
        memset(txid2, 0x22, 32);

        struct utxo_commitment a, b;
        utxo_commitment_init(&a);
        utxo_commitment_init(&b);

        /* Add in different orders */
        utxo_commitment_add(&a, txid1, 0, 1000, 10);
        utxo_commitment_add(&a, txid2, 1, 2000, 20);

        utxo_commitment_add(&b, txid2, 1, 2000, 20);
        utxo_commitment_add(&b, txid1, 0, 1000, 10);

        bool ok = utxo_commitment_equal(&a, &b);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("utxo_commitment: different UTXOs produce different hashes... ");
    {
        struct utxo_commitment a, b;
        utxo_commitment_init(&a);
        utxo_commitment_init(&b);
        uint8_t txid[32];
        memset(txid, 0x33, 32);

        utxo_commitment_add(&a, txid, 0, 1000, 10);
        utxo_commitment_add(&b, txid, 0, 1001, 10); /* different value */

        bool ok = !utxo_commitment_equal(&a, &b);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("utxo_commitment: serialize/deserialize roundtrip... ");
    {
        struct utxo_commitment uc;
        utxo_commitment_init(&uc);
        uint8_t txid[32];
        memset(txid, 0x44, 32);
        utxo_commitment_add(&uc, txid, 5, 99999, 500);
        utxo_commitment_add(&uc, txid, 6, 88888, 501);

        uint8_t buf[UTXO_COMMITMENT_SERIALIZED_SIZE];
        utxo_commitment_serialize(&uc, buf);

        struct utxo_commitment uc2;
        bool ok = utxo_commitment_deserialize(&uc2, buf, sizeof(buf));
        ok = ok && utxo_commitment_equal(&uc, &uc2);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("utxo_commitment: deserialize rejects short buffer... ");
    {
        struct utxo_commitment uc;
        uint8_t buf[10] = {0};
        bool ok = !utxo_commitment_deserialize(&uc, buf, sizeof(buf));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("utxo_commitment: merge combines two sets... ");
    {
        uint8_t txid1[32], txid2[32];
        memset(txid1, 0x55, 32);
        memset(txid2, 0x66, 32);

        /* Build combined set */
        struct utxo_commitment combined;
        utxo_commitment_init(&combined);
        utxo_commitment_add(&combined, txid1, 0, 1000, 10);
        utxo_commitment_add(&combined, txid2, 0, 2000, 20);

        /* Build two separate sets and merge */
        struct utxo_commitment a, b;
        utxo_commitment_init(&a);
        utxo_commitment_init(&b);
        utxo_commitment_add(&a, txid1, 0, 1000, 10);
        utxo_commitment_add(&b, txid2, 0, 2000, 20);
        utxo_commitment_merge(&a, &b);

        bool ok = utxo_commitment_equal(&a, &combined);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("utxo_commitment: large set add/remove consistency... ");
    {
        struct utxo_commitment uc;
        utxo_commitment_init(&uc);

        /* Add 1000 UTXOs */
        for (uint32_t i = 0; i < 1000; i++) {
            uint8_t txid[32] = {0};
            memcpy(txid, &i, sizeof(i));
            utxo_commitment_add(&uc, txid, i, (int64_t)i * 100000, (int32_t)i);
        }

        /* Remove first 500 */
        for (uint32_t i = 0; i < 500; i++) {
            uint8_t txid[32] = {0};
            memcpy(txid, &i, sizeof(i));
            utxo_commitment_remove(&uc, txid, i, (int64_t)i * 100000, (int32_t)i);
        }

        /* Build from scratch with just 500-999 */
        struct utxo_commitment expected;
        utxo_commitment_init(&expected);
        for (uint32_t i = 500; i < 1000; i++) {
            uint8_t txid[32] = {0};
            memcpy(txid, &i, sizeof(i));
            utxo_commitment_add(&expected, txid, i, (int64_t)i * 100000, (int32_t)i);
        }

        bool ok = utxo_commitment_equal(&uc, &expected);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    TEST("utxo_commitment skip flag bypasses add/remove") {
        struct utxo_commitment uc;
        utxo_commitment_init(&uc);

        uint8_t txid[32] = {1,2,3,4,5,6,7,8};

        /* Normal add — accumulator becomes non-zero */
        utxo_commitment_add(&uc, txid, 0, 100, 1);
        ASSERT(uc.count == 1);
        bool is_zero = true;
        for (int i = 0; i < 32; i++)
            if (uc.accumulator[i] != 0) { is_zero = false; break; }
        ASSERT(!is_zero);

        /* Save state, enable skip */
        struct utxo_commitment saved = uc;
        g_utxo_commitment_skip = true;

        /* Add under skip — should be no-op */
        uint8_t txid2[32] = {9,10,11,12};
        utxo_commitment_add(&uc, txid2, 1, 200, 2);
        ASSERT(utxo_commitment_equal(&uc, &saved));

        /* Remove under skip — should be no-op */
        utxo_commitment_remove(&uc, txid, 0, 100, 1);
        ASSERT(utxo_commitment_equal(&uc, &saved));

        /* Disable skip */
        g_utxo_commitment_skip = false;

        /* Normal remove — accumulator returns to zero */
        utxo_commitment_remove(&uc, txid, 0, 100, 1);
        ASSERT(uc.count == 0);
        is_zero = true;
        for (int i = 0; i < 32; i++)
            if (uc.accumulator[i] != 0) { is_zero = false; break; }
        ASSERT(is_zero);
        PASS();
    } _test_next:;

    /* ── Block swarm tests ────────────────────────────────── */

    printf("block_piece_hash deterministic... ");
    {
        uint8_t hashes[2][32];
        memset(hashes[0], 0xAA, 32);
        memset(hashes[1], 0xBB, 32);

        uint8_t h1[32], h2[32];
        block_piece_hash((const uint8_t (*)[32])hashes, 2, 0, h1);
        block_piece_hash((const uint8_t (*)[32])hashes, 2, 0, h2);
        if (memcmp(h1, h2, 32) == 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("block_piece_hash differs by index... ");
    {
        uint8_t hashes[1][32];
        memset(hashes[0], 0xCC, 32);

        uint8_t h0[32], h1[32];
        block_piece_hash((const uint8_t (*)[32])hashes, 1, 0, h0);
        block_piece_hash((const uint8_t (*)[32])hashes, 1, 1, h1);
        if (memcmp(h0, h1, 32) != 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("block_swarm init and free... ");
    {
        struct block_piece_manifest m = {
            .start_height = 1, .end_height = 256,
            .num_pieces = 2,
            .piece_hashes = zcl_calloc(2, 32, "test_piece_hashes")
        };
        memset(m.piece_hashes[0], 0x11, 32);
        memset(m.piece_hashes[1], 0x22, 32);

        struct block_swarm bs;
        bool ok = block_swarm_init(&bs, &m, "/tmp");
        ok = ok && bs.manifest.num_pieces == 2;
        ok = ok && bs.pieces_complete == 0;
        ok = ok && bs.pieces_inflight == 0;
        block_swarm_free(&bs);
        free(m.piece_hashes);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("block_swarm assign sequential... ");
    {
        struct block_piece_manifest m = {
            .start_height = 1, .end_height = 384,
            .num_pieces = 3,
            .piece_hashes = zcl_calloc(3, 32, "test_piece_hashes")
        };
        struct block_swarm bs;
        block_swarm_init(&bs, &m, "/tmp");

        int32_t p0 = block_swarm_assign_piece(&bs, 1, NULL, 0);
        int32_t p1 = block_swarm_assign_piece(&bs, 2, NULL, 0);
        int32_t p2 = block_swarm_assign_piece(&bs, 3, NULL, 0);
        int32_t p3 = block_swarm_assign_piece(&bs, 4, NULL, 0);

        bool ok = (p0 >= 0 && p1 >= 0 && p2 >= 0);
        ok = ok && (p0 != p1 && p1 != p2);
        ok = ok && (p3 == -1);
        ok = ok && (bs.pieces_inflight == 3);

        block_swarm_free(&bs);
        free(m.piece_hashes);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("block_swarm receive completes... ");
    {
        struct block_piece_manifest m = {
            .start_height = 1, .end_height = 128,
            .num_pieces = 1,
            .piece_hashes = zcl_calloc(1, 32, "test_piece_hashes")
        };
        struct block_swarm bs;
        block_swarm_init(&bs, &m, "/tmp");

        int32_t pi = block_swarm_assign_piece(&bs, 1, NULL, 0);
        bool ok = (pi == 0);
        ok = ok && block_swarm_receive_piece(&bs, 0, 1);
        ok = ok && block_swarm_is_complete(&bs);
        ok = ok && (block_swarm_progress(&bs) == 100);

        block_swarm_free(&bs);
        free(m.piece_hashes);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("block_swarm timeout re-queues... ");
    {
        struct block_piece_manifest m = {
            .start_height = 1, .end_height = 256,
            .num_pieces = 2,
            .piece_hashes = zcl_calloc(2, 32, "test_piece_hashes")
        };
        struct block_swarm bs;
        block_swarm_init(&bs, &m, "/tmp");

        block_swarm_assign_piece(&bs, 1, NULL, 0);
        bs.piece_request_time[0] = (int64_t)platform_time_wall_time_t() - 60;

        block_swarm_handle_timeouts(&bs, 30);
        bool ok = (bs.piece_states[0] == CHUNK_NEEDED);
        ok = ok && (bs.pieces_inflight == 0);

        int32_t pi = block_swarm_assign_piece(&bs, 2, NULL, 0);
        ok = ok && (pi == 0);

        block_swarm_free(&bs);
        free(m.piece_hashes);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("block_swarm fail allows retry... ");
    {
        struct block_piece_manifest m = {
            .start_height = 1, .end_height = 128,
            .num_pieces = 1,
            .piece_hashes = zcl_calloc(1, 32, "test_piece_hashes")
        };
        struct block_swarm bs;
        block_swarm_init(&bs, &m, "/tmp");

        block_swarm_assign_piece(&bs, 1, NULL, 0);
        block_swarm_fail_piece(&bs, 0);
        bool ok = (bs.piece_states[0] == CHUNK_NEEDED);
        ok = ok && (bs.pieces_failed == 1);

        int32_t pi = block_swarm_assign_piece(&bs, 2, NULL, 0);
        ok = ok && (pi == 0);

        block_swarm_free(&bs);
        free(m.piece_hashes);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("block_swarm bitmap serialize... ");
    {
        struct block_piece_manifest m = {
            .start_height = 1, .end_height = 1024,
            .num_pieces = 8,
            .piece_hashes = zcl_calloc(8, 32, "test_piece_hashes")
        };
        struct block_swarm bs;
        block_swarm_init(&bs, &m, "/tmp");

        bs.piece_states[0] = CHUNK_COMPLETE; bs.pieces_complete++;
        bs.piece_states[2] = CHUNK_COMPLETE; bs.pieces_complete++;
        bs.piece_states[7] = CHUNK_COMPLETE; bs.pieces_complete++;

        uint8_t bitmap[1];
        uint32_t len = block_swarm_serialize_bitmap(&bs, bitmap, 1);
        bool ok = (len == 1);
        ok = ok && (bitmap[0] == (1 | (1 << 2) | (1 << 7)));

        block_swarm_free(&bs);
        free(m.piece_hashes);
        if (ok) printf("OK\n");
        else { printf("FAIL (bitmap=0x%02x)\n", bitmap[0]); failures++; }
    }

    printf("block_swarm rarest-first... ");
    {
        struct block_piece_manifest m = {
            .start_height = 1, .end_height = 512,
            .num_pieces = 4,
            .piece_hashes = zcl_calloc(4, 32, "test_piece_hashes")
        };
        struct block_swarm bs;
        block_swarm_init(&bs, &m, "/tmp");

        uint8_t bm_a[] = { 0x03 };
        uint8_t bm_b[] = { 0x06 };
        block_swarm_update_availability(&bs, bm_a, 1);
        block_swarm_update_availability(&bs, bm_b, 1);

        int32_t pi = block_swarm_assign_piece(&bs, 1, NULL, 0);
        bool ok = (pi == 3); /* piece 3 has 0 availability = rarest */

        block_swarm_free(&bs);
        free(m.piece_hashes);
        if (ok) printf("OK\n");
        else { printf("FAIL (got piece %d)\n", pi); failures++; }
    }

    printf("block_swarm endgame mode... ");
    {
        struct block_piece_manifest m = {
            .start_height = 1, .end_height = 512,
            .num_pieces = 4,
            .piece_hashes = zcl_calloc(4, 32, "test_piece_hashes")
        };
        struct block_swarm bs;
        block_swarm_init(&bs, &m, "/tmp");

        bs.piece_states[0] = CHUNK_COMPLETE; bs.pieces_complete++;
        bs.piece_states[1] = CHUNK_COMPLETE; bs.pieces_complete++;
        bs.piece_states[2] = CHUNK_COMPLETE; bs.pieces_complete++;

        int32_t pi = block_swarm_assign_piece(&bs, 1, NULL, 0);
        bool ok = (pi == 3 && bs.endgame);

        uint32_t indices[4];
        uint32_t count = block_swarm_endgame_pieces(&bs, indices, 4);
        ok = ok && (count == 1) && (indices[0] == 3);

        block_swarm_free(&bs);
        free(m.piece_hashes);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("block_swarm bitmap peer filtering... ");
    {
        struct block_piece_manifest m = {
            .start_height = 1, .end_height = 512,
            .num_pieces = 4,
            .piece_hashes = zcl_calloc(4, 32, "test_piece_hashes")
        };
        struct block_swarm bs;
        block_swarm_init(&bs, &m, "/tmp");

        uint8_t bm[] = { 0x0C }; /* bits 2,3 only */

        int32_t pi = block_swarm_assign_piece(&bs, 1, bm, sizeof(bm));
        bool ok = (pi == 2 || pi == 3);

        block_swarm_free(&bs);
        free(m.piece_hashes);
        if (ok) printf("OK\n");
        else { printf("FAIL (got piece %d)\n", pi); failures++; }
    }

    printf("block_swarm short-bitmap assign stays bounded... ");
    {
        struct block_piece_manifest m = {
            .start_height = 1, .end_height = 524288,
            .num_pieces = 4096,
            .piece_hashes = zcl_calloc(4096, 32, "test_piece_hashes")
        };
        struct block_swarm bs;
        bool ok = block_swarm_init(&bs, &m, "/tmp");

        /* A 4096-piece manifest against a 1-byte bitmap: every piece index
         * lands past the buffer's span, so each bit reads as ABSENT and no
         * byte beyond bitmap[0] may ever be touched. */
        uint8_t bm[] = { 0x00 };
        int32_t pi_none = block_swarm_assign_piece(&bs, 1, bm, sizeof(bm));
        ok = ok && pi_none == -1;

        int32_t pi_thru = block_swarm_assign_piece_through_height(
            &bs, 2, bm, sizeof(bm), 524288);
        ok = ok && pi_thru == -1;

        int32_t pi_all = block_swarm_assign_piece(&bs, 3, NULL, 0);
        ok = ok && pi_all == 0;

        block_swarm_free(&bs);
        free(m.piece_hashes);
        if (ok) printf("OK\n");
        else { printf("FAIL (none=%d thru=%d all=%d)\n", pi_none, pi_thru, pi_all); failures++; }
    }

    return failures;
}
