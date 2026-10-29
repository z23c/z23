/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "net/compact_blocks.h"
#include "core/hash.h"
#include "chain/chainparams.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/peer_scoring.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/safe_alloc.h"
#include "validation/txmempool.h"
#include <string.h>
#include <stdio.h>

/* Drive process_cmpctblock() with a partially-reconstructing compact block
 * while the per-peer pending-block stash allocation is faulted out. Pre-fix
 * the handler built a getblocktxn request from node->compact_missing_indices
 * (NULL, stash failed) with num_missing > 0, and block_txn_request_serialize
 * dereferenced NULL[0] — a crash under genuine memory exhaustion; the heap
 * missing-index list leaked too. Post-fix the handler frees the partial
 * block and the index list and skips the doomed request. The second pass,
 * unfaulted, proves the valid partial path still stashes exactly one miss. */
static int test_process_cmpctblock_oom_pending_stash(void)
{
    int failures = 0;
    printf("process_cmpctblock: OOM on the pending stash frees and does not "
           "deref NULL... ");

    const struct chain_params *params = chain_params_get();
    peer_scoring_init();

    struct net_manager nm;
    net_manager_init(&nm);
    struct tx_mempool pool;
    tx_mempool_init(&pool, 0);

    /* A params copy whose powLimit accepts any header: process_cmpctblock
     * gates on CheckProofOfWork before reconstructing, and a fabricated
     * header cannot satisfy the real network target (mirrors test_chain.c's
     * custom consensus_params with powLimit = all-0xff). */
    struct chain_params local_params = *params;
    memset(local_params.consensus.powLimit.data, 0xff, 32);

    struct msg_processor mp;
    memset(&mp, 0, sizeof(mp));
    mp.params = &local_params;
    mp.net_mgr = &nm;
    mp.mempool = &pool;

    struct p2p_node node;
    memset(&node, 0, sizeof(node));
    node.id = 91;
    snprintf(node.addr_name, sizeof(node.addr_name), "cmpct-oom-peer");
    /* Non-localhost so the PoW-gate scoring path treats it as an ordinary
     * peer (mirrors test_msg_handlers.c's setup_node()). */
    node.addr.svc.addr.ip[10] = 0xff;
    node.addr.svc.addr.ip[11] = 0xff;
    node.addr.svc.addr.ip[12] = 198;
    node.addr.svc.addr.ip[13] = 51;
    node.addr.svc.addr.ip[14] = 100;
    node.addr.svc.addr.ip[15] = 91;

    /* Block with 2 txs: coinbase (prefilled by compact_block_from_block) +
     * one regular tx whose short txid resolves against the empty mempool to
     * exactly one missing index. */
    struct block blk;
    block_init(&blk);
    blk.header.nVersion = 4;
    blk.header.nTime = 1700000200;
    /* An easy target (test_chain.c's derivation): 0x2100ffff compact means
     * a target near 2^256, so the fabricated header's hash passes
     * CheckProofOfWork against the all-0xff powLimit below. */
    struct arith_uint256 easy_target;
    arith_uint256_set_compact(&easy_target, 0x2100ffffu, NULL, NULL);
    blk.header.nBits = arith_uint256_get_compact(&easy_target, false);
    blk.header.nNonce.data[0] = 33;
    blk.num_vtx = 2;
    blk.vtx = calloc(2, sizeof(struct transaction));
    for (int i = 0; i < 2; i++) {
        transaction_init(&blk.vtx[i]);
        blk.vtx[i].version = 4;
        blk.vtx[i].overwintered = true;
        blk.vtx[i].version_group_id = SAPLING_VERSION_GROUP_ID;
        memset(blk.vtx[i].hash.data, (uint8_t)(i + 1), 32);
    }
    blk.vtx[0].num_vin = 1;
    blk.vtx[0].vin = calloc(1, sizeof(struct tx_in));
    tx_in_init(&blk.vtx[0].vin[0]);

    struct compact_block_msg cb;
    struct byte_stream s;
    stream_init(&s, 1024);
    struct uint256 hash;
    block_get_hash(&blk, &hash);
    bool built = compact_block_from_block(&cb, &blk, 7) &&
                 compact_block_msg_serialize(&cb, &s);

    if (!built) {
        printf("FAIL (fixture build)\n");
        failures++;
    } else {
        /* Pass 1: fault the stash allocation. */
        block_clear_seen(&hash);
        s.read_pos = 0;
        zcl_alloc_fault_fail_next("compact_pending_block");
        bool rc = process_cmpctblock(&mp, &node, &s);
        zcl_alloc_fault_clear();
        if (!rc || node.compact_pending_block != NULL ||
            node.compact_missing_indices != NULL ||
            node.compact_num_missing != 0) {
            printf("FAIL (oom pass: rc=%d pending=%p indices=%p n=%zu)\n",
                   rc, (void *)node.compact_pending_block,
                   (void *)node.compact_missing_indices,
                   node.compact_num_missing);
            failures++;
        }

        /* Pass 2: unfaulted — the valid partial path must stash one miss. */
        block_clear_seen(&hash);
        s.read_pos = 0;
        bool rc2 = process_cmpctblock(&mp, &node, &s);
        if (!rc2 || node.compact_pending_block == NULL ||
            node.compact_missing_indices == NULL ||
            node.compact_num_missing != 1) {
            printf("FAIL (clean pass: rc=%d pending=%p indices=%p n=%zu)\n",
                   rc2, (void *)node.compact_pending_block,
                   (void *)node.compact_missing_indices,
                   node.compact_num_missing);
            failures++;
        }
        if (failures == 0)
            printf("OK\n");
    }

    /* compact_pending_clear() is static to msg_compact.c; mirror it for the
     * teardown (pass 1 leaves nothing stashed, pass 2 leaves the moved block
     * and the index list). */
    if (node.compact_pending_block) {
        block_free(node.compact_pending_block);
        free(node.compact_pending_block);
        node.compact_pending_block = NULL;
    }
    free(node.compact_missing_indices);
    node.compact_missing_indices = NULL;
    node.compact_num_missing = 0;
    node.compact_request_time = 0;
    memset(&node.compact_pending_hash, 0, sizeof(node.compact_pending_hash));
    stream_free(&s);
    compact_block_msg_free(&cb);
    block_free(&blk);
    tx_mempool_free(&pool);
    net_manager_free(&nm);
    return failures;
}

static int test_siphash_key_and_short_txid(void)
{
    int failures = 0;

    /* ── SipHash-2-4 known test vectors ─────────────────────────── */
    /* Reference: https://131002.net/siphash/siphash.pdf Appendix A */
    printf("siphash_2_4 reference vector... ");
    {
        uint8_t key[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        uint8_t data[15] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e
        };
        uint64_t result = siphash_2_4(key, data, 15);
        /* Expected: 0xa129ca6149be45e5 */
        if (result == 0xa129ca6149be45e5ULL)
            printf("OK\n");
        else {
            printf("FAIL (got 0x%016lx, expected 0xa129ca6149be45e5)\n",
                   (unsigned long)result);
            failures++;
        }
    }

    printf("siphash_2_4 empty input... ");
    {
        uint8_t key[16] = {0};
        uint64_t result = siphash_2_4(key, NULL, 0);
        /* SipHash with all-zero key and empty input should produce a
         * deterministic non-zero value */
        if (result != 0) {
            printf("OK (0x%016lx)\n", (unsigned long)result);
        } else {
            printf("FAIL (unexpectedly zero)\n");
            failures++;
        }
    }

    printf("siphash_2_4 deterministic... ");
    {
        uint8_t key[16] = {0x42};
        uint8_t data[] = "hello";
        uint64_t r1 = siphash_2_4(key, data, 5);
        uint64_t r2 = siphash_2_4(key, data, 5);
        if (r1 == r2)
            printf("OK\n");
        else {
            printf("FAIL (non-deterministic)\n");
            failures++;
        }
    }

    /* ── Key derivation ─────────────────────────────────────────── */
    printf("compact_block_derive_key deterministic... ");
    {
        struct block_header hdr;
        block_header_init(&hdr);
        hdr.nVersion = 4;
        hdr.nTime = 1700000000;
        hdr.nBits = 0x1d00ffff;

        uint8_t key1[16], key2[16];
        compact_block_derive_key(&hdr, 12345, key1);
        compact_block_derive_key(&hdr, 12345, key2);
        if (memcmp(key1, key2, 16) == 0)
            printf("OK\n");
        else {
            printf("FAIL\n"); failures++;
        }
    }

    printf("compact_block_derive_key different nonces produce different keys... ");
    {
        struct block_header hdr;
        block_header_init(&hdr);
        hdr.nTime = 1700000000;

        uint8_t key1[16], key2[16];
        compact_block_derive_key(&hdr, 1, key1);
        compact_block_derive_key(&hdr, 2, key2);
        if (memcmp(key1, key2, 16) != 0)
            printf("OK\n");
        else {
            printf("FAIL (same keys for different nonces)\n"); failures++;
        }
    }

    /* ── Short txid computation ─────────────────────────────────── */
    printf("compact_block_short_txid deterministic... ");
    {
        uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        struct uint256 txhash;
        memset(txhash.data, 0xAB, 32);

        uint8_t sid1[SHORT_TXID_LEN], sid2[SHORT_TXID_LEN];
        compact_block_short_txid(key, &txhash, sid1);
        compact_block_short_txid(key, &txhash, sid2);
        if (memcmp(sid1, sid2, SHORT_TXID_LEN) == 0)
            printf("OK\n");
        else {
            printf("FAIL\n"); failures++;
        }
    }

    printf("compact_block_short_txid different txhashes produce different ids... ");
    {
        uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        struct uint256 h1, h2;
        memset(h1.data, 0x11, 32);
        memset(h2.data, 0x22, 32);

        uint8_t s1[SHORT_TXID_LEN], s2[SHORT_TXID_LEN];
        compact_block_short_txid(key, &h1, s1);
        compact_block_short_txid(key, &h2, s2);
        if (memcmp(s1, s2, SHORT_TXID_LEN) != 0)
            printf("OK\n");
        else {
            printf("FAIL (collision)\n"); failures++;
        }
    }

    return failures;
}

static int test_compact_block_from_block_basic(void)
{
    int failures = 0;

    /* ── Compact block from full block ──────────────────────────── */
    printf("compact_block_from_block basic... ");
    {
        /* Build a minimal block with 3 txs: coinbase + 2 regular */
        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.nTime = 1700000000;
        blk.header.nBits = 0x1d00ffff;
        blk.num_vtx = 3;
        blk.vtx = calloc(3, sizeof(struct transaction));

        for (int i = 0; i < 3; i++) {
            transaction_init(&blk.vtx[i]);
            blk.vtx[i].version = 4;
            blk.vtx[i].overwintered = true;
            blk.vtx[i].version_group_id = SAPLING_VERSION_GROUP_ID;
            /* Give each tx a unique hash */
            memset(blk.vtx[i].hash.data, (uint8_t)(i + 1), 32);
        }
        /* Mark first as coinbase */
        blk.vtx[0].num_vin = 1;
        blk.vtx[0].vin = calloc(1, sizeof(struct tx_in));
        tx_in_init(&blk.vtx[0].vin[0]);

        struct compact_block_msg cb;
        bool ok = compact_block_from_block(&cb, &blk, 42);
        if (ok && cb.num_prefilled == 1 && cb.num_short_txids == 2 &&
            cb.prefilled[0].index == 0) {
            printf("OK (1 prefilled, 2 short txids)\n");
        } else {
            printf("FAIL (ok=%d prefilled=%zu short=%zu)\n",
                   ok, cb.num_prefilled, cb.num_short_txids);
            failures++;
        }
        compact_block_msg_free(&cb);
        block_free(&blk);
    }

    return failures;
}

static int test_compact_block_msg_roundtrip(void)
{
    int failures = 0;

    /* ── Serialization round-trip ───────────────────────────────── */
    printf("compact_block_msg serialize/deserialize round-trip... ");
    {
        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.nTime = 1700000001;
        blk.header.nBits = 0x1d00ffff;
        blk.num_vtx = 2;
        blk.vtx = calloc(2, sizeof(struct transaction));
        for (int i = 0; i < 2; i++) {
            transaction_init(&blk.vtx[i]);
            blk.vtx[i].version = 4;
            blk.vtx[i].overwintered = true;
            blk.vtx[i].version_group_id = SAPLING_VERSION_GROUP_ID;
            memset(blk.vtx[i].hash.data, (uint8_t)(0x10 + i), 32);
        }
        blk.vtx[0].num_vin = 1;
        blk.vtx[0].vin = calloc(1, sizeof(struct tx_in));
        tx_in_init(&blk.vtx[0].vin[0]);

        struct compact_block_msg cb1;
        compact_block_from_block(&cb1, &blk, 99);

        struct byte_stream s;
        stream_init(&s, 4096);
        bool ser_ok = compact_block_msg_serialize(&cb1, &s);

        struct compact_block_msg cb2;
        s.read_pos = 0;
        bool deser_ok = compact_block_msg_deserialize(&cb2, &s);

        bool match = ser_ok && deser_ok &&
                     cb1.num_short_txids == cb2.num_short_txids &&
                     cb1.num_prefilled == cb2.num_prefilled &&
                     cb1.nonce == cb2.nonce &&
                     memcmp(cb1.siphash_key, cb2.siphash_key, 16) == 0;

        if (cb1.num_short_txids > 0 && match) {
            match = memcmp(cb1.short_txids, cb2.short_txids,
                           cb1.num_short_txids * SHORT_TXID_LEN) == 0;
        }

        if (match)
            printf("OK\n");
        else {
            printf("FAIL (ser=%d deser=%d)\n", ser_ok, deser_ok);
            failures++;
        }

        stream_free(&s);
        compact_block_msg_free(&cb1);
        compact_block_msg_free(&cb2);
        block_free(&blk);
    }

    return failures;
}

static int test_compact_block_reconstruct_hard_failure(void)
{
    int failures = 0;

     /* Hard-failure returns must still initialize out_block. A 152-byte
      * cmpctblock (tests/harness/fuzz_seeds/p2p/crash-478b30c0482cf3e2842fa459987a7a2e5374e708.bin)
      * with short-txid count 0 and prefilled count 0 takes the first failure
      * return in compact_block_reconstruct(); if that runs before
      * block_init(out_block), process_cmpctblock()'s block_free(&out_block)
      * walks stale stack contents. The poison below stands in for a
      * long-lived process's stack. */
    printf("compact_block_reconstruct hard failure leaves out_block freeable... ");
    {
        static struct transaction stale_slot;
        transaction_init(&stale_slot);

        int local_failures = 0;

        /* Case 1: total == 0 — the exact shape of the fuzz artifact. */
        {
            struct compact_block_msg cb;
            compact_block_msg_init(&cb);

            struct block out;
            out.vtx = &stale_slot;          /* stale pointer from an earlier frame */
            out.num_vtx = (size_t)1 << 40;  /* stale count from an earlier frame */

            uint64_t *missing = NULL;
            size_t num_missing = 0;
            bool complete = compact_block_reconstruct(&cb, NULL, 0, NULL, 0,
                                                      &out, &missing,
                                                      &num_missing);
            if (complete || num_missing != 0 ||
                out.vtx != NULL || out.num_vtx != 0) {
                local_failures++;
                /* Do NOT block_free() a struct still holding the poison:
                 * that is the wild walk this test exists to prevent, and
                 * it would abort the whole group instead of reporting. */
                block_init(&out);
            }
            block_free(&out);   /* must be a no-op, not a wild walk */
            free(missing);
            compact_block_msg_free(&cb);
        }

        /* Case 2: total > MAX_COMPACT_BLOCK_TXNS. Each count is capped at
         * MAX individually by compact_block_msg_deserialize, so their sum
         * can still exceed it and reach the same early return. */
        {
            struct compact_block_msg cb;
            compact_block_msg_init(&cb);
            cb.num_short_txids = MAX_COMPACT_BLOCK_TXNS;
            cb.num_prefilled = 1;
            /* No backing arrays: the count check must reject before any
             * read of cb.short_txids / cb.prefilled. */

            struct block out;
            out.vtx = &stale_slot;
            out.num_vtx = (size_t)1 << 40;

            uint64_t *missing = NULL;
            size_t num_missing = 0;
            bool complete = compact_block_reconstruct(&cb, NULL, 0, NULL, 0,
                                                      &out, &missing,
                                                      &num_missing);
            if (complete || num_missing != 0 ||
                out.vtx != NULL || out.num_vtx != 0) {
                local_failures++;
                block_init(&out);
            }
            block_free(&out);
            free(missing);
            cb.num_short_txids = 0;
            cb.num_prefilled = 0;
            compact_block_msg_free(&cb);
        }

        if (local_failures == 0)
            printf("OK\n");
        else {
            printf("FAIL (%d of 2 hard-failure returns left out_block "
                   "holding the caller's stale stack)\n", local_failures);
            failures += local_failures;
        }
    }

    return failures;
}

static int test_compact_block_reconstruct_matches(void)
{
    int failures = 0;

    /* ── Reconstruction with full mempool match ─────────────────── */
    printf("compact_block_reconstruct full match... ");
    {
        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.nTime = 1700000002;
        blk.header.nBits = 0x1d00ffff;
        blk.num_vtx = 3;
        blk.vtx = calloc(3, sizeof(struct transaction));
        for (int i = 0; i < 3; i++) {
            transaction_init(&blk.vtx[i]);
            blk.vtx[i].version = 4;
            blk.vtx[i].overwintered = true;
            blk.vtx[i].version_group_id = SAPLING_VERSION_GROUP_ID;
            memset(blk.vtx[i].hash.data, (uint8_t)(0x30 + i), 32);
        }
        blk.vtx[0].num_vin = 1;
        blk.vtx[0].vin = calloc(1, sizeof(struct tx_in));
        tx_in_init(&blk.vtx[0].vin[0]);

        struct compact_block_msg cb;
        compact_block_from_block(&cb, &blk, 77);

        /* "mempool" contains the two non-coinbase txs */
        struct transaction mp_txs[2];
        for (int i = 0; i < 2; i++) {
            transaction_init(&mp_txs[i]);
            mp_txs[i].version = 4;
            mp_txs[i].overwintered = true;
            mp_txs[i].version_group_id = SAPLING_VERSION_GROUP_ID;
            memset(mp_txs[i].hash.data, (uint8_t)(0x31 + i), 32);
        }

        struct block out;
        uint64_t *missing = NULL;
        size_t num_missing = 0;
        bool complete = compact_block_reconstruct(&cb, mp_txs, 2, NULL, 0,
                                                   &out, &missing, &num_missing);
        if (complete && num_missing == 0 && out.num_vtx == 3)
            printf("OK\n");
        else {
            printf("FAIL (complete=%d missing=%zu vtx=%zu)\n",
                   complete, num_missing, out.num_vtx);
            failures++;
        }

        free(missing);
        block_free(&out);
        for (int i = 0; i < 2; i++)
            transaction_free(&mp_txs[i]);
        compact_block_msg_free(&cb);
        block_free(&blk);
    }

    /* ── Reconstruction with missing txs ────────────────────────── */
    printf("compact_block_reconstruct missing txs... ");
    {
        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.nTime = 1700000003;
        blk.header.nBits = 0x1d00ffff;
        blk.num_vtx = 4;
        blk.vtx = calloc(4, sizeof(struct transaction));
        for (int i = 0; i < 4; i++) {
            transaction_init(&blk.vtx[i]);
            blk.vtx[i].version = 4;
            blk.vtx[i].overwintered = true;
            blk.vtx[i].version_group_id = SAPLING_VERSION_GROUP_ID;
            memset(blk.vtx[i].hash.data, (uint8_t)(0x40 + i), 32);
        }
        blk.vtx[0].num_vin = 1;
        blk.vtx[0].vin = calloc(1, sizeof(struct tx_in));
        tx_in_init(&blk.vtx[0].vin[0]);

        struct compact_block_msg cb;
        compact_block_from_block(&cb, &blk, 88);

        /* Only provide 1 of 3 non-coinbase txs in "mempool" */
        struct transaction mp_txs[1];
        transaction_init(&mp_txs[0]);
        mp_txs[0].version = 4;
        mp_txs[0].overwintered = true;
        mp_txs[0].version_group_id = SAPLING_VERSION_GROUP_ID;
        memset(mp_txs[0].hash.data, 0x41, 32);  /* tx index 1 */

        struct block out;
        uint64_t *missing = NULL;
        size_t num_missing = 0;
        bool complete = compact_block_reconstruct(&cb, mp_txs, 1, NULL, 0,
                                                   &out, &missing, &num_missing);
        if (!complete && num_missing == 2)
            printf("OK (2 missing as expected)\n");
        else {
            printf("FAIL (complete=%d missing=%zu)\n", complete, num_missing);
            failures++;
        }

        free(missing);
        block_free(&out);
        transaction_free(&mp_txs[0]);
        compact_block_msg_free(&cb);
        block_free(&blk);
    }

    return failures;
}

static int test_compact_block_fill_missing(void)
{
    int failures = 0;

    /* ── Fill missing ───────────────────────────────────────────── */
    printf("compact_block_fill_missing... ");
    {
        /* Create a partial block with 3 slots, slot 1 missing */
        struct block partial;
        block_init(&partial);
        partial.num_vtx = 3;
        partial.vtx = calloc(3, sizeof(struct transaction));
        for (int i = 0; i < 3; i++) {
            transaction_init(&partial.vtx[i]);
            partial.vtx[i].version = 4;
            partial.vtx[i].overwintered = true;
            partial.vtx[i].version_group_id = SAPLING_VERSION_GROUP_ID;
        }

        /* Prepare the blocktxn response */
        struct block_txn_response resp;
        block_txn_response_init(&resp);
        resp.num_txs = 1;
        resp.txs = calloc(1, sizeof(struct transaction));
        transaction_init(&resp.txs[0]);
        resp.txs[0].version = 4;
        resp.txs[0].overwintered = true;
        resp.txs[0].version_group_id = SAPLING_VERSION_GROUP_ID;
        memset(resp.txs[0].hash.data, 0xBB, 32);

        uint64_t missing_idx = 1;
        bool ok = compact_block_fill_missing(&partial, &resp, &missing_idx, 1);
        if (ok)
            printf("OK\n");
        else {
            printf("FAIL\n"); failures++;
        }

        block_txn_response_free(&resp);
        block_free(&partial);
    }

    return failures;
}

static int test_block_txn_request_roundtrip(void)
{
    int failures = 0;

    /* ── getblocktxn round-trip ─────────────────────────────────── */
    printf("block_txn_request serialize/deserialize round-trip... ");
    {
        struct block_txn_request req;
        block_txn_request_init(&req);
        memset(req.block_hash.data, 0xCC, 32);
        req.num_indices = 3;
        req.indices = calloc(3, sizeof(uint64_t));
        req.indices[0] = 1;
        req.indices[1] = 5;
        req.indices[2] = 10;

        struct byte_stream s;
        stream_init(&s, 256);
        bool ser_ok = block_txn_request_serialize(&req, &s);

        struct block_txn_request req2;
        s.read_pos = 0;
        bool deser_ok = block_txn_request_deserialize(&req2, &s);

        bool match = ser_ok && deser_ok &&
                     req.num_indices == req2.num_indices &&
                     memcmp(req.block_hash.data, req2.block_hash.data, 32) == 0;
        for (size_t i = 0; i < req.num_indices && match; i++) {
            if (req.indices[i] != req2.indices[i])
                match = false;
        }

        if (match)
            printf("OK\n");
        else {
            printf("FAIL (ser=%d deser=%d)\n", ser_ok, deser_ok);
            failures++;
        }

        stream_free(&s);
        block_txn_request_free(&req);
        block_txn_request_free(&req2);
    }

    return failures;
}

static int test_block_txn_response_init_and_coinbase(void)
{
    int failures = 0;

    /* ── blocktxn round-trip ────────────────────────────────────── */
    printf("block_txn_response serialize/deserialize round-trip... ");
    {
        struct block_txn_response resp;
        block_txn_response_init(&resp);
        memset(resp.block_hash.data, 0xDD, 32);
        resp.num_txs = 2;
        resp.txs = calloc(2, sizeof(struct transaction));
        for (int i = 0; i < 2; i++) {
            transaction_init(&resp.txs[i]);
            resp.txs[i].version = 4;
            resp.txs[i].overwintered = true;
            resp.txs[i].version_group_id = SAPLING_VERSION_GROUP_ID;
        }

        struct byte_stream s;
        stream_init(&s, 4096);
        bool ser_ok = block_txn_response_serialize(&resp, &s);

        struct block_txn_response resp2;
        s.read_pos = 0;
        bool deser_ok = block_txn_response_deserialize(&resp2, &s);

        bool match = ser_ok && deser_ok &&
                     resp.num_txs == resp2.num_txs &&
                     memcmp(resp.block_hash.data, resp2.block_hash.data, 32) == 0;

        if (match)
            printf("OK\n");
        else {
            printf("FAIL (ser=%d deser=%d)\n", ser_ok, deser_ok);
            failures++;
        }

        stream_free(&s);
        block_txn_response_free(&resp);
        block_txn_response_free(&resp2);
    }

    /* ── Compact block msg lifecycle ────────────────────────────── */
    printf("compact_block_msg init/free... ");
    {
        struct compact_block_msg cb;
        compact_block_msg_init(&cb);
        /* Should be safe to free an initialized-but-empty struct */
        compact_block_msg_free(&cb);
        printf("OK\n");
    }

    /* ── Empty block (coinbase only) ────────────────────────────── */
    printf("compact_block_from_block coinbase-only... ");
    {
        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.nTime = 1700000004;
        blk.num_vtx = 1;
        blk.vtx = calloc(1, sizeof(struct transaction));
        transaction_init(&blk.vtx[0]);
        blk.vtx[0].version = 4;
        blk.vtx[0].overwintered = true;
        blk.vtx[0].version_group_id = SAPLING_VERSION_GROUP_ID;
        blk.vtx[0].num_vin = 1;
        blk.vtx[0].vin = calloc(1, sizeof(struct tx_in));
        tx_in_init(&blk.vtx[0].vin[0]);
        memset(blk.vtx[0].hash.data, 0xFF, 32);

        struct compact_block_msg cb;
        bool ok = compact_block_from_block(&cb, &blk, 0);
        if (ok && cb.num_prefilled == 1 && cb.num_short_txids == 0)
            printf("OK\n");
        else {
            printf("FAIL\n"); failures++;
        }
        compact_block_msg_free(&cb);
        block_free(&blk);
    }

    return failures;
}

/* ── Characterization: compact_block_msg_deserialize ───────────── */

/* Wire fixtures below are encoded with the public serializers, so the
 * expectations pin what the decoder does with bytes a real peer could send. */

static void cbt_header(struct block_header *h)
{
    block_header_init(h);
    h->nVersion = 4;
    h->nTime = 1700000400;
    h->nBits = 0x2100ffffu;
    h->nNonce.data[0] = 9;
}

static void cbt_make_tx(struct transaction *tx, uint8_t hash_fill,
                        uint32_t lock_time)
{
    transaction_init(tx);
    tx->version = 4;
    tx->overwintered = true;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    tx->lock_time = lock_time;
    tx->num_vin = 1;
    tx->vin = calloc(1, sizeof(struct tx_in));
    tx_in_init(&tx->vin[0]);
    memset(tx->hash.data, hash_fill, 32);
}

/* Block of n txs, coinbase first. Tx i hashes to fill_base + i. */
static void cbt_block(struct block *blk, size_t n, uint8_t fill_base)
{
    block_init(blk);
    cbt_header(&blk->header);
    blk->num_vtx = n;
    blk->vtx = calloc(n, sizeof(struct transaction));
    for (size_t i = 0; i < n; i++)
        cbt_make_tx(&blk->vtx[i], (uint8_t)(fill_base + i), (uint32_t)(10 + i));
}

/* header || nonce: the prefix every cmpctblock payload starts with. */
static bool cbt_prefix(struct byte_stream *s, uint64_t nonce)
{
    struct block_header h;
    cbt_header(&h);
    return block_header_serialize(&h, s) && stream_write_u64_le(s, nonce);
}

/* Deserialize from the start of s and require the failure contract: false,
 * with every field the decoder filled already released. */
static bool cbt_deser_clean_fail(struct byte_stream *s)
{
    struct compact_block_msg cb;
    s->read_pos = 0;
    bool rc = compact_block_msg_deserialize(&cb, s);
    bool ok = !rc && cb.short_txids == NULL && cb.num_short_txids == 0 &&
              cb.prefilled == NULL && cb.num_prefilled == 0;
    compact_block_msg_free(&cb);
    return ok;
}

static int test_cb_deser_truncated_prefix(void)
{
    int failures = 0;
    printf("compact_block_msg_deserialize truncated header/nonce/count... ");

    uint8_t one[1] = {0};
    struct byte_stream s;

    stream_init_from_data(&s, one, 0);
    if (!cbt_deser_clean_fail(&s)) failures++;

    stream_init_from_data(&s, one, 1);
    if (!cbt_deser_clean_fail(&s)) failures++;

    /* Header only: the nonce read fails. */
    stream_init(&s, 256);
    struct block_header h;
    cbt_header(&h);
    if (!block_header_serialize(&h, &s)) failures++;
    if (!cbt_deser_clean_fail(&s)) failures++;
    stream_free(&s);

    /* Header + nonce: the short txid count read fails. */
    stream_init(&s, 256);
    if (!cbt_prefix(&s, 5)) failures++;
    if (!cbt_deser_clean_fail(&s)) failures++;
    stream_free(&s);

    printf(failures ? "FAIL\n" : "OK\n");
    return failures;
}

static int test_cb_deser_count_and_body_failures(void)
{
    int failures = 0;
    printf("compact_block_msg_deserialize count caps and truncated bodies... ");

    uint8_t sid[SHORT_TXID_LEN] = {1, 2, 3, 4, 5, 6};
    struct byte_stream s;

    /* Short-id count over the cap is rejected before any id is read. */
    stream_init(&s, 256);
    cbt_prefix(&s, 5);
    stream_write_compact_size(&s, MAX_COMPACT_BLOCK_TXNS + 1);
    if (!cbt_deser_clean_fail(&s)) failures++;
    stream_free(&s);

    /* Two short ids declared, one present: the second read fails. */
    stream_init(&s, 256);
    cbt_prefix(&s, 5);
    stream_write_compact_size(&s, 2);
    stream_write_bytes(&s, sid, SHORT_TXID_LEN);
    if (!cbt_deser_clean_fail(&s)) failures++;
    stream_free(&s);

    /* Short ids empty, prefilled count missing. */
    stream_init(&s, 256);
    cbt_prefix(&s, 5);
    stream_write_compact_size(&s, 0);
    if (!cbt_deser_clean_fail(&s)) failures++;
    stream_free(&s);

    /* Prefilled count over the cap. */
    stream_init(&s, 256);
    cbt_prefix(&s, 5);
    stream_write_compact_size(&s, 0);
    stream_write_compact_size(&s, MAX_COMPACT_BLOCK_TXNS + 1);
    if (!cbt_deser_clean_fail(&s)) failures++;
    stream_free(&s);

    /* One prefilled tx declared, its differential index missing. */
    stream_init(&s, 256);
    cbt_prefix(&s, 5);
    stream_write_compact_size(&s, 0);
    stream_write_compact_size(&s, 1);
    if (!cbt_deser_clean_fail(&s)) failures++;
    stream_free(&s);

    /* One prefilled tx whose body is a single byte: tx decode fails. */
    stream_init(&s, 256);
    cbt_prefix(&s, 5);
    stream_write_compact_size(&s, 0);
    stream_write_compact_size(&s, 1);
    stream_write_compact_size(&s, 0);
    uint8_t one[1] = {0};
    stream_write_bytes(&s, one, 1);
    if (!cbt_deser_clean_fail(&s)) failures++;
    stream_free(&s);

    printf(failures ? "FAIL\n" : "OK\n");
    return failures;
}

static int test_cb_deser_alloc_faults(void)
{
    int failures = 0;
    printf("compact_block_msg_deserialize OOM on id and prefilled arrays... ");

    uint8_t sid[SHORT_TXID_LEN] = {1, 2, 3, 4, 5, 6};
    struct byte_stream s;

    stream_init(&s, 256);
    cbt_prefix(&s, 5);
    stream_write_compact_size(&s, 1);
    stream_write_bytes(&s, sid, SHORT_TXID_LEN);
    zcl_alloc_fault_fail_next("compact_deser_stxids");
    if (!cbt_deser_clean_fail(&s)) failures++;
    zcl_alloc_fault_clear();
    stream_free(&s);

    stream_init(&s, 256);
    cbt_prefix(&s, 5);
    stream_write_compact_size(&s, 0);
    stream_write_compact_size(&s, 1);
    zcl_alloc_fault_fail_next("compact_deser_prefilled");
    if (!cbt_deser_clean_fail(&s)) failures++;
    zcl_alloc_fault_clear();
    stream_free(&s);

    printf(failures ? "FAIL\n" : "OK\n");
    return failures;
}

static int test_cb_deser_success_shapes(void)
{
    int failures = 0;
    printf("compact_block_msg_deserialize empty and short-id bodies... ");

    uint8_t key[16];
    uint8_t ids[2 * SHORT_TXID_LEN] = {
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22
    };
    struct byte_stream s;
    struct compact_block_msg cb;

    /* Empty body: both counts zero. */
    stream_init(&s, 256);
    cbt_prefix(&s, 5);
    stream_write_compact_size(&s, 0);
    stream_write_compact_size(&s, 0);
    s.read_pos = 0;
    bool ok = compact_block_msg_deserialize(&cb, &s);
    compact_block_derive_key(&cb.header, 5, key);
    if (!ok || cb.nonce != 5 || cb.header.nTime != 1700000400 ||
        cb.num_short_txids != 0 || cb.short_txids != NULL ||
        cb.num_prefilled != 0 || cb.prefilled != NULL ||
        memcmp(cb.siphash_key, key, 16) != 0)
        failures++;
    compact_block_msg_free(&cb);
    stream_free(&s);

    /* Two short ids, no prefilled: bytes copied in wire order. */
    stream_init(&s, 256);
    cbt_prefix(&s, 5);
    stream_write_compact_size(&s, 2);
    stream_write_bytes(&s, ids, sizeof(ids));
    stream_write_compact_size(&s, 0);
    s.read_pos = 0;
    ok = compact_block_msg_deserialize(&cb, &s);
    if (!ok || cb.num_short_txids != 2 || cb.num_prefilled != 0 ||
        memcmp(cb.short_txids, ids, sizeof(ids)) != 0)
        failures++;
    compact_block_msg_free(&cb);
    stream_free(&s);

    printf(failures ? "FAIL\n" : "OK\n");
    return failures;
}

static int test_cb_deser_prefilled_differential(void)
{
    int failures = 0;
    printf("compact_block_msg_deserialize prefilled differential indices... ");

    /* Wire diffs 0, 1, 2 decode to absolute indices 0, 2, 5. */
    struct transaction txs[3];
    for (int i = 0; i < 3; i++)
        cbt_make_tx(&txs[i], (uint8_t)(0x71 + i), (uint32_t)(100 + i));
    const uint64_t diffs[3] = {0, 1, 2};
    const uint16_t want_index[3] = {0, 2, 5};

    struct byte_stream s;
    stream_init(&s, 1024);
    cbt_prefix(&s, 6);
    stream_write_compact_size(&s, 0);
    stream_write_compact_size(&s, 3);
    for (int i = 0; i < 3; i++) {
        stream_write_compact_size(&s, diffs[i]);
        transaction_serialize(&txs[i], &s);
    }
    s.read_pos = 0;

    struct compact_block_msg cb;
    bool ok = compact_block_msg_deserialize(&cb, &s);
    if (!ok || cb.num_prefilled != 3 || cb.nonce != 6)
        failures++;
    for (size_t i = 0; ok && i < 3 && i < cb.num_prefilled; i++) {
        if (cb.prefilled[i].index != want_index[i] ||
            cb.prefilled[i].tx.lock_time != 100 + i)
            failures++;
    }
    compact_block_msg_free(&cb);
    stream_free(&s);
    for (int i = 0; i < 3; i++)
        transaction_free(&txs[i]);

    printf(failures ? "FAIL\n" : "OK\n");
    return failures;
}

/* ── Characterization: compact_block_reconstruct ───────────────── */

/* Runs reconstruct with an optional armed allocation fault (NULL label =
 * none) and checks the hard-failure contract: false, no missing list, and an
 * out_block that block_free() leaves empty. */
static bool cbt_recon_hard_fail(const struct compact_block_msg *cb,
                                const struct transaction *mp, size_t nmp,
                                const char *fault_label, unsigned nth)
{
    struct block out;
    uint64_t *missing = NULL;
    size_t num_missing = 0;
    if (fault_label)
        zcl_alloc_fault_fail_nth(fault_label, nth);
    bool complete = compact_block_reconstruct(cb, mp, nmp, NULL, 0, &out,
                                              &missing, &num_missing);
    zcl_alloc_fault_clear();
    bool ok = !complete && missing == NULL && num_missing == 0 &&
              out.vtx == NULL && out.num_vtx == 0;
    free(missing);
    block_free(&out);
    return ok;
}

static int test_cb_recon_hard_fail_paths(void)
{
    int failures = 0;
    printf("compact_block_reconstruct range and OOM paths... ");

    /* Coinbase-only block: total 1, so a prefilled index of 1 is out of range. */
    struct block blk1;
    cbt_block(&blk1, 1, 0x20);
    struct compact_block_msg cb1;
    compact_block_from_block(&cb1, &blk1, 1);
    cb1.prefilled[0].index = 1;
    if (!cbt_recon_hard_fail(&cb1, NULL, 0, NULL, 0)) failures++;
    compact_block_msg_free(&cb1);
    block_free(&blk1);

    /* Coinbase + one short id: each allocation on the way can fail. */
    struct block blk2;
    cbt_block(&blk2, 2, 0x40);
    struct compact_block_msg cb2;
    compact_block_from_block(&cb2, &blk2, 2);

    struct transaction mp[1];
    cbt_make_tx(&mp[0], 0x41, 21);      /* hash matches block tx 1 */

    if (!cbt_recon_hard_fail(&cb2, NULL, 0, "tx_vin", 1)) failures++;
    if (!cbt_recon_hard_fail(&cb2, NULL, 0, "compact_filled_map", 1)) failures++;
    if (!cbt_recon_hard_fail(&cb2, NULL, 0, "compact_missing", 1)) failures++;
    if (!cbt_recon_hard_fail(&cb2, mp, 1, "compact_sid_table", 1)) failures++;
    /* Prefilled copy is the first tx_vin alloc; the source copy is the second. */
    if (!cbt_recon_hard_fail(&cb2, mp, 1, "tx_vin", 2)) failures++;

    transaction_free(&mp[0]);
    compact_block_msg_free(&cb2);
    block_free(&blk2);

    printf(failures ? "FAIL\n" : "OK\n");
    return failures;
}

static int test_cb_recon_full_match_order(void)
{
    int failures = 0;
    printf("compact_block_reconstruct full match keeps block order... ");

    struct block blk;
    cbt_block(&blk, 3, 0x30);           /* tx 1 = 0x31, tx 2 = 0x32 */
    struct compact_block_msg cb;
    compact_block_from_block(&cb, &blk, 77);

    /* Mempool supplies the two txs in reverse order. */
    struct transaction mp[2];
    cbt_make_tx(&mp[0], 0x32, 22);
    cbt_make_tx(&mp[1], 0x31, 21);

    struct block out;
    uint64_t *missing = NULL;
    size_t nmiss = 99;
    bool complete = compact_block_reconstruct(&cb, mp, 2, NULL, 0, &out,
                                              &missing, &nmiss);
    if (!complete || missing != NULL || nmiss != 0 || out.num_vtx != 3 ||
        out.header.nTime != 1700000400 ||
        out.vtx[0].hash.data[0] != 0x30 ||
        out.vtx[1].hash.data[0] != 0x31 || out.vtx[1].lock_time != 21 ||
        out.vtx[2].hash.data[0] != 0x32 || out.vtx[2].lock_time != 22)
        failures++;

    free(missing);
    block_free(&out);
    transaction_free(&mp[0]);
    transaction_free(&mp[1]);
    compact_block_msg_free(&cb);
    block_free(&blk);

    printf(failures ? "FAIL\n" : "OK\n");
    return failures;
}

static int test_cb_recon_extra_sources(void)
{
    int failures = 0;
    printf("compact_block_reconstruct extra_txs as short-id sources... ");

    struct block blk;
    cbt_block(&blk, 3, 0x30);
    struct compact_block_msg cb;
    compact_block_from_block(&cb, &blk, 77);

    /* Case A: mempool empty, both txs come from extra_txs. */
    struct transaction extra[2];
    cbt_make_tx(&extra[0], 0x32, 22);
    cbt_make_tx(&extra[1], 0x31, 21);
    struct block out;
    uint64_t *missing = NULL;
    size_t nmiss = 99;
    bool complete = compact_block_reconstruct(&cb, NULL, 0, extra, 2, &out,
                                              &missing, &nmiss);
    if (!complete || nmiss != 0 || out.vtx[1].lock_time != 21 ||
        out.vtx[2].lock_time != 22)
        failures++;
    free(missing);
    block_free(&out);

    /* Case B: source 0 is mempool, source 1 is extra_txs[0]. */
    struct transaction mp[1];
    cbt_make_tx(&mp[0], 0x31, 21);
    struct transaction extra_b[1];
    cbt_make_tx(&extra_b[0], 0x32, 22);
    missing = NULL;
    nmiss = 99;
    complete = compact_block_reconstruct(&cb, mp, 1, extra_b, 1, &out,
                                         &missing, &nmiss);
    if (!complete || nmiss != 0 || out.vtx[1].hash.data[0] != 0x31 ||
        out.vtx[2].hash.data[0] != 0x32)
        failures++;
    free(missing);
    block_free(&out);

    transaction_free(&extra[0]);
    transaction_free(&extra[1]);
    transaction_free(&mp[0]);
    transaction_free(&extra_b[0]);
    compact_block_msg_free(&cb);
    block_free(&blk);

    printf(failures ? "FAIL\n" : "OK\n");
    return failures;
}

static int test_cb_recon_partial_missing(void)
{
    int failures = 0;
    printf("compact_block_reconstruct partial and no-source missing lists... ");

    /* Case A: 4 txs, mempool has only tx 1. Missing slots are 2 and 3. */
    struct block blk;
    cbt_block(&blk, 4, 0x40);
    struct compact_block_msg cb;
    compact_block_from_block(&cb, &blk, 78);
    struct transaction mp[1];
    cbt_make_tx(&mp[0], 0x41, 21);

    struct block out;
    uint64_t *missing = NULL;
    size_t nmiss = 0;
    bool complete = compact_block_reconstruct(&cb, mp, 1, NULL, 0, &out,
                                              &missing, &nmiss);
    if (complete || nmiss != 2 || missing == NULL ||
        missing[0] != 2 || missing[1] != 3 || out.num_vtx != 4 ||
        out.vtx[1].hash.data[0] != 0x41)
        failures++;
    free(missing);
    block_free(&out);
    transaction_free(&mp[0]);
    compact_block_msg_free(&cb);
    block_free(&blk);

    /* Case B: no sources at all, so slot 1 is missing. */
    struct block blk2;
    cbt_block(&blk2, 2, 0x50);
    struct compact_block_msg cb2;
    compact_block_from_block(&cb2, &blk2, 79);
    missing = NULL;
    nmiss = 0;
    complete = compact_block_reconstruct(&cb2, NULL, 0, NULL, 0, &out,
                                         &missing, &nmiss);
    if (complete || nmiss != 1 || missing == NULL || missing[0] != 1)
        failures++;
    free(missing);
    block_free(&out);
    compact_block_msg_free(&cb2);
    block_free(&blk2);

    printf(failures ? "FAIL\n" : "OK\n");
    return failures;
}

static int test_cb_recon_duplicate_hash_first_wins(void)
{
    int failures = 0;
    printf("compact_block_reconstruct duplicate mempool hash keeps first... ");

    struct block blk;
    cbt_block(&blk, 2, 0x41);
    memset(blk.vtx[1].hash.data, 0x41, 32);   /* block tx 1 hash is now 0x41 */
    struct compact_block_msg cb;
    compact_block_from_block(&cb, &blk, 80);

    struct transaction mp[2];
    cbt_make_tx(&mp[0], 0x41, 1);
    cbt_make_tx(&mp[1], 0x41, 2);

    struct block out;
    uint64_t *missing = NULL;
    size_t nmiss = 0;
    bool complete = compact_block_reconstruct(&cb, mp, 2, NULL, 0, &out,
                                              &missing, &nmiss);
    if (!complete || out.vtx[1].lock_time != 1)
        failures++;
    free(missing);
    block_free(&out);
    transaction_free(&mp[0]);
    transaction_free(&mp[1]);
    compact_block_msg_free(&cb);
    block_free(&blk);

    printf(failures ? "FAIL\n" : "OK\n");
    return failures;
}

static int test_cb_recon_wire_decoded_short_ids(void)
{
    int failures = 0;
    printf("compact_block_reconstruct wire-decoded cb resolves short ids... ");

    struct transaction mp[2];
    cbt_make_tx(&mp[0], 0x61, 1);
    cbt_make_tx(&mp[1], 0x62, 2);
    struct transaction coinbase;
    cbt_make_tx(&coinbase, 0x70, 7);

    /* The SipHash key is derived from the same header and nonce the wire
     * carries, so the short ids are computed from that key. */
    struct block_header h;
    cbt_header(&h);
    uint8_t key[16];
    compact_block_derive_key(&h, 3, key);
    uint8_t ids[2 * SHORT_TXID_LEN];
    compact_block_short_txid(key, &mp[0].hash, ids);
    compact_block_short_txid(key, &mp[1].hash, ids + SHORT_TXID_LEN);

    /* Wire: nonce 3, two short ids, one prefilled coinbase at index 0. */
    struct byte_stream s;
    stream_init(&s, 1024);
    cbt_prefix(&s, 3);
    stream_write_compact_size(&s, 2);
    stream_write_bytes(&s, ids, sizeof(ids));
    stream_write_compact_size(&s, 1);
    stream_write_compact_size(&s, 0);
    transaction_serialize(&coinbase, &s);
    s.read_pos = 0;

    struct compact_block_msg cb;
    bool deser = compact_block_msg_deserialize(&cb, &s);

    struct block out;
    block_init(&out);
    uint64_t *missing = NULL;
    size_t nmiss = 0;
    bool complete = deser && compact_block_reconstruct(&cb, mp, 2, NULL, 0,
                                                       &out, &missing, &nmiss);
    if (!complete || out.num_vtx != 3 || out.vtx[0].lock_time != 7 ||
        out.vtx[1].hash.data[0] != 0x61 || out.vtx[2].hash.data[0] != 0x62)
        failures++;
    free(missing);
    block_free(&out);

    /* Same cb, mempool holds only the first tx: slot 2 is missing. */
    missing = NULL;
    nmiss = 0;
    complete = deser && compact_block_reconstruct(&cb, mp, 1, NULL, 0, &out,
                                                  &missing, &nmiss);
    if (complete || nmiss != 1 || missing == NULL || missing[0] != 2)
        failures++;
    free(missing);
    block_free(&out);

    compact_block_msg_free(&cb);
    stream_free(&s);
    transaction_free(&coinbase);
    transaction_free(&mp[0]);
    transaction_free(&mp[1]);

    printf(failures ? "FAIL\n" : "OK\n");
    return failures;
}

int test_compact_blocks(void)
{
    int failures = 0;

    failures += test_siphash_key_and_short_txid();
    failures += test_compact_block_from_block_basic();
    failures += test_compact_block_msg_roundtrip();
    failures += test_compact_block_reconstruct_hard_failure();
    failures += test_compact_block_reconstruct_matches();
    failures += test_compact_block_fill_missing();
    failures += test_block_txn_request_roundtrip();
    failures += test_block_txn_response_init_and_coinbase();
    failures += test_process_cmpctblock_oom_pending_stash();
    failures += test_cb_deser_truncated_prefix();
    failures += test_cb_deser_count_and_body_failures();
    failures += test_cb_deser_alloc_faults();
    failures += test_cb_deser_success_shapes();
    failures += test_cb_deser_prefilled_differential();
    failures += test_cb_recon_hard_fail_paths();
    failures += test_cb_recon_full_match_order();
    failures += test_cb_recon_extra_sources();
    failures += test_cb_recon_partial_missing();
    failures += test_cb_recon_duplicate_hash_first_wins();
    failures += test_cb_recon_wire_decoded_short_ids();

    return failures;
}
