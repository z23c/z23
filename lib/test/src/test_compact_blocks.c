/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "net/compact_blocks.h"
#include "core/hash.h"
#include <string.h>
#include <stdio.h>

int test_compact_blocks(void)
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

    /* ── Regression: hard-failure returns must still initialize out_block ──
     *
     * lib/test/fuzz_seeds/p2p/crash-478b30c0482cf3e2842fa459987a7a2e5374e708.bin
     * is a 152-byte cmpctblock from an unauthenticated peer whose payload
     * decodes to a well-formed header, a nonce, and then a short-txid count
     * of 0 and a prefilled count of 0. total == 0 takes the very first
     * failure return in compact_block_reconstruct(). Before the fix that
     * return ran BEFORE block_init(out_block), so process_cmpctblock()'s
     * `else { block_free(&out_block); }` walked whatever the stack held at
     * that frame offset: transaction_free() over a stale pointer for a
     * stale count. The background fuzzer caught it as an ASan
     * heap-buffer-overflow in transaction_free <- block_free <-
     * process_cmpctblock; it only ever fires in a long-lived process,
     * because a freshly-mapped stack reads back as zero.
     *
     * The poison below is what a long-lived process supplies for free.
     * Without the fix these assertions fail; with the assertions removed
     * the block_free() at the end walks 2^40 transaction slots. */
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
