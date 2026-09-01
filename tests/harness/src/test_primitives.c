/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "chain/pow.h"
#include "core/serialize.h"
#include "util/safe_alloc.h"

int test_primitives(void)
{
    int failures = 0;

    printf("transaction_init zeroes state... ");
    {
        struct transaction tx;
        transaction_init(&tx);

        if (tx.vin == NULL && tx.vout == NULL &&
            tx.num_vin == 0 && tx.num_vout == 0 &&
            tx.version == 1 && tx.lock_time == 0)
            printf("OK\n");
        else {
            printf("FAIL (num_vin=%zu, num_vout=%zu, ver=%d)\n",
                   tx.num_vin, tx.num_vout, tx.version);
            failures++;
        }
        transaction_free(&tx);
    }

    printf("transaction_free is safe on zeroed tx... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_free(&tx);
        transaction_free(&tx);
        printf("OK\n");
    }

    printf("transaction_alloc allocates vin/vout... ");
    {
        struct transaction tx;
        transaction_init(&tx);

        bool ok = transaction_alloc(&tx, 2, 3);
        if (ok && tx.vin != NULL && tx.vout != NULL &&
            tx.num_vin == 2 && tx.num_vout == 3)
            printf("OK\n");
        else {
            printf("FAIL (ok=%d, num_vin=%zu, num_vout=%zu)\n",
                   ok, tx.num_vin, tx.num_vout);
            failures++;
        }
        transaction_free(&tx);
    }

    printf("transaction_alloc zero-size leaves pointers NULL (no calloc(0) stub leak)... ");
    {
        /* Regression for fuzz_block-discovered 1-byte leak in
         * transaction_deserialize: calling transaction_alloc(_, _, 0)
         * previously left tx->vout = calloc(0,_) as a glibc-unique
         * 1-byte pointer, which the deserializer then overwrote
         * unconditionally at the "read num_vout" step — leaking the
         * stub. Zero-size must mean "no array", not "1-byte dummy". */
        struct transaction a;
        transaction_init(&a);
        bool ok_a = transaction_alloc(&a, 0, 0);
        bool clean_a = ok_a && a.vin == NULL && a.vout == NULL &&
                       a.num_vin == 0 && a.num_vout == 0;

        struct transaction b;
        transaction_init(&b);
        bool ok_b = transaction_alloc(&b, 0, 2);
        bool clean_b = ok_b && b.vin == NULL && b.vout != NULL &&
                       b.num_vin == 0 && b.num_vout == 2;

        struct transaction c;
        transaction_init(&c);
        bool ok_c = transaction_alloc(&c, 3, 0);
        bool clean_c = ok_c && c.vin != NULL && c.vout == NULL &&
                       c.num_vin == 3 && c.num_vout == 0;

        /* Simulate the deserializer overwrite: previously this step
         * leaked the prior 1-byte stub at a.vout. With the fix it's
         * a NULL→new assignment, which is allocation-neutral. */
        a.vout = zcl_calloc(2, sizeof(struct tx_out), "test_vout");
        a.num_vout = 2;

        if (clean_a && clean_b && clean_c && a.vout != NULL)
            printf("OK\n");
        else {
            printf("FAIL (a=%d b=%d c=%d)\n", clean_a, clean_b, clean_c);
            failures++;
        }
        transaction_free(&a);
        transaction_free(&b);
        transaction_free(&c);
    }

    printf("transaction_is_coinbase true for coinbase tx... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);

        outpoint_set_null(&tx.vin[0].prevout);
        tx.vin[0].sequence = UINT32_MAX;

        if (transaction_is_coinbase(&tx))
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
        transaction_free(&tx);
    }

    printf("transaction_is_coinbase false for regular tx... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);

        memset(tx.vin[0].prevout.hash.data, 0xAB, 32);
        tx.vin[0].prevout.n = 0;

        if (!transaction_is_coinbase(&tx))
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
        transaction_free(&tx);
    }

    printf("transaction_is_coinbase false for multi-input tx... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 2, 1);

        outpoint_set_null(&tx.vin[0].prevout);
        memset(tx.vin[1].prevout.hash.data, 0x01, 32);
        tx.vin[1].prevout.n = 0;

        if (!transaction_is_coinbase(&tx))
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
        transaction_free(&tx);
    }

    printf("transaction_serialize + deserialize roundtrip... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        tx.version = 1;
        tx.overwintered = false;
        transaction_alloc(&tx, 1, 1);

        memset(tx.vin[0].prevout.hash.data, 0xAA, 32);
        tx.vin[0].prevout.n = 7;
        tx.vin[0].script_sig.size = 2;
        tx.vin[0].script_sig.data[0] = OP_1;
        tx.vin[0].script_sig.data[1] = OP_1;
        tx.vin[0].sequence = 0xFFFFFFFF;

        tx.vout[0].value = 50000;
        tx.vout[0].script_pub_key.size = 3;
        tx.vout[0].script_pub_key.data[0] = OP_DUP;
        tx.vout[0].script_pub_key.data[1] = OP_HASH160;
        tx.vout[0].script_pub_key.data[2] = OP_EQUAL;

        struct byte_stream s;
        stream_init(&s, 512);
        bool ser_ok = transaction_serialize(&tx, &s);

        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        struct transaction tx2;
        transaction_init(&tx2);
        bool deser_ok = transaction_deserialize(&tx2, &r);

        bool match = (tx2.version == tx.version &&
                      tx2.num_vin == tx.num_vin &&
                      tx2.num_vout == tx.num_vout &&
                      tx2.vin[0].prevout.n == 7 &&
                      memcmp(tx2.vin[0].prevout.hash.data,
                             tx.vin[0].prevout.hash.data, 32) == 0 &&
                      tx2.vout[0].value == 50000 &&
                      tx2.vout[0].script_pub_key.size == 3);

        if (ser_ok && deser_ok && match)
            printf("OK\n");
        else {
            printf("FAIL (ser=%d, deser=%d, match=%d)\n",
                   ser_ok, deser_ok, match);
            failures++;
        }

        transaction_free(&tx);
        transaction_free(&tx2);
        stream_free(&s);
    }

    printf("transaction_compute_hash produces non-zero hash... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        tx.version = 1;
        tx.overwintered = false;
        transaction_alloc(&tx, 1, 1);

        outpoint_set_null(&tx.vin[0].prevout);
        tx.vin[0].sequence = UINT32_MAX;
        tx.vout[0].value = 50 * 100000000LL;
        tx.vout[0].script_pub_key.size = 1;
        tx.vout[0].script_pub_key.data[0] = OP_TRUE;

        transaction_compute_hash(&tx);
        if (!uint256_is_null(&tx.hash))
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
        transaction_free(&tx);
    }

    printf("transaction_get_value_out sums outputs... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 0, 2);

        tx.vout[0].value = 100000;
        tx.vout[1].value = 200000;

        int64_t total = transaction_get_value_out(&tx);
        if (total == 300000)
            printf("OK\n");
        else {
            printf("FAIL (total=%" PRId64 ")\n", total);
            failures++;
        }
        transaction_free(&tx);
    }

    printf("block_header_init sets defaults... ");
    {
        struct block_header h;
        block_header_init(&h);

        if (h.nVersion == 4 && h.nBits == 0 && h.nTime == 0 &&
            uint256_is_null(&h.hashPrevBlock) &&
            uint256_is_null(&h.hashMerkleRoot))
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("block_header_is_null on fresh header... ");
    {
        struct block_header h;
        block_header_init(&h);

        if (block_header_is_null(&h))
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("block_header_get_hash produces non-zero hash... ");
    {
        struct block_header h;
        block_header_init(&h);
        h.nVersion = 4;
        h.nBits = 0x2007ffff;
        h.nTime = 1477671596;
        memset(h.hashPrevBlock.data, 0x01, 32);
        memset(h.hashMerkleRoot.data, 0x02, 32);

        struct uint256 hash;
        block_header_get_hash(&h, &hash);

        if (!uint256_is_null(&hash))
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("block_header_serialize + deserialize roundtrip... ");
    {
        struct block_header h;
        block_header_init(&h);
        h.nVersion = 4;
        h.nBits = 0x1d00ffff;
        h.nTime = 1700000000;
        memset(h.hashPrevBlock.data, 0xAA, 32);
        memset(h.hashMerkleRoot.data, 0xBB, 32);
        memset(h.hashFinalSaplingRoot.data, 0xCC, 32);
        memset(h.nNonce.data, 0xDD, 32);
        h.nSolutionSize = 0;

        struct byte_stream s;
        stream_init(&s, 2048);
        bool ser_ok = block_header_serialize(&h, &s);

        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        struct block_header h2;
        block_header_init(&h2);
        bool deser_ok = block_header_deserialize(&h2, &r);

        bool match = (h2.nVersion == 4 &&
                      h2.nBits == 0x1d00ffff &&
                      h2.nTime == 1700000000 &&
                      memcmp(h2.hashPrevBlock.data, h.hashPrevBlock.data, 32) == 0 &&
                      memcmp(h2.hashMerkleRoot.data, h.hashMerkleRoot.data, 32) == 0 &&
                      memcmp(h2.hashFinalSaplingRoot.data, h.hashFinalSaplingRoot.data, 32) == 0);

        if (ser_ok && deser_ok && match)
            printf("OK\n");
        else {
            printf("FAIL (ser=%d, deser=%d, match=%d)\n",
                   ser_ok, deser_ok, match);
            failures++;
        }
        stream_free(&s);
    }

    printf("block_locator_init zeroes state... ");
    {
        struct block_locator loc;
        block_locator_init(&loc);

        if (loc.vhave == NULL && loc.num_hashes == 0)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("block_locator_serialize + deserialize roundtrip... ");
    {
        struct block_locator loc;
        block_locator_init(&loc);
        loc.num_hashes = 3;
        loc.vhave = zcl_calloc(3, sizeof(struct uint256), "test_locator_hashes");
        memset(loc.vhave[0].data, 0x11, 32);
        memset(loc.vhave[1].data, 0x22, 32);
        memset(loc.vhave[2].data, 0x33, 32);

        struct byte_stream s;
        stream_init(&s, 256);
        bool ser_ok = block_locator_serialize(&loc, &s);

        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        struct block_locator loc2;
        block_locator_init(&loc2);
        bool deser_ok = block_locator_deserialize(&loc2, &r);

        bool match = (loc2.num_hashes == 3 &&
                      memcmp(loc2.vhave[0].data, loc.vhave[0].data, 32) == 0 &&
                      memcmp(loc2.vhave[1].data, loc.vhave[1].data, 32) == 0 &&
                      memcmp(loc2.vhave[2].data, loc.vhave[2].data, 32) == 0);

        if (ser_ok && deser_ok && match)
            printf("OK\n");
        else {
            printf("FAIL (ser=%d, deser=%d, match=%d)\n",
                   ser_ok, deser_ok, match);
            failures++;
        }

        block_locator_free(&loc);
        block_locator_free(&loc2);
        stream_free(&s);
    }

    printf("block_locator_free on empty locator... ");
    {
        struct block_locator loc;
        block_locator_init(&loc);
        block_locator_free(&loc);
        block_locator_free(&loc);
        printf("OK\n");
    }

    printf("outpoint_set_null + outpoint_is_null... ");
    {
        struct outpoint op;
        outpoint_set_null(&op);

        if (outpoint_is_null(&op))
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("outpoint_is_null false for non-null... ");
    {
        struct outpoint op;
        memset(op.hash.data, 0xFF, 32);
        op.n = 0;

        if (!outpoint_is_null(&op))
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("outpoint_cmp ordering... ");
    {
        struct outpoint a, b;
        memset(a.hash.data, 0x01, 32);
        a.n = 0;
        memset(b.hash.data, 0x01, 32);
        b.n = 1;

        int cmp = outpoint_cmp(&a, &b);
        int cmp_eq = outpoint_cmp(&a, &a);
        int cmp_rev = outpoint_cmp(&b, &a);

        if (cmp < 0 && cmp_eq == 0 && cmp_rev > 0)
            printf("OK\n");
        else {
            printf("FAIL (cmp=%d, eq=%d, rev=%d)\n", cmp, cmp_eq, cmp_rev);
            failures++;
        }
    }

    printf("tx_out_set_null + tx_out_is_null... ");
    {
        struct tx_out out;
        tx_out_set_null(&out);

        if (tx_out_is_null(&out) && out.value == -1)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("transaction_copy produces independent copy... ");
    {
        struct transaction src;
        transaction_init(&src);
        src.version = 1;
        src.overwintered = false;
        transaction_alloc(&src, 1, 1);
        src.vout[0].value = 12345;
        outpoint_set_null(&src.vin[0].prevout);

        struct transaction dst;
        transaction_init(&dst);
        bool ok = transaction_copy(&dst, &src);

        if (ok && dst.num_vin == 1 && dst.num_vout == 1 &&
            dst.vout[0].value == 12345 && dst.vin != src.vin)
            printf("OK\n");
        else {
            printf("FAIL (ok=%d)\n", ok);
            failures++;
        }

        transaction_free(&src);
        transaction_free(&dst);
    }

    return failures;
}
