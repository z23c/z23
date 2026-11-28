/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "base/safe_alloc.h"
#include "primitives/transaction_v6_decode.h"
#include "bloom/bloom.h"
#include "chain/chainparams.h"
#include "validation/check_transaction.h"
#include "validation/tx_verifier.h"
#include "validation/contextual_check_tx.h"
#include "coins/undo.h"
#include "bloom/merkleblock.h"

static int test_tx_outpoint_alloc_and_value(void)
{
    int failures = 0;

    printf("outpoint init/null... ");
    {
        struct outpoint op;
        outpoint_set_null(&op);
        if (outpoint_is_null(&op))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("tx_out init/null... ");
    {
        struct tx_out out;
        tx_out_set_null(&out);
        if (tx_out_is_null(&out) && out.value == -1)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("transaction alloc/free... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        if (transaction_alloc(&tx, 2, 3) && tx.num_vin == 2 && tx.num_vout == 3 &&
            outpoint_is_null(&tx.vin[0].prevout) && tx_out_is_null(&tx.vout[0])) {
            transaction_free(&tx);
            if (tx.vin == NULL && tx.vout == NULL)
                printf("OK\n");
            else { printf("FAIL\n"); failures++; }
        } else { printf("FAIL\n"); failures++; }
    }

    printf("transaction_get_value_out... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 0, 2);
        tx.vout[0].value = 50 * COIN;
        tx.vout[1].value = 25 * COIN;
        int64_t total = transaction_get_value_out(&tx);
        if (total == 75 * COIN)
            printf("OK (%" PRId64 ")\n", total);
        else { printf("FAIL (%" PRId64 ")\n", total); failures++; }
        transaction_free(&tx);
    }

    return failures;
}

static int test_tx_coinbase_bloom_and_merkle_roots(void)
{
    int failures = 0;

    printf("transaction_is_coinbase... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        /* vin[0] prevout is null by default -> coinbase */
        tx.vout[0].value = 10 * COIN;
        if (transaction_is_coinbase(&tx))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        transaction_free(&tx);
    }

    printf("bloom_filter insert/contains... ");
    {
        struct bloom_filter bf;
        bloom_filter_init(&bf, 10, 0.000001, 2147483649U, BLOOM_UPDATE_ALL);
        unsigned char data1[] = {0x99, 0x10, 0x8a, 0xd8};
        unsigned char data2[] = {0x19, 0x10, 0x8a, 0xd8};
        unsigned char data3[] = {0xab, 0xcd, 0xef, 0x01};
        bloom_filter_insert(&bf, data1, 4);
        bloom_filter_insert(&bf, data2, 4);
        if (bloom_filter_contains(&bf, data1, 4) &&
            bloom_filter_contains(&bf, data2, 4) &&
            !bloom_filter_contains(&bf, data3, 4))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        bloom_filter_free(&bf);
    }

    printf("bloom_filter uint256... ");
    {
        struct bloom_filter bf;
        bloom_filter_init(&bf, 10, 0.000001, 0, BLOOM_UPDATE_NONE);
        struct uint256 h;
        uint256_set_null(&h);
        h.data[0] = 0xDE;
        h.data[31] = 0xAD;
        bloom_filter_insert_uint256(&bf, &h);
        if (bloom_filter_contains_uint256(&bf, &h)) {
            struct uint256 h2;
            uint256_set_null(&h2);
            h2.data[0] = 0xFF;
            if (!bloom_filter_contains_uint256(&bf, &h2))
                printf("OK\n");
            else { printf("FAIL (false positive)\n"); failures++; }
        } else { printf("FAIL\n"); failures++; }
        bloom_filter_free(&bf);
    }

    printf("rolling_bloom insert/contains... ");
    {
        struct rolling_bloom_filter rbf;
        rolling_bloom_init(&rbf, 10, 0.000001);
        unsigned char data1[] = {1, 2, 3, 4};
        unsigned char data2[] = {5, 6, 7, 8};
        rolling_bloom_insert(&rbf, data1, 4);
        if (rolling_bloom_contains(&rbf, data1, 4) &&
            !rolling_bloom_contains(&rbf, data2, 4))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        rolling_bloom_free(&rbf);
    }

    printf("compute_merkle_root 1 tx... ");
    {
        struct uint256 tx;
        memset(tx.data, 0xAA, 32);
        struct uint256 root = compute_merkle_root(&tx, 1);
        if (uint256_cmp(&root, &tx) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("compute_merkle_root 2 txs... ");
    {
        struct uint256 txids[2];
        memset(txids[0].data, 0x11, 32);
        memset(txids[1].data, 0x22, 32);
        struct uint256 root = compute_merkle_root(txids, 2);
        struct uint256 expected;
        merkle_hash_pair(&txids[0], &txids[1], &expected);
        if (uint256_cmp(&root, &expected) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

static int test_tx_partial_merkle_build_extract(void)
{
    int failures = 0;

    printf("partial_merkle_tree build/extract... ");
    {
        struct uint256 txids[4];
        for (int i = 0; i < 4; i++)
            memset(txids[i].data, (unsigned char)(i + 1), 32);
        bool match[4] = {false, true, false, false};

        struct partial_merkle_tree t;
        merkle_tree_init(&t);
        if (merkle_tree_build(&t, txids, 4, match, 4)) {
            struct uint256 matched[4];
            size_t num_matched;
            struct uint256 root;
            if (merkle_tree_extract(&t, matched, &num_matched, &root) &&
                num_matched == 1 &&
                uint256_cmp(&matched[0], &txids[1]) == 0) {
                struct uint256 full_root = compute_merkle_root(txids, 4);
                if (uint256_cmp(&root, &full_root) == 0)
                    printf("OK\n");
                else { printf("FAIL (root mismatch)\n"); failures++; }
            } else { printf("FAIL (extract)\n"); failures++; }
        } else { printf("FAIL (build)\n"); failures++; }
        merkle_tree_free(&t);
    }

    return failures;
}

static int test_tx_sighash_type_anyone_can_pay(void)
{
    int failures = 0;

    printf("sighash_type... ");
    {
        struct sighash_type s = sighash_type_default();
        if (s.raw == SIGHASH_ALL &&
            sighash_get_base_type(s) == BASE_SIGHASH_ALL &&
            sighash_is_defined(s) &&
            !sighash_has_anyone_can_pay(s)) {
            struct sighash_type s2 = sighash_with_anyone_can_pay(s, true);
            if (sighash_has_anyone_can_pay(s2) && s2.raw == (SIGHASH_ALL | SIGHASH_ANYONECANPAY))
                printf("OK\n");
            else { printf("FAIL\n"); failures++; }
        } else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

/* Write each value, then read them back in order: true when every write and
 * read succeeds, each read returns its value, and the stream holds no error. */
static bool stream_u64_roundtrip(bool (*put)(struct byte_stream *, uint64_t),
                                 bool (*get)(struct byte_stream *, uint64_t *),
                                 const uint64_t *vals, size_t n)
{
    struct byte_stream s;
    stream_init(&s, 64);
    bool ok = true;
    for (size_t i = 0; ok && i < n; i++)
        ok = put(&s, vals[i]);
    s.read_pos = 0;
    for (size_t i = 0; ok && i < n; i++) {
        uint64_t v = 0;
        ok = get(&s, &v) && v == vals[i];
    }
    ok = ok && !s.error;
    stream_free(&s);
    return ok;
}

static int test_tx_stream_scalar_roundtrips(void)
{
    int failures = 0;

    printf("stream write/read u32... ");
    {
        struct byte_stream s;
        stream_init(&s, 64);
        stream_write_u32_le(&s, 0xDEADBEEF);
        stream_write_u32_le(&s, 0x12345678);
        s.read_pos = 0;
        uint32_t v1 = 0, v2 = 0;
        bool ok = stream_read_u32_le(&s, &v1) && stream_read_u32_le(&s, &v2);
        if (ok && v1 == 0xDEADBEEF && v2 == 0x12345678 && s.size == 8)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&s);
    }

    printf("stream compact_size roundtrip... ");
    {
        static const uint64_t vals[] = {0, 252, 253, 0x10000, 0x100000000ULL};
        if (stream_u64_roundtrip(stream_write_compact_size, stream_read_compact_size,
                                 vals, sizeof(vals) / sizeof(vals[0])))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("stream varint roundtrip... ");
    {
        static const uint64_t vals[] = {0, 127, 128, 0xFFFF, 0xFFFFFFFFULL};
        if (stream_u64_roundtrip(stream_write_varint, stream_read_varint,
                                 vals, sizeof(vals) / sizeof(vals[0])))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("stream from_data read-only... ");
    {
        unsigned char data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        struct byte_stream s;
        stream_init_from_data(&s, data, sizeof(data));
        uint32_t v1 = 0, v2 = 0;
        bool ok = stream_read_u32_le(&s, &v1) && stream_read_u32_le(&s, &v2);
        if (ok && v1 == 0x04030201 && v2 == 0x08070605 && stream_remaining(&s) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

static int test_tx_header_and_outpoint_serde(void)
{
    int failures = 0;

    printf("block_header serialize/deserialize roundtrip... ");
    {
        struct block_header h;
        block_header_init(&h);
        h.nVersion = 4;
        h.nTime = 1234567890;
        h.nBits = 0x1d00ffff;
        memset(h.hashPrevBlock.data, 0xAA, 32);
        memset(h.hashMerkleRoot.data, 0xBB, 32);

        struct byte_stream s;
        stream_init(&s, 256);
        block_header_serialize(&h, &s);

        struct block_header h2;
        block_header_init(&h2);
        s.read_pos = 0;
        block_header_deserialize(&h2, &s);

        if (h2.nVersion == 4 && h2.nTime == 1234567890 &&
            h2.nBits == 0x1d00ffff &&
            uint256_cmp(&h2.hashPrevBlock, &h.hashPrevBlock) == 0 &&
            uint256_cmp(&h2.hashMerkleRoot, &h.hashMerkleRoot) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&s);
    }

    printf("block_header_get_hash... ");
    {
        struct block_header h;
        block_header_init(&h);
        h.nTime = 1000;
        h.nBits = 0x207fffff;
        struct uint256 hash;
        block_header_get_hash(&h, &hash);
        if (!uint256_is_null(&hash))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("outpoint serialize/deserialize... ");
    {
        struct outpoint op = { .n = 42 };
        memset(op.hash.data, 0xAB, 32);
        struct byte_stream s;
        stream_init(&s, 64);
        outpoint_serialize(&op, &s);
        s.read_pos = 0;
        struct outpoint op2;
        outpoint_deserialize(&op2, &s);
        if (op2.n == 42 && memcmp(op2.hash.data, op.hash.data, 32) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&s);
    }

    return failures;
}

static int test_tx_vin_vout_and_hash(void)
{
    int failures = 0;

    printf("tx_in serialize/deserialize... ");
    {
        struct tx_in in;
        tx_in_init(&in);
        memset(in.prevout.hash.data, 0xCC, 32);
        in.prevout.n = 7;
        in.sequence = 0xFFFFFFFE;
        in.script_sig.data[0] = 0x01;
        in.script_sig.data[1] = 0x02;
        in.script_sig.size = 2;
        struct byte_stream s;
        stream_init(&s, 128);
        tx_in_serialize(&in, &s);
        s.read_pos = 0;
        struct tx_in in2;
        tx_in_init(&in2);
        tx_in_deserialize(&in2, &s);
        if (in2.prevout.n == 7 && in2.sequence == 0xFFFFFFFE &&
            in2.script_sig.size == 2 &&
            in2.script_sig.data[0] == 0x01 && in2.script_sig.data[1] == 0x02)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&s);
    }

    printf("tx_out serialize/deserialize... ");
    {
        struct tx_out out;
        out.value = 100000000;
        out.script_pub_key.size = 3;
        out.script_pub_key.data[0] = OP_DUP;
        out.script_pub_key.data[1] = OP_HASH160;
        out.script_pub_key.data[2] = OP_CHECKSIG;
        struct byte_stream s;
        stream_init(&s, 128);
        tx_out_serialize(&out, &s);
        s.read_pos = 0;
        struct tx_out out2;
        tx_out_set_null(&out2);
        tx_out_deserialize(&out2, &s);
        if (out2.value == 100000000 && out2.script_pub_key.size == 3 &&
            out2.script_pub_key.data[0] == OP_DUP)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&s);
    }

    printf("transaction_compute_hash... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.version = 1;
        tx.vout[0].value = 50 * COIN;
        transaction_compute_hash(&tx);
        if (!uint256_is_null(&tx.hash))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        transaction_free(&tx);
    }

    return failures;
}

static int test_tx_signature_hash_sprout_sapling(void)
{
    int failures = 0;

    printf("signature_hash sprout... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.version = 1;
        tx.overwintered = false;
        tx.vin[0].sequence = 0xffffffff;
        memset(tx.vin[0].prevout.hash.data, 0x11, 32);
        tx.vin[0].prevout.n = 0;
        tx.vout[0].value = 100000000;
        tx.vout[0].script_pub_key.data[0] = OP_DUP;
        tx.vout[0].script_pub_key.size = 1;
        tx.lock_time = 0;

        struct script sc;
        sc.data[0] = OP_DUP;
        sc.size = 1;

        struct sighash_type ht = sighash_type_default();
        struct uint256 result;
        bool ok = signature_hash(&sc, &tx, 0, ht, 0, 0, NULL, &result);
        if (ok && !uint256_is_null(&result))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        transaction_free(&tx);
    }

    printf("signature_hash sapling... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.version = SAPLING_TX_VERSION;
        tx.overwintered = true;
        tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        tx.vin[0].sequence = 0xffffffff;
        memset(tx.vin[0].prevout.hash.data, 0x22, 32);
        tx.vin[0].prevout.n = 0;
        tx.vout[0].value = 50000000;
        tx.vout[0].script_pub_key.data[0] = OP_DUP;
        tx.vout[0].script_pub_key.size = 1;
        tx.lock_time = 0;
        tx.expiry_height = 500000;
        tx.value_balance = 0;

        struct script sc;
        sc.data[0] = OP_DUP;
        sc.size = 1;

        struct sighash_type ht = sighash_type_default();
        struct uint256 result;
        uint32_t branch_id = 0x76b809bb; /* Sapling branch ID */
        bool ok = signature_hash(&sc, &tx, 0, ht, 50000000, branch_id, NULL, &result);
        if (ok && !uint256_is_null(&result))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        transaction_free(&tx);
    }

    printf("precomputed_tx_data... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 2, 1);
        tx.version = SAPLING_TX_VERSION;
        tx.overwintered = true;
        tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        for (int i = 0; i < 2; i++) {
            tx.vin[i].sequence = 0xffffffff;
            memset(tx.vin[i].prevout.hash.data, (unsigned char)(0x10 + i), 32);
            tx.vin[i].prevout.n = (uint32_t)i;
        }
        tx.vout[0].value = 100000000;
        tx.vout[0].script_pub_key.size = 0;

        struct precomputed_tx_data cache;
        precompute_tx_data(&tx, &cache);

        struct script sc;
        sc.size = 0;
        struct sighash_type ht = sighash_type_default();
        uint32_t branch_id = 0x76b809bb;

        struct uint256 r1, r2;
        signature_hash(&sc, &tx, 0, ht, 100000000, branch_id, NULL, &r1);
        signature_hash(&sc, &tx, 0, ht, 100000000, branch_id, &cache, &r2);

        if (memcmp(r1.data, r2.data, 32) == 0 && !uint256_is_null(&r1))
            printf("OK\n");
        else { printf("FAIL (cache mismatch)\n"); failures++; }
        transaction_free(&tx);
    }

    return failures;
}

static int test_tx_check_transaction_rules(void)
{
    int failures = 0;

    printf("check_transaction valid... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.version = 1;
        tx.overwintered = false;
        memset(tx.vin[0].prevout.hash.data, 0x11, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].sequence = 0xffffffff;
        tx.vin[0].script_sig.data[0] = 0x01;
        tx.vin[0].script_sig.data[1] = 0x01;
        tx.vin[0].script_sig.size = 2;
        tx.vout[0].value = 50 * COIN;
        tx.vout[0].script_pub_key.data[0] = OP_DUP;
        tx.vout[0].script_pub_key.size = 1;

        struct validation_state state;
        validation_state_init(&state);
        if (check_transaction(&tx, &state))
            printf("OK\n");
        else { printf("FAIL (%s)\n", state.reject_reason); failures++; }
        transaction_free(&tx);
    }

    printf("check_transaction negative output... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.version = 1;
        memset(tx.vin[0].prevout.hash.data, 0x11, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].script_sig.size = 2;
        tx.vout[0].value = -1;

        struct validation_state state;
        validation_state_init(&state);
        if (!check_transaction(&tx, &state) &&
            strcmp(state.reject_reason, "bad-txns-vout-negative") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        transaction_free(&tx);
    }

    printf("check_transaction empty vin... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 0, 1);
        tx.version = 1;
        tx.vout[0].value = COIN;

        struct validation_state state;
        validation_state_init(&state);
        if (!check_transaction(&tx, &state) &&
            strcmp(state.reject_reason, "bad-txns-vin-empty") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        transaction_free(&tx);
    }

    printf("check_transaction duplicate inputs... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 2, 1);
        tx.version = 1;
        memset(tx.vin[0].prevout.hash.data, 0x22, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].script_sig.size = 2;
        memcpy(&tx.vin[1].prevout, &tx.vin[0].prevout, sizeof(struct outpoint));
        tx.vin[1].script_sig.size = 2;
        tx.vout[0].value = COIN;

        struct validation_state state;
        validation_state_init(&state);
        if (!check_transaction(&tx, &state) &&
            strcmp(state.reject_reason, "bad-txns-inputs-duplicate") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        transaction_free(&tx);
    }

    printf("check_transaction overwinter version... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.version = SAPLING_TX_VERSION;
        tx.overwintered = true;
        tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        tx.expiry_height = 1000;
        memset(tx.vin[0].prevout.hash.data, 0x33, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].script_sig.size = 2;
        tx.vout[0].value = COIN;

        struct validation_state state;
        validation_state_init(&state);
        if (check_transaction(&tx, &state))
            printf("OK\n");
        else { printf("FAIL (%s)\n", state.reject_reason); failures++; }
        transaction_free(&tx);
    }

    return failures;
}

static int test_tx_sig_checker_wiring(void)
{
    int failures = 0;

    printf("tx_sig_checker create... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.version = SAPLING_TX_VERSION;
        tx.overwintered = true;
        tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        tx.vin[0].sequence = 0xffffffff;
        memset(tx.vin[0].prevout.hash.data, 0x11, 32);
        tx.vin[0].prevout.n = 0;
        tx.vout[0].value = 50 * COIN;
        tx.vout[0].script_pub_key.size = 0;

        struct tx_sig_checker tsc;
        tx_sig_checker_init(&tsc, &tx, 0, 50 * COIN, 0x76b809bb, NULL);
        struct sig_checker checker = tx_make_sig_checker(&tsc);

        if (checker.check_sig != NULL &&
            checker.check_lock_time != NULL &&
            checker.verify_signature != NULL &&
            checker.ctx == &tsc)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        transaction_free(&tx);
    }

    printf("tx_sig_checker bad sig... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.version = SAPLING_TX_VERSION;
        tx.overwintered = true;
        tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        tx.vin[0].sequence = 0xffffffff;
        memset(tx.vin[0].prevout.hash.data, 0x11, 32);
        tx.vin[0].prevout.n = 0;
        tx.vout[0].value = COIN;
        tx.vout[0].script_pub_key.size = 0;

        struct tx_sig_checker tsc;
        tx_sig_checker_init(&tsc, &tx, 0, COIN, 0x76b809bb, NULL);

        struct script sc;
        sc.size = 0;
        unsigned char fake_sig[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01};
        unsigned char fake_pk[] = {0x04};
        /* Should fail: invalid pubkey */
        if (!tx_sig_checker_check_sig(&tsc, fake_sig, sizeof(fake_sig),
                                       fake_pk, 1, &sc))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        transaction_free(&tx);
    }

    return failures;
}

static int test_tx_contextual_and_expiry(void)
{
    int failures = 0;

    printf("contextual_check_tx sprout rejects overwinter... ");
    {
        const struct consensus_params *p = &chain_params_get()->consensus;
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.overwintered = true;
        tx.version = OVERWINTER_TX_VERSION;
        tx.version_group_id = OVERWINTER_VERSION_GROUP_ID;
        memset(tx.vin[0].prevout.hash.data, 0x11, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].script_sig.size = 0;
        tx.vout[0].value = COIN;
        tx.vout[0].script_pub_key.size = 0;
        struct validation_state state;
        validation_state_init(&state);
        /* height 1 is Sprout on mainnet */
        bool ok = contextual_check_transaction(&tx, &state, p, 1, 100);
        if (!ok && strcmp(state.reject_reason, "tx-overwinter-not-active") == 0)
            printf("OK\n");
        else { printf("FAIL (ok=%d reason=%s)\n", ok, state.reject_reason); failures++; }
        transaction_free(&tx);
    }

    printf("contextual_check_tx sapling valid... ");
    {
        const struct consensus_params *p = &chain_params_get()->consensus;
        int sapHeight = p->vUpgrades[UPGRADE_SAPLING].nActivationHeight;
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.overwintered = true;
        tx.version = SAPLING_TX_VERSION;
        tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        tx.expiry_height = (uint32_t)(sapHeight + 100);
        memset(tx.vin[0].prevout.hash.data, 0x11, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].script_sig.size = 0;
        tx.vout[0].value = COIN;
        tx.vout[0].script_pub_key.size = 0;
        struct validation_state state;
        validation_state_init(&state);
        bool ok = contextual_check_transaction(&tx, &state, p, sapHeight, 100);
        if (ok)
            printf("OK\n");
        else { printf("FAIL (reason=%s)\n", state.reject_reason); failures++; }
        transaction_free(&tx);
    }

    printf("contextual_check_tx expired... ");
    {
        const struct consensus_params *p = &chain_params_get()->consensus;
        int sapHeight = p->vUpgrades[UPGRADE_SAPLING].nActivationHeight;
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.overwintered = true;
        tx.version = SAPLING_TX_VERSION;
        tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        tx.expiry_height = (uint32_t)(sapHeight + 100);
        memset(tx.vin[0].prevout.hash.data, 0x11, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].script_sig.size = 0;
        tx.vout[0].value = COIN;
        tx.vout[0].script_pub_key.size = 0;
        /* zclassicd IsExpiredTx is strict '>': a tx is valid in the block
         * AT its expiry_height and expires only the block AFTER
         * (zclassic-cpp/src/main.cpp:788 `nBlockHeight > nExpiryHeight`).
         * So at height == expiry it is NOT expired; at expiry+1 it is. */
        struct validation_state s_at, s_after;
        validation_state_init(&s_at);
        validation_state_init(&s_after);
        bool ok_at = contextual_check_transaction(&tx, &s_at, p,
                                                  (int)tx.expiry_height, 100);
        bool ok_after = contextual_check_transaction(&tx, &s_after, p,
                                                     (int)tx.expiry_height + 1, 100);
        if (ok_at && !ok_after &&
            strcmp(s_after.reject_reason, "tx-overwinter-expired") == 0)
            printf("OK\n");
        else { printf("FAIL (ok_at=%d ok_after=%d reason=%s)\n",
                      ok_at, ok_after, s_after.reject_reason); failures++; }
        transaction_free(&tx);
    }

    printf("is_expired_tx... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        tx.overwintered = true;
        tx.expiry_height = 500;
        /* strict '>': NOT expired at the expiry height itself, expired only
         * the block after (matches zclassicd IsExpiredTx, main.cpp:788). */
        if (!is_expired_tx(&tx, 500) && is_expired_tx(&tx, 501) &&
            !is_expired_tx(&tx, 499) && !is_expired_tx(&tx, 0))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

static int test_tx_in_undo_roundtrip(void)
{
    int failures = 0;

    printf("tx_in_undo serialize/deserialize roundtrip... ");
    {
        struct tx_in_undo u;
        tx_in_undo_init(&u);
        u.coinbase = true;
        u.height = 12345;
        u.version = 2;
        u.txout.value = 50 * COIN;
        /* P2PKH script */
        u.txout.script_pub_key.data[0] = OP_DUP;
        u.txout.script_pub_key.data[1] = OP_HASH160;
        u.txout.script_pub_key.data[2] = 20;
        memset(u.txout.script_pub_key.data + 3, 0xAB, 20);
        u.txout.script_pub_key.data[23] = OP_EQUALVERIFY;
        u.txout.script_pub_key.data[24] = OP_CHECKSIG;
        u.txout.script_pub_key.size = 25;

        struct byte_stream s;
        stream_init(&s, 256);
        tx_in_undo_serialize(&u, &s);

        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        struct tx_in_undo u2;
        tx_in_undo_init(&u2);
        tx_in_undo_deserialize(&u2, &r);

        if (u2.coinbase == true && u2.height == 12345 && u2.version == 2 &&
            u2.txout.value == 50 * COIN &&
            u2.txout.script_pub_key.size == 25 &&
            u2.txout.script_pub_key.data[0] == OP_DUP &&
            memcmp(u2.txout.script_pub_key.data + 3, u.txout.script_pub_key.data + 3, 20) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&s);
    }

    return failures;
}

static int test_tx_block_undo_roundtrip(void)
{
    int failures = 0;

    printf("block_undo serialize/deserialize roundtrip... ");
    {
        struct block_undo bu;
        block_undo_init(&bu);
        block_undo_alloc(&bu, 1);
        tx_undo_alloc(&bu.vtxundo[0], 2);
        bu.vtxundo[0].vprevout[0].coinbase = false;
        bu.vtxundo[0].vprevout[0].height = 100;
        bu.vtxundo[0].vprevout[0].version = 1;
        bu.vtxundo[0].vprevout[0].txout.value = COIN;
        bu.vtxundo[0].vprevout[0].txout.script_pub_key.data[0] = OP_RETURN;
        bu.vtxundo[0].vprevout[0].txout.script_pub_key.size = 1;
        bu.vtxundo[0].vprevout[1].coinbase = true;
        bu.vtxundo[0].vprevout[1].height = 50;
        bu.vtxundo[0].vprevout[1].version = 1;
        bu.vtxundo[0].vprevout[1].txout.value = 2 * COIN;
        bu.vtxundo[0].vprevout[1].txout.script_pub_key.data[0] = OP_TRUE;
        bu.vtxundo[0].vprevout[1].txout.script_pub_key.size = 1;
        memset(bu.old_sprout_tree_root.data, 0xCC, 32);

        struct byte_stream s;
        stream_init(&s, 512);
        block_undo_serialize(&bu, &s);

        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        struct block_undo bu2;
        block_undo_init(&bu2);
        block_undo_deserialize(&bu2, &r);

        if (bu2.num_txundo == 1 &&
            bu2.vtxundo[0].num_prevout == 2 &&
            bu2.vtxundo[0].vprevout[0].height == 100 &&
            bu2.vtxundo[0].vprevout[1].coinbase == true &&
            bu2.vtxundo[0].vprevout[1].txout.value == 2 * COIN &&
            bu2.old_sprout_tree_root.data[0] == 0xCC)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        block_undo_free(&bu);
        block_undo_free(&bu2);
        stream_free(&s);
    }

    return failures;
}

static int test_tx_merkle_tree_serde(void)
{
    int failures = 0;

    printf("merkle_tree serialize/deserialize roundtrip... ");
    {
        struct uint256 txids[4];
        bool match[4] = {false, true, false, true};
        for (int i = 0; i < 4; i++)
            memset(txids[i].data, i + 1, 32);

        struct partial_merkle_tree tree;
        merkle_tree_init(&tree);
        merkle_tree_build(&tree, txids, 4, match, 4);

        struct byte_stream ws;
        stream_init(&ws, 256);
        bool ok = merkle_tree_serialize(&tree, &ws);

        struct partial_merkle_tree tree2;
        merkle_tree_init(&tree2);
        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        ok = ok && merkle_tree_deserialize(&tree2, &rs);

        ok = ok && tree2.num_transactions == tree.num_transactions;
        ok = ok && tree2.num_hashes == tree.num_hashes;
        for (size_t i = 0; i < tree.num_hashes && ok; i++)
            ok = ok && uint256_cmp(&tree.hashes[i], &tree2.hashes[i]) == 0;

        struct uint256 matched1[4], matched2[4], root1, root2;
        size_t nm1 = 0, nm2 = 0;
        merkle_tree_extract(&tree, matched1, &nm1, &root1);
        merkle_tree_extract(&tree2, matched2, &nm2, &root2);
        ok = ok && nm1 == nm2 && uint256_cmp(&root1, &root2) == 0;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }

        merkle_tree_free(&tree);
        merkle_tree_free(&tree2);
        stream_free(&ws);
        stream_free(&rs);
    }

    return failures;
}

static int test_tx_merkle_block_serde(void)
{
    int failures = 0;

    printf("merkle_block serialize/deserialize roundtrip... ");
    {
        struct merkle_block mb;
        merkle_block_init(&mb);
        mb.header.nVersion = 4;
        mb.header.nBits = 0x1d00ffff;
        mb.header.nTime = 1231006505;
        memset(mb.header.hashPrevBlock.data, 0xAA, 32);

        struct uint256 txids[2];
        bool match[2] = {true, false};
        memset(txids[0].data, 0x11, 32);
        memset(txids[1].data, 0x22, 32);
        merkle_tree_build(&mb.txn, txids, 2, match, 2);

        struct byte_stream ws;
        stream_init(&ws, 2048);
        bool ok = merkle_block_serialize(&mb, &ws);

        struct merkle_block mb2;
        merkle_block_init(&mb2);
        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        ok = ok && merkle_block_deserialize(&mb2, &rs);

        ok = ok && mb2.header.nVersion == 4;
        ok = ok && mb2.header.nBits == 0x1d00ffff;
        ok = ok && mb2.txn.num_transactions == 2;
        ok = ok && mb2.txn.num_hashes == mb.txn.num_hashes;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }

        merkle_block_free(&mb);
        merkle_block_free(&mb2);
        stream_free(&ws);
        stream_free(&rs);
    }

    return failures;
}

static int test_tx_serialize_roundtrip(void)
{
    int failures = 0;

    printf("transaction serialize/deserialize roundtrip... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        memset(tx.vin[0].prevout.hash.data, 0xAB, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].sequence = 0xFFFFFFFF;
        tx.vout[0].value = 50 * 100000000LL;
        tx.lock_time = 0;
        transaction_compute_hash(&tx);
        struct uint256 orig_hash = tx.hash;

        struct byte_stream ws;
        stream_init(&ws, 512);
        bool ok = transaction_serialize(&tx, &ws);

        struct transaction tx2;
        transaction_init(&tx2);
        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        ok = ok && transaction_deserialize(&tx2, &rs);

        ok = ok && tx2.num_vin == 1 && tx2.num_vout == 1;
        ok = ok && tx2.vout[0].value == 50 * 100000000LL;
        ok = ok && uint256_cmp(&tx2.hash, &orig_hash) == 0;

        size_t sz = transaction_serialize_size(&tx);
        ok = ok && sz == ws.size;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }

        transaction_free(&tx);
        transaction_free(&tx2);
        stream_free(&ws);
        stream_free(&rs);
    }

    return failures;
}

/* Pins js_description_serialize / js_description_deserialize byte layout.
 * Groth wire: 8+8 vpub, 32 anchor, 2x32 nullifiers, 2x32 commitments,
 * 32 ephemeral key, 32 random seed, 2x32 macs, GROTH_PROOF_SIZE (192) proof,
 * 2x601 ciphertexts = 1698 bytes. PHGR wire: same but a PHGR_PROOF_SIZE (296)
 * proof = 1802 bytes. */
struct js_pin_span {
    size_t off;
    size_t len;
    unsigned char fill;
};

static const struct js_pin_span js_pin_groth_spans[] = {
    {16, 32, 0xA1}, {48, 32, 0xB0}, {80, 32, 0xB1}, {112, 32, 0xC0},
    {144, 32, 0xC1}, {176, 32, 0xE0}, {208, 32, 0xD0}, {240, 32, 0xF0},
    {272, 32, 0xF1}, {304, GROTH_PROOF_SIZE, 0x5A}, {496, 601, 0x41},
    {1097, 601, 0x42},
};

static const struct js_pin_span js_pin_phgr_spans[] = {
    {16, 32, 0xA1}, {48, 32, 0xB0}, {80, 32, 0xB1}, {112, 32, 0xC0},
    {144, 32, 0xC1}, {176, 32, 0xE0}, {208, 32, 0xD0}, {240, 32, 0xF0},
    {272, 32, 0xF1}, {304, 296, 0x5A}, {600, 601, 0x41}, {1201, 601, 0x42},
};

static void js_pin_fill(struct js_description *jsd)
{
    memset(jsd, 0, sizeof *jsd);
    jsd->vpub_old = 0x0102030405060708LL;
    jsd->vpub_new = -2;
    memset(jsd->anchor.data, 0xA1, 32);
    memset(jsd->nullifiers[0].data, 0xB0, 32);
    memset(jsd->nullifiers[1].data, 0xB1, 32);
    memset(jsd->commitments[0].data, 0xC0, 32);
    memset(jsd->commitments[1].data, 0xC1, 32);
    memset(jsd->ephemeral_key.data, 0xE0, 32);
    memset(jsd->random_seed.data, 0xD0, 32);
    memset(jsd->macs[0].data, 0xF0, 32);
    memset(jsd->macs[1].data, 0xF1, 32);
    memset(jsd->proof, 0x5A, sizeof jsd->proof);
    memset(jsd->ciphertexts[0], 0x41, sizeof jsd->ciphertexts[0]);
    memset(jsd->ciphertexts[1], 0x42, sizeof jsd->ciphertexts[1]);
    jsd->use_groth = true;
}

static bool js_pin_spans_match(const unsigned char *p, size_t n,
                               const struct js_pin_span *sp, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (sp[i].off > n || sp[i].len > n - sp[i].off)
            return false;
        for (size_t j = 0; j < sp[i].len; j++)
            if (p[sp[i].off + j] != sp[i].fill)
                return false;
    }
    return true;
}

static bool js_pin_wire_ok(const struct byte_stream *ws, size_t want_size,
                           const struct js_pin_span *sp, size_t count)
{
    static const unsigned char vpub_old_le[8] = {0x08, 0x07, 0x06, 0x05,
                                                 0x04, 0x03, 0x02, 0x01};
    static const unsigned char vpub_new_le[8] = {0xFE, 0xFF, 0xFF, 0xFF,
                                                 0xFF, 0xFF, 0xFF, 0xFF};
    return ws->size == want_size && !ws->error &&
           memcmp(ws->data, vpub_old_le, 8) == 0 &&
           memcmp(ws->data + 8, vpub_new_le, 8) == 0 &&
           js_pin_spans_match(ws->data, ws->size, sp, count);
}

static int test_tx_js_description_serialize_groth_layout(void)
{
    int failures = 0;

    printf("js_description serialize groth layout... ");
    {
        struct js_description js;
        js_pin_fill(&js);
        struct byte_stream ws;
        stream_init(&ws, 0);
        bool ok = js_description_serialize(&js, &ws) &&
                  js_pin_wire_ok(&ws, 1698, js_pin_groth_spans,
                                 sizeof js_pin_groth_spans / sizeof js_pin_groth_spans[0]);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&ws);
    }

    return failures;
}

static int test_tx_js_description_serialize_phgr_layout(void)
{
    int failures = 0;

    printf("js_description serialize phgr layout... ");
    {
        struct js_description js;
        js_pin_fill(&js);
        js.use_groth = false;
        struct byte_stream ws;
        stream_init(&ws, 0);
        bool ok = js_description_serialize(&js, &ws) &&
                  js_pin_wire_ok(&ws, 1802, js_pin_phgr_spans,
                                 sizeof js_pin_phgr_spans / sizeof js_pin_phgr_spans[0]);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&ws);
    }

    return failures;
}

static int test_tx_js_description_serialize_groth_tail_ignored(void)
{
    int failures = 0;

    printf("js_description serialize groth ignores proof tail... ");
    {
        struct js_description a, b;
        js_pin_fill(&a);
        js_pin_fill(&b);
        memset(b.proof + GROTH_PROOF_SIZE, 0x77,
               PHGR_PROOF_SIZE - GROTH_PROOF_SIZE);
        struct byte_stream wa, wb;
        stream_init(&wa, 0);
        stream_init(&wb, 0);
        bool ok = js_description_serialize(&a, &wa) &&
                  js_description_serialize(&b, &wb);
        ok = ok && wa.size == 1698 && wb.size == 1698;
        ok = ok && memcmp(wa.data, wb.data, wa.size) == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&wa);
        stream_free(&wb);
    }

    return failures;
}

static int test_tx_js_description_serialize_failure(void)
{
    int failures = 0;

    printf("js_description serialize into read-only stream fails... ");
    {
        struct js_description js;
        js_pin_fill(&js);
        unsigned char backing[4] = {0};
        struct byte_stream ns;
        stream_init_from_data(&ns, backing, 0);
        bool ok = !js_description_serialize(&js, &ns) && ns.error;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

static int test_tx_js_description_deserialize_truncation(void)
{
    int failures = 0;
    /* Each cut lands on a field boundary (fails reading the field that
     * starts there) or one byte short of the end of a field. */
    static const size_t groth_cuts[] = {0, 8, 16, 48, 80, 112, 144, 176,
                                        208, 240, 272, 304, 495, 496,
                                        1096, 1097, 1697};
    static const size_t phgr_cuts[] = {0, 8, 16, 48, 80, 112, 144, 176,
                                       208, 240, 272, 304, 600, 1201, 1801};

    printf("js_description deserialize groth truncation refused... ");
    {
        struct js_description js;
        js_pin_fill(&js);
        struct byte_stream ws;
        stream_init(&ws, 0);
        bool ok = js_description_serialize(&js, &ws);
        for (size_t i = 0; ok && i < sizeof groth_cuts / sizeof groth_cuts[0]; i++) {
            struct js_description out;
            struct byte_stream rs;
            stream_init_from_data(&rs, ws.data, groth_cuts[i]);
            ok = !js_description_deserialize(&out, true, &rs) && rs.error;
            stream_free(&rs);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&ws);
    }

    printf("js_description deserialize phgr truncation refused... ");
    {
        struct js_description js;
        js_pin_fill(&js);
        js.use_groth = false;
        struct byte_stream ws;
        stream_init(&ws, 0);
        bool ok = js_description_serialize(&js, &ws);
        for (size_t i = 0; ok && i < sizeof phgr_cuts / sizeof phgr_cuts[0]; i++) {
            struct js_description out;
            struct byte_stream rs;
            stream_init_from_data(&rs, ws.data, phgr_cuts[i]);
            ok = !js_description_deserialize(&out, false, &rs) && rs.error;
            stream_free(&rs);
        }
        /* A groth-length buffer is too short for the 296-byte phgr proof. */
        struct js_description out;
        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, 1698);
        ok = ok && !js_description_deserialize(&out, false, &rs) && rs.error;
        stream_free(&rs);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&ws);
    }

    return failures;
}

static int test_tx_js_description_deserialize_groth_roundtrip(void)
{
    int failures = 0;

    printf("js_description deserialize groth roundtrip... ");
    {
        struct js_description src, dst;
        js_pin_fill(&src);
        struct byte_stream ws, rs, re;
        stream_init(&ws, 0);
        stream_init(&re, 0);
        bool ok = js_description_serialize(&src, &ws);
        stream_init_from_data(&rs, ws.data, ws.size);
        ok = ok && js_description_deserialize(&dst, true, &rs) &&
             rs.read_pos == 1698 && stream_remaining(&rs) == 0 &&
             dst.use_groth && dst.vpub_old == src.vpub_old && dst.vpub_new == -2;
        ok = ok && js_description_serialize(&dst, &re) &&
             re.size == ws.size && memcmp(re.data, ws.data, ws.size) == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&ws);
        stream_free(&re);
    }

    return failures;
}

static int test_tx_js_description_deserialize_groth_zero_proof_tail(void)
{
    int failures = 0;

    printf("js_description deserialize groth zeroes proof tail... ");
    {
        struct js_description src, dst;
        js_pin_fill(&src);
        struct byte_stream ws, rs;
        stream_init(&ws, 0);
        bool ok = js_description_serialize(&src, &ws);
        memset(&dst, 0, sizeof dst);
        memset(dst.proof, 0xEE, sizeof dst.proof);
        dst.use_groth = false;
        stream_init_from_data(&rs, ws.data, ws.size);
        ok = ok && js_description_deserialize(&dst, true, &rs);
        static const struct js_pin_span proof_spans[] = {
            {0, GROTH_PROOF_SIZE, 0x5A},
            {GROTH_PROOF_SIZE, PHGR_PROOF_SIZE - GROTH_PROOF_SIZE, 0x00},
        };
        ok = ok && dst.use_groth &&
             js_pin_spans_match(dst.proof, sizeof dst.proof, proof_spans, 2);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&ws);
    }

    return failures;
}

static int test_tx_js_description_deserialize_phgr_proof(void)
{
    int failures = 0;

    printf("js_description deserialize phgr reads 296-byte proof... ");
    {
        struct js_description src, dst;
        js_pin_fill(&src);
        src.use_groth = false;
        struct byte_stream ws, rs;
        stream_init(&ws, 0);
        bool ok = js_description_serialize(&src, &ws);
        memset(&dst, 0, sizeof dst);
        stream_init_from_data(&rs, ws.data, ws.size);
        ok = ok && js_description_deserialize(&dst, false, &rs);
        ok = ok && !dst.use_groth && rs.read_pos == 1802;
        static const struct js_pin_span proof_spans[] = {{0, 296, 0x5A}};
        ok = ok && js_pin_spans_match(dst.proof, sizeof dst.proof, proof_spans, 1);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&ws);
    }

    return failures;
}

static int test_tx_js_description_deserialize_groth_trailing(void)
{
    int failures = 0;

    printf("js_description deserialize groth reads 1698 of phgr 1802 bytes... ");
    {
        struct js_description src, dst;
        js_pin_fill(&src);
        src.use_groth = false;
        struct byte_stream ws, rs;
        stream_init(&ws, 0);
        bool ok = js_description_serialize(&src, &ws);
        stream_init_from_data(&rs, ws.data, ws.size);
        ok = ok && js_description_deserialize(&dst, true, &rs);
        /* This function does not reject trailing bytes; it stops at 1698,
         * leaving the 104 bytes of the phgr proof tail (1802 - 1698). */
        ok = ok && rs.read_pos == 1698 && stream_remaining(&rs) == 104;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&ws);
    }

    return failures;
}

static bool tx_v6_wire_initial_lifecycle(struct transaction *tx,
                                         uint8_t wire[24])
{
    struct byte_stream fresh;
    struct uint256 hash_out;
    stream_init(&fresh, 64);
    bool ok = !transaction_serialize(tx, &fresh) && fresh.size == 0 &&
              !transaction_hash_serialized(tx, &hash_out);
    stream_free(&fresh);
    zcl_alloc_fault_fail_next("tx_v6_wire");
    bool fresh_oom = !transaction_v6_store_wire(tx, wire, 24, 24);
    stream_init(&fresh, 64);
    ok = ok && fresh_oom && !transaction_serialize(tx, &fresh) &&
         fresh.size == 0 && !transaction_hash_serialized(tx, &hash_out);
    stream_free(&fresh);
    tx->hash.data[0] = 7;
    wire[20] = 42;
    return ok && transaction_v6_store_wire(tx, wire, 24, 24) &&
        uint256_is_null(&tx->hash);
}

static bool tx_v6_wire_rejection_lifecycle(struct transaction *tx,
                                           uint8_t wire[24], bool ok)
{
    wire[20] = 9;
    struct byte_stream stream;
    stream_init(&stream, 64);
    ok = ok && !transaction_serialize(tx, &stream) && stream.size == 0;
    stream_free(&stream);
    ok = ok && tx->v6_wire.size == 24 && tx->v6_wire.data[20] == 42;
    ok = ok && !transaction_v6_store_wire(tx, wire, 19, 24);
    ok = ok && !transaction_v6_store_wire(tx, wire, 24, 23);
    wire[0] = 5;
    ok = ok && !transaction_v6_store_wire(tx, wire, 24, 24);
    wire[0] = 6;
    struct transaction decoded;
    struct byte_stream input;
    stream_init_from_data(&input, wire, 24);
    bool accepted = transaction_deserialize(&decoded, &input);
    transaction_free(&decoded);
    ok = ok && !accepted;
    ok = ok && tx->v6_wire.size == 24 && tx->v6_wire.data[20] == 42;
    ok = ok && transaction_v6_store_wire(tx, tx->v6_wire.data, tx->v6_wire.size,
                                         tx->v6_wire.size);
    tx->hash.data[0] = 9;
    return ok;
}

static bool tx_v6_wire_copy_lifecycle(struct transaction *tx,
                                      const uint8_t wire[24], bool ok)
{
    zcl_alloc_fault_fail_next("tx_v6_wire");
    bool allocation_rejected = !transaction_v6_store_wire(tx, wire, 24, 24);
    ok = ok && allocation_rejected && tx->v6_wire.data[20] == 42 &&
        tx->hash.data[0] == 9;
    zcl_alloc_fault_fail_next("tx_v6_wire");
    struct transaction copy;
    bool copy_failed = !transaction_copy(&copy, tx);
    ok = ok && copy_failed && tx->v6_wire.data[20] == 42;
    bool copied = transaction_copy(&copy, tx);
    ok = ok && copied && copy.v6_wire.data != tx->v6_wire.data &&
         copy.v6_wire.size == 24 && copy.v6_wire.data[20] == 42 &&
         copy.hash.data[0] == 9;
    transaction_free(tx);
    ok = ok && copied && copy.v6_wire.data[20] == 42;
    if (copied) transaction_free(&copy);
    return ok;
}

static int test_tx_v6_wire_lifecycle(void)
{
    uint8_t wire[24] = {6, 0, 0, 0x80, 0x98, 0xb6, 0x84, 0xd8};
    struct transaction tx;
    transaction_init(&tx);
    tx.overwintered = true;
    tx.version = IRONWOOD_TX_VERSION;
    tx.version_group_id = IRONWOOD_VERSION_GROUP_ID;
    bool ok = tx_v6_wire_initial_lifecycle(&tx, wire);
    ok = tx_v6_wire_rejection_lifecycle(&tx, wire, ok);
    ok = tx_v6_wire_copy_lifecycle(&tx, wire, ok);
    printf("transaction v6 wire ownership and copy... %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static bool tx_v6_write_header(struct byte_stream *wire)
{
    static const uint8_t header[20] = {
        6, 0, 0, 0x80, 0x98, 0xb6, 0x84, 0xd8,
        0x5b, 0x16, 0xa5, 0x37, 0x44, 0x33, 0x22, 0x11,
        0x08, 0x07, 0x06, 0x05
    };
    return stream_write_bytes(wire, header, sizeof header);
}

static bool tx_v6_transparent_frame(struct byte_stream *wire, struct tx_in *in,
                                    struct tx_out *out)
{
    tx_in_init(in);
    for (size_t i = 0; i < sizeof in->prevout.hash.data; ++i)
        in->prevout.hash.data[i] = (uint8_t)i;
    in->prevout.n = 0x12345678;
    in->script_sig.data[0] = 0xaa;
    in->script_sig.data[1] = 0xbb;
    in->script_sig.data[2] = 0xcc;
    in->script_sig.size = 3;
    in->sequence = 0x89abcdef;
    tx_out_set_null(out);
    out->value = 123456789;
    out->script_pub_key.data[0] = 0x51;
    out->script_pub_key.data[1] = 0x52;
    out->script_pub_key.size = 2;

    stream_init(wire, 128);
    return tx_v6_write_header(wire) &&
        stream_write_compact_size(wire, 1) && tx_in_serialize(in, wire) &&
        stream_write_compact_size(wire, 1) && tx_out_serialize(out, wire) &&
        stream_write_compact_size(wire, 0) &&
        stream_write_compact_size(wire, 0) &&
        stream_write_compact_size(wire, 0) &&
        stream_write_compact_size(wire, 0);
}

static bool tx_v6_sapling_frame(struct byte_stream *wire)
{
    uint8_t spend[96], output[756], anchor[32], proof[192], signature[64];
    uint8_t output_proof[192], binding[64];
    memset(spend, 0x11, sizeof spend);
    memset(output, 0x22, sizeof output);
    memset(anchor, 0x33, sizeof anchor);
    memset(proof, 0x44, sizeof proof);
    memset(signature, 0x55, sizeof signature);
    memset(output_proof, 0x66, sizeof output_proof);
    memset(binding, 0x77, sizeof binding);
    stream_init(wire, 2048);
    return tx_v6_write_header(wire) &&
        stream_write_compact_size(wire, 0) &&
        stream_write_compact_size(wire, 0) &&
        stream_write_compact_size(wire, 1) &&
        stream_write_bytes(wire, spend, sizeof spend) &&
        stream_write_compact_size(wire, 1) &&
        stream_write_bytes(wire, output, sizeof output) &&
        stream_write_i64_le(wire, 200000) &&
        stream_write_bytes(wire, anchor, sizeof anchor) &&
        stream_write_bytes(wire, proof, sizeof proof) &&
        stream_write_bytes(wire, signature, sizeof signature) &&
        stream_write_bytes(wire, output_proof, sizeof output_proof) &&
        stream_write_bytes(wire, binding, sizeof binding) &&
        stream_write_compact_size(wire, 0) &&
        stream_write_compact_size(wire, 0);
}

static bool tx_v6_ironwood_frame(struct byte_stream *wire, int64_t balance)
{
    uint8_t action[820] = {0}, anchor[32] = {0};
    uint8_t signature[64] = {0}, binding[64] = {0}, flags = 7;
    stream_init(wire, 1200);
    return tx_v6_write_header(wire) &&
        stream_write_compact_size(wire, 0) &&
        stream_write_compact_size(wire, 0) &&
        stream_write_compact_size(wire, 0) &&
        stream_write_compact_size(wire, 0) &&
        stream_write_compact_size(wire, 0) &&
        stream_write_compact_size(wire, 1) &&
        stream_write_bytes(wire, action, sizeof action) &&
        stream_write_u8(wire, flags) &&
        stream_write_i64_le(wire, balance) &&
        stream_write_bytes(wire, anchor, sizeof anchor) &&
        stream_write_compact_size(wire, 0) &&
        stream_write_bytes(wire, signature, sizeof signature) &&
        stream_write_bytes(wire, binding, sizeof binding);
}

static bool tx_v6_decode_oom(const unsigned char *data, size_t size,
                             const char *label)
{
    struct byte_stream input;
    stream_init_from_data(&input, data, size);
    struct transaction tx;
    zcl_alloc_fault_fail_next(label);
    bool refused = !transaction_v6_decode_prefix(&tx, &input, size);
    bool fired = zcl_alloc_fault_armed_label() == NULL;
    zcl_alloc_fault_clear();
    bool ok = refused && fired && input.read_pos == 0 && !input.error;
    transaction_free(&tx);
    return ok && !tx.vin && !tx.vout && !tx.v_shielded_spend &&
        !tx.v_shielded_output && !tx.v6_wire.data && !tx.num_vin &&
        !tx.num_vout && !tx.num_shielded_spend && !tx.num_shielded_output;
}

static bool tx_v6_transparent_fields_match(const struct transaction *tx,
                                            const struct tx_in *expected_in,
                                            const struct tx_out *expected_out)
{
    return tx->num_vin == 1 && tx->num_vout == 1 &&
        tx->vin[0].prevout.n == expected_in->prevout.n &&
        uint256_eq(&tx->vin[0].prevout.hash, &expected_in->prevout.hash) &&
        tx->vin[0].script_sig.size == expected_in->script_sig.size &&
        !memcmp(tx->vin[0].script_sig.data, expected_in->script_sig.data, 3) &&
        tx->vin[0].sequence == expected_in->sequence &&
        tx->vout[0].value == expected_out->value &&
        tx->vout[0].script_pub_key.size == expected_out->script_pub_key.size &&
        !memcmp(tx->vout[0].script_pub_key.data, expected_out->script_pub_key.data, 2) &&
        tx->lock_time == 0x11223344 && tx->expiry_height == 0x05060708;
}

static bool tx_v6_wire_and_hash_match(const struct transaction *tx,
                                      const struct byte_stream *wire)
{
    return tx->v6_wire.data && tx->v6_wire.data != wire->data &&
        tx->v6_wire.size == wire->size &&
        !memcmp(tx->v6_wire.data, wire->data, wire->size) &&
        !uint256_is_null(&tx->hash);
}

static int test_tx_v6_transparent_model(void)
{
    struct byte_stream wire;
    struct tx_in expected_in;
    struct tx_out expected_out;
    bool built = tx_v6_transparent_frame(&wire, &expected_in, &expected_out);
    struct byte_stream input;
    stream_init_from_data(&input, wire.data, wire.size);
    struct transaction tx;
    transaction_init(&tx);
    bool ok = built && transaction_v6_decode_prefix(&tx, &input, wire.size) &&
        input.read_pos == wire.size &&
        tx_v6_transparent_fields_match(&tx, &expected_in, &expected_out) &&
        tx_v6_wire_and_hash_match(&tx, &wire);
    struct byte_stream refused;
    stream_init(&refused, 64);
    ok = ok && !transaction_serialize(&tx, &refused) && refused.size == 0;
    stream_free(&refused);
    transaction_free(&tx);
    stream_free(&wire);
    printf("transaction v6 transparent model and serialization refusal... %s\n",
           ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static bool tx_v6_transparent_oom(const struct byte_stream *wire)
{
    static const char *const labels[] = {
        "tx_v6_wire", "tx_vin", "tx_vout"
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof labels / sizeof labels[0]; ++i)
        ok = tx_v6_decode_oom(wire->data, wire->size, labels[i]) && ok;
    return ok;
}

static bool tx_v6_sapling_oom(const struct byte_stream *wire)
{
    static const char *const labels[] = {
        "tx_shielded_spend", "tx_shielded_output"
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof labels / sizeof labels[0]; ++i)
        ok = tx_v6_decode_oom(wire->data, wire->size, labels[i]) && ok;
    return ok;
}

static bool tx_v6_sapling_model_matches(const struct transaction *tx,
                                        const struct byte_stream *input, size_t size)
{
    return input->read_pos == size && tx->num_shielded_spend == 1 &&
        tx->num_shielded_output == 1 && tx->value_balance == 200000 &&
        tx->v_shielded_spend[0].cv.data[0] == 0x11 &&
        tx->v_shielded_spend[0].anchor.data[0] == 0x33 &&
        tx->v_shielded_spend[0].zkproof[0] == 0x44 &&
        tx->v_shielded_spend[0].spend_auth_sig[0] == 0x55 &&
        tx->v_shielded_output[0].cv.data[0] == 0x22 &&
        tx->v_shielded_output[0].zkproof[0] == 0x66 &&
        tx->binding_sig[0] == 0x77;
}

static int test_tx_v6_model_allocation_failures(void)
{
    struct byte_stream transparent, sapling;
    struct tx_in in;
    struct tx_out out;
    bool ok = tx_v6_transparent_frame(&transparent, &in, &out) &&
        tx_v6_sapling_frame(&sapling);
    ok = tx_v6_transparent_oom(&transparent) && ok;
    ok = tx_v6_sapling_oom(&sapling) && ok;

    struct byte_stream input;
    stream_init_from_data(&input, sapling.data, sapling.size);
    struct transaction tx;
    ok = transaction_v6_decode_prefix(&tx, &input, sapling.size) &&
        tx_v6_sapling_model_matches(&tx, &input, sapling.size) && ok;
    transaction_free(&tx);
    stream_free(&transparent);
    stream_free(&sapling);
    printf("transaction v6 Sapling model and allocation-failure cleanup... %s\n",
           ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static bool tx_v6_ironwood_balance_case(int64_t balance, int64_t expected_out,
                                        int64_t expected_in)
{
    struct byte_stream wire;
    if (!tx_v6_ironwood_frame(&wire, balance)) return false;
    struct byte_stream input;
    stream_init_from_data(&input, wire.data, wire.size);
    struct transaction tx;
    bool ok = transaction_v6_decode_prefix(&tx, &input, wire.size) &&
        input.read_pos == wire.size && tx.ironwood_value_balance == balance &&
        transaction_get_value_out(&tx) == expected_out &&
        transaction_get_shielded_value_in(&tx) == expected_in;
    struct transaction copy;
    bool copied = transaction_copy(&copy, &tx);
    ok = copied && copy.ironwood_value_balance == balance &&
        copy.v6_wire.data != tx.v6_wire.data &&
        !memcmp(copy.v6_wire.data, tx.v6_wire.data, wire.size) && ok;
    transaction_free(&copy);
    transaction_free(&tx);
    ok = tx.ironwood_value_balance == 0 && ok;
    stream_free(&wire);
    return ok;
}

static int test_tx_v6_ironwood_accounting(void)
{
    bool ok = tx_v6_ironwood_balance_case(-200000, 200000, 0) &&
        tx_v6_ironwood_balance_case(200000, 0, 200000) &&
        tx_v6_ironwood_balance_case(0, 0, 0) &&
        tx_v6_ironwood_balance_case(-MAX_MONEY, MAX_MONEY, 0) &&
        tx_v6_ironwood_balance_case(MAX_MONEY, 0, MAX_MONEY);
    printf("transaction v6 Ironwood balance accounting and deep copy... %s\n",
           ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static bool tx_v6_ironwood_nonzero_prior_total(void)
{
    struct transaction tx;
    transaction_init(&tx);
    tx.value_balance = 1;
    tx.ironwood_value_balance = INT64_MAX;
    bool rejected = transaction_get_shielded_value_in(&tx) == -1;
    transaction_free(&tx);
    return rejected;
}

static bool tx_v6_ironwood_invalid_spans(void)
{
    struct byte_stream wire;
    if (!tx_v6_ironwood_frame(&wire, -1)) return false;
    size_t truncated = wire.size - (32 + 1 + 64 + 64 + 1);
    struct byte_stream input;
    stream_init_from_data(&input, wire.data, truncated);
    struct transaction tx;
    bool ok = !transaction_v6_decode_prefix(&tx, &input, truncated) &&
        input.read_pos == 0 && tx.ironwood_value_balance == 0;
    transaction_free(&tx);
    stream_free(&wire);

    struct tx_in in;
    struct tx_out out;
    ok = tx_v6_transparent_frame(&wire, &in, &out) && ok;
    stream_init_from_data(&input, wire.data, wire.size);
    ok = transaction_v6_decode_prefix(&tx, &input, wire.size) &&
        tx.ironwood_value_balance == 0 &&
        transaction_get_value_out(&tx) == 123456789 &&
        transaction_get_shielded_value_in(&tx) == 0 && ok;
    transaction_free(&tx);
    stream_free(&wire);
    return ok;
}

static int test_tx_v6_ironwood_boundaries(void)
{
    static const struct {
        int64_t balance, out, in;
    } cases[] = {
        {INT64_MIN, -1, 0},
        {-(MAX_MONEY + 1), -1, 0},
        {MAX_MONEY + 1, 0, -1},
        {INT64_MAX, 0, -1}
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        struct transaction tx;
        transaction_init(&tx);
        tx.ironwood_value_balance = cases[i].balance;
        ok = transaction_get_value_out(&tx) == cases[i].out &&
            transaction_get_shielded_value_in(&tx) == cases[i].in && ok;
        transaction_free(&tx);
    }

    ok = tx_v6_ironwood_nonzero_prior_total() && ok;

    ok = tx_v6_ironwood_invalid_spans() && ok;
    printf("transaction v6 Ironwood balance bounds and invalid spans... %s\n",
           ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

int test_transaction(void)
{
    int failures = 0;

    failures += test_tx_v6_wire_lifecycle();
    failures += test_tx_v6_transparent_model();
    failures += test_tx_v6_model_allocation_failures();
    failures += test_tx_v6_ironwood_accounting();
    failures += test_tx_v6_ironwood_boundaries();
    failures += test_tx_outpoint_alloc_and_value();
    failures += test_tx_coinbase_bloom_and_merkle_roots();
    failures += test_tx_partial_merkle_build_extract();
    failures += test_tx_sighash_type_anyone_can_pay();
    failures += test_tx_stream_scalar_roundtrips();
    failures += test_tx_header_and_outpoint_serde();
    failures += test_tx_vin_vout_and_hash();
    failures += test_tx_signature_hash_sprout_sapling();
    failures += test_tx_check_transaction_rules();
    failures += test_tx_sig_checker_wiring();
    failures += test_tx_contextual_and_expiry();
    failures += test_tx_in_undo_roundtrip();
    failures += test_tx_block_undo_roundtrip();
    failures += test_tx_merkle_tree_serde();
    failures += test_tx_merkle_block_serde();
    failures += test_tx_serialize_roundtrip();
    failures += test_tx_js_description_serialize_groth_layout();
    failures += test_tx_js_description_serialize_phgr_layout();
    failures += test_tx_js_description_serialize_groth_tail_ignored();
    failures += test_tx_js_description_serialize_failure();
    failures += test_tx_js_description_deserialize_truncation();
    failures += test_tx_js_description_deserialize_groth_roundtrip();
    failures += test_tx_js_description_deserialize_groth_zero_proof_tail();
    failures += test_tx_js_description_deserialize_phgr_proof();
    failures += test_tx_js_description_deserialize_groth_trailing();
    return failures;
}
