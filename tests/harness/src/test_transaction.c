/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "bloom/bloom.h"
#include "chain/chainparams.h"
#include "validation/check_transaction.h"
#include "validation/tx_verifier.h"
#include "validation/contextual_check_tx.h"
#include "coins/undo.h"
#include "bloom/merkleblock.h"

int test_transaction(void)
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

    printf("stream write/read u32... ");
    {
        struct byte_stream s;
        stream_init(&s, 64);
        stream_write_u32_le(&s, 0xDEADBEEF);
        stream_write_u32_le(&s, 0x12345678);
        s.read_pos = 0;
        uint32_t v1, v2;
        stream_read_u32_le(&s, &v1);
        stream_read_u32_le(&s, &v2);
        if (v1 == 0xDEADBEEF && v2 == 0x12345678 && s.size == 8)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&s);
    }

    printf("stream compact_size roundtrip... ");
    {
        struct byte_stream s;
        stream_init(&s, 64);
        stream_write_compact_size(&s, 0);
        stream_write_compact_size(&s, 252);
        stream_write_compact_size(&s, 253);
        stream_write_compact_size(&s, 0x10000);
        stream_write_compact_size(&s, 0x100000000ULL);
        s.read_pos = 0;
        uint64_t v;
        bool ok = true;
        stream_read_compact_size(&s, &v); ok &= (v == 0);
        stream_read_compact_size(&s, &v); ok &= (v == 252);
        stream_read_compact_size(&s, &v); ok &= (v == 253);
        stream_read_compact_size(&s, &v); ok &= (v == 0x10000);
        stream_read_compact_size(&s, &v); ok &= (v == 0x100000000ULL);
        if (ok && !s.error)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&s);
    }

    printf("stream varint roundtrip... ");
    {
        struct byte_stream s;
        stream_init(&s, 64);
        stream_write_varint(&s, 0);
        stream_write_varint(&s, 127);
        stream_write_varint(&s, 128);
        stream_write_varint(&s, 0xFFFF);
        stream_write_varint(&s, 0xFFFFFFFFULL);
        s.read_pos = 0;
        uint64_t v;
        bool ok = true;
        stream_read_varint(&s, &v); ok &= (v == 0);
        stream_read_varint(&s, &v); ok &= (v == 127);
        stream_read_varint(&s, &v); ok &= (v == 128);
        stream_read_varint(&s, &v); ok &= (v == 0xFFFF);
        stream_read_varint(&s, &v); ok &= (v == 0xFFFFFFFFULL);
        if (ok && !s.error)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&s);
    }

    printf("stream from_data read-only... ");
    {
        unsigned char data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        struct byte_stream s;
        stream_init_from_data(&s, data, sizeof(data));
        uint32_t v1, v2;
        stream_read_u32_le(&s, &v1);
        stream_read_u32_le(&s, &v2);
        if (v1 == 0x04030201 && v2 == 0x08070605 && stream_remaining(&s) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

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
