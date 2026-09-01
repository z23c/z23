/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "coins/undo.h"
#include "storage/coins_view_sqlite.h"

struct mutable_coins_backing {
    struct uint256 txid;
    struct coins coins;
    bool present;
};

static bool mutable_backing_get(void *self, const struct uint256 *txid,
                                struct coins *out)
{
    struct mutable_coins_backing *b = self;
    if (!b->present || !uint256_eq(txid, &b->txid))
        return false;
    coins_copy(out, &b->coins);
    return true;
}

static bool mutable_backing_have(void *self, const struct uint256 *txid)
{
    struct mutable_coins_backing *b = self;
    return b->present && uint256_eq(txid, &b->txid) &&
           !coins_is_pruned(&b->coins);
}

static struct coins_view_vtable mutable_backing_vtable = {
    .get_coins = mutable_backing_get,
    .have_coins = mutable_backing_have,
};

int test_coins(void)
{
    int failures = 0;

    printf("coins cache memory counts vout amplification... ");
    {
        struct coins_view backing = {0};
        struct coins_view_cache cache;
        coins_view_cache_init(&cache, &backing);
        struct uint256 txid;
        uint256_set_null(&txid);
        struct coins_cache_entry *entry =
            coins_view_cache_modify_new(&cache, &txid);
        bool ok = entry && coins_alloc(&entry->coins, 3);
        if (ok)
            coins_view_cache_account_vout_resize(&cache, 0, 3);
        size_t expected = cache.cache_coins.num_buckets *
                              sizeof(struct coins_map_entry) +
                          3 * sizeof(struct tx_out);
        if (ok && coins_view_cache_memory_usage(&cache) == expected)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        coins_view_cache_free(&cache);
    }

    printf("coins_init... ");
    {
        struct coins c;
        coins_init(&c);
        if (!c.is_coinbase && c.vout == NULL && c.num_vout == 0 &&
            c.height == 0 && c.version == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("coins_alloc/free... ");
    {
        struct coins c;
        coins_init(&c);
        bool ok = coins_alloc(&c, 3);
        if (ok && c.num_vout == 3 && c.vout != NULL) {
            coins_free(&c);
            if (c.vout == NULL && c.num_vout == 0)
                printf("OK\n");
            else { printf("FAIL (free)\n"); failures++; }
        } else {
            printf("FAIL (alloc)\n"); failures++;
        }
    }

    printf("coins_alloc outputs are null... ");
    {
        struct coins c;
        coins_init(&c);
        coins_alloc(&c, 4);
        bool all_null = true;
        for (size_t i = 0; i < c.num_vout; i++) {
            if (!tx_out_is_null(&c.vout[i])) {
                all_null = false;
                break;
            }
        }
        if (all_null)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        coins_free(&c);
    }

    printf("tx_out_is_null... ");
    {
        struct tx_out out;
        tx_out_set_null(&out);
        bool null_check = tx_out_is_null(&out);
        out.value = 100;
        bool non_null_check = !tx_out_is_null(&out);
        if (null_check && non_null_check)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("coins_is_available... ");
    {
        struct coins c;
        coins_init(&c);
        coins_alloc(&c, 3);
        if (coins_is_available(&c, 0)) {
            printf("FAIL (null output reported available)\n");
            failures++;
        } else {
            c.vout[1].value = 5000;
            if (coins_is_available(&c, 1) && !coins_is_available(&c, 0) &&
                !coins_is_available(&c, 99))
                printf("OK\n");
            else { printf("FAIL\n"); failures++; }
        }
        coins_free(&c);
    }

    printf("coins_is_pruned all null... ");
    {
        struct coins c;
        coins_init(&c);
        coins_alloc(&c, 3);
        if (coins_is_pruned(&c))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        coins_free(&c);
    }

    printf("coins_is_pruned with live output... ");
    {
        struct coins c;
        coins_init(&c);
        coins_alloc(&c, 3);
        c.vout[1].value = 1000;
        if (!coins_is_pruned(&c))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        coins_free(&c);
    }

    printf("coins_is_pruned empty... ");
    {
        struct coins c;
        coins_init(&c);
        if (coins_is_pruned(&c))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("coins_spend... ");
    {
        struct coins c;
        coins_init(&c);
        coins_alloc(&c, 2);
        c.vout[0].value = 500;
        c.vout[1].value = 1000;
        bool spent = coins_spend(&c, 0);
        if (spent && !coins_is_available(&c, 0) && coins_is_available(&c, 1))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        coins_free(&c);
    }

    printf("coins_spend out of range... ");
    {
        struct coins c;
        coins_init(&c);
        coins_alloc(&c, 2);
        c.vout[0].value = 500;
        bool spent = coins_spend(&c, 5);
        if (!spent)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        coins_free(&c);
    }

    printf("coins_spend already spent... ");
    {
        struct coins c;
        coins_init(&c);
        coins_alloc(&c, 1);
        c.vout[0].value = 500;
        coins_spend(&c, 0);
        bool double_spend = coins_spend(&c, 0);
        if (!double_spend)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        coins_free(&c);
    }

    printf("coins_cleanup trims trailing nulls... ");
    {
        struct coins c;
        coins_init(&c);
        coins_alloc(&c, 5);
        c.vout[0].value = 100;
        c.vout[1].value = 200;
        coins_cleanup(&c);
        if (c.num_vout == 2)
            printf("OK (num_vout=%zu)\n", c.num_vout);
        else {
            printf("FAIL (num_vout=%zu, expected 2)\n", c.num_vout);
            failures++;
        }
        coins_free(&c);
    }

    printf("coins_copy... ");
    {
        struct coins src, dst;
        coins_init(&src);
        coins_init(&dst);
        coins_alloc(&src, 2);
        src.is_coinbase = true;
        src.height = 12345;
        src.version = 4;
        src.vout[0].value = 9999;
        src.vout[1].value = 8888;
        coins_copy(&dst, &src);
        if (dst.is_coinbase && dst.height == 12345 && dst.version == 4 &&
            dst.num_vout == 2 && dst.vout[0].value == 9999 &&
            dst.vout[1].value == 8888 && dst.vout != src.vout)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        coins_free(&src);
        coins_free(&dst);
    }

    printf("coins_from_transaction... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 3);
        tx.version = 4;
        tx.vout[0].value = 100;
        tx.vout[1].value = 200;
        tx.vout[2].value = 300;
        struct coins c;
        coins_init(&c);
        bool ok = coins_from_transaction(&c, &tx, 500);
        if (ok && c.height == 500 && c.version == 4 &&
            coins_is_available(&c, 0) && coins_is_available(&c, 1) &&
            coins_is_available(&c, 2) &&
            c.vout[0].value == 100 && c.vout[2].value == 300)
            printf("OK\n");
        else { printf("FAIL (ok=%d)\n", (int)ok); failures++; }
        coins_free(&c);
        transaction_free(&tx);
    }

    /* Round-23 contract: coins_from_transaction returns false (not a silent
     * empty record) when num_vout exceeds the 65536 cap. The cap check fires
     * before any vout deref, so we override num_vout past the cap on a tx that
     * really allocated only 1 output — restoring it before free. A false
     * return with an empty record is what update_coins relies on to fail the
     * connect instead of dropping the tx's outputs. */
    printf("coins_from_transaction over-cap returns false... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.version = 4;
        size_t real_vout = tx.num_vout;
        tx.num_vout = 65537;              /* over the 65536 cap */
        struct coins c;
        coins_init(&c);
        bool ok = coins_from_transaction(&c, &tx, 500);
        tx.num_vout = real_vout;          /* restore for a clean free */
        if (!ok && c.num_vout == 0 && c.vout == NULL)
            printf("OK\n");
        else { printf("FAIL (ok=%d num_vout=%zu)\n", (int)ok, c.num_vout); failures++; }
        coins_free(&c);
        transaction_free(&tx);
    }

    /* Round-23 contract: on a real OOM in coins_alloc, coins_from_transaction
     * returns false with an empty record rather than a misleading num_vout==0
     * "all pruned" coin. We arm the allocator fault seam on coins_alloc's
     * "coins_vout" label (fires once, then self-clears). */
    printf("coins_from_transaction OOM returns false... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 2);
        tx.version = 4;
        tx.vout[0].value = 100;
        tx.vout[1].value = 200;
        struct coins c;
        coins_init(&c);
        zcl_alloc_fault_fail_next("coins_vout");
        bool ok = coins_from_transaction(&c, &tx, 700);
        zcl_alloc_fault_clear();              /* belt-and-suspenders if unfired */
        if (!ok && c.num_vout == 0 && c.vout == NULL)
            printf("OK\n");
        else { printf("FAIL (ok=%d num_vout=%zu)\n", (int)ok, c.num_vout); failures++; }
        coins_free(&c);
        transaction_free(&tx);
    }

    printf("coins_stats_init... ");
    {
        struct coins_stats s;
        coins_stats_init(&s);
        if (s.height == 0 && s.num_transactions == 0 &&
            s.num_tx_outputs == 0 && s.total_amount == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("coins_alloc zero... ");
    {
        struct coins c;
        coins_init(&c);
        bool ok = coins_alloc(&c, 0);
        if (ok && c.num_vout == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        coins_free(&c);
    }

    /* ================================================================
     * coins_map: insert, find, erase, count
     * ================================================================ */
    printf("coins_map: insert/find/count... ");
    {
        struct coins_map m;
        coins_map_init(&m);

        struct uint256 txid1, txid2, txid3;
        memset(txid1.data, 0x11, 32);
        memset(txid2.data, 0x22, 32);
        memset(txid3.data, 0x33, 32);

        struct coins_cache_entry *e1 = coins_map_insert(&m, &txid1);
        struct coins_cache_entry *e2 = coins_map_insert(&m, &txid2);
        bool ok = (e1 != NULL) && (e2 != NULL) && (coins_map_count(&m) == 2);

        /* Find existing */
        ok = ok && (coins_map_find(&m, &txid1) == e1);
        ok = ok && (coins_map_find(&m, &txid2) == e2);
        /* Find non-existing */
        ok = ok && (coins_map_find(&m, &txid3) == NULL);
        /* Insert duplicate returns same entry */
        ok = ok && (coins_map_insert(&m, &txid1) == e1);
        ok = ok && (coins_map_count(&m) == 2);

        coins_map_free(&m);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("coins_map: erase... ");
    {
        struct coins_map m;
        coins_map_init(&m);

        struct uint256 txid1, txid2;
        memset(txid1.data, 0xAA, 32);
        memset(txid2.data, 0xBB, 32);

        coins_map_insert(&m, &txid1);
        coins_map_insert(&m, &txid2);

        bool ok = coins_map_erase(&m, &txid1);
        ok = ok && (coins_map_count(&m) == 1);
        ok = ok && (coins_map_find(&m, &txid1) == NULL);
        ok = ok && (coins_map_find(&m, &txid2) != NULL);

        /* Erase non-existing returns false */
        ok = ok && !coins_map_erase(&m, &txid1);

        coins_map_free(&m);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("coins_map: handles many insertions (rehash)... ");
    {
        struct coins_map m;
        coins_map_init(&m);

        for (int i = 0; i < 100; i++) {
            struct uint256 txid;
            memset(txid.data, 0, 32);
            memcpy(txid.data, &i, sizeof(i));
            coins_map_insert(&m, &txid);
        }
        bool ok = (coins_map_count(&m) == 100);

        /* Verify we can find them all */
        for (int i = 0; i < 100; i++) {
            struct uint256 txid;
            memset(txid.data, 0, 32);
            memcpy(txid.data, &i, sizeof(i));
            ok = ok && (coins_map_find(&m, &txid) != NULL);
        }

        coins_map_free(&m);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * coins_view_cache: init, modify_new, get_coins, have_coins
     * ================================================================ */
    printf("coins_view_cache: init and basic operations... ");
    {
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache cache;
        coins_view_cache_init(&cache, &null_view);

        bool ok = (coins_map_count(&cache.cache_coins) == 0);

        /* modify_new creates a fresh entry */
        struct uint256 txid;
        memset(txid.data, 0x42, 32);
        struct coins_cache_entry *entry = coins_view_cache_modify_new(&cache, &txid);
        ok = ok && (entry != NULL);
        ok = ok && (entry->flags & COINS_CACHE_DIRTY);
        ok = ok && (entry->flags & COINS_CACHE_FRESH);

        /* Populate the coins */
        coins_alloc(&entry->coins, 2);
        entry->coins.vout[0].value = 100;
        uint8_t pk1[] = {0x76};
        script_set(&entry->coins.vout[0].script_pub_key, pk1, 1);
        entry->coins.vout[1].value = 200;
        script_set(&entry->coins.vout[1].script_pub_key, pk1, 1);
        entry->coins.height = 500;
        entry->coins.version = 4;

        /* have_coins should find it */
        ok = ok && coins_view_cache_have_coins(&cache, &txid);

        /* get_coins should retrieve it */
        struct coins retrieved;
        coins_init(&retrieved);
        ok = ok && coins_view_cache_get_coins(&cache, &txid, &retrieved);
        ok = ok && (retrieved.vout[0].value == 100);
        ok = ok && (retrieved.vout[1].value == 200);
        ok = ok && (retrieved.height == 500);
        coins_free(&retrieved);

        /* Unknown txid should not be found */
        struct uint256 unknown;
        memset(unknown.data, 0xFF, 32);
        ok = ok && !coins_view_cache_have_coins(&cache, &unknown);

        coins_view_cache_free(&cache);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* A process-lifetime cache over canonical coins_kv must not retain an
     * output from the generation before a finalized block spent it. */
    printf("coins_view_cache: committed backing generation invalidates... ");
    {
        struct mutable_coins_backing backing;
        memset(&backing, 0, sizeof(backing));
        memset(backing.txid.data, 0x4A, sizeof(backing.txid.data));
        coins_init(&backing.coins);
        bool ok = coins_alloc(&backing.coins, 1);
        backing.coins.vout[0].value = 1250000000;
        uint8_t pk[] = {0x51};
        script_set(&backing.coins.vout[0].script_pub_key, pk, sizeof(pk));
        backing.present = true;

        struct coins_view view = {
            .vtable = &mutable_backing_vtable,
            .impl = &backing,
        };
        struct coins_view_cache cache;
        coins_view_cache_init(&cache, &view);

        /* Populate the clean read-through entry, then commit its spend in the
         * independent backing authority. Before invalidation this is exactly
         * the stale generation that admitted A a second time. */
        ok = ok && coins_view_cache_have_coins(&cache, &backing.txid);
        struct coins loaded;
        coins_init(&loaded);
        ok = ok && coins_view_cache_get_coins(&cache, &backing.txid, &loaded);
        coins_free(&loaded);
        backing.present = false;
        ok = ok && coins_view_cache_have_coins(&cache, &backing.txid);

        ok = ok && coins_view_cache_invalidate(&cache, &backing.txid);
        ok = ok && !coins_view_cache_have_coins(&cache, &backing.txid);
        ok = ok && coins_map_count(&cache.cache_coins) == 0;

        coins_view_cache_free(&cache);
        coins_free(&backing.coins);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * coins_view_cache: modify existing entry
     * ================================================================ */
    printf("coins_view_cache: modify marks dirty... ");
    {
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache cache;
        coins_view_cache_init(&cache, &null_view);

        struct uint256 txid;
        memset(txid.data, 0x55, 32);
        struct coins_cache_entry *entry = coins_view_cache_modify_new(&cache, &txid);
        coins_alloc(&entry->coins, 1);
        entry->coins.vout[0].value = 50;
        uint8_t pk2[] = {0x76};
        script_set(&entry->coins.vout[0].script_pub_key, pk2, 1);

        /* modify should return same entry and mark dirty */
        entry->flags = 0; /* clear flags */
        struct coins_cache_entry *e2 = coins_view_cache_modify(&cache, &txid);
        bool ok = (e2 == entry) && (e2->flags & COINS_CACHE_DIRTY);

        coins_view_cache_free(&cache);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * coins_view_cache: set/get best block
     * ================================================================ */
    printf("coins_view_cache: set/get best block... ");
    {
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache cache;
        coins_view_cache_init(&cache, &null_view);

        struct uint256 block_hash;
        memset(block_hash.data, 0xAA, 32);
        coins_view_cache_set_best_block(&cache, &block_hash);

        struct uint256 retrieved;
        coins_view_cache_get_best_block(&cache, &retrieved);
        bool ok = uint256_eq(&retrieved, &block_hash);

        coins_view_cache_free(&cache);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * coins_view_cache: have_inputs for coinbase is always true
     * ================================================================ */
    printf("coins_view_cache: have_inputs coinbase always true... ");
    {
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache cache;
        coins_view_cache_init(&cache, &null_view);

        /* Create a coinbase tx (prevout hash all zeros, n=UINT32_MAX) */
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        memset(tx.vin[0].prevout.hash.data, 0, 32);
        tx.vin[0].prevout.n = UINT32_MAX;
        tx.vout[0].value = 1250000000LL;

        bool ok = coins_view_cache_have_inputs(&cache, &tx);

        transaction_free(&tx);
        coins_view_cache_free(&cache);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * coins_view_cache: flush to parent cache
     * ================================================================ */
    printf("coins_view_cache: flush to parent... ");
    {
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));

        struct coins_view_cache parent;
        coins_view_cache_init(&parent, &null_view);

        /* Make parent usable as a backing view */
        struct coins_view parent_as_view;
        coins_view_cache_as_view(&parent_as_view, &parent);

        struct coins_view_cache child;
        coins_view_cache_init(&child, &parent_as_view);

        /* Add a coin to child */
        struct uint256 txid;
        memset(txid.data, 0x77, 32);
        struct coins_cache_entry *entry = coins_view_cache_modify_new(&child, &txid);
        coins_alloc(&entry->coins, 1);
        entry->coins.vout[0].value = 999;
        uint8_t pk3[] = {0x76};
        script_set(&entry->coins.vout[0].script_pub_key, pk3, 1);

        struct uint256 block_hash;
        memset(block_hash.data, 0x88, 32);
        coins_view_cache_set_best_block(&child, &block_hash);

        /* Flush child to parent */
        bool ok = coins_view_cache_flush_for_testing(&child);

        /* Child should be empty after flush */
        ok = ok && (coins_map_count(&child.cache_coins) == 0);

        /* Parent should now have the coin */
        ok = ok && coins_view_cache_have_coins(&parent, &txid);
        struct coins retrieved;
        coins_init(&retrieved);
        ok = ok && coins_view_cache_get_coins(&parent, &txid, &retrieved);
        ok = ok && (retrieved.vout[0].value == 999);
        coins_free(&retrieved);

        /* Parent should have the best block hash */
        struct uint256 parent_hash;
        coins_view_cache_get_best_block(&parent, &parent_hash);
        ok = ok && uint256_eq(&parent_hash, &block_hash);

        coins_view_cache_free(&child);
        coins_view_cache_free(&parent);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * coins_view_cache: get_value_in for coinbase returns 0
     * ================================================================ */
    printf("coins_view_cache: get_value_in coinbase returns 0... ");
    {
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache cache;
        coins_view_cache_init(&cache, &null_view);

        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        memset(tx.vin[0].prevout.hash.data, 0, 32);
        tx.vin[0].prevout.n = UINT32_MAX;
        tx.vout[0].value = 1250000000LL;

        int64_t val = coins_view_cache_get_value_in(&cache, &tx);
        bool ok = (val == 0);

        transaction_free(&tx);
        coins_view_cache_free(&cache);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * BUG FIX TEST: OP_RETURN outputs excluded from UTXO set
     * Bitcoin Core's AddCoin() calls IsUnspendable() and skips OP_RETURN.
     * Our coins_from_transaction must do the same.
     * ================================================================ */
    printf("coins_from_transaction: OP_RETURN excluded... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 3);
        tx.version = 4;

        /* vout[0]: normal P2PKH output */
        tx.vout[0].value = 100000;
        uint8_t p2pkh[] = {0x76, 0xa9, 0x14,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0x88, 0xac};
        script_set(&tx.vout[0].script_pub_key, p2pkh, sizeof(p2pkh));

        /* vout[1]: OP_RETURN (unspendable — must NOT enter UTXO set) */
        tx.vout[1].value = 0;
        uint8_t op_return[] = {0x6a, 0x04, 'S', 'L', 'P', 0x00};
        script_set(&tx.vout[1].script_pub_key, op_return, sizeof(op_return));

        /* vout[2]: normal P2SH output */
        tx.vout[2].value = 50000;
        uint8_t p2sh[] = {0xa9, 0x14,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0x87};
        script_set(&tx.vout[2].script_pub_key, p2sh, sizeof(p2sh));

        struct coins c;
        coins_init(&c);
        coins_from_transaction(&c, &tx, 1000);

        /* vout[0] should be available (P2PKH) */
        bool ok = coins_is_available(&c, 0);
        /* vout[1] should be NULL (OP_RETURN filtered out) */
        ok = ok && !coins_is_available(&c, 1);
        /* vout[2] should be available (P2SH) */
        ok = ok && coins_is_available(&c, 2);
        /* Values should be correct */
        ok = ok && (c.vout[0].value == 100000);
        ok = ok && (c.vout[2].value == 50000);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        coins_free(&c);
        transaction_free(&tx);
    }

    printf("coins_from_transaction: all OP_RETURN tx pruned... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.version = 4;

        /* Single OP_RETURN output */
        tx.vout[0].value = 0;
        uint8_t op_return[] = {0x6a, 0x02, 0xFF, 0xFF};
        script_set(&tx.vout[0].script_pub_key, op_return, sizeof(op_return));

        struct coins c;
        coins_init(&c);
        coins_from_transaction(&c, &tx, 2000);

        /* Should be pruned (no available outputs) */
        bool ok = coins_is_pruned(&c);
        /* num_vout should be 0 after cleanup */
        ok = ok && (c.num_vout == 0);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        coins_free(&c);
        transaction_free(&tx);
    }

    printf("script_is_unspendable: OP_RETURN... ");
    {
        struct script s;
        uint8_t op_ret[] = {0x6a, 0x04, 0x00, 0x00, 0x00, 0x00};
        script_set(&s, op_ret, sizeof(op_ret));
        bool ok = script_is_unspendable(&s);

        /* Normal P2PKH should be spendable */
        uint8_t p2pkh[] = {0x76, 0xa9, 0x14,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0x88, 0xac};
        script_set(&s, p2pkh, sizeof(p2pkh));
        ok = ok && !script_is_unspendable(&s);

        /* Empty script is spendable */
        s.size = 0;
        ok = ok && !script_is_unspendable(&s);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── coins_view_sqlite batch_write error safety ── */

    printf("coins_view_sqlite: batch_write with NULL db returns false... ");
    {
        struct coins_view_sqlite cvs;
        memset(&cvs, 0, sizeof(cvs));
        /* db is NULL — should return false immediately */
        struct coins_map cm;
        coins_map_init(&cm);
        struct uint256 hash;
        uint256_set_null(&hash);
        bool ok = !coins_view_sqlite_batch_write(&cvs, &cm, &hash, NULL);
        coins_map_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("coins_view_sqlite: roundtrip flush and read back... ");
    {
        /* Create an in-memory SQLite DB, open coins_view_sqlite on it,
         * write some UTXOs via batch_write, then read them back. */
        sqlite3 *db = NULL;
        int rc = sqlite3_open(":memory:", &db);
        bool ok = (rc == SQLITE_OK && db != NULL);
        if (ok) {
            /* Create utxos table */
            TEST_DB_EXEC(db,
                "CREATE TABLE IF NOT EXISTS utxos ("
                " txid BLOB NOT NULL, vout INTEGER NOT NULL,"
                " value INTEGER, script BLOB, script_type INTEGER,"
                " address_hash BLOB, height INTEGER, is_coinbase INTEGER,"
                " PRIMARY KEY(txid, vout))");
            TEST_DB_EXEC(db,
                "CREATE TABLE IF NOT EXISTS node_state ("
                " key TEXT PRIMARY KEY, value BLOB)");

            struct coins_view_sqlite cvs;
            if (coins_view_sqlite_open(&cvs, db)) {
                /* Build a coins_map with one entry */
                struct coins_map cm;
                coins_map_init(&cm);
                struct uint256 txid;
                memset(txid.data, 0x42, 32);
                struct coins_cache_entry *e = coins_map_insert(&cm, &txid);
                coins_alloc(&e->coins, 2);
                e->coins.vout[0].value = 50000000;
                uint8_t p2pkh[] = {0x76, 0xa9, 0x14,
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                    0x88, 0xac};
                script_set(&e->coins.vout[0].script_pub_key,
                           p2pkh, sizeof(p2pkh));
                e->coins.height = 100;
                e->coins.is_coinbase = true;
                e->flags = COINS_CACHE_DIRTY;

                struct uint256 best;
                memset(best.data, 0xBB, 32);

                /* Flush to SQLite */
                ok = coins_view_sqlite_batch_write(&cvs, &cm, &best,
                                                       NULL);

                /* Read back */
                if (ok) {
                    struct coins readback;
                    coins_init(&readback);
                    ok = coins_view_sqlite_get_coins(&cvs, &txid, &readback);
                    ok = ok && readback.height == 100;
                    ok = ok && readback.is_coinbase;
                    ok = ok && readback.num_vout >= 1;
                    ok = ok && readback.vout[0].value == 50000000;
                    coins_free(&readback);

                    /* Read back best block */
                    struct uint256 read_best;
                    ok = ok && coins_view_sqlite_get_best_block(&cvs, &read_best);
                    ok = ok && uint256_eq(&read_best, &best);
                }

                coins_map_free(&cm);
                coins_view_sqlite_close(&cvs);
            } else {
                ok = false;
            }
            sqlite3_close(db);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("coins_view_sqlite: flush retains cache on failure... ");
    {
        /* The test-only coins view cache flush must NOT clear the cache when
         * batch_write returns false. Verify via the null-view pattern. */
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache cache;
        coins_view_cache_init(&cache, &null_view);

        /* Add a coin to the cache */
        struct uint256 txid;
        memset(txid.data, 0x77, 32);
        struct coins_cache_entry *entry =
            coins_view_cache_modify_new(&cache, &txid);
        coins_alloc(&entry->coins, 1);
        entry->coins.vout[0].value = 999;
        entry->coins.height = 500;

        /* Flush will fail because null_view has no batch_write */
        bool flush_ok = coins_view_cache_flush_for_testing(&cache);
        /* Flush should fail */
        bool ok = !flush_ok;
        /* Cache should still have the entry (not cleared) */
        ok = ok && coins_view_cache_have_coins(&cache, &txid);
        ok = ok && (cache.cache_coins.size > 0);

        coins_view_cache_free(&cache);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("coins_view_sqlite: SAVEPOINT nests inside foreign transaction... ");
    {
        /* THE CRITICAL TEST: coins flush works inside a foreign transaction.
         * 1. Open a sqlite3 db
         * 2. Start a foreign BEGIN TRANSACTION (like node_db batch)
         * 3. Call coins_view_sqlite_batch_write (uses SAVEPOINT)
         * 4. SAVEPOINT nests inside the BEGIN, flush succeeds
         * 5. COMMIT the foreign txn, then verify UTXOs readable */
        sqlite3 *db = NULL;
        int rc = sqlite3_open(":memory:", &db);
        bool ok = (rc == SQLITE_OK && db != NULL);
        if (ok) {
            TEST_DB_EXEC(db,
                "CREATE TABLE IF NOT EXISTS utxos ("
                " txid BLOB NOT NULL, vout INTEGER NOT NULL,"
                " value INTEGER, script BLOB, script_type INTEGER,"
                " address_hash BLOB, height INTEGER, is_coinbase INTEGER,"
                " PRIMARY KEY(txid, vout))");
            TEST_DB_EXEC(db,
                "CREATE TABLE IF NOT EXISTS node_state ("
                " key TEXT PRIMARY KEY, value BLOB)");

            struct coins_view_sqlite cvs;
            if (coins_view_sqlite_open(&cvs, db)) {
                /* Simulate node_db opening a transaction */
                TEST_DB_BEGIN_TXN(db);
                /* Verify autocommit is OFF (foreign txn is open) */
                ok = (sqlite3_get_autocommit(db) == 0);

                /* Build coins map */
                struct coins_map cm;
                coins_map_init(&cm);
                struct uint256 txid;
                memset(txid.data, 0x55, 32);
                struct coins_cache_entry *e = coins_map_insert(&cm, &txid);
                coins_alloc(&e->coins, 1);
                e->coins.vout[0].value = 12345678;
                uint8_t p2pkh[] = {0x76, 0xa9, 0x14,
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                    0x88, 0xac};
                script_set(&e->coins.vout[0].script_pub_key,
                           p2pkh, sizeof(p2pkh));
                e->coins.height = 200;
                e->coins.is_coinbase = false;
                e->flags = COINS_CACHE_DIRTY;

                struct uint256 best;
                memset(best.data, 0xCC, 32);

                /* SAVEPOINT nests inside the foreign BEGIN — flush succeeds */
                bool flush_ok = coins_view_sqlite_batch_write(
                    &cvs, &cm, &best, NULL);
                ok = ok && flush_ok;

                /* Foreign transaction is still open (SAVEPOINT doesn't end it) */
                ok = ok && (sqlite3_get_autocommit(db) == 0);

                /* UTXO is visible within the transaction */
                if (ok) {
                    struct coins readback;
                    coins_init(&readback);
                    ok = ok && coins_view_sqlite_get_coins(&cvs, &txid, &readback);
                    ok = ok && readback.vout[0].value == 12345678;
                    ok = ok && readback.height == 200;
                    coins_free(&readback);
                }

                /* Commit the foreign transaction — data persists */
                TEST_DB_COMMIT(db);
                ok = ok && (sqlite3_get_autocommit(db) != 0);

                coins_map_free(&cm);
                coins_view_sqlite_close(&cvs);
            } else {
                ok = false;
            }
            sqlite3_close(db);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("coins_view_sqlite: multi-flush with interleaved foreign txns... ");
    {
        /* Simulate the IBD pattern: repeated flushes where each one
         * might find a foreign transaction open. ALL must succeed. */
        sqlite3 *db = NULL;
        sqlite3_open(":memory:", &db);
        bool ok = (db != NULL);
        if (ok) {
            TEST_DB_EXEC(db,
                "CREATE TABLE IF NOT EXISTS utxos ("
                " txid BLOB NOT NULL, vout INTEGER NOT NULL,"
                " value INTEGER, script BLOB, script_type INTEGER,"
                " address_hash BLOB, height INTEGER, is_coinbase INTEGER,"
                " PRIMARY KEY(txid, vout))");
            TEST_DB_EXEC(db,
                "CREATE TABLE IF NOT EXISTS node_state ("
                " key TEXT PRIMARY KEY, value BLOB)");

            struct coins_view_sqlite cvs;
            coins_view_sqlite_open(&cvs, db);

            uint8_t p2pkh[] = {0x76, 0xa9, 0x14,
                1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                0x88, 0xac};

            /* Do 10 flush cycles, alternating foreign txn / clean */
            for (int cycle = 0; cycle < 10 && ok; cycle++) {
                /* Half the time, open a foreign transaction first */
                if (cycle % 2 == 0)
                    TEST_DB_BEGIN(db);

                struct coins_map cm;
                coins_map_init(&cm);
                struct uint256 txid;
                memset(txid.data, 0, 32);
                txid.data[0] = (uint8_t)cycle;
                struct coins_cache_entry *e = coins_map_insert(&cm, &txid);
                coins_alloc(&e->coins, 1);
                e->coins.vout[0].value = 1000 * (cycle + 1);
                script_set(&e->coins.vout[0].script_pub_key,
                           p2pkh, sizeof(p2pkh));
                e->coins.height = cycle * 500;
                e->flags = COINS_CACHE_DIRTY;

                struct uint256 best;
                memset(best.data, (uint8_t)cycle, 32);

                bool flush_ok = coins_view_sqlite_batch_write(
                    &cvs, &cm, &best, NULL);
                ok = ok && flush_ok;

                /* If we opened a foreign txn, commit it after flush */
                if (cycle % 2 == 0)
                    TEST_DB_COMMIT(db);

                coins_map_free(&cm);
            }

            /* Verify all 10 UTXOs are readable */
            for (int cycle = 0; cycle < 10 && ok; cycle++) {
                struct uint256 txid;
                memset(txid.data, 0, 32);
                txid.data[0] = (uint8_t)cycle;
                struct coins readback;
                coins_init(&readback);
                ok = ok && coins_view_sqlite_get_coins(&cvs, &txid, &readback);
                ok = ok && readback.vout[0].value == 1000 * (cycle + 1);
                coins_free(&readback);
            }

            coins_view_sqlite_close(&cvs);
            sqlite3_close(db);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("coins_view_sqlite: read helpers reset statements before flush... ");
    {
        sqlite3 *db = NULL;
        int rc = sqlite3_open(":memory:", &db);
        bool ok = (rc == SQLITE_OK && db != NULL);
        if (ok) {
            TEST_DB_EXEC(db,
                "CREATE TABLE IF NOT EXISTS utxos ("
                " txid BLOB NOT NULL, vout INTEGER NOT NULL,"
                " value INTEGER, script BLOB, script_type INTEGER,"
                " address_hash BLOB, height INTEGER, is_coinbase INTEGER,"
                " PRIMARY KEY(txid, vout))");
            TEST_DB_EXEC(db,
                "CREATE TABLE IF NOT EXISTS node_state ("
                " key TEXT PRIMARY KEY, value BLOB)");

            struct coins_view_sqlite cvs;
            ok = coins_view_sqlite_open(&cvs, db);
            if (ok) {
                uint8_t p2pkh[] = {0x76, 0xa9, 0x14,
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                    0x88, 0xac};
                struct coins_map cm;
                struct uint256 txid, best, read_best;
                struct coins readback;

                coins_map_init(&cm);
                memset(txid.data, 0x66, 32);
                memset(best.data, 0xAB, 32);
                uint256_set_null(&read_best);

                struct coins_cache_entry *e = coins_map_insert(&cm, &txid);
                coins_alloc(&e->coins, 1);
                e->coins.vout[0].value = 424242;
                script_set(&e->coins.vout[0].script_pub_key,
                           p2pkh, sizeof(p2pkh));
                e->coins.height = 321;
                e->flags = COINS_CACHE_DIRTY;

                ok = coins_view_sqlite_batch_write(&cvs, &cm, &best,
                                                       NULL);
                ok = ok && coins_view_sqlite_have_coins(&cvs, &txid);
                coins_init(&readback);
                ok = ok && coins_view_sqlite_get_coins(&cvs, &txid, &readback);
                ok = ok && readback.vout[0].value == 424242;
                coins_free(&readback);
                ok = ok && coins_view_sqlite_get_best_block(&cvs, &read_best);
                ok = ok && uint256_eq(&best, &read_best);

                TEST_DB_BEGIN_TXN(db);
                memset(best.data, 0xBC, 32);
                ok = ok && coins_view_sqlite_batch_write(
                    &cvs, &cm, &best, NULL);
                TEST_DB_COMMIT(db);

                coins_map_free(&cm);
                coins_view_sqlite_close(&cvs);
            }
            sqlite3_close(db);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("coins_view_sqlite: spend-after-flush roundtrip... ");
    {
        /* Test the exact failure mode: create UTXO, flush, spend UTXO,
         * flush again. The second flush must DELETE from SQLite. */
        sqlite3 *db = NULL;
        sqlite3_open(":memory:", &db);
        bool ok = (db != NULL);
        if (ok) {
            sqlite3_exec(db,
                "CREATE TABLE IF NOT EXISTS utxos ("
                " txid BLOB NOT NULL, vout INTEGER NOT NULL,"
                " value INTEGER, script BLOB, script_type INTEGER,"
                " address_hash BLOB, height INTEGER, is_coinbase INTEGER,"
                " PRIMARY KEY(txid, vout))", NULL, NULL, NULL);
            sqlite3_exec(db,
                "CREATE TABLE IF NOT EXISTS node_state ("
                " key TEXT PRIMARY KEY, value BLOB)", NULL, NULL, NULL);

            struct coins_view_sqlite cvs;
            coins_view_sqlite_open(&cvs, db);

            /* Step 1: Create and flush a UTXO */
            struct uint256 txid;
            memset(txid.data, 0xAA, 32);
            {
                struct coins_map cm;
                coins_map_init(&cm);
                struct coins_cache_entry *e = coins_map_insert(&cm, &txid);
                coins_alloc(&e->coins, 1);
                e->coins.vout[0].value = 50000000;
                uint8_t p2pkh[] = {0x76, 0xa9, 0x14,
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                    0x88, 0xac};
                script_set(&e->coins.vout[0].script_pub_key,
                           p2pkh, sizeof(p2pkh));
                e->coins.height = 100;
                e->flags = COINS_CACHE_DIRTY;
                struct uint256 best;
                memset(best.data, 0x11, 32);
                ok = coins_view_sqlite_batch_write(&cvs, &cm, &best,
                                                       NULL);
                coins_map_free(&cm);
            }

            /* Verify UTXO exists in SQLite */
            if (ok) {
                struct coins c;
                coins_init(&c);
                ok = coins_view_sqlite_get_coins(&cvs, &txid, &c);
                ok = ok && c.vout[0].value == 50000000;
                coins_free(&c);
            }

            /* Step 2: "Spend" the UTXO (mark as pruned) and flush */
            if (ok) {
                struct coins_map cm;
                coins_map_init(&cm);
                struct coins_cache_entry *e = coins_map_insert(&cm, &txid);
                /* Pruned = all outputs null, num_vout = 0 */
                e->coins.num_vout = 0;
                e->coins.vout = NULL;
                e->flags = COINS_CACHE_DIRTY;
                struct uint256 best;
                memset(best.data, 0x22, 32);
                ok = coins_view_sqlite_batch_write(&cvs, &cm, &best,
                                                       NULL);
                coins_map_free(&cm);
            }

            /* Verify UTXO is gone from SQLite */
            if (ok) {
                struct coins c;
                coins_init(&c);
                bool found = coins_view_sqlite_get_coins(&cvs, &txid, &c);
                /* Should NOT be found (was deleted) */
                ok = !found;
                coins_free(&c);
            }

            coins_view_sqlite_close(&cvs);
            sqlite3_close(db);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
