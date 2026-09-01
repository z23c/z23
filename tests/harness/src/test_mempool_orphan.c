/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for orphan transaction pool: max 50 txs, 10-min TTL,
 * reconnect on parent arrival. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "validation/orphan_pool.h"
#include "validation/txmempool.h"
#include "util/safe_alloc.h"

/* ── helpers ────────────────────────────────────────────── */

static void init_orphan_tx(struct transaction *tx, uint8_t id, uint8_t parent_id)
{
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->num_vin = 1;
    tx->vin = zcl_calloc(1, sizeof(struct tx_in), "orphan_vin");
    memset(tx->vin[0].prevout.hash.data, parent_id, 32);
    tx->vin[0].prevout.n = 0;
    uint8_t sig[] = {0x00};
    script_set(&tx->vin[0].script_sig, sig, 1);
    tx->vin[0].sequence = 0xFFFFFFFF;
    tx->num_vout = 1;
    tx->vout = zcl_calloc(1, sizeof(struct tx_out), "orphan_vout");
    tx->vout[0].value = 50000;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx->vout[0].script_pub_key, pk, 3);
    memset(tx->hash.data, id, 32);
}

static void init_multi_input_orphan(struct transaction *tx, uint8_t id,
                                      uint8_t parent1, uint8_t parent2)
{
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->num_vin = 2;
    tx->vin = zcl_calloc(2, sizeof(struct tx_in), "orphan_multi_vin");
    memset(tx->vin[0].prevout.hash.data, parent1, 32);
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = 0xFFFFFFFF;
    uint8_t sig[] = {0x00};
    script_set(&tx->vin[0].script_sig, sig, 1);
    memset(tx->vin[1].prevout.hash.data, parent2, 32);
    tx->vin[1].prevout.n = 0;
    tx->vin[1].sequence = 0xFFFFFFFF;
    script_set(&tx->vin[1].script_sig, sig, 1);
    tx->num_vout = 1;
    tx->vout = zcl_calloc(1, sizeof(struct tx_out), "orphan_multi_vout");
    tx->vout[0].value = 50000;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx->vout[0].script_pub_key, pk, 3);
    memset(tx->hash.data, id, 32);
}

static void free_orphan_tx(struct transaction *tx)
{
    free(tx->vin);
    free(tx->vout);
}

/* ── tests ──────────────────────────────────────────────── */

int test_mempool_orphan(void)
{
    int failures = 0;
    printf("\n=== Mempool Orphan Pool ===\n");

    printf("GIVEN empty pool THEN size is 0... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        if (orphan_pool_size(&pool) != 0) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
        orphan_pool_free(&pool);
    }

    printf("GIVEN orphan tx THEN add succeeds and exists returns true... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        struct transaction tx; init_orphan_tx(&tx,0x01, 0xAA);
        bool added = orphan_pool_add(&pool, &tx);
        bool exists = orphan_pool_exists(&pool, &tx.hash);
        size_t sz = orphan_pool_size(&pool);
        free_orphan_tx(&tx);
        orphan_pool_free(&pool);
        if (!added || !exists || sz != 1) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN duplicate tx THEN second add is rejected... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        struct transaction tx; init_orphan_tx(&tx,0x02, 0xBB);
        orphan_pool_add(&pool, &tx);
        bool dup = orphan_pool_add(&pool, &tx);
        size_t sz = orphan_pool_size(&pool);
        free_orphan_tx(&tx);
        orphan_pool_free(&pool);
        if (dup || sz != 1) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN full pool (50 txs) THEN 51st add is rejected... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        struct transaction txs[51];
        for (int i = 0; i < 50; i++) {
            init_orphan_tx(&txs[i], (uint8_t)(i + 1), 0xAA);
            orphan_pool_add(&pool, &txs[i]);
        }
        init_orphan_tx(&txs[50], 0xFF, 0xBB);
        bool added = orphan_pool_add(&pool, &txs[50]);
        size_t sz = orphan_pool_size(&pool);
        for (int i = 0; i <= 50; i++) free_orphan_tx(&txs[i]);
        orphan_pool_free(&pool);
        if (added || sz != 50) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN orphan tx THEN remove by hash works... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        struct transaction tx; init_orphan_tx(&tx,0x10, 0xCC);
        orphan_pool_add(&pool, &tx);
        orphan_pool_remove(&pool, &tx.hash);
        size_t sz = orphan_pool_size(&pool);
        bool exists = orphan_pool_exists(&pool, &tx.hash);
        free_orphan_tx(&tx);
        orphan_pool_free(&pool);
        if (sz != 0 || exists) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN entries THEN clear removes all... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        for (int i = 0; i < 5; i++) {
            struct transaction tx; init_orphan_tx(&tx,(uint8_t)(i + 1), 0xDD);
            orphan_pool_add(&pool, &tx);
            free_orphan_tx(&tx);
        }
        orphan_pool_clear(&pool);
        if (orphan_pool_size(&pool) != 0) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
        orphan_pool_free(&pool);
    }

    printf("GIVEN expired orphans THEN expire removes them... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        struct transaction tx1; init_orphan_tx(&tx1,0x01, 0xAA);
        struct transaction tx2; init_orphan_tx(&tx2,0x02, 0xBB);
        orphan_pool_add(&pool, &tx1);
        orphan_pool_add(&pool, &tx2);
        /* Backdate tx1 */
        zcl_mutex_lock(&pool.cs);
        for (size_t i = 0; i < ORPHAN_MAX_ENTRIES; i++) {
            if (pool.entries[i].used &&
                uint256_eq(&pool.entries[i].tx.hash, &tx1.hash))
                pool.entries[i].arrival_time -= ORPHAN_TTL_SECONDS + 1;
        }
        zcl_mutex_unlock(&pool.cs);
        int64_t now = (int64_t)platform_time_wall_time_t();
        size_t removed = orphan_pool_expire(&pool, now);
        bool t1gone = !orphan_pool_exists(&pool, &tx1.hash);
        bool t2here = orphan_pool_exists(&pool, &tx2.hash);
        free_orphan_tx(&tx1);
        free_orphan_tx(&tx2);
        orphan_pool_free(&pool);
        if (removed != 1 || !t1gone || !t2here) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN non-expired orphans THEN expire removes none... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        struct transaction tx; init_orphan_tx(&tx,0x01, 0xAA);
        orphan_pool_add(&pool, &tx);
        int64_t now = (int64_t)platform_time_wall_time_t();
        size_t removed = orphan_pool_expire(&pool, now);
        free_orphan_tx(&tx);
        orphan_pool_free(&pool);
        if (removed != 0) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN orphan spending parent P THEN find_children returns it... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        struct transaction tx1; init_orphan_tx(&tx1,0x01, 0xAA);
        struct transaction tx2; init_orphan_tx(&tx2,0x02, 0xBB);
        struct transaction tx3; init_orphan_tx(&tx3,0x03, 0xAA);
        orphan_pool_add(&pool, &tx1);
        orphan_pool_add(&pool, &tx2);
        orphan_pool_add(&pool, &tx3);
        struct uint256 parent_aa;
        memset(parent_aa.data, 0xAA, 32);
        struct transaction children[10];
        size_t n = orphan_pool_find_children(&pool, &parent_aa, children, 10);
        for (size_t i = 0; i < n; i++) transaction_free(&children[i]);
        free_orphan_tx(&tx1);
        free_orphan_tx(&tx2);
        free_orphan_tx(&tx3);
        orphan_pool_free(&pool);
        if (n != 2) { printf("FAIL (got %zu)\n", n); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN orphan THEN extract_children removes from pool... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        struct transaction tx1; init_orphan_tx(&tx1,0x01, 0xAA);
        struct transaction tx2; init_orphan_tx(&tx2,0x02, 0xBB);
        orphan_pool_add(&pool, &tx1);
        orphan_pool_add(&pool, &tx2);
        struct uint256 parent_aa;
        memset(parent_aa.data, 0xAA, 32);
        struct transaction children[10];
        size_t n = orphan_pool_extract_children(&pool, &parent_aa, children, 10);
        size_t sz = orphan_pool_size(&pool);
        bool t1gone = !orphan_pool_exists(&pool, &tx1.hash);
        bool t2here = orphan_pool_exists(&pool, &tx2.hash);
        for (size_t i = 0; i < n; i++) transaction_free(&children[i]);
        free_orphan_tx(&tx1);
        free_orphan_tx(&tx2);
        orphan_pool_free(&pool);
        if (n != 1 || sz != 1 || !t1gone || !t2here) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN multi-input orphan THEN find_children matches on any input... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        struct transaction tx;
        init_multi_input_orphan(&tx, 0x01, 0xAA, 0xBB);
        orphan_pool_add(&pool, &tx);
        struct uint256 parent_bb;
        memset(parent_bb.data, 0xBB, 32);
        struct transaction children[10];
        size_t n = orphan_pool_find_children(&pool, &parent_bb, children, 10);
        for (size_t i = 0; i < n; i++) transaction_free(&children[i]);
        free_orphan_tx(&tx);
        orphan_pool_free(&pool);
        if (n != 1) { printf("FAIL (got %zu)\n", n); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN no matching parent THEN find_children returns 0... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        struct transaction tx; init_orphan_tx(&tx,0x01, 0xAA);
        orphan_pool_add(&pool, &tx);
        struct uint256 parent_cc;
        memset(parent_cc.data, 0xCC, 32);
        struct transaction children[10];
        size_t n = orphan_pool_find_children(&pool, &parent_cc, children, 10);
        free_orphan_tx(&tx);
        orphan_pool_free(&pool);
        if (n != 0) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN NULL tx THEN add returns false... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        bool added = orphan_pool_add(&pool, NULL);
        orphan_pool_free(&pool);
        if (added) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN remove of non-existent hash THEN no crash... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        struct uint256 fake;
        memset(fake.data, 0xFF, 32);
        orphan_pool_remove(&pool, &fake);
        if (orphan_pool_size(&pool) != 0) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
        orphan_pool_free(&pool);
    }

    printf("GIVEN tx with 0 inputs THEN add returns false... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.version = 1;
        bool added = orphan_pool_add(&pool, &tx);
        orphan_pool_free(&pool);
        if (added) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN add-remove-readd THEN succeeds... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        struct transaction tx; init_orphan_tx(&tx,0x01, 0xAA);
        orphan_pool_add(&pool, &tx);
        orphan_pool_remove(&pool, &tx.hash);
        bool readded = orphan_pool_add(&pool, &tx);
        bool exists = orphan_pool_exists(&pool, &tx.hash);
        free_orphan_tx(&tx);
        orphan_pool_free(&pool);
        if (!readded || !exists) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN all 50 expired THEN expire removes all... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        struct transaction txs[50];
        for (int i = 0; i < 50; i++) {
            init_orphan_tx(&txs[i], (uint8_t)(i + 1), 0xAA);
            orphan_pool_add(&pool, &txs[i]);
        }
        zcl_mutex_lock(&pool.cs);
        for (size_t i = 0; i < ORPHAN_MAX_ENTRIES; i++) {
            if (pool.entries[i].used)
                pool.entries[i].arrival_time -= ORPHAN_TTL_SECONDS + 1;
        }
        zcl_mutex_unlock(&pool.cs);
        int64_t now = (int64_t)platform_time_wall_time_t();
        size_t removed = orphan_pool_expire(&pool, now);
        size_t sz = orphan_pool_size(&pool);
        for (int i = 0; i < 50; i++) free_orphan_tx(&txs[i]);
        orphan_pool_free(&pool);
        if (removed != 50 || sz != 0) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    printf("GIVEN extract with max_out=1 THEN returns at most 1... ");
    {
        struct orphan_pool pool;
        orphan_pool_init(&pool);
        struct transaction tx1; init_orphan_tx(&tx1,0x01, 0xAA);
        struct transaction tx2; init_orphan_tx(&tx2,0x02, 0xAA);
        orphan_pool_add(&pool, &tx1);
        orphan_pool_add(&pool, &tx2);
        struct uint256 parent_aa;
        memset(parent_aa.data, 0xAA, 32);
        struct transaction children[1];
        size_t n = orphan_pool_extract_children(&pool, &parent_aa, children, 1);
        size_t sz = orphan_pool_size(&pool);
        transaction_free(&children[0]);
        free_orphan_tx(&tx1);
        free_orphan_tx(&tx2);
        orphan_pool_free(&pool);
        if (n != 1 || sz != 1) { printf("FAIL (n=%zu sz=%zu)\n", n, sz); failures++; }
        else printf("OK\n");
    }

    printf("=== Mempool Orphan Pool: %d failures ===\n\n", failures);
    return failures;
}
