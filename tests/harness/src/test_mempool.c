/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "policy/fees.h"
#include "net/net.h"
#include "net/msgprocessor.h"
#include "net/msg_internal.h"
#include "net/peer_scoring.h"
#include "validation/main_state.h"
#include "util/sync.h"
#include <stdatomic.h>

/* OOM hook: unconditionally fails the allocation. */
static void *p22_force_null_alloc(size_t bytes)
{
    (void)bytes;
    return NULL;
}

/* ── fixture helpers ──────────────────────────────────────
 *
 * Minimal mp + coins_view + net_mgr + p2p_node scaffolding so the
 * msg_tx_accept classifier can be driven end-to-end without
 * dragging in snapshot sync, Dandelion, wallet, and block-map
 * plumbing. The node fixture mirrors the pattern in
 * test_peer_scoring.c so ban-score increments behave the same way
 * the real connman observes them. */
static void p21_setup_node(struct p2p_node *node, const char *name)
{
    memset(node, 0, sizeof(*node));
    snprintf(node->addr_name, sizeof(node->addr_name), "%s", name);
    /* Non-localhost IPv4-mapped address so is_trusted_peer() returns
     * false and peer_misbehaving actually accumulates score. */
    node->addr.svc.addr.ip[10] = 0xff;
    node->addr.svc.addr.ip[11] = 0xff;
    node->addr.svc.addr.ip[12] = 1;
    node->addr.svc.addr.ip[13] = 2;
    node->addr.svc.addr.ip[14] = 3;
    node->addr.svc.addr.ip[15] = 4;
}

/* Stamp a fresh p2p UTXO into the coins_view_cache at `txid` with
 * `value` in the first vout. The scriptPubKey is OP_1 (anyone-can-
 * spend): an empty scriptSig satisfies it, so the spends these helpers
 * build pass the per-input verify_script that accept_to_mempool now
 * runs. Returns true on success. */
static bool p21_add_utxo(struct coins_view_cache *cache,
                         const struct uint256 *txid, int64_t value)
{
    struct coins_cache_entry *entry =
        coins_view_cache_modify_new(cache, txid);
    if (!entry) return false;
    coins_alloc(&entry->coins, 1);
    entry->coins.vout[0].value = value;
    uint8_t pk[] = {0x51}; /* OP_1 — anyone-can-spend */
    script_set(&entry->coins.vout[0].script_pub_key, pk, 1);
    entry->coins.height = 1;
    entry->coins.version = 4;
    return true;
}

/* Build a minimal transparent 1-in 1-out transaction spending
 * `prev_hash:0` for `out_value`. Caller owns the tx and must call
 * transaction_free. */
static void p21_build_spend(struct transaction *tx,
                            const struct uint256 *prev_hash,
                            int64_t out_value)
{
    transaction_init(tx);
    transaction_alloc(tx, 1, 1);
    tx->vin[0].prevout.hash = *prev_hash;
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = 0xFFFFFFFF;
    tx->vout[0].value = out_value;
    tx->lock_time = 0;
    transaction_compute_hash(tx);
}

int test_mempool(void)
{
    int failures = 0;
    struct main_state p21_main_state;
    main_state_init(&p21_main_state);
    const struct chain_params *p21_params = chain_params_get();

    printf("txmempool init/free... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 1000);
        bool ok = tx_mempool_size(&pool) == 0;
        ok = ok && tx_mempool_total_size(&pool) == 0;
        ok = ok && tx_mempool_txs_updated(&pool) == 0;
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("txmempool add/exists/lookup... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 1000);

        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        memset(tx.vin[0].prevout.hash.data, 0xAB, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].sequence = 0xFFFFFFFF;
        tx.vout[0].value = 50 * COIN_VALUE;
        tx.lock_time = 0;
        transaction_compute_hash(&tx);

        struct mempool_entry entry;
        mempool_entry_init(&entry, &tx, 10000, 1700000000, 1e9, 100,
                           true, false, 0);

        bool ok = tx_mempool_add_unchecked(&pool, &tx.hash, &entry);
        ok = ok && tx_mempool_size(&pool) == 1;
        ok = ok && tx_mempool_exists(&pool, &tx.hash);
        ok = ok && tx_mempool_total_size(&pool) > 0;

        struct transaction found;
        transaction_init(&found);
        ok = ok && tx_mempool_lookup(&pool, &tx.hash, &found);
        ok = ok && uint256_eq(&found.hash, &tx.hash);
        ok = ok && found.vout[0].value == 50 * COIN_VALUE;

        transaction_free(&found);
        mempool_entry_free(&entry);
        transaction_free(&tx);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("txmempool exact insertion has one locked owner... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 1000);

        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 0, 1);
        tx.vout[0].value = COIN_VALUE;
        transaction_compute_hash(&tx);

        struct mempool_entry entry;
        mempool_entry_init(&entry, &tx, 0, 1700000000, 0, 100,
                           true, false, 0);
        bool first = tx_mempool_add_unchecked(&pool, &tx.hash, &entry);
        /* No transparent input exists to make the conflict map accidentally
         * deduplicate this case: exact txid arbitration must happen inside
         * the insertion lock itself. */
        bool second = tx_mempool_add_unchecked(&pool, &tx.hash, &entry);
        bool ok = first && !second && tx_mempool_size(&pool) == 1;
        tx_mempool_remove_for_block(&pool, &tx, 1, 130);
        ok = ok && tx_mempool_size(&pool) == 0;
        ok = ok && !tx_mempool_exists(&pool, &tx.hash);

        mempool_entry_free(&entry);
        transaction_free(&tx);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("txmempool remove... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 1000);

        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        memset(tx.vin[0].prevout.hash.data, 0xCD, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].sequence = 0xFFFFFFFF;
        tx.vout[0].value = 25 * COIN_VALUE;
        transaction_compute_hash(&tx);

        struct mempool_entry entry;
        mempool_entry_init(&entry, &tx, 5000, 1700000000, 1e8, 200,
                           true, false, 0);
        tx_mempool_add_unchecked(&pool, &tx.hash, &entry);

        bool ok = tx_mempool_size(&pool) == 1;
        tx_mempool_remove(&pool, &tx.hash);
        ok = ok && tx_mempool_size(&pool) == 0;
        ok = ok && !tx_mempool_exists(&pool, &tx.hash);

        mempool_entry_free(&entry);
        transaction_free(&tx);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("txmempool clear... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 1000);

        for (int i = 0; i < 5; i++) {
            struct transaction tx;
            transaction_init(&tx);
            transaction_alloc(&tx, 1, 1);
            memset(tx.vin[0].prevout.hash.data, (unsigned char)(i + 1), 32);
            tx.vin[0].prevout.n = 0;
            tx.vin[0].sequence = 0xFFFFFFFF;
            tx.vout[0].value = (int64_t)(i + 1) * COIN_VALUE;
            transaction_compute_hash(&tx);

            struct mempool_entry entry;
            mempool_entry_init(&entry, &tx, 1000, 1700000000, 1e6, 100,
                               true, false, 0);
            tx_mempool_add_unchecked(&pool, &tx.hash, &entry);
            mempool_entry_free(&entry);
            transaction_free(&tx);
        }

        bool ok = tx_mempool_size(&pool) == 5;
        tx_mempool_clear(&pool);
        ok = ok && tx_mempool_size(&pool) == 0;
        ok = ok && tx_mempool_total_size(&pool) == 0;

        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("txmempool prioritise/apply_deltas... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 1000);

        struct uint256 hash;
        memset(hash.data, 0xEE, 32);

        tx_mempool_prioritise(&pool, &hash, 100.0, 5000);

        double pd = 0.0;
        int64_t fd = 0;
        tx_mempool_apply_deltas(&pool, &hash, &pd, &fd);
        bool ok = (pd == 100.0 && fd == 5000);

        tx_mempool_prioritise(&pool, &hash, 50.0, 2000);
        pd = 0.0; fd = 0;
        tx_mempool_apply_deltas(&pool, &hash, &pd, &fd);
        ok = ok && (pd == 150.0 && fd == 7000);

        tx_mempool_clear_prioritisation(&pool, &hash);
        pd = 0.0; fd = 0;
        tx_mempool_apply_deltas(&pool, &hash, &pd, &fd);
        ok = ok && (pd == 0.0 && fd == 0);

        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("txmempool query_hashes... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 1000);

        for (int i = 0; i < 3; i++) {
            struct transaction tx;
            transaction_init(&tx);
            transaction_alloc(&tx, 1, 1);
            memset(tx.vin[0].prevout.hash.data, (unsigned char)(0x10 + i), 32);
            tx.vin[0].prevout.n = 0;
            tx.vin[0].sequence = 0xFFFFFFFF;
            tx.vout[0].value = COIN_VALUE;
            transaction_compute_hash(&tx);

            struct mempool_entry entry;
            mempool_entry_init(&entry, &tx, 1000, 1700000000, 1e6, 100,
                               true, false, 0);
            tx_mempool_add_unchecked(&pool, &tx.hash, &entry);
            mempool_entry_free(&entry);
            transaction_free(&tx);
        }

        struct uint256 out[10];
        size_t num_out = 0;
        tx_mempool_query_hashes(&pool, out, 10, &num_out);
        bool ok = (num_out == 3);

        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("txmempool remove_without_branch_id... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 1000);

        for (int i = 0; i < 4; i++) {
            struct transaction tx;
            transaction_init(&tx);
            transaction_alloc(&tx, 1, 1);
            memset(tx.vin[0].prevout.hash.data, (unsigned char)(0x20 + i), 32);
            tx.vin[0].prevout.n = 0;
            tx.vin[0].sequence = 0xFFFFFFFF;
            tx.vout[0].value = COIN_VALUE;
            transaction_compute_hash(&tx);

            struct mempool_entry entry;
            mempool_entry_init(&entry, &tx, 1000, 1700000000, 1e6, 100,
                               true, false, (i < 2) ? 0x76b809bbU : 0x892f2085U);
            tx_mempool_add_unchecked(&pool, &tx.hash, &entry);
            mempool_entry_free(&entry);
            transaction_free(&tx);
        }

        bool ok = tx_mempool_size(&pool) == 4;
        tx_mempool_remove_without_branch_id(&pool, 0x892f2085U);
        ok = ok && tx_mempool_size(&pool) == 2;

        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("txmempool has_no_inputs_of... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 1000);

        struct transaction tx1;
        transaction_init(&tx1);
        transaction_alloc(&tx1, 1, 1);
        memset(tx1.vin[0].prevout.hash.data, 0x30, 32);
        tx1.vin[0].prevout.n = 0;
        tx1.vin[0].sequence = 0xFFFFFFFF;
        tx1.vout[0].value = COIN_VALUE;
        transaction_compute_hash(&tx1);

        struct mempool_entry entry;
        mempool_entry_init(&entry, &tx1, 1000, 1700000000, 1e6, 100,
                           true, false, 0);
        tx_mempool_add_unchecked(&pool, &tx1.hash, &entry);

        struct transaction tx2;
        transaction_init(&tx2);
        transaction_alloc(&tx2, 1, 1);
        tx2.vin[0].prevout.hash = tx1.hash;
        tx2.vin[0].prevout.n = 0;
        tx2.vin[0].sequence = 0xFFFFFFFF;
        tx2.vout[0].value = COIN_VALUE;
        transaction_compute_hash(&tx2);

        bool ok = !tx_mempool_has_no_inputs_of(&pool, &tx2);

        struct transaction tx3;
        transaction_init(&tx3);
        transaction_alloc(&tx3, 1, 1);
        memset(tx3.vin[0].prevout.hash.data, 0xFF, 32);
        tx3.vin[0].prevout.n = 0;
        tx3.vin[0].sequence = 0xFFFFFFFF;
        tx3.vout[0].value = COIN_VALUE;
        transaction_compute_hash(&tx3);

        ok = ok && tx_mempool_has_no_inputs_of(&pool, &tx3);

        mempool_entry_free(&entry);
        transaction_free(&tx1);
        transaction_free(&tx2);
        transaction_free(&tx3);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("mempool_entry get_priority... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        memset(tx.vin[0].prevout.hash.data, 0x40, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].sequence = 0xFFFFFFFF;
        tx.vout[0].value = 10 * COIN_VALUE;
        transaction_compute_hash(&tx);

        struct mempool_entry entry;
        mempool_entry_init(&entry, &tx, 50000, 1700000000, 1000.0, 100,
                           true, false, 0);

        double p = mempool_entry_get_priority(&entry, 200);
        bool ok = (p > 1000.0);

        mempool_entry_free(&entry);
        transaction_free(&tx);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("tx_confirm_stats init/setup/find_bucket... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double bkts[] = {10.0, 100.0, 1000.0, 10000.0};
        tx_confirm_stats_setup(&s, bkts, 4, 10, 0.998);

        bool ok = s.num_buckets == 5;
        ok = ok && s.max_confirms == 10;

        ok = ok && tx_confirm_stats_find_bucket(&s, 5.0) == 0;
        ok = ok && tx_confirm_stats_find_bucket(&s, 10.0) == 0;
        ok = ok && tx_confirm_stats_find_bucket(&s, 50.0) == 1;
        ok = ok && tx_confirm_stats_find_bucket(&s, 5000.0) == 3;
        ok = ok && tx_confirm_stats_find_bucket(&s, 99999.0) == 4;

        tx_confirm_stats_free(&s);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("tx_confirm_stats record/update... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double bkts[] = {100.0, 1000.0, 10000.0};
        tx_confirm_stats_setup(&s, bkts, 3, 5, 0.998);

        tx_confirm_stats_clear_current(&s, 1);
        tx_confirm_stats_record(&s, 1, 500.0);
        tx_confirm_stats_record(&s, 2, 500.0);
        tx_confirm_stats_update_averages(&s);

        bool ok = s.tx_ct_avg[1] > 0;
        ok = ok && s.avg[1] > 0;

        tx_confirm_stats_free(&s);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("block_policy_estimator init/free... ");
    {
        struct fee_rate min_fee;
        min_fee.satoshis_per_k = 1000;
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        bool ok = est.best_seen_height == 0;
        ok = ok && est.fee_stats.num_buckets > 0;
        ok = ok && est.pri_stats.num_buckets > 0;
        ok = ok && est.min_tracked_fee.satoshis_per_k >= 10;

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("block_policy_estimator estimate_fee empty... ");
    {
        struct fee_rate min_fee;
        min_fee.satoshis_per_k = 1000;
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        struct fee_rate r = policy_estimate_fee(&est, 2);
        bool ok = r.satoshis_per_k == 0;
        double p = policy_estimate_priority(&est, 2);
        ok = ok && p == -1;

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("policy is_fee/pri_data_point... ");
    {
        struct fee_rate min_fee;
        min_fee.satoshis_per_k = 1000;
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        struct fee_rate high_fee;
        high_fee.satoshis_per_k = 50000;
        bool ok = policy_is_fee_data_point(&est, &high_fee, 0.0);

        struct fee_rate zero_fee;
        zero_fee.satoshis_per_k = 0;
        ok = ok && policy_is_pri_data_point(&est, &zero_fee, 1e12);

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * tx_confirm_stats: clear_current resets per-block counters
     * ================================================================ */
    printf("tx_confirm_stats clear_current... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double bkts[] = {100.0, 1000.0};
        tx_confirm_stats_setup(&s, bkts, 2, 5, 0.998);

        /* Add some data then clear */
        tx_confirm_stats_record(&s, 1, 500.0);
        tx_confirm_stats_clear_current(&s, 10);

        /* After clear, per-block counters should be zero */
        bool ok = (s.cur_block_tx_ct[0] == 0) && (s.cur_block_tx_ct[1] == 0);
        ok = ok && (s.cur_block_val[0] == 0.0) && (s.cur_block_val[1] == 0.0);

        tx_confirm_stats_free(&s);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * tx_confirm_stats: new_tx + remove_tx
     * ================================================================ */
    printf("tx_confirm_stats new_tx/remove_tx... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double bkts[] = {100.0, 1000.0, 10000.0};
        tx_confirm_stats_setup(&s, bkts, 3, 10, 0.998);

        unsigned int bi = tx_confirm_stats_new_tx(&s, 5, 500.0);
        /* bucket 1 (500 >= 100, < 1000) */
        bool ok = (bi == 1);
        /* Check unconfirmed count increased */
        ok = ok && (s.unconf_txs[5 % 10][1] == 1);

        /* Remove it */
        tx_confirm_stats_remove_tx(&s, 5, 8, bi);
        ok = ok && (s.unconf_txs[5 % 10][1] == 0);

        tx_confirm_stats_free(&s);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * tx_confirm_stats: max_confirms
     * ================================================================ */
    printf("tx_confirm_stats max_confirms... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double bkts[] = {100.0};
        tx_confirm_stats_setup(&s, bkts, 1, 25, 0.998);

        bool ok = (tx_confirm_stats_max_confirms(&s) == 25);

        tx_confirm_stats_free(&s);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * tx_confirm_stats: update_averages decays
     * ================================================================ */
    printf("tx_confirm_stats update_averages applies decay... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double bkts[] = {100.0, 1000.0};
        tx_confirm_stats_setup(&s, bkts, 2, 5, 0.5);

        /* Record data, update averages, then update again with empty block */
        tx_confirm_stats_record(&s, 1, 500.0);
        tx_confirm_stats_update_averages(&s);
        double avg_after_first = s.tx_ct_avg[1];

        /* Clear and update again with no new data — decay should reduce */
        tx_confirm_stats_clear_current(&s, 1);
        tx_confirm_stats_update_averages(&s);
        double avg_after_second = s.tx_ct_avg[1];

        bool ok = (avg_after_first > 0) && (avg_after_second < avg_after_first);

        tx_confirm_stats_free(&s);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * tx_confirm_stats: estimate_median returns -1 with no data
     * ================================================================ */
    printf("tx_confirm_stats estimate_median: -1 with no data... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double bkts[] = {100.0, 1000.0, 10000.0};
        tx_confirm_stats_setup(&s, bkts, 3, 10, 0.998);

        double m = tx_confirm_stats_estimate_median(&s, 2, 0.1, 0.95, true, 5);
        bool ok = (m == -1.0);

        tx_confirm_stats_free(&s);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * policy_estimate_fee: invalid conf_target
     * ================================================================ */
    printf("policy_estimate_fee: invalid targets return zero... ");
    {
        struct fee_rate min_fee;
        min_fee.satoshis_per_k = 1000;
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        struct fee_rate r0 = policy_estimate_fee(&est, 0);
        struct fee_rate rn = policy_estimate_fee(&est, -1);
        struct fee_rate rh = policy_estimate_fee(&est, 999999);
        bool ok = (r0.satoshis_per_k == 0) && (rn.satoshis_per_k == 0) && (rh.satoshis_per_k == 0);

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * policy_estimate_priority: invalid conf_target
     * ================================================================ */
    printf("policy_estimate_priority: invalid targets return -1... ");
    {
        struct fee_rate min_fee;
        min_fee.satoshis_per_k = 1000;
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        double p0 = policy_estimate_priority(&est, 0);
        double pn = policy_estimate_priority(&est, -1);
        double ph = policy_estimate_priority(&est, 999999);
        bool ok = (p0 == -1) && (pn == -1) && (ph == -1);

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * policy_process_block: advances best_seen_height
     * ================================================================ */
    printf("policy_process_block: advances best_seen_height... ");
    {
        struct fee_rate min_fee;
        min_fee.satoshis_per_k = 1000;
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        policy_process_block(&est, 100, NULL, 0, true);
        bool ok = (est.best_seen_height == 100);
        /* Advancing further works */
        policy_process_block(&est, 200, NULL, 0, true);
        ok = ok && (est.best_seen_height == 200);
        /* Going backwards does not advance */
        policy_process_block(&est, 150, NULL, 0, true);
        ok = ok && (est.best_seen_height == 200);

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * policy_remove_tx: no-op for unknown hash
     * ================================================================ */
    printf("policy_remove_tx: no-op for unknown hash... ");
    {
        struct fee_rate min_fee;
        min_fee.satoshis_per_k = 1000;
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        struct uint256 h;
        memset(h.data, 0xFF, 32);
        policy_remove_tx(&est, &h); /* should not crash */
        bool ok = true;

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * process_mempool happy path — all tx hashes flow into
     * node->inventory_to_send via p2p_node_push_inventory, proving
     * the heap-allocated scratch buffer carries the full result set
     * end to end (previously a 1.6 MB stack alloc).
     * ================================================================ */
    printf("process_mempool: 100 tx happy path pushes all inv... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 1000);

        for (int i = 0; i < 100; i++) {
            struct transaction tx;
            transaction_init(&tx);
            transaction_alloc(&tx, 1, 1);
            memset(tx.vin[0].prevout.hash.data, 0, 32);
            tx.vin[0].prevout.hash.data[0] = (unsigned char)(i & 0xFF);
            tx.vin[0].prevout.hash.data[1] = (unsigned char)((i >> 8) & 0xFF);
            tx.vin[0].prevout.n = 0;
            tx.vin[0].sequence = 0xFFFFFFFF;
            tx.vout[0].value = COIN_VALUE;
            transaction_compute_hash(&tx);

            struct mempool_entry entry;
            mempool_entry_init(&entry, &tx, 1000, 1700000000, 1e6, 100,
                               true, false, 0);
            tx_mempool_add_unchecked(&pool, &tx.hash, &entry);
            mempool_entry_free(&entry);
            transaction_free(&tx);
        }

        struct msg_processor mp = {0};
        mp.mempool = &pool;

        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        zcl_mutex_init(&node.cs_inventory);

        bool ok = process_mempool(&mp, &node);
        ok = ok && (node.inventory_to_send_count == 100);

        free(node.inventory_to_send);
        zcl_mutex_destroy(&node.cs_inventory);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * process_mempool returns false on OOM and pushes no inv.
     * Test hook forces the scratch allocation to fail; the caller
     * observes false and node->inventory_to_send is never touched.
     * ================================================================ */
    printf("process_mempool: OOM returns false, no inv pushed... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 1000);

        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        memset(tx.vin[0].prevout.hash.data, 0x42, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].sequence = 0xFFFFFFFF;
        tx.vout[0].value = COIN_VALUE;
        transaction_compute_hash(&tx);

        struct mempool_entry entry;
        mempool_entry_init(&entry, &tx, 1000, 1700000000, 1e6, 100,
                           true, false, 0);
        tx_mempool_add_unchecked(&pool, &tx.hash, &entry);
        mempool_entry_free(&entry);
        transaction_free(&tx);

        struct msg_processor mp = {0};
        mp.mempool = &pool;

        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        zcl_mutex_init(&node.cs_inventory);

        msgprocessor_test_set_mempool_alloc_hook(p22_force_null_alloc);
        bool ok = !process_mempool(&mp, &node);
        msgprocessor_test_set_mempool_alloc_hook(NULL);

        ok = ok && (node.inventory_to_send_count == 0);
        ok = ok && (node.inventory_to_send == NULL);

        zcl_mutex_destroy(&node.cs_inventory);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * invalid tx (out-of-range vout value) is rejected with
     * TX_ACCEPT_INVALID, the mempool stays empty, and the sending
     * peer's ban-score is incremented by PEER_OFFENCE_INVALID_MESSAGE.
     * Exercises the check_transaction → peer scoring wiring that was
     * missing. Prior to the fix, the same tx would have
     * entered the mempool with fee=0 and the peer would have kept
     * their reputation intact.
     * ================================================================ */
    printf("invalid tx → INVALID + peer ban-score... ");
    {
        /* Baseline scoring config — clean env so defaults apply. */
        unsetenv("ZCL_PEER_BAN_THRESHOLD");
        unsetenv("ZCL_PEER_BAN_HOURS");
        unsetenv("ZCL_PEER_SCORE_DECAY_PER_MIN");
        peer_scoring_init();

        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);

        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);

        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));
        struct p2p_node node;
        p21_setup_node(&node, "p21_invalid");

        struct msg_processor mp = {0};
        mp.mempool = &pool;
        mp.coins_tip = &coins;
        mp.main_state = &p21_main_state;
        mp.params = p21_params;
        mp.net_mgr = &nm;

        /* Forge an out-of-range vout value — triggers
         * "bad-txns-vout-negative" inside check_transaction. */
        struct uint256 prev;
        memset(prev.data, 0xAA, 32);
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.vin[0].prevout.hash = prev;
        tx.vin[0].prevout.n = 0;
        tx.vin[0].sequence = 0xFFFFFFFF;
        tx.vout[0].value = -1;  /* forbidden */
        transaction_compute_hash(&tx);

        enum tx_accept_result ar = msg_tx_accept(&mp, &node, &tx);

        bool ok = (ar == TX_ACCEPT_INVALID);
        ok = ok && (tx_mempool_size(&pool) == 0);
        ok = ok && (atomic_load(&node.misbehavior) ==
                    peer_offence_weight(PEER_OFFENCE_INVALID_MESSAGE));

        transaction_free(&tx);
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * double-spend vs current mempool. First tx accepted,
     * second tx spending the same UTXO rejected with TX_ACCEPT_CONFLICT,
     * second peer's ban-score incremented. Mempool size stays at 1.
     *
     *, the conflict was detected only inside
     * tx_mempool_add_unchecked where it collapsed into a generic bool
     * — and the peer who submitted the conflicting tx was never
     * penalised, so nothing stopped a flood of colliding txs.
     * ================================================================ */
    printf("double-spend → CONFLICT + peer ban-score... ");
    {
        unsetenv("ZCL_PEER_BAN_THRESHOLD");
        unsetenv("ZCL_PEER_BAN_HOURS");
        unsetenv("ZCL_PEER_SCORE_DECAY_PER_MIN");
        peer_scoring_init();

        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);

        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);

        /* Pre-seed one UTXO worth 100 coin. Both spenders will
         * target it; only the first should succeed. */
        struct uint256 utxo;
        memset(utxo.data, 0xBB, 32);
        bool ok = p21_add_utxo(&coins, &utxo, 100 * COIN_VALUE);

        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));
        struct p2p_node peer_a, peer_b;
        p21_setup_node(&peer_a, "p21_ds_A");
        p21_setup_node(&peer_b, "p21_ds_B");
        peer_b.id = 2;

        struct msg_processor mp = {0};
        mp.mempool = &pool;
        mp.coins_tip = &coins;
        mp.main_state = &p21_main_state;
        mp.params = p21_params;
        mp.net_mgr = &nm;

        /* First spend — unique output hash so the two txs have
         * different txids but point to the same outpoint. */
        struct transaction tx_a;
        p21_build_spend(&tx_a, &utxo, 50 * COIN_VALUE);
        enum tx_accept_result ar_a = msg_tx_accept(&mp, &peer_a, &tx_a);
        ok = ok && (ar_a == TX_ACCEPT_OK);
        ok = ok && (tx_mempool_size(&pool) == 1);
        ok = ok && (atomic_load(&peer_a.misbehavior) == 0);

        /* Second spend — same outpoint, different value so the
         * txid differs and the duplicate check doesn't short-circuit. */
        struct transaction tx_b;
        p21_build_spend(&tx_b, &utxo, 40 * COIN_VALUE);
        enum tx_accept_result ar_b = msg_tx_accept(&mp, &peer_b, &tx_b);
        ok = ok && (ar_b == TX_ACCEPT_CONFLICT);
        ok = ok && (tx_mempool_size(&pool) == 1);
        ok = ok && (atomic_load(&peer_b.misbehavior) ==
                    peer_offence_weight(PEER_OFFENCE_INVALID_MESSAGE));

        transaction_free(&tx_a);
        transaction_free(&tx_b);
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * below-relay-fee tx is silently dropped. Returns
     * TX_ACCEPT_BELOW_FEE, mempool stays empty, and the peer's
     * ban-score is UNCHANGED — zero-fee floods are a rate-limit
     * problem, not peer misbehaviour, and penalising would blowback
     * on honest peers forwarding a CPFP-only transaction.
     * ================================================================ */
    printf("below-relay-fee → BELOW_FEE, no ban-score... ");
    {
        unsetenv("ZCL_PEER_BAN_THRESHOLD");
        unsetenv("ZCL_PEER_BAN_HOURS");
        unsetenv("ZCL_PEER_SCORE_DECAY_PER_MIN");
        peer_scoring_init();

        /* Non-zero min_relay_fee so the check has teeth. */
        struct tx_mempool pool;
        tx_mempool_init(&pool, 1000);

        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);

        /* UTXO whose value exactly equals the output value → fee=0. */
        struct uint256 utxo;
        memset(utxo.data, 0xCC, 32);
        bool ok = p21_add_utxo(&coins, &utxo, 10 * COIN_VALUE);

        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));
        struct p2p_node node;
        p21_setup_node(&node, "p21_below_fee");

        struct msg_processor mp = {0};
        mp.mempool = &pool;
        mp.coins_tip = &coins;
        mp.main_state = &p21_main_state;
        mp.params = p21_params;
        mp.net_mgr = &nm;

        struct transaction tx;
        p21_build_spend(&tx, &utxo, 10 * COIN_VALUE);

        enum tx_accept_result ar = msg_tx_accept(&mp, &node, &tx);

        ok = ok && (ar == TX_ACCEPT_BELOW_FEE);
        ok = ok && (tx_mempool_size(&pool) == 0);
        ok = ok && (atomic_load(&node.misbehavior) == 0);

        transaction_free(&tx);
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * outpoint map grows past the old fixed 4096 ceiling.
     *
     * the next_tx open-addressing map was fixed at
     * OUTPOINT_MAP_CAP (4096) slots and outpoint_insert's return was
     * ignored. Past ~0.7 load it would fail silently: the input was
     * not recorded, so a later conflicting tx spending the SAME
     * outpoint was NOT seen as a double-spend and got accepted +
     * relayed — a mempool-integrity defect reachable by a normal tx
     * flood (cap 50k).
     *
     * This adds far more than 4096 distinct outpoints, then proves
     * (a) every add succeeded and is tracked, (b) the map actually
     * grew beyond 4096 slots, and (c) double-spend detection STILL
     * fires for an outpoint inserted well past the old ceiling.
     * ================================================================ */
    printf("txmempool outpoint map grows past 4096 + double-spend... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 1000);

        const int N = 6000; /* > OUTPOINT_MAP_CAP (4096) */
        bool ok = true;

        for (int i = 0; i < N && ok; i++) {
            struct transaction tx;
            transaction_init(&tx);
            transaction_alloc(&tx, 1, 1);
            /* Distinct outpoint per tx: encode i into prevout.hash. */
            memset(tx.vin[0].prevout.hash.data, 0, 32);
            tx.vin[0].prevout.hash.data[0] = (unsigned char)(i & 0xFF);
            tx.vin[0].prevout.hash.data[1] = (unsigned char)((i >> 8) & 0xFF);
            tx.vin[0].prevout.hash.data[2] = (unsigned char)((i >> 16) & 0xFF);
            tx.vin[0].prevout.hash.data[3] = 0x5A; /* salt away from later test hashes */
            tx.vin[0].prevout.n = 0;
            tx.vin[0].sequence = 0xFFFFFFFF;
            tx.vout[0].value = COIN_VALUE;
            transaction_compute_hash(&tx);

            struct mempool_entry entry;
            mempool_entry_init(&entry, &tx, 1000, 1700000000, 1e6, 100,
                               true, false, 0);
            /* add_unchecked MUST report success — a silent insert
             * failure (the bug) would still return true here, so we
             * also independently re-prove tracking below. */
            bool added = tx_mempool_add_unchecked(&pool, &tx.hash, &entry);
            ok = ok && added;
            mempool_entry_free(&entry);
            transaction_free(&tx);
        }

        /* All N entries are present. */
        ok = ok && (tx_mempool_size(&pool) == (size_t)N);

        /* The live-occupancy counter saw every distinct outpoint and
         * the map grew well past the old fixed 4096 ceiling. */
        ok = ok && (pool.next_tx_used == (size_t)N);
        ok = ok && (pool.next_tx_cap > (size_t)OUTPOINT_MAP_CAP);

        /* Pick an outpoint inserted FAR past the old 4096 boundary and
         * prove double-spend detection still fires for it. With the
         * pre-fix silent saturation, this outpoint would never have
         * been recorded and the conflict check below would miss it. */
        int probe = 5000; /* > 4096 */
        struct transaction conflict;
        transaction_init(&conflict);
        transaction_alloc(&conflict, 1, 1);
        memset(conflict.vin[0].prevout.hash.data, 0, 32);
        conflict.vin[0].prevout.hash.data[0] = (unsigned char)(probe & 0xFF);
        conflict.vin[0].prevout.hash.data[1] = (unsigned char)((probe >> 8) & 0xFF);
        conflict.vin[0].prevout.hash.data[2] = (unsigned char)((probe >> 16) & 0xFF);
        conflict.vin[0].prevout.hash.data[3] = 0x5A;
        conflict.vin[0].prevout.n = 0;
        conflict.vin[0].sequence = 0xFFFFFFFF;
        conflict.vout[0].value = COIN_VALUE / 2; /* different txid */
        transaction_compute_hash(&conflict);

        /* Read-only probe sees the conflict. */
        ok = ok && tx_mempool_has_conflict(&pool, &conflict);

        /* And the add path rejects it as a double-spend rather than
         * accepting + tracking it (size must not grow). */
        struct mempool_entry centry;
        mempool_entry_init(&centry, &conflict, 1000, 1700000000, 1e6, 100,
                           true, false, 0);
        bool conflict_added = tx_mempool_add_unchecked(&pool, &conflict.hash, &centry);
        ok = ok && !conflict_added;
        ok = ok && (tx_mempool_size(&pool) == (size_t)N);

        mempool_entry_free(&centry);
        transaction_free(&conflict);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * After growth, removals shrink live occupancy and free the
     * outpoint so a fresh tx may legitimately reuse it. Guards against
     * the grow path leaking the next_tx_used counter or corrupting the
     * probe chains during rehash.
     * ================================================================ */
    printf("txmempool grow then remove frees outpoints... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 1000);

        const int N = 5000; /* forces at least one grow */
        struct uint256 hashes[5000];
        struct outpoint ops[5000];
        bool ok = true;

        for (int i = 0; i < N && ok; i++) {
            struct transaction tx;
            transaction_init(&tx);
            transaction_alloc(&tx, 1, 1);
            memset(tx.vin[0].prevout.hash.data, 0, 32);
            tx.vin[0].prevout.hash.data[0] = (unsigned char)(i & 0xFF);
            tx.vin[0].prevout.hash.data[1] = (unsigned char)((i >> 8) & 0xFF);
            tx.vin[0].prevout.hash.data[2] = (unsigned char)((i >> 16) & 0xFF);
            tx.vin[0].prevout.hash.data[3] = 0x77;
            tx.vin[0].prevout.n = 0;
            tx.vin[0].sequence = 0xFFFFFFFF;
            tx.vout[0].value = COIN_VALUE;
            transaction_compute_hash(&tx);

            ops[i].hash = tx.vin[0].prevout.hash;
            ops[i].n = 0;
            hashes[i] = tx.hash;

            struct mempool_entry entry;
            mempool_entry_init(&entry, &tx, 1000, 1700000000, 1e6, 100,
                               true, false, 0);
            ok = ok && tx_mempool_add_unchecked(&pool, &tx.hash, &entry);
            mempool_entry_free(&entry);
            transaction_free(&tx);
        }

        ok = ok && (pool.next_tx_used == (size_t)N);
        ok = ok && (pool.next_tx_cap > (size_t)OUTPOINT_MAP_CAP);

        /* Remove every other entry; occupancy must track exactly. */
        int removed = 0;
        for (int i = 0; i < N; i += 2) {
            tx_mempool_remove(&pool, &hashes[i]);
            removed++;
        }
        ok = ok && (pool.next_tx_used == (size_t)(N - removed));
        ok = ok && (tx_mempool_size(&pool) == (size_t)(N - removed));

        /* A freed outpoint (i=0 was removed) is no longer a conflict. */
        struct transaction reuse;
        transaction_init(&reuse);
        transaction_alloc(&reuse, 1, 1);
        reuse.vin[0].prevout.hash = ops[0].hash;
        reuse.vin[0].prevout.n = 0;
        reuse.vin[0].sequence = 0xFFFFFFFF;
        reuse.vout[0].value = COIN_VALUE;
        transaction_compute_hash(&reuse);
        ok = ok && !tx_mempool_has_conflict(&pool, &reuse);

        /* A surviving outpoint (i=1 kept) is still a conflict. */
        struct transaction kept;
        transaction_init(&kept);
        transaction_alloc(&kept, 1, 1);
        kept.vin[0].prevout.hash = ops[1].hash;
        kept.vin[0].prevout.n = 0;
        kept.vin[0].sequence = 0xFFFFFFFF;
        kept.vout[0].value = COIN_VALUE;
        transaction_compute_hash(&kept);
        ok = ok && tx_mempool_has_conflict(&pool, &kept);

        transaction_free(&reuse);
        transaction_free(&kept);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    main_state_free(&p21_main_state);
    return failures;
}
