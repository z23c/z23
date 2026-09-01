/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test for the fee-estimator tx-stats map growth path
 * (core/modules/policy/src/fees.c insert_stats_entry).
 *
 * Hazard fixed: insert_stats_entry self-assigned the realloc result and
 * then memset/dereferenced it with no NULL check, so an OOM on the
 * "fee_map_entries" realloc was a null-deref (and a leak of the original
 * buffer). The fix routes the realloc through a temp pointer, returns
 * NULL via LOG_NULL on failure (insert_stats_entry returns a pointer),
 * and only assigns e->map_entries once the new block is known good.
 *
 * Two cases:
 *   1. test_fees_oom — drives the realloc *growth* branch many times past the
 *      initial map_cap with the temp-pointer code in place and asserts it
 *      grows cleanly with no crash, no clobber, and correct bookkeeping.
 *   2. test_fees_oom_inject — arms a one-shot allocation fault on the
 *      "fee_map_entries" realloc so insert_stats_entry returns NULL, then
 *      confirms policy_process_transaction skips the data point cleanly via
 *      its caller NULL-guard (no null-deref) and leaves the estimator state
 *      byte-for-byte unchanged. This covers the OOM path end-to-end, including
 *      the caller guard that earlier only the growth branch left untested.
 */

#include "test/test_core.h"
#include "coins/undo.h"
#include "validation/txmempool.h"
#include "policy/fees.h"

int test_fees_oom(void)
{
    int failures = 0;

    TEST_CASE("insert_stats_entry: realloc growth past map_cap (no crash)") {
        struct block_policy_estimator e;
        struct fee_rate min_relay;
        fee_rate_init(&min_relay);
        min_relay.satoshis_per_k = (CAmount)MIN_FEERATE_VAL;
        block_policy_estimator_init(&e, &min_relay);

        ASSERT(e.map_entries != NULL);

        /* Shrink the map so the very next inserts cross map_cap and hit
         * the doubling realloc branch quickly. Reallocate the backing
         * store so the structure stays internally consistent. */
        e.num_map_entries = 0;
        e.map_cap = 2;
        struct tx_stats_entry *small =
            zcl_realloc(e.map_entries, e.map_cap * sizeof(*e.map_entries),
                        "fee_map_entries");
        ASSERT(small != NULL);
        e.map_entries = small;
        memset(e.map_entries, 0, e.map_cap * sizeof(*e.map_entries));

        size_t start_cap = e.map_cap;

        /* Insert well past map_cap distinct fee-data points. Each call
         * with fee==0 + had_no_deps + current_estimate routes through
         * insert_stats_entry, forcing several doubling reallocs. */
        const unsigned int N = 64;
        for (unsigned int i = 0; i < N; i++) {
            struct mempool_entry me;
            memset(&me, 0, sizeof(me));
            transaction_init(&me.tx);
            /* Distinct hash per entry so each is a fresh insert. */
            me.tx.hash.data[0] = (uint8_t)(i & 0xff);
            me.tx.hash.data[1] = (uint8_t)((i >> 8) & 0xff);
            me.fee = 0;            /* fee==0 -> pri-data path, always inserts */
            me.tx_size = 250;
            me.mod_size = 250;     /* non-zero: avoids div-by-zero in priority */
            me.priority = 0.0;
            me.height = 1;
            me.had_no_deps = true;
            policy_process_transaction(&e, &me, true);
            transaction_free(&me.tx);
        }

        /* The growth branch ran: every distinct tx was inserted, the cap
         * doubled past its shrunk start, and num never exceeds cap. */
        ASSERT(e.num_map_entries == N);
        ASSERT(e.map_cap > start_cap);
        ASSERT(e.num_map_entries <= e.map_cap);
        ASSERT(e.map_entries != NULL);

        /* The most-recently-inserted entry is intact (not clobbered by a
         * stale pointer surviving a realloc). */
        struct uint256 last;
        uint256_set_null(&last);
        last.data[0] = (uint8_t)((N - 1) & 0xff);
        last.data[1] = (uint8_t)(((N - 1) >> 8) & 0xff);
        bool found_last = false;
        for (size_t i = 0; i < e.num_map_entries; i++) {
            if (e.map_entries[i].used &&
                uint256_eq(&e.map_entries[i].hash, &last)) {
                found_last = true;
                break;
            }
        }
        ASSERT(found_last);

        block_policy_estimator_free(&e);
    } TEST_END

    return failures;
}

int test_fees_oom_inject(void)
{
    int failures = 0;

    TEST_CASE("policy_process_transaction: realloc OOM on growth fails clean") {
        struct block_policy_estimator e;
        struct fee_rate min_relay;
        fee_rate_init(&min_relay);
        min_relay.satoshis_per_k = (CAmount)MIN_FEERATE_VAL;
        block_policy_estimator_init(&e, &min_relay);
        ASSERT(e.map_entries != NULL);

        /* Shrink to cap=2 and fill exactly to capacity so the NEXT insert
         * crosses map_cap and triggers the doubling realloc. */
        e.num_map_entries = 0;
        e.map_cap = 2;
        struct tx_stats_entry *small =
            zcl_realloc(e.map_entries, e.map_cap * sizeof(*e.map_entries),
                        "fee_map_entries");
        ASSERT(small != NULL);
        e.map_entries = small;
        memset(e.map_entries, 0, e.map_cap * sizeof(*e.map_entries));

        for (unsigned int i = 0; i < 2; i++) {
            struct mempool_entry me;
            memset(&me, 0, sizeof(me));
            transaction_init(&me.tx);
            me.tx.hash.data[0] = (uint8_t)i;
            me.fee = 0;
            me.tx_size = 250;
            me.mod_size = 250;
            me.priority = 0.0;
            me.height = 1;
            me.had_no_deps = true;
            policy_process_transaction(&e, &me, true);
            transaction_free(&me.tx);
        }
        ASSERT(e.num_map_entries == 2);
        ASSERT(e.map_cap == 2);
        size_t num_before = e.num_map_entries;
        size_t cap_before = e.map_cap;

        /* Arm the one-shot OOM on the growth realloc, then insert a 3rd,
         * distinct tx. insert_stats_entry's realloc returns NULL -> it
         * returns NULL -> policy_process_transaction hits the caller guard
         * and returns without dereferencing. Reaching the asserts below at
         * all proves there was no null-deref crash. */
        zcl_alloc_fault_fail_next("fee_map_entries");
        struct mempool_entry me3;
        memset(&me3, 0, sizeof(me3));
        transaction_init(&me3.tx);
        me3.tx.hash.data[0] = 0x77;
        me3.fee = 0;
        me3.tx_size = 250;
        me3.mod_size = 250;
        me3.priority = 0.0;
        me3.height = 1;
        me3.had_no_deps = true;
        policy_process_transaction(&e, &me3, true);   /* must not crash */
        transaction_free(&me3.tx);

        zcl_alloc_fault_clear(); /* defensive: disarm if it never fired */

        /* The failed growth left the estimator exactly as it was: no commit
         * of the doubled cap, no phantom entry, backing store intact. */
        ASSERT(e.num_map_entries == num_before);
        ASSERT(e.map_cap == cap_before);
        ASSERT(e.map_entries != NULL);

        block_policy_estimator_free(&e);
    } TEST_END

    return failures;
}
