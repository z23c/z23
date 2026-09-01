/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for domain/consensus/locktime.{c,h}.
 *
 * Pins the pure BIP65/BIP113 lock-time arithmetic and Overwinter
 * expiry predicates extracted from
 * core/modules/validation/include/validation/contextual_check_tx.h.
 *
 * The "regression seal" section calls BOTH the new domain API and
 * the legacy wrapper (is_final_tx / is_expired_tx / is_expiring_soon_tx)
 * across the lock-time boundary in both domains (height vs unix time)
 * and proves they agree byte-for-byte. This is what prevents a future
 * edit to one path from silently diverging from the other.
 */

#include "test/test_core.h"
#include "validation/main_constants.h"

#include "domain/consensus/locktime.h"
#include "validation/contextual_check_tx.h"
#include "primitives/transaction.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <string.h>

#define DCL_CHECK(name, expr) do { \
    printf("domain_consensus_locktime: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Minimal tx builder: one input at the given sequence, zero outputs,
 * given lock_time. Caller frees with locktime_tx_free. */
static void locktime_tx_init(struct transaction *tx,
                              uint32_t lock_time, uint32_t sequence)
{
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->lock_time = lock_time;
    tx->num_vin = 1;
    tx->vin = zcl_calloc(1, sizeof(struct tx_in), "test_locktime_vin");
    tx->vin[0].sequence = sequence;
    /* Make sure prevout is non-null so transaction_is_coinbase=false. */
    memset(tx->vin[0].prevout.hash.data, 0xCC, 32);
    tx->vin[0].prevout.n = 0;
}

static void locktime_tx_free(struct transaction *tx)
{
    free(tx->vin);
}

int test_domain_consensus_locktime(void)
{
    int failures = 0;

    /* ── NULL contract ─────────────────────────────────────── */

    DCL_CHECK("is_final_tx(NULL,...) returns false",
              !domain_consensus_tx_is_final(NULL, 0, 0));
    DCL_CHECK("is_expired_tx(NULL,...) returns false",
              !domain_consensus_tx_is_expired(NULL, 0));
    DCL_CHECK("is_expiring_soon_tx(NULL,...) returns false",
              !domain_consensus_tx_is_expiring_soon(NULL, 0));

    /* ── is_final_tx: lock_time == 0 always final ──────────── */
    {
        struct transaction tx;
        locktime_tx_init(&tx, 0, 0);
        DCL_CHECK("lock_time=0 always final",
                  domain_consensus_tx_is_final(&tx, 100, 1000000));
        locktime_tx_free(&tx);
    }

    /* ── is_final_tx: height-based boundary ────────────────── */
    {
        struct transaction tx;
        locktime_tx_init(&tx, 100, 0);
        /* height < locktime: not final */
        DCL_CHECK("height-based: height < locktime not final",
                  !domain_consensus_tx_is_final(&tx, 50, 0));
        /* height == locktime: NOT final (lt < cutoff is strict) */
        DCL_CHECK("height-based: height == locktime not final",
                  !domain_consensus_tx_is_final(&tx, 100, 0));
        /* height > locktime: final */
        DCL_CHECK("height-based: height > locktime final",
                  domain_consensus_tx_is_final(&tx, 101, 0));
        locktime_tx_free(&tx);
    }

    /* ── is_final_tx: time-based boundary (lock_time >= 5e8) ─ */
    {
        struct transaction tx;
        locktime_tx_init(&tx, 500000100, 0);
        DCL_CHECK("time-based: time < locktime not final",
                  !domain_consensus_tx_is_final(&tx, 999999, 500000000));
        /* Edge: time == locktime: lt < cutoff is strict → not final. */
        DCL_CHECK("time-based: time == locktime not final",
                  !domain_consensus_tx_is_final(&tx, 999999, 500000100));
        DCL_CHECK("time-based: time > locktime final",
                  domain_consensus_tx_is_final(&tx, 999999, 500000200));
        locktime_tx_free(&tx);
    }

    /* ── is_final_tx: threshold flip at exactly LOCKTIME_THRESHOLD ── */
    {
        struct transaction tx;
        /* lock_time == 500000000 → falls into the time domain (>= threshold).
         * Compare against block_time. */
        locktime_tx_init(&tx, 500000000, 0);
        DCL_CHECK("threshold boundary: lt=5e8 uses time domain not height",
                  /* high block_height alone must NOT make it final */
                  !domain_consensus_tx_is_final(&tx, 999999999, 0));
        DCL_CHECK("threshold boundary: lt=5e8 finalized by time > 5e8",
                  domain_consensus_tx_is_final(&tx, 0, 500000001));
        locktime_tx_free(&tx);

        /* lock_time == 499999999 → falls into the height domain (< threshold). */
        locktime_tx_init(&tx, 499999999, 0);
        DCL_CHECK("threshold boundary: lt=5e8-1 uses height domain not time",
                  !domain_consensus_tx_is_final(&tx, 0, 9999999999LL));
        DCL_CHECK("threshold boundary: lt=5e8-1 finalized by height",
                  domain_consensus_tx_is_final(&tx, 500000000, 0));
        locktime_tx_free(&tx);
    }

    /* ── is_final_tx: sequence override ────────────────────── */
    {
        struct transaction tx;
        locktime_tx_init(&tx, 999999, 0xFFFFFFFF);
        DCL_CHECK("all inputs final (seq=0xFFFFFFFF) overrides locktime",
                  domain_consensus_tx_is_final(&tx, 0, 0));
        locktime_tx_free(&tx);
    }

    /* ── is_final_tx: multi-input sequence override ────────── */
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.version = 1;
        tx.lock_time = 999999;
        tx.num_vin = 3;
        tx.vin = zcl_calloc(3, sizeof(struct tx_in), "test_locktime_vin");
        tx.vin[0].sequence = 0xFFFFFFFF;
        tx.vin[1].sequence = 0xFFFFFFFF;
        tx.vin[2].sequence = 0xFFFFFFFE; /* one input NOT final */
        for (int i = 0; i < 3; i++) {
            memset(tx.vin[i].prevout.hash.data, 0xCC, 32);
            tx.vin[i].prevout.n = (uint32_t)i;
        }
        DCL_CHECK("any non-final input prevents finality past locktime",
                  !domain_consensus_tx_is_final(&tx, 0, 0));
        free(tx.vin);
    }

    /* ── is_expired_tx contract ────────────────────────────── */
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.expiry_height = 0; /* zero means no expiry */
        DCL_CHECK("expiry_height=0 never expires",
                  !domain_consensus_tx_is_expired(&tx, 999999));
    }
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.expiry_height = 500;
        tx.num_vin = 1;
        tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_locktime_vin");
        memset(tx.vin[0].prevout.hash.data, 0xAA, 32);
        tx.vin[0].prevout.n = 0;
        /* Strict GT, matching zclassicd IsExpiredTx (main.cpp:788): a tx is
         * still valid in the block AT its expiry_height and only expires the
         * block AFTER. (Was wrongly `>=` here, which expired one block early.) */
        DCL_CHECK("expiry_height=500, height=499 not expired",
                  !domain_consensus_tx_is_expired(&tx, 499));
        DCL_CHECK("expiry_height=500, height=500 (== expiry) NOT expired",
                  !domain_consensus_tx_is_expired(&tx, 500));
        DCL_CHECK("expiry_height=500, height=501 (> expiry) expired",
                  domain_consensus_tx_is_expired(&tx, 501));
        free(tx.vin);
    }

    /* Coinbase never expires (even with expiry_height set). */
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.expiry_height = 100;
        tx.num_vin = 1;
        tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_locktime_vin");
        /* Coinbase: prevout.hash all-zero AND prevout.n == 0xFFFFFFFF. */
        memset(tx.vin[0].prevout.hash.data, 0, 32);
        tx.vin[0].prevout.n = 0xFFFFFFFF;
        DCL_CHECK("coinbase never expires regardless of expiry_height",
                  !domain_consensus_tx_is_expired(&tx, 999999));
        free(tx.vin);
    }

    /* ── is_expiring_soon_tx ───────────────────────────────── */
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.expiry_height = 1010;
        tx.num_vin = 1;
        tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_locktime_vin");
        memset(tx.vin[0].prevout.hash.data, 0xAA, 32);
        tx.vin[0].prevout.n = 0;
        /* threshold = 3, strict GT. next=1007 → check@1010 (== expiry) →
         * NOT yet expired → NOT expiring soon. */
        DCL_CHECK("not expiring_soon at next_height+threshold == expiry",
                  !domain_consensus_tx_is_expiring_soon(&tx, 1007));
        /* next=1008 → check@1011 (> expiry) → expired → expiring soon. */
        DCL_CHECK("expiring_soon when next_height+threshold > expiry",
                  domain_consensus_tx_is_expiring_soon(&tx, 1008));
        /* next_height=1006 → check@1009 → not expired. */
        DCL_CHECK("not expiring_soon when window < expiry",
                  !domain_consensus_tx_is_expiring_soon(&tx, 1006));
        free(tx.vin);
    }

    /* ────────────────────────────────────────────────────────────
     * REGRESSION SEAL: domain API ≡ legacy wrapper across lock-time
     * boundaries (height domain, time domain, sequence override) and
     * expiry boundary. This is the byte-for-byte equivalence proof.
     * If a future edit drifts one path the seal fires. */

    /* Lock-time by HEIGHT: sweep around the lt=N boundary. */
    {
        const uint32_t locktimes[] = { 1, 100, 100000, 499999999 };
        const int      heights[]   = { 0, 1, 99, 100, 101, 500, 999999 };
        bool agreed = true;
        for (size_t i = 0; i < sizeof(locktimes)/sizeof(locktimes[0]); i++) {
            for (size_t j = 0; j < sizeof(heights)/sizeof(heights[0]); j++) {
                struct transaction tx;
                locktime_tx_init(&tx, locktimes[i], 0);
                bool d = domain_consensus_tx_is_final(&tx, heights[j], 0);
                bool l = is_final_tx(&tx, heights[j], 0);
                if (d != l) agreed = false;
                locktime_tx_free(&tx);
            }
        }
        DCL_CHECK("seal: is_final_tx height-domain matches across boundary",
                  agreed);
    }

    /* Lock-time by TIME: sweep around the lt=T boundary in time domain. */
    {
        const uint32_t locktimes[] = { 500000000, 500000001, 500000100,
                                         1000000000, 2000000000u };
        const int64_t  times[]     = { 0, 499999999, 500000000, 500000001,
                                         500000100, 999999999, 3000000000LL };
        bool agreed = true;
        for (size_t i = 0; i < sizeof(locktimes)/sizeof(locktimes[0]); i++) {
            for (size_t j = 0; j < sizeof(times)/sizeof(times[0]); j++) {
                struct transaction tx;
                locktime_tx_init(&tx, locktimes[i], 0);
                bool d = domain_consensus_tx_is_final(&tx, 12, times[j]);
                bool l = is_final_tx(&tx, 12, times[j]);
                if (d != l) agreed = false;
                locktime_tx_free(&tx);
            }
        }
        DCL_CHECK("seal: is_final_tx time-domain matches across boundary",
                  agreed);
    }

    /* Sequence override: any non-final input flips finality at every
     * height — seal it. */
    {
        const uint32_t seqs[] = { 0, 1, 0x7FFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF };
        bool agreed = true;
        for (size_t i = 0; i < sizeof(seqs)/sizeof(seqs[0]); i++) {
            struct transaction tx;
            locktime_tx_init(&tx, 999999, seqs[i]);
            for (int h = 0; h < 6; h++) {
                bool d = domain_consensus_tx_is_final(&tx, h * 200000, 0);
                bool l = is_final_tx(&tx, h * 200000, 0);
                if (d != l) agreed = false;
            }
            locktime_tx_free(&tx);
        }
        DCL_CHECK("seal: is_final_tx sequence-override matches", agreed);
    }

    /* Expiry boundary: sweep heights around expiry_height for several
     * expiry values. */
    {
        const uint32_t expiries[] = { 1, 2, 100, 1000000 };
        bool agreed = true;
        for (size_t i = 0; i < sizeof(expiries)/sizeof(expiries[0]); i++) {
            struct transaction tx;
            memset(&tx, 0, sizeof(tx));
            tx.expiry_height = expiries[i];
            tx.num_vin = 1;
            tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_locktime_vin");
            memset(tx.vin[0].prevout.hash.data, 0xAA, 32);
            tx.vin[0].prevout.n = 0;
            int sweep[] = { 0, (int)expiries[i]-1, (int)expiries[i],
                             (int)expiries[i]+1, (int)expiries[i]+100 };
            for (size_t j = 0; j < sizeof(sweep)/sizeof(sweep[0]); j++) {
                bool d = domain_consensus_tx_is_expired(&tx, sweep[j]);
                bool l = is_expired_tx(&tx, sweep[j]);
                if (d != l) agreed = false;
                bool ds = domain_consensus_tx_is_expiring_soon(&tx, sweep[j]);
                bool ls = is_expiring_soon_tx(&tx, sweep[j]);
                if (ds != ls) agreed = false;
            }
            free(tx.vin);
        }
        DCL_CHECK("seal: is_expired/expiring_soon match across boundary",
                  agreed);
    }

    /* The compile-time constants must mirror the legacy literals
     * exactly (they're tx-relay-visible). */
    DCL_CHECK("seal: LOCKTIME_THRESHOLD_TX == domain threshold",
              (int64_t)LOCKTIME_THRESHOLD_TX
                  == DOMAIN_CONSENSUS_LOCKTIME_THRESHOLD);
    DCL_CHECK("seal: TX_EXPIRING_SOON_THRESHOLD == domain threshold",
              TX_EXPIRING_SOON_THRESHOLD
                  == DOMAIN_CONSENSUS_TX_EXPIRING_SOON_THRESHOLD);

    return failures;
}
