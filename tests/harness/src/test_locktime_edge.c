/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * NET-NEW consensus edge-case tests for domain/consensus/locktime.{c,h}.
 *
 * test_domain_consensus_locktime.c and test_bip113_bip65.c already pin the
 * happy-path BIP65/BIP113 boundaries, the height/time domain flip, the
 * sequence override, and the Overwinter expiry boundary. This file
 * deliberately does NOT restate any of those. It targets the degenerate
 * and overflow corners that a "must never fork" node has to answer
 * identically forever:
 *
 *   - Vacuous-truth finality of a tx with ZERO inputs past the lock-time
 *     boundary (the for-loop body never runs → "final"). This mirrors the
 *     vacuous-truth in Bitcoin Core's IsFinalTx / a degenerate tx that
 *     somehow reaches the predicate; pinning it stops a future "tighten
 *     the empty-vin case" edit from silently changing the verdict.
 *   - The EXACT lock_time == LOCKTIME_THRESHOLD (5e8) corner, where the
 *     domain-selection comparison (`< THRESHOLD`, strict) and the
 *     finality comparison (`< cutoff`, strict) interact. The lt=5e8 case
 *     is the first value in the TIME domain and must compare against
 *     n_block_time, never n_block_height.
 *   - The maximum lock_time (0xFFFFFFFF) in the time domain, just below /
 *     above the cutoff — guards the int64 widening of a uint32 lock_time.
 *   - Negative n_block_height fed to a height-domain lock_time: the int64
 *     widening must keep a positive lock_time from ever comparing `< neg`,
 *     so the tx stays non-final (conservative).
 *   - is_expired with a NEGATIVE n_height: the `(uint32_t)n_height` cast
 *     in locktime.c wraps a negative height to a huge unsigned value. We
 *     PIN the current consensus behavior so any future change is loud, and
 *     pair it with expiry_height==0 (never-expires) to prove the cast is
 *     gated behind the zero check.
 *   - is_expired at the MAXIMUM expiry_height (0xFFFFFFFF) — boundary of
 *     the uint32 expiry domain.
 *   - is_expiring_soon near INT_MAX, where n_next_block_height + 3 would
 *     overflow signed int: confirm the predicate still returns a verdict
 *     (it must not crash / it must be deterministic) and is consistent
 *     with is_expired at the saturated height.
 *
 * Pure: no clock, no RNG, no I/O, no node, no network. Every case invokes
 * the real domain_consensus_* function and asserts the exact verdict.
 */

#include "test/test_core.h"

#include "domain/consensus/locktime.h"
#include "primitives/transaction.h"
#include "util/safe_alloc.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#define DCLE_CHECK(name, expr) do { \
    printf("locktime_edge: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* One input at the given sequence, given lock_time, non-coinbase prevout. */
static void le_tx_init(struct transaction *tx,
                       uint32_t lock_time, uint32_t sequence)
{
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->lock_time = lock_time;
    tx->num_vin = 1;
    tx->vin = zcl_calloc(1, sizeof(struct tx_in), "test_locktime_edge_vin");
    tx->vin[0].sequence = sequence;
    memset(tx->vin[0].prevout.hash.data, 0xCC, 32);
    tx->vin[0].prevout.n = 0;
}

static void le_tx_free(struct transaction *tx)
{
    free(tx->vin);
}

int test_locktime_edge(void)
{
    int failures = 0;

    /* ── 1. Zero-input tx past the lock-time boundary → vacuously final.
     * lock_time=100 (height domain), height=0 is below the cutoff so the
     * `lt < cutoff` early-out does NOT fire; the for-loop over inputs runs
     * zero times → returns true. A degenerate no-input tx is reported
     * final; pin it so a future edit can't silently change the verdict. */
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.version = 1;
        tx.lock_time = 100;        /* height domain, not yet reached at h=0 */
        tx.num_vin = 0;            /* no inputs */
        tx.vin = NULL;
        DCLE_CHECK("zero-input tx is vacuously final past lock boundary",
                   domain_consensus_tx_is_final(&tx, 0, 0));
        /* And with lock_time below the height it's final via the early-out
         * regardless of the (empty) input set. */
        DCLE_CHECK("zero-input tx final by height early-out too",
                   domain_consensus_tx_is_final(&tx, 200, 0));
    }

    /* ── 2. lock_time EXACTLY at LOCKTIME_THRESHOLD (5e8): first value in
     * the TIME domain. Must compare against n_block_time, never height. */
    {
        struct transaction tx;
        le_tx_init(&tx, 500000000u, 0 /* non-final input */);

        /* Huge height alone must NOT finalize a 5e8 (time-domain) lock. */
        DCLE_CHECK("lt==5e8 ignores height (uses time domain)",
                   !domain_consensus_tx_is_final(&tx, INT_MAX, 0));
        /* time == lock_time: strict `lt < cutoff` is false → falls to the
         * sequence check; input is non-final → tx not final. */
        DCLE_CHECK("lt==5e8 not final when time == lock_time",
                   !domain_consensus_tx_is_final(&tx, 0, 500000000LL));
        /* time one past → final by the time early-out. */
        DCLE_CHECK("lt==5e8 final when time == lock_time+1",
                   domain_consensus_tx_is_final(&tx, 0, 500000001LL));
        le_tx_free(&tx);
    }

    /* ── 3. Maximum lock_time (0xFFFFFFFF) in the time domain. Guards the
     * widening of a uint32 lock_time to int64 (no sign surprise). */
    {
        struct transaction tx;
        le_tx_init(&tx, 0xFFFFFFFFu /* = 4294967295 */, 0 /* non-final */);

        /* time just below max → not final (and non-final input). */
        DCLE_CHECK("lt==UINT32_MAX not final when time < lock_time",
                   !domain_consensus_tx_is_final(&tx, 0, 4294967294LL));
        /* time == max → strict compare false, non-final input → not final. */
        DCLE_CHECK("lt==UINT32_MAX not final when time == lock_time",
                   !domain_consensus_tx_is_final(&tx, 0, 4294967295LL));
        /* time one past max → final by time early-out (proves no truncation
         * of the 32-bit lock_time when widened). */
        DCLE_CHECK("lt==UINT32_MAX final when time == lock_time+1",
                   domain_consensus_tx_is_final(&tx, 0, 4294967296LL));
        le_tx_free(&tx);
    }

    /* ── 4. Negative n_block_height with a height-domain lock_time. A
     * positive lock_time must never compare `< negative`, so the tx stays
     * non-final (conservative). Pins the int64 widening of the height. */
    {
        struct transaction tx;
        le_tx_init(&tx, 100u, 0 /* non-final input */);
        DCLE_CHECK("height-domain lt not final at negative height",
                   !domain_consensus_tx_is_final(&tx, -1, 0));
        DCLE_CHECK("height-domain lt not final at INT_MIN height",
                   !domain_consensus_tx_is_final(&tx, INT_MIN, 0));
        /* But a 0xFFFFFFFF-sequence input still overrides at any height. */
        le_tx_free(&tx);
        le_tx_init(&tx, 100u, 0xFFFFFFFFu);
        DCLE_CHECK("final-sequence overrides even at negative height",
                   domain_consensus_tx_is_final(&tx, -1, 0));
        le_tx_free(&tx);
    }

    /* ── 5. is_expired with a NEGATIVE height. locktime.c casts to uint32,
     * so a negative height wraps to a huge unsigned value. PIN the current
     * consensus verdict (so any future change is loud) and prove the zero
     * expiry_height guard short-circuits before the cast. */
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.expiry_height = 0;       /* never expires */
        tx.num_vin = 1;
        tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_locktime_edge_vin");
        memset(tx.vin[0].prevout.hash.data, 0xAA, 32);
        tx.vin[0].prevout.n = 0;
        DCLE_CHECK("expiry_height=0 never expires even at negative height",
                   !domain_consensus_tx_is_expired(&tx, -1));
        free(tx.vin);
    }
    {
        /* With a real expiry_height, a negative height casts to ~4.29e9 and
         * (uint32_t)n_height >= expiry_height is true → reported expired.
         * This is the documented cast behavior; pin it. */
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.expiry_height = 100;
        tx.num_vin = 1;
        tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_locktime_edge_vin");
        memset(tx.vin[0].prevout.hash.data, 0xAA, 32);
        tx.vin[0].prevout.n = 0;
        DCLE_CHECK("expiry: negative height wraps to huge unsigned → expired",
                   domain_consensus_tx_is_expired(&tx, -1));
        free(tx.vin);
    }

    /* ── 6. is_expired at the MAXIMUM expiry_height (0xFFFFFFFF). The only
     * non-negative height that reaches it is one whose uint32 cast equals
     * UINT32_MAX. A normal in-range height stays not-expired. */
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.expiry_height = 0xFFFFFFFFu;
        tx.num_vin = 1;
        tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_locktime_edge_vin");
        memset(tx.vin[0].prevout.hash.data, 0xAA, 32);
        tx.vin[0].prevout.n = 0;
        /* INT_MAX (~2.1e9) < UINT32_MAX (~4.29e9) → not expired. */
        DCLE_CHECK("expiry=UINT32_MAX not expired at INT_MAX height",
                   !domain_consensus_tx_is_expired(&tx, INT_MAX));
        /* Strict GT (matching zclassicd IsExpiredTx): NO uint32 height can
         * EXCEED UINT32_MAX, so expiry_height=UINT32_MAX means the tx NEVER
         * expires — not even at the saturated boundary (a height whose uint32
         * cast == UINT32_MAX, e.g. -1). (Was `>=`, which wrongly expired it
         * exactly there.) */
        DCLE_CHECK("expiry=UINT32_MAX never expires (strict >, cast==UINT32_MAX)",
                   !domain_consensus_tx_is_expired(&tx, -1));
        free(tx.vin);
    }

    /* ── 7. is_expiring_soon near INT_MAX: n_next_block_height + 3 would
     * overflow signed int. The predicate must still return a deterministic
     * verdict and stay consistent with is_expired at a high height. We do
     * NOT trigger UB ourselves; we exercise a large-but-safe height and the
     * exact threshold-window boundary, then a coinbase (never expires). */
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.expiry_height = 1000u;
        tx.num_vin = 1;
        tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_locktime_edge_vin");
        memset(tx.vin[0].prevout.hash.data, 0xAA, 32);
        tx.vin[0].prevout.n = 0;
        /* window = +3, strict GT. next=997 → check@1000 == expiry → NOT yet
         * (a tx is valid AT its expiry_height). next=998 → check@1001 > expiry
         * → expiring soon. */
        DCLE_CHECK("NOT expiring_soon at next+3 == expiry_height (strict >)",
                   !domain_consensus_tx_is_expiring_soon(&tx, 997));
        DCLE_CHECK("expiring_soon at next+3 > expiry_height",
                   domain_consensus_tx_is_expiring_soon(&tx, 998));
        /* next=996 → check@999 < expiry → not yet. */
        DCLE_CHECK("not expiring_soon one block before the window",
                   !domain_consensus_tx_is_expiring_soon(&tx, 996));
        /* A huge but in-range next-height is well past expiry → soon. */
        DCLE_CHECK("expiring_soon for far-future next height",
                   domain_consensus_tx_is_expiring_soon(&tx, 1000000000));
        free(tx.vin);
    }

    /* Coinbase is never expiring-soon even with expiry_height set: the
     * coinbase short-circuit in is_expired must propagate through the
     * is_expiring_soon wrapper. */
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.expiry_height = 5;
        tx.num_vin = 1;
        tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_locktime_edge_vin");
        memset(tx.vin[0].prevout.hash.data, 0, 32);   /* coinbase */
        tx.vin[0].prevout.n = 0xFFFFFFFF;
        DCLE_CHECK("coinbase never expiring_soon despite expiry_height",
                   !domain_consensus_tx_is_expiring_soon(&tx, 1000000000));
        free(tx.vin);
    }

    return failures;
}
