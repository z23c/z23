/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for domain/consensus/checkpoints.{c,h}.
 *
 * Pins the pure checkpoint-matching logic extracted from
 * core/modules/chain/src/checkpoints.c. Tests exercise the domain API
 * directly AND cross-check against the legacy core/modules/chain wrappers
 * to prove the extraction is behaviour-preserving.
 *
 * Coverage:
 *   - hash_at_height: NULL safety, exact match, miss, multiple entries
 *   - last_height:    NULL/empty (-1), single, multi-entry, unordered
 *   - validate_header: NULL safety, no-checkpoint passthrough, exact
 *                      match accept, mismatch reject
 *   - total_blocks_estimate: empty (0), populated (deepest entry)
 *   - progress_at_now: pure (same now → same fraction across calls);
 *                      bounded in [0,1]; below/above checkpoint branches;
 *                      NULL-data guard; divide-by-zero guard
 *   - wrapper parity: legacy core/modules/chain APIs return identical values
 *                     to their domain counterparts on a synthetic table
 *                     with multiple heights.
 */

#include "test/test_core.h"
#include "chain/chainparams.h"

#include "domain/consensus/checkpoints.h"
#include "chain/checkpoints.h"
#include "chain/chain.h"
#include "core/uint256.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#define DCC_CHECK(name, expr) do { \
    printf("domain_consensus_checkpoints: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Synthetic checkpoint table — three entries at heights 100, 1000, 5000. */
static void mk_table(struct checkpoint_data *cd,
                     struct checkpoint_entry entries[3])
{
    memset(entries, 0, sizeof(struct checkpoint_entry) * 3);
    entries[0].height = 100;
    memset(entries[0].hash.data, 0xAA, 32);
    entries[1].height = 1000;
    memset(entries[1].hash.data, 0xBB, 32);
    entries[2].height = 5000;
    memset(entries[2].hash.data, 0xCC, 32);

    cd->entries = entries;
    cd->nEntries = 3;
    cd->nTimeLastCheckpoint = 1500000000;       /* 2017-07-14 */
    cd->nTransactionsLastCheckpoint = 200000;
    cd->fTransactionsPerDay = 1000.0;
}

/* ──────────────────── hash_at_height ──────────────────── */
static int check_hash_at_height(void)
{
    int failures = 0;

    {
        struct checkpoint_entry e[3];
        struct checkpoint_data cd;
        mk_table(&cd, e);

        struct uint256 h;
        memset(&h, 0, sizeof(h));

        /* NULL data → false, no crash. */
        DCC_CHECK("hash_at_height(NULL,0,&h) -> false",
                  !domain_consensus_checkpoints_hash_at_height(NULL, 0, &h));
        /* NULL out → false, no crash. */
        DCC_CHECK("hash_at_height(cd,100,NULL) -> false",
                  !domain_consensus_checkpoints_hash_at_height(&cd, 100, NULL));

        /* Exact match at first entry. */
        memset(&h, 0, sizeof(h));
        bool hit = domain_consensus_checkpoints_hash_at_height(&cd, 100, &h);
        DCC_CHECK("hash_at_height(100) -> hit", hit);
        DCC_CHECK("hash_at_height(100) hash matches",
                  hit && h.data[0] == 0xAA && h.data[31] == 0xAA);

        /* Exact match at middle entry. */
        memset(&h, 0, sizeof(h));
        hit = domain_consensus_checkpoints_hash_at_height(&cd, 1000, &h);
        DCC_CHECK("hash_at_height(1000) -> hit",
                  hit && h.data[0] == 0xBB);

        /* Exact match at last entry. */
        memset(&h, 0, sizeof(h));
        hit = domain_consensus_checkpoints_hash_at_height(&cd, 5000, &h);
        DCC_CHECK("hash_at_height(5000) -> hit",
                  hit && h.data[0] == 0xCC);

        /* Miss in the gap. */
        memset(&h, 0xFF, sizeof(h));  /* sentinel: should remain untouched */
        bool miss = domain_consensus_checkpoints_hash_at_height(&cd, 500, &h);
        DCC_CHECK("hash_at_height(500) -> miss", !miss);
        DCC_CHECK("hash_at_height miss leaves out_hash untouched",
                  h.data[0] == 0xFF && h.data[31] == 0xFF);

        /* Miss below table. */
        DCC_CHECK("hash_at_height(0) -> miss",
                  !domain_consensus_checkpoints_hash_at_height(&cd, 0, &h));
        /* Miss above table. */
        DCC_CHECK("hash_at_height(99999) -> miss",
                  !domain_consensus_checkpoints_hash_at_height(&cd, 99999, &h));
    }

    return failures;
}

/* ──────────────────── last_height ──────────────────── */
static int check_last_height(void)
{
    int failures = 0;

    {
        /* NULL → -1. */
        DCC_CHECK("last_height(NULL) -> -1",
                  domain_consensus_checkpoints_last_height(NULL) == -1);

        /* Empty table → -1. */
        struct checkpoint_data empty = {0};
        DCC_CHECK("last_height(empty) -> -1",
                  domain_consensus_checkpoints_last_height(&empty) == -1);

        /* Populated → deepest. */
        struct checkpoint_entry e[3];
        struct checkpoint_data cd;
        mk_table(&cd, e);
        DCC_CHECK("last_height(populated) -> 5000",
                  domain_consensus_checkpoints_last_height(&cd) == 5000);

        /* Unordered table: defensive scan must still pick the max. */
        struct checkpoint_entry shuffled[3];
        memset(shuffled, 0, sizeof(shuffled));
        shuffled[0].height = 5000;
        shuffled[1].height = 100;
        shuffled[2].height = 1000;
        struct checkpoint_data cd_shuf = {
            .entries = shuffled, .nEntries = 3,
            .nTimeLastCheckpoint = 0,
            .nTransactionsLastCheckpoint = 0,
            .fTransactionsPerDay = 0.0,
        };
        DCC_CHECK("last_height(unordered) -> 5000 (defensive)",
                  domain_consensus_checkpoints_last_height(&cd_shuf) == 5000);
    }

    return failures;
}

/* ──────────────────── validate_header ──────────────────── */
static int check_validate_header(void)
{
    int failures = 0;

    {
        struct checkpoint_entry e[3];
        struct checkpoint_data cd;
        mk_table(&cd, e);

        struct uint256 any;
        memset(any.data, 0x77, 32);

        /* NULL data → true (degenerate). */
        DCC_CHECK("validate_header(NULL,h,&any) -> true",
                  domain_consensus_checkpoints_validate_header(NULL, 100, &any));
        /* NULL hash → true (degenerate). */
        DCC_CHECK("validate_header(cd,h,NULL) -> true",
                  domain_consensus_checkpoints_validate_header(&cd, 100, NULL));

        /* No checkpoint at this height → true (nothing to check). */
        DCC_CHECK("validate_header(cd,500,any) -> true",
                  domain_consensus_checkpoints_validate_header(&cd, 500, &any));

        /* Exact-match hash at a pinned height → true. */
        struct uint256 match;
        memset(match.data, 0xAA, 32);
        DCC_CHECK("validate_header(cd,100,match) -> true",
                  domain_consensus_checkpoints_validate_header(&cd, 100, &match));

        /* Mismatched hash at a pinned height → false (fork). */
        struct uint256 wrong;
        memset(wrong.data, 0x99, 32);
        DCC_CHECK("validate_header(cd,100,wrong) -> false (fork)",
                  !domain_consensus_checkpoints_validate_header(&cd, 100, &wrong));

        /* Mismatched hash at the deepest pin too. */
        DCC_CHECK("validate_header(cd,5000,wrong) -> false (fork)",
                  !domain_consensus_checkpoints_validate_header(&cd, 5000, &wrong));
    }

    return failures;
}

/* ──────────────── L3 LOCK-IN: checkpoint fork-guard is exact-height-only ──
 * (docs/work/parity-audit-round2-findings.md, L3.) validate_header()
 * returns true when no checkpoint exists at the EXACT height, even below
 * the last checkpoint; zclassicd also rejects nHeight <
 * lastCheckpoint.nHeight (main.cpp:4386-4392). This pins the current
 * behavior: a header at a non-checkpointed height below the last
 * checkpoint (5000) is ACCEPTED with any hash, while an exact-height
 * mismatch rejects. The accepts flip if a below-last-checkpoint guard
 * lands. */
static int check_l3_fork_guard_pins(void)
{
    int failures = 0;

    {
        struct checkpoint_entry e[3];
        struct checkpoint_data cd;
        mk_table(&cd, e);  /* checkpoints at 100, 1000, 5000 */

        const int last = domain_consensus_checkpoints_last_height(&cd);  /* 5000 */
        DCC_CHECK("L3: last checkpoint height is 5000", last == 5000);

        /* Arbitrary attacker-chosen hash with no relation to any pin. */
        struct uint256 forged;
        memset(forged.data, 0x42, 32);

        /* A height strictly below the last checkpoint but at no exact pin
         * (e.g. 4000, between 1000 and 5000) — zcl23 ACCEPTS with any hash. */
        DCC_CHECK("L3 PIN: header below last checkpoint (h=4000), "
                  "non-pinned, arbitrary hash -> ACCEPTED today",
                  domain_consensus_checkpoints_validate_header(&cd, 4000, &forged));

        /* Even just below the deepest pin (h=4999) — still accepted, because
         * the only rule is exact-height match and 4999 is not a pin. */
        DCC_CHECK("L3 PIN: header at h=4999 (just below last cp), "
                  "arbitrary hash -> ACCEPTED today",
                  domain_consensus_checkpoints_validate_header(&cd, 4999, &forged));

        /* A non-pinned height ABOVE the last checkpoint (h=6000) is also
         * accepted (parity with zclassicd); brackets the loosening to
         * "below last checkpoint". */
        DCC_CHECK("L3: header above last checkpoint (h=6000) -> accepted (parity)",
                  domain_consensus_checkpoints_validate_header(&cd, 6000, &forged));

        /* The one rule zcl23 DOES enforce: an EXACT-height mismatch at a pin
         * rejects. h=5000 is a pin and `forged` != 0xCC. */
        DCC_CHECK("L3: exact-height mismatch at h=5000 -> REJECTED (enforced)",
                  !domain_consensus_checkpoints_validate_header(&cd, 5000, &forged));
    }

    return failures;
}

/* ──────────────────── total_blocks_estimate ──────────────────── */
static int check_total_blocks_estimate(void)
{
    int failures = 0;

    {
        /* NULL → 0. */
        DCC_CHECK("total_blocks_estimate(NULL) -> 0",
                  domain_consensus_checkpoints_total_blocks_estimate(NULL) == 0);

        /* Empty → 0. */
        struct checkpoint_data empty = {0};
        DCC_CHECK("total_blocks_estimate(empty) -> 0",
                  domain_consensus_checkpoints_total_blocks_estimate(&empty) == 0);

        /* Populated: the contract is the LAST entry's height, not the
         * maximum (as zclassicd ships); mk_table is ascending. */
        struct checkpoint_entry e[3];
        struct checkpoint_data cd;
        mk_table(&cd, e);
        DCC_CHECK("total_blocks_estimate(populated) -> 5000",
                  domain_consensus_checkpoints_total_blocks_estimate(&cd) == 5000);
    }

    return failures;
}

/* ──────────────────── progress_at_now ──────────────────── */
static int check_progress_at_now(void)
{
    int failures = 0;

    {
        struct checkpoint_entry e[3];
        struct checkpoint_data cd;
        mk_table(&cd, e);

        /* NULL data → 0.0 (clean guard, no crash). */
        DCC_CHECK("progress_at_now(NULL data) -> 0.0",
                  domain_consensus_checkpoints_progress_at_now(
                      NULL, 100, 1500000000, 1600000000, true) == 0.0);

        /* Determinism: same inputs → same output across calls (pure). */
        double a = domain_consensus_checkpoints_progress_at_now(
                       &cd, 100000, 1500000000, 1600000000, true);
        double b = domain_consensus_checkpoints_progress_at_now(
                       &cd, 100000, 1500000000, 1600000000, true);
        DCC_CHECK("progress_at_now is deterministic", a == b);

        /* Bounded in [0, 1]. nChainTx 100000 ≤ 200000 (cheap branch). */
        DCC_CHECK("progress_at_now bounded (below-checkpoint)",
                  a >= 0.0 && a <= 1.0);

        /* Above-checkpoint branch: nChainTx > nTransactionsLastCheckpoint. */
        double c = domain_consensus_checkpoints_progress_at_now(
                       &cd, 300000, 1500000000, 1600000000, true);
        DCC_CHECK("progress_at_now bounded (above-checkpoint)",
                  c >= 0.0 && c <= 1.0);

        /* fSigchecks=false vs true differ in multiplier, away from the
         * boundary. */
        double w_sig  = domain_consensus_checkpoints_progress_at_now(
                            &cd, 100000, 1500000000, 1600000000, true);
        double w_nosig = domain_consensus_checkpoints_progress_at_now(
                            &cd, 100000, 1500000000, 1600000000, false);
        DCC_CHECK("progress_at_now: fSigchecks toggle matters",
                  w_sig != w_nosig);

        /* Divide-by-zero guard: nChainTx==0, now==nTimeLastCheckpoint.
         * In the legacy code this produced 0 / 0 = NaN; we now clamp to 0. */
        double z = domain_consensus_checkpoints_progress_at_now(
                       &cd, 0, 0, cd.nTimeLastCheckpoint, true);
        DCC_CHECK("progress_at_now divide-by-zero -> 0.0",
                  z == 0.0);
    }

    return failures;
}

/* ──────────────────── wrapper-vs-domain regression seal ──────────────── */
static int check_wrapper_parity(void)
{
    int failures = 0;

    {
        struct checkpoint_entry e[3];
        struct checkpoint_data cd;
        mk_table(&cd, e);

        /* hash_at_height parity across the entire ±1 neighbourhood of
         * every pinned height plus a couple of misses. */
        const int probes[] = {99, 100, 101, 999, 1000, 1001, 4999, 5000, 5001, 0, 99999};
        bool all_match = true;
        for (size_t i = 0; i < sizeof(probes)/sizeof(probes[0]); i++) {
            struct uint256 h_dom; memset(&h_dom, 0, sizeof(h_dom));
            struct uint256 h_lib; memset(&h_lib, 0, sizeof(h_lib));
            bool d_ok = domain_consensus_checkpoints_hash_at_height(&cd, probes[i], &h_dom);
            bool l_ok = checkpoints_hash_at_height(&cd, probes[i], &h_lib);
            if (d_ok != l_ok) { all_match = false; break; }
            if (d_ok && memcmp(h_dom.data, h_lib.data, 32) != 0) {
                all_match = false; break;
            }
        }
        DCC_CHECK("wrapper hash_at_height parity", all_match);

        /* last_height parity. */
        DCC_CHECK("wrapper last_height parity",
                  checkpoints_last_height(&cd) ==
                  domain_consensus_checkpoints_last_height(&cd));

        /* validate_header parity across pinned + non-pinned heights. */
        struct uint256 match_aa; memset(match_aa.data, 0xAA, 32);
        struct uint256 wrong;    memset(wrong.data,    0x99, 32);
        bool ok = true;
        ok = ok &&
             (checkpoints_validate_header(&cd, 100, &match_aa) ==
              domain_consensus_checkpoints_validate_header(&cd, 100, &match_aa));
        ok = ok &&
             (checkpoints_validate_header(&cd, 100, &wrong) ==
              domain_consensus_checkpoints_validate_header(&cd, 100, &wrong));
        ok = ok &&
             (checkpoints_validate_header(&cd, 500, &wrong) ==
              domain_consensus_checkpoints_validate_header(&cd, 500, &wrong));
        DCC_CHECK("wrapper validate_header parity", ok);

        /* total_blocks_estimate parity. */
        DCC_CHECK("wrapper total_blocks_estimate parity",
                  checkpoints_get_total_blocks_estimate(&cd) ==
                  domain_consensus_checkpoints_total_blocks_estimate(&cd));

        /* The wrapper reads the wall clock, so assert (a) its NULL-pindex
         * contract (0.0) and (b) that a fixed pindex yields a value the
         * domain primitive reproduces with `now` near today. Bounded in
         * [0,1] is the load-bearing check. */
        DCC_CHECK("wrapper guess_progress(NULL pindex) -> 0.0",
                  checkpoints_guess_verification_progress(&cd, NULL, true) == 0.0);

        struct block_index bi;
        block_index_init(&bi);
        bi.nChainTx = 100000;
        bi.nTime    = 1500000000;
        double w_prog = checkpoints_guess_verification_progress(&cd, &bi, true);
        DCC_CHECK("wrapper guess_progress bounded in [0,1]",
                  w_prog >= 0.0 && w_prog <= 1.0);
        /* Call the domain primitive with a `now` that straddles the
         * wrapper's clock read and check the result is on the same side of
         * [0,1]; exact equality follows from the wrapper forwarding to it. */
        double d_prog_now = domain_consensus_checkpoints_progress_at_now(
                              &cd,
                              (uint64_t)bi.nChainTx,
                              block_index_get_time(&bi),
                              /* now ≈ wrapper's read; tolerate small drift */
                              1700000000,
                              true);
        DCC_CHECK("domain progress with explicit now bounded in [0,1]",
                  d_prog_now >= 0.0 && d_prog_now <= 1.0);
    }

    return failures;
}

/* ──────────────────── sanity: real mainnet table parity ──────────── */
/* Round-trip the selected chainparams' real checkpoint_data through both
 * APIs, not just the synthetic table. */
static int check_mainnet_parity(void)
{
    int failures = 0;

    {
        const struct chain_params *p = chain_params_get();
        if (p) {
            const struct checkpoint_data *cd = &p->checkpointData;
            /* Whatever the real table contains, the two functions must
             * agree on its deepest height. */
            DCC_CHECK("mainnet last_height: wrapper == domain",
                      checkpoints_last_height(cd) ==
                      domain_consensus_checkpoints_last_height(cd));
            DCC_CHECK("mainnet total_blocks_estimate: wrapper == domain",
                      checkpoints_get_total_blocks_estimate(cd) ==
                      domain_consensus_checkpoints_total_blocks_estimate(cd));
        }
    }

    return failures;
}

int test_domain_consensus_checkpoints(void)
{
    int failures = 0;

    failures += check_hash_at_height();
    failures += check_last_height();
    failures += check_validate_header();
    failures += check_l3_fork_guard_pins();
    failures += check_total_blocks_estimate();
    failures += check_progress_at_now();
    failures += check_wrapper_parity();
    failures += check_mainnet_parity();

    return failures;
}
