/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sync_throughput — repeatable in-tree benchmark for initial block sync
 * throughput. No live node, no network, no canonical datadir: every byte
 * is built deterministically in-process (fixed times, fixed values, the
 * baked real Equihash witness for the PoW leg) and every timed stage
 * calls the REAL production function, so the numbers describe the node,
 * not a model of it.
 *
 * Stages (each timed separately so the profile says WHERE the time goes):
 *   S1 header wire round-trip  (serialize + parse)          -> headers/s
 *   S2 header PoW verify       (Equihash 200,9, real witness)-> us/verify
 *   S3 merkle root computation (1/2/8/64-tx widths)         -> roots/s
 *   S4 structural block check  (check_block, PoW excluded)  -> us/block,
 *                                                               bodies/s
 *   S5 header-range planning   (hrs_partition over anchors)  -> us/plan
 *   S6 flat header point reads (block_index_flat_header_at) -> heights/s
 *
 * Budgets are declared in reference-box units and scaled for the running
 * box by test/test_timing_budget.h's calibrate-then-scale contract
 * (test_budget_scale), so a busy machine reports a smaller margin, not
 * a false red.
 *
 * Teeth (a benchmark of a hollow verifier is worthless):
 *   - every fixture block passes check_block AND a mutated copy fails
 *     with the exact historical reason;
 *   - the timed Equihash witness verifies true AND a one-bit-flipped
 *     copy verifies false (same two directions as verify_bench_selftest,
 *     pinned on the exact input being timed);
 *   - every flat point read returns the exact bytes written by the
 *     fixture save, and a missing height refuses;
 *   - hrs_partition output is pinned against a golden span set.
 */

#include "test/test_core.h"
#include "test/test_timing_budget.h"
#include "test/verify_bench_fixture.h"
#include "test/test_sync_throughput_internal.h"

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "bloom/merkle.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/equihash.h"
#include "validation/check_block.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "services/block_index_loader.h"
#include "services/header_range_scheduler.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── Deterministic fixture ─────────────────────────────────────── */

static struct block g_blocks[ST_FIXTURE_BLOCKS];
static struct byte_stream g_wire[ST_FIXTURE_BLOCKS];
static int g_fixture_ready = 0;


/* One coinbase shaped exactly like test_chain.c's proven-valid recipe:
 * 1 vin (prevout.n = UINT32_MAX), 1 vout, 2-byte script_sig. */
static bool st_build_coinbase(struct transaction *tx, uint32_t seq)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1))
        return false;
    tx->vin[0].prevout.n = UINT32_MAX;
    tx->vout[0].value = 50 * 100000000LL;
    tx->vin[0].script_sig.data[0] = (uint8_t)(1 + (seq & 0x7f));
    tx->vin[0].script_sig.data[1] = 0;
    tx->vin[0].script_sig.size = 2;
    transaction_compute_hash(tx);
    return true;
}

bool st_build_fixture(void)
{
    if (g_fixture_ready)
        return true;
    for (uint32_t i = 0; i < ST_FIXTURE_BLOCKS; i++) {
        block_init(&g_blocks[i]);
        g_blocks[i].header.nVersion = 4;
        g_blocks[i].header.nTime = ST_FIXED_TIME + i * 150u;
        g_blocks[i].header.nBits = 0x1f07ffffu;
        memset(g_blocks[i].header.hashPrevBlock.data, (int)(i & 0xff), 32);
        g_blocks[i].num_vtx = 1;
        g_blocks[i].vtx = zcl_calloc(1, sizeof(struct transaction),
                                     "sync_throughput fixture");
        if (!g_blocks[i].vtx)
            return false;
        if (!st_build_coinbase(&g_blocks[i].vtx[0], i))
            return false;
        g_blocks[i].header.hashMerkleRoot =
            compute_merkle_root(&g_blocks[i].vtx[0].hash, 1);
        stream_init(&g_wire[i], 256);
        if (!block_header_serialize(&g_blocks[i].header, &g_wire[i]))
            return false;
    }
    g_fixture_ready = 1;
    return true;
}

void st_free_fixture(void)
{
    if (!g_fixture_ready)
        return;
    for (uint32_t i = 0; i < ST_FIXTURE_BLOCKS; i++) {
        block_free(&g_blocks[i]);
        stream_free(&g_wire[i]);
    }
    g_fixture_ready = 0;
}

/* Deterministic txid array for the merkle stage: width w, lane-fixed. */
static void st_fill_txids(struct uint256 *out, size_t w, uint32_t lane)
{
    for (size_t i = 0; i < w; i++) {
        for (int b = 0; b < 32; b++)
            out[i].data[b] =
                (uint8_t)((i * 31u + (size_t)b * 17u + lane) & 0xffu);
    }
}

/* ── Stage timers ──────────────────────────────────────────────── */

double st_per_s(uint64_t ops, uint64_t elapsed_us)
{
    if (elapsed_us == 0)
        return 0.0;
    return (double)ops * 1000000.0 / (double)elapsed_us;
}

/* Bridge onto test/test_timing_budget.h's calibrate-then-scale contract
 * (struct test_budget / test_budget_scale): a ceiling scales UP with the
 * measured load factor (a loaded box gets more time), a floor scales
 * DOWN by the same factor (a loaded box may go slower). The factor does
 * not depend on the nominal value passed to test_budget_scale, so both
 * helpers below read only .factor off an otherwise-throwaway call. */
bool st_check_ceiling_us(const char *label, uint64_t measured_us,
                                uint64_t nominal_us, int *failures)
{
    struct test_budget b = test_budget_scale(nominal_us);
    bool ok = measured_us <= b.effective_us;
    printf("  %s: measured=%lluus nominal=%lluus effective=%lluus "
           "factor=%.2fx -> %s\n", label,
           (unsigned long long)measured_us, (unsigned long long)nominal_us,
           (unsigned long long)b.effective_us, b.factor,
           ok ? "PASS" : "FAIL");
    if (!ok)
        (*failures)++;
    return ok;
}

bool st_check_floor_per_s(const char *label, double measured_per_s,
                                 double nominal_per_s, int *failures)
{
    struct test_budget b = test_budget_scale(1);
    double effective = nominal_per_s / b.factor;
    bool ok = measured_per_s >= effective;
    printf("  %s: measured=%.1f/s nominal=%.1f/s effective=%.1f/s "
           "factor=%.2fx -> %s\n", label, measured_per_s, nominal_per_s,
           effective, b.factor, ok ? "PASS" : "FAIL");
    if (!ok)
        (*failures)++;
    return ok;
}

/* S1: header wire round-trip. Returns headers/s. */
double st_stage_header_roundtrip(int *failures)
{
    const uint64_t iters = 20000u;
    struct block_header h2;
    int64_t t0 = platform_time_monotonic_us();
    for (uint64_t k = 0; k < iters; k++) {
        const struct byte_stream *w = &g_wire[k % ST_FIXTURE_BLOCKS];
        struct byte_stream r;
        stream_init_from_data(&r, w->data, w->size);
        block_header_init(&h2);
        if (!block_header_deserialize(&h2, &r)) {
            printf("  S1 header round-trip deserialize... FAIL\n");
            (*failures)++;
            return 0.0;
        }
        if (h2.nVersion != 4 ||
            h2.nTime != ST_FIXED_TIME + (uint32_t)(k % ST_FIXTURE_BLOCKS) * 150u) {
            printf("  S1 header round-trip field match... FAIL\n");
            (*failures)++;
            return 0.0;
        }
    }
    uint64_t elapsed = (uint64_t)(platform_time_monotonic_us() - t0);
    double rate = st_per_s(iters, elapsed);
    printf("  S1 header wire round-trip: %llu headers in %lluus = %.1f headers/s\n",
           (unsigned long long)iters, (unsigned long long)elapsed, rate);
    /* Declared budget: reference box parses >= 60k headers/s. */
    st_check_floor_per_s("S1 headers/s floor", rate, 60000.0, failures);
    return rate;
}

/* S2: Equihash PoW verify on the baked real witness. Returns us/verify. */
double st_stage_pow_verify(int *failures)
{
    struct block_header h;
    verify_bench_fill_eh_header(&h);

    /* Teeth on the exact timed input: valid accepts, 1-bit flip rejects. */
    ST_CHECK("S2 timed witness verifies true",
             check_equihash_solution(&h, NULL));
    {
        struct block_header bad = h;
        bad.nSolution[600] ^= 0x01;
        ST_CHECK("S2 one-bit-flipped witness verifies false",
                 !check_equihash_solution(&bad, NULL));
    }

    const int iters = 4;
    int64_t t0 = platform_time_monotonic_us();
    for (int k = 0; k < iters; k++) {
        if (!check_equihash_solution(&h, NULL)) {
            printf("  S2 PoW verify stayed true... FAIL\n");
            (*failures)++;
            return 0.0;
        }
    }
    uint64_t elapsed = (uint64_t)(platform_time_monotonic_us() - t0);
    double us_each = (double)elapsed / (double)iters;
    printf("  S2 Equihash verify: %d verifies in %lluus = %.1f us/verify\n",
           iters, (unsigned long long)elapsed, us_each);
    /* Declared budget: reference box verifies (200,9) in <= 60ms. */
    st_check_ceiling_us("S2 us/verify ceiling",
                        (uint64_t)(us_each + 0.5), 60000u, failures);
    return us_each;
}

/* S3: merkle roots at 1/2/8/64-tx widths. Returns roots/s at width 8. */
double st_stage_merkle(int *failures)
{
    static const size_t widths[] = { 1, 2, 8, 64 };
    struct uint256 txids[64];
    double rate_w8 = 0.0;
    for (size_t wi = 0; wi < sizeof(widths) / sizeof(widths[0]); wi++) {
        size_t w = widths[wi];
        st_fill_txids(txids, w, (uint32_t)wi);
        /* Golden tooth: width-1 root is the single txid (Bitcoin rule). */
        struct uint256 root_once = compute_merkle_root(txids, w);
        if (w == 1 && memcmp(root_once.data, txids[0].data, 32) != 0) {
            printf("  S3 merkle width-1 identity... FAIL\n");
            (*failures)++;
            return 0.0;
        }
        /* Determinism tooth: same input twice gives the same root. */
        struct uint256 root_twice = compute_merkle_root(txids, w);
        if (memcmp(root_once.data, root_twice.data, 32) != 0) {
            printf("  S3 merkle determinism w=%zu... FAIL\n", w);
            (*failures)++;
            return 0.0;
        }
        const uint64_t iters = 20000u;
        int64_t t0 = platform_time_monotonic_us();
        for (uint64_t k = 0; k < iters; k++)
            (void)compute_merkle_root(txids, w);
        uint64_t elapsed = (uint64_t)(platform_time_monotonic_us() - t0);
        double rate = st_per_s(iters, elapsed);
        printf("  S3 merkle w=%2zu: %llu roots in %lluus = %.1f roots/s\n",
               w, (unsigned long long)iters,
               (unsigned long long)elapsed, rate);
        if (w == 8)
            rate_w8 = rate;
    }
    /* Declared budget: reference box computes >= 25k width-8 roots/s. */
    st_check_floor_per_s("S3 width-8 roots/s floor", rate_w8,
                         25000.0, failures);
    return rate_w8;
}

/* S4: structural check_block (PoW excluded — S2 owns that leg).
 * Returns us/block. */
double st_stage_check_block(int *failures)
{
    const struct chain_params *p = chain_params_get();
    if (!p) {
        printf("  S4 chain params... FAIL\n");
        (*failures)++;
        return 0.0;
    }
    /* Teeth: every fixture block passes; version-1 fails version-too-low;
     * wrong merkle root fails bad-txnmrklroot. */
    for (uint32_t i = 0; i < ST_FIXTURE_BLOCKS; i++) {
        struct validation_state state;
        validation_state_init(&state);
        if (!check_block(&g_blocks[i], &state, p, false, true, true)) {
            printf("  S4 fixture block %u passes... FAIL (%s)\n",
                   i, state.reject_reason);
            (*failures)++;
            return 0.0;
        }
    }
    {
        struct validation_state state;
        validation_state_init(&state);
        struct block bad = g_blocks[0];
        bad.header.nVersion = 1;
        struct block tmp;
        block_init(&tmp);
        tmp.header = bad.header;
        tmp.num_vtx = 0;
        tmp.vtx = NULL;
        /* version gate fires before tx checks, so an empty vtx is fine. */
        bool ok = check_block(&tmp, &state, p, false, true, false);
        ST_CHECK("S4 version-1 header rejected as version-too-low",
                 !ok && strcmp(state.reject_reason, "version-too-low") == 0);
    }
    {
        struct validation_state state;
        validation_state_init(&state);
        struct block badv;
        block_init(&badv);
        badv.header = g_blocks[1].header;
        memset(badv.header.hashMerkleRoot.data, 0xab, 32);
        badv.num_vtx = g_blocks[1].num_vtx;
        badv.vtx = g_blocks[1].vtx; /* borrow; check_block does not free */
        bool ok = check_block(&badv, &state, p, false, true, false);
        ST_CHECK("S4 wrong merkle root rejected as bad-txnmrklroot",
                 !ok && strcmp(state.reject_reason, "bad-txnmrklroot") == 0);
    }

    const uint64_t iters = 400u;
    int64_t t0 = platform_time_monotonic_us();
    for (uint64_t k = 0; k < iters; k++) {
        struct validation_state state;
        validation_state_init(&state);
        if (!check_block(&g_blocks[k % ST_FIXTURE_BLOCKS],
                         &state, p, false, true, true)) {
            printf("  S4 check_block stayed true... FAIL\n");
            (*failures)++;
            return 0.0;
        }
    }
    uint64_t elapsed = (uint64_t)(platform_time_monotonic_us() - t0);
    double us_each = (double)elapsed / (double)iters;
    double bodies = st_per_s(iters, elapsed);
    printf("  S4 check_block: %llu blocks in %lluus = %.1f us/block = %.1f bodies/s\n",
           (unsigned long long)iters, (unsigned long long)elapsed,
           us_each, bodies);
    /* Declared budget: reference box checks a 1-tx block in <= 2ms. */
    st_check_ceiling_us("S4 us/block ceiling",
                        (uint64_t)(us_each + 0.5), 2000u, failures);
    return us_each;
}

/* S5: header-range planning over a deterministic anchor set. */
/* S5 golden tooth: exact spans for a small pinned case. Split out of
 * st_stage_range_plan to keep each stage helper under the complexity cap. */
static void st_stage_range_plan_golden(int *failures)
{
    int32_t anchors[] = { 30, 30, 70, 150, -5 };
    struct hrs_span out[8];
    size_t n = hrs_partition(0, 100, anchors, 5, out, 8);
    ST_CHECK("S5 golden partition yields 3 spans",
             n == 3 && out[0].lo == 0 && out[0].hi == 30 &&
             out[1].lo == 30 && out[1].hi == 70 &&
             out[2].lo == 70 && out[2].hi == 100);
}

/* True iff spans[0..n) are a contiguous, disjoint, in-bounds partition:
 * each span non-empty and within [0, bound], and each span's hi equals
 * the next span's lo. Shared by both S5b legs below so neither pays the
 * loop's branches twice. */
static bool st_spans_contiguous(const struct hrs_span *spans, size_t n,
                                int32_t bound)
{
    for (size_t i = 0; i < n; i++) {
        if (spans[i].lo >= spans[i].hi || spans[i].lo < 0 ||
            spans[i].hi > bound)
            return false;
        if (i + 1 < n && spans[i].hi != spans[i + 1].lo)
            return false;
    }
    return true;
}

/* S5b nasty leg: descending, dense, duplicate and out-of-range anchors
 * must still yield a bounded, contiguous partition of [0, 1000]. Split
 * out of st_stage_range_plan_shape to keep each helper under the
 * complexity cap. */
static void st_stage_range_plan_shape_nasty(int *failures)
{
    int32_t nasty[312];
    for (int i = 0; i < 300; i++)
        nasty[i] = (int32_t)(990 - i * 3);      /* descending, dense */
    for (int i = 300; i < 306; i++)
        nasty[i] = 500;                          /* duplicates */
    nasty[306] = -1000; nasty[307] = 0; nasty[308] = 1000;
    nasty[309] = 1000000; nasty[310] = 500; nasty[311] = 999;
    struct hrs_span sod[140];
    size_t nn = hrs_partition(0, 1000, nasty, 312, sod, 140);
    bool cover = nn > 0 && sod[0].lo == 0 && sod[nn - 1].hi == 1000;
    ST_CHECK("S5b adversarial anchors still partition [0,1000]",
             cover && st_spans_contiguous(sod, nn, 1000) && nn <= 129);
}

/* S5b overflow leg: 5000 in-range anchors must still yield a bounded,
 * contiguous partition starting at lo and ending at hi. Split out of
 * st_stage_range_plan_shape to keep each helper under the complexity
 * cap. */
static void st_stage_range_plan_shape_overflow(int *failures)
{
    const size_t big_n = 5000u;
    int32_t *big = zcl_malloc(big_n * sizeof(*big),
                               "sync_throughput big anchors");
    if (!big) {
        printf("  S5b big anchor alloc... FAIL\n");
        (*failures)++;
        return;
    }
    for (size_t i = 0; i < big_n; i++)
        big[i] = (int32_t)((i * 7919u) % 99999u + 1);
    struct hrs_span bod[HRS_MAX_SPANS];
    size_t bn = hrs_partition(0, 100000, big, big_n, bod, HRS_MAX_SPANS);
    bool bcover = bn > 0 && bn <= HRS_MAX_SPANS &&
        bod[0].lo == 0 && bod[bn - 1].hi == 100000;
    ST_CHECK("S5b 5000-anchor overflow stays a bounded partition",
             bcover && st_spans_contiguous(bod, bn, 100000));
    free(big);
}

/* S5b: partition SHAPE properties on adversarial inputs (descending
 * anchors, heavy duplicates, out-of-range entries, and an overflow past
 * span-table capacity). Every output must be a contiguous, disjoint
 * partition of exactly [lo, hi] — the property both the old insertion
 * sort and the new sort-merge satisfy, so this pins the optimisation's
 * behaviour without pinning its algorithm. Each leg lives in its own
 * helper (see above) so no single function carries the whole stage's
 * branch count. */
static void st_stage_range_plan_shape(int *failures)
{
    st_stage_range_plan_shape_nasty(failures);
    st_stage_range_plan_shape_overflow(failures);
}

/* S5 load + S5c worst-case legs: throughput of hrs_partition over a large
 * anchor set, ascending (production shape) and descending (adversarial
 * shape, every chunk merges). Split out of st_stage_range_plan to keep
 * each stage helper under the complexity cap. Returns us/plan for the
 * ascending leg. */
static double st_stage_range_plan_load(int *failures)
{
    const int32_t hi = 200000;
    const size_t n_anchors = 28572u;
    int32_t *anchors = zcl_malloc(n_anchors * sizeof(*anchors),
                                  "sync_throughput anchors");
    if (!anchors) {
        printf("  S5 anchor alloc... FAIL\n");
        (*failures)++;
        return 0.0;
    }
    for (size_t i = 0; i < n_anchors; i++)
        anchors[i] = (int32_t)(i * 7);
    struct hrs_span *out = zcl_malloc(160 * sizeof(*out),
                                      "sync_throughput spans");
    if (!out) {
        free(anchors);
        printf("  S5 span alloc... FAIL\n");
        (*failures)++;
        return 0.0;
    }
    const uint64_t iters = 20u;
    int64_t t0 = platform_time_monotonic_us();
    size_t total_spans = 0;
    for (uint64_t k = 0; k < iters; k++)
        total_spans += hrs_partition(0, hi, anchors, n_anchors, out, 128);
    uint64_t elapsed = (uint64_t)(platform_time_monotonic_us() - t0);
    double us_each = (double)elapsed / (double)iters;
    printf("  S5 hrs_partition: %llu plans (%zu anchors) in %lluus = %.1f us/plan (%zu spans)\n",
           (unsigned long long)iters, n_anchors,
           (unsigned long long)elapsed, us_each, total_spans / iters);
    free(anchors);
    free(out);
    /* Worst-case leg: the same anchors descending. Bounds the adversarial
     * shape (every chunk merges) as distinct from the ascending
     * production shape above. */
    {
        int32_t *desc = zcl_malloc(n_anchors * sizeof(*desc),
                                   "sync_throughput desc anchors");
        struct hrs_span *dout = zcl_malloc(160 * sizeof(*dout),
                                           "sync_throughput desc spans");
        if (desc && dout) {
            for (size_t i = 0; i < n_anchors; i++)
                desc[i] = (int32_t)((n_anchors - 1 - i) * 7);
            const uint64_t diters = 20u;
            int64_t dt0 = platform_time_monotonic_us();
            size_t dtotal = 0;
            for (uint64_t k = 0; k < diters; k++)
                dtotal += hrs_partition(0, hi, desc, n_anchors, dout, 128);
            uint64_t delapsed =
                (uint64_t)(platform_time_monotonic_us() - dt0);
            double dus_each = (double)delapsed / (double)diters;
            printf("  S5c hrs_partition descending: %llu plans in %lluus = %.1f us/plan (%zu spans)\n",
                   (unsigned long long)diters,
                   (unsigned long long)delapsed, dus_each, dtotal / diters);
            st_check_ceiling_us("S5c descending us/plan ceiling",
                                (uint64_t)(dus_each + 0.5),
                                250000u, failures);
        } else {
            printf("  S5c desc alloc... FAIL\n");
            (*failures)++;
        }
        free(desc);
        free(dout);
    }
    /* Declared budget: reference box plans 28k anchors in <= 250ms. */
    st_check_ceiling_us("S5 us/plan ceiling",
                        (uint64_t)(us_each + 0.5), 250000u, failures);
    return us_each;
}

/* S5 header-range planning over a deterministic anchor set: golden shape,
 * throughput (ascending + descending), then adversarial shape properties.
 * Each leg lives in its own helper (see above) so no single function
 * carries the whole stage's branch count. Returns us/plan (ascending). */
double st_stage_range_plan(int *failures)
{
    st_stage_range_plan_golden(failures);
    double us_each = st_stage_range_plan_load(failures);
    st_stage_range_plan_shape(failures);
    return us_each;
}

