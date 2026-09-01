/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet_perf — runs a fixed, deterministic block/UTXO workload through the
 * REAL connect_block fold at several sizes and reports per-stage CPU cost, so
 * an algorithmic-complexity regression on the block-connect path can be caught
 * in CI. The contract, the scope limits, and why the gated metric is a growth
 * RATIO rather than a nanosecond budget are all in sim/simnet_perf.h.
 */

#include "sim/simnet_perf.h"

#include "sim/simnet.h"
#include "coins/coins_fault.h"
#include "coins/coins_view.h"
#include "consensus/consensus.h"      /* COINBASE_MATURITY */
#include "platform/clock.h"           /* clock_thread_cpu_ns */
#include "primitives/transaction.h"
#include "script/script.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

/* Fee left on each measured spend. Any positive value works; 1 keeps the
 * block's fee sum negligible so the coinbase reward check is never near a
 * boundary. */
#define PERF_SPEND_FEE 1

/* Upper bound on a single point's untimed setup, so a fat
 * --blocks/--txs-per-block/--funding-multiple on the command line cannot ask
 * for a run that never finishes. The default ladder's largest point mints
 * 12,288 setup blocks (768 * 8 * 2); this leaves ample room. */
#define PERF_MAX_FUNDING_BLOCKS 200000

/* Sample buffer bound (the minimum is taken over these). */
#define PERF_MAX_REPS 64

/* Upper bound on `funding_multiple`. The armed arm's untimed funding phase is
 * O(n^2) in the map size, so this keeps a command-line value from turning setup
 * into the whole run. */
#define PERF_MAX_FUNDING_MULTIPLE 16

/* ── One measured sample ─────────────────────────────────────────────── */

struct perf_sample {
    int64_t build_cpu_ns;
    int64_t fold_cpu_ns;
    uint64_t measured_txs;
    uint64_t coins_at_end;
    int tip_height;
};

/* Transparent spend of `in_txid`:0 paying `out_value` to a placeholder
 * P2PKH-shaped script. Same shape as the manual spend builders in
 * test_simnet_doublespend.c / test_simnet_chained_tx.c: simnet mints under a
 * covering checkpoint, so connect_block runs with expensive_checks=false and
 * scriptSig content is never verified — only the outpoint linkage and coin
 * availability matter. `marker` varies the scriptSig so every spend in a block
 * gets a distinct txid while staying a pure function of its inputs (identical
 * arguments always produce an identical tx, which is what keeps the whole
 * workload deterministic). */
static bool perf_make_spend(struct transaction *tx,
                            const struct uint256 *in_txid,
                            int64_t out_value, uint8_t marker)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1))
        LOG_FAIL("simnet_perf", "OOM allocating spend tx");
    tx->version = 1;
    tx->vin[0].prevout.hash = *in_txid;
    tx->vin[0].prevout.n = 0;
    uint8_t sig[2] = { 0x00, marker };
    script_set(&tx->vin[0].script_sig, sig, sizeof(sig));
    tx->vin[0].sequence = 0xFFFFFFFF;
    tx->vout[0].value = out_value;
    uint8_t pk[3] = { 0x76, 0xa9, 0x14 };
    script_set(&tx->vout[0].script_pub_key, pk, sizeof(pk));
    transaction_compute_hash(tx);
    return true;
}

/* Run ONE sample of the workload at `blocks` measured blocks.
 *
 * Four phases:
 *   1a. BALLAST (untimed) — `funding_multiple - 1` coinbase-only blocks per
 *      spendable one, txids discarded. Never spent, never looked up. They sit
 *      in the UTXO map AHEAD of the coins the measured phase will spend, which
 *      is the whole point: see `funding_multiple` in sim/simnet_perf.h. Both
 *      the ballast and the funding scale with the ladder point, so the growth
 *      ratio's meaning is unchanged.
 *   1b. FUNDING (untimed) — mint `blocks * txs_per_block` coinbase-only blocks
 *      and keep every coinbase txid. These are the coins the measured phase
 *      spends.
 *   2. MATURITY FILLER (untimed) — COINBASE_MATURITY more coinbase-only blocks
 *      so the OLDEST funded coinbase is spendable by the real maturity
 *      predicate. Because the measured phase consumes funded coinbases in mint
 *      order from the FRONT, the tightest case is the last measured block
 *      spending the newest funded coinbase, which clears maturity by
 *      COINBASE_MATURITY + blocks.
 *   3. MEASURED — `blocks` blocks, each carrying its own coinbase plus
 *      `txs_per_block` transparent spends of distinct funded coinbases. CPU
 *      time is attributed to `build` (this file assembling the txs) and `fold`
 *      (merkle root + the REAL connect_block, i.e. the coins-view work).
 *
 * Only phase 3 is timed; phases 1a-2 are setup that sizes the map. */
static bool perf_one_sample(const struct simnet_perf_config *cfg, int blocks,
                            struct perf_sample *out)
{
    const int per_block = cfg->txs_per_block;
    /* Coinbases the measured phase will actually spend. */
    const size_t spendable = (size_t)blocks * (size_t)per_block;
    /* Coinbases minted purely to sit in front of them in the map — see
     * `funding_multiple` in sim/simnet_perf.h. Their txids are never needed,
     * so they cost no memory here. */
    const size_t ballast = spendable * (size_t)(cfg->funding_multiple - 1);

    memset(out, 0, sizeof(*out));

    struct uint256 *funded =
        zcl_malloc(spendable * sizeof(*funded), "simnet_perf_funded");
    if (!funded)
        LOG_FAIL("simnet_perf", "OOM allocating %zu funded txids", spendable);

    struct transaction *block_txs =
        zcl_calloc((size_t)per_block, sizeof(*block_txs), "simnet_perf_txs");
    if (!block_txs) {
        free(funded);
        LOG_FAIL("simnet_perf", "OOM allocating %d tx slots", per_block);
    }

    struct simnet s;
    if (!simnet_init(&s)) {
        free(block_txs);
        free(funded);
        LOG_FAIL("simnet_perf", "simnet_init failed");
    }

    bool ok = true;

    if (cfg->inject == SIMNET_PERF_INJECT_COINS_HASH_COLLAPSE) {
        /* Armed on a freshly initialized (therefore empty) map, which is the
         * only safe moment — see coins/coins_fault.h's arming contract. */
        if (!coins_fault_arm_map_hash_collapse(&s.view.cache_coins, true)) {
            LOG_ERROR("simnet_perf", "could not arm the coins hash collapse");
            ok = false;
        }
    }

    /* Phase 1a: map ballast. Minted BEFORE the spendable funding, and the
     * order is load-bearing — coins_map (core/modules/coins/src/coins_view.c) is open
     * addressing with linear probing, so under the collapsed hash every key
     * probes from slot 0 and a coin's lookup cost is its POSITION in the
     * insertion run, not the map's size. Ballast minted first therefore sits
     * in front of every spendable coin and deepens all of them; ballast minted
     * last sits behind them and is never probed. Measured, scale 1: ballast
     * last moved the armed/clean ratio 4.4x -> 4.8x, ballast first moved it
     * 4.4x -> 6.3-8.4x. */
    for (size_t i = 0; ok && i < ballast; i++) {
        if (!simnet_mint_coinbase(&s, NULL)) {
            LOG_ERROR("simnet_perf", "ballast mint %zu rejected", i);
            ok = false;
        }
    }

    /* Phase 1b: spendable funding. */
    for (size_t i = 0; ok && i < spendable; i++) {
        if (!simnet_mint_coinbase(&s, &funded[i])) {
            LOG_ERROR("simnet_perf", "funding mint %zu rejected", i);
            ok = false;
        }
    }

    /* Phase 2: maturity filler. */
    for (int i = 0; ok && i < COINBASE_MATURITY; i++) {
        if (!simnet_mint_coinbase(&s, NULL)) {
            LOG_ERROR("simnet_perf", "maturity filler mint %d rejected", i);
            ok = false;
        }
    }

    /* Read the coinbase output value once, outside the timed region, so the
     * measured phase does no bookkeeping lookups of its own. Every synthetic
     * coinbase carries the same value. */
    int64_t cb_value = 0;
    if (ok && !simnet_coin_value(&s, &funded[0], 0, &cb_value)) {
        LOG_ERROR("simnet_perf", "funded coinbase 0 absent from the UTXO view");
        ok = false;
    }
    if (ok && cb_value <= PERF_SPEND_FEE) {
        LOG_ERROR("simnet_perf", "coinbase value %lld too small to spend",
                (long long)cb_value);
        ok = false;
    }

    /* Phase 3: the measured fold. */
    int64_t build_ns = 0;
    int64_t fold_ns = 0;
    uint64_t measured_txs = 0;
    for (int b = 0; ok && b < blocks; b++) {
        int64_t t0 = clock_thread_cpu_ns();
        for (int k = 0; k < per_block; k++) {
            if (!perf_make_spend(&block_txs[k],
                                 &funded[(size_t)b * (size_t)per_block + (size_t)k],
                                 cb_value - PERF_SPEND_FEE, (uint8_t)(k & 0xFF))) {
                ok = false;
                break;
            }
        }
        int64_t t1 = clock_thread_cpu_ns();
        if (!ok) {
            /* perf_make_spend already logged; free the partial block. */
            for (int k = 0; k < per_block; k++)
                transaction_free(&block_txs[k]);
            break;
        }
        /* Ownership of every tx's vin/vout transfers to simnet here (it
         * transaction_init()s our copies), so the buffer is clean next round
         * on both the accept and the reject path. */
        bool minted = simnet_mint_txs(&s, block_txs, (size_t)per_block);
        int64_t t2 = clock_thread_cpu_ns();

        build_ns += t1 - t0;
        fold_ns += t2 - t1;
        if (!minted) {
            LOG_ERROR("simnet_perf", "measured mint %d rejected", b);
            ok = false;
            break;
        }
        /* The block's own coinbase folds through connect_block too. */
        measured_txs += (uint64_t)per_block + 1u;
    }

    if (ok) {
        out->build_cpu_ns = build_ns;
        out->fold_cpu_ns = fold_ns;
        out->measured_txs = measured_txs;
        out->coins_at_end = (uint64_t)coins_map_count(&s.view.cache_coins);
        out->tip_height = simnet_tip_height(&s);
        if (out->fold_cpu_ns <= 0 || out->measured_txs == 0) {
            LOG_ERROR("simnet_perf",
                    "refusing a vacuous sample (fold_ns=%lld txs=%llu)",
                    (long long)out->fold_cpu_ns,
                    (unsigned long long)out->measured_txs);
            ok = false;
        }
    }

    simnet_free(&s);
    free(block_txs);
    free(funded);
    return ok;
}

/* ── Estimator ───────────────────────────────────────────────────────── */

/* Minimum of `n` samples (n >= 1) — NOT the mean, and no longer the median.
 *
 * Why the minimum. Timing noise on this box is ONE-SIDED: contention, cache
 * eviction by a co-resident worker, SMT sibling pressure and page faults can
 * only ever ADD time to a sample, never remove it. (Using
 * clock_thread_cpu_ns() removes plain scheduler preemption from the count, but
 * not memory-bandwidth or cache/SMT interference, which inflate CPU time too.)
 * Under a one-sided error model the minimum is the maximum-likelihood estimate
 * of the uncontaminated cost, and it is the only estimator whose error goes to
 * zero as reps grow; a median still reports whatever the middle sample's
 * contamination happened to be.
 *
 * This also makes the detector self-test STRICTLY harder to satisfy, which is
 * the point. test_simnet_perf asserts `armed >= 4.0 * clean` per ladder point.
 * Additive noise d on both arms drags the observed ratio (A+d)/(C+d) toward
 * 1.0, so a contaminated CLEAN sample is what breaks a true positive — and a
 * contaminated ARMED sample is what could manufacture a false one. The minimum
 * strips d from both arms: it cannot inflate the armed arm into passing, and it
 * cannot inflate the clean arm into failing. Measured: a solo run on a loaded
 * box put clean scale-1 at 9556 ns/tx against a 4795 ns/tx floor — a 2.0x
 * one-sided inflation on an 8 ms measurement window. */
static int64_t perf_min(const int64_t *v, size_t n)
{
    int64_t m = v[0];
    for (size_t i = 1; i < n; i++)
        if (v[i] < m)
            m = v[i];
    return m;
}

/* ── Public surface ──────────────────────────────────────────────────── */

void simnet_perf_config_defaults(struct simnet_perf_config *cfg)
{
    if (!cfg)
        return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->blocks = SIMNET_PERF_DEFAULT_BLOCKS;
    cfg->txs_per_block = SIMNET_PERF_DEFAULT_TXS_PER_BLOCK;
    cfg->scales[0] = 1;
    cfg->scales[1] = 2;
    cfg->scales[2] = 4;
    cfg->scale_count = 3;
    cfg->reps = SIMNET_PERF_DEFAULT_REPS;
    cfg->funding_multiple = SIMNET_PERF_DEFAULT_FUNDING_MULTIPLE;
    cfg->inject = SIMNET_PERF_INJECT_NONE;
}

bool simnet_perf_run(const struct simnet_perf_config *cfg,
                     struct simnet_perf_result *out)
{
    if (!cfg || !out)
        LOG_FAIL("simnet_perf", "NULL config or result");
    if (cfg->blocks < 1 || cfg->txs_per_block < 1)
        LOG_FAIL("simnet_perf", "blocks=%d txs_per_block=%d must both be >= 1",
                 cfg->blocks, cfg->txs_per_block);
    if (cfg->scale_count < 2 || cfg->scale_count > SIMNET_PERF_MAX_POINTS)
        LOG_FAIL("simnet_perf",
                 "scale_count=%zu must be 2..%d (a growth ratio needs two "
                 "workload sizes)", cfg->scale_count, SIMNET_PERF_MAX_POINTS);
    if (cfg->reps < 1 || cfg->reps > PERF_MAX_REPS)
        LOG_FAIL("simnet_perf", "reps=%d must be 1..%d", cfg->reps,
                 PERF_MAX_REPS);
    if (cfg->funding_multiple < 1 ||
        cfg->funding_multiple > PERF_MAX_FUNDING_MULTIPLE)
        LOG_FAIL("simnet_perf", "funding_multiple=%d must be 1..%d",
                 cfg->funding_multiple, PERF_MAX_FUNDING_MULTIPLE);
    for (size_t i = 0; i < cfg->scale_count; i++) {
        if (cfg->scales[i] < 1)
            LOG_FAIL("simnet_perf", "scales[%zu]=%d must be >= 1", i,
                     cfg->scales[i]);
        if (i > 0 && cfg->scales[i] <= cfg->scales[i - 1])
            LOG_FAIL("simnet_perf",
                     "scales must strictly increase (scales[%zu]=%d <= %d)",
                     i, cfg->scales[i], cfg->scales[i - 1]);
        int64_t funding = (int64_t)cfg->blocks * cfg->scales[i] *
                          cfg->txs_per_block * cfg->funding_multiple;
        if (funding > PERF_MAX_FUNDING_BLOCKS)
            LOG_FAIL("simnet_perf",
                     "scale %d needs %lld funding blocks, over the %d cap",
                     cfg->scales[i], (long long)funding,
                     PERF_MAX_FUNDING_BLOCKS);
    }

    memset(out, 0, sizeof(*out));
    out->reps = cfg->reps;
    out->inject = cfg->inject;

    int64_t build_samples[PERF_MAX_REPS];
    int64_t fold_samples[PERF_MAX_REPS];
    const int reps = cfg->reps;

    for (size_t p = 0; p < cfg->scale_count; p++) {
        const int blocks = cfg->blocks * cfg->scales[p];
        struct simnet_perf_point *pt = &out->points[p];
        pt->scale = cfg->scales[p];
        pt->blocks = blocks;
        pt->funding_blocks = (uint64_t)blocks * (uint64_t)cfg->txs_per_block *
                             (uint64_t)cfg->funding_multiple;

        /* One DISCARDED warm-up sample per point (r == -1), then `reps`
         * measured ones, of which perf_min() keeps the fastest. Without the
         * warm-up the first point of the ladder absorbs the process's page
         * faults, malloc arena growth, and cold icache, which inflates the
         * denominator of the growth ratio and would flatter every result.
         * (perf_min() would discard a cold sample anyway — a cold sample is
         * never the minimum — so the explicit warm-up is now belt-and-braces
         * rather than load-bearing; it is kept because `make sim-perf`'s
         * absolute growth budget was calibrated with it. Same discipline as
         * tools/simd_bench.c.) */
        for (int r = -1; r < reps; r++) {
            struct perf_sample sample;
            if (!perf_one_sample(cfg, blocks, &sample))
                LOG_FAIL("simnet_perf",
                         "workload failed at scale %d rep %d — a rejected mint "
                         "is a harness bug, never a perf result",
                         cfg->scales[p], r);
            if (r < 0)
                continue;
            build_samples[r] = sample.build_cpu_ns;
            fold_samples[r] = sample.fold_cpu_ns;
            pt->measured_txs = sample.measured_txs;
            pt->coins_at_end = sample.coins_at_end;
            pt->tip_height = sample.tip_height;
        }

        pt->build_cpu_ns = perf_min(build_samples, (size_t)reps);
        pt->fold_cpu_ns = perf_min(fold_samples, (size_t)reps);
        pt->total_cpu_ns = pt->build_cpu_ns + pt->fold_cpu_ns;
        pt->fold_ns_per_tx = pt->fold_cpu_ns / (int64_t)pt->measured_txs;
        pt->total_ns_per_block = pt->total_cpu_ns / (int64_t)blocks;
        out->point_count = p + 1;
    }

    const struct simnet_perf_point *first = &out->points[0];
    const struct simnet_perf_point *last = &out->points[out->point_count - 1];

    /* growth = 1000 * (cost_per_tx at last) / (cost_per_tx at first), done as
     * one integer expression so the two divisions never truncate first.
     * Operand magnitudes: ns <= ~1e10, txs <= ~1e7, so the product stays far
     * inside int64. */
    out->fold_growth_permille =
        (1000 * last->fold_cpu_ns * (int64_t)first->measured_txs) /
        (first->fold_cpu_ns * (int64_t)last->measured_txs);
    out->total_growth_permille =
        (1000 * last->total_cpu_ns * (int64_t)first->measured_txs) /
        (first->total_cpu_ns * (int64_t)last->measured_txs);

    out->scale_span = last->scale / first->scale;
    out->fold_ns_per_tx = last->fold_ns_per_tx;
    out->total_ns_per_block = last->total_ns_per_block;
    out->measured_txs = last->measured_txs;
    out->coins_at_end = last->coins_at_end;
    return true;
}

bool simnet_perf_metric(const struct simnet_perf_result *r, const char *name,
                        int64_t *out)
{
    if (!r || !name || !out)
        return false;
    if (strcmp(name, "fold_growth_permille") == 0) {
        *out = r->fold_growth_permille;
        return true;
    }
    if (strcmp(name, "total_growth_permille") == 0) {
        *out = r->total_growth_permille;
        return true;
    }
    if (strcmp(name, "fold_ns_per_tx") == 0) {
        *out = r->fold_ns_per_tx;
        return true;
    }
    if (strcmp(name, "total_ns_per_block") == 0) {
        *out = r->total_ns_per_block;
        return true;
    }
    if (strcmp(name, "measured_txs") == 0) {
        *out = (int64_t)r->measured_txs;
        return true;
    }
    if (strcmp(name, "coins_at_end") == 0) {
        *out = (int64_t)r->coins_at_end;
        return true;
    }
    if (strcmp(name, "scale_span") == 0) {
        *out = r->scale_span;
        return true;
    }
    if (strcmp(name, "points") == 0) {
        *out = (int64_t)r->point_count;
        return true;
    }
    if (strcmp(name, "reps") == 0) {
        *out = r->reps;
        return true;
    }
    return false;
}

int simnet_perf_expect(const struct simnet_perf_result *r, const char *name,
                       const char *op, int64_t expected, int64_t *out_actual)
{
    int64_t actual = 0;
    if (!r || !name || !op)
        return -3;
    if (!simnet_perf_metric(r, name, &actual))
        return -3;
    if (out_actual)
        *out_actual = actual;
    /* Same operator set as the chaos DSL's compare_metric (tools/sim/chaos.c). */
    if (strcmp(op, "==") == 0) return actual == expected ? 0 : -1;
    if (strcmp(op, "!=") == 0) return actual != expected ? 0 : -1;
    if (strcmp(op, ">=") == 0) return actual >= expected ? 0 : -1;
    if (strcmp(op, "<=") == 0) return actual <= expected ? 0 : -1;
    if (strcmp(op, ">") == 0)  return actual > expected ? 0 : -1;
    if (strcmp(op, "<") == 0)  return actual < expected ? 0 : -1;
    return -2;
}

void simnet_perf_print(const struct simnet_perf_result *r, FILE *out)
{
    if (!r || !out)
        return;
    fprintf(out,
            "  scale  blocks  fund_blk  txs   coins   build_us   fold_us  "
            "fold_ns/tx  total_ns/blk\n");
    for (size_t i = 0; i < r->point_count; i++) {
        const struct simnet_perf_point *p = &r->points[i];
        fprintf(out,
                "  %5d  %6d  %8llu  %4llu  %6llu  %9lld  %8lld  %10lld  %12lld\n",
                p->scale, p->blocks, (unsigned long long)p->funding_blocks,
                (unsigned long long)p->measured_txs,
                (unsigned long long)p->coins_at_end,
                (long long)(p->build_cpu_ns / 1000),
                (long long)(p->fold_cpu_ns / 1000),
                (long long)p->fold_ns_per_tx,
                (long long)p->total_ns_per_block);
    }
    fprintf(out,
            "  growth over a %dx workload span (1000 = flat, per-tx cost "
            "unchanged):\n"
            "    fold_growth_permille  = %lld\n"
            "    total_growth_permille = %lld\n",
            r->scale_span, (long long)r->fold_growth_permille,
            (long long)r->total_growth_permille);
    if (r->inject != SIMNET_PERF_INJECT_NONE)
        fprintf(out, "  INJECTED REGRESSION ARMED (inject=%d) — this run is a "
                     "detector self-test, not a measurement of the tree\n",
                (int)r->inject);
}
