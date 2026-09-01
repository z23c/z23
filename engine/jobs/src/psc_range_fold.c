/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * psc_range_fold — Parallel State Compiler orchestrator. See
 * jobs/psc_range_fold.h + jobs/psc_internal.h.
 *
 * Ties the two phases together: (a) K extraction workers, each owning a
 * disjoint CONTIGUOUS height sub-range of [lo,hi], read blocks via the provider
 * and emit their transparent CREATE/SPEND event stream; (b) the sharded
 * sort-merge join (psc_join.c) reconstructs the terminal coin set; then the
 * terminal set is hashed with the SAME canonical (txid,vout) SHA3 encoder
 * coins_kv_commitment / coins_ram_commitment use — so the digest is directly
 * comparable to the serial fold's coins_kv commitment (the merge bar).
 *
 * The worker pool is a bounded, spawn-and-join parallel-for over the exact
 * thread_registry_spawn seam pv_lookahead.c / validate_work_pool.c use; the
 * threads are joined before psc_compile_range returns, so they are marked
 * thread-supervision-ok (bounded/joined), not registered on the liveness tree.
 * P0 keeps the intermediate event set + join in RAM (no spill); the design's
 * external sort-merge (spill runs, largest-L3 pinning) is a later lane.
 */
#include "jobs/psc_range_fold.h"
#include "jobs/psc_internal.h"

#include "coins/utxo_commitment.h"
#include "crypto/sha3.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "util/cpu_topology.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PSC_MAX_WORKERS 64

/* ── bounded spawn-and-join parallel-for ───────────────────────────────── */

struct pf_shared {
    _Atomic int   next;
    int           n_items;
    void        (*fn)(int item, void *ctx);
    void         *ctx;
};

static void *pf_worker(void *arg)
{
    struct pf_shared *sh = arg;
    for (;;) {
        int item = atomic_fetch_add(&sh->next, 1);
        if (item >= sh->n_items) break;
        sh->fn(item, sh->ctx);
    }
    thread_registry_unregister_self();
    return NULL;
}

/* Run fn(0..n_items-1) across up to n_workers threads (work-stealing via an
 * atomic counter), joining all before return. n_workers<=1 or n_items<=1 runs
 * inline on the calling thread. Matches psc_parallel_for_fn. */
static void psc_parallel_for(int n_items, int n_workers,
                             void (*fn)(int item, void *ctx), void *ctx)
{
    if (n_items <= 0) return;
    if (n_workers > PSC_MAX_WORKERS) n_workers = PSC_MAX_WORKERS;
    if (n_workers > n_items) n_workers = n_items;
    if (n_workers <= 1) {
        for (int i = 0; i < n_items; i++) fn(i, ctx);
        return;
    }

    struct pf_shared sh = { .n_items = n_items, .fn = fn, .ctx = ctx };
    atomic_store(&sh.next, 0);
    pthread_t tids[PSC_MAX_WORKERS];
    bool started[PSC_MAX_WORKERS] = {0};
    int spawned = 0;
    for (int i = 0; i < n_workers; i++) {
        char name[32];
        snprintf(name, sizeof(name), "psc.worker.%d", i);
        // thread-supervision-ok:bounded-worker-pool joined below in psc_parallel_for; runs a bounded finalized-range fold partition, no idle loop
        int rc = thread_registry_spawn(name, pf_worker, &sh, &tids[i]);
        if (rc != 0) {
            LOG_WARN("psc", "[psc] worker %d spawn failed rc=%d — folding the "
                     "remainder inline", i, rc);
            break;
        }
        started[i] = true;
        spawned++;
    }
    /* If some spawns failed, the calling thread also drains work items so no
     * item is dropped (pf_worker's atomic counter is shared). */
    if (spawned < n_workers) {
        for (;;) {
            int item = atomic_fetch_add(&sh.next, 1);
            if (item >= sh.n_items) break;
            sh.fn(item, sh.ctx);
        }
    }
    for (int i = 0; i < n_workers; i++)
        if (started[i]) pthread_join(tids[i], NULL);
}

/* ── extraction phase ──────────────────────────────────────────────────── */

struct extract_ctx {
    uint32_t              lo, hi;
    int                   k;         /* number of sub-ranges */
    psc_block_provider_fn provider;
    void                 *provider_user;
    struct psc_events    *events;    /* [k] — one stream per sub-range */
    char                (*reject)[48];  /* [k] */
    _Atomic bool          failed;
};

static void extract_subrange(int i, void *vctx)
{
    struct extract_ctx *ctx = vctx;
    uint64_t total = (uint64_t)ctx->hi - ctx->lo + 1;
    uint64_t chunk = (total + (uint64_t)ctx->k - 1) / (uint64_t)ctx->k;
    uint64_t start = ctx->lo + (uint64_t)i * chunk;
    if (start > ctx->hi) return;
    uint64_t end = start + chunk - 1;
    if (end > ctx->hi) end = ctx->hi;

    for (uint64_t h = start; h <= end; h++) {
        if (atomic_load(&ctx->failed)) return;
        struct block blk;
        block_init(&blk);
        if (!ctx->provider((uint32_t)h, &blk, ctx->provider_user)) {
            block_free(&blk);
            snprintf(ctx->reject[i], 48, "provider_failed");
            atomic_store(&ctx->failed, true);
            LOG_WARN("psc", "[psc] provider failed at height=%llu",
                     (unsigned long long)h);
            return;
        }
        char rej[48] = {0};
        bool ok = psc_extract_block(&blk, (uint32_t)h, &ctx->events[i], rej);
        block_free(&blk);
        if (!ok) {
            snprintf(ctx->reject[i], 48, "%s", rej[0] ? rej : "internal");
            atomic_store(&ctx->failed, true);
            return;
        }
    }
}

/* Gather K per-worker event streams into one global event array + one global
 * script pool (rebasing each stream's script offsets). Returns false on OOM. */
static bool psc_gather(struct psc_events *streams, int k,
                       struct psc_event **out_ev, size_t *out_n,
                       uint8_t **out_scripts)
{
    size_t total_ev = 0, total_scr = 0;
    for (int i = 0; i < k; i++) {
        total_ev += streams[i].n;
        total_scr += streams[i].scr_used;
    }
    struct psc_event *ev = total_ev
        ? zcl_malloc(total_ev * sizeof(*ev), "psc_gather_ev") : NULL;
    uint8_t *scr = total_scr
        ? zcl_malloc(total_scr, "psc_gather_scr") : NULL;
    if ((total_ev && !ev) || (total_scr && !scr)) {
        free(ev); free(scr);
        LOG_WARN("psc", "[psc] gather OOM (ev=%zu scr=%zu)", total_ev, total_scr);
        return false;
    }
    size_t we = 0, ws = 0;
    for (int i = 0; i < k; i++) {
        size_t base = ws;
        if (streams[i].scr_used) {
            memcpy(scr + ws, streams[i].scripts, streams[i].scr_used);
            ws += streams[i].scr_used;
        }
        for (size_t j = 0; j < streams[i].n; j++) {
            struct psc_event e = streams[i].ev[j];
            if (e.kind == PSC_CREATE && e.script_len)
                e.script_off = (uint32_t)(base + e.script_off);
            ev[we++] = e;
        }
    }
    *out_ev = ev;
    *out_n = total_ev;
    *out_scripts = scr;
    return true;
}

/* ── terminal digest ───────────────────────────────────────────────────── */

static int psc_coin_cmp(const void *a, const void *b)
{
    const struct psc_coin *x = a, *y = b;
    int c = memcmp(x->txid, y->txid, 32);
    if (c) return c;
    return x->vout < y->vout ? -1 : x->vout > y->vout ? 1 : 0;
}

static void psc_digest(struct psc_coin *coins, size_t n,
                       uint8_t out_sha3[32], int64_t *out_supply)
{
    qsort(coins, n, sizeof(*coins), psc_coin_cmp);
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    int64_t supply = 0;
    for (size_t i = 0; i < n; i++) {
        const struct psc_coin *c = &coins[i];
        utxo_commitment_sha3_write_record(&ctx, c->txid, c->vout, c->value,
                                          c->script_len ? c->script : NULL,
                                          c->script_len, (uint32_t)c->height,
                                          c->is_coinbase);
        supply += c->value;
    }
    sha3_256_finalize(&ctx, out_sha3);
    *out_supply = supply;
}

/* ── public entry ──────────────────────────────────────────────────────── */

bool psc_compile_range(uint32_t lo, uint32_t hi, int k_workers, int s_shards,
                       psc_block_provider_fn provider, void *provider_user,
                       struct psc_range_result *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->reject_height = -1;
    if (!provider) {
        snprintf(out->reject_kind, sizeof(out->reject_kind), "no_provider");
        return false;
    }
    if (hi < lo) {
        snprintf(out->reject_kind, sizeof(out->reject_kind), "empty_range");
        return false;
    }
    if (k_workers <= 0) {
        k_workers = cpu_topology_physical_cores();
        if (k_workers < 1) k_workers = 1;
    }
    if (k_workers > PSC_MAX_WORKERS) k_workers = PSC_MAX_WORKERS;
    if (s_shards <= 0) s_shards = k_workers * 2;
    if (s_shards < 1) s_shards = 1;
    out->k_workers = k_workers;
    out->s_shards = s_shards;

    int64_t t0 = platform_time_monotonic_us();

    /* Phase (a): parallel extraction over K contiguous sub-ranges. */
    struct psc_events *streams =
        zcl_calloc((size_t)k_workers, sizeof(*streams), "psc_streams");
    char (*rejects)[48] = zcl_calloc((size_t)k_workers, sizeof(*rejects),
                                     "psc_rejects");
    if (!streams || !rejects) {
        free(streams); free(rejects);
        snprintf(out->reject_kind, sizeof(out->reject_kind), "internal");
        return false;
    }
    for (int i = 0; i < k_workers; i++) psc_events_init(&streams[i]);

    struct extract_ctx ectx = {
        .lo = lo, .hi = hi, .k = k_workers, .provider = provider,
        .provider_user = provider_user, .events = streams, .reject = rejects,
    };
    atomic_store(&ectx.failed, false);
    psc_parallel_for(k_workers, k_workers, extract_subrange, &ectx);
    int64_t t1 = platform_time_monotonic_us();
    out->extract_us = (double)(t1 - t0);

    if (atomic_load(&ectx.failed)) {
        for (int i = 0; i < k_workers; i++) {
            if (rejects[i][0]) {
                snprintf(out->reject_kind, sizeof(out->reject_kind), "%s",
                         rejects[i]);
                break;
            }
        }
        if (!out->reject_kind[0])
            snprintf(out->reject_kind, sizeof(out->reject_kind), "internal");
        for (int i = 0; i < k_workers; i++) psc_events_free(&streams[i]);
        free(streams); free(rejects);
        return false;
    }

    /* Gather K streams into one global event array + script pool. */
    struct psc_event *ev = NULL;
    uint8_t *scripts = NULL;
    size_t nev = 0;
    bool gathered = psc_gather(streams, k_workers, &ev, &nev, &scripts);
    for (int i = 0; i < k_workers; i++) psc_events_free(&streams[i]);
    free(streams); free(rejects);
    if (!gathered) {
        free(ev); free(scripts);
        snprintf(out->reject_kind, sizeof(out->reject_kind), "internal");
        return false;
    }
    out->events_total = nev;

    /* Phase (b): sharded sort-merge join. */
    int64_t t2 = platform_time_monotonic_us();
    struct psc_coin *coins = NULL;
    size_t ncoins = 0;
    char reject[48] = {0};
    int32_t reject_height = -1;
    bool joined = psc_join(ev, nev, scripts, s_shards, k_workers,
                           psc_parallel_for, &coins, &ncoins, reject,
                           &reject_height);
    int64_t t3 = platform_time_monotonic_us();
    out->join_us = (double)(t3 - t2);

    if (!joined) {
        bool is_reject = strcmp(reject, "spend_unknown_utxo") == 0 ||
                         strcmp(reject, "utxo_collision") == 0;
        snprintf(out->reject_kind, sizeof(out->reject_kind), "%s",
                 reject[0] ? reject : "internal");
        out->reject_height = reject_height;
        out->ok = false;
        free(coins); free(ev); free(scripts);
        out->total_us = (double)(platform_time_monotonic_us() - t0);
        /* A typed ordering reject is a definite verdict (return true); a hard
         * internal error is a failure (return false). */
        return is_reject;
    }

    /* Phase (c): terminal digest (canonical (txid,vout) SHA3). */
    int64_t t4 = platform_time_monotonic_us();
    int64_t supply = 0;
    psc_digest(coins, ncoins, out->terminal_sha3, &supply);
    out->terminal_count = ncoins;
    out->terminal_supply = supply;
    out->ok = true;
    out->digest_us = (double)(platform_time_monotonic_us() - t4);

    free(coins); free(ev); free(scripts);
    out->total_us = (double)(platform_time_monotonic_us() - t0);
    return true;
}
