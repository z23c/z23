/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * psc_join — Parallel State Compiler phase (b): the sharded outpoint
 * sort-merge join. See jobs/psc_internal.h.
 *
 * Every event routes to shard = hash(outpoint) mod S, so ALL events for one
 * outpoint land in the same shard. Per shard we sort by (outpoint, seq) and
 * replay each outpoint's event run: the valid history is a strict alternation
 * CREATE, SPEND, CREATE, SPEND … starting with a CREATE. A CREATE while
 * already LIVE is a duplicate outpoint / BIP30 reuse ("utxo_collision"); a
 * SPEND while ABSENT is a spend of an unknown/already-spent coin
 * ("spend_unknown_utxo"). An outpoint whose
 * TERMINAL event is a CREATE is a live coin; its fields come from that last
 * CREATE (value/height/is_coinbase/script) — the same coin the serial fold's
 * adds-before-spends walk would leave in coins_kv.
 *
 * This is coins_ram.c's build_effective_sorted + comm_cmp generalized from one
 * durable stream to K per-shard event streams. Shards are independent, so the
 * sort+validate+emit runs in parallel across the caller's worker pool.
 */
#include "jobs/psc_internal.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* FNV-1a over txid||vout — the SAME family coins_ram.c:key_hash uses. */
static uint64_t psc_key_hash(const uint8_t txid[32], uint32_t vout)
{
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < 32; i++) { h ^= txid[i]; h *= 1099511628211ULL; }
    for (int i = 0; i < 4; i++) {
        h ^= (uint8_t)(vout >> (8 * i)); h *= 1099511628211ULL;
    }
    return h;
}

/* Context-free sort record: (txid,vout,seq) key + the global event index. */
struct psc_sortrec {
    uint8_t  txid[32];
    uint32_t vout;
    uint64_t seq;
    uint32_t idx;   /* index into the global event array */
};

static int psc_sortrec_cmp(const void *a, const void *b)
{
    const struct psc_sortrec *x = a, *y = b;
    int c = memcmp(x->txid, y->txid, 32);
    if (c) return c;
    if (x->vout != y->vout) return x->vout < y->vout ? -1 : 1;
    if (x->seq  != y->seq)  return x->seq  < y->seq  ? -1 : 1;
    return 0;
}

struct psc_shard_out {
    struct psc_coin *coins;
    size_t           n;
    size_t           cap;
    bool             rejected;
    bool             error;      /* hard OOM / internal */
    char             reject[48];
    uint64_t         reject_seq; /* seq of the smallest offending event */
    int32_t          reject_height;
};

struct psc_join_ctx {
    const struct psc_event *ev;
    const uint8_t          *scripts;
    int                     s_shards;
    /* per-shard sort records (scattered from the global event array) */
    struct psc_sortrec    **buckets;   /* [s_shards] */
    size_t                 *bucket_n;  /* [s_shards] */
    struct psc_shard_out   *out;       /* [s_shards] */
};

static bool shard_emit(struct psc_shard_out *so, const struct psc_event *e)
{
    if (so->n == so->cap) {
        size_t ncap = so->cap ? so->cap * 2 : 256;
        struct psc_coin *nc = zcl_realloc(so->coins, ncap * sizeof(*nc),
                                          "psc_shard_coins");
        if (!nc) { LOG_WARN("psc", "[psc] OOM emitting shard coin"); return false; }
        so->coins = nc;
        so->cap = ncap;
    }
    struct psc_coin *c = &so->coins[so->n++];
    memcpy(c->txid, e->txid, 32);
    c->vout = e->vout;
    c->value = e->value;
    c->height = e->height;
    c->is_coinbase = e->is_coinbase;
    c->script_len = e->script_len;
    c->script = NULL;   /* bound to the shared pool by the caller via offset */
    return true;
}

static void shard_note_reject(struct psc_shard_out *so, const char *kind,
                              uint64_t seq, int32_t height)
{
    if (!so->rejected || seq < so->reject_seq) {
        so->rejected = true;
        so->reject_seq = seq;
        so->reject_height = height;
        snprintf(so->reject, sizeof(so->reject), "%s", kind);
    }
}

/* Process one shard: sort its records, replay each outpoint run. */
static void psc_join_shard(int shard, void *vctx)
{
    struct psc_join_ctx *ctx = vctx;
    struct psc_sortrec *recs = ctx->buckets[shard];
    size_t n = ctx->bucket_n[shard];
    struct psc_shard_out *so = &ctx->out[shard];
    const struct psc_event *EV = ctx->ev;

    if (n == 0) return;
    qsort(recs, n, sizeof(*recs), psc_sortrec_cmp);

    size_t i = 0;
    while (i < n) {
        /* [i, j) is one outpoint run (equal txid+vout), seq-ascending. */
        size_t j = i + 1;
        while (j < n &&
               memcmp(recs[j].txid, recs[i].txid, 32) == 0 &&
               recs[j].vout == recs[i].vout)
            j++;

        bool live = false;
        bool group_bad = false;
        uint32_t last_create = 0;   /* global ev index of the live CREATE */
        for (size_t k = i; k < j; k++) {
            const struct psc_event *e = &EV[recs[k].idx];
            if (e->kind == PSC_CREATE) {
                if (live) {
                    shard_note_reject(so, "utxo_collision", e->seq, e->height);
                    group_bad = true;
                }
                live = true;
                last_create = recs[k].idx;
            } else { /* PSC_SPEND */
                if (!live) {
                    shard_note_reject(so, "spend_unknown_utxo", e->seq,
                                      e->height);
                    group_bad = true;
                }
                live = false;
            }
        }
        if (!group_bad && live) {
            const struct psc_event *e = &EV[last_create];
            if (!shard_emit(so, e)) { so->error = true; return; }
            /* bind the script pointer into the shared pool by offset */
            so->coins[so->n - 1].script =
                e->script_len ? ctx->scripts + e->script_off : NULL;
        }
        i = j;
    }
}

bool psc_join(const struct psc_event *ev, size_t n, const uint8_t *scripts,
              int s_shards, int k_workers, psc_parallel_for_fn parallel_for,
              struct psc_coin **out_coins, size_t *out_count,
              char reject[48], int32_t *reject_height)
{
    *out_coins = NULL;
    *out_count = 0;
    if (reject) reject[0] = '\0';
    if (reject_height) *reject_height = -1;
    if (s_shards < 1) s_shards = 1;
    if (k_workers < 1) k_workers = 1;

    struct psc_join_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ev = ev;
    ctx.scripts = scripts;
    ctx.s_shards = s_shards;
    ctx.buckets  = zcl_calloc((size_t)s_shards, sizeof(*ctx.buckets), "psc_buckets");
    ctx.bucket_n = zcl_calloc((size_t)s_shards, sizeof(*ctx.bucket_n), "psc_bucket_n");
    ctx.out      = zcl_calloc((size_t)s_shards, sizeof(*ctx.out), "psc_shard_out");
    if (!ctx.buckets || !ctx.bucket_n || !ctx.out) {
        free(ctx.buckets); free(ctx.bucket_n); free(ctx.out);
        if (reject) snprintf(reject, 48, "internal");
        return false;
    }

    /* Scatter (counting sort): pass 1 counts per shard, pass 2 places records.
     * O(E) single-threaded — cheap relative to the parallel per-shard sort. */
    uint32_t *shard_of = NULL;
    if (n) {
        shard_of = zcl_malloc(n * sizeof(*shard_of), "psc_shard_of");
        if (!shard_of) {
            free(ctx.buckets); free(ctx.bucket_n); free(ctx.out);
            if (reject) snprintf(reject, 48, "internal");
            return false;
        }
    }
    for (size_t i = 0; i < n; i++) {
        uint32_t s = (uint32_t)(psc_key_hash(ev[i].txid, ev[i].vout) %
                                (uint64_t)s_shards);
        shard_of[i] = s;
        ctx.bucket_n[s]++;
    }
    bool alloc_ok = true;
    for (int s = 0; s < s_shards && alloc_ok; s++) {
        if (ctx.bucket_n[s] == 0) continue;
        ctx.buckets[s] = zcl_malloc(ctx.bucket_n[s] * sizeof(**ctx.buckets),
                                    "psc_bucket");
        if (!ctx.buckets[s]) alloc_ok = false;
    }
    if (!alloc_ok) {
        for (int s = 0; s < s_shards; s++) free(ctx.buckets[s]);
        free(shard_of); free(ctx.buckets); free(ctx.bucket_n); free(ctx.out);
        if (reject) snprintf(reject, 48, "internal");
        return false;
    }
    {
        size_t *fill = zcl_calloc((size_t)s_shards, sizeof(*fill), "psc_fill");
        if (!fill) {
            for (int s = 0; s < s_shards; s++) free(ctx.buckets[s]);
            free(shard_of); free(ctx.buckets); free(ctx.bucket_n); free(ctx.out);
            if (reject) snprintf(reject, 48, "internal");
            return false;
        }
        for (size_t i = 0; i < n; i++) {
            uint32_t s = shard_of[i];
            struct psc_sortrec *r = &ctx.buckets[s][fill[s]++];
            memcpy(r->txid, ev[i].txid, 32);
            r->vout = ev[i].vout;
            r->seq = ev[i].seq;
            r->idx = (uint32_t)i;
        }
        free(fill);
    }
    free(shard_of);

    /* Parallel: sort + validate + emit each shard independently. */
    parallel_for(s_shards, k_workers, psc_join_shard, &ctx);

    /* Reduce: any hard error, then the smallest-seq typed reject, else gather. */
    bool any_error = false, any_reject = false;
    uint64_t best_seq = UINT64_MAX;
    char     best_kind[48] = {0};
    int32_t  best_height = -1;
    size_t   total = 0;
    for (int s = 0; s < s_shards; s++) {
        if (ctx.out[s].error) any_error = true;
        if (ctx.out[s].rejected) {
            any_reject = true;
            if (ctx.out[s].reject_seq < best_seq) {
                best_seq = ctx.out[s].reject_seq;
                best_height = ctx.out[s].reject_height;
                snprintf(best_kind, sizeof(best_kind), "%s", ctx.out[s].reject);
            }
        }
        total += ctx.out[s].n;
    }

    bool ok = false;
    if (any_error) {
        if (reject) snprintf(reject, 48, "internal");
    } else if (any_reject) {
        if (reject) snprintf(reject, 48, "%s", best_kind);
        if (reject_height) *reject_height = best_height;
    } else {
        struct psc_coin *coins = total
            ? zcl_malloc(total * sizeof(*coins), "psc_coins") : NULL;
        if (total && !coins) {
            if (reject) snprintf(reject, 48, "internal");
        } else {
            size_t w = 0;
            for (int s = 0; s < s_shards; s++) {
                if (ctx.out[s].n)
                    memcpy(coins + w, ctx.out[s].coins,
                           ctx.out[s].n * sizeof(*coins));
                w += ctx.out[s].n;
            }
            *out_coins = coins;
            *out_count = total;
            ok = true;
        }
    }

    for (int s = 0; s < s_shards; s++) {
        free(ctx.buckets[s]);
        free(ctx.out[s].coins);
    }
    free(ctx.buckets); free(ctx.bucket_n); free(ctx.out);
    return ok;
}
