/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * psc_internal — shared structs + phase decls for the Parallel State Compiler
 * (psc_range_fold.h). Included only by the PSC translation units
 * (psc_extract.c, psc_join.c, psc_range_fold.c); not a public API.
 *
 * The unit of work between the two parallel phases is a stream of typed
 * per-outpoint EVENTS. Extraction (phase a) turns each block into CREATE +
 * SPEND events tagged with a global apply-order key `seq`; the join (phase b)
 * groups events by outpoint, replays them in seq order, and reduces each
 * outpoint's history to a terminal coin (or a typed reject). `seq` encodes the
 * EXACT order the serial fold applies effects — height ascending, and within a
 * block all CREATEs (adds) before all SPENDs, each in original (tx,vout/vin)
 * order — so the parallel reduction lands on the same terminal set.
 */
#ifndef ZCL_JOBS_PSC_INTERNAL_H
#define ZCL_JOBS_PSC_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct block;

enum psc_event_kind { PSC_CREATE = 0, PSC_SPEND = 1 };

/* seq layout (uint64): [height:32][phase:1][index:31].
 *   height — block height (ascending == apply order across blocks).
 *   phase  — 0 CREATE, 1 SPEND (adds-before-spends WITHIN a block, matching
 *            utxo_apply_stage.c apply_coins_kv).
 *   index  — position within (block, phase) in original tx/vout(vin) order. */
static inline uint64_t psc_seq_make(uint32_t height, unsigned phase,
                                    uint32_t index)
{
    return ((uint64_t)height << 32) | ((uint64_t)(phase & 1u) << 31) |
           (uint64_t)(index & 0x7fffffffu);
}
static inline uint32_t psc_seq_height(uint64_t seq) { return (uint32_t)(seq >> 32); }

/* One transparent UTXO-set event. CREATE carries the full coin (value/height/
 * is_coinbase/script); SPEND carries only the outpoint (+ its height for the
 * reject report). Scripts live out-of-line in the owning stream's byte pool,
 * referenced by (script_off, script_len) — CREATE only. */
struct psc_event {
    uint8_t  txid[32];
    uint32_t vout;
    uint64_t seq;
    int64_t  value;        /* CREATE */
    uint32_t script_off;   /* CREATE: byte offset into psc_events.scripts */
    uint32_t script_len;   /* CREATE */
    int32_t  height;       /* coin creation / spend block height */
    uint8_t  kind;         /* enum psc_event_kind */
    uint8_t  is_coinbase;  /* CREATE */
};

/* A growable event vector + its out-of-line script byte pool. */
struct psc_events {
    struct psc_event *ev;
    size_t            n;
    size_t            cap;
    uint8_t          *scripts;
    size_t            scr_used;
    size_t            scr_cap;
};

void psc_events_init(struct psc_events *e);
void psc_events_free(struct psc_events *e);
/* Append a CREATE (copies script into the pool) / a SPEND. Return false + log
 * on OOM. */
bool psc_events_add_create(struct psc_events *e, const uint8_t txid[32],
                           uint32_t vout, int64_t value, int32_t height,
                           bool is_coinbase, const uint8_t *script,
                           uint32_t script_len, uint64_t seq);
bool psc_events_add_spend(struct psc_events *e, const uint8_t txid[32],
                          uint32_t vout, int32_t height, uint64_t seq);

/* Extract one block's transparent CREATE/SPEND events into `out`, applying the
 * SAME block-local exclusion predicates the serial utxo_apply_compute_block_delta
 * uses: genesis-hash skip, tx_out_is_null, script_is_unspendable, per-output
 * MoneyRange. Existence / duplicate-outpoint (BIP30) / create-before-spend are
 * DEFERRED to the join as ordering properties (unlike compute_block_delta,
 * which resolves them inline against a live lookup — see psc_extract.c's
 * rationale for why the builder can NOT be reused lookup-free). Returns false +
 * fills reject[48] on a block-local reject ("value_overflow") or OOM/structural
 * error. */
bool psc_extract_block(const struct block *blk, uint32_t height,
                       struct psc_events *out, char reject[48]);

/* One terminal coin emitted by the join (last event for an outpoint is a
 * CREATE). `script` points into the caller-supplied global script pool. */
struct psc_coin {
    uint8_t        txid[32];
    uint32_t       vout;
    int64_t        value;
    int32_t        height;
    uint8_t        is_coinbase;
    uint32_t       script_len;
    const uint8_t *script;
};

/* Sharded outpoint sort-merge join. Routes each of `n` events to
 * hash(outpoint) mod `s_shards`, sorts each shard by (outpoint, seq),
 * validates the per-outpoint CREATE/SPEND alternation, and emits every
 * outpoint whose terminal event is a CREATE into *out_coins (malloc'd; caller
 * frees). `scripts` is the shared pool the events' script_off index into.
 * `k_workers` shards are processed in parallel via the caller's pool primitive
 * (psc_parallel_for, passed as a function so this TU stays pool-agnostic).
 *
 * On a consensus-ordering violation returns false with reject[48] filled
 * ("spend_unknown_utxo" / "utxo_collision") and *reject_height set. On a hard
 * error returns false with reject "internal". On success returns true. */
typedef void (*psc_parallel_for_fn)(int n_items, int n_workers,
                                    void (*fn)(int item, void *ctx), void *ctx);

bool psc_join(const struct psc_event *ev, size_t n, const uint8_t *scripts,
              int s_shards, int k_workers, psc_parallel_for_fn parallel_for,
              struct psc_coin **out_coins, size_t *out_count,
              char reject[48], int32_t *reject_height);

#endif /* ZCL_JOBS_PSC_INTERNAL_H */
