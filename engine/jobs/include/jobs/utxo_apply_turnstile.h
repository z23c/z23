/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_turnstile - the pure ZIP-209 turnstile core for the reducer
 * path. This is step 1 of docs/work/reducer-shielded-consensus-plan.md (c):
 * a reviewed, side-effect-free port of the arithmetic in
 * core/modules/validation/src/connect_block.c (per-block Sprout/Sapling
 * value sums, then cumulative totals that must not go negative).
 *
 * NOTHING CALLS THIS YET. It reads no store, writes no row and decides no
 * block. Shadow mode and enforcement are later, owner-gated lanes
 * (FORWARD_PLAN.md item 8); only they may wire it into block application. */

#ifndef ZCL_JOBS_UTXO_APPLY_TURNSTILE_H
#define ZCL_JOBS_UTXO_APPLY_TURNSTILE_H

#include <stdbool.h>
#include <stdint.h>

struct block;

/* Per-block shielded value, exactly connect_block.c: over every joinsplit of
 * every tx sprout += vpub_old - vpub_new; sapling += tx value_balance.
 * Plain int64 arithmetic in the same order. */
void utxo_apply_turnstile_block_values(const struct block *blk,
                                       int64_t *sprout, int64_t *sapling);

/* One pool's cumulative total; `known` mirrors zclassicd's boost::optional
 * (an unknown total is never enforced and stays unknown). */
struct utxo_apply_turnstile_pool {
    int64_t total;
    bool known;
};

/* Apply a block's values to the parent's totals. Sprout is checked first. A
 * pool is enforced only when its previous total is known; an unknown parent
 * leaves the new total unknown. Returns NULL when accepted, else the exact
 * zclassicd reject string ("bad-txns-sprout-turnstile-violation" or
 * "bad-txns-sapling-turnstile-violation"). `out_*` are written on every
 * call, including a refusal (as connect_block.c has already stored the
 * offending total at that point). */
const char *utxo_apply_turnstile_check(
    struct utxo_apply_turnstile_pool prev_sprout,
    struct utxo_apply_turnstile_pool prev_sapling,
    int64_t block_sprout, int64_t block_sapling,
    struct utxo_apply_turnstile_pool *out_sprout,
    struct utxo_apply_turnstile_pool *out_sapling);

#endif
