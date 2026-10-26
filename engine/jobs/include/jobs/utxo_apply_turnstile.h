/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_turnstile - the ZIP-209 turnstile for the reducer path
 * (docs/work/reducer-shielded-consensus-plan.md (c)). The pure core is a
 * side-effect-free port of the arithmetic in
 * core/modules/validation/src/connect_block.c (per-block Sprout/Sapling
 * value sums, then cumulative totals that must not go negative). The
 * stage-facing step below reads the parent row from shielded_pool_kv and
 * decides; it runs in SHADOW mode by default (log + count, still apply) and
 * refuses only when g_enforce_turnstile is set (-enforce-turnstile). */

#ifndef ZCL_JOBS_UTXO_APPLY_TURNSTILE_H
#define ZCL_JOBS_UTXO_APPLY_TURNSTILE_H

#include <stdbool.h>
#include <stdint.h>

#include <stddef.h>
#include <stdatomic.h>

struct block;
struct delta_summary;
struct sqlite3;
struct uint256;

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

/* What the stage must persist when the block applies: the totals AFTER this
 * block, written only on the success path inside the stage txn. */
struct utxo_apply_turnstile_pending {
    bool write;
    int64_t sprout;
    int64_t sapling;
};

/* Shadow/enforce observability (read by the utxo_apply status dump). */
extern _Atomic uint64_t g_ua_turnstile_would_reject_total;
extern _Atomic uint64_t g_ua_turnstile_unknown_total;

/* Stage step for the block at `next_h` (hash is for logging only; may be
 * NULL). Reads the parent row (next_h-1; genesis has a known {0,0} parent).
 * No parent row: accept, pending->write=false, unknown counter (never refuse
 * or hold in any mode). Known parent and accepted: pending->write=true. Known
 * parent and refused: shadow mode warns once per height, counts and still
 * accepts with pending->write=true; enforcement sets summary->ok=false,
 * status "turnstile_sprout" or "turnstile_sapling", failure_kind to the exact
 * zclassicd string, and pending->write=false. Returns false only on a store
 * failure (the caller treats it as fatal). */
bool utxo_apply_turnstile_stage_check(
    struct sqlite3 *db, const struct block *blk, int64_t next_h,
    const struct uint256 *hash, struct delta_summary *summary,
    struct utxo_apply_turnstile_pending *pending);

#endif
