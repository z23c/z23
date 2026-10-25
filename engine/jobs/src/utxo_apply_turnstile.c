/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure ZIP-209 turnstile core; step 1 of reducer-shielded-consensus-plan.md
 * (c). Nothing calls it yet: shadow mode and enforcement are later,
 * owner-gated lanes. See jobs/utxo_apply_turnstile.h. */

#include "jobs/utxo_apply_turnstile.h"

#include "primitives/block.h"
#include "primitives/transaction.h"

void utxo_apply_turnstile_block_values(const struct block *blk,
                                       int64_t *sprout, int64_t *sapling)
{
    int64_t sprout_value = 0;
    int64_t sapling_value = 0;
    for (size_t i = 0; blk && i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];
        for (size_t j = 0; j < tx->num_joinsplit; j++) {
            sprout_value += tx->v_joinsplit[j].vpub_old;
            sprout_value -= tx->v_joinsplit[j].vpub_new;
        }
        sapling_value += tx->value_balance;
    }
    if (sprout)
        *sprout = sprout_value;
    if (sapling)
        *sapling = sapling_value;
}

const char *utxo_apply_turnstile_check(
    struct utxo_apply_turnstile_pool prev_sprout,
    struct utxo_apply_turnstile_pool prev_sapling,
    int64_t block_sprout, int64_t block_sapling,
    struct utxo_apply_turnstile_pool *out_sprout,
    struct utxo_apply_turnstile_pool *out_sapling)
{
    struct utxo_apply_turnstile_pool ns = { 0, false };
    struct utxo_apply_turnstile_pool np = { 0, false };
    const char *reject = NULL;

    if (prev_sprout.known) {
        ns.total = prev_sprout.total + block_sprout;
        ns.known = true;
        if (ns.total < 0)
            reject = "bad-txns-sprout-turnstile-violation";
    }
    if (!reject && prev_sapling.known) {
        np.total = prev_sapling.total + block_sapling;
        np.known = true;
        if (np.total < 0)
            reject = "bad-txns-sapling-turnstile-violation";
    }
    if (out_sprout)
        *out_sprout = ns;
    if (out_sapling)
        *out_sapling = np;
    return reject;
}
