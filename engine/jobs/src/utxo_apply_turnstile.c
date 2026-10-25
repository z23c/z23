/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure ZIP-209 turnstile core; step 1 of reducer-shielded-consensus-plan.md
 * (c). Nothing calls it yet: shadow mode and enforcement are later,
 * owner-gated lanes. See jobs/utxo_apply_turnstile.h. */

#include "jobs/utxo_apply_turnstile.h"

#include "jobs/utxo_apply_delta.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/shielded_pool_kv.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <string.h>

_Atomic uint64_t g_ua_turnstile_would_reject_total = 0;
_Atomic uint64_t g_ua_turnstile_unknown_total = 0;

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

/* Totals the block would leave in each pool whether or not it is refused:
 * the chain's real running totals, which is what shadow mode records. */
struct ts_totals {
    int64_t sprout;
    int64_t sapling;
};

static void ts_warn_once(int64_t next_h, const struct uint256 *hash,
                         const struct ts_totals *parent,
                         const struct ts_totals *blockv, const char *reject)
{
    static _Atomic int64_t last_warned = -1;
    if (atomic_exchange(&last_warned, next_h) == next_h)
        return;
    char hex[65] = "(none)";
    if (hash)
        uint256_get_hex(hash, hex);
    LOG_WARN("utxo_apply",
             "[utxo_apply] turnstile SHADOW would reject height=%lld "
             "hash=%s parent_sprout=%lld parent_sapling=%lld "
             "block_sprout=%lld block_sapling=%lld reason=%s",
             (long long)next_h, hex, (long long)parent->sprout,
             (long long)parent->sapling, (long long)blockv->sprout,
             (long long)blockv->sapling, reject);
}

static void ts_refuse(struct delta_summary *summary, const char *reject)
{
    bool sprout = strcmp(reject, "bad-txns-sprout-turnstile-violation") == 0;
    summary->ok = false;
    summary->status = sprout ? "turnstile_sprout" : "turnstile_sapling";
    summary->failure_kind = reject;
    memset(summary->failure_detail, 0, sizeof(summary->failure_detail));
}

bool utxo_apply_turnstile_stage_check(
    sqlite3 *db, const struct block *blk, int64_t next_h,
    const struct uint256 *hash, struct delta_summary *summary,
    struct utxo_apply_turnstile_pending *pending)
{
    struct ts_totals parent = { 0, 0 };
    struct ts_totals blockv = { 0, 0 };
    bool parent_known = true;
    pending->write = false;
    if (next_h > 0 &&
        !shielded_pool_kv_get(db, next_h - 1, &parent.sprout,
                              &parent.sapling, &parent_known))
        return false;
    if (!parent_known) {
        atomic_fetch_add(&g_ua_turnstile_unknown_total, 1);
        return true;
    }
    utxo_apply_turnstile_block_values(blk, &blockv.sprout, &blockv.sapling);
    struct utxo_apply_turnstile_pool ns, np;
    const char *reject = utxo_apply_turnstile_check(
        (struct utxo_apply_turnstile_pool){ parent.sprout, true },
        (struct utxo_apply_turnstile_pool){ parent.sapling, true },
        blockv.sprout, blockv.sapling, &ns, &np);
    if (reject && atomic_load(&g_enforce_turnstile)) {
        ts_refuse(summary, reject);
        return true;
    }
    if (reject) {
        atomic_fetch_add(&g_ua_turnstile_would_reject_total, 1);
        ts_warn_once(next_h, hash, &parent, &blockv, reject);
    }
    /* Both totals from the parent row, so a Sprout refusal (which leaves the
     * Sapling total unknown in the pure core) still records the real chain. */
    pending->write = true;
    pending->sprout = parent.sprout + blockv.sprout;
    pending->sapling = parent.sapling + blockv.sapling;
    return true;
}
