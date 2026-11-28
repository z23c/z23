/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure ZIP-209 turnstile core; step 1 of reducer-shielded-consensus-plan.md
 * (c). Nothing calls it yet: shadow mode and enforcement are later,
 * owner-gated lanes. See jobs/utxo_apply_turnstile.h. */

#include "jobs/utxo_apply_turnstile.h"

#include "jobs/utxo_apply_delta.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "core/serialize.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/shielded_pool_kv.h"
#include "util/log_macros.h"
#include "validation/connect_block.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <string.h>

_Atomic uint64_t g_ua_turnstile_would_reject_total = 0;
_Atomic uint64_t g_ua_turnstile_unknown_total = 0;

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

static bool ts_i64_add(int64_t a, int64_t b, int64_t *out)
{
    if ((b > 0 && a > INT64_MAX - b) || (b < 0 && a < INT64_MIN - b))
        return false;
    *out = a + b;
    return true;
}

const char *utxo_apply_turnstile_ironwood_check(
    struct utxo_apply_turnstile_pool prev_ironwood,
    int64_t block_ironwood,
    struct utxo_apply_turnstile_pool *out_ironwood)
{
    struct utxo_apply_turnstile_pool next = { 0, false };
    if (out_ironwood) *out_ironwood = next;
    if (!prev_ironwood.known) return NULL;
    int64_t total = 0;
    if (!ts_i64_add(prev_ironwood.total, block_ironwood, &total))
        return "bad-txns-ironwood-turnstile-violation";
    if (out_ironwood) {
        out_ironwood->total = total;
        out_ironwood->known = true;
    }
    return total < 0 ? "bad-txns-ironwood-turnstile-violation" : NULL;
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
    bool ironwood = strcmp(reject, "bad-txns-ironwood-turnstile-violation") == 0;
    summary->ok = false;
    summary->status = ironwood ? "turnstile_ironwood" :
        sprout ? "turnstile_sprout" : "turnstile_sapling";
    summary->failure_kind = reject;
    memset(summary->failure_detail, 0, sizeof(summary->failure_detail));
}

static bool ts_ironwood_refuse(struct delta_summary *summary,
                               struct utxo_apply_turnstile_pending *pending)
{
    pending->write = false;
    pending->ironwood_known = false;
    ts_refuse(summary, "bad-txns-ironwood-turnstile-violation");
    return true;
}

static bool ts_ironwood_stage(sqlite3 *db, const struct block *blk,
    int64_t next_h, struct delta_summary *summary,
    struct utxo_apply_turnstile_pending *pending)
{
    struct utxo_apply_turnstile_pool prev = { 0, next_h == 0 };
    bool found = next_h == 0;
    if (next_h > 0 &&
        !shielded_pool_kv_get_ironwood(db, next_h - 1, &prev.total,
                                       &prev.known, &found)) return false;
    if (!found || !prev.known)
        return ts_ironwood_refuse(summary, pending);
    int64_t block_value = 0;
    if (!connect_block_shielded_values(blk, NULL, NULL, &block_value))
        return ts_ironwood_refuse(summary, pending);
    struct utxo_apply_turnstile_pool next;
    const char *reject = utxo_apply_turnstile_ironwood_check(
        prev, block_value, &next);
    if (reject && !next.known)
        return ts_ironwood_refuse(summary, pending);
    if (reject && atomic_load(&g_enforce_turnstile))
        return ts_ironwood_refuse(summary, pending);
    if (reject) {
        atomic_fetch_add(&g_ua_turnstile_would_reject_total, 1);
        LOG_WARN("utxo_apply", "turnstile SHADOW Ironwood violation at height=%lld",
                 (long long)next_h);
    }
    pending->ironwood = next.total;
    pending->ironwood_known = next.known;
    return true;
}

/* A fresh on-demand node can anchor genesis without applying its body.
 * Reconstruct its pool row in H1's transaction from the pinned descriptor.
 * The storage puts compare existing totals and refuse a disagreement. */
static bool ts_research_genesis_pools(sqlite3 *db,
    const struct chain_research_descriptor *profile, const struct uint256 *parent)
{
    if (sqlite3_get_autocommit(db) || chain_params_get() != profile->chain ||
        !profile->genesis_wire || !profile->genesis_wire_len)
        LOG_FAIL("utxo_apply", "cannot establish transactional research genesis totals");
    struct byte_stream wire;
    stream_init_from_data(&wire, profile->genesis_wire, profile->genesis_wire_len);
    struct block genesis;
    block_init(&genesis);
    int64_t sprout = 0, sapling = 0, ironwood = 0;
    bool ok = block_deserialize(&genesis, &wire) && !stream_remaining(&wire) &&
              genesis.num_vtx == 1;
    if (ok) {
        struct uint256 hash;
        block_get_hash(&genesis, &hash);
        transaction_compute_hash(&genesis.vtx[0]);
        ok = uint256_eq(&hash, parent) &&
             uint256_eq(&genesis.vtx[0].hash, &genesis.header.hashMerkleRoot) &&
             connect_block_shielded_values(&genesis, &sprout, &sapling, &ironwood);
    }
    block_free(&genesis);
    if (!ok) LOG_FAIL("utxo_apply", "research genesis body does not authenticate pool totals");
    return shielded_pool_kv_put(db, 0, sprout, sapling) &&
           shielded_pool_kv_put_ironwood(db, 0, ironwood);
}

bool utxo_apply_turnstile_stage_check(
    sqlite3 *db, const struct block *blk, int64_t next_h,
    const struct uint256 *hash, struct delta_summary *summary,
    struct utxo_apply_turnstile_pending *pending)
{
    struct ts_totals parent = { 0, 0 };
    struct ts_totals blockv = { 0, 0 };
    bool parent_known = true;
    const struct chain_research_descriptor *profile = chain_research_profile_current();
    pending->write = false;
    if (next_h == 1 && profile && profile->id == CHAIN_RESEARCH_IRONWOOD &&
        blk && uint256_eq(&blk->header.hashPrevBlock, &profile->chain->consensus.hashGenesisBlock) &&
        !ts_research_genesis_pools(db, profile, &blk->header.hashPrevBlock))
        return false; // raw-return-ok:callee-logged-research-genesis-pool-failure
    if (next_h > 0 &&
        !shielded_pool_kv_get(db, next_h - 1, &parent.sprout,
                              &parent.sapling, &parent_known))
        return false;
    if (!parent_known) {
        if (chain_research_profile_current())
            return ts_ironwood_refuse(summary, pending);
        atomic_fetch_add(&g_ua_turnstile_unknown_total, 1);
        return true;
    }
    connect_block_shielded_values(blk, &blockv.sprout, &blockv.sapling, NULL);
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
    if (chain_research_profile_current() &&
        !ts_ironwood_stage(db, blk, next_h, summary, pending)) return false;
    return true;
}
