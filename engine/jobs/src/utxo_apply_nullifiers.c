/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_nullifiers — implementation. See jobs/utxo_apply_nullifiers.h.
 *
 * The reducer's port of zclassicd's shielded double-spend gate (C-3),
 * extracted from utxo_apply_stage.c along the utxo_apply_delta*.c seam.
 * Writes only the `nullifiers` table (via storage/nullifier_kv) inside the
 * caller's stage transaction. */

#include "platform/time_compat.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "jobs/utxo_apply_delta.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/reducer_commit_invariants.h"
#include "jobs/stage_helpers.h"

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "primitives/transaction_v6_wire.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/reducer_stage_profile.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NF_SUBSYS "utxo_apply"
static _Atomic int64_t g_nf_activation_cursor = -1;
static _Atomic bool g_nf_activation_cursor_known = false;

bool utxo_apply_shielded_history_initialize(sqlite3 *db)
{
    if (!db) {
        LOG_WARN(NF_SUBSYS, "[utxo_apply] history initialize: NULL db");
        return false;
    }
    struct stage_cursor_read_result stage_cursor =
        stage_cursor_read_persisted(db, NF_SUBSYS, NF_SUBSYS);
    if (!stage_cursor.ok)
        return false;

    uint64_t cursor = stage_cursor.cursor;
    if (!stage_cursor.found) {
        int32_t applied = -1;
        bool applied_found = false;
        if (!coins_kv_get_applied_height(db, &applied, &applied_found))
            LOG_RETURN(false, NF_SUBSYS,
                       "[utxo_apply] history initialize: applied-height read failed");
        int64_t coin_count = coins_kv_count(db);
        if (coin_count < 0)
            return false;
        /* Only a positively empty authority is complete from genesis. */
        if (applied_found || coin_count > 0) {
            cursor = applied_found && applied > 0 ? (uint64_t)applied : 1u;
            LOG_WARN(NF_SUBSYS,
                     "[utxo_apply] stage cursor absent on non-virgin authority "
                     "applied=%d found=%d coins=%lld boundary=%llu",
                     applied, applied_found ? 1 : 0, (long long)coin_count,
                     (unsigned long long)cursor);
        }
    }
    if (cursor > (uint64_t)INT64_MAX ||
        !anchor_kv_initialize_history(db, (int64_t)cursor))
        return false;
    utxo_apply_anchor_gap_blocker_refresh(db);
    if (!nullifier_kv_initialize_history(db, (int64_t)cursor))
        LOG_RETURN(false, NF_SUBSYS,
                   "[utxo_apply] history initialize: nullifier marker failed "
                   "cursor=%llu", (unsigned long long)cursor);
    utxo_apply_nullifier_gap_blocker_refresh(db);
    return true;
}

static bool shielded_history_blocker_ensure(sqlite3 *db,
                                            const char *blocker_id)
{
    if (!blocker_exists(blocker_id)) {
        if (strcmp(blocker_id, UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID) == 0)
            utxo_apply_anchor_gap_blocker_refresh(db);
        else
            utxo_apply_nullifier_gap_blocker_refresh(db);
    }
    if (!blocker_exists(blocker_id))
        LOG_FAIL(NF_SUBSYS,
                 "[utxo_apply] shielded history hold has no causal blocker id=%s",
                 blocker_id);
    return true;
}

static bool shielded_history_hold(sqlite3 *db,
                                  struct delta_summary *summary,
                                  const struct transaction *tx,
                                  const char *kind,
                                  const char *blocker_id)
{
    if (!shielded_history_blocker_ensure(db, blocker_id))
        LOG_FAIL(NF_SUBSYS,
                 "[utxo_apply] cannot hold shielded history without blocker id=%s",
                 blocker_id);
    summary->ok = false;
    summary->status = "shielded_history_incomplete";
    summary->failure_kind = kind;
    memset(summary->failure_detail, 0, sizeof(summary->failure_detail));
    if (tx)
        memcpy(summary->failure_detail, tx->hash.data, 32);
    return true;
}

/* One scan of the block: the first shielded tx of each kind and whether the
 * block needs each pool's history at all. */
struct shielded_preflight_scan {
    const struct transaction *first_spend;
    const struct transaction *first_sprout;
    const struct transaction *first_sapling;
    bool needs_sprout;
    bool needs_sapling;
};

static void shielded_preflight_scan_transactions(
    const struct block *blk, struct shielded_preflight_scan *scan)
{
    for (size_t i = 0; i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];
        bool sprout = tx->num_joinsplit > 0;
        bool sapling = tx->num_shielded_spend > 0;
        scan->needs_sprout = scan->needs_sprout || sprout;
        scan->needs_sapling = scan->needs_sapling || sapling;
        if (!scan->first_sprout && sprout)
            scan->first_sprout = tx;
        if (!scan->first_sapling && sapling)
            scan->first_sapling = tx;
        if (!scan->first_spend && (sprout || sapling))
            scan->first_spend = tx;
    }
}

/* Outcome of the anchor-pool completeness probe below. */
enum shielded_anchor_probe_result {
    SHIELDED_ANCHOR_PROBE_OK,
    SHIELDED_ANCHOR_PROBE_GAP,
    SHIELDED_ANCHOR_PROBE_ERROR
};

/* Reads the Sprout then the Sapling anchor activation markers (zclassicd's
 * order; a Sprout gap is decided before the Sapling marker is read) and
 * reports the first pool whose history prefix is incomplete, along with the
 * offending tx and its hold kind. */
static enum shielded_anchor_probe_result shielded_anchor_history_probe(
    sqlite3 *db, bool needs_sprout, bool needs_sapling,
    const struct transaction *first_sprout,
    const struct transaction *first_sapling,
    const struct transaction **gap_tx, const char **gap_kind)
{
    if (needs_sprout) {
        int64_t cursor = 0;
        bool found = false;
        if (!anchor_kv_activation_cursor(db, ANCHOR_POOL_SPROUT, &cursor,
                                         &found))
            return SHIELDED_ANCHOR_PROBE_ERROR;
        if (!found || cursor > 0) {
            *gap_tx = first_sprout;
            *gap_kind = "sprout-anchor-history-gap";
            return SHIELDED_ANCHOR_PROBE_GAP;
        }
    }
    if (needs_sapling) {
        int64_t cursor = 0;
        bool found = false;
        if (!anchor_kv_activation_cursor(db, ANCHOR_POOL_SAPLING, &cursor,
                                         &found))
            return SHIELDED_ANCHOR_PROBE_ERROR;
        if (!found || cursor > 0) {
            *gap_tx = first_sapling;
            *gap_kind = "sapling-anchor-history-gap";
            return SHIELDED_ANCHOR_PROBE_GAP;
        }
    }
    return SHIELDED_ANCHOR_PROBE_OK;
}

static bool shielded_history_preflight(sqlite3 *db, const struct block *blk,
                                       int height,
                                       struct delta_summary *summary)
{
    if (!db || !blk || height < 0 || !summary) {
        LOG_WARN(NF_SUBSYS,
                 "[utxo_apply] shielded history preflight: invalid args");
        return false;
    }

    struct shielded_preflight_scan scan = {0};
    shielded_preflight_scan_transactions(blk, &scan);
    if (!scan.first_spend)
        return true;

    /* A seeded current frontier is enough to keep folding outputs, but it is
     * NOT proof that every older membership root exists.  A positive adoption
     * cursor therefore holds spends even when their particular root happens to
     * be present (or is the protocol-defined empty root). */
    const struct transaction *gap_tx = NULL;
    const char *gap_kind = NULL;
    enum shielded_anchor_probe_result anchor =
        shielded_anchor_history_probe(db, scan.needs_sprout,
                                      scan.needs_sapling, scan.first_sprout,
                                      scan.first_sapling, &gap_tx,
                                      &gap_kind);
    if (anchor == SHIELDED_ANCHOR_PROBE_ERROR)
        return false;
    if (anchor == SHIELDED_ANCHOR_PROBE_GAP)
        return shielded_history_hold(db, summary, gap_tx, gap_kind,
                                     UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);

    int64_t nf_cursor = 0;
    bool nf_found = false;
    if (!nullifier_kv_activation_cursor(db, &nf_cursor, &nf_found)) {
        LOG_WARN(NF_SUBSYS,
                 "[utxo_apply] shielded history preflight could not read "
                 "nullifier completeness marker");
        return false;
    }
    if (!nf_found || nf_cursor > 0)
        return shielded_history_hold(
            db, summary, scan.first_spend, "nullifier-history-gap",
            UTXO_APPLY_NF_GAP_BLOCKER_ID);
    return true;
}

static enum utxo_apply_shielded_gate_result shielded_history_gate_impl(
    sqlite3 *db, const struct block *blk, int height,
    struct delta_summary *summary)
{
    if (!db || !blk || !summary || height < 0) {
        LOG_WARN(NF_SUBSYS,
                 "[utxo_apply] shielded history gate: invalid args h=%d",
                 height);
        return UTXO_SHIELDED_GATE_ERROR;
    }
    if (!shielded_history_preflight(db, blk, height, summary))
        return UTXO_SHIELDED_GATE_ERROR;
    if (!summary->ok)
        return UTXO_SHIELDED_GATE_HOLD;

    if (!utxo_apply_check_and_insert_anchors(db, blk, height, summary))
        return UTXO_SHIELDED_GATE_ERROR;
    if (summary->ok)
        return UTXO_SHIELDED_GATE_CONTINUE;
    if (strcmp(summary->status, "shielded_anchor_history_gap") != 0)
        return UTXO_SHIELDED_GATE_CONTINUE;
    if (!shielded_history_blocker_ensure(
            db, UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID))
        return UTXO_SHIELDED_GATE_ERROR;
    return UTXO_SHIELDED_GATE_HOLD;
}

/* Fold-path attribution (RPF_UA_SHIELDED_GATE_US): times the whole gate —
 * dominated by anchor_kv root re-derivation inside the anchor insert. */
enum utxo_apply_shielded_gate_result utxo_apply_shielded_history_gate(
    sqlite3 *db, const struct block *blk, int height,
    struct delta_summary *summary)
{
    const int64_t t0 = platform_time_monotonic_us();
    enum utxo_apply_shielded_gate_result r =
        shielded_history_gate_impl(db, blk, height, summary);
    reducer_stage_profile_observe_us(
        REDUCER_PROFILE_UTXO_APPLY, RPF_UA_SHIELDED_GATE_US,
        (uint64_t)(platform_time_monotonic_us() - t0));
    return r;
}

/* One entry of the per-block nullifier accumulator: the pass-1 same-block
 * check set and the pass-2 insert list. Sprout, Sapling and Ironwood are
 * SEPARATE namespaces (see storage/nullifier_kv.h). */
struct nf_entry {
    uint8_t nf[32];
    int pool;
};

struct nf_seen_index {
    size_t *slots;  /* entry index + 1; 0 means empty */
    size_t mask;
};

static uint64_t nf_hash_key(const uint8_t nf[32], int pool)
{
    uint64_t h = 1469598103934665603ULL;
    h ^= (uint64_t)(uint32_t)pool;
    h *= 1099511628211ULL;
    for (size_t i = 0; i < 32; i++) {
        h ^= nf[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static bool nf_index_init(struct nf_seen_index *idx, size_t total)
{
    memset(idx, 0, sizeof(*idx));
    if (total > SIZE_MAX / 2)
        return false;
    size_t want = total * 2;
    if (want < 8)
        want = 8;
    size_t cap = 1;
    while (cap < want) {
        if (cap > SIZE_MAX / 2)
            return false;
        cap <<= 1;
    }
    idx->slots = zcl_calloc(cap, sizeof(*idx->slots), "utxo_apply_nf_index");
    if (!idx->slots)
        return false;
    idx->mask = cap - 1;
    return true;
}

static bool nf_index_seen(const struct nf_seen_index *idx,
                          const struct nf_entry *acc,
                          const uint8_t nf[32], int pool)
{
    size_t pos = (size_t)nf_hash_key(nf, pool) & idx->mask;
    for (size_t probes = 0; probes <= idx->mask; probes++) {
        size_t slot = idx->slots[pos];
        if (slot == 0)
            return false;
        const struct nf_entry *e = &acc[slot - 1];
        if (e->pool == pool && memcmp(e->nf, nf, 32) == 0)
            return true;
        pos = (pos + 1) & idx->mask;
    }
    return false;
}

static bool nf_index_insert(struct nf_seen_index *idx,
                            const struct nf_entry *acc, size_t entry_i)
{
    size_t pos = (size_t)nf_hash_key(acc[entry_i].nf, acc[entry_i].pool)
        & idx->mask;
    for (size_t probes = 0; probes <= idx->mask; probes++) {
        size_t slot = idx->slots[pos];
        if (slot == 0) {
            idx->slots[pos] = entry_i + 1;
            return true;
        }
        const struct nf_entry *e = &acc[slot - 1];
        if (e->pool == acc[entry_i].pool &&
            memcmp(e->nf, acc[entry_i].nf, 32) == 0)
            return true;
        pos = (pos + 1) & idx->mask;
    }
    LOG_WARN(NF_SUBSYS, "[utxo_apply] nullifier lookup table full");
    return false;
}

static bool nf_index_insert_range(struct nf_seen_index *idx,
                                  const struct nf_entry *acc,
                                  size_t first, size_t last)
{
    for (size_t i = first; i < last; i++) {
        if (!nf_index_insert(idx, acc, i)) {
            LOG_WARN(NF_SUBSYS,
                     "[utxo_apply] nullifier lookup insert failed at %zu",
                     i);
            return false;
        }
    }
    return true;
}

static void nf_acc_free(struct nf_entry *acc, struct nf_seen_index *idx)
{
    if (idx)
        free(idx->slots);
    free(acc);
}

/* Check one nullifier against the durable set + the EARLIER-tx accumulator,
 * then append it. Returns false on a STORE error (caller fails closed);
 * a consensus hit flips summary->ok with zclassicd's exact reject string. */
static bool nf_check_one(sqlite3 *db, const uint8_t nf[32], int pool,
                         const struct uint256 *txid,
                         const struct nf_seen_index *seen,
                         struct nf_entry *acc, size_t *n,
                         struct delta_summary *summary)
{
    bool found = false;
    if (!nullifier_kv_get(db, nf, pool, &found, NULL))
        return false;  /* store error already logged by nullifier_kv */
    /* Legacy pools retain zclassicd's per-tx check-then-set order: their own
     * entries are indexed at the tx boundary after structural duplicate checks.
     * Opaque Ironwood has no such upstream admission pass, so its caller indexes
     * each action immediately and this set also covers earlier actions in it. */
    if (found || nf_index_seen(seen, acc, nf, pool)) {
        summary->ok = false;
        summary->status = "shielded_double_spend";
        summary->failure_kind = "bad-txns-joinsplit-requirements-not-met";
        memset(summary->failure_detail, 0, sizeof(summary->failure_detail));
        memcpy(summary->failure_detail, txid->data, 32);
        return true;   /* consensus reject — nothing was inserted */
    }
    memcpy(acc[*n].nf, nf, 32);
    acc[*n].pool = pool;
    (*n)++;
    return true;
}

static bool nf_v6_public_metadata_valid(const struct transaction *tx)
{
    return tx->overwintered && tx->version == IRONWOOD_TX_VERSION &&
        tx->version_group_id == IRONWOOD_VERSION_GROUP_ID;
}

static bool nf_v6_header_valid(const struct v6_wire_view *view)
{
    static const uint8_t expected_header[8] = {
        6, 0, 0, 0x80, 0x98, 0xb6, 0x84, 0xd8
    };
    return view->header.data && view->header.size == 20 &&
        memcmp(view->header.data, expected_header, sizeof expected_header) == 0;
}

static bool nf_v6_bundles_supported(const struct v6_wire_view *view)
{
    return !view->sapling_spends.count && !view->orchard.count;
}

static bool nf_v6_view(const struct transaction *tx,
                       struct v6_wire_view *view)
{
    memset(view, 0, sizeof(*view));
    bool wire_present = tx->v6_wire.data || tx->v6_wire.size;
    bool v6_metadata = tx->overwintered && tx->version == IRONWOOD_TX_VERSION;
    if (!wire_present && !v6_metadata)
        return true;
    if (!wire_present || !nf_v6_public_metadata_valid(tx)) {
        LOG_WARN(NF_SUBSYS,
                 "[utxo_apply] v6 wire metadata rejected: overwintered=%d "
                 "version=%d group=%08x", tx->overwintered ? 1 : 0,
                 tx->version, (unsigned)tx->version_group_id);
        return false;
    }
    enum v6_wire_error error =
        v6_core_parse(tx->v6_wire.data, tx->v6_wire.size, view);
    if (error != V6_WIRE_OK || !nf_v6_header_valid(view)) {
        LOG_WARN(NF_SUBSYS,
                 "[utxo_apply] malformed opaque v6 wire rejected: error=%d size=%zu",
                 (int)error, tx->v6_wire.size);
        memset(view, 0, sizeof(*view));
        return false;
    }
    if (!nf_v6_bundles_supported(view)) {
        LOG_WARN(NF_SUBSYS,
                 "[utxo_apply] unsupported v6 bundle rejected: sapling_spends=%llu "
                 "orchard_actions=%llu",
                 (unsigned long long)view->sapling_spends.count,
                 (unsigned long long)view->orchard.count);
        memset(view, 0, sizeof(*view));
        return false;
    }
    return true;
}

/* Exact bound on the block's nullifier entries (accumulator size). */
static bool nf_count_block_nullifiers(const struct block *blk, size_t *total_out)
{
    size_t total = 0;
    for (size_t ti = 0; ti < blk->num_vtx; ti++) {
        const struct transaction *tx = &blk->vtx[ti];
        if (tx->num_joinsplit > (SIZE_MAX - total) / ZC_NUM_JS_INPUTS)
            return false;
        total += tx->num_joinsplit * ZC_NUM_JS_INPUTS;
        if (tx->num_shielded_spend > SIZE_MAX - total)
            return false;
        total += tx->num_shielded_spend;
        struct v6_wire_view v6;
        if (!nf_v6_view(tx, &v6) ||
            v6.ironwood.count > (uint64_t)(SIZE_MAX - total))
            return false;
        total += (size_t)v6.ironwood.count;
    }
    *total_out = total;
    return true;
}

/* Pass-1 outcome for one tx: keep going, consensus-reject (summary->ok is
 * already false), or a malformed-wire/store error. */
enum nf_pass1_result {
    NF_PASS1_CONTINUE,
    NF_PASS1_REJECT,
    NF_PASS1_STORE_ERROR
};

static enum nf_pass1_result nf_pass1_accumulate_legacy(
    sqlite3 *db, const struct transaction *tx, struct nf_seen_index *seen,
    struct nf_entry *acc, size_t *n, struct delta_summary *summary)
{
    size_t tx_first = *n;   /* entries below this are EARLIER txs */
    for (size_t i = 0; i < tx->num_joinsplit; i++) {
        for (size_t j = 0; j < ZC_NUM_JS_INPUTS; j++) {
            if (!nf_check_one(db,
                              tx->v_joinsplit[i].nullifiers[j].data,
                              NULLIFIER_POOL_SPROUT, &tx->hash,
                              seen, acc, n, summary))
                return NF_PASS1_STORE_ERROR;
            if (!summary->ok)
                return NF_PASS1_REJECT;
        }
    }
    for (size_t i = 0; i < tx->num_shielded_spend; i++) {
        if (!nf_check_one(db,
                          tx->v_shielded_spend[i].nullifier.data,
                          NULLIFIER_POOL_SAPLING, &tx->hash,
                          seen, acc, n, summary))
            return NF_PASS1_STORE_ERROR;
        if (!summary->ok)
            return NF_PASS1_REJECT;
    }
    if (!nf_index_insert_range(seen, acc, tx_first, *n))
        return NF_PASS1_STORE_ERROR;
    return NF_PASS1_CONTINUE;
}

static enum nf_pass1_result nf_pass1_accumulate_ironwood(
    sqlite3 *db, const struct transaction *tx, const struct v6_wire_view *v6,
    struct nf_seen_index *seen, struct nf_entry *acc, size_t *n,
    struct delta_summary *summary)
{
    for (uint64_t i = 0; i < v6->ironwood.count; i++) {
        struct v6_action_view action;
        if (!v6_core_bundle_action(&v6->ironwood, i, &action) ||
            !action.nullifier.data || action.nullifier.size != 32) {
            LOG_WARN(NF_SUBSYS,
                     "[utxo_apply] checked Ironwood action view failed at %llu",
                     (unsigned long long)i);
            return NF_PASS1_STORE_ERROR;
        }
        if (!nf_check_one(db, action.nullifier.data, NULLIFIER_POOL_IRONWOOD,
                          &tx->hash, seen, acc, n, summary))
            return NF_PASS1_STORE_ERROR;
        if (!summary->ok)
            return NF_PASS1_REJECT;
        if (!nf_index_insert(seen, acc, *n - 1))
            return NF_PASS1_STORE_ERROR;
    }
    return NF_PASS1_CONTINUE;
}

/* Pass 1 for one tx: check every Sprout JoinSplit nullifier, then every
 * Sapling spend nullifier, against the durable set + the EARLIER-tx
 * accumulator. Ironwood uses the same durable/earlier-tx checks and indexes
 * each action immediately so duplicate actions in one tx are also rejected. */
static enum nf_pass1_result nf_pass1_accumulate_tx(
    sqlite3 *db, const struct transaction *tx, struct nf_seen_index *seen,
    struct nf_entry *acc, size_t *n, struct delta_summary *summary)
{
    struct v6_wire_view v6;
    if (!nf_v6_view(tx, &v6))
        return NF_PASS1_STORE_ERROR;
    enum nf_pass1_result result =
        nf_pass1_accumulate_legacy(db, tx, seen, acc, n, summary);
    if (result != NF_PASS1_CONTINUE)
        return result;
    return nf_pass1_accumulate_ironwood(db, tx, &v6, seen, acc, n, summary);
}

/* NOT inside utxo_apply_compute_block_delta on purpose: repair dry-runs call
 * the delta builder in throwaway txns where in-range nullifier rows still
 * exist and would false-fail an otherwise-valid repair. TWO-PASS so a
 * rejected block never leaves partial rows even before the txn rollback:
 * pass 1 checks every nullifier of every tx (durable set + earlier-tx
 * accumulator); pass 2 inserts only if the whole block is clean. */
static bool check_and_insert_nullifiers_impl(struct sqlite3 *db,
                                             const struct block *blk,
                                             int height,
                                             struct delta_summary *summary)
{
    size_t total = 0;
    if (!nf_count_block_nullifiers(blk, &total)) {
        LOG_WARN(NF_SUBSYS,
                 "[utxo_apply] invalid or overflowing nullifier count h=%d",
                 height);
        return false;
    }
    if (total == 0)
        return true;

    struct nf_entry *acc =
        zcl_calloc(total, sizeof(*acc), "utxo_apply_nullifiers");
    if (!acc) {
        LOG_WARN(NF_SUBSYS,
                 "[utxo_apply] nullifier accumulator alloc failed h=%d "
                 "(%zu entries)", height, total);
        return false;
    }
    struct nf_seen_index seen;
    if (!nf_index_init(&seen, total)) {
        LOG_WARN(NF_SUBSYS,
                 "[utxo_apply] nullifier lookup alloc failed h=%d "
                 "(%zu entries)", height, total);
        nf_acc_free(acc, NULL);
        return false;
    }

    size_t n = 0;
    for (size_t ti = 0; ti < blk->num_vtx; ti++) {
        const struct transaction *tx = &blk->vtx[ti];
        enum nf_pass1_result r = nf_pass1_accumulate_tx(db, tx, &seen, acc,
                                                        &n, summary);
        if (r == NF_PASS1_REJECT) {
            nf_acc_free(acc, &seen);
            return true;
        }
        if (r == NF_PASS1_STORE_ERROR) {
            nf_acc_free(acc, &seen);
            return false;
        }
    }

    /* Pass 2 — the whole block is clean: reveal every nullifier at this
     * height. Permanent consensus state, like coins (never pruned). */
    for (size_t i = 0; i < n; i++) {
        if (!nullifier_kv_add(db, acc[i].nf, acc[i].pool, (int64_t)height)) {
            nf_acc_free(acc, &seen);
            return false;  /* store error already logged; txn rolls back */
        }
        /* Feed the batch-commit uniqueness invariant (c): a duplicate reveal
         * within the batch is refused at commit instead of being silently
         * swallowed by nullifier_kv_add's INSERT OR REPLACE (no-op unless a
         * drain batch is open). */
        reducer_commit_invariants_note_nullifier(height, acc[i].nf,
                                                 acc[i].pool);
    }
    nf_acc_free(acc, &seen);
    return true;
}

/* Fold-path attribution (RPF_UA_NULLIFIERS_US). */
bool utxo_apply_check_and_insert_nullifiers(struct sqlite3 *db,
                                            const struct block *blk,
                                            int height,
                                            struct delta_summary *summary)
{
    const int64_t t0 = platform_time_monotonic_us();
    bool ok = check_and_insert_nullifiers_impl(db, blk, height, summary);
    reducer_stage_profile_observe_us(
        REDUCER_PROFILE_UTXO_APPLY, RPF_UA_NULLIFIERS_US,
        (uint64_t)(platform_time_monotonic_us() - t0));
    return ok;
}

void utxo_apply_nullifier_gap_blocker_refresh(struct sqlite3 *db)
{
    int64_t activation = 0;
    bool found = false;

    if (!db) {
        LOG_WARN(NF_SUBSYS,
                 "[utxo_apply] gap blocker refresh: NULL db handle");
        return;
    }
    if (!nullifier_kv_activation_cursor(db, &activation, &found)) {
        LOG_WARN(NF_SUBSYS,
                 "[utxo_apply] nullifier activation marker read failed — "
                 "gap blocker not refreshed");
        return;
    }
    int64_t act = found ? activation : -1;
    atomic_store_explicit(&g_nf_activation_cursor, act,
                          memory_order_relaxed);
    atomic_store_explicit(&g_nf_activation_cursor_known, true,
                          memory_order_release);
    if (found && act == 0) {
        /* Explicit zero is the only complete representation: from-genesis
         * replay or a successfully completed historical backfill. */
        blocker_clear(UTXO_APPLY_NF_GAP_BLOCKER_ID);
        return;
    }

    struct blocker_record rec;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "nullifier history completeness %s (activation cursor %lld); "
             "every Sprout JoinSplit/Sapling spend is held fail-closed until "
             "shielded-history backfill or from-genesis replay completes "
             "(storage/nullifier_kv.h activation gap).",
             found ? "has an unknown prefix" : "marker is absent",
             (long long)act);
    /* PERMANENT: no retry fixes this — only an owner-gated backfill (or a
     * resync) does, so it must stay visible until an operator clears it. */
    if (!blocker_init(&rec, UTXO_APPLY_NF_GAP_BLOCKER_ID, NF_SUBSYS,
                      BLOCKER_PERMANENT, reason))
        return;   /* blocker_init logged the overflow */
    blocker_set(&rec);  /* -1 (cap exhausted) already logged by blocker_set */
}

bool utxo_apply_nullifier_gap_snapshot(int64_t *activation_cursor,
                                       bool *backfill_gap)
{
    if (!activation_cursor || !backfill_gap)
        return false;
    if (!atomic_load_explicit(&g_nf_activation_cursor_known,
                              memory_order_acquire))
        return false;
    int64_t cursor = atomic_load_explicit(&g_nf_activation_cursor,
                                          memory_order_relaxed);
    *activation_cursor = cursor;
    *backfill_gap = cursor != 0;
    return true;
}
