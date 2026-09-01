/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

// one-result-type-ok:read-only-evidence-snapshot — missing evidence is carried
// by explicit known/match fields; collection is a total observational API.

#include "services/chain_frontier_snapshot_service.h"

#include "chain/chain.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"
#include "services/chain_state_service.h"
#include "storage/progress_store.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <string.h>

static bool chain_frontier_value_from_index(
    struct chain_frontier_value *out,
    const struct block_index *index,
    enum block_status minimum_validity)
{
    memset(out, 0, sizeof(*out));
    if (!index || index->nHeight < 0)
        return false;
    out->height_known = true;
    out->height = index->nHeight;
    out->status = block_index_status_load(index);
    out->status_known = true;
    out->failure_free =
        (out->status & (unsigned int)BLOCK_FAILED_ANY_MASK) == 0;
    out->validity_sufficient =
        (out->status & (unsigned int)BLOCK_VALID_MASK) >=
        (unsigned int)minimum_validity;
    if (!index->phashBlock || uint256_is_null(index->phashBlock) ||
        arith_uint256_is_zero(&index->nChainWork))
        return true;
    uint256_get_hex(index->phashBlock, out->hash);
    arith_uint256_get_hex(&index->nChainWork, out->chain_work);
    out->binding_known = true;
    return true;
}

static bool chain_frontier_read_authority(
    int32_t height,
    struct uint256 *hash,
    bool *durable,
    enum chain_frontier_authority_source *source)
{
    struct uint256 runtime_hash;
    struct uint256 durable_hash;
    int64_t runtime_height = -1;

    *durable = false;
    *source = CHAIN_FRONTIER_AUTHORITY_NONE;
    uint256_set_null(&runtime_hash);
    uint256_set_null(&durable_hash);

    bool runtime_known = tip_finalize_stage_authority_snapshot(
        &runtime_height, runtime_hash.data) && runtime_height == height &&
        !uint256_is_null(&runtime_hash);
    if (runtime_known) {
        *hash = runtime_hash;
        *source = CHAIN_FRONTIER_AUTHORITY_RUNTIME_PUBLICATION;
    }

    /* Operator/agent collection is total and latency-bounded. A reducer batch
     * may legitimately own progress_store_tx_lock across durable event writes;
     * never queue an RPC behind that batch. Opportunistically upgrade the
     * already-exact runtime pair to durable evidence only when the singleton
     * handle is immediately available. tip_finalize_stage_block_hash_at takes
     * the same recursive lock internally, so the successful trylock brackets
     * the shared SQLite handle safely. */
    sqlite3 *db = progress_store_db();
    if (db && progress_store_tx_trylock()) {
        bool durable_known = tip_finalize_stage_block_hash_at(
            db, height, durable_hash.data) && !uint256_is_null(&durable_hash);
        progress_store_tx_unlock();
        if (durable_known) {
            *hash = durable_hash;
            *durable = true;
            *source = CHAIN_FRONTIER_AUTHORITY_DURABLE_TIP_FINALIZE_LOG;
            return true;
        }
    }

    if (runtime_known)
        return true;
    uint256_set_null(hash);
    return false;
}

static bool chain_frontier_ancestor_relation(
    struct block_index *lower,
    struct block_index *higher,
    bool *known)
{
    *known = false;
    if (!lower || !higher || !lower->phashBlock || !higher->phashBlock ||
        lower->nHeight < 0 || higher->nHeight < lower->nHeight)
        return false;
    struct block_index *ancestor = block_index_get_ancestor(
        higher, lower->nHeight);
    if (!ancestor || !ancestor->phashBlock)
        return false;
    *known = true;
    return uint256_eq(ancestor->phashBlock, lower->phashBlock);
}

void chain_frontier_snapshot_collect(struct chain_frontier_snapshot *out,
                                     struct main_state *main)
{
    if (!out)
        return;
    struct chain_frontier_snapshot snapshot = {0};
    snapshot.hstar_published =
        reducer_frontier_provable_tip_is_published();
    int32_t hstar = reducer_frontier_provable_tip_cached();
    snapshot.served.height_known = snapshot.hstar_published;
    snapshot.served.height = hstar;
    if (!main) {
        *out = snapshot;
        return;
    }

    struct uint256 authority_hash;
    uint256_set_null(&authority_hash);
    if (snapshot.hstar_published) {
        snapshot.authority_pair_known = chain_frontier_read_authority(
            hstar, &authority_hash, &snapshot.durable_authority_known,
            &snapshot.authority_source);
    }

    struct chain_state_frontier_view view;
    snapshot.context_known = csr_capture_frontiers(
        csr_instance(), &main->chain_active, &main->pindex_best_header,
        hstar, &view).ok;
    if (!snapshot.context_known) {
        *out = snapshot;
        return;
    }

    struct block_index *served = view.window.requested;
    struct block_index *indexed = view.window.tip;
    struct block_index *header = view.header_tip;
    chain_frontier_value_from_index(&snapshot.served, served,
                                    BLOCK_VALID_SCRIPTS);
    chain_frontier_value_from_index(&snapshot.indexed, indexed,
                                    BLOCK_VALID_TREE);
    chain_frontier_value_from_index(&snapshot.header, header,
                                    BLOCK_VALID_TREE);
    if (snapshot.hstar_published) {
        snapshot.served.height_known = true;
        snapshot.served.height = hstar;
    }
    snapshot.authority_matches_served = snapshot.authority_pair_known &&
        served && served->nHeight == hstar && served->phashBlock &&
        uint256_eq(&authority_hash, served->phashBlock);
    if (!snapshot.authority_matches_served)
        snapshot.served.binding_known = false;

    bool served_indexed_known = false;
    bool indexed_header_known = false;
    snapshot.served_ancestor_indexed = chain_frontier_ancestor_relation(
        served, indexed, &served_indexed_known);
    snapshot.indexed_ancestor_header = chain_frontier_ancestor_relation(
        indexed, header, &indexed_header_known);
    snapshot.ancestry_known = served_indexed_known && indexed_header_known;
    snapshot.work_known = served && indexed && header &&
        !arith_uint256_is_zero(&served->nChainWork) &&
        !arith_uint256_is_zero(&indexed->nChainWork) &&
        !arith_uint256_is_zero(&header->nChainWork);
    int served_indexed_work = snapshot.work_known
        ? arith_uint256_compare(&served->nChainWork, &indexed->nChainWork) : 0;
    int indexed_header_work = snapshot.work_known
        ? arith_uint256_compare(&indexed->nChainWork, &header->nChainWork) : 0;
    snapshot.work_monotone = snapshot.work_known &&
        (served->nHeight == indexed->nHeight
            ? served_indexed_work == 0 : served_indexed_work < 0) &&
        (indexed->nHeight == header->nHeight
            ? indexed_header_work == 0 : indexed_header_work < 0);
    snapshot.validity_known = snapshot.served.status_known &&
        snapshot.indexed.status_known && snapshot.header.status_known;
    snapshot.validity_sufficient = snapshot.validity_known &&
        snapshot.served.validity_sufficient &&
        snapshot.indexed.validity_sufficient &&
        snapshot.header.validity_sufficient;
    snapshot.failure_free = snapshot.validity_known &&
        snapshot.served.failure_free && snapshot.indexed.failure_free &&
        snapshot.header.failure_free;
    *out = snapshot;
}

static bool chain_frontier_value_equal(const struct chain_frontier_value *a,
                                       const struct chain_frontier_value *b)
{
    return a->height_known == b->height_known &&
           a->binding_known == b->binding_known &&
           a->status_known == b->status_known &&
           a->validity_sufficient == b->validity_sufficient &&
           a->failure_free == b->failure_free &&
           a->height == b->height && strcmp(a->hash, b->hash) == 0 &&
           a->status == b->status &&
           strcmp(a->chain_work, b->chain_work) == 0;
}

bool chain_frontier_snapshot_equal(const struct chain_frontier_snapshot *a,
                                   const struct chain_frontier_snapshot *b)
{
    return a && b && a->context_known == b->context_known &&
        a->hstar_published == b->hstar_published &&
        a->authority_pair_known == b->authority_pair_known &&
        a->durable_authority_known == b->durable_authority_known &&
        a->authority_matches_served == b->authority_matches_served &&
        a->authority_source == b->authority_source &&
        a->ancestry_known == b->ancestry_known &&
        a->served_ancestor_indexed == b->served_ancestor_indexed &&
        a->indexed_ancestor_header == b->indexed_ancestor_header &&
        a->work_known == b->work_known &&
        a->work_monotone == b->work_monotone &&
        a->validity_known == b->validity_known &&
        a->validity_sufficient == b->validity_sufficient &&
        a->failure_free == b->failure_free &&
        chain_frontier_value_equal(&a->served, &b->served) &&
        chain_frontier_value_equal(&a->indexed, &b->indexed) &&
        chain_frontier_value_equal(&a->header, &b->header);
}

bool chain_frontier_snapshot_values_known(
    const struct chain_frontier_snapshot *snapshot)
{
    return snapshot && snapshot->context_known &&
        snapshot->served.height_known && snapshot->indexed.height_known &&
        snapshot->header.height_known;
}

bool chain_frontier_snapshot_bindings_known(
    const struct chain_frontier_snapshot *snapshot)
{
    return chain_frontier_snapshot_values_known(snapshot) &&
        snapshot->served.binding_known && snapshot->indexed.binding_known &&
        snapshot->header.binding_known;
}

bool chain_frontier_snapshot_consistent(
    const struct chain_frontier_snapshot *snapshot)
{
    return chain_frontier_snapshot_bindings_known(snapshot) &&
        snapshot->authority_pair_known && snapshot->durable_authority_known &&
        snapshot->authority_matches_served && snapshot->ancestry_known &&
        snapshot->served_ancestor_indexed &&
        snapshot->indexed_ancestor_header && snapshot->work_known &&
        snapshot->work_monotone && snapshot->validity_known &&
        snapshot->validity_sufficient && snapshot->failure_free;
}

bool chain_frontier_snapshot_clean_genesis(
    const struct chain_frontier_snapshot *snapshot)
{
    /* Mirror chain_frontier_snapshot_consistent gate-for-gate, swapping the
     * durable-authority requirement for a genuine RUNTIME authority at served
     * H* = genesis (0). Genesis finality is a compiled constant, so a runtime
     * (not-yet-durable) authority for it is sound; a mid-fold node (H* > 0) or a
     * NONE/DURABLE-sourced authority is never clean-genesis here. */
    return snapshot && snapshot->served.height_known &&
        snapshot->served.height == 0 &&
        chain_frontier_snapshot_bindings_known(snapshot) &&
        snapshot->authority_pair_known && snapshot->authority_matches_served &&
        snapshot->authority_source ==
            CHAIN_FRONTIER_AUTHORITY_RUNTIME_PUBLICATION &&
        snapshot->ancestry_known && snapshot->served_ancestor_indexed &&
        snapshot->indexed_ancestor_header && snapshot->work_known &&
        snapshot->work_monotone && snapshot->validity_known &&
        snapshot->validity_sufficient && snapshot->failure_free;
}

const char *chain_frontier_authority_source_name(
    enum chain_frontier_authority_source source)
{
    switch (source) {
    case CHAIN_FRONTIER_AUTHORITY_RUNTIME_PUBLICATION:
        return "tip_finalize_runtime_publication";
    case CHAIN_FRONTIER_AUTHORITY_DURABLE_TIP_FINALIZE_LOG:
        return "durable_tip_finalize_log";
    case CHAIN_FRONTIER_AUTHORITY_NONE:
        return "unavailable";
    }
    return "unavailable";
}
