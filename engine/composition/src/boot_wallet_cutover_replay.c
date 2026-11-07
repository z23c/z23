/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: startup coordination of checkpoint wallet replay phases. */
#include "config/boot_wallet_cutover_replay.h"
#include "boot_wallet_cutover_empty_internal.h"
#include "models/database.h"
#include "controllers/wallet_helpers.h"
#include "services/node_db_catchup_wallet_replay.h"
#include "services/node_db_catchup_wallet_transparent_startup.h"
#include "validation/main_state.h"
#include <limits.h>
#include <string.h>

static bool bcr_chain_matches(const struct boot_cutover_replay *r, struct main_state *ms, bool exact_tip)
{
    struct block_index *tip = active_chain_at(&ms->chain_active, r->endpoint.height);
    struct block_index *target = active_chain_at(&ms->chain_active, r->binding.target_height);
    bool ok = tip && tip->phashBlock && target && target->phashBlock &&
        !memcmp(tip->phashBlock->data, r->endpoint.hash.data, 32) &&
        !memcmp(tip->hashFinalSaplingRoot.data, r->endpoint.root.data, 32) &&
        !memcmp(target->phashBlock->data, r->binding.target_hash, 32) &&
        block_index_get_ancestor(tip, r->binding.target_height) == target;
    return ok && (!exact_tip || active_chain_tip(&ms->chain_active) == tip);
}

static bool bcr_chain_locked(const struct boot_cutover_replay *r, struct main_state *ms, bool exact_tip)
{
    if (!zcl_mutex_trylock(&ms->cs_main)) return false;
    bool ok = bcr_chain_matches(r, ms, exact_tip);
    zcl_mutex_unlock(&ms->cs_main);
    return ok;
}

bool boot_cutover_replay_archive_chains_current(const struct boot_cutover_replay *r)
{
    return r && r->ctx && r->ctx->main_state && r->canonical_state &&
        bcr_chain_matches(r, r->ctx->main_state, true) &&
        bcr_chain_matches(r, r->canonical_state, true);
}

static bool bcr_readiness_matches(const struct wallet_readiness *a,
                                  const struct wallet_readiness *b)
{
    return a->state == WALLET_READINESS_PENDING && a->epoch != UINT64_MAX &&
        a->epoch == b->epoch && a->generation_present == b->generation_present &&
        a->generation == b->generation;
}

static bool bcr_current(struct boot_cutover_replay *r)
{
    struct wallet_readiness before = wallet_readiness_get(r->ctx->wallet);
    struct wallet_cutover_binding binding;
    uint8_t identity[32];
    if (!bcr_readiness_matches(&before, &r->readiness) ||
        wallet_sqlite_cutover_read(r->ctx->wallet_db, &binding) != WALLET_CUTOVER_PENDING ||
        !wallet_cutover_binding_equal(&binding, &r->binding) || !bcr_chain_locked(r, r->ctx->main_state, r->canonical_state != NULL) ||
        (r->canonical_state && r->canonical_state != r->ctx->main_state &&
         !bcr_chain_locked(r, r->canonical_state, true)) ||
        !wallet_scan_identity(r->ctx->wallet, identity) || memcmp(identity, r->identity, 32))
        return false;
    struct wallet_readiness after = wallet_readiness_get(r->ctx->wallet);
    return bcr_readiness_matches(&after, &before);
}

static bool bcr_args_valid(struct boot_cutover_replay *r,
    struct wallet_rpc_context *ctx, struct db_service *service,
    const struct wallet_cutover_binding *binding, int floor,
    const struct wallet_witness_endpoint *endpoint, const uint8_t identity[32])
{
    return r && ctx && ctx->wallet && ctx->wallet_db && ctx->node_db &&
        ctx->main_state && ctx->datadir && service && binding && endpoint &&
        identity && binding->target_height >= 0 && floor >= 0 &&
        endpoint->height >= floor && endpoint->height >= binding->target_height;
}

bool boot_cutover_replay_init(struct boot_cutover_replay *r,
    struct wallet_rpc_context *ctx, struct db_service *service,
    const struct wallet_cutover_binding *binding, int floor,
    const struct wallet_witness_endpoint *endpoint, const uint8_t identity[32])
{
    if (r) r->phase = BOOT_CUTOVER_INVALIDATED;
    if (!bcr_args_valid(r, ctx, service, binding, floor, endpoint, identity)) return false;
    memset(r, 0, sizeof(*r));
    r->ctx = ctx; r->service = service; r->binding = *binding;
    r->endpoint = *endpoint; r->floor = floor; r->next = floor;
    r->readiness = wallet_readiness_get(ctx->wallet);
    memcpy(r->identity, identity, 32);
    if (bcr_current(r)) return true;
    r->phase = BOOT_CUTOVER_INVALIDATED;
    return false;
}

bool boot_cutover_replay_init_archive(struct boot_cutover_replay *r,
    struct wallet_rpc_context *ctx, struct db_service *service,
    const struct wallet_cutover_binding *binding, int floor,
    const struct wallet_witness_endpoint *endpoint, const uint8_t identity[32],
    struct main_state *canonical_state, const char *archive_datadir)
{
    if (r) r->phase = BOOT_CUTOVER_INVALIDATED;
    if (!canonical_state || !ctx || canonical_state == ctx->main_state || !archive_datadir || !archive_datadir[0] ||
        strlen(archive_datadir) >= sizeof(r->archive_datadir) - sizeof("/blocks/blk00000.dat") ||
        !boot_cutover_replay_init(r, ctx, service, binding, floor, endpoint, identity))
        return false;
    r->canonical_state = canonical_state;
    memcpy(r->archive_datadir, archive_datadir, strlen(archive_datadir) + 1);
    if (bcr_current(r)) return true;
    r->phase = BOOT_CUTOVER_INVALIDATED;
    return false;
}

static const char *bcr_body_dir(const struct boot_cutover_replay *r)
{
    return r->canonical_state ? r->archive_datadir : r->ctx->datadir;
}

static bool bcr_chunk_endpoint(struct boot_cutover_replay *r, int end, uint8_t hash[32])
{
    struct main_state *ms = r->ctx->main_state;
    if (!zcl_mutex_trylock(&ms->cs_main)) return false;
    const struct block_index *ref = active_chain_at(&ms->chain_active, r->endpoint.height);
    const struct block_index *p = active_chain_at(&ms->chain_active, end);
    bool ok = ref && ref->phashBlock && p && p->phashBlock &&
        !memcmp(ref->phashBlock->data, r->endpoint.hash.data, 32);
    if (ok) memcpy(hash, p->phashBlock->data, 32);
    zcl_mutex_unlock(&ms->cs_main);
    return ok;
}

static bool bcr_transparent(struct boot_cutover_replay *r, int end)
{
    if (!r->transparent_filter_attempted) {
        r->transparent_filter_attempted = true;
        r->transparent_filter = transparent_replay_filter_new(r->ctx->wallet);
    }
    struct transparent_replay_result out = node_db_catchup_wallet_transparent_indexed(
        r->ctx->main_state, r->ctx->wallet, bcr_body_dir(r), r->next, end,
        r->endpoint.height, r->endpoint.hash.data, r->identity, r->transparent_filter);
    return out.status == TRANSPARENT_REPLAY_COMPLETE && out.start_height == r->next &&
        out.end_height == end && out.reference_height == r->endpoint.height &&
        out.last_complete == end && !memcmp(out.endpoint_hash, r->endpoint.hash.data, 32) &&
        !memcmp(out.scan_identity, r->identity, 32);
}

static bool bcr_sapling_receipt(struct boot_cutover_replay *r, int end,
    enum sapling_replay_phase phase, const uint8_t hash[32],
    const struct sapling_replay_result *out)
{
    return out->status == SAPLING_REPLAY_COMPLETE && out->phase == phase &&
        out->start_height == r->next && out->end_height == end && out->last_complete == end &&
        out->reference_height == r->endpoint.height && !memcmp(out->endpoint_hash, hash, 32) &&
        !memcmp(out->reference_hash, r->endpoint.hash.data, 32) && !memcmp(out->scan_identity, r->identity, 32);
}

static bool bcr_sapling(struct boot_cutover_replay *r, int end)
{
    uint8_t hash[32];
    if (!bcr_chunk_endpoint(r, end, hash)) return false;
    enum sapling_replay_phase phase = r->phase == BOOT_CUTOVER_DISCOVER ?
        SAPLING_REPLAY_DISCOVER : SAPLING_REPLAY_SPENDS;
    struct sapling_replay_result out = node_db_catchup_sapling_replay_at_reference(
        r->service, r->ctx->node_db, r->ctx->main_state, r->ctx->wallet,
        bcr_body_dir(r), r->next, end, r->endpoint.height, r->endpoint.hash.data,
        phase, hash, r->identity, phase == SAPLING_REPLAY_SPENDS ? r->key_digest : NULL);
    if (!bcr_sapling_receipt(r, end, phase, hash, &out)) return false;
    if (phase == SAPLING_REPLAY_DISCOVER) {
        if (r->next != r->floor && memcmp(r->key_digest, out.key_digest, 32)) return false;
        memcpy(r->key_digest, out.key_digest, 32);
    }
    return true;
}

static bool bcr_witness(struct boot_cutover_replay *r)
{
    struct wallet_witness_outcome out = {0};
    bool ok = r->canonical_state ?
        wallet_rescan_witnesses_at_archive(r->ctx, &r->endpoint, r->archive_datadir, &out) :
        wallet_rescan_witnesses_at(r->ctx, &r->endpoint, &out);
    return ok &&
        out.status == WALLET_WITNESS_COMPLETE && out.endpoint_height == r->endpoint.height &&
        !memcmp(out.endpoint_hash.data, r->endpoint.hash.data, 32) &&
        !memcmp(out.endpoint_root.data, r->endpoint.root.data, 32) &&
        out.notes_total == out.witnesses_saved;
}

void boot_cutover_replay_clear(struct boot_cutover_replay *r)
{
    if (!r) return;
    transparent_replay_filter_free(r->transparent_filter);
    r->transparent_filter = NULL;
}

static bool bcr_shielded_empty(struct boot_cutover_replay *r)
{
    sqlite3 *db = r->ctx->node_db->db;
    sqlite3_mutex *mu = db ? sqlite3_db_mutex(db) : NULL;
    if (!mu || sqlite3_mutex_try(mu) != SQLITE_OK) return false;
    bool locked = zcl_mutex_trylock(&r->ctx->wallet->sapling_keys.cs);
    bool empty = locked && boot_wallet_cutover_shielded_empty_locked(
        r->ctx->wallet_db, db, r->ctx->wallet, r->sapling_load_ok);
    if (locked) zcl_mutex_unlock(&r->ctx->wallet->sapling_keys.cs);
    sqlite3_mutex_leave(mu);
    return empty;
}

static bool bcr_can_complete_empty(struct boot_cutover_replay *r)
{
    return r->phase == BOOT_CUTOVER_DISCOVER && bcr_shielded_empty(r);
}

static enum boot_cutover_replay_status bcr_complete_empty(struct boot_cutover_replay *r)
{
    r->shielded_empty = true;
    if (!bcr_current(r)) { r->phase = BOOT_CUTOVER_INVALIDATED; return BOOT_CUTOVER_STALE; }
    r->phase = BOOT_CUTOVER_DONE;
    return BOOT_CUTOVER_COMPLETE;
}

enum boot_cutover_replay_status boot_cutover_replay_step(struct boot_cutover_replay *r)
{
    if (!r) return BOOT_CUTOVER_INVALID;
    if (r->phase == BOOT_CUTOVER_INVALIDATED) return BOOT_CUTOVER_STALE;
    if (!r->ctx) return BOOT_CUTOVER_INVALID;
    if (!bcr_current(r)) {
        r->phase = BOOT_CUTOVER_INVALIDATED; return BOOT_CUTOVER_STALE;
    }
    if (r->phase == BOOT_CUTOVER_DONE) return BOOT_CUTOVER_COMPLETE;
    if (bcr_can_complete_empty(r)) return bcr_complete_empty(r);
    int end = r->endpoint.height - r->next >= 255 ? r->next + 255 : r->endpoint.height;
    bool ok = r->phase == BOOT_CUTOVER_TRANSPARENT ? bcr_transparent(r, end) :
        r->phase == BOOT_CUTOVER_WITNESS ? bcr_witness(r) : bcr_sapling(r, end);
    if (!bcr_current(r)) { r->phase = BOOT_CUTOVER_INVALIDATED; return BOOT_CUTOVER_STALE; }
    if (!ok) return BOOT_CUTOVER_RETRY;
    if (r->phase != BOOT_CUTOVER_WITNESS && end < r->endpoint.height) r->next = end + 1;
    else { r->phase++; r->next = r->floor; }
    return r->phase == BOOT_CUTOVER_DONE ? BOOT_CUTOVER_COMPLETE : BOOT_CUTOVER_PROGRESS;
}
