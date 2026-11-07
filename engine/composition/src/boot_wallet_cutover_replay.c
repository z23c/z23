/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: startup coordination of checkpoint wallet replay phases. */
#include "config/boot_wallet_cutover_replay.h"
#include "controllers/wallet_helpers.h"
#include "services/node_db_catchup_wallet_replay.h"
#include "services/node_db_catchup_wallet_transparent.h"
#include "validation/main_state.h"
#include <limits.h>
#include <string.h>

static bool bcr_chain_current(struct boot_cutover_replay *r)
{
    struct main_state *ms = r->ctx->main_state;
    if (!zcl_mutex_trylock(&ms->cs_main)) return false;
    struct block_index *tip = active_chain_at(&ms->chain_active, r->endpoint.height);
    struct block_index *target = active_chain_at(&ms->chain_active, r->binding.target_height);
    bool ok = tip && tip->phashBlock && target && target->phashBlock &&
        !memcmp(tip->phashBlock->data, r->endpoint.hash.data, 32) &&
        !memcmp(tip->hashFinalSaplingRoot.data, r->endpoint.root.data, 32) &&
        !memcmp(target->phashBlock->data, r->binding.target_hash, 32) &&
        block_index_get_ancestor(tip, r->binding.target_height) == target;
    zcl_mutex_unlock(&ms->cs_main);
    return ok;
}

static bool bcr_current(struct boot_cutover_replay *r)
{
    struct wallet_readiness before = wallet_readiness_get(r->ctx->wallet);
    struct wallet_cutover_binding binding;
    uint8_t identity[32];
    if (before.state != WALLET_READINESS_PENDING || before.epoch == UINT64_MAX ||
        before.epoch != r->readiness.epoch ||
        before.generation_present != r->readiness.generation_present ||
        before.generation != r->readiness.generation ||
        wallet_sqlite_cutover_read(r->ctx->wallet_db, &binding) != WALLET_CUTOVER_PENDING ||
        !wallet_cutover_binding_equal(&binding, &r->binding) || !bcr_chain_current(r) ||
        !wallet_scan_identity(r->ctx->wallet, identity) || memcmp(identity, r->identity, 32))
        return false;
    struct wallet_readiness after = wallet_readiness_get(r->ctx->wallet);
    return after.state == WALLET_READINESS_PENDING && after.epoch == before.epoch &&
        after.generation_present == before.generation_present && after.generation == before.generation;
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
    struct transparent_replay_result out = node_db_catchup_wallet_transparent(
        r->ctx->main_state, r->ctx->wallet, r->ctx->datadir, r->next, end,
        r->endpoint.height, r->endpoint.hash.data, r->identity);
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
        r->ctx->datadir, r->next, end, r->endpoint.height, r->endpoint.hash.data,
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
    return wallet_rescan_witnesses_at(r->ctx, &r->endpoint, &out) &&
        out.status == WALLET_WITNESS_COMPLETE && out.endpoint_height == r->endpoint.height &&
        !memcmp(out.endpoint_hash.data, r->endpoint.hash.data, 32) &&
        !memcmp(out.endpoint_root.data, r->endpoint.root.data, 32) &&
        out.notes_total == out.witnesses_saved;
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
    int end = r->endpoint.height - r->next >= 255 ? r->next + 255 : r->endpoint.height;
    bool ok = r->phase == BOOT_CUTOVER_TRANSPARENT ? bcr_transparent(r, end) :
        r->phase == BOOT_CUTOVER_WITNESS ? bcr_witness(r) : bcr_sapling(r, end);
    if (!bcr_current(r)) { r->phase = BOOT_CUTOVER_INVALIDATED; return BOOT_CUTOVER_STALE; }
    if (!ok) return BOOT_CUTOVER_RETRY;
    if (r->phase != BOOT_CUTOVER_WITNESS && end < r->endpoint.height) r->next = end + 1;
    else { r->phase++; r->next = r->floor; }
    return r->phase == BOOT_CUTOVER_DONE ? BOOT_CUTOVER_COMPLETE : BOOT_CUTOVER_PROGRESS;
}
