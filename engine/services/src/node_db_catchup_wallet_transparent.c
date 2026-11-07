/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: bounded transparent wallet replay against an authenticated endpoint. */
#include "services/node_db_catchup_wallet_transparent.h"
#include "node_db_catchup_internal.h"
#include "primitives/block.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"
#include "wallet/wallet_transparent_replay.h"
#include <string.h>
#include <limits.h>

#define TRANSPARENT_REPLAY_MAX_BLOCKS 256

struct transparent_location {
    int file;
    unsigned int offset;
    struct uint256 hash;
};

static enum transparent_replay_status transparent_snapshot(
    struct main_state *state, int height, int end, const struct uint256 *endpoint,
    struct transparent_location *loc)
{
    if (!zcl_mutex_trylock(&state->cs_main)) return TRANSPARENT_REPLAY_BUSY;
    const struct block_index *p = active_chain_at(&state->chain_active, height);
    const struct block_index *e = active_chain_at(&state->chain_active, end);
    enum transparent_replay_status status = TRANSPARENT_REPLAY_INCOMPLETE;
    if (e && e->phashBlock && !uint256_eq(e->phashBlock, endpoint))
        status = TRANSPARENT_REPLAY_CHAIN_CHANGED;
    else if (p && p->phashBlock && e && e->phashBlock && p->nFile >= 0) {
        loc->file = p->nFile; loc->offset = p->nDataPos; loc->hash = *p->phashBlock;
        status = TRANSPARENT_REPLAY_COMPLETE;
    }
    zcl_mutex_unlock(&state->cs_main);
    return status;
}

struct transparent_apply {
    struct main_state *state;
    struct wallet *wallet;
    struct block *block;
    const struct transparent_location *loc;
    const struct uint256 *endpoint;
    const uint8_t *identity;
    int height, end, reference_height;
};

static bool transparent_chain_current(const struct transparent_apply *a)
{
    const struct block_index *p = active_chain_at(&a->state->chain_active, a->height);
    const struct block_index *e = active_chain_at(&a->state->chain_active, a->reference_height);
    return p && p->phashBlock && uint256_eq(p->phashBlock, &a->loc->hash) &&
           e && e->phashBlock && uint256_eq(e->phashBlock, a->endpoint);
}

static enum transparent_replay_status transparent_fold(const struct transparent_apply *a)
{
    uint8_t identity[32];
    if (wallet_readiness_get_locked(a->wallet).state != WALLET_READINESS_PENDING)
        return TRANSPARENT_REPLAY_WALLET_ERROR;
    if (!transparent_chain_current(a)) return TRANSPARENT_REPLAY_CHAIN_CHANGED;
    if (!wallet_scan_identity_locked(a->wallet, identity) || memcmp(identity, a->identity, 32))
        return TRANSPARENT_REPLAY_KEYS_CHANGED;
    int tip = a->reference_height;
    if (tip < a->height || tip - a->height == INT_MAX) return TRANSPARENT_REPLAY_CHAIN_CHANGED;
    int depth = tip - a->height + 1;
    for (size_t i = 0; i < a->block->num_vtx; i++)
        if (wallet_transparent_fold_locked(a->wallet, &a->block->vtx[i], &a->loc->hash, depth) ==
            WALLET_TRANSPARENT_ERROR) return TRANSPARENT_REPLAY_WALLET_ERROR;
    return TRANSPARENT_REPLAY_COMPLETE;
}

static enum transparent_replay_status transparent_apply_block(const struct transparent_apply *a)
{
    if (!zcl_mutex_trylock(&a->state->cs_main)) return TRANSPARENT_REPLAY_BUSY;
    bool w = zcl_mutex_trylock(&a->wallet->cs);
    bool k = w && zcl_mutex_trylock(&a->wallet->keystore.cs);
    bool s = k && zcl_mutex_trylock(&a->wallet->sapling_keys.cs);
    enum transparent_replay_status status = s ? transparent_fold(a) : TRANSPARENT_REPLAY_BUSY;
    if (s) zcl_mutex_unlock(&a->wallet->sapling_keys.cs);
    if (k) zcl_mutex_unlock(&a->wallet->keystore.cs);
    if (w) zcl_mutex_unlock(&a->wallet->cs);
    zcl_mutex_unlock(&a->state->cs_main);
    return status;
}

static enum transparent_replay_status transparent_one(struct transparent_apply *a,
                                                        const char *datadir)
{
    struct transparent_location loc;
    enum transparent_replay_status status = transparent_snapshot(
        a->state, a->height, a->reference_height, a->endpoint, &loc);
    if (status != TRANSPARENT_REPLAY_COMPLETE) return status;
    struct block block;
    block_init(&block);
    struct zcl_result read_result = node_db_catchup_read_authenticated_block(
        datadir, loc.file, loc.offset, &loc.hash, &block);
    if (!read_result.ok) status = TRANSPARENT_REPLAY_INCOMPLETE;
    else { a->loc = &loc; a->block = &block; status = transparent_apply_block(a); }
    block_free(&block);
    return status;
}

struct transparent_replay_result node_db_catchup_wallet_transparent(
    struct main_state *state, struct wallet *wallet, const char *datadir,
    int start, int end, int reference_height, const uint8_t endpoint_hash[32], const uint8_t scan_identity[32])
{
    struct transparent_replay_result result = {.status = TRANSPARENT_REPLAY_INVALID,
        .start_height = start, .end_height = end, .reference_height = reference_height, .last_complete = -1};
    if (!state || !wallet || !datadir || !datadir[0] || !endpoint_hash || !scan_identity ||
        start < 0 || end < start || reference_height < end || reference_height - start == INT_MAX ||
        end - start >= TRANSPARENT_REPLAY_MAX_BLOCKS)
        return result;
    result.last_complete = start - 1;
    memcpy(result.endpoint_hash, endpoint_hash, 32);
    memcpy(result.scan_identity, scan_identity, 32);
    struct uint256 endpoint;
    memcpy(endpoint.data, endpoint_hash, 32);
    struct transparent_apply a = {.state = state, .wallet = wallet, .end = end, .reference_height = reference_height,
        .endpoint = &endpoint, .identity = scan_identity};
    for (int h = start;; h++) {
        a.height = h;
        result.status = transparent_one(&a, datadir);
        if (result.status != TRANSPARENT_REPLAY_COMPLETE) break;
        result.last_complete = h;
        if (h == end) break;
    }
    return result;
}
