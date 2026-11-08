/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: startup coordination of checkpoint wallet replay phases. */
#include "config/boot_wallet_cutover_replay.h"
#include "boot_wallet_cutover_empty_internal.h"
#include "models/database.h"
#include "wallet/wallet_lock.h"
#include "controllers/wallet_helpers.h"
#include "services/node_db_catchup_wallet_replay.h"
#include "services/node_db_catchup_wallet_transparent_startup.h"
#include "util/log_macros.h"
#include "validation/main_state.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifdef ZCL_TESTING
static void (*bcr_test_after_current)(void *), (*bcr_test_before_postcheck)(void *);
static void *bcr_test_after_current_ctx, *bcr_test_before_postcheck_ctx;
void boot_cutover_replay_test_before_postcheck(void (*hook)(void *), void *ctx)
{
    bcr_test_before_postcheck = hook; bcr_test_before_postcheck_ctx = ctx;
}
void boot_cutover_replay_test_after_current(void (*hook)(void *), void *ctx)
{
    bcr_test_after_current = hook; bcr_test_after_current_ctx = ctx;
}
#endif

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

static enum boot_cutover_replay_status bcr_chain_locked(
    const struct boot_cutover_replay *r, struct main_state *ms, bool exact_tip)
{
    if (!zcl_mutex_trylock(&ms->cs_main)) return BOOT_CUTOVER_BUSY;
    bool ok = bcr_chain_matches(r, ms, exact_tip);
    zcl_mutex_unlock(&ms->cs_main);
    return ok ? BOOT_CUTOVER_PROGRESS : BOOT_CUTOVER_STALE;
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

static enum boot_cutover_replay_status bcr_current(struct boot_cutover_replay *r)
{
    struct wallet_readiness before = wallet_readiness_get(r->ctx->wallet);
    struct wallet_cutover_binding binding;
    uint8_t identity[32];
    if (!bcr_readiness_matches(&before, &r->readiness) ||
        wallet_sqlite_cutover_read(r->ctx->wallet_db, &binding) != WALLET_CUTOVER_PENDING ||
        !wallet_cutover_binding_equal(&binding, &r->binding)) return BOOT_CUTOVER_STALE;
    enum boot_cutover_replay_status state = bcr_chain_locked(r, r->ctx->main_state, r->canonical_state != NULL);
    if (state != BOOT_CUTOVER_PROGRESS) return state;
    if (r->canonical_state && r->canonical_state != r->ctx->main_state) {
        state = bcr_chain_locked(r, r->canonical_state, true);
        if (state != BOOT_CUTOVER_PROGRESS) return state;
    }
    if (!wallet_scan_identity(r->ctx->wallet, identity) || memcmp(identity, r->identity, 32))
        return BOOT_CUTOVER_STALE;
    struct wallet_readiness after = wallet_readiness_get(r->ctx->wallet);
    return bcr_readiness_matches(&after, &before) ? BOOT_CUTOVER_PROGRESS : BOOT_CUTOVER_STALE;
}

bool boot_cutover_replay_current_locked(const struct boot_cutover_replay *r)
{
    if (!r || !r->ctx || !r->ctx->wallet || !r->ctx->main_state) return false;
    struct wallet_readiness ready = wallet_readiness_get_locked(r->ctx->wallet);
    uint8_t identity[32];
    if (!bcr_readiness_matches(&ready, &r->readiness) ||
        !wallet_scan_identity_locked(r->ctx->wallet, identity) ||
        memcmp(identity, r->identity, 32) ||
        !bcr_chain_matches(r, r->ctx->main_state, r->canonical_state != NULL)) return false;
    return !r->canonical_state || r->canonical_state == r->ctx->main_state ||
        bcr_chain_matches(r, r->canonical_state, true);
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
    if (bcr_current(r) == BOOT_CUTOVER_PROGRESS) return true;
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
    if (bcr_current(r) == BOOT_CUTOVER_PROGRESS) return true;
    r->phase = BOOT_CUTOVER_INVALIDATED;
    return false;
}

static const char *bcr_body_dir(const struct boot_cutover_replay *r)
{
    return r->canonical_state ? r->archive_datadir : r->ctx->datadir;
}

static enum boot_cutover_replay_status bcr_chunk_endpoint(struct boot_cutover_replay *r, int end, uint8_t hash[32])
{
    struct main_state *ms = r->ctx->main_state;
    if (!zcl_mutex_trylock(&ms->cs_main)) return BOOT_CUTOVER_BUSY;
    const struct block_index *ref = active_chain_at(&ms->chain_active, r->endpoint.height);
    const struct block_index *p = active_chain_at(&ms->chain_active, end);
    bool ok = ref && ref->phashBlock && p && p->phashBlock &&
        !memcmp(ref->phashBlock->data, r->endpoint.hash.data, 32);
    if (ok) memcpy(hash, p->phashBlock->data, 32);
    zcl_mutex_unlock(&ms->cs_main);
    return ok ? BOOT_CUTOVER_PROGRESS : BOOT_CUTOVER_RETRY;
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

static void bcr_sapling_receipt_warn(const struct boot_cutover_replay *r, int end,
    enum sapling_replay_phase phase, const uint8_t hash[32], const struct sapling_replay_result *out)
{
    LOG_WARN("wallet", "Sapling replay receipt refused: status=%d phase=%d expected_phase=%d "
             "start=%d end=%d last_complete=%d reference=%d expected_reference=%d "
             "start_match=%d end_match=%d endpoint_match=%d reference_match=%d identity_match=%d",
             (int)out->status, (int)out->phase, (int)phase, out->start_height, out->end_height,
             out->last_complete, out->reference_height, r->endpoint.height,
             out->start_height == r->next, out->end_height == end,
             !memcmp(out->endpoint_hash, hash, 32), !memcmp(out->reference_hash, r->endpoint.hash.data, 32),
             !memcmp(out->scan_identity, r->identity, 32));
}

static bool bcr_sapling_partial_receipt(
    const struct boot_cutover_replay *r, int end, enum sapling_replay_phase phase,
    const uint8_t hash[32], const struct sapling_replay_result *out)
{
    return out->phase == phase && out->start_height == r->next &&
        out->end_height == end && out->last_complete >= r->next - 1 &&
        (out->last_complete < end ||
         (out->status == SAPLING_REPLAY_STOPPED && out->last_complete == end)) &&
        out->reference_height == r->endpoint.height &&
        !memcmp(out->endpoint_hash, hash, 32) &&
        !memcmp(out->reference_hash, r->endpoint.hash.data, 32) &&
        !memcmp(out->scan_identity, r->identity, 32);
}

static enum boot_cutover_replay_status bcr_sapling_busy(
    struct boot_cutover_replay *r, int end, enum sapling_replay_phase phase,
    const uint8_t hash[32], const struct sapling_replay_result *out)
{
    if (!bcr_sapling_partial_receipt(r, end, phase, hash, out)) return BOOT_CUTOVER_RETRY;
    if (phase == SAPLING_REPLAY_DISCOVER && r->next != r->floor &&
        memcmp(r->key_digest, out->key_digest, 32)) return BOOT_CUTOVER_RETRY;
    if (out->last_complete >= r->next) {
        if (phase == SAPLING_REPLAY_DISCOVER) memcpy(r->key_digest, out->key_digest, 32);
        r->next = out->last_complete + 1;
    }
    return BOOT_CUTOVER_BUSY;
}

static const uint8_t *bcr_expected_key_digest(const struct boot_cutover_replay *r,
                                               enum sapling_replay_phase phase)
{
    return (phase == SAPLING_REPLAY_SPENDS ||
            (phase == SAPLING_REPLAY_DISCOVER && r->next != r->floor)) ? r->key_digest : NULL;
}

static enum boot_cutover_replay_status bcr_sapling_result(struct boot_cutover_replay *r,
    int end, enum sapling_replay_phase phase, const uint8_t hash[32],
    struct sapling_replay_result out)
{
    if (r->checkpoint_resume && phase == SAPLING_REPLAY_DISCOVER &&
        out.status == SAPLING_REPLAY_KEYS_UNAVAILABLE &&
        memcmp(r->key_digest, out.key_digest, 32)) {
        r->checkpoint_resume = false; r->next = r->floor;
        memset(r->key_digest, 0, sizeof(r->key_digest));
        return BOOT_CUTOVER_BUSY;
    }
    if (out.status == SAPLING_REPLAY_BUSY || out.status == SAPLING_REPLAY_STOPPED) {
        enum boot_cutover_replay_status partial = bcr_sapling_busy(r, end, phase, hash, &out);
        return partial == BOOT_CUTOVER_BUSY && out.status == SAPLING_REPLAY_STOPPED ?
            BOOT_CUTOVER_STOPPED : partial;
    }
    if (!bcr_sapling_receipt(r, end, phase, hash, &out)) {
        bcr_sapling_receipt_warn(r, end, phase, hash, &out);
        return BOOT_CUTOVER_RETRY;
    }
    if (phase == SAPLING_REPLAY_DISCOVER) {
        r->checkpoint_resume = false;
        if (r->next != r->floor && memcmp(r->key_digest, out.key_digest, 32)) {
            LOG_WARN("wallet", "Sapling replay key set changed: start=%d end=%d reference=%d",
                     r->next, end, r->endpoint.height);
            return BOOT_CUTOVER_RETRY;
        }
        memcpy(r->key_digest, out.key_digest, 32);
    }
    return BOOT_CUTOVER_PROGRESS;
}

static enum boot_cutover_replay_status bcr_sapling(struct boot_cutover_replay *r, int end)
{
    uint8_t hash[32];
    enum boot_cutover_replay_status endpoint = bcr_chunk_endpoint(r, end, hash);
    if (endpoint == BOOT_CUTOVER_BUSY) return endpoint;
    if (endpoint != BOOT_CUTOVER_PROGRESS) {
        LOG_WARN("wallet", "Sapling replay endpoint unavailable: start=%d end=%d reference=%d",
                 r->next, end, r->endpoint.height);
        return BOOT_CUTOVER_RETRY;
    }
    enum sapling_replay_phase phase = r->phase == BOOT_CUTOVER_DISCOVER ?
        SAPLING_REPLAY_DISCOVER : SAPLING_REPLAY_SPENDS;
    struct sapling_replay_result out = node_db_catchup_sapling_replay_at_reference(
        r->service, r->ctx->node_db, r->ctx->main_state, r->ctx->wallet,
        bcr_body_dir(r), r->next, end, r->endpoint.height, r->endpoint.hash.data,
        phase, hash, r->identity, bcr_expected_key_digest(r, phase));
    return bcr_sapling_result(r, end, phase, hash, out);
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

static bool bcr_full_empty_proof(struct boot_cutover_replay *r)
{
    if (!r || r->phase != BOOT_CUTOVER_TRANSPARENT || !r->ctx || !r->ctx->node_db || !r->ctx->wallet) return false;
    struct wallet *w = r->ctx->wallet;
    sqlite3 *db = r->ctx->node_db->db;
    sqlite3_mutex *mu = db ? sqlite3_db_mutex(db) : NULL;
    if (!mu || sqlite3_mutex_try(mu) != SQLITE_OK) return false;
    bool wallet_locked = zcl_mutex_trylock(&w->cs);
    bool key_locked = wallet_locked && zcl_mutex_trylock(&w->keystore.cs);
    bool sapling_locked = key_locked && zcl_mutex_trylock(&w->sapling_keys.cs);
    bool empty = sapling_locked && boot_wallet_cutover_full_empty_locked(
        r->ctx->wallet_db, db, w, r->sapling_load_ok);
    if (sapling_locked) zcl_mutex_unlock(&w->sapling_keys.cs);
    if (key_locked) zcl_mutex_unlock(&w->keystore.cs);
    if (wallet_locked) zcl_mutex_unlock(&w->cs);
    sqlite3_mutex_leave(mu);
    return empty;
}

bool boot_cutover_replay_complete_full_empty(struct boot_cutover_replay *r)
{
    if (!bcr_full_empty_proof(r) || bcr_current(r) != BOOT_CUTOVER_PROGRESS) return false;
    r->full_empty = true; r->shielded_empty = true; r->phase = BOOT_CUTOVER_DONE;
    return true;
}

static bool bcr_transparent_empty(struct boot_cutover_replay *r)
{
    struct wallet *w = r->ctx->wallet;
    sqlite3 *db = r->ctx->node_db->db;
    sqlite3_mutex *mu = db ? sqlite3_db_mutex(db) : NULL;
    if (!mu || sqlite3_mutex_try(mu) != SQLITE_OK) return false;
    bool wallet_locked = zcl_mutex_trylock(&w->cs);
    bool key_locked = wallet_locked && zcl_mutex_trylock(&w->keystore.cs);
    bool empty = key_locked && boot_wallet_cutover_transparent_empty_locked(r->ctx->wallet_db, db, w);
    if (key_locked) zcl_mutex_unlock(&w->keystore.cs);
    if (wallet_locked) zcl_mutex_unlock(&w->cs);
    sqlite3_mutex_leave(mu);
    return empty;
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

static bool bcr_notes_end_read(sqlite3 *db, bool opened, bool empty)
{
    if (opened && sqlite3_exec(db, empty ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) {
        if (!sqlite3_get_autocommit(db) && sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
            LOG_ERROR("wallet", "notes-empty proof rollback failed: %s", sqlite3_errmsg(db));
        empty = false;
    }
    if (opened && !sqlite3_get_autocommit(db)) abort();
    return empty;
}

static bool bcr_notes_empty(struct boot_cutover_replay *r)
{
    struct wallet *w = r->ctx->wallet;
    sqlite3 *db = r->ctx->node_db->db;
    sqlite3_mutex *mu = db ? sqlite3_db_mutex(db) : NULL;
    if (!mu || sqlite3_mutex_try(mu) != SQLITE_OK) return false;
    bool wallet_locked = zcl_mutex_trylock(&w->cs);
    bool key_locked = wallet_locked && zcl_mutex_trylock(&w->keystore.cs);
    bool sapling_locked = key_locked && zcl_mutex_trylock(&w->sapling_keys.cs);
    bool opened = sapling_locked && sqlite3_get_autocommit(db) &&
        sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK;
    bool empty = opened && wallet_sqlite_verify_startup_sapling_in_tx_locked_r(
        r->ctx->wallet_db, w, db).ok && boot_wallet_cutover_notes_empty_locked(
        r->ctx->wallet_db, db, w, r->sapling_load_ok);
    empty = bcr_notes_end_read(db, opened, empty);
    if (sapling_locked) zcl_mutex_unlock(&w->sapling_keys.cs);
    if (key_locked) zcl_mutex_unlock(&w->keystore.cs);
    if (wallet_locked) zcl_mutex_unlock(&w->cs);
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
    enum boot_cutover_replay_status current = bcr_current(r);
    if (current == BOOT_CUTOVER_BUSY) return current;
    if (current != BOOT_CUTOVER_PROGRESS) { r->phase = BOOT_CUTOVER_INVALIDATED; return BOOT_CUTOVER_STALE; }
    r->phase = BOOT_CUTOVER_DONE;
    return BOOT_CUTOVER_COMPLETE;
}

static enum boot_cutover_replay_status bcr_advance(struct boot_cutover_replay *r, int end)
{
    if (r->phase != BOOT_CUTOVER_WITNESS && end < r->endpoint.height) r->next = end + 1;
    else { r->phase++; r->next = r->floor; }
    return r->phase == BOOT_CUTOVER_DONE ? BOOT_CUTOVER_COMPLETE : BOOT_CUTOVER_PROGRESS;
}

static enum boot_cutover_replay_status bcr_run_phase(struct boot_cutover_replay *r, int end)
{
    if (r->phase == BOOT_CUTOVER_TRANSPARENT)
        return bcr_transparent(r, end) ? BOOT_CUTOVER_PROGRESS : BOOT_CUTOVER_RETRY;
    if (r->phase == BOOT_CUTOVER_WITNESS)
        return bcr_witness(r) ? BOOT_CUTOVER_PROGRESS : BOOT_CUTOVER_RETRY;
    return bcr_sapling(r, end);
}

static enum boot_cutover_replay_status bcr_finish_phase(struct boot_cutover_replay *r,
    int end, enum boot_cutover_replay_status step)
{
    enum boot_cutover_replay_status current = bcr_current(r);
    if (current == BOOT_CUTOVER_BUSY) {
        if (step == BOOT_CUTOVER_PROGRESS) { r->pending_complete = true; r->pending_end = end; }
        return step == BOOT_CUTOVER_RETRY ? step : current;
    }
    if (current != BOOT_CUTOVER_PROGRESS) { r->phase = BOOT_CUTOVER_INVALIDATED; return BOOT_CUTOVER_STALE; }
    return step == BOOT_CUTOVER_PROGRESS ? bcr_advance(r, end) : step;
}

static enum boot_cutover_replay_status bcr_skip_transparent(struct boot_cutover_replay *r)
{
    enum boot_cutover_replay_status current = bcr_current(r);
    if (current == BOOT_CUTOVER_BUSY) return current;
    if (current != BOOT_CUTOVER_PROGRESS) { r->phase = BOOT_CUTOVER_INVALIDATED; return BOOT_CUTOVER_STALE; }
    r->transparent_empty = true; r->phase = BOOT_CUTOVER_DISCOVER; r->next = r->floor;
    return BOOT_CUTOVER_PROGRESS;
}

static enum boot_cutover_replay_status bcr_complete_empty_spends(struct boot_cutover_replay *r)
{
    enum boot_cutover_replay_status current = bcr_current(r);
    if (current == BOOT_CUTOVER_BUSY) return current;
    if (current != BOOT_CUTOVER_PROGRESS) { r->phase = BOOT_CUTOVER_INVALIDATED; return BOOT_CUTOVER_STALE; }
    r->spends_empty = true; r->phase = BOOT_CUTOVER_DONE;
    return BOOT_CUTOVER_COMPLETE;
}

static bool bcr_can_complete_empty_spends(struct boot_cutover_replay *r)
{
    return r->phase == BOOT_CUTOVER_SPENDS && r->next == r->floor && bcr_notes_empty(r);
}

enum boot_cutover_replay_status boot_cutover_replay_step(struct boot_cutover_replay *r)
{
    if (!r) return BOOT_CUTOVER_INVALID;
    if (r->phase == BOOT_CUTOVER_INVALIDATED) return BOOT_CUTOVER_STALE;
    if (!r->ctx) return BOOT_CUTOVER_INVALID;
    enum boot_cutover_replay_status current = bcr_current(r);
    if (current == BOOT_CUTOVER_BUSY) return current;
    if (current != BOOT_CUTOVER_PROGRESS) {
        r->phase = BOOT_CUTOVER_INVALIDATED; return BOOT_CUTOVER_STALE;
    }
    if (r->phase == BOOT_CUTOVER_DONE) return BOOT_CUTOVER_COMPLETE;
    if (r->pending_complete) {
        r->pending_complete = false;
        return bcr_advance(r, r->pending_end);
    }
    if (bcr_can_complete_empty(r)) return bcr_complete_empty(r);
    if (bcr_can_complete_empty_spends(r)) {
        return bcr_complete_empty_spends(r);
    }
    if (r->phase == BOOT_CUTOVER_TRANSPARENT && bcr_transparent_empty(r))
        return bcr_skip_transparent(r);
#ifdef ZCL_TESTING
    if (bcr_test_after_current) bcr_test_after_current(bcr_test_after_current_ctx);
#endif
    int end = r->endpoint.height - r->next >= 255 ? r->next + 255 : r->endpoint.height;
    enum boot_cutover_replay_status step = bcr_run_phase(r, end);
#ifdef ZCL_TESTING
    if (bcr_test_before_postcheck) bcr_test_before_postcheck(bcr_test_before_postcheck_ctx);
#endif
    return bcr_finish_phase(r, end, step);
}
