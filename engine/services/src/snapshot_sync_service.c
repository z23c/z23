/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Snapshot Sync Service — high-performance UTXO snapshot sync.
 *
 * Two-step cryptographic verification:
 *   FlyClient — 50 random block samples with MMB proofs
 *               + PoW target checks (≥150-bit forgery security)
 *   SHA3-256 over all UTXOs in canonical order
 *
 * Uses ActiveRecord models, shared node_db connection with turbo
 * mode, batch COMMIT every SNAPSYNC_BATCH_COMMIT_ROWS rows.
 *
 * State machine: IDLE → NEGOTIATING → RECEIVING → VERIFYING → COMPLETE
 *
 * This translation unit holds the public lifecycle (init/reset),
 * the global singleton, the service-wide lock and helper accessors,
 * and the active-state / awaiting / stall queries. The four
 * phase-specific concerns live in:
 *
 *   snapshot_offer.c   — offer manifest validation + accept
 *   snapshot_fetch.c   — chunk receive, turbo mode, staging
 *   snapshot_verify.c  — FlyClient + SHA3 verification, finalize
 *   snapshot_apply.c   — promote staging + tip activation
 *   snapshot_serve.c   — the SERVE side: admission (client puzzle +
 *                        rate limit) and the chunk cursor for a peer
 *                        asking US for a snapshot
 *
 * The public API is declared by net/snapshot_sync_contract.h so app/config/net
 * callers share one contract header. */

// one-result-type-ok:snapshot-predicates-conditions-and-write-runner — the
// bool exports that remain here are NOT fallible-service surfaces:
//   * pure predicates: snapsync_is_peer_blacklisted / snapsync_is_active /
//     snapsync_awaiting_utxos — the bool IS the query answer.
//   * condition-fired checks: snapsync_check_negotiation_stall /
//     snapsync_check_failed_reset / snapsync_check_stall — the bool means
//     "the condition fired and I acted (blacklist+reset)", never a failure;
//     each is driven by an engine/conditions/ predicate.
//   * write-runner: snapsync_run_write_internal — returns the shared
//     db_service_write_fn (config/db_service.h) callback's bool commit answer.
// The genuinely fallible service surface returns struct zcl_result
// (snapsync_bind_store_internal and the begin/verify/handle/finalize
// actions in the sibling snapshot_*.c files).

#include "net/snapshot_sync_contract.h"
#include "services/snapshot_manifest.h"
#include "models/db_txn.h"
#include "models/database.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "config/runtime.h"
#include "event/event.h"
#include "net/fast_sync.h"
#include "sync/sync_state.h"
#include "net/net.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "platform/time_compat.h"

#include "snapshot_sync_internal.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

/* Global singleton */
static struct snapshot_sync_service g_snapsync_instance;
static bool g_snapsync_init_done = false;
static pthread_mutex_t g_snapsync_service_lock = PTHREAD_MUTEX_INITIALIZER;

/* Snapshot anchor: non-owning pointer to a placeholder block_index at
 * verified snapshot height. The pointed-to block_index is owned by the
 * block map; this slot only lets getheaders locators resume from the
 * snapshot height instead of the lower locally-indexed chain tip. */
static struct block_index *g_snapshot_anchor = NULL;

void snapsync_service_lock_internal(void)
{
    pthread_mutex_lock(&g_snapsync_service_lock);
}

void snapsync_service_unlock_internal(void)
{
    pthread_mutex_unlock(&g_snapsync_service_lock);
}

struct snapshot_sync_service *snapsync_global(void) { return &g_snapsync_instance; }
bool snapsync_global_initialized(void) { return g_snapsync_init_done; }

struct snapshot_sync_service *snapsync_condition_service(void)
{
    struct snapshot_sync_service *svc = app_runtime_snapshot_sync();
    if (svc)
        return svc;
    if (!snapsync_global_initialized())
        return NULL;
    return snapsync_global();
}

void snapsync_global_ensure_init(struct node_db *ndb)
{
    snapsync_service_lock_internal();
    if (!g_snapsync_init_done) {
        snapsync_init(&g_snapsync_instance, ndb);
        g_snapsync_init_done = true;
    }
    snapsync_service_unlock_internal();
}

int64_t snapsync_now_us_internal(void)
{
    /* MONOTONIC, not wall-clock: every caller uses this purely as a delta
     * (elapsed = now - start, stall = now - last_progress, blacklist expiry).
     * A wall-clock jump on an NTP/suspend/VM step would spuriously fire
     * snapsync_check_stall mid-transfer, abort the in-flight snapshot, and
     * blacklist the healthy serving peer; a backward step would make blacklist
     * entries never expire. The monotonic clock cannot jump. */
    return platform_time_monotonic_us();
}

static struct db_service *snapsync_db_service(
    const struct snapshot_sync_service *svc)
{
    struct db_service *dbsvc = app_runtime_db_service();

    if (!svc || !dbsvc)
        return NULL;  /* normal: db_service may not be wired yet */
    return db_service_node_db(dbsvc) == svc->ndb ? dbsvc : NULL;
}

bool snapsync_run_write_internal(struct snapshot_sync_service *svc,
                                 db_service_write_fn fn,
                                 void *ctx)
{
    struct db_service *dbsvc = snapsync_db_service(svc);

    if (!svc || !svc->ndb || !fn)
        LOG_FAIL("snapshot_sync", "run_write: null svc, ndb, or fn pointer");
    if (dbsvc)
        return db_service_run_write(dbsvc, fn, ctx);
    return fn(svc->ndb, ctx);
}

/* Single place the snapshot subsystem selects its storage adapter. The
 * service/offer/fetch files name only snapshot_store_port; here we bind the
 * default sqlite adapter. (The two SHA3 commitment calls stay inline with
 * the live handle — they are commitment math, not storage access.) */
struct zcl_result snapsync_bind_store_internal(
    struct snapshot_store_sqlite_ctx *ctx,
    struct node_db *ndb,
    struct snapshot_store_port *out_port)
{
    if (!snapshot_store_sqlite_bind(ctx, ndb, out_port))
        return ZCL_ERR(-1, "bind_store: null ctx (%p) or out_port (%p)",
                       (void *)ctx, (void *)out_port);
    return ZCL_OK;
}

/* ── Peer Blacklist ──────────────────────────────────────── */

bool snapsync_is_peer_blacklisted(const struct snapshot_sync_service *svc,
                                  uint32_t peer_id)
{
    if (!svc || peer_id == 0)
        return false;

    int64_t now = snapsync_now_us_internal();
    int64_t expiry_us = SNAPSYNC_BLACKLIST_SECS * 1000000LL;

    for (int i = 0; i < svc->blacklist_count; i++) {
        if (svc->blacklist[i].peer_id == peer_id &&
            (now - svc->blacklist[i].blacklisted_at_us) < expiry_us)
            return true;
    }
    return false;
}

void snapsync_blacklist_peer(struct snapshot_sync_service *svc,
                             uint32_t peer_id)
{
    if (!svc || peer_id == 0)
        return;

    int64_t now = snapsync_now_us_internal();
    int64_t expiry_us = SNAPSYNC_BLACKLIST_SECS * 1000000LL;

    /* Check if already blacklisted — refresh timestamp */
    for (int i = 0; i < svc->blacklist_count; i++) {
        if (svc->blacklist[i].peer_id == peer_id) {
            svc->blacklist[i].blacklisted_at_us = now;
            return;
        }
    }

    /* Evict expired entries first */
    for (int i = 0; i < svc->blacklist_count; ) {
        if ((now - svc->blacklist[i].blacklisted_at_us) >= expiry_us) {
            svc->blacklist[i] = svc->blacklist[--svc->blacklist_count];
        } else {
            i++;
        }
    }

    /* Add new entry */
    if (svc->blacklist_count < SNAPSYNC_MAX_BLACKLIST) {
        svc->blacklist[svc->blacklist_count].peer_id = peer_id;
        svc->blacklist[svc->blacklist_count].blacklisted_at_us = now;
        svc->blacklist_count++;
    }
}

/* ── Init / Reset ────────────────────────────────────────── */

void snapsync_init(struct snapshot_sync_service *svc, struct node_db *ndb)
{
    if (!svc)
        return;
    snapsync_service_lock_internal();
    memset(svc, 0, sizeof(*svc));
    svc->state = SNAPSYNC_IDLE;
    svc->ndb = ndb;
    snapsync_service_unlock_internal();
}

void snapsync_reset(struct snapshot_sync_service *svc)
{
    bool rollback_ok = true;
    bool normal_mode_ok = true;
    bool discard_ok = true;
    bool has_db = false;
    bool has_db_owner = false;

    if (!svc) {
        return;
    }
    snapsync_service_lock_internal();
    bool turbo_active = svc->turbo_active;
    has_db_owner = svc->ndb != NULL;
    has_db = svc->ndb && svc->ndb->open;
    snapsync_service_unlock_internal();
    if (has_db_owner && !has_db)
        rollback_ok = false;
    if (has_db)
        rollback_ok = snapsync_run_write_internal(svc, snapsync_rollback_receive_write_internal, NULL);
    if (turbo_active) {
        normal_mode_ok = snapsync_exit_turbo_mode_internal(svc).ok;
    }
    if (has_db)
        discard_ok = snapsync_run_write_internal(
            svc, snapsync_discard_staging_write_internal, "reset");

    if (!rollback_ok || !normal_mode_ok || !discard_ok) {
        snapsync_service_lock_internal();
        svc->state = SNAPSYNC_FAILED;
        (void)snapsync_set_state(SNAPSYNC_FAILED,
                                 "reset incomplete; containment retained");
        snapsync_service_unlock_internal();
        LOG_WARN("snapshot_sync",
                 "reset incomplete rollback_ok=%d normal_mode_ok=%d "
                 "discard_ok=%d; state=FAILED blocker_retained=%s",
                 rollback_ok, normal_mode_ok, discard_ok,
                 SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
        return;
    }

    snapsync_service_lock_internal();
    svc->turbo_active = false;
    svc->state = SNAPSYNC_IDLE;
    svc->received_utxos = 0;
    svc->start_time_us = 0;
    svc->serving_peer_id = 0;
    svc->last_commit_at = 0;
    memset(svc->offered_utxo_root, 0, 32);
    memset(svc->offered_mmb_root, 0, 32);
    memset(svc->offered_block_hash, 0, 32);
    memset(svc->offered_chain_work, 0, 32);
    memset(&svc->fc_challenge, 0, sizeof(svc->fc_challenge));
    svc->fc_verified = false;
    svc->offered_height = 0;
    svc->offered_peer_tip_height = 0;
    svc->offered_count = 0;
    svc->offered_protocol_version = 0;
    svc->offered_schema_version = 0;
    svc->last_progress_time_us = 0;
    svc->last_progress_utxos = 0;
    /* Clear only the non-owning anchor slot. The anchor itself belongs
     * to main_state.map_block_index (or a caller-owned test object). */
    g_snapshot_anchor = NULL;
    svc->state = SNAPSYNC_IDLE;
    snapsync_set_state(SNAPSYNC_IDLE, "reset");
    snapsync_service_unlock_internal();

    /* The contained-activation blocker is owned by the failed peer-snapshot
     * attempt. Clear it only after rollback, normal-mode restoration, and
     * staging discard have all succeeded and the service is back in IDLE. */
    blocker_clear(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
}

bool snapsync_is_active(void)
{
    struct snapshot_sync_service *svc = app_runtime_snapshot_sync();
    struct snapsync_status st;

    switch (snapsync_get_state()) {
    case SNAPSYNC_NEGOTIATING:
    case SNAPSYNC_RECEIVING:
    case SNAPSYNC_VERIFYING:
        return true;
    default:
        break;
    }

    if (!svc) {
        if (!snapsync_global_initialized())
            return false;  // raw-return-ok:not-initialized-is-a-normal-not-active-result
        svc = snapsync_global();
    }
    snapsync_get_status_snapshot(svc, &st);
    return st.state == SNAPSYNC_NEGOTIATING ||
           st.state == SNAPSYNC_RECEIVING ||
           st.state == SNAPSYNC_VERIFYING;
}

bool snapsync_awaiting_utxos(void)
{
    struct snapshot_sync_service *svc = app_runtime_snapshot_sync();
    if (!svc) {
        if (!snapsync_global_initialized()) {
            /* If the snapsync service isn't even initialized, this is
             * by definition not an active snapshot exchange. Return
             * false so the chain can sync via standard P2P
             * block-by-block connection — gating this on
             * "utxo_count < 100000" would wedge a fresh-datadir
             * genesis-up sync at SKIP_AWAITING_UTXOS forever, because
             * no snapshot service ever initializes for P2P-from-scratch. */
            return false;
        }
        svc = snapsync_global();
    }
    if (!svc || !svc->ndb || !svc->ndb->open)
        return false;

    /* If snapshot sync already completed or failed with recovery, not waiting */
    struct snapsync_status st;
    snapsync_get_status_snapshot(svc, &st);
    if (st.state == SNAPSYNC_COMPLETE)
        return false;

    /* The CANONICAL store decides "a real UTXO set exists" — the
     * mirror count / node_state anchor below are legacy fallbacks only. */
    if (coins_kv_count(progress_store_db()) > 100000)
        return false;  /* real UTXO set exists (coins_kv authority) */

    /* Check coins_best_block — if set to a meaningful height, UTXOs exist */
    uint8_t cb_buf[32] = {0};
    size_t cb_len = 0;
    if (node_db_state_get(svc->ndb, "coins_best_block",
                          cb_buf, sizeof(cb_buf), &cb_len) && cb_len == 32) {
        bool all_zero = true;
        for (int i = 0; i < 32; i++)
            if (cb_buf[i]) { all_zero = false; break; }
        if (!all_zero) {
            /* coins_best_block is set.  Check that it points to a block
             * at a meaningful height (not just h=587 from a failed partial
             * connect).  If the height is below the snapshot offer height
             * and below a safety threshold, we're still waiting. */
            int64_t utxo_count = 0;
            struct snapshot_store_sqlite_ctx sctx;
            struct snapshot_store_port store = {0};
            if (snapsync_bind_store_internal(&sctx, svc->ndb, &store).ok)
                (void)store.utxo_count(store.self, &utxo_count);
            /* A real snapshot import produces 1M+ UTXOs.  A partial
             * block connect from genesis produces very few. */
            if (utxo_count > 100000)
                return false;  /* real UTXO set exists */
        }
    }

    /* If we get here, UTXO count is low (<100K) — check if snapshot
     * sync is still a possibility (not yet completed or permanently
     * failed with no hope of recovery).
     *
     * SNAPSYNC_IDLE is not the same as "actively waiting". On a
     * fresh-datadir node where no peer is offering a snapshot,
     * snapsync stays in IDLE indefinitely — treating IDLE as
     * "awaiting" wedges genesis-up P2P sync (activation_should_connect
     * returns SKIP_AWAITING_UTXOS, no block ever connects, the chain
     * stays at h=0 forever even as block bodies arrive). Only treat
     * NEGOTIATING / RECEIVING / VERIFYING as "actively waiting". In
     * IDLE state, fall back to genesis-up sync. */
    if (st.state == SNAPSYNC_NEGOTIATING ||
        st.state == SNAPSYNC_RECEIVING ||
        st.state == SNAPSYNC_VERIFYING)
        return true;  /* actively in a snapshot exchange */

    return false;
}

void snapsync_get_stall_status(struct snapshot_sync_service *svc,
                               struct snapsync_stall_status *out)
{
    struct snapsync_stall_status local = {0};
    if (!out)
        out = &local;
    memset(out, 0, sizeof(*out));

    if (!svc) {
        svc = app_runtime_snapshot_sync();
        if (!svc) {
            if (!snapsync_global_initialized())
                return;
            svc = snapsync_global();
        }
    }

    snapsync_service_lock_internal();
    out->receiving = svc->state == SNAPSYNC_RECEIVING;
    out->received_utxos = svc->received_utxos;
    out->offered_utxos = svc->offered_count;
    out->serving_peer_id = svc->serving_peer_id;
    if (!out->receiving || svc->last_progress_time_us == 0) {
        snapsync_service_unlock_internal();
        return;
    }

    if (svc->received_utxos > svc->last_progress_utxos) {
        svc->last_progress_time_us = snapsync_now_us_internal();
        svc->last_progress_utxos = svc->received_utxos;
        snapsync_service_unlock_internal();
        return;
    }

    int64_t elapsed_us = snapsync_now_us_internal() -
                         svc->last_progress_time_us;
    out->elapsed_secs = elapsed_us > 0 ? elapsed_us / 1000000LL : 0;
    out->stalled = elapsed_us >=
        (int64_t)SNAPSYNC_STALL_TIMEOUT_SECS * 1000000LL;
    snapsync_service_unlock_internal();
}

void snapsync_get_negotiation_status(struct snapshot_sync_service *svc,
                                     struct snapsync_negotiation_status *out)
{
    struct snapsync_negotiation_status local = {0};
    if (!out)
        out = &local;
    memset(out, 0, sizeof(*out));

    if (!svc) {
        svc = app_runtime_snapshot_sync();
        if (!svc) {
            if (!snapsync_global_initialized())
                return;
            svc = snapsync_global();
        }
    }

    snapsync_service_lock_internal();
    out->negotiating = svc->state == SNAPSYNC_NEGOTIATING;
    out->offered_height = svc->offered_height;
    out->offered_utxos = svc->offered_count;
    out->serving_peer_id = svc->serving_peer_id;
    if (!out->negotiating || svc->start_time_us == 0) {
        snapsync_service_unlock_internal();
        return;
    }

    int64_t elapsed_us = snapsync_now_us_internal() - svc->start_time_us;
    out->elapsed_secs = elapsed_us > 0 ? elapsed_us / 1000000LL : 0;
    out->stalled = elapsed_us >=
        (int64_t)SNAPSYNC_NEGOTIATION_TIMEOUT_SECS * 1000000LL;
    snapsync_service_unlock_internal();
}

void snapsync_get_failed_status(struct snapshot_sync_service *svc,
                                struct snapsync_failed_status *out)
{
    struct snapsync_failed_status local = {0};
    if (!out)
        out = &local;
    memset(out, 0, sizeof(*out));

    if (!svc) {
        svc = app_runtime_snapshot_sync();
        if (!svc) {
            if (!snapsync_global_initialized())
                return;
            svc = snapsync_global();
        }
    }

    snapsync_service_lock_internal();
    out->failed = svc->state == SNAPSYNC_FAILED;
    out->offered_height = svc->offered_height;
    out->offered_utxos = svc->offered_count;
    out->serving_peer_id = svc->serving_peer_id;
    out->turbo_active = svc->turbo_active;
    out->staged_row_count =
        (svc->ndb && svc->ndb->open) ? snapsync_staging_count_internal(svc->ndb)
                                     : 0;
    if (out->failed && svc->start_time_us > 0) {
        int64_t elapsed_us = snapsync_now_us_internal() - svc->start_time_us;
        out->elapsed_secs = elapsed_us > 0 ? elapsed_us / 1000000LL : 0;
    }
    snapsync_service_unlock_internal();
}

bool snapsync_check_negotiation_stall(void)
{
    struct snapshot_sync_service *svc = app_runtime_snapshot_sync();
    if (!svc) {
        if (!snapsync_global_initialized())
            return false;  // raw-return-ok:not-initialized-is-a-normal-not-active-result
        svc = snapsync_global();
    }

    struct snapsync_negotiation_status st;
    snapsync_get_negotiation_status(svc, &st);
    if (!st.stalled)
        return false;

    event_emitf(EV_SNAPSHOT_OFFER_RECEIVED, st.serving_peer_id,
                "accepted=false reason=negotiation_stall elapsed_s=%lld "
                "h=%d utxos=%llu action=blacklist_reset",
                (long long)st.elapsed_secs,
                st.offered_height,
                (unsigned long long)st.offered_utxos);
    snapsync_blacklist_peer(svc, st.serving_peer_id);
    snapsync_reset(svc);
    return true;
}

bool snapsync_check_failed_reset(void)
{
    struct snapshot_sync_service *svc = app_runtime_snapshot_sync();
    if (!svc) {
        if (!snapsync_global_initialized())
            return false;  // raw-return-ok:not-initialized-is-a-normal-not-active-result
        svc = snapsync_global();
    }

    struct snapsync_failed_status st;
    snapsync_get_failed_status(svc, &st);
    if (!st.failed)
        return false;

    event_emitf(EV_SNAPSYNC_VERIFIED, st.serving_peer_id,
                "snapshot=FAILED reason=terminal_failed elapsed_s=%lld "
                "h=%d utxos=%llu staged=%lld action=blacklist_reset",
                (long long)st.elapsed_secs,
                st.offered_height,
                (unsigned long long)st.offered_utxos,
                (long long)st.staged_row_count);
    snapsync_blacklist_peer(svc, st.serving_peer_id);
    snapsync_reset(svc);
    snapsync_service_lock_internal();
    bool reset_idle = svc->state == SNAPSYNC_IDLE;
    snapsync_service_unlock_internal();
    if (!reset_idle) {
        event_emitf(EV_SNAPSYNC_VERIFIED, st.serving_peer_id,
                    "snapshot=FAILED reason=reset_incomplete "
                    "fallback_to_headers=false blocker=%s",
                    SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
        return true;
    }
    if (sync_get_state() == SYNC_SNAPSHOT_RECEIVE)
        sync_set_state(SYNC_HEADERS_DOWNLOAD, "snapshot failed reset");
    return true;
}

bool snapsync_check_stall(void)
{
    struct snapshot_sync_service *svc = app_runtime_snapshot_sync();
    if (!svc) {
        if (!snapsync_global_initialized())
            return false;  // raw-return-ok:not-initialized-is-a-normal-not-active-result
        svc = snapsync_global();
    }

    struct snapsync_stall_status stall;
    snapsync_get_stall_status(svc, &stall);
    if (!stall.stalled)
        return false;

    event_emitf(EV_SNAPSYNC_VERIFIED, stall.serving_peer_id,
                "snapshot=FAILED reason=stall elapsed_s=%lld received=%llu offered=%llu action=blacklist_reset",
                (long long)stall.elapsed_secs,
                (unsigned long long)stall.received_utxos,
                (unsigned long long)stall.offered_utxos);

    /* Blacklist the stalling peer before reset (reset clears serving_peer_id) */
    snapsync_blacklist_peer(svc, stall.serving_peer_id);

    snapsync_reset(svc);

    /* Discard committed staging rows so the next offer starts clean.
     * Active UTXOs were never touched by the stalled receive. */
    if (svc->ndb && svc->ndb->open) {
        if (snapsync_discard_staging_internal(svc->ndb, "stall_cleanup").ok)
            event_emitf(EV_SNAPSYNC_VERIFIED, stall.serving_peer_id,
                        "snapshot=FAILED reason=stall staging_discarded=true");
    }

    /* Reset sync state so the node can accept a new snapshot offer.
     * SYNC_SNAPSHOT_RECEIVE → SYNC_HEADERS_DOWNLOAD allows re-entry
     * into the snapshot path when the next peer offers. */
    if (sync_get_state() == SYNC_SNAPSHOT_RECEIVE)
        sync_set_state(SYNC_HEADERS_DOWNLOAD, "snapshot stall reset");

    return true;
}

struct block_index *snapsync_get_anchor(void)
{
    /* Guard g_snapshot_anchor with the service lock: reset/set update
     * the slot under this mutex. The returned block_index is non-owned
     * and remains the caller's responsibility. */
    snapsync_service_lock_internal();
    struct block_index *result = g_snapshot_anchor;
    snapsync_service_unlock_internal();
    return result;
}
void snapsync_set_anchor(struct block_index *anchor)
{
    snapsync_service_lock_internal();
    g_snapshot_anchor = anchor;
    snapsync_service_unlock_internal();
}

/* ── Progress Query ──────────────────────────────────────── */

void snapsync_get_progress(const struct snapshot_sync_service *svc,
                           uint64_t *received, uint64_t *total,
                           double *rate_per_sec)
{
    if (!svc || (!received && !total && !rate_per_sec))
        return;

    snapsync_service_lock_internal();
    if (received) *received = svc->received_utxos;
    if (total) *total = svc->offered_count;
    if (rate_per_sec) {
        if (svc->start_time_us > 0) {
            double elapsed = (double)(snapsync_now_us_internal() - svc->start_time_us) / 1000000.0;
            *rate_per_sec = elapsed > 0 ? (double)svc->received_utxos / elapsed : 0;
        } else {
            *rate_per_sec = 0;
        }
    }
    snapsync_service_unlock_internal();
}

void snapsync_get_status_snapshot(const struct snapshot_sync_service *svc,
                                 struct snapsync_status *out)
{
    if (!svc || !out)
        return;

    snapsync_service_lock_internal();
    out->state = svc->state;
    out->offered_count = svc->offered_count;
    out->serving_peer_id = svc->serving_peer_id;
    out->offered_height = svc->offered_height;
    out->turbo_active = svc->turbo_active;
    out->staged_row_count = snapsync_staging_count_internal(svc->ndb);
    snapsync_service_unlock_internal();
}

