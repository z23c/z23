/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Stateful block-source decision runtime: the live state, lifecycle,
 * runtime-input builder, projection-deferral counter, and the shared mirror
 * blocker classifier for the block-source policy. The pure
 * scoring/name/plan policy lives in block_source_policy.c; the cohesive
 * stateful siblings are:
 *   - block_source_policy_persist.c   : node.db persist/restore
 *   - block_source_policy_decisions.c : decision predicates + event/record
 *   - block_source_policy_status.c    : status read + dump-state JSON dumper
 * This file owns runtime state; siblings own persistence, decisions, and
 * status so each file keeps one clear framework purpose. */

#include "block_source_policy_internal.h"

#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "services/legacy_mirror_sync_service.h"
#include "net/snapshot_sync_contract.h"
#include "config/runtime.h"          /* app_runtime_snapshot_sync */
#include "services/sync_monitor.h"
#include "models/block.h"
#include "models/database.h"
#include "net/connman.h"
#include "net/peer_lifecycle.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/mirror_consensus.h"
#include "util/sync.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* Projection-deferral persistence keys. These mirror the prefix used by the
 * persistence seam (block_source_policy_persist.c); the projection-deferral
 * counter persists alongside the last decision but its writer lives here with
 * the runtime that owns the counter. */
#define BSP_STATE_PREFIX "chain_advance_coordinator."
#define BSP_KEY_PROJECTION_DEFERRED_TOTAL \
    BSP_STATE_PREFIX "projection_deferred_total"
#define BSP_KEY_LAST_PROJECTION_DEFERRED_HEIGHT \
    BSP_STATE_PREFIX "last_projection_deferred_height"
#define BSP_KEY_LAST_PROJECTION_DEFERRED_TIME \
    BSP_STATE_PREFIX "last_projection_deferred_time"
#define BSP_KEY_LAST_PROJECTION_DEFERRED_REASON \
    BSP_STATE_PREFIX "last_projection_deferred_reason"

/* Min seconds between projection-deferral mirror persists (see
 * block_source_policy_note_projection_deferred). */
#define BSP_PROJECTION_DEFERRED_PERSIST_INTERVAL_SECS 2

/* ---------------------------------------------------------------------------
 * Stateful block-source decision surface.
 * --------------------------------------------------------------------------- */

struct bsp_state g_bsp;

void bsp_copy_text(char *dst, size_t dst_len, const char *src)
{
    if (!dst || dst_len == 0) return;
    if (!src) src = "";
    snprintf(dst, dst_len, "%s", src);
}

void bsp_lock_init_once(void)
{
    if (!g_bsp.lock_init) {
        zcl_mutex_init(&g_bsp.lock);
        g_bsp.lock_init = true;
    }
}

/* Classify legacy_mirror_sync_service blocker strings into the typed enum
 * reported by source scoring, status, and decision events. Consensus blocker
 * names share mirror_consensus_classify_blocker_reason(); source policy only
 * adds runtime resource/dependency codes that mirror_consensus does not own. */
enum blocker_class bsp_classify_mirror_blocker_class(const char *code)
{
    if (!code || code[0] == '\0')
        return BLOCKER_TRANSIENT;

    /* Resource contention — DB writer busy or similar. RESOURCE class
     * signals "operator action may be needed". */
    if (strcmp(code, "db-writer-busy") == 0)
        return BLOCKER_RESOURCE;

    /* Waiting on a downstream subsystem (activation controller). */
    if (strcmp(code, "activation-failed") == 0)
        return BLOCKER_DEPENDENCY;

    return mirror_consensus_classify_blocker_reason(code);
}

void bsp_enrich_projection_deferral(struct bsp_decision *d)
{
    if (!d)
        return;

    bsp_lock_init_once();
    zcl_mutex_lock(&g_bsp.lock);
    d->projection_deferred_total = g_bsp.projection_deferred_total;
    d->last_projection_deferred_height =
        g_bsp.last_projection_deferred_height;
    d->last_projection_deferred_time = g_bsp.last_projection_deferred_time;
    bsp_copy_text(d->last_projection_deferred_reason,
                  sizeof(d->last_projection_deferred_reason),
                  g_bsp.last_projection_deferred_reason);
    zcl_mutex_unlock(&g_bsp.lock);
}

void block_source_policy_init(struct connman *cm,
                              struct main_state *ms,
                              struct node_db *ndb)
{
    bsp_lock_init_once();
    zcl_mutex_lock(&g_bsp.lock);
    g_bsp.connman = cm;
    g_bsp.main_state = ms;
    g_bsp.node_db = ndb;
    zcl_mutex_unlock(&g_bsp.lock);

    /* Restore the persisted decision + projection-deferral mirror. A miss is
     * non-fatal (cold start returns ZCL_OK; a real node.db read error is
     * logged but init still proceeds with empty in-memory state). */
    struct zcl_result r = bsp_restore_decision(ndb);
    if (!r.ok)
        LOG_WARN("bsp", "restore decision: %s", r.message);
    r = bsp_restore_projection_deferral(ndb);
    if (!r.ok)
        LOG_WARN("bsp", "restore projection deferral: %s", r.message);
}

static int runtime_local_height(struct main_state *ms)
{
    if (!ms) return -1; /* raw-return-ok:sentinel */
    return active_chain_height(&ms->chain_active);
}

static int runtime_best_header_height(struct main_state *ms)
{
    if (!ms || !ms->pindex_best_header) return -1; /* raw-return-ok:sentinel */
    return ms->pindex_best_header->nHeight;
}

static bool p2p_minimum_viable(const struct bsp_plan_input *in,
                               const struct bsp_source_status *p2p,
                               const struct connman_outbound_health *ph)
{
    if (!in || !p2p || !ph)
        return false;
    if (ph->healthy >= 3)
        return true;
    if (ph->healthy < 2)
        return false;
    if (ph->healthy_ipv4_group_count < 2)
        return false;
    if (p2p->height < 0)
        return false;
    if (p2p->lag > 1)
        return false;
    if (in->local_height >= 0) {
        int64_t local_gap = (int64_t)in->local_height - p2p->height;
        if (local_gap <= 0)
            return true;
        if (local_gap > 1)
            return false;
        return ph->inbound_healthy > 0;
    }
    return true;
}

void bsp_build_runtime_input(struct bsp_plan_input *in)
{
    memset(in, 0, sizeof(*in));
    in->local_height = -1;
    in->best_header_height = -1;
    in->target_height = -1;

    bsp_lock_init_once();
    zcl_mutex_lock(&g_bsp.lock);
    struct connman *cm = g_bsp.connman;
    struct main_state *ms = g_bsp.main_state;
    struct node_db *ndb = g_bsp.node_db;
    zcl_mutex_unlock(&g_bsp.lock);

    in->local_height = runtime_local_height(ms);
    in->best_header_height = runtime_best_header_height(ms);

    struct peer_lifecycle_summary pls;
    memset(&pls, 0, sizeof(pls));
    peer_lifecycle_get_summary(&pls);

    struct bsp_source_status *p2p = &in->sources[BSP_SOURCE_P2P];
    struct connman_outbound_health ph;
    memset(&ph, 0, sizeof(ph));
    if (cm)
        connman_get_outbound_health(cm, &ph);
    p2p->source = BSP_SOURCE_P2P;
    p2p->available = pls.handshake_complete > 0 ||
                     ph.healthy > 0;
    p2p->height = cm ? connman_max_peer_height(cm) : -1;
    p2p->lag = (in->best_header_height > p2p->height && p2p->height >= 0)
        ? (int64_t)(in->best_header_height - p2p->height)
        : 0;
    p2p->healthy = p2p_minimum_viable(in, p2p, &ph);
    p2p->timeouts = pls.timeout;
    p2p->failures = pls.rejected;
    p2p->outbound_total = (int64_t)ph.outbound_total;
    p2p->inbound_total = (int64_t)ph.inbound_total;
    p2p->healthy_peers = (int64_t)ph.healthy;
    p2p->inbound_healthy_peers = (int64_t)ph.inbound_healthy;
    p2p->total_healthy_peers = (int64_t)(ph.healthy + ph.inbound_healthy);
    p2p->connecting_peers = (int64_t)ph.connecting;
    p2p->handshake_incomplete = (int64_t)ph.handshake_incomplete;
    p2p->inbound_handshake_incomplete =
        (int64_t)ph.inbound_handshake_incomplete;
    p2p->peer_groups = (int64_t)ph.ipv4_group_count;
    p2p->max_peer_group_size = (int64_t)ph.ipv4_max_group_size;
    p2p->healthy_peer_groups = (int64_t)ph.healthy_ipv4_group_count;
    p2p->healthy_max_peer_group_size =
        (int64_t)ph.healthy_ipv4_max_group_size;
    p2p->addnode_count = (int64_t)ph.addnode_count;
    p2p->addnode_backoff_active = (int64_t)ph.addnode_backoff_active;
    p2p->addnode_backoff_max_sec = (int64_t)ph.addnode_backoff_max_sec;
    p2p->addnode_tcp_failures = ph.addnode_tcp_failures;
    p2p->addnode_protocol_failures = ph.addnode_protocol_failures;
    p2p->progress_current = pls.handshake_complete;
    p2p->progress_total = pls.attempted;
    bsp_copy_text(p2p->state, sizeof(p2p->state),
                  p2p->healthy ? "healthy" :
                  (p2p->available ? "degraded" : "unavailable"));
    snprintf(p2p->reason, sizeof(p2p->reason),
             "peer_height=%d header_height=%d stale_lag=%lld "
             "handshakes=%lld healthy=%zu inbound_healthy=%zu "
             "total_healthy=%zu outbound=%zu inbound=%zu connecting=%zu "
             "groups=%zu max_group=%zu healthy_groups=%zu "
             "healthy_max_group=%zu ideal_floor=3 backoff=%zu/%zu max=%d "
             "tcp_fail=%lld proto_fail=%lld",
             p2p->height,
             in->best_header_height,
             (long long)p2p->lag,
             (long long)pls.handshake_complete,
             ph.healthy,
             ph.inbound_healthy,
             ph.healthy + ph.inbound_healthy,
             ph.outbound_total,
             ph.inbound_total,
             ph.connecting,
             ph.ipv4_group_count,
             ph.ipv4_max_group_size,
             ph.healthy_ipv4_group_count,
             ph.healthy_ipv4_max_group_size,
             ph.addnode_backoff_active,
             ph.addnode_count,
             ph.addnode_backoff_max_sec,
             (long long)ph.addnode_tcp_failures,
             (long long)ph.addnode_protocol_failures);
    if (ph.outbound_total > 0 && ph.healthy == 0)
        bsp_copy_text(p2p->blocker, sizeof(p2p->blocker), "no_healthy_outbound");
    else if (p2p->available && !p2p->healthy)
        bsp_copy_text(p2p->blocker, sizeof(p2p->blocker), "peer_floor");

    struct watchdog_local_recovery_stats wr;
    memset(&wr, 0, sizeof(wr));
    sync_monitor_get_local_recovery_stats(&wr);
    in->local_recovery_active = wr.active;
    in->local_retries_exhausted = wr.retries_exhausted;

    struct bsp_source_status *li = &in->sources[BSP_SOURCE_LOCAL_IMPORT];
    li->source = BSP_SOURCE_LOCAL_IMPORT;
    li->available = wr.active;
    li->healthy = wr.active && wr.distinct_peer_count > 0;
    li->height = wr.missing_height > 0 ? wr.missing_height - 1
                                       : in->local_height;
    li->progress_current = li->height;
    li->progress_total = wr.missing_height;
    li->retry_count = wr.retry_count;
    li->distinct_peer_count = wr.distinct_peer_count;
    bsp_copy_text(li->state, sizeof(li->state),
                  wr.mode[0] ? wr.mode : (wr.active ? "active" : "idle"));
    snprintf(li->reason, sizeof(li->reason),
             "mode=%s retries=%d distinct_peers=%d",
             wr.mode, wr.retry_count, wr.distinct_peer_count);

    struct snapshot_sync_service *ssvc = app_runtime_snapshot_sync();
    struct snapsync_status sstat;
    memset(&sstat, 0, sizeof(sstat));
    if (ssvc)
        snapsync_get_status_snapshot(ssvc, &sstat);
    struct bsp_source_status *snap = &in->sources[BSP_SOURCE_SNAPSHOT];
    snap->source = BSP_SOURCE_SNAPSHOT;
    snap->available = ssvc && sstat.state != SNAPSYNC_IDLE;
    snap->healthy = ssvc &&
        (sstat.state == SNAPSYNC_NEGOTIATING ||
         sstat.state == SNAPSYNC_RECEIVING ||
         sstat.state == SNAPSYNC_VERIFYING ||
         sstat.state == SNAPSYNC_COMPLETE);
    snap->authorized = sstat.state == SNAPSYNC_COMPLETE;
    snap->blocked = sstat.state == SNAPSYNC_FAILED;
    snap->height = sstat.offered_height;
    snap->progress_current = sstat.staged_row_count;
    snap->progress_total = (int64_t)sstat.offered_count;
    snap->serving_peer_id = (int64_t)sstat.serving_peer_id;
    bsp_copy_text(snap->state, sizeof(snap->state),
                  snapsync_state_name(sstat.state));
    if (snap->blocked)
        bsp_copy_text(snap->blocker, sizeof(snap->blocker), "snapshot_failed");
    snprintf(snap->reason, sizeof(snap->reason),
             "state=%s peer=%u staged=%lld offered=%llu",
             snapsync_state_name(sstat.state),
             sstat.serving_peer_id,
             (long long)sstat.staged_row_count,
             (unsigned long long)sstat.offered_count);
    if (snap->height > in->target_height)
        in->target_height = snap->height;

    struct legacy_mirror_sync_stats msnap;
    memset(&msnap, 0, sizeof(msnap));
    legacy_mirror_sync_stats_snapshot(&msnap);
    struct bsp_source_status *mir = &in->sources[BSP_SOURCE_ZCLASSICD_MIRROR];
    mir->source = BSP_SOURCE_ZCLASSICD_MIRROR;
    mir->available = msnap.enabled && msnap.reachable;
    mir->healthy = msnap.enabled && msnap.lag_known && msnap.lag >= 0 &&
                   (msnap.state[0] == '\0' ||
                    strcmp(msnap.state, "blocked") != 0);
    mir->height = msnap.legacy_advisory_height_known
                      ? msnap.legacy_height : -1;
    mir->failures = msnap.rpc_errors;
    mir->progress_current = msnap.blocks_applied;
    mir->progress_total = msnap.target_height;
    mir->lag = msnap.lag_known ? msnap.lag : -1;
    mir->lag_known = msnap.lag_known;
    mir->lag_valid = msnap.lag_valid;
    mir->retry_count = msnap.local_retry_count;
    mir->distinct_peer_count = msnap.local_distinct_peer_count;
    bsp_copy_text(mir->state, sizeof(mir->state),
                  msnap.state[0] ? msnap.state :
                  (mir->available ? "healthy" : "unavailable"));
    mir->blocked = msnap.activation_blocker_reason[0] != '\0' ||
                   strcmp(msnap.state, "blocked") == 0;
    if (mir->blocked) {
        bsp_copy_text(mir->blocker, sizeof(mir->blocker),
                      msnap.activation_blocker_reason[0] ? msnap.activation_blocker_reason
                                                   : msnap.last_blocker_id);
        mir->blocked_class = bsp_classify_mirror_blocker_class(mir->blocker);
    } else {
        mir->blocked_class = BLOCKER_TRANSIENT;
    }
    mir->authorized = mir->available && mir->healthy && !mir->blocked;
    if (msnap.lag_known) {
        snprintf(mir->reason, sizeof(mir->reason),
                 "state=%s lag=%d local_retries_exhausted=%s",
                 msnap.state, msnap.lag,
                 msnap.local_retries_exhausted ? "true" : "false");
    } else {
        snprintf(mir->reason, sizeof(mir->reason),
                 "state=%s lag=unknown local_retries_exhausted=%s",
                 msnap.state,
                 msnap.local_retries_exhausted ? "true" : "false");
    }
    in->mirror_lag_sla_breach_blocks = msnap.lag_sla_breach_blocks;
    if (msnap.target_height_known && msnap.target_height > in->target_height)
        in->target_height = msnap.target_height;
    if (msnap.legacy_advisory_height_known &&
        msnap.legacy_height > in->target_height)
        in->target_height = msnap.legacy_height;

    if (p2p->height > in->target_height)
        in->target_height = p2p->height;
    if (in->best_header_height > in->target_height)
        in->target_height = in->best_header_height;
    if (in->target_height < in->local_height)
        in->target_height = in->local_height;

    in->projection_height = -1;
    in->projection_lag = -1;
    in->projection_deferred = false;
    bsp_copy_text(in->projection_state, sizeof(in->projection_state),
                  "unknown");
    if (ndb && ndb->open) {
        int projection_height = db_block_max_height(ndb);
        in->projection_height = projection_height;
        if (projection_height >= 0) {
            int projection_basis = in->local_height;
            if (in->target_height > projection_basis)
                projection_basis = in->target_height;
            if (projection_basis < 0)
                projection_basis = projection_height;
            in->projection_lag =
                projection_basis > projection_height
                    ? (int64_t)(projection_basis - projection_height)
                    : 0;
            in->projection_deferred = in->projection_lag > 0;
            bsp_copy_text(in->projection_state, sizeof(in->projection_state),
                          in->projection_deferred ? "deferred" : "current");
        } else {
            in->projection_deferred = in->local_height > 0;
            bsp_copy_text(in->projection_state, sizeof(in->projection_state),
                          in->projection_deferred ? "missing" : "empty");
        }
    }
}

void block_source_policy_note_projection_deferred(int height,
                                                  const char *reason)
{
    struct node_db *ndb = NULL;
    int64_t total = 0;
    int64_t when = (int64_t)platform_time_wall_time_t();
    char reason_copy[64];
    bool persist = false;

    bsp_copy_text(reason_copy, sizeof(reason_copy),
                  reason && *reason ? reason : "unknown");

    bsp_lock_init_once();
    zcl_mutex_lock(&g_bsp.lock);
    g_bsp.projection_deferred_total++;
    total = g_bsp.projection_deferred_total;
    g_bsp.last_projection_deferred_height = height;
    g_bsp.last_projection_deferred_time = when;
    bsp_copy_text(g_bsp.last_projection_deferred_reason,
                  sizeof(g_bsp.last_projection_deferred_reason),
                  reason_copy);
    ndb = g_bsp.node_db;
    /* Persist/event throttle. Every note updates the in-memory counters
     * (status + dump-state readers stay exact), but the node.db mirror is
     * 4 autocommit KV UPSERTs plus one event-log append PER CALL — on a
     * catch-up fold this runs per block and sits on the tip-finalize
     * critical path. The mirror exists for crash-time diagnosis, so
     * persisting at most once per interval loses nothing an operator can
     * act on. At the live tip blocks are minutes apart, the throttle never
     * binds, and every note still persists and emits on every call. */
    persist = !ndb ||
              g_bsp.last_projection_deferred_persist == 0 ||
              when - g_bsp.last_projection_deferred_persist >=
                  BSP_PROJECTION_DEFERRED_PERSIST_INTERVAL_SECS;
    if (persist)
        g_bsp.last_projection_deferred_persist = when;
    zcl_mutex_unlock(&g_bsp.lock);

    if (persist && ndb) {
        (void)node_db_state_set_int(ndb, BSP_KEY_PROJECTION_DEFERRED_TOTAL,
                                    total);
        (void)node_db_state_set_int(
            ndb, BSP_KEY_LAST_PROJECTION_DEFERRED_HEIGHT,
            (int64_t)height);
        (void)node_db_state_set_int(ndb, BSP_KEY_LAST_PROJECTION_DEFERRED_TIME,
                                    when);
        (void)node_db_state_set(ndb, BSP_KEY_LAST_PROJECTION_DEFERRED_REASON,
                                reason_copy, strlen(reason_copy) + 1);
    }

    if (persist)
        event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                    "op=projection_deferred reason=%s h=%d total=%lld "
                    "authority=local_consensus_validation",
                    reason_copy, height, (long long)total);
}

void block_source_policy_reset_for_test(void)
{
    bsp_lock_init_once();
    zcl_mutex_lock(&g_bsp.lock);
    g_bsp.connman = NULL;
    g_bsp.main_state = NULL;
    g_bsp.node_db = NULL;
    memset(&g_bsp.last, 0, sizeof(g_bsp.last));
    g_bsp.has_last = false;
    g_bsp.last_decision_time = 0;
    memset(g_bsp.last_op, 0, sizeof(g_bsp.last_op));
    g_bsp.decisions_total = 0;
    g_bsp.projection_deferred_total = 0;
    g_bsp.last_projection_deferred_height = 0;
    g_bsp.last_projection_deferred_time = 0;
    memset(g_bsp.last_projection_deferred_reason, 0,
           sizeof(g_bsp.last_projection_deferred_reason));
    g_bsp.last_projection_deferred_persist = 0;
    zcl_mutex_unlock(&g_bsp.lock);
}
