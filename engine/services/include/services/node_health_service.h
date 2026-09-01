/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_NODE_HEALTH_SERVICE_H
#define ZCL_NODE_HEALTH_SERVICE_H

#include "event/event.h"
#include "sync/sync_state.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_NODE_HEALTH_LAG_WARN_BLOCKS 10
#define ZCL_NODE_HEALTH_OPERATOR_DETAIL_LEN (EVENT_PAYLOAD_SIZE + 1)
#define ZCL_NODE_HEALTH_REASON_LEN (EVENT_PAYLOAD_SIZE + 64)

struct node_db;
struct main_state;
struct bsp_decision;

struct node_health_snapshot {
    enum sync_state sync_state;
    bool healthy;
    /* Explicit serving split for operator surfaces:
     * - healthy is the existing restart/heartbeat gate.
     * - serving says whether the node should be treated as green for
     *   serving validated chain state.
     * - warning_* carries yellow observations that should be visible but
     *   must not be mistaken for a red blocker.
     * - blocking_reason is populated only when serving/healthy is false.
     *
     * degraded_reason remains for backward-compatible consumers and may
     * contain either a blocking reason or the highest-priority warning. */
    bool serving;
    bool warning;
    size_t warning_count;
    bool synced;
    bool has_peers;
    bool tor_enabled;
    bool tor_ready;
    bool onion_service_ready;
    /* True when the active tip's block timestamp is older than the
     * block-time staleness threshold. This is an observation used to
     * trigger extra peer/header probes; by itself it does not make an
     * otherwise synced at-tip node unhealthy because a quiet chain can
     * legitimately have no recent block. */
    bool tip_stale;
    bool queue_backed_up;
    size_t peer_count;
    int tip_height;
    int header_height;
    int peer_best_height;
    int tip_lag;
    /* Prime Directive health = network_tip − log_head, expressed as one
     * real number. `log_head` is the tip_finalize stage cursor (the
     * height the reducer has finalized through the event log);
     * `log_head_gap` = peer_best_height − log_head. The no-forward-progress
     * canary reads this. -1 when unknown. */
    int log_head;
    int log_head_gap;
    int64_t tip_stale_seconds;
    int64_t utxo_count;
    int64_t wal_size_bytes;
    int64_t uptime_seconds;
    int64_t db_last_activity_age_seconds;
    int error_total;
    int db_last_sqlite_rc;
    int64_t last_error_age_seconds;
    bool last_error_recent;
    char last_error[EVENT_PAYLOAD_SIZE + 1];
    char last_error_type[64];
    char degraded_reason[ZCL_NODE_HEALTH_REASON_LEN];
    char blocking_reason[ZCL_NODE_HEALTH_REASON_LEN];
    char warning_reasons[256];
    char onion_address[128];
    char db_last_op[64];
    bool db_open;
    bool db_tx_open;
    bool db_turbo_mode;
    bool db_service_started;
    bool db_service_worker_started;
    bool db_service_stop_requested;
    size_t db_service_queue_depth;
    int64_t db_service_uptime_seconds;
    bool catchup_active;
    int catchup_height;
    int catchup_target_height;
    int64_t catchup_uptime_seconds;
    int64_t catchup_progress_age_seconds;
    bool import_active;
    int import_rows_written;
    int64_t import_uptime_seconds;
    int64_t import_progress_age_seconds;
    uint64_t blocks_requested;
    uint64_t blocks_received;
    uint64_t blocks_timed_out;
    uint64_t in_flight;
    uint64_t queued;
    uint64_t download_bytes_received;
    double   download_mbps_avg;

    /* Memory */
    int64_t memory_rss_mb;

    /* Watchdog stats */
    int      wd_checks_run;
    int      wd_recoveries;
    double   wd_blocks_per_sec;
    int      wd_escalation_level;
    int64_t  wd_last_recovery_time;
    int      wd_last_recovery_type;       /* enum watchdog_recovery_type */
    int      wd_last_recovery_target_height;
    int      wd_last_recovery_manifest_height;
    char     wd_last_recovery_name[32];
    char     wd_last_recovery_reason[96];
    char     wd_last_recovery_trigger[64];

    /* Seconds since the most recent block-connect, or -1 if we have
     * not seen one yet (cold boot). Decoupled from sync_state so a
     * stall in HEADERS_DOWNLOAD with header_gap=0 surfaces as a real
     * staleness signal. Healthy gate flips false when this exceeds
     * TIP_ADVANCE_AGE_DEGRADED_SECS (600) AND peers>0 AND
     * sync_state!=SYNC_AT_TIP. */
    int64_t  tip_advance_age_seconds;

    /* Mirror lag SLO breach severity (none|warn|critical|fatal). "fatal"
     * flips snapshot.healthy false for serving, conditions, and remedies;
     * it remains separate from the systemd process-hang watchdog. Surfaced
     * via `z23 status`, `z23 dumpstate health`, and Prometheus
     * zcl_mirror_lag_breach_seconds. */
    int64_t  mirror_lag_blocks;
    int64_t  mirror_lag_breach_seconds;
    int64_t  mirror_lag_critical_seconds;
    char     mirror_lag_breach_severity[16];

    /* Magic Bean / zclassic23 peer classification: counts of currently
     * connected peers whose advertised subver matches the legacy
     * /MagicBean:.../ or the native /ZClassic23:.../ identifier. ZClassic23 is
     * counted by unique remote host so an inbound+outbound socket pair to one
     * node does not inflate the physical-node count shown on dashboards. */
    size_t   magicbean_peer_count;
    size_t   zclassic_c23_peer_count;

    /* Operator-needed latch (from platform/modules/util/alerts.c). True once the
     * auto-healing condition engine exhausts remedies for a CRITICAL
     * problem and emits EV_OPERATOR_NEEDED — the "a halt can never be
     * silent" signal. Flips healthy=false and sets degraded_reason so
     * `z23 status` shows it and the sd_notify heartbeat stops. Cleared
     * automatically when the underlying condition clears. */
    bool     operator_needed;
    bool     operator_latch_recovered;
    char     operator_needed_detail[ZCL_NODE_HEALTH_OPERATOR_DETAIL_LEN];

    /* Fail-loud validation pack rollup (services/invariant_sentinel.h):
     * false while any pack blocker or the chain HOLD latch is active.
     * detail = the first active pack blocker id. Informational — does
     * NOT flip `healthy` (a held node keeps serving; the pack already
     * pages via EV_OPERATOR_NEEDED). */
    bool     validation_pack_ok;
    char     validation_pack_detail[64];
};

void node_health_collect(struct node_health_snapshot *snapshot,
                         struct node_db *ndb,
                         const struct main_state *ms);

/* Last-collected verdict timestamp, published by node_health_collect() on
 * every call (health ring, RPC handlers, soak service — last writer wins).
 * Returns false when no collect has completed yet this process. This is
 * diagnostic evidence only: a collect can block for minutes on reducer-held
 * locks during bulk ingest, so publication freshness must not decide process
 * liveness. */
bool node_health_last_verdict(int64_t *publish_us_out);

/* Publish side of the same contract (node_health_verdict.c): called once at
 * the end of every node_health_collect. */
void node_health_verdict_publish(const struct node_health_snapshot *snapshot);
/* Does the block-source policy consider us to be at the chain tip?
 *
 * This is a HEIGHT-and-source-health question over one bsp_decision: the
 * source we picked is available/healthy/selectable and its target is no more
 * than one block above us. It is NOT the question "am I synced", and it is not
 * permission to publish an at-tip claim.
 *
 * That distinction was the bug. node_health_collect() used to let a true
 * answer here overwrite the sync FSM's verdict with an unconditional
 * SYNC_AT_TIP + synced=true. The FSM refuses at-tip while the node cannot
 * prove it holds the block bodies for its own history, so a node with a hole
 * below its tip had that refusal overturned in the health snapshot, and the
 * manufactured claim then went out on /api/status, /api/node/summary,
 * /api/v1/health, `healthcheck full`, and the starter-bundle mint gate — a
 * second, ungated answer to a question that already had a gated one.
 *
 * So the UPGRADE in node_health_collect() now also requires
 * body_history_is_proven() (storage/body_history.h — "the single question
 * every at-tip gate asks"), which is fail-closed: false for a known hole AND
 * false for a node that has never measured. The DOWNGRADE stays unconditional,
 * because only ever weakening a claim never needs permission.
 *
 * Kept pure — a predicate over its argument, no globals — so the E2
 * one-result-type override at the top of node_health_service.c stays true. The
 * archive gate lives at the call site, not in here. */
bool node_health_chain_advance_synced(const struct bsp_decision *decision);

/* Pure resolution of the Prime-Directive "network tip" used for the health lag
 * number, hardened against a single lying peer (see NODE_HEALTH_PLAUSIBLE_TIP_BAND
 * in node_health_service.c):
 *   - raw_max          : MAX advertised height over connected peers (-1 if none).
 *   - peers_above_band : how many connected peers claim > header_tip+band.
 *   - header_tip       : our validated header tip (-1 if unknown → no clamp).
 *   - modal_ready      : network_monitor has a folded view.
 *   - modal_height     : its modal advertised height (-1 if none).
 *   - modal_count      : peers agreeing on modal_height.
 * A lone above-band claim is clamped to header_tip+band; a modal agreed by
 * >= 3 peers wins over the clamped MAX. Health READ only — never chain
 * selection. */
int64_t node_health_resolve_network_tip(int64_t raw_max, int peers_above_band,
                                        int64_t header_tip, bool modal_ready,
                                        int64_t modal_height, int modal_count);
#ifdef ZCL_TESTING
void node_health_test_set_log_head_override(int log_head);
void node_health_test_set_chain_advance_decision_override(
    const struct bsp_decision *decision);
void node_health_test_set_memory_rss_mb_override(int64_t memory_rss_mb);
#endif

#endif
