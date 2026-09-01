/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Always-on legacy mirror sync service.
 *
 * Keeps this node close to a co-located zclassicd by using zclassicd
 * as the fast source for headers and block bodies while still routing
 * every header and block through local consensus validation.
 */

#ifndef ZCL_SERVICES_LEGACY_MIRROR_SYNC_SERVICE_H
#define ZCL_SERVICES_LEGACY_MIRROR_SYNC_SERVICE_H

#include <stdbool.h>
#include <stdint.h>

#include "util/blocker.h"
#include "util/result.h"

struct main_state;
struct coins_view_cache;
struct chain_params;
struct json_value;

struct legacy_mirror_sync_config {
    const char *rpc_host;        /* default "127.0.0.1" */
    int         rpc_port;        /* default 8232 */
    const char *rpc_user;        /* read zclassic.conf if NULL */
    const char *rpc_password;    /* read zclassic.conf if NULL */
    int         cadence_secs;    /* default 3 */
    int         max_blocks_tick; /* default 512 */
    int         lag_sla;         /* default 1 — block-level "caught up" threshold */
    /* SLO thresholds for fail-loud + concurrent redundancy.
     * lag > breach_blocks for >= breach_secs → EV_LAG_SLO_BREACH severity=critical
     * lag > critical_blocks for >= critical_secs → severity=fatal + health=false. */
    int         lag_sla_breach_blocks;   /* default 10 */
    int         lag_sla_breach_secs;     /* default 60 */
    int         lag_sla_critical_blocks; /* default 100 */
    int         lag_sla_critical_secs;   /* default 300 */
    bool        enabled;         /* default true when credentials exist */
};

struct zcl_result
legacy_mirror_sync_init(const struct legacy_mirror_sync_config *cfg,
                        struct main_state *ms,
                        struct coins_view_cache *coins_tip,
                        const struct chain_params *params,
                        const char *datadir);
struct zcl_result legacy_mirror_sync_start(void);
void legacy_mirror_sync_stop(void);

/* One synchronous catch-up attempt. Uses the service single-flight lock,
 * so callers may invoke this from watchdog/manual RPC paths without
 * overlapping the heartbeat tick. */
struct zcl_result legacy_mirror_sync_request_catchup(const char *reason);
struct zcl_result legacy_mirror_sync_request_catchup_result(
    const char *reason);

struct legacy_mirror_sync_stats {
    bool    enabled;
    bool    running;
    bool    reachable;
    bool    zclassicd_rpc_transport_reachable;
    bool    legacy_oracle_usable;
    bool    in_flight;
    int     legacy_height;
    int     legacy_headers;
    int     local_height;
    int     best_header_height;
    bool    legacy_advisory_height_known;
    bool    target_height_known;
    bool    lag_known;
    bool    lag_valid;
    /* Tip hashes belong to local_height and legacy_height respectively.
     * They are directly comparable only when those heights are equal.
     * comparison_* is the explicit same-height chain comparison and remains
     * unknown until both hashes at comparison_height have been obtained. */
    bool    tip_hashes_agree;
    bool    comparison_known;
    bool    comparison_hashes_agree;
    int     comparison_height;
    int     hash_disagreement_height;
    int     lag;
    int     target_height;
    int     authority_rewind_target;
    int     csr_sqlite_rc;
    int     last_advanced_height;
    int     last_progress_blocks;
    bool    local_recovery_active;
    bool    mirror_repair_gated_by_local_retries;
    bool    local_retries_exhausted;
    int     local_missing_height;
    int     local_retry_count;
    int     local_distinct_peer_count;
    int     local_peer_rotation_count;
    int     stuck_height;
    unsigned int stuck_status_flags;
    char    stuck_reason[64];
    int64_t stalls_total;
    int64_t last_catchup;
    int64_t last_attempt;
    int64_t catchups_total;
    int64_t rpc_errors;
    int64_t blocks_applied;
    int64_t headers_added;
    char    state[32];
    int64_t overrides_total;
    int64_t unsafe_overrides_total;
    int64_t blockers_total;
    int     last_override_height;
    char    zclassic23_hash[65];
    char    zclassicd_hash[65];
    char    comparison_zclassic23_hash[65];
    char    comparison_zclassicd_hash[65];
    char    consensus_authority[32];
    char    candidate_trust[32];
    bool    override_active;
    bool    last_override_safe;
    char    last_override_reason[128];
    char    last_override_scope[32];
    enum blocker_class activation_blocker_class;
    enum blocker_class last_blocker_class;
    char    activation_blocker_reason[128];
    char    last_blocker_id[64];
    bool    blocker_recovered_by_tip_agreement;
    bool    blocker_recovered_by_common_height_agreement;
    char    csr_failure_reason[160];
    char    last_error[160];
    int     zclassicd_rpc_error_code;
    char    zclassicd_rpc_error_message[160];
    /* Lag-SLO breach state — fail loudly and fast. Tracked atomically;
     * snapshot is point-in-time and consistent within one tick. */
    int     lag_sla_breach_blocks;   /* configured threshold */
    int     lag_sla_breach_secs;
    int     lag_sla_critical_blocks;
    int     lag_sla_critical_secs;
    int64_t lag_breach_since;        /* unix ts when lag first crossed breach; 0 if under */
    int64_t lag_critical_since;      /* unix ts when lag first crossed critical; 0 if under */
    int64_t lag_breach_seconds;      /* time spent above breach (clamped to 0) */
    int64_t lag_critical_seconds;    /* time spent above critical */
    /* "none" | "warn" | "critical" | "fatal" — promoted to health.severity */
    char    lag_breach_severity[16];
};

void legacy_mirror_sync_stats_snapshot(
    struct legacy_mirror_sync_stats *out);
/* Fast-lane snapshot for first-call APIs. Reads the mirror monitor's cached
 * atomics/strings only; it does not refresh local chain heights or walk the
 * active-chain hash index. Use the full snapshot for health/mirror drilldowns
 * that can afford richer synchronous evidence. */
void legacy_mirror_sync_stats_cached_snapshot(
    struct legacy_mirror_sync_stats *out);
/* API compatibility helper: legacy numeric lag fields report 0 when the
 * mirror height is unknown. Use the paired *_observed JSON fields to
 * distinguish "unknown" (null) from a real zero-block lag. */
int legacy_mirror_sync_reported_lag(
    const struct legacy_mirror_sync_stats *stats);
void legacy_mirror_sync_push_observed_lag_json(
    struct json_value *out,
    const char *key,
    const struct legacy_mirror_sync_stats *stats);
void legacy_mirror_sync_push_status_contract_json(
    struct json_value *out,
    const struct legacy_mirror_sync_stats *stats);
const char *legacy_mirror_sync_blocker_code(
    const struct legacy_mirror_sync_stats *stats);
/* Recovery evidence can suppress only the exact hash-disagreement it proves;
 * a different remaining blocker is always active. */
bool legacy_mirror_sync_blocker_is_active(
    const struct legacy_mirror_sync_stats *stats);
bool legacy_mirror_sync_blocker_should_surface(
    const struct legacy_mirror_sync_stats *stats,
    bool non_legacy_source_selected);
bool legacy_mirror_sync_dump_state_json(struct json_value *out,
                                        const char *key);

/* Re-read env-tunable mirror knobs (cadence, max blocks per tick, lag SLA
 * thresholds) into the running service. Safe to call any time after
 * legacy_mirror_sync_init; takes g_lms.lock briefly. Breach latches are
 * NOT cleared — if a tighter threshold should fire, the next tick's
 * evaluator will see the still-elevated lag and emit. If a looser
 * threshold now puts lag under, the natural reset path clears the latch. */
void legacy_mirror_sync_reload_from_env(void);

void legacy_mirror_sync_reset_for_test(void);
#ifdef ZCL_TESTING
void legacy_mirror_sync_test_set_stats(
    const struct legacy_mirror_sync_stats *stats,
    struct main_state *ms);
#endif

#endif /* ZCL_SERVICES_LEGACY_MIRROR_SYNC_SERVICE_H */
