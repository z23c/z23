/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the metric-threshold alert CATALOG — which rules exist, the
 * ZCL_ALERT_* env knob behind each threshold, and the comparison vocabulary.
 *
 * Split out of prometheus_metrics.c along the file-size ceiling seam between
 * policy and mechanism. prometheus_metrics.c keeps the gauges themselves, the
 * exposition renderer, the per-rule value fetch, and the edge-triggered
 * latch + cooldown + EV_CONDITION_DETECTED firing loop; this file holds the
 * declarative table those mechanisms walk. Adding or retuning a rule is
 * therefore an edit to this file alone. Rationale for the rule shape (edge
 * trigger, cooldown, event vehicle) lives with the engine in
 * prometheus_metrics.c; the symbols that cross the seam live in
 * prometheus_metrics_internal.h.
 *
 * LOCKING: g_alert_rules / g_alert_state / g_alert_rule_count are written
 * here only from alert_rules_seed_locked(), whose caller in
 * prometheus_metrics.c holds g_alert_lock. This file takes no lock of its
 * own.
 */

#include "prometheus_metrics_internal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct metric_alert_rule g_alert_rules[METRICS_PROMETHEUS_ALERT_MAX_RULES];
struct metric_alert_rule_state
    g_alert_state[METRICS_PROMETHEUS_ALERT_MAX_RULES];
size_t g_alert_rule_count;
static bool g_alert_rules_seeded;

/* Env override for a threshold, trivial cases only (numeric knobs an
 * operator may reasonably want to tune without a rebuild). Malformed or
 * absent env values fall back to `def`. */
double alert_env_double(const char *name, double def)
{
    const char *v = getenv(name);
    if (!v || !*v) return def;
    char *end = NULL;
    double d = strtod(v, &end);
    if (end == v) return def;  /* not parseable — keep the default */
    return d;
}

/* Seeded once (lazily, so ZCL_ALERT_* env vars set before the first
 * evaluation are honored). Idempotent. */
void alert_rules_seed_locked(void)
{
    if (g_alert_rules_seeded) return;

    g_alert_rule_count = 0;
    g_alert_rules[g_alert_rule_count++] = (struct metric_alert_rule){
        .gauge_name   = "zcl_tip_advance_age_seconds",
        .cmp          = METRIC_ALERT_GT,
        .threshold    = alert_env_double("ZCL_ALERT_TIP_STALL_SECS", 600.0),
        .event_name   = "tip_stalled",
        .severity     = "critical",
        .cooldown_sec = 300,
    };
    g_alert_rules[g_alert_rule_count++] = (struct metric_alert_rule){
        .gauge_name   = "zcl_mirror_lag_blocks",
        .cmp          = METRIC_ALERT_GT,
        .threshold    = alert_env_double("ZCL_ALERT_MIRROR_LAG_BLOCKS", 50.0),
        .event_name   = "mirror_lag_high",
        .severity     = "warning",
        .cooldown_sec = 300,
    };
    g_alert_rules[g_alert_rule_count++] = (struct metric_alert_rule){
        .gauge_name   = "zcl_mirror_lag_critical_seconds",
        .cmp          = METRIC_ALERT_GT,
        .threshold    = 0.0,
        .event_name   = "mirror_lag_critical",
        .severity     = "critical",
        .cooldown_sec = 300,
    };
    g_alert_rules[g_alert_rule_count++] = (struct metric_alert_rule){
        /* Mirrors the comment at the zcl_blockers_active render site
         * above: "permanent>0 is always an operator-escalation event". */
        .gauge_name   = "zcl_blockers_active{class=\"permanent\"}",
        .cmp          = METRIC_ALERT_GT,
        .threshold    = 0.0,
        .event_name   = "blocker_permanent_active",
        .severity     = "critical",
        .cooldown_sec = 300,
    };
    g_alert_rules[g_alert_rule_count++] = (struct metric_alert_rule){
        .gauge_name   = "zcl_rss_mb",
        .cmp          = METRIC_ALERT_GT,
        .threshold    = alert_env_double("ZCL_ALERT_RSS_MB_CEILING", 6000.0),
        .event_name   = "rss_high",
        .severity     = "warning",
        .cooldown_sec = 300,
    };
    g_alert_rules[g_alert_rule_count++] = (struct metric_alert_rule){
        /* zcl_header_gap_breach_seconds already folds in the magnitude
         * threshold (ZCL_ALERT_HEADER_GAP_BLOCKS, default 144) and the
         * SYNC_HEADERS_DOWNLOAD exclusion — see metrics_prometheus_set_header_gap.
         * This is the rule that pages a node held hundreds of blocks behind
         * headers for hours with tip_stalled
         * as the only signal, because tip_advance_age only fires on a
         * total block-connect stall, not a growing header/served gap. */
        .gauge_name   = "zcl_header_gap_breach_seconds",
        .cmp          = METRIC_ALERT_GT,
        .threshold    = alert_env_double("ZCL_ALERT_HEADER_GAP_BREACH_SECS", 900.0),
        .event_name   = "header_gap_growing",
        .severity     = "critical",
        .cooldown_sec = 300,
    };
    g_alert_rules[g_alert_rule_count++] = (struct metric_alert_rule){
        /* zcl_peer_collapse_breach_seconds already folds in the peer
         * floor (ZCL_ALERT_PEER_COLLAPSE_MIN_PEERS, default 2) and the
         * post-boot grace window (ZCL_ALERT_PEER_COLLAPSE_GRACE_SECS,
         * default 120s) — see metrics_prometheus_set_node_gauges. */
        .gauge_name   = "zcl_peer_collapse_breach_seconds",
        .cmp          = METRIC_ALERT_GT,
        .threshold    = alert_env_double("ZCL_ALERT_PEER_COLLAPSE_SECS", 300.0),
        .event_name   = "peer_count_collapsed",
        .severity     = "critical",
        .cooldown_sec = 300,
    };
    g_alert_rules[g_alert_rule_count++] = (struct metric_alert_rule){
        /* zcl_sync_state_stuck_seconds is 0 whenever at_tip or the state
         * id last changed — see metrics_prometheus_set_sync_state. */
        .gauge_name   = "zcl_sync_state_stuck_seconds",
        .cmp          = METRIC_ALERT_GT,
        .threshold    = alert_env_double("ZCL_ALERT_SYNC_STUCK_SECS", 3600.0),
        .event_name   = "sync_state_stuck",
        .severity     = "warning",
        .cooldown_sec = 300,
    };
    g_alert_rules[g_alert_rule_count++] = (struct metric_alert_rule){
        /* zcl_consensus_reject_delta is the rolling-window delta of the
         * existing zcl_consensus_rejects_total{kind="all",reason="all"}
         * counter — see the windowing step at the top of
         * metrics_prometheus_evaluate_alert_rules(). */
        .gauge_name   = "zcl_consensus_reject_delta",
        .cmp          = METRIC_ALERT_GT,
        .threshold    = alert_env_double("ZCL_ALERT_CONSENSUS_REJECT_DELTA", 20.0),
        .event_name   = "consensus_reject_spike",
        .severity     = "warning",
        .cooldown_sec = 300,
    };

    memset(g_alert_state, 0, sizeof(g_alert_state));
    g_alert_rules_seeded = true;
}

bool alert_cmp_crossed(enum metric_alert_cmp cmp, double value,
                       double threshold)
{
    switch (cmp) {
    case METRIC_ALERT_GT: return value >  threshold;
    case METRIC_ALERT_LT: return value <  threshold;
    case METRIC_ALERT_GE: return value >= threshold;
    case METRIC_ALERT_LE: return value <= threshold;
    }
    return false;
}

const char *alert_cmp_symbol(enum metric_alert_cmp cmp)
{
    switch (cmp) {
    case METRIC_ALERT_GT: return ">";
    case METRIC_ALERT_LT: return "<";
    case METRIC_ALERT_GE: return ">=";
    case METRIC_ALERT_LE: return "<=";
    }
    return "?";
}
