/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the Prometheus alert subsystem's private cross-TU contract — the
 * rule/state types and the rule-catalog entry points that the catalog defines
 * and the evaluation engine consumes.
 *
 * prometheus_metrics.c owns the GAUGES and the EVALUATION ENGINE: every
 * counter and hysteresis gauge, the exposition renderer, the per-rule value
 * fetch, and the edge-triggered latch + cooldown + EV_CONDITION_DETECTED
 * firing loop, all under g_alert_lock. prometheus_metrics_alert_rules.c owns
 * the CATALOG: which rules exist, their ZCL_ALERT_* env-tunable thresholds,
 * and the comparison vocabulary. The split happened when the combined file
 * passed the 800-line shape ceiling. These declarations are all that crosses
 * that seam, so they live here and nowhere else — nothing outside those two
 * translation units may include this header.
 */

#ifndef ZCL_METRICS_PROMETHEUS_METRICS_INTERNAL_H
#define ZCL_METRICS_PROMETHEUS_METRICS_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum metric_alert_cmp {
    METRIC_ALERT_GT,
    METRIC_ALERT_LT,
    METRIC_ALERT_GE,
    METRIC_ALERT_LE,
};

struct metric_alert_rule {
    const char        *gauge_name;    /* Prometheus metric name (display only) */
    enum metric_alert_cmp cmp;
    double              threshold;
    const char        *event_name;    /* rule id: "name=metric_alert.<event_name>" */
    const char        *severity;      /* "severity=<severity>" in the payload */
    int                 cooldown_sec; /* min seconds between repeat fires while crossed */
};

#define METRICS_PROMETHEUS_ALERT_MAX_RULES 12

struct metric_alert_rule_state {
    bool     active;           /* latched true while the gauge stays crossed */
    int64_t  last_fired_unix;
    uint64_t fire_count;
};

/* ── the rule catalog (prometheus_metrics_alert_rules.c) ────────────
 *
 * The rule table and its per-rule latch state. Both are seeded by
 * alert_rules_seed_locked() and read/written by the evaluation engine in
 * prometheus_metrics.c; every access on both sides is made under that file's
 * g_alert_lock, which is the ONLY lock either half takes for them. They carry
 * external linkage solely because the seam runs between the catalog that
 * fills them and the engine that walks them. */
extern struct metric_alert_rule g_alert_rules[METRICS_PROMETHEUS_ALERT_MAX_RULES];
extern struct metric_alert_rule_state
    g_alert_state[METRICS_PROMETHEUS_ALERT_MAX_RULES];
extern size_t g_alert_rule_count;

/* Env override for a threshold. Also used directly by the gauge setters in
 * prometheus_metrics.c for their own env-tunable hysteresis thresholds
 * (peer_count_collapsed etc.). */
double alert_env_double(const char *name, double def);

/* Seeded once (lazily, so ZCL_ALERT_* env vars set before the first
 * evaluation are honored). Idempotent. Caller holds g_alert_lock. */
void alert_rules_seed_locked(void);

/* The comparison vocabulary: the crossing test and its display symbol. */
bool alert_cmp_crossed(enum metric_alert_cmp cmp, double value,
                       double threshold);
const char *alert_cmp_symbol(enum metric_alert_cmp cmp);

#endif /* ZCL_METRICS_PROMETHEUS_METRICS_INTERNAL_H */
