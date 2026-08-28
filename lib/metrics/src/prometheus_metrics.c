/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Prometheus node metrics implementation. See prometheus_metrics.h.
 */

#include "metrics/prometheus_metrics.h"
#include "metrics/stage_metrics.h"
#include "core/utiltime.h"
#include "event/event.h"
#include "net/peer_scoring.h"
#include "sync/sync_state.h"
#include "util/blocker.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* Peer scoring counters.  Bucketed by offence kind so cardinality is
 * bounded by the allowlist below; anything not on the list goes into
 * "other".  Bans are a single counter — splitting them by kind would
 * be misleading because peer_misbehaving() bans on cumulative score,
 * not on the offence that crossed the threshold. */
#define METRICS_PROMETHEUS_PEER_KINDS 12
static const char *const k_peer_kind_names[METRICS_PROMETHEUS_PEER_KINDS] = {
    "timeout",
    "invalid_message",
    "flood",
    "invalid_header",
    "invalid_block",
    "unrequested",
    "offer_rejected",
    "invalid_payload",
    "invalid_chunk",
    "invalid_proof",
    "protocol_violation",
    "other",
};
static uint64_t             g_peer_offences[METRICS_PROMETHEUS_PEER_KINDS];
static uint64_t             g_peer_offences_total;
static uint64_t             g_peer_bans_total;

/* ── Node-level gauges (set by caller, read by prometheus render) ── */
static _Atomic int64_t  g_node_block_height;
static _Atomic int64_t  g_node_peer_count;
static _Atomic int64_t  g_node_rss_mb_x100;   /* fixed-point: RSS_MB * 100 */
static _Atomic int64_t  g_node_utxo_count;
static _Atomic int64_t  g_node_uptime_seconds;
/* Seconds since last EV_BLOCK_CONNECTED, fed by
 * sync_monitor_tip_advance_age() via the lib/metrics tick.
 * Negative means "not yet observed" (cold boot); emitted as -1 so
 * PromQL queries can distinguish bootstrap from a real stall via
 * `> 0` guards. */
static _Atomic int64_t  g_node_tip_advance_age = -1;

/* Mirror lag SLO breach gauges. Set by the metrics tick from the live
 * legacy_mirror_sync_stats snapshot. Pre-bootstrap defaults: lag=-1
 * (mirror not yet attached); seconds=0 (no breach). */
static _Atomic int64_t  g_mirror_lag_blocks = -1;
static _Atomic int64_t  g_mirror_lag_breach_seconds = 0;
static _Atomic int64_t  g_mirror_lag_critical_seconds = 0;

/* Peer-kind gauges. Set by the metrics tick from node_health_snapshot
 * peer classification (subver_is_magicbean / subver_is_zcl23). These
 * are the "Magic Bean reporting" signal — track how many zclassicd-era
 * peers and native zclassic23 peers are connected to us over time. */
static _Atomic int64_t  g_node_magicbean_peer_count;
static _Atomic int64_t  g_node_zcl23_peer_count;

/* Consensus reject registry — bounded (kind, reason) → count table.
 * `kind` is "tx" or "block"; reason is a kebab-case string emitted by
 * the REJECT_IF/UNLESS macros in lib/validation/src/check_*.c.  Beyond
 * `METRICS_PROMETHEUS_MAX_REJECT_REASONS` distinct (kind, reason) pairs we fold
 * into the per-kind overflow counters so cardinality stays bounded.
 * The per-kind totals are incremented unconditionally — they stay
 * consistent with the sum of slot counts + overflow counts. */
struct reject_reason_slot {
    char     reason[48];
    char     kind[8];  /* "tx" or "block" */
    uint64_t count;
};
static struct reject_reason_slot g_reject_slots[METRICS_PROMETHEUS_MAX_REJECT_REASONS];
static size_t                    g_reject_slot_count;
static uint64_t                  g_reject_total_tx;
static uint64_t                  g_reject_total_block;
static uint64_t                  g_reject_overflow_tx;
static uint64_t                  g_reject_overflow_block;

static pthread_mutex_t      g_lock = PTHREAD_MUTEX_INITIALIZER;
static bool                 g_observer_installed = false;

/* HTTP RPC middleware counter source (prometheus_metrics.h). Registered by
 * the composition root; read by the renderer under g_lock, which is also
 * where the direct rpc_http_middleware_stats_snapshot() call it replaced
 * used to run — so the lock order (g_lock then the middleware's own mutex)
 * is unchanged. */
static metrics_rpc_http_gauges_fn g_rpc_http_source = NULL;
static void                      *g_rpc_http_source_ctx = NULL;

/* Sync state gauge (set atomically alongside node gauges) */
static _Atomic int          g_node_sync_state;
static const char          *g_node_sync_state_name = "unknown";

/* ── New (Lane 1a) hysteresis gauges ───────────────────────────────
 *
 * These follow the same "breach seconds" shape as g_mirror_lag_breach_
 * seconds above (a duration gauge that a threshold alert compares
 * against, e.g. `> 0`), but the hysteresis is computed HERE instead of
 * in an owning service, using the node's own uptime counter (already
 * threaded through metrics_prometheus_set_node_gauges) as the clock basis
 * rather than wall-clock GetTime(). That makes every one of them
 * deterministically testable: a hermetic test drives "time" by simply
 * passing increasing `uptime_seconds` values, with no real sleep. */

/* header_gap_growing: best-known header height minus served height H*.
 * Raw magnitude fed by metrics_prometheus_set_header_gap(); -1 = unknown. */
static _Atomic int64_t g_header_gap_blocks = -1;
static _Atomic int64_t g_header_gap_breach_seconds;
static _Atomic int64_t g_header_gap_breach_since_uptime = -1; /* -1 = not currently breaching */

/* peer_count_collapsed: connected peers under the floor, post-boot-grace. */
static _Atomic int64_t g_peer_collapse_breach_seconds;
static _Atomic int64_t g_peer_collapse_since_uptime = -1; /* -1 = not currently collapsed */

/* sync_state_stuck: seconds the sync-state id has been unchanged while
 * not at_tip. */
static _Atomic int     g_sync_state_prev = -1; /* -1 = never observed */
static _Atomic int64_t g_sync_state_changed_at_uptime;
static _Atomic int64_t g_sync_state_stuck_seconds;

/* consensus_reject_spike: delta of total (tx+block) consensus rejects
 * over a rolling window aligned to node uptime. */
static _Atomic int64_t g_reject_spike_delta;
static _Atomic int64_t g_reject_spike_baseline_total = -1; /* -1 = not yet baselined */
static _Atomic int64_t g_reject_spike_baseline_uptime;

/* ── Parsers ────────────────────────────────────────────────── */

/* Extract a field value from a "key=value ..." payload.  Writes up to
 * cap-1 chars into out.  Stops at space or end.  Returns true if found. */
static bool parse_kv(const char *payload, size_t len, const char *key,
                     char *out, size_t cap)
{
    if (cap == 0) return false;
    out[0] = '\0';
    size_t klen = strlen(key);
    for (size_t i = 0; i < len; ) {
        /* Skip leading spaces */
        while (i < len && payload[i] == ' ') i++;
        /* Match key= */
        if (i + klen + 1 <= len &&
            strncmp(payload + i, key, klen) == 0 &&
            payload[i + klen] == '=') {
            size_t j = i + klen + 1;
            size_t o = 0;
            while (j < len && payload[j] != ' ' && o + 1 < cap) {
                out[o++] = payload[j++];
            }
            out[o] = '\0';
            return true;
        }
        /* Skip token */
        while (i < len && payload[i] != ' ') i++;
    }
    return false;
}

void metrics_prometheus_reset(void)
{
    pthread_mutex_lock(&g_lock);
    memset(g_peer_offences, 0, sizeof(g_peer_offences));
    g_peer_offences_total = 0;
    g_peer_bans_total = 0;
    memset(g_reject_slots, 0, sizeof(g_reject_slots));
    g_reject_slot_count = 0;
    g_reject_total_tx = 0;
    g_reject_total_block = 0;
    g_reject_overflow_tx = 0;
    g_reject_overflow_block = 0;
    pthread_mutex_unlock(&g_lock);

    metrics_prometheus_alerts_reset();
}

/* ── Node-level gauge setter ────────────────────────────────── */

/* Forward declaration: full definition lives in the "Metric-threshold
 * alert rules" section below (it reads ZCL_ALERT_* env overrides), but
 * the gauge setters above that section also need it for their own
 * env-tunable hysteresis thresholds (peer_count_collapsed etc.). */
static double alert_env_double(const char *name, double def);

void metrics_prometheus_set_node_gauges(int64_t block_height, int64_t peer_count,
                                 double rss_mb, int64_t utxo_count,
                                 int64_t uptime_seconds)
{
    atomic_store(&g_node_block_height, block_height);
    atomic_store(&g_node_peer_count, peer_count);
    atomic_store(&g_node_rss_mb_x100, (int64_t)(rss_mb * 100.0));
    atomic_store(&g_node_utxo_count, utxo_count);
    atomic_store(&g_node_uptime_seconds, uptime_seconds);

    /* peer_count_collapsed hysteresis: grace period after boot (so a
     * fresh node still dialing peers never fires), then accrue breach
     * seconds using uptime — NOT wall-clock — as the clock, so a
     * hermetic test can drive it without sleeping. */
    double grace_sec  = alert_env_double("ZCL_ALERT_PEER_COLLAPSE_GRACE_SECS", 120.0);
    double min_peers  = alert_env_double("ZCL_ALERT_PEER_COLLAPSE_MIN_PEERS", 2.0);
    bool   past_grace = (double)uptime_seconds >= grace_sec;
    if (past_grace && (double)peer_count < min_peers) {
        int64_t since = atomic_load(&g_peer_collapse_since_uptime);
        if (since < 0) {
            atomic_store(&g_peer_collapse_since_uptime, uptime_seconds);
            since = uptime_seconds;
        }
        int64_t breach = uptime_seconds - since;
        atomic_store(&g_peer_collapse_breach_seconds, breach > 0 ? breach : 0);
    } else {
        atomic_store(&g_peer_collapse_since_uptime, -1);
        atomic_store(&g_peer_collapse_breach_seconds, 0);
    }
}

void metrics_prometheus_set_tip_advance_age(int64_t seconds)
{
    atomic_store(&g_node_tip_advance_age, seconds);
}

void metrics_prometheus_set_mirror_lag(int64_t lag_blocks,
                                int64_t breach_seconds,
                                int64_t critical_seconds)
{
    atomic_store(&g_mirror_lag_blocks, lag_blocks);
    atomic_store(&g_mirror_lag_breach_seconds, breach_seconds);
    atomic_store(&g_mirror_lag_critical_seconds, critical_seconds);
}

void metrics_prometheus_set_peer_kinds(int64_t magicbean_count,
                                int64_t zcl23_count)
{
    atomic_store(&g_node_magicbean_peer_count, magicbean_count);
    atomic_store(&g_node_zcl23_peer_count, zcl23_count);

    /* Last of the gauge setters lib/metrics's 1-second thread calls each
     * tick (set_node_gauges, set_sync_state, set_header_gap,
     * set_tip_advance_age, set_mirror_lag, set_peer_kinds — see
     * lib/metrics/src/metrics.c's metrics_thread_fn) — so by this point
     * every gauge the alert rules read is fresh for this tick.
     * Piggy-backing here means the rule engine runs on the node's
     * existing periodic tick with no new thread. */
    metrics_prometheus_evaluate_alert_rules();
}

/* ── Metric-threshold alert rules (C3) ──────────────────────────────
 *
 * Declarative rule table over the SAME gauges rendered in
 * metrics_prometheus_render_prometheus() above — no re-parsing of the
 * rendered text, no re-enumeration of metric names. Edge-triggered:
 * a rule fires the instant its gauge crosses the threshold, then
 * stays silent until either the value drops back below threshold
 * (clearing the latch) or `cooldown_sec` elapses while still crossed
 * (a "still broken" reminder — the blocker escape-dispatch rate limit,
 * util/blocker.h BLOCKER_DEFAULT_RATE_LIMIT_MS, is the same idea at a
 * faster cadence). Firing emits EV_CONDITION_DETECTED — the generic
 * "name=... severity=..." vehicle the condition-engine healers already
 * use (lib/framework/src/condition.c) — with a `metric_alert.` name
 * prefix so it is distinguishable from a healer's own detection. That
 * event type must be present in operator_events.c's k_operator_events[]
 * allow-list to be treated as operator-class; see that file. */

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

static struct metric_alert_rule g_alert_rules[METRICS_PROMETHEUS_ALERT_MAX_RULES];
static struct metric_alert_rule_state
    g_alert_state[METRICS_PROMETHEUS_ALERT_MAX_RULES];
static size_t                      g_alert_rule_count;
static bool                        g_alert_rules_seeded;
static pthread_mutex_t             g_alert_lock = PTHREAD_MUTEX_INITIALIZER;

/* Env override for a threshold, trivial cases only (numeric knobs an
 * operator may reasonably want to tune without a rebuild). Malformed or
 * absent env values fall back to `def`. */
static double alert_env_double(const char *name, double def)
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
static void alert_rules_seed_locked(void)
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

/* Current value for one rule's gauge. Reads the same in-process source
 * metrics_prometheus_render_prometheus() reads — atomics fed by the metrics
 * tick, or a direct live call for the blocker registry. */
static double alert_rule_fetch_value(const struct metric_alert_rule *r)
{
    if (strcmp(r->event_name, "tip_stalled") == 0)
        return (double)atomic_load(&g_node_tip_advance_age);
    if (strcmp(r->event_name, "mirror_lag_high") == 0)
        return (double)atomic_load(&g_mirror_lag_blocks);
    if (strcmp(r->event_name, "mirror_lag_critical") == 0)
        return (double)atomic_load(&g_mirror_lag_critical_seconds);
    if (strcmp(r->event_name, "blocker_permanent_active") == 0)
        return (double)blocker_count_by_class(BLOCKER_PERMANENT);
    if (strcmp(r->event_name, "rss_high") == 0)
        return (double)atomic_load(&g_node_rss_mb_x100) / 100.0;
    if (strcmp(r->event_name, "header_gap_growing") == 0)
        return (double)atomic_load(&g_header_gap_breach_seconds);
    if (strcmp(r->event_name, "peer_count_collapsed") == 0)
        return (double)atomic_load(&g_peer_collapse_breach_seconds);
    if (strcmp(r->event_name, "sync_state_stuck") == 0)
        return (double)atomic_load(&g_sync_state_stuck_seconds);
    if (strcmp(r->event_name, "consensus_reject_spike") == 0)
        return (double)atomic_load(&g_reject_spike_delta);
    return 0.0;
}

static bool alert_cmp_crossed(enum metric_alert_cmp cmp, double value,
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

static const char *alert_cmp_symbol(enum metric_alert_cmp cmp)
{
    switch (cmp) {
    case METRIC_ALERT_GT: return ">";
    case METRIC_ALERT_LT: return "<";
    case METRIC_ALERT_GE: return ">=";
    case METRIC_ALERT_LE: return "<=";
    }
    return "?";
}

/* consensus_reject_spike input: advance the rolling window (aligned to
 * node uptime, not wall-clock — see the file-header comment on the
 * "New (Lane 1a) hysteresis gauges" block) and, once a full window has
 * elapsed, publish the delta since the last window boundary as
 * g_reject_spike_delta. First call just establishes the baseline so a
 * cumulative-since-boot total never reads as a false "spike". Called
 * from metrics_prometheus_evaluate_alert_rules() so it advances once per tick
 * alongside every other rule, using metrics_prometheus_consensus_rejects_total()
 * — the same accessor the native consensus report uses. */
static void consensus_reject_spike_tick(void)
{
    double  window_sec      = alert_env_double("ZCL_ALERT_CONSENSUS_REJECT_WINDOW_SECS", 60.0);
    int64_t uptime          = atomic_load(&g_node_uptime_seconds);
    int64_t total           = (int64_t)metrics_prometheus_consensus_rejects_total();
    int64_t baseline_total  = atomic_load(&g_reject_spike_baseline_total);
    int64_t baseline_uptime = atomic_load(&g_reject_spike_baseline_uptime);

    if (baseline_total < 0) {
        atomic_store(&g_reject_spike_baseline_total, total);
        atomic_store(&g_reject_spike_baseline_uptime, uptime);
        return;
    }
    if ((double)(uptime - baseline_uptime) < window_sec)
        return;  /* window still open — keep reporting the last delta */

    int64_t delta = total - baseline_total;
    atomic_store(&g_reject_spike_delta, delta > 0 ? delta : 0);
    atomic_store(&g_reject_spike_baseline_total, total);
    atomic_store(&g_reject_spike_baseline_uptime, uptime);
}

void metrics_prometheus_evaluate_alert_rules(void)
{
    pthread_mutex_lock(&g_alert_lock);
    alert_rules_seed_locked();
    consensus_reject_spike_tick();

    int64_t now = GetTime();
    for (size_t i = 0; i < g_alert_rule_count; i++) {
        const struct metric_alert_rule *r = &g_alert_rules[i];
        struct metric_alert_rule_state *st = &g_alert_state[i];

        double value = alert_rule_fetch_value(r);
        bool crossed = alert_cmp_crossed(r->cmp, value, r->threshold);

        if (!crossed) {
            st->active = false;  /* clears the latch — next crossing fires fresh */
            continue;
        }

        bool rising_edge   = !st->active;
        bool cooldown_over = st->last_fired_unix == 0 ||
                             (now - st->last_fired_unix) >= r->cooldown_sec;
        bool should_fire   = rising_edge || cooldown_over;

        st->active = true;

        if (should_fire) {
            st->last_fired_unix = now;
            st->fire_count++;
            event_emitf(EV_CONDITION_DETECTED, 0,
                        "name=metric_alert.%s severity=%s gauge=%s "
                        "value=%.2f threshold=%s%.2f",
                        r->event_name, r->severity, r->gauge_name,
                        value, alert_cmp_symbol(r->cmp), r->threshold);
        }
    }
    pthread_mutex_unlock(&g_alert_lock);
}

size_t metrics_prometheus_alert_rule_count(void)
{
    pthread_mutex_lock(&g_alert_lock);
    alert_rules_seed_locked();
    size_t n = g_alert_rule_count;
    pthread_mutex_unlock(&g_alert_lock);
    return n;
}

uint64_t metrics_prometheus_alert_fire_count(const char *rule_event_name)
{
    if (!rule_event_name) return 0;
    pthread_mutex_lock(&g_alert_lock);
    alert_rules_seed_locked();
    uint64_t v = 0;
    for (size_t i = 0; i < g_alert_rule_count; i++) {
        if (strcmp(g_alert_rules[i].event_name, rule_event_name) == 0) {
            v = g_alert_state[i].fire_count;
            break;
        }
    }
    pthread_mutex_unlock(&g_alert_lock);
    return v;
}

void metrics_prometheus_alerts_reset(void)
{
    pthread_mutex_lock(&g_alert_lock);
    alert_rules_seed_locked();
    memset(g_alert_state, 0, sizeof(g_alert_state));
    pthread_mutex_unlock(&g_alert_lock);

    /* Isolate the Lane 1a hysteresis gauges between tests too — each
     * mirrors an "active episode" latch the same way g_alert_state does. */
    atomic_store(&g_header_gap_blocks, -1);
    atomic_store(&g_header_gap_breach_seconds, 0);
    atomic_store(&g_header_gap_breach_since_uptime, -1);
    atomic_store(&g_peer_collapse_breach_seconds, 0);
    atomic_store(&g_peer_collapse_since_uptime, -1);
    atomic_store(&g_sync_state_prev, -1);
    atomic_store(&g_sync_state_changed_at_uptime, 0);
    atomic_store(&g_sync_state_stuck_seconds, 0);
    atomic_store(&g_reject_spike_delta, 0);
    atomic_store(&g_reject_spike_baseline_total, -1);
    atomic_store(&g_reject_spike_baseline_uptime, 0);
}

/* ── Peer scoring counters ──────────────────────────────────── */

static int peer_kind_slot(const char *kind)
{
    if (!kind || !*kind) return METRICS_PROMETHEUS_PEER_KINDS - 1; /* "other" */
    for (int i = 0; i < METRICS_PROMETHEUS_PEER_KINDS; i++) {
        if (strcmp(k_peer_kind_names[i], kind) == 0) return i;
    }
    return METRICS_PROMETHEUS_PEER_KINDS - 1; /* "other" */
}

void metrics_prometheus_record_peer_offence(const char *kind)
{
    pthread_mutex_lock(&g_lock);
    g_peer_offences[peer_kind_slot(kind)]++;
    g_peer_offences_total++;
    pthread_mutex_unlock(&g_lock);
}

void metrics_prometheus_record_peer_ban(void)
{
    pthread_mutex_lock(&g_lock);
    g_peer_bans_total++;
    pthread_mutex_unlock(&g_lock);
}

/* ── Consensus reject counters ──────────────────────────────── */

/* Find an existing (kind, reason) slot or create a new one.  Returns
 * -1 when the table is full so the caller can fall back to overflow.
 * Must be called with g_lock held. */
static int reject_slot_locked(const char *kind, const char *reason)
{
    for (size_t i = 0; i < g_reject_slot_count; i++) {
        if (strcmp(g_reject_slots[i].kind, kind) == 0 &&
            strcmp(g_reject_slots[i].reason, reason) == 0)
            return (int)i;
    }
    if (g_reject_slot_count >= METRICS_PROMETHEUS_MAX_REJECT_REASONS)
        return -1;
    size_t idx = g_reject_slot_count++;
    memset(&g_reject_slots[idx], 0, sizeof(g_reject_slots[idx]));
    snprintf(g_reject_slots[idx].reason,
             sizeof(g_reject_slots[idx].reason), "%s", reason);
    snprintf(g_reject_slots[idx].kind,
             sizeof(g_reject_slots[idx].kind), "%s", kind);
    return (int)idx;
}

void metrics_prometheus_record_consensus_reject(const char *kind, const char *reason)
{
    /* Normalise inputs so the table is predictable regardless of
     * observer call path. */
    bool is_block = (kind && strcmp(kind, "block") == 0);
    const char *k = is_block ? "block" : "tx";
    if (!reason || !*reason) reason = "unknown";

    pthread_mutex_lock(&g_lock);
    int idx = reject_slot_locked(k, reason);
    if (idx >= 0) {
        g_reject_slots[idx].count++;
    } else if (is_block) {
        g_reject_overflow_block++;
    } else {
        g_reject_overflow_tx++;
    }
    if (is_block) g_reject_total_block++;
    else          g_reject_total_tx++;
    pthread_mutex_unlock(&g_lock);
}

uint64_t metrics_prometheus_consensus_rejects_total(void)
{
    pthread_mutex_lock(&g_lock);
    uint64_t v = g_reject_total_tx + g_reject_total_block;
    pthread_mutex_unlock(&g_lock);
    return v;
}

/* ── Event observers ────────────────────────────────────────── */

/* Extract the offence kind from an EV_PEER_MISBEHAVE / EV_PEER_BANNED
 * payload.  The shapes used by net.c are:
 *   misbehave: "+10=50 invalid_message: bad header"
 *   banned:    "score=100 invalid_block: bad consensus"
 * In both cases the kind is the FIRST whitespace-separated word that
 * (a) is not the score header (no '=' inside) and (b) optionally has
 * a trailing ':'.  We strip the colon and return the bare name. */
static void parse_peer_kind(const char *payload, size_t payload_len,
                             char *out, size_t cap)
{
    if (cap == 0) return;
    out[0] = '\0';
    size_t i = 0;
    /* Skip the score header token (the one with '=') */
    while (i < payload_len) {
        size_t tok_start = i;
        while (i < payload_len && payload[i] != ' ') i++;
        size_t tok_len = i - tok_start;
        bool has_eq = false;
        for (size_t j = tok_start; j < tok_start + tok_len; j++) {
            if (payload[j] == '=') { has_eq = true; break; }
        }
        if (!has_eq && tok_len > 0) {
            size_t copy_len = tok_len;
            /* Strip a trailing ':' so we get the bare kind name. */
            if (copy_len > 0 && payload[tok_start + copy_len - 1] == ':')
                copy_len--;
            if (copy_len >= cap) copy_len = cap - 1;
            memcpy(out, payload + tok_start, copy_len);
            out[copy_len] = '\0';
            return;
        }
        while (i < payload_len && payload[i] == ' ') i++;
    }
}

static void peer_event_observer(enum event_type type, uint32_t peer_id,
                                const void *payload, uint32_t payload_len,
                                void *ctx)
{
    (void)peer_id; (void)ctx;
    if (type == EV_PEER_MISBEHAVE) {
        char kind[32] = {0};
        if (payload && payload_len > 0)
            parse_peer_kind(payload, payload_len, kind, sizeof(kind));
        metrics_prometheus_record_peer_offence(kind);
    } else if (type == EV_PEER_BANNED) {
        metrics_prometheus_record_peer_ban();
    }
}

static void consensus_reject_observer(enum event_type type, uint32_t peer_id,
                                      const void *payload,
                                      uint32_t payload_len, void *ctx)
{
    (void)peer_id; (void)ctx;
    const char *kind;
    if      (type == EV_CONSENSUS_REJECT_TX)    kind = "tx";
    else if (type == EV_CONSENSUS_REJECT_BLOCK) kind = "block";
    else return;

    char reason[48] = {0};
    if (payload && payload_len > 0)
        parse_kv(payload, payload_len, "reason", reason, sizeof(reason));
    metrics_prometheus_record_consensus_reject(kind, reason);
}

void metrics_prometheus_set_sync_state(int state, const char *name)
{
    atomic_store(&g_node_sync_state, state);
    g_node_sync_state_name = name ? name : "unknown";

    /* sync_state_stuck hysteresis: uses the same-tick uptime gauge (set
     * by metrics_prometheus_set_node_gauges, which lib/metrics's tick always
     * calls first — see its ordering) as the clock basis, not
     * wall-clock, so a hermetic test can drive it deterministically. */
    int64_t uptime = atomic_load(&g_node_uptime_seconds);
    int     prev   = atomic_load(&g_sync_state_prev);
    if (prev != state) {
        atomic_store(&g_sync_state_prev, state);
        atomic_store(&g_sync_state_changed_at_uptime, uptime);
    }
    int64_t changed_at = atomic_load(&g_sync_state_changed_at_uptime);
    bool    at_tip     = (state == SYNC_AT_TIP);
    int64_t stuck = (!at_tip && uptime >= changed_at) ? uptime - changed_at : 0;
    atomic_store(&g_sync_state_stuck_seconds, stuck);
}

void metrics_prometheus_set_header_gap(int64_t gap_blocks)
{
    atomic_store(&g_header_gap_blocks, gap_blocks);

    double  blocks_threshold = alert_env_double("ZCL_ALERT_HEADER_GAP_BLOCKS", 144.0);
    int64_t uptime = atomic_load(&g_node_uptime_seconds);
    int     state  = atomic_load(&g_node_sync_state);

    /* A large header/served gap is the normal, expected shape of initial
     * header download (peers race ahead on headers before any block
     * bodies are fetched) — only accrue breach time outside that phase,
     * so a fresh IBD node never spuriously fires this rule. */
    bool eligible = gap_blocks >= 0 && state != SYNC_HEADERS_DOWNLOAD;

    if (eligible && (double)gap_blocks > blocks_threshold) {
        int64_t since = atomic_load(&g_header_gap_breach_since_uptime);
        if (since < 0) {
            atomic_store(&g_header_gap_breach_since_uptime, uptime);
            since = uptime;
        }
        int64_t breach = uptime - since;
        atomic_store(&g_header_gap_breach_seconds, breach > 0 ? breach : 0);
    } else {
        atomic_store(&g_header_gap_breach_since_uptime, -1);
        atomic_store(&g_header_gap_breach_seconds, 0);
    }
}

void metrics_prometheus_init(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_observer_installed) {
        pthread_mutex_unlock(&g_lock);
        return;
    }
    event_observe(EV_PEER_MISBEHAVE, peer_event_observer, NULL);
    event_observe(EV_PEER_BANNED, peer_event_observer, NULL);
    event_observe(EV_CONSENSUS_REJECT_TX, consensus_reject_observer, NULL);
    event_observe(EV_CONSENSUS_REJECT_BLOCK, consensus_reject_observer, NULL);
    g_observer_installed = true;
    pthread_mutex_unlock(&g_lock);
}

/* ── Prometheus text format ─────────────────────────────────── */

__attribute__((format(printf, 4, 5)))
static size_t append(char *buf, size_t cap, size_t pos, const char *fmt, ...)
{
    if (pos >= cap) return pos;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + pos, cap - pos, fmt, ap);
    va_end(ap);
    if (n < 0) return pos;
    if ((size_t)n >= cap - pos) return cap - 1;
    return pos + (size_t)n;
}

void metrics_prometheus_set_rpc_http_source(metrics_rpc_http_gauges_fn fn,
                                            void *ctx)
{
    pthread_mutex_lock(&g_lock);
    g_rpc_http_source = fn;
    g_rpc_http_source_ctx = fn ? ctx : NULL;
    pthread_mutex_unlock(&g_lock);
}

size_t metrics_prometheus_render_prometheus(char *buf, size_t cap)
{
    if (!buf || cap == 0) return 0;
    pthread_mutex_lock(&g_lock);

    size_t pos = 0;
    pos = append(buf, cap, pos,
        "# HELP zcl_peer_offences_total Peer scoring offences observed since boot\n"
        "# TYPE zcl_peer_offences_total counter\n");
    for (int i = 0; i < METRICS_PROMETHEUS_PEER_KINDS; i++) {
        pos = append(buf, cap, pos,
            "zcl_peer_offences_total{kind=\"%s\"} %llu\n",
            k_peer_kind_names[i], (unsigned long long)g_peer_offences[i]);
    }
    pos = append(buf, cap, pos,
        "zcl_peer_offences_total{kind=\"all\"} %llu\n",
        (unsigned long long)g_peer_offences_total);

    pos = append(buf, cap, pos,
        "# HELP zcl_peer_bans_total Peers banned (score crossed threshold)\n"
        "# TYPE zcl_peer_bans_total counter\n"
        "zcl_peer_bans_total %llu\n",
        (unsigned long long)g_peer_bans_total);

    /* ── HTTP RPC middleware block ───────────────────────────── */
    struct metrics_rpc_http_gauges snap = {0};
    if (g_rpc_http_source)
        g_rpc_http_source(&snap, g_rpc_http_source_ctx);

    pos = append(buf, cap, pos,
        "# HELP zcl_rpc_requests_total HTTP RPC middleware decisions by result\n"
        "# TYPE zcl_rpc_requests_total counter\n"
        "zcl_rpc_requests_total{result=\"allowed\"} %llu\n"
        "zcl_rpc_requests_total{result=\"rate_limited_global\"} %llu\n"
        "zcl_rpc_requests_total{result=\"rate_limited_per_ip\"} %llu\n"
        "zcl_rpc_requests_total{result=\"banned\"} %llu\n",
        (unsigned long long)snap.allowed,
        (unsigned long long)snap.rate_limited_global,
        (unsigned long long)snap.rate_limited_per_ip,
        (unsigned long long)snap.banned_rejected);

    pos = append(buf, cap, pos,
        "# HELP zcl_rpc_auth_failures_total HTTP RPC auth (401) failures\n"
        "# TYPE zcl_rpc_auth_failures_total counter\n"
        "zcl_rpc_auth_failures_total %llu\n",
        (unsigned long long)snap.auth_failures);

    pos = append(buf, cap, pos,
        "# HELP zcl_rpc_bans_issued_total IP bans issued by HTTP RPC middleware\n"
        "# TYPE zcl_rpc_bans_issued_total counter\n"
        "zcl_rpc_bans_issued_total %llu\n",
        (unsigned long long)snap.bans_issued);

    pos = append(buf, cap, pos,
        "# HELP zcl_rpc_bans_active Currently-active HTTP RPC IP bans\n"
        "# TYPE zcl_rpc_bans_active gauge\n"
        "zcl_rpc_bans_active %llu\n",
        (unsigned long long)snap.active_bans);

    pos = append(buf, cap, pos,
        "# HELP zcl_rpc_tracked_ips IPs currently in the per-IP bucket table\n"
        "# TYPE zcl_rpc_tracked_ips gauge\n"
        "zcl_rpc_tracked_ips %llu\n",
        (unsigned long long)snap.tracked_ips);

    /* ── Consensus reject block ─────────────────────────────── */
    pos = append(buf, cap, pos,
        "# HELP zcl_consensus_rejects_total Consensus rejects by kind + reason\n"
        "# TYPE zcl_consensus_rejects_total counter\n");
    for (size_t i = 0; i < g_reject_slot_count; i++) {
        pos = append(buf, cap, pos,
            "zcl_consensus_rejects_total{kind=\"%s\",reason=\"%s\"} %llu\n",
            g_reject_slots[i].kind,
            g_reject_slots[i].reason,
            (unsigned long long)g_reject_slots[i].count);
    }
    pos = append(buf, cap, pos,
        "zcl_consensus_rejects_total{kind=\"tx\",reason=\"__other__\"} %llu\n"
        "zcl_consensus_rejects_total{kind=\"block\",reason=\"__other__\"} %llu\n"
        "zcl_consensus_rejects_total{kind=\"tx\",reason=\"all\"} %llu\n"
        "zcl_consensus_rejects_total{kind=\"block\",reason=\"all\"} %llu\n"
        "zcl_consensus_rejects_total{kind=\"all\",reason=\"all\"} %llu\n",
        (unsigned long long)g_reject_overflow_tx,
        (unsigned long long)g_reject_overflow_block,
        (unsigned long long)g_reject_total_tx,
        (unsigned long long)g_reject_total_block,
        (unsigned long long)(g_reject_total_tx + g_reject_total_block));

    /* ── Node-level gauges ───────────────────────────────────── */
    int64_t bh = atomic_load(&g_node_block_height);
    int64_t pc = atomic_load(&g_node_peer_count);
    int64_t rss100 = atomic_load(&g_node_rss_mb_x100);
    int64_t uc = atomic_load(&g_node_utxo_count);
    int64_t up = atomic_load(&g_node_uptime_seconds);
    int ss = atomic_load(&g_node_sync_state);
    const char *ssn = g_node_sync_state_name;

    pos = append(buf, cap, pos,
        "# HELP zcl_block_height Current best chain height\n"
        "# TYPE zcl_block_height gauge\n"
        "zcl_block_height %lld\n",
        (long long)bh);

    pos = append(buf, cap, pos,
        "# HELP zcl_peer_count Connected P2P peers\n"
        "# TYPE zcl_peer_count gauge\n"
        "zcl_peer_count %lld\n",
        (long long)pc);

    int64_t mb_pc = atomic_load(&g_node_magicbean_peer_count);
    int64_t z23_pc = atomic_load(&g_node_zcl23_peer_count);
    pos = append(buf, cap, pos,
        "# HELP zcl_magicbean_peer_count Connected peers identifying as zclassicd-era /MagicBean:.../ clients\n"
        "# TYPE zcl_magicbean_peer_count gauge\n"
        "zcl_magicbean_peer_count %lld\n"
        "# HELP zcl_zclassic23_peer_count Connected peers identifying as ZClassic23 (NODE_ZCL23 services or subver tag)\n"
        "# TYPE zcl_zclassic23_peer_count gauge\n"
        "zcl_zclassic23_peer_count %lld\n"
        "# HELP zcl_zclassic_c23_peer_count Compatibility alias for zcl_zclassic23_peer_count\n"
        "# TYPE zcl_zclassic_c23_peer_count gauge\n"
        "zcl_zclassic_c23_peer_count %lld\n",
        (long long)mb_pc, (long long)z23_pc, (long long)z23_pc);

    pos = append(buf, cap, pos,
        "# HELP zcl_rss_mb Resident set size in megabytes\n"
        "# TYPE zcl_rss_mb gauge\n"
        "zcl_rss_mb %.2f\n",
        (double)rss100 / 100.0);

    pos = append(buf, cap, pos,
        "# HELP zcl_utxo_count Number of unspent transaction outputs\n"
        "# TYPE zcl_utxo_count gauge\n"
        "zcl_utxo_count %lld\n",
        (long long)uc);

    pos = append(buf, cap, pos,
        "# HELP zcl_sync_state Sync state (0=idle, 5=at_tip)\n"
        "# TYPE zcl_sync_state gauge\n"
        "zcl_sync_state{name=\"%s\"} %d\n",
        ssn ? ssn : "unknown", ss);

    pos = append(buf, cap, pos,
        "# HELP zcl_uptime_seconds Node uptime in seconds\n"
        "# TYPE zcl_uptime_seconds gauge\n"
        "zcl_uptime_seconds %lld\n",
        (long long)up);

    int64_t tage = atomic_load(&g_node_tip_advance_age);
    pos = append(buf, cap, pos,
        "# HELP zcl_tip_advance_age_seconds Seconds since last EV_BLOCK_CONNECTED (-1 pre-bootstrap)\n"
        "# TYPE zcl_tip_advance_age_seconds gauge\n"
        "zcl_tip_advance_age_seconds %lld\n",
        (long long)tage);

    int64_t mlag = atomic_load(&g_mirror_lag_blocks);
    int64_t mbreach = atomic_load(&g_mirror_lag_breach_seconds);
    int64_t mcrit = atomic_load(&g_mirror_lag_critical_seconds);
    pos = append(buf, cap, pos,
        "# HELP zcl_mirror_lag_blocks zclassic23 block-height lag behind zclassicd (-1 pre-bootstrap)\n"
        "# TYPE zcl_mirror_lag_blocks gauge\n"
        "zcl_mirror_lag_blocks %lld\n"
        "# HELP zcl_mirror_lag_breach_seconds Seconds spent above the breach SLO (0 when under)\n"
        "# TYPE zcl_mirror_lag_breach_seconds gauge\n"
        "zcl_mirror_lag_breach_seconds %lld\n"
        "# HELP zcl_mirror_lag_critical_seconds Seconds spent above the critical SLO (0 when under)\n"
        "# TYPE zcl_mirror_lag_critical_seconds gauge\n"
        "zcl_mirror_lag_critical_seconds %lld\n",
        (long long)mlag, (long long)mbreach, (long long)mcrit);

    /* ── Lane 1a hysteresis gauges ────────────────────────────── */
    int64_t hgap        = atomic_load(&g_header_gap_blocks);
    int64_t hgap_breach = atomic_load(&g_header_gap_breach_seconds);
    pos = append(buf, cap, pos,
        "# HELP zcl_header_gap_blocks Best-known header height minus served height H* (-1 unknown)\n"
        "# TYPE zcl_header_gap_blocks gauge\n"
        "zcl_header_gap_blocks %lld\n"
        "# HELP zcl_header_gap_breach_seconds Seconds the header gap has exceeded its threshold outside header-download (0 when under or ineligible)\n"
        "# TYPE zcl_header_gap_breach_seconds gauge\n"
        "zcl_header_gap_breach_seconds %lld\n",
        (long long)hgap, (long long)hgap_breach);

    int64_t pcollapse = atomic_load(&g_peer_collapse_breach_seconds);
    pos = append(buf, cap, pos,
        "# HELP zcl_peer_collapse_breach_seconds Seconds spent with connected peers under the collapse floor, past the post-boot grace window (0 when under/in grace)\n"
        "# TYPE zcl_peer_collapse_breach_seconds gauge\n"
        "zcl_peer_collapse_breach_seconds %lld\n",
        (long long)pcollapse);

    int64_t sstuck = atomic_load(&g_sync_state_stuck_seconds);
    pos = append(buf, cap, pos,
        "# HELP zcl_sync_state_stuck_seconds Seconds the sync-state id has been unchanged while not at_tip (0 when at_tip or just changed)\n"
        "# TYPE zcl_sync_state_stuck_seconds gauge\n"
        "zcl_sync_state_stuck_seconds %lld\n",
        (long long)sstuck);

    int64_t rdelta = atomic_load(&g_reject_spike_delta);
    pos = append(buf, cap, pos,
        "# HELP zcl_consensus_reject_delta Consensus reject count delta over the last completed rolling window\n"
        "# TYPE zcl_consensus_reject_delta gauge\n"
        "zcl_consensus_reject_delta %lld\n",
        (long long)rdelta);

    /* ── Typed blocker block ──────────────────────
     *
     * Live counts per class + escape-dispatch total. The blocker
     * primitive's own JSON dumper is exposed through native diagnostics;
     * Prometheus gets the numeric gauges so dashboards can
     * alert on class-level pressure (e.g. permanent>0 is always an
     * operator-escalation event). */
    int active_total = blocker_count_active();
    int active_perm  = blocker_count_by_class(BLOCKER_PERMANENT);
    int active_trans = blocker_count_by_class(BLOCKER_TRANSIENT);
    int active_dep   = blocker_count_by_class(BLOCKER_DEPENDENCY);
    int active_res   = blocker_count_by_class(BLOCKER_RESOURCE);
    int escape_total = blocker_escape_dispatched_count();
    pos = append(buf, cap, pos,
        "# HELP zcl_blockers_active Currently-active typed blockers per class\n"
        "# TYPE zcl_blockers_active gauge\n"
        "zcl_blockers_active{class=\"permanent\"} %d\n"
        "zcl_blockers_active{class=\"transient\"} %d\n"
        "zcl_blockers_active{class=\"dependency\"} %d\n"
        "zcl_blockers_active{class=\"resource\"} %d\n"
        "zcl_blockers_active{class=\"all\"} %d\n"
        "# HELP zcl_blocker_escape_dispatched_total Edge-triggered escape dispatches since boot\n"
        "# TYPE zcl_blocker_escape_dispatched_total counter\n"
        "zcl_blocker_escape_dispatched_total %d\n",
        active_perm, active_trans, active_dep, active_res, active_total,
        escape_total);

    /* ── Reducer stage block (Phase E4) ───────────────────────
     *
     * zcl_stage_step_us_ewma / zcl_stage_cursor per stage, plus the
     * shared zcl_stage_batch_commit_us_ewma gauge. Fixed 8-stage
     * cardinality — see lib/metrics/src/stage_metrics.c. */
    pos = metrics_stage_render_prometheus(buf, cap, pos);

    if (pos < cap) buf[pos] = '\0';
    pthread_mutex_unlock(&g_lock);
    return pos;
}

size_t metrics_prometheus_consensus_report_json(char *buf, size_t cap)
{
    if (!buf || cap == 0) return 0;
    pthread_mutex_lock(&g_lock);

    size_t pos = 0;
    pos = append(buf, cap, pos,
        "{\"totals\":{"
            "\"tx\":%llu,"
            "\"block\":%llu,"
            "\"all\":%llu"
         "},\"overflow\":{"
            "\"tx\":%llu,"
            "\"block\":%llu"
         "},\"tracked_reasons\":%zu,\"capacity\":%d,\"by_reason\":[",
        (unsigned long long)g_reject_total_tx,
        (unsigned long long)g_reject_total_block,
        (unsigned long long)(g_reject_total_tx + g_reject_total_block),
        (unsigned long long)g_reject_overflow_tx,
        (unsigned long long)g_reject_overflow_block,
        g_reject_slot_count,
        METRICS_PROMETHEUS_MAX_REJECT_REASONS);

    for (size_t i = 0; i < g_reject_slot_count; i++) {
        pos = append(buf, cap, pos,
            "%s{\"kind\":\"%s\",\"reason\":\"%s\",\"count\":%llu}",
            i == 0 ? "" : ",",
            g_reject_slots[i].kind,
            g_reject_slots[i].reason,
            (unsigned long long)g_reject_slots[i].count);
    }
    pos = append(buf, cap, pos, "]}");

    if (pos < cap) buf[pos] = '\0';
    pthread_mutex_unlock(&g_lock);
    return pos;
}
