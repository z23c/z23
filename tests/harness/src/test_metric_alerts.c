/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the metric-threshold alert rules (C3):
 * engine/modules/metrics/src/prometheus_metrics.c's metrics_prometheus_evaluate_alert_rules()
 * and the operator-event allow-list entry ("condition.detected", in
 * engine/modules/metrics/src/operator_events.c) that marks its output operator-class.
 *
 * Hermetic: no live node. Gauges are seeded directly via the public setters
 * in metrics/prometheus_metrics.h; the emitted EV_CONDITION_DETECTED events
 * are captured with a local sync event_observe() the same way
 * tests/harness/src/test_recovery_policy.c captures EV_RECOVERY_POLICY_*.
 */

#include "test/test_core.h"
#include "metrics/prometheus_metrics.h"
#include "metrics/operator_events.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include "util/blocker.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* ── Event capture (sync observer on EV_CONDITION_DETECTED) ────── */

#define MA_CAP_MAX 32

static _Atomic int g_ma_count;
static char        g_ma_payloads[MA_CAP_MAX][256];
static _Atomic int g_ma_write_pos;

static void ma_observer(enum event_type type, uint32_t peer_id,
                         const void *payload, uint32_t payload_len,
                         void *ctx)
{
    (void)peer_id; (void)ctx;
    if (type != EV_CONDITION_DETECTED) return;
    atomic_fetch_add(&g_ma_count, 1);

    int pos = atomic_fetch_add(&g_ma_write_pos, 1) % MA_CAP_MAX;
    size_t n = payload_len < sizeof(g_ma_payloads[0]) - 1
                   ? payload_len : sizeof(g_ma_payloads[0]) - 1;
    memcpy(g_ma_payloads[pos], payload, n);
    g_ma_payloads[pos][n] = '\0';
}

static void ma_install_observer(void)
{
    event_clear_observers(EV_CONDITION_DETECTED);
    atomic_store(&g_ma_count, 0);
    atomic_store(&g_ma_write_pos, 0);
    memset(g_ma_payloads, 0, sizeof(g_ma_payloads));
    event_observe(EV_CONDITION_DETECTED, ma_observer, NULL);
}

/* True if any captured payload since the last reset contains `needle`. */
static bool ma_captured_contains(const char *needle)
{
    int written = atomic_load(&g_ma_write_pos);
    int n = written < MA_CAP_MAX ? written : MA_CAP_MAX;
    for (int i = 0; i < n; i++)
        if (strstr(g_ma_payloads[i], needle)) return true;
    return false;
}

static void ma_reset_all(void)
{
    metrics_prometheus_alerts_reset();
    atomic_store(&g_ma_count, 0);
    atomic_store(&g_ma_write_pos, 0);
    memset(g_ma_payloads, 0, sizeof(g_ma_payloads));
}

/* ── Rule table shape ────────────────────────────────────────── */

static int test_rule_count_and_names(void)
{
    int failures = 0;
    TEST("metric_alerts: seeds the expected rule set") {
        ma_reset_all();
        ASSERT(metrics_prometheus_alert_rule_count() == 9);
        /* Every seeded rule name is queryable (starts at 0 fires). */
        ASSERT(metrics_prometheus_alert_fire_count("tip_stalled") == 0);
        ASSERT(metrics_prometheus_alert_fire_count("mirror_lag_high") == 0);
        ASSERT(metrics_prometheus_alert_fire_count("mirror_lag_critical") == 0);
        ASSERT(metrics_prometheus_alert_fire_count("blocker_permanent_active") == 0);
        ASSERT(metrics_prometheus_alert_fire_count("rss_high") == 0);
        ASSERT(metrics_prometheus_alert_fire_count("header_gap_growing") == 0);
        ASSERT(metrics_prometheus_alert_fire_count("peer_count_collapsed") == 0);
        ASSERT(metrics_prometheus_alert_fire_count("sync_state_stuck") == 0);
        ASSERT(metrics_prometheus_alert_fire_count("consensus_reject_spike") == 0);
        /* An unknown rule name is simply absent, not an error. */
        ASSERT(metrics_prometheus_alert_fire_count("no_such_rule") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_allow_listed_for_push(void)
{
    int failures = 0;
    TEST("metric_alerts: condition.detected is in the operator-event allow-list") {
        ASSERT(metrics_is_operator_event("condition.detected"));
        /* Sanity: an unrelated, non-operator event type is still excluded. */
        ASSERT(!metrics_is_operator_event("chain.tip_updated"));
        PASS();
    } _test_next:;
    return failures;
}

/* ── Edge-trigger + cooldown semantics (tip_advance_age rule) ───── */

static int test_fires_exactly_once_on_crossing(void)
{
    int failures = 0;
    TEST("metric_alerts: tip_advance_age fires exactly once on the rising edge") {
        ma_reset_all();
        ma_install_observer();

        /* Below threshold (default 600s): no fire. */
        metrics_prometheus_set_tip_advance_age(30);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(atomic_load(&g_ma_count) == 0);
        ASSERT(metrics_prometheus_alert_fire_count("tip_stalled") == 0);

        /* Crosses above threshold: fires once. */
        metrics_prometheus_set_tip_advance_age(900);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(atomic_load(&g_ma_count) == 1);
        ASSERT(metrics_prometheus_alert_fire_count("tip_stalled") == 1);
        ASSERT(ma_captured_contains("name=metric_alert.tip_stalled"));
        ASSERT(ma_captured_contains("severity=critical"));

        /* Still crossed, cooldown (300s) has not elapsed: no repeat. */
        metrics_prometheus_evaluate_alert_rules();
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(atomic_load(&g_ma_count) == 1);
        ASSERT(metrics_prometheus_alert_fire_count("tip_stalled") == 1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_not_raised_below_threshold(void)
{
    int failures = 0;
    TEST("metric_alerts: never fires while the gauge stays under threshold") {
        ma_reset_all();
        ma_install_observer();

        for (int i = 0; i < 5; i++) {
            metrics_prometheus_set_tip_advance_age(i * 10);
            metrics_prometheus_evaluate_alert_rules();
        }
        ASSERT(atomic_load(&g_ma_count) == 0);
        ASSERT(metrics_prometheus_alert_fire_count("tip_stalled") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_refires_after_clearing_and_recrossing(void)
{
    int failures = 0;
    TEST("metric_alerts: clearing the latch lets a fresh crossing fire again") {
        ma_reset_all();
        ma_install_observer();

        metrics_prometheus_set_tip_advance_age(900);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("tip_stalled") == 1);

        /* Drops back under threshold: clears the edge latch. */
        metrics_prometheus_set_tip_advance_age(5);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("tip_stalled") == 1); /* no fire while clear */

        /* Crosses again: a new rising edge, fires immediately (cooldown
         * gates repeats of a CONTINUOUS breach, not a fresh episode). */
        metrics_prometheus_set_tip_advance_age(900);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("tip_stalled") == 2);
        PASS();
    } _test_next:;
    return failures;
}

/* Pre-bootstrap sentinel (-1) must never spuriously cross a GT rule. */
static int test_sentinel_value_does_not_fire(void)
{
    int failures = 0;
    TEST("metric_alerts: the -1 'not yet observed' sentinel never crosses a GT rule") {
        ma_reset_all();
        ma_install_observer();

        metrics_prometheus_set_tip_advance_age(-1);
        metrics_prometheus_set_mirror_lag(-1, 0, 0);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(atomic_load(&g_ma_count) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Other seeded rules: each fires with the right name/severity ── */

static int test_mirror_lag_high_rule(void)
{
    int failures = 0;
    TEST("metric_alerts: mirror_lag_high fires above its threshold") {
        ma_reset_all();
        ma_install_observer();

        metrics_prometheus_set_mirror_lag(5, 0, 0);   /* under default 50 */
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("mirror_lag_high") == 0);

        metrics_prometheus_set_mirror_lag(120, 0, 0); /* over default 50 */
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("mirror_lag_high") == 1);
        ASSERT(ma_captured_contains("name=metric_alert.mirror_lag_high"));
        ASSERT(ma_captured_contains("severity=warning"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_mirror_lag_critical_rule(void)
{
    int failures = 0;
    TEST("metric_alerts: mirror_lag_critical_seconds fires the instant it is nonzero") {
        ma_reset_all();
        ma_install_observer();

        metrics_prometheus_set_mirror_lag(0, 0, 0);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("mirror_lag_critical") == 0);

        metrics_prometheus_set_mirror_lag(0, 30, 5);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("mirror_lag_critical") == 1);
        ASSERT(ma_captured_contains("name=metric_alert.mirror_lag_critical"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_blocker_permanent_active_rule(void)
{
    int failures = 0;
    TEST("metric_alerts: a permanent blocker fires blocker_permanent_active") {
        ma_reset_all();
        ma_install_observer();
        blocker_clear("test.metric_alert_permanent");

        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("blocker_permanent_active") == 0);

        struct blocker_record r;
        ASSERT(blocker_init(&r, "test.metric_alert_permanent", "test",
                            BLOCKER_PERMANENT, "hermetic test"));
        ASSERT(blocker_set(&r) >= 0);

        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("blocker_permanent_active") == 1);
        ASSERT(ma_captured_contains("name=metric_alert.blocker_permanent_active"));
        ASSERT(ma_captured_contains("severity=critical"));

        blocker_clear("test.metric_alert_permanent");
        metrics_prometheus_evaluate_alert_rules();
        /* Cleared: the latch drops; no further assertion on fire_count
         * needed since the crossing rule already proved the fire path. */
        PASS();
    } _test_next:;
    return failures;
}

static int test_rss_high_rule(void)
{
    int failures = 0;
    TEST("metric_alerts: rss_high fires above its ceiling") {
        ma_reset_all();
        ma_install_observer();

        metrics_prometheus_set_node_gauges(0, 0, 512.0, 0, 0); /* under default 6000 MB */
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("rss_high") == 0);

        metrics_prometheus_set_node_gauges(0, 0, 7000.0, 0, 0); /* over default 6000 MB */
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("rss_high") == 1);
        ASSERT(ma_captured_contains("name=metric_alert.rss_high"));
        ASSERT(ma_captured_contains("severity=warning"));
        PASS();
    } _test_next:;
    return failures;
}

/* ── Lane 1a: header_gap_growing, peer_count_collapsed,
 * sync_state_stuck, consensus_reject_spike ─────────────────────
 *
 * All four hysteresis gauges use the node's own uptime counter as
 * their clock basis (not wall-clock GetTime()), specifically so a
 * hermetic test can drive "time" deterministically by passing
 * increasing `uptime_seconds` values to metrics_prometheus_set_node_gauges()
 * instead of sleeping — see the Prometheus backend's "New (Lane 1a)
 * hysteresis gauges" comment. */

static int test_header_gap_growing_rule(void)
{
    int failures = 0;
    TEST("metric_alerts: header_gap_growing fires only after a sustained "
         "post-headers-download breach, and never during header download") {
        ma_reset_all();
        ma_install_observer();

        /* Under the 144-block threshold: no breach. */
        metrics_prometheus_set_node_gauges(0, 0, 0, 0, 100);
        metrics_prometheus_set_sync_state(SYNC_BLOCKS_DOWNLOAD, "blocks_download");
        metrics_prometheus_set_header_gap(50);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("header_gap_growing") == 0);

        /* Over threshold: breach timer starts, but 0s elapsed so far. */
        metrics_prometheus_set_header_gap(200);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("header_gap_growing") == 0);

        /* 950s later, still over threshold and still not header-download:
         * crosses the 900s sustain window. */
        metrics_prometheus_set_node_gauges(0, 0, 0, 0, 1050);
        metrics_prometheus_set_sync_state(SYNC_BLOCKS_DOWNLOAD, "blocks_download");
        metrics_prometheus_set_header_gap(200);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("header_gap_growing") == 1);
        ASSERT(ma_captured_contains("name=metric_alert.header_gap_growing"));
        ASSERT(ma_captured_contains("severity=critical"));

        /* A fresh episode during SYNC_HEADERS_DOWNLOAD never breaches,
         * however long the gap persists — that phase's header/served
         * gap is the normal shape of initial block download. */
        ma_reset_all();
        metrics_prometheus_set_node_gauges(0, 0, 0, 0, 100);
        metrics_prometheus_set_sync_state(SYNC_HEADERS_DOWNLOAD, "headers_download");
        metrics_prometheus_set_header_gap(5000);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("header_gap_growing") == 0);

        metrics_prometheus_set_node_gauges(0, 0, 0, 0, 10000);
        metrics_prometheus_set_sync_state(SYNC_HEADERS_DOWNLOAD, "headers_download");
        metrics_prometheus_set_header_gap(5000);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("header_gap_growing") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_peer_count_collapsed_rule(void)
{
    int failures = 0;
    TEST("metric_alerts: peer_count_collapsed respects the boot grace "
         "window and the sustain duration, and re-fires on a fresh episode") {
        ma_reset_all();
        ma_install_observer();

        /* Still inside the default 120s boot grace: no breach even
         * though peer_count is under the collapse floor. */
        metrics_prometheus_set_node_gauges(0, 1, 0, 0, 50);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("peer_count_collapsed") == 0);

        /* Past grace, under floor: breach timer starts at 0s. */
        metrics_prometheus_set_node_gauges(0, 1, 0, 0, 150);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("peer_count_collapsed") == 0);

        /* 350s later, still under floor: crosses the 300s sustain window. */
        metrics_prometheus_set_node_gauges(0, 1, 0, 0, 500);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("peer_count_collapsed") == 1);
        ASSERT(ma_captured_contains("name=metric_alert.peer_count_collapsed"));
        ASSERT(ma_captured_contains("severity=critical"));

        /* Recovers above the floor: clears the latch, no further fire. */
        metrics_prometheus_set_node_gauges(0, 5, 0, 0, 550);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("peer_count_collapsed") == 1);

        /* A fresh collapse episode fires again once sustained. */
        metrics_prometheus_set_node_gauges(0, 1, 0, 0, 600);
        metrics_prometheus_evaluate_alert_rules();
        metrics_prometheus_set_node_gauges(0, 1, 0, 0, 950);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("peer_count_collapsed") == 2);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sync_state_stuck_rule(void)
{
    int failures = 0;
    TEST("metric_alerts: sync_state_stuck fires only once unchanged for "
         "3600s while not at_tip, resets on a state change, and never "
         "fires at_tip") {
        ma_reset_all();
        ma_install_observer();

        /* First observation just anchors the "changed at" timestamp. */
        metrics_prometheus_set_node_gauges(0, 0, 0, 0, 100);
        metrics_prometheus_set_sync_state(SYNC_BLOCKS_DOWNLOAD, "blocks_download");
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("sync_state_stuck") == 0);

        /* Same state id, 3900s later: crosses the 3600s threshold. */
        metrics_prometheus_set_node_gauges(0, 0, 0, 0, 4000);
        metrics_prometheus_set_sync_state(SYNC_BLOCKS_DOWNLOAD, "blocks_download");
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("sync_state_stuck") == 1);
        ASSERT(ma_captured_contains("name=metric_alert.sync_state_stuck"));
        ASSERT(ma_captured_contains("severity=warning"));

        /* A state change resets the "changed at" timer — no immediate
         * re-fire even though a lot of uptime has already elapsed. */
        metrics_prometheus_set_sync_state(SYNC_CONNECTING_BLOCKS, "connecting_blocks");
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("sync_state_stuck") == 1);

        /* at_tip never counts as stuck, no matter how much uptime passes
         * while the state id stays the same. */
        ma_reset_all();
        metrics_prometheus_set_node_gauges(0, 0, 0, 0, 100);
        metrics_prometheus_set_sync_state(SYNC_AT_TIP, "at_tip");
        metrics_prometheus_evaluate_alert_rules();
        metrics_prometheus_set_node_gauges(0, 0, 0, 0, 999999);
        metrics_prometheus_set_sync_state(SYNC_AT_TIP, "at_tip");
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("sync_state_stuck") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_consensus_reject_spike_rule(void)
{
    int failures = 0;
    TEST("metric_alerts: consensus_reject_spike fires on a large delta "
         "within a rolling window, not on the raw cumulative total") {
        ma_reset_all();
        ma_install_observer();

        /* First tick just establishes the window baseline — never a
         * spurious fire off the pre-existing cumulative total. */
        metrics_prometheus_set_node_gauges(0, 0, 0, 0, 1000);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("consensus_reject_spike") == 0);

        /* Small delta (5), window elapses (100s > default 60s): under
         * the default threshold of 20 — no fire. */
        for (int i = 0; i < 5; i++)
            metrics_prometheus_record_consensus_reject("tx", "small_delta_probe");
        metrics_prometheus_set_node_gauges(0, 0, 0, 0, 1100);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("consensus_reject_spike") == 0);

        /* Large delta (25) in the next window: crosses the threshold. */
        for (int i = 0; i < 25; i++)
            metrics_prometheus_record_consensus_reject("block", "large_delta_probe");
        metrics_prometheus_set_node_gauges(0, 0, 0, 0, 1200);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("consensus_reject_spike") == 1);
        ASSERT(ma_captured_contains("name=metric_alert.consensus_reject_spike"));
        ASSERT(ma_captured_contains("severity=warning"));
        PASS();
    } _test_next:;
    return failures;
}

/* ── metrics_prometheus_reset() also clears alert state ────────────────── */

static int test_metrics_reset_clears_alert_state(void)
{
    int failures = 0;
    TEST("metric_alerts: metrics_prometheus_reset() folds in alert state reset") {
        ma_install_observer();
        metrics_prometheus_set_tip_advance_age(900);
        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("tip_stalled") >= 1);

        metrics_prometheus_reset();
        ASSERT(metrics_prometheus_alert_fire_count("tip_stalled") == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ────────────────────────────────────────────── */

int test_metric_alerts(void);

int test_metric_alerts(void)
{
    int failures = 0;

    failures += test_rule_count_and_names();
    failures += test_allow_listed_for_push();

    failures += test_fires_exactly_once_on_crossing();
    failures += test_not_raised_below_threshold();
    failures += test_refires_after_clearing_and_recrossing();
    failures += test_sentinel_value_does_not_fire();

    failures += test_mirror_lag_high_rule();
    failures += test_mirror_lag_critical_rule();
    failures += test_blocker_permanent_active_rule();
    failures += test_rss_high_rule();

    failures += test_header_gap_growing_rule();
    failures += test_peer_count_collapsed_rule();
    failures += test_sync_state_stuck_rule();
    failures += test_consensus_reject_spike_rule();

    failures += test_metrics_reset_clears_alert_state();

    event_clear_observers(EV_CONDITION_DETECTED);
    blocker_clear("test.metric_alert_permanent");
    metrics_prometheus_reset();
    return failures;
}
