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
#ifndef _WIN32
#include <sys/wait.h>
#endif

#include "platform/time_compat.h"
#include <stdarg.h>
#include "platform/os_proc.h"
#include "platform/clock.h"
static int64_t ma_fixed_mono(void *self) { (void)self; return INT64_C(1000000000); }
static int64_t ma_fixed_wall(void *self) { (void)self; return INT64_C(1700000000000); }
static const clock_iface_t ma_clock = {
    .now_monotonic_ns = ma_fixed_mono,
    .now_wall_ms = ma_fixed_wall,
};
static bool ma_read_fails;
static int ma_read_attempts;
static struct os_proc_mem ma_mem = {.rss_bytes = 0};
static bool ma_mem_read(struct os_proc_mem *out) {
    ++ma_read_attempts;
    *out = ma_mem;
    return !ma_read_fails;
}
static char ma_worker_diagnostic[256];
static bool ma_diagnostic_ok;
static int ma_diagnostic_count;
static int ma_worker_fprintf(FILE *stream, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = vsnprintf(ma_worker_diagnostic, sizeof(ma_worker_diagnostic), fmt, ap);
    va_end(ap);
    ++ma_diagnostic_count;
    ma_diagnostic_ok &= stream == stderr && rc >= 0 &&
                        (size_t)rc < sizeof(ma_worker_diagnostic);
    return rc;
}
static bool ma_terminal;
static char ma_worker_output[16384];
static void ma_worker_sleep(int ms);
static int ma_worker_printf(const char *fmt, ...) {
    size_t n = strlen(ma_worker_output);
    va_list ap;
    va_start(ap, fmt);
    int rc = vsnprintf(ma_worker_output + n, sizeof(ma_worker_output) - n, fmt, ap);
    va_end(ap);
    return rc;
}
#define g_transactions_validated ma_transactions_validated
#define g_eh_solver_runs ma_eh_solver_runs
#define metrics_print_art ma_print_art
#define metrics_start ma_metrics_start
#define metrics_stop ma_metrics_stop
#define printf ma_worker_printf
#define fprintf ma_worker_fprintf
#define os_proc_mem_read ma_mem_read
#define platform_sleep_ms(ms) ma_worker_sleep(ms)
#ifdef _WIN32
#define GetStdHandle(kind) ((HANDLE)(uintptr_t)1)
#define GetConsoleMode(handle, mode) ((void)(handle), (void)(mode), ma_terminal)
#else
#define isatty(fd) (ma_terminal)
#endif
#include "../../../engine/modules/metrics/src/metrics.c"
#undef g_transactions_validated
#undef g_eh_solver_runs
#undef metrics_print_art
#undef metrics_start
#undef metrics_stop
#undef printf
#undef fprintf
#undef os_proc_mem_read
#undef platform_sleep_ms
#ifdef _WIN32
#undef GetStdHandle
#undef GetConsoleMode
#else
#undef isatty
#endif
static void ma_end_tick(struct metrics_external_gauges *out, void *ctx) {
    (void)out;
    atomic_store(&((struct metrics_context *)ctx)->running, false);
}
static struct metrics_context *ma_episode_ctx;
static int ma_episode_tick;
static bool ma_episode_values_ok;
static int ma_episode_diagnostic_base;
static void ma_worker_sleep(int ms) {
    (void)ms;
    if (!ma_episode_ctx) return;
    char rendered[16384];
    size_t n = metrics_prometheus_render_prometheus(rendered, sizeof(rendered));
    const char *value = ma_episode_tick == 3 ? "zcl_rss_mb 1.50\n" : "zcl_rss_mb -1.00\n";
    ma_episode_values_ok &= n < sizeof(rendered) - 1 && strstr(rendered, value) != NULL;
    ma_episode_values_ok &= ma_diagnostic_count - ma_episode_diagnostic_base ==
                            (ma_episode_tick < 4 ? 1 : 2);
    ++ma_episode_tick;
    ma_mem.rss_bytes = ma_episode_tick == 3 ? INT64_C(1572864) : -1;
    ma_read_fails = ma_episode_tick == 1 || ma_episode_tick == 4;
    ma_worker_output[0] = '\0';
    if (ma_episode_tick == 6) atomic_store(&ma_episode_ctx->running, false);
}
static int test_worker_display_hint(void) {
    int failures = 0;
    static struct main_state ms;
    zcl_mutex_init(&ms.cs_main);
    struct metrics_context ctx = {.ms = &ms, .external_gauges = ma_end_tick, .external_gauges_ctx = &ctx};
    const clock_iface_t *saved_clock = clock_default();
    clock_set_default(&ma_clock);
    TEST("metric_alerts: worker gives effective terminal hide instruction") {
        for (int terminal = 0; terminal < 2; terminal++) {
            ma_terminal = terminal != 0;
            ma_worker_output[0] = '\0';
            atomic_store(&ctx.running, true);
            metrics_thread_fn(&ctx);
            ASSERT((strstr(ma_worker_output, "[Restart with startup argument '-showmetrics=0' to hide]") != NULL) == ma_terminal);
            ASSERT((strstr(ma_worker_output, "----------------------------------------\n") != NULL) == !ma_terminal);
            ASSERT(strstr(ma_worker_output, "[Set 'showmetrics=0'") == NULL);
        }
        PASS();
    } _test_next:;
    clock_set_default(saved_clock);
    zcl_mutex_destroy(&ms.cs_main);
    return failures;
}
static const enum event_type ma_subscription_types[] = {
    EV_PEER_MISBEHAVE, EV_PEER_BANNED,
    EV_CONSENSUS_REJECT_TX, EV_CONSENSUS_REJECT_BLOCK
};

static void ma_subscription_noop(enum event_type type, uint32_t peer_id,
    const void *payload, uint32_t payload_len, void *ctx)
{
    (void)type; (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
}

static int ma_subscription_case(size_t target)
{
    int failures = 0;
    TEST("metric_alerts: subscription recovers without duplicate observers") {
        for (size_t i = 0; i < 4; i++)
            event_clear_observers(ma_subscription_types[i]);
        metrics_prometheus_reset();
        for (int i = 0; i < EVENT_MAX_OBSERVERS; i++)
            ASSERT(event_observe(ma_subscription_types[target], ma_subscription_noop, NULL));
        metrics_prometheus_init();
        metrics_prometheus_init();
        ASSERT(!event_observe(ma_subscription_types[target], ma_subscription_noop, NULL));
        event_clear_observers(ma_subscription_types[target]);
        metrics_prometheus_init();
        metrics_prometheus_init();
        for (size_t i = 0; i < 4; i++) {
            event_emitf(ma_subscription_types[i], 0, "kind=timeout reason=fixture");
            event_emitf(ma_subscription_types[i], 0, "kind=timeout reason=fixture");
        }
        char text[16384];
        ASSERT(metrics_prometheus_render_prometheus(text, sizeof(text)) < sizeof(text) - 1);
        ASSERT(strstr(text, "zcl_peer_offences_total{kind=\"all\"} 2\n"));
        ASSERT(strstr(text, "zcl_peer_bans_total 2\n"));
        ASSERT(strstr(text, "zcl_consensus_rejects_total{kind=\"tx\",reason=\"all\"} 2\n"));
        ASSERT(strstr(text, "zcl_consensus_rejects_total{kind=\"block\",reason=\"all\"} 2\n"));
        for (size_t i = 0; i < 4; i++) {
            for (int n = 1; n < EVENT_MAX_OBSERVERS; n++)
                ASSERT(event_observe(ma_subscription_types[i], ma_subscription_noop, NULL));
            ASSERT(!event_observe(ma_subscription_types[i], ma_subscription_noop, NULL));
        }
        PASS();
    } _test_next:;
    return failures;
}

static int ma_subscription_child(size_t i)
{
    int failures = 0;
#ifdef _WIN32
    char role[] = "metrics-subscription-0", path[PATH_MAX];
    role[sizeof(role) - 2] = (char)('0' + i);
    int fd = test_mkstemp(path, sizeof(path), "metric_subscription");
    if (fd < 0) { perror("metric subscription log"); return 1; }
    failures += close(fd) != 0;
    void *child = test_spawn_self_with_role("test_metric_alerts", role, path);
    int status = child ? test_self_child_wait(child) : -1;
    if (_putenv_s("ZCL_TEST_FORK_GROUP", "") != 0 ||
        _putenv_s("ZCL_TEST_FORK_ROLE", "") != 0) {
        fprintf(stderr, "metric subscription environment cleanup failed\n"); failures++;
    }
    if (unlink(path) != 0) { perror("metric subscription cleanup"); failures++; }
    if (status != 0) failures++;
#else
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) { perror("metric subscription fork"); return 1; }
    if (child == 0) {
        int result = ma_subscription_case(i);
        fflush(stdout);
        _exit(result ? 1 : 0);
    }
    int status = 0;
    pid_t done;
    do { done = waitpid(child, &status, 0); } while (done < 0 && errno == EINTR);
    if (done != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) failures++;
#endif
    return failures;
}

static int test_subscription_retries(void)
{
    int failures = 0;
    for (size_t i = 0; i < 4; i++) failures += ma_subscription_child(i);
    return failures;
}

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

static int test_peer_floor_env_bounds(void)
{
    int failures = 0;
    TEST("metric_alerts: malformed peer floors fall back without disabling alerts") {
        const char *knob = "ZCL_ALERT_PEER_COLLAPSE_MIN_PEERS";
        const char *old = getenv(knob);
        char saved[4096];
        ASSERT(!old || strlen(old) < sizeof(saved));
        if (old) memcpy(saved, old, strlen(old) + 1);
        const struct { const char *value; int64_t peers; uint64_t fires; } cases[] = {
            {"nan", 0, 1}, {"inf", 2, 0}, {"-inf", 0, 1},
            {"1e999", 2, 0}, {"2junk", 0, 1}, {"3junk", 2, 0},
            {" \t\n", 0, 1},
            {"-1", 0, 1}, {"1e-999", 0, 1}, {"", 0, 1},
            {"2", 0, 1}, {"2", 2, 0}, {"2.5", 2, 1},
            {" \t2.5\n ", 2, 1}, {"0", 0, 0},
            {NULL, 0, 1}, {NULL, 2, 0},
        };
        bool ok = true;
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            int rc = cases[i].value ? setenv(knob, cases[i].value, 1)
                                   : unsetenv(knob);
            if (rc != 0) {
                fprintf(stderr, "peer floor case %zu: environment setup failed\n", i);
                ok = false;
                break;
            }
            /* This knob is read by the setter, not the lazy catalog seed. */
            ma_reset_all();
            metrics_prometheus_set_node_gauges(0, cases[i].peers, 0, 0, 150);
            metrics_prometheus_evaluate_alert_rules();
            uint64_t initial = metrics_prometheus_alert_fire_count("peer_count_collapsed");
            metrics_prometheus_set_node_gauges(0, cases[i].peers, 0, 0, 500);
            metrics_prometheus_evaluate_alert_rules();
            uint64_t fires = metrics_prometheus_alert_fire_count("peer_count_collapsed");
            if (initial != 0 || fires != cases[i].fires) {
                fprintf(stderr, "peer floor case %zu: initial=%" PRIu64
                        " fires=%" PRIu64 " expected=%" PRIu64 "\n",
                        i, initial, fires, cases[i].fires);
                ok = false;
            }
        }
        int restored = old ? setenv(knob, saved, 1) : unsetenv(knob);
        if (restored != 0) fprintf(stderr, "peer floor environment restore failed\n");
        ma_reset_all();
        ASSERT(restored == 0);
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

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

static int test_capability_blocker_does_not_alert(void)
{
    int failures = 0;
    TEST("metric_alerts: a capability-only blocker does not fire blocker_permanent_active") {
        ma_reset_all();
        ma_install_observer();
        blocker_clear("test.metric_alert_capability");

        struct blocker_record r;
        ASSERT(blocker_init(&r, "test.metric_alert_capability", "test",
                            BLOCKER_PERMANENT, "hermetic test"));
        r.capability_only = true;
        ASSERT(blocker_set(&r) >= 0);

        metrics_prometheus_evaluate_alert_rules();
        ASSERT(metrics_prometheus_alert_fire_count("blocker_permanent_active") == 0);
        ASSERT(!ma_captured_contains("name=metric_alert.blocker_permanent_active"));

        blocker_clear("test.metric_alert_capability");
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

struct ma_rss_result {
    bool values_ok;
    bool diagnostics_ok;
};

static bool ma_rss_gauges_match(const char *expected, uint64_t fires) {
    char rendered[16384];
    size_t n = metrics_prometheus_render_prometheus(rendered, sizeof(rendered));
    return n < sizeof(rendered) - 1 && strstr(rendered, expected) != NULL &&
           metrics_prometheus_alert_fire_count("rss_high") == fires;
}

static struct ma_rss_result ma_rss_samples(struct metrics_context *ctx) {
    static const int64_t bytes[] = {INT64_C(7340032000), -1, INT64_C(7340032000), 0, INT64_C(1572864)};
    static const char *expected[] = {"zcl_rss_mb 7000.00\n", "zcl_rss_mb -1.00\n",
                                   "zcl_rss_mb -1.00\n", "zcl_rss_mb 0.00\n", "zcl_rss_mb 1.50\n"};
    struct ma_rss_result result = {true, true};
    ma_read_attempts = 0;
    ma_diagnostic_ok = true;
    for (int i = 0; i < 5; i++) {
        ma_mem.rss_bytes = bytes[i];
        ma_read_fails = i == 2;
        metrics_prometheus_reset();
        ma_worker_output[0] = '\0';
        ma_worker_diagnostic[0] = '\0';
        atomic_store(&ctx->running, true);
        metrics_thread_fn(ctx);
        bool diagnostic = i == 1 || i == 2;
        bool reported = strstr(ma_worker_diagnostic,
            "metrics: RSS unavailable: process memory reader") != NULL;
        result.diagnostics_ok &= diagnostic ? reported : ma_worker_diagnostic[0] == '\0';
        result.values_ok &= ma_rss_gauges_match(expected[i], i == 0 ? 1u : 0u);
    }
    return result;
}

static int test_rss_tick(void) {
    int failures = 0;
    TEST("metric_alerts: tick publishes fresh RSS or unavailable with a diagnostic") {
        static struct main_state ms;
        zcl_mutex_init(&ms.cs_main);
        struct metrics_context ctx = {.ms = &ms, .external_gauges = ma_end_tick};
        ctx.external_gauges_ctx = &ctx;
        const clock_iface_t *saved_clock = clock_default();
        clock_set_default(&ma_clock);
        struct ma_rss_result samples = ma_rss_samples(&ctx);
        ma_read_fails = false;
        ma_mem.rss_bytes = 0;
        clock_set_default(saved_clock);
        zcl_mutex_destroy(&ms.cs_main);
        metrics_prometheus_reset();
        ASSERT(samples.values_ok && ma_read_attempts == 5);
        ASSERT(samples.diagnostics_ok && ma_diagnostic_ok);
        PASS();
    } _test_next:;
    return failures;
}

static int test_rss_unavailable_episodes(void) {
    int failures = 0;
    TEST("metric_alerts: worker logs each RSS unavailable episode once and resets per session") {
        static struct main_state ms;
        zcl_mutex_init(&ms.cs_main);
        struct metrics_context ctx = {.ms = &ms};
        const clock_iface_t *saved_clock = clock_default();
        clock_set_default(&ma_clock);
        ma_terminal = false;
        ma_diagnostic_count = 0;
        ma_diagnostic_ok = true;
        ma_read_attempts = 0;
        ma_episode_values_ok = true;
        for (int session = 0; session < 2; ++session) {
            ma_episode_ctx = &ctx;
            ma_episode_tick = 0;
            ma_episode_diagnostic_base = ma_diagnostic_count;
            ma_mem.rss_bytes = -1;
            ma_read_fails = false;
            ma_worker_output[0] = '\0';
            atomic_store(&ctx.running, true);
            metrics_thread_fn(&ctx);
        }
        ma_episode_ctx = NULL;
        ma_read_fails = false;
        ma_mem.rss_bytes = 0;
        clock_set_default(saved_clock);
        zcl_mutex_destroy(&ms.cs_main);
        metrics_prometheus_reset();
        ASSERT(ma_episode_values_ok && ma_read_attempts == 12);
        ASSERT(ma_diagnostic_ok && ma_diagnostic_count == 4);
        PASS();
    } _test_next:;
    return failures;
}

/* ── header_gap_growing, peer_count_collapsed, sync_state_stuck,
 * consensus_reject_spike ─────────────────────────────────────────
 *
 * These hysteresis gauges use the node's own uptime counter as clock basis,
 * so a test drives "time" by passing increasing `uptime_seconds` to
 * metrics_prometheus_set_node_gauges() instead of sleeping. */

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

static int test_peer_offence_payload_extent(void)
{
    static const char witness[] = "+1=1 invalid_message\0junk: detail";
    static const char score_nul[] = "+1=1\0junk invalid_message: detail";
    static const char detail_nul[] = "+1=1 invalid_message: detail\0junk";
    static const char valid[] = "+1=1 invalid_message: detail";
    static const char double_nul[] = "+1=1 invalid_message: detail\0";
    static const struct {
        const char *payload;
        uint32_t len;
        bool malformed;
    } cases[] = {
        {witness, sizeof(witness) - 1, true},
        {score_nul, sizeof(score_nul) - 1, true},
        {detail_nul, sizeof(detail_nul) - 1, true},
        {valid, sizeof(valid) - 1, false},
        {valid, sizeof(valid), false},
        {double_nul, sizeof(double_nul), true},
    };
    int failures = 0;
    TEST("metric_alerts: peer payload NUL routes to other without losing totals") {
        event_log_init();
        metrics_prometheus_init();
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            char rendered[16384];
            metrics_prometheus_reset();
            event_emit(EV_PEER_MISBEHAVE, 1, cases[i].payload, cases[i].len);
            size_t n = metrics_prometheus_render_prometheus(rendered, sizeof(rendered));
            ASSERT(n > 0 && n < sizeof(rendered) - 1);
            ASSERT(strstr(rendered, cases[i].malformed
                ? "\nzcl_peer_offences_total{kind=\"other\"} 1\n"
                : "\nzcl_peer_offences_total{kind=\"other\"} 0\n") != NULL);
            ASSERT(strstr(rendered, cases[i].malformed
                ? "\nzcl_peer_offences_total{kind=\"invalid_message\"} 0\n"
                : "\nzcl_peer_offences_total{kind=\"invalid_message\"} 1\n") != NULL);
            ASSERT(strstr(rendered, "\nzcl_peer_offences_total{kind=\"all\"} 1\n") != NULL);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ────────────────────────────────────────────── */

int test_metric_alerts(void);

int test_metric_alerts(void)
{
#ifdef _WIN32
    const char *role = getenv("ZCL_TEST_FORK_ROLE");
    if (role && strncmp(role, "metrics-subscription-", 21) == 0 &&
        role[21] >= '0' && role[21] <= '3' && role[22] == '\0')
        return ma_subscription_case((size_t)(role[21] - '0'));
#endif
    int failures = 0;

    failures += test_worker_display_hint();
    failures += test_subscription_retries();
    failures += test_rule_count_and_names();
    failures += test_peer_floor_env_bounds();
    failures += test_allow_listed_for_push();

    failures += test_fires_exactly_once_on_crossing();
    failures += test_not_raised_below_threshold();
    failures += test_refires_after_clearing_and_recrossing();
    failures += test_sentinel_value_does_not_fire();

    failures += test_mirror_lag_high_rule();
    failures += test_mirror_lag_critical_rule();
    failures += test_blocker_permanent_active_rule();
    failures += test_capability_blocker_does_not_alert();
    failures += test_rss_high_rule();
    failures += test_rss_tick();
    failures += test_rss_unavailable_episodes();

    failures += test_header_gap_growing_rule();
    failures += test_peer_count_collapsed_rule();
    failures += test_sync_state_stuck_rule();
    failures += test_consensus_reject_spike_rule();

    failures += test_metrics_reset_clears_alert_state();
    failures += test_peer_offence_payload_extent();

    event_clear_observers(EV_CONDITION_DETECTED);
    blocker_clear("test.metric_alert_permanent");
    metrics_prometheus_reset();
    return failures;
}
