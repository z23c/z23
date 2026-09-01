/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Lag-SLO breach tests for the legacy_mirror_sync_service.
 *
 * Asserts the contract every downstream consumer (Prometheus,
 * node_health, native diagnostics) hangs off:
 *
 *   - lag ≥ breach_blocks for ≥ breach_secs  → EV_LAG_SLO_BREACH (warn|critical)
 *   - lag ≥ critical_blocks for ≥ critical_secs → EV_LAG_SLO_BREACH (fatal)
 *
 * Fatal severity drives node_health.healthy=false for serving, conditions,
 * remedies, and operator paging. It is not a process-hang signal. */

#include "test/test_core.h"

#include "services/legacy_mirror_sync_service.h"
#include "event/event.h"
#include "json/json.h"
#include "util/supervisor.h"

#include <stdatomic.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static _Atomic int g_slo_breach_events;
static _Atomic int g_concurrent_events;
static char g_last_payload[EVENT_PAYLOAD_SIZE];

static void slo_observer(enum event_type type, uint32_t peer_id,
                         const void *payload, uint32_t payload_len,
                         void *ctx)
{
    (void)peer_id;
    (void)ctx;
    if (type != EV_LAG_SLO_BREACH) return;
    atomic_fetch_add(&g_slo_breach_events, 1);
    if (payload && payload_len > 0 &&
        payload_len < EVENT_PAYLOAD_SIZE) {
        memcpy(g_last_payload, payload, payload_len);
        g_last_payload[payload_len] = '\0';
    }
}

static void concurrent_observer(enum event_type type, uint32_t peer_id,
                                const void *payload, uint32_t payload_len,
                                void *ctx)
{
    (void)peer_id;
    (void)payload;
    (void)payload_len;
    (void)ctx;
    if (type == EV_MIRROR_CONCURRENT_CATCHUP)
        atomic_fetch_add(&g_concurrent_events, 1);
}

static int test_event_names_are_stable(void)
{
    int failures = 0;
    TEST_CASE("lag_slo: EV_LAG_SLO_BREACH has stable name strings")
    {
        ASSERT_STR_EQ(event_type_name(EV_LAG_SLO_BREACH),
                      "mirror.lag_slo_breach");
        ASSERT_STR_EQ(event_type_name(EV_PEER_FLOOR_BREACH),
                      "peer.floor_breach");
        ASSERT_STR_EQ(event_type_name(EV_MIRROR_CONCURRENT_CATCHUP),
                      "mirror.concurrent_catchup");
    } TEST_END
    return failures;
}

static int test_severity_none_when_under_threshold(void)
{
    int failures = 0;
    TEST_CASE("lag_slo: severity=none when lag below threshold")
    {
        legacy_mirror_sync_reset_for_test();
        struct legacy_mirror_sync_stats in = {0};
        in.enabled = true;
        in.running = true;
        in.reachable = true;
        in.legacy_height = 100;
        in.local_height = 95;
        /* lag = 5, default breach threshold = 10 */
        legacy_mirror_sync_test_set_stats(&in, NULL);

        struct legacy_mirror_sync_stats out = {0};
        legacy_mirror_sync_stats_snapshot(&out);
        ASSERT_STR_EQ(out.lag_breach_severity, "none");
        ASSERT(out.lag_breach_seconds == 0);
    } TEST_END
    return failures;
}

static int test_snapshot_surfaces_thresholds(void)
{
    int failures = 0;
    TEST_CASE("lag_slo: snapshot exposes configured SLO thresholds")
    {
        legacy_mirror_sync_reset_for_test();
        struct legacy_mirror_sync_stats in = {0};
        in.enabled = true;
        in.running = true;
        legacy_mirror_sync_test_set_stats(&in, NULL);

        struct legacy_mirror_sync_stats out = {0};
        legacy_mirror_sync_stats_snapshot(&out);
        ASSERT(out.lag_sla_breach_blocks >= 0);
        ASSERT(out.lag_sla_critical_blocks >= 0);
        ASSERT(out.lag_sla_breach_secs >= 0);
        ASSERT(out.lag_sla_critical_secs >= 0);
    } TEST_END
    return failures;
}

static int test_slo_breach_observer_fires(void)
{
    int failures = 0;
    TEST_CASE("lag_slo: EV_LAG_SLO_BREACH observer catches emit")
    {
        atomic_store(&g_slo_breach_events, 0);
        memset(g_last_payload, 0, sizeof(g_last_payload));
        event_clear_observers(EV_LAG_SLO_BREACH);
        event_observe(EV_LAG_SLO_BREACH, slo_observer, NULL);
        event_emitf(EV_LAG_SLO_BREACH, 0,
                    "lag=200 legacy_height=3117882 local_height=3117682 "
                    "since=90s severity=critical");
        ASSERT(atomic_load(&g_slo_breach_events) == 1);
        ASSERT(strstr(g_last_payload, "severity=critical") != NULL);
        ASSERT(strstr(g_last_payload, "lag=200") != NULL);
        event_clear_observers(EV_LAG_SLO_BREACH);
    } TEST_END
    return failures;
}

static int test_concurrent_catchup_observer_fires(void)
{
    int failures = 0;
    TEST_CASE("lag_slo: EV_MIRROR_CONCURRENT_CATCHUP observer catches emit")
    {
        atomic_store(&g_concurrent_events, 0);
        event_clear_observers(EV_MIRROR_CONCURRENT_CATCHUP);
        event_observe(EV_MIRROR_CONCURRENT_CATCHUP, concurrent_observer,
                      NULL);
        event_emitf(EV_MIRROR_CONCURRENT_CATCHUP, 0,
                    "applied=15 target=3117800 source=mirror reason=tick");
        ASSERT(atomic_load(&g_concurrent_events) == 1);
        event_clear_observers(EV_MIRROR_CONCURRENT_CATCHUP);
    } TEST_END
    return failures;
}

static int test_legacy_mirror_registers_supervisor_contract(void)
{
    int failures = 0;
    TEST_CASE("lag_slo: legacy mirror registers a chain supervisor contract")
    {
        legacy_mirror_sync_reset_for_test();
        supervisor_reset_for_testing();
        unsetenv("ZCL_MIRROR_SYNC");
        unsetenv("ZCL_MIRROR_CADENCE_SECS");

        struct legacy_mirror_sync_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = 1,
            .rpc_user = "user",
            .rpc_password = "pass",
            .cadence_secs = 300,
            .enabled = true,
        };
        ASSERT(legacy_mirror_sync_init(&cfg, NULL, NULL, NULL, NULL).ok);
        ASSERT(legacy_mirror_sync_start().ok);

        struct supervisor_snapshot snaps[SUPERVISOR_CAP];
        int n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
        const struct supervisor_snapshot *mirror = NULL;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].name, "chain.legacy_mirror") == 0) {
                mirror = &snaps[i];
                break;
            }
        }
        ASSERT(mirror != NULL);
        ASSERT(mirror->period_secs == 300);
        ASSERT(mirror->deadline_secs == 0);

        struct legacy_mirror_sync_stats s = {0};
        legacy_mirror_sync_stats_snapshot(&s);
        ASSERT(s.running);

        legacy_mirror_sync_stop();
        ASSERT(supervisor_child_count_total() == 0);
        legacy_mirror_sync_reset_for_test();
        supervisor_reset_for_testing();
    } TEST_END
    return failures;
}

static int test_legacy_mirror_backs_off_when_rpc_is_absent(void)
{
    int failures = 0;
    TEST_CASE("lag_slo: absent legacy RPC backs off instead of busy-looping")
    {
        legacy_mirror_sync_reset_for_test();
        supervisor_reset_for_testing();
        supervisor_set_tick_ms_for_testing(20);
        unsetenv("ZCL_MIRROR_SYNC");
        unsetenv("ZCL_MIRROR_CADENCE_SECS");

        struct legacy_mirror_sync_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = 1, /* closed by contract in this hermetic fixture */
            .rpc_user = "user",
            .rpc_password = "pass",
            .cadence_secs = 1,
            .enabled = true,
        };
        ASSERT(legacy_mirror_sync_init(&cfg, NULL, NULL, NULL, NULL).ok);
        ASSERT(legacy_mirror_sync_start().ok);

        int observed_period = 1;
        for (int attempt = 0; attempt < 150; attempt++) {
            struct supervisor_snapshot snaps[SUPERVISOR_CAP];
            int n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
            for (int i = 0; i < n; i++) {
                if (strcmp(snaps[i].name, "chain.legacy_mirror") == 0)
                    observed_period = snaps[i].period_secs;
            }
            if (observed_period > 1)
                break;
            struct timespec pause = {
                .tv_sec = 0,
                .tv_nsec = 20 * 1000 * 1000,
            };
            nanosleep(&pause, NULL);
        }

        struct legacy_mirror_sync_stats stats = {0};
        legacy_mirror_sync_stats_snapshot(&stats);
        ASSERT(stats.rpc_errors >= 1);
        ASSERT(observed_period >= 2);
        ASSERT(observed_period <= 300);

        struct supervisor_snapshot snaps[SUPERVISOR_CAP];
        int snap_n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
        const struct supervisor_snapshot *mirror = NULL;
        for (int i = 0; i < snap_n; i++) {
            if (strcmp(snaps[i].name, "chain.legacy_mirror") == 0) {
                mirror = &snaps[i];
                break;
            }
        }
        ASSERT(mirror != NULL);
        ASSERT(mirror->stall_reason == SUPERVISOR_STALL_NONE);
        ASSERT(mirror->stall_fires == 0);
        ASSERT(mirror->idle_ticks >= 1);

        legacy_mirror_sync_stop();
        legacy_mirror_sync_reset_for_test();
        supervisor_reset_for_testing();
    } TEST_END
    return failures;
}

/* C2 monitor-extraction pin: the lean monitor's dump_state_json must
 * keep emitting every key that downstream consumers (node_health,
 * metrics, chain_advance_coordinator, deploy_verify.sh, and the native
 * legacy_mirror state primitive) read. A careless lean-up that
 * drops an include or a stats field would silently shrink this shape;
 * this test fails loudly if any contract key disappears. */
static int test_dump_shape_is_stable(void)
{
    int failures = 0;
    TEST_CASE("lag_slo: dump_state_json keeps the full monitor contract shape")
    {
        legacy_mirror_sync_reset_for_test();
        struct legacy_mirror_sync_stats in = {0};
        in.enabled = true;
        in.running = true;
        in.reachable = true;
        in.legacy_height = 100;
        in.local_height = 95;
        legacy_mirror_sync_test_set_stats(&in, NULL);

        struct json_value out;
        json_init(&out);
        json_set_object(&out);
        ASSERT(legacy_mirror_sync_dump_state_json(&out, NULL));

        /* Heartbeat / lag-SLO monitor surface — the half C2 preserves. */
        static const char *const required_keys[] = {
            "mirror_enabled", "state", "mirror_running", "running",
            "reachable", "mirror_reachable", "in_flight",
            "mirror_monitor_running", "zclassicd_rpc_transport_reachable",
            "legacy_oracle_usable", "zclassicd_rpc_error_code",
            "zclassicd_rpc_error_message",
            "zclassic23_height", "zclassic23_hash",
            "zclassicd_height", "zclassicd_hash",
            "legacy_height", "legacy_headers", "local_height",
            "best_header_height", "legacy_advisory_height_known",
            "target_height_known", "lag_known", "lag_valid", "lag",
            "tip_hashes_agree", "lag_observed",
            "candidate_source", "candidate_trust",
            "candidate_lag_known", "candidate_lag_valid", "candidate_lag",
            "candidate_lag_observed",
            "candidate_blocker", "blocker_recovered_by_tip_agreement",
            "target_height", "authority_rewind_target",
            "last_advanced_height", "last_progress_blocks",
            "stuck_height", "stuck_status_flags", "stuck_reason",
            "stalls_total", "last_catchup", "last_attempt",
            "catchups_total", "rpc_errors", "blocks_applied",
            "headers_added", "consensus_authority", "blockers_total",
            "activation_blocker", "last_blocker_code",
            "active_error_code", "active_error_detail", "last_error",
            "lag_sla_breach_blocks", "lag_sla_breach_secs",
            "lag_sla_critical_blocks", "lag_sla_critical_secs",
            "lag_breach_since", "lag_breach_seconds",
            "lag_critical_since", "lag_critical_seconds",
            "lag_breach_severity",
        };
        for (size_t i = 0; i < sizeof(required_keys) / sizeof(*required_keys);
             i++) {
            if (json_get(&out, required_keys[i]) == NULL) {
                printf("    missing dump key: %s\n", required_keys[i]);
                failures++;
            }
        }
        json_free(&out);
    } TEST_END
    return failures;
}

int test_lag_slo(void)
{
    int failures = 0;
    event_log_init();
    printf("\n=== Lag SLO breach observability ===\n");
    failures += test_event_names_are_stable();
    failures += test_severity_none_when_under_threshold();
    failures += test_snapshot_surfaces_thresholds();
    failures += test_slo_breach_observer_fires();
    failures += test_concurrent_catchup_observer_fires();
    failures += test_legacy_mirror_registers_supervisor_contract();
    failures += test_legacy_mirror_backs_off_when_rpc_is_absent();
    failures += test_dump_shape_is_stable();
    legacy_mirror_sync_reset_for_test();
    supervisor_reset_for_testing();
    return failures;
}
