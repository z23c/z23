/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the alert routing subsystem (wave 9 #5). */

#include "test/test_core.h"
#include "util/alerts.h"
#include "event/event.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool contains(const char *hay, const char *needle)
{
    return hay && needle && strstr(hay, needle) != NULL;
}

static int test_seed_rules_registered(void)
{
    int failures = 0;
    TEST("alerts: init registers 6 seed rules") {
        alerts_shutdown();
        /* Ensure alerts system is not disabled */
        unsetenv("ZCL_ALERTS_DISABLE");
        unsetenv("ZCL_ALERT_WEBHOOK_URL");
        alerts_init();
        /* 4 original + operator_needed + condition_detected (the silent-halt
         * fix: EV_OPERATOR_NEEDED now reaches a sink). */
        ASSERT(alerts_rule_count() == 6);
        alerts_shutdown();
        PASS();
    } _test_next:;
    return failures;
}

static int test_disable_flag(void)
{
    int failures = 0;
    TEST("alerts: ZCL_ALERTS_DISABLE=1 suppresses all rules") {
        alerts_shutdown();
        setenv("ZCL_ALERTS_DISABLE", "1", 1);
        alerts_init();
        ASSERT(alerts_rule_count() == 0);
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        PASS();
    } _test_next:;
    return failures;
}

static int test_threshold_fires_at_count(void)
{
    int failures = 0;
    TEST("alerts: rule fires when threshold is crossed") {
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        unsetenv("ZCL_ALERT_WEBHOOK_URL");
        alerts_init();

        /* disk_low has threshold=1, so a single event should fire. */
        alerts_reset();
        ASSERT(alerts_fire_count("disk_low") == 0);

        event_emitf(EV_DISK_LOW, 0, "path=/data free=100 warn_thr=1000");
        ASSERT(alerts_fire_count("disk_low") == 1);

        alerts_shutdown();
        PASS();
    } _test_next:;
    return failures;
}

static int test_cooldown_suppresses_repeat(void)
{
    int failures = 0;
    TEST("alerts: cooldown suppresses repeat fires") {
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        alerts_init();
        alerts_reset();

        /* Fire once */
        event_emitf(EV_DISK_LOW, 0, "test1");
        ASSERT(alerts_fire_count("disk_low") == 1);

        /* Second event within cooldown (600s) should NOT fire again */
        event_emitf(EV_DISK_LOW, 0, "test2");
        ASSERT(alerts_fire_count("disk_low") == 1);

        alerts_shutdown();
        PASS();
    } _test_next:;
    return failures;
}

static int test_multi_event_threshold(void)
{
    int failures = 0;
    TEST("alerts: peer_bans_high needs 5 events to fire") {
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        alerts_init();
        alerts_reset();

        /* peer_bans_high: threshold=5 */
        for (int i = 0; i < 4; i++)
            event_emitf(EV_PEER_BANNED, 0, "test ban %d", i);
        ASSERT(alerts_fire_count("peer_bans_high") == 0);

        /* 5th event crosses threshold */
        event_emitf(EV_PEER_BANNED, 0, "test ban 4");
        ASSERT(alerts_fire_count("peer_bans_high") == 1);

        alerts_shutdown();
        PASS();
    } _test_next:;
    return failures;
}

static int test_add_custom_rule(void)
{
    int failures = 0;
    TEST("alerts: add_rule registers custom rule") {
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        alerts_init();

        struct alert_rule custom = {
            .name = "test_custom",
            .trigger = EV_NODE_READY,
            .threshold = 1,
            .window_sec = 60,
            .cooldown_sec = 120,
            .enabled = true,
        };
        snprintf(custom.name, sizeof(custom.name), "test_custom");
        ASSERT(alerts_add_rule(&custom));
        ASSERT(alerts_rule_count() == 7);

        /* Duplicate name rejected */
        ASSERT(!alerts_add_rule(&custom));
        ASSERT(alerts_rule_count() == 7);

        alerts_shutdown();
        PASS();
    } _test_next:;
    return failures;
}

static int test_report_json_shape(void)
{
    int failures = 0;
    TEST("alerts: report_json has rules + webhook + totals") {
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        unsetenv("ZCL_ALERT_WEBHOOK_URL");
        alerts_init();
        alerts_reset();

        /* Fire one alert */
        event_emitf(EV_DISK_LOW, 0, "test");

        char buf[4096];
        size_t n = alerts_report_json(buf, sizeof(buf));
        ASSERT(n > 0);

        ASSERT(contains(buf, "\"webhook\":false"));
        ASSERT(contains(buf, "\"rules\":["));
        ASSERT(contains(buf, "\"name\":\"disk_low\""));
        ASSERT(contains(buf, "\"name\":\"peer_bans_high\""));
        ASSERT(contains(buf, "\"name\":\"rpc_ratelimit_spike\""));
        ASSERT(contains(buf, "\"name\":\"chain_tip_rejected\""));
        ASSERT(contains(buf, "\"name\":\"operator_needed\""));
        ASSERT(contains(buf, "\"total_rules\":6"));
        ASSERT(contains(buf, "\"fires\":1"));
        ASSERT(contains(buf, "\"trigger\":\"disk.low\""));

        alerts_shutdown();
        PASS();
    } _test_next:;
    return failures;
}

static int test_reset_clears_state(void)
{
    int failures = 0;
    TEST("alerts: reset clears fire counts and window counts") {
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        alerts_init();

        event_emitf(EV_DISK_LOW, 0, "test");
        ASSERT(alerts_fire_count("disk_low") == 1);

        alerts_reset();
        ASSERT(alerts_fire_count("disk_low") == 0);

        alerts_shutdown();
        PASS();
    } _test_next:;
    return failures;
}

static int test_rule_table_full(void)
{
    int failures = 0;
    TEST("alerts: table full rejects further rules") {
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        alerts_init();
        /* 6 seed rules already registered; fill to ALERT_MAX_RULES */
        for (int i = 0; i < (int)(ALERT_MAX_RULES - 6); i++) {
            struct alert_rule r = {
                .trigger = EV_NODE_READY,
                .threshold = 1,
                .window_sec = 60,
                .cooldown_sec = 60,
                .enabled = true,
            };
            snprintf(r.name, sizeof(r.name), "fill_%d", i);
            ASSERT(alerts_add_rule(&r));
        }
        ASSERT(alerts_rule_count() == ALERT_MAX_RULES);

        /* One more should fail */
        struct alert_rule overflow = {
            .trigger = EV_NODE_READY,
            .threshold = 1, .window_sec = 60, .cooldown_sec = 60,
            .enabled = true,
        };
        snprintf(overflow.name, sizeof(overflow.name), "overflow");
        ASSERT(!alerts_add_rule(&overflow));

        alerts_shutdown();
        PASS();
    } _test_next:;
    return failures;
}

static int test_operator_needed_latch(void)
{
    int failures = 0;
    TEST("alerts: EV_OPERATOR_NEEDED latches + clears on EV_CONDITION_CLEARED") {
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        unsetenv("ZCL_ALERT_WEBHOOK_URL");
        alerts_init();
        alerts_reset();

        /* Before any halt: not latched. */
        ASSERT(!alerts_operator_needed(NULL, 0, NULL));

        /* The condition engine exhausted remedies → emits EV_OPERATOR_NEEDED.
         * This is THE silent-halt signal; it must now be observable. */
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "condition=tip_not_advancing attempts=5");
        char detail[ALERT_OPERATOR_NEEDED_DETAIL_LEN] = {0};
        int64_t since = 0;
        ASSERT(alerts_operator_needed(detail, sizeof(detail), &since));
        ASSERT(contains(detail, "tip_not_advancing"));
        ASSERT(alerts_fire_count("operator_needed") == 1);

        /* The underlying condition resolves → latch drops automatically. */
        event_emitf(EV_CONDITION_CLEARED, 0,
                    "name=tip_not_advancing cleared_count=1");
        ASSERT(!alerts_operator_needed(NULL, 0, NULL));

        const char *long_payload =
            "check=window.consistency I4.3 utxo_apply log hole: contiguous "
            "ok=1 prefix h=3056758 but cursor=3171120 first_hole_h=3056759 "
            "repair_owner=reducer_frontier_reconcile_light";
        event_emitf(EV_OPERATOR_NEEDED, 0, "%s", long_payload);
        char long_detail[ALERT_OPERATOR_NEEDED_DETAIL_LEN] = {0};
        ASSERT(alerts_operator_needed(long_detail, sizeof(long_detail), NULL));
        ASSERT(strlen(long_detail) > 128);
        ASSERT(contains(long_detail, "first_hole_h=3056759"));
        ASSERT(contains(long_detail, "reducer_frontier_reconcile_light"));

        alerts_shutdown();
        PASS();
    } _test_next:;
    return failures;
}

static int test_operator_needed_chain_advance_recovery_clear(void)
{
    int failures = 0;
    TEST("alerts: chain advance latch only clears after frontier recovery") {
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        unsetenv("ZCL_ALERT_WEBHOOK_URL");
        alerts_init();
        alerts_reset();

        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "condition=chain_advance_local_recovery_gate attempts=5");
        char detail[ALERT_OPERATOR_NEEDED_DETAIL_LEN] = {0};
        ASSERT(alerts_operator_needed(detail, sizeof(detail), NULL));
        ASSERT(contains(detail, "chain_advance_local_recovery_gate"));

        ASSERT(!alerts_operator_needed_clear_if_chain_advance_recovered(
            false, detail, sizeof(detail), NULL));
        ASSERT(alerts_operator_needed(NULL, 0, NULL));

        ASSERT(alerts_operator_needed_clear_if_chain_advance_recovered(
            true, detail, sizeof(detail), NULL));
        ASSERT(contains(detail, "chain_advance_local_recovery_gate"));
        ASSERT(!alerts_operator_needed(NULL, 0, NULL));

        event_emitf(EV_OPERATOR_NEEDED, 0, "chain_integrity_failed");
        ASSERT(!alerts_operator_needed_clear_if_chain_advance_recovered(
            true, detail, sizeof(detail), NULL));
        ASSERT(alerts_operator_needed(NULL, 0, NULL));

        alerts_shutdown();
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ─────────────────────────────────────────────── */

int test_alerts(void);

int test_alerts(void)
{
    int failures = 0;
    event_log_init();

    failures += test_seed_rules_registered();
    failures += test_disable_flag();
    failures += test_threshold_fires_at_count();
    failures += test_cooldown_suppresses_repeat();
    failures += test_multi_event_threshold();
    failures += test_add_custom_rule();
    failures += test_report_json_shape();
    failures += test_reset_clears_state();
    failures += test_rule_table_full();
    failures += test_operator_needed_latch();
    failures += test_operator_needed_chain_advance_recovery_clear();

    alerts_shutdown();
    return failures;
}
