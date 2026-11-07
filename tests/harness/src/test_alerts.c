/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the alert routing subsystem. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "test/test_core.h"
#include "util/alerts.h"
#include "event/event.h"
#include "json/json.h"
#include "zutf8/zutf8.h"
#include "util/sd_notify.h"
#include "platform/socket_compat.h"
#include "platform/clock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif

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

static void foreign_alert_observer(enum event_type type, uint32_t peer_id,
                                  const void *payload, uint32_t len, void *ctx)
{
    (void)type; (void)peer_id; (void)payload; (void)len;
    (*(int *)ctx)++;
}

static int test_registration_refusal(void)
{
    int failures = 0, calls = 0, saved = -1;
    FILE *log = NULL;
    TEST("alerts: refused observers do not publish rules") {
        alerts_shutdown();
        event_clear_all_observers();
        unsetenv("ZCL_ALERTS_DISABLE");
        unsetenv("ZCL_ALERT_WEBHOOK_URL");
        for (int i = 0; i < EVENT_MAX_OBSERVERS; i++)
            ASSERT(event_observe(EV_OPERATOR_NEEDED, foreign_alert_observer, &calls));
        log = tmpfile();
        ASSERT(log != NULL);
        ASSERT(fflush(stderr) == 0);
        saved = dup(STDERR_FILENO);
        ASSERT(saved >= 0);
        ASSERT(dup2(fileno(log), STDERR_FILENO) >= 0);
        alerts_init();
        int flushed = fflush(stderr);
        int restored = dup2(saved, STDERR_FILENO);
        ASSERT(restored >= 0);
        ASSERT(flushed == 0);
        ASSERT(fseek(log, 0, SEEK_SET) == 0);
        char text[1024] = {0};
        ASSERT(fread(text, 1, sizeof(text) - 1, log) > 0);
        ASSERT(contains(text, "rule operator_needed registration refused"));
        ASSERT(alerts_rule_count() == 5);
        char report[4096];
        ASSERT(alerts_report_json(report, sizeof(report)) > 0);
        ASSERT(!contains(report, "\"name\":\"operator_needed\""));
        event_emitf(EV_OPERATOR_NEEDED, 0, "condition=A attempts=5");
        ASSERT(calls == EVENT_MAX_OBSERVERS);
        ASSERT(!alerts_operator_needed(NULL, 0, NULL));
        event_emitf(EV_DISK_LOW, 0, "test");
        ASSERT(alerts_fire_count("disk_low") == 1);
        for (int i = 0; i < EVENT_MAX_OBSERVERS; i++)
            ASSERT(event_observe(EV_NODE_READY, foreign_alert_observer, &calls));
        struct alert_rule rule = {
            .name = "refused", .trigger = EV_NODE_READY, .threshold = 1,
            .window_sec = 60, .cooldown_sec = 120, .enabled = true,
        };
        ASSERT(!alerts_add_rule(&rule));
        ASSERT(alerts_rule_count() == 5);
        rule.trigger = EV_TCP_CONNECTED;
        ASSERT(alerts_add_rule(&rule));
        ASSERT(alerts_rule_count() == 6);
        event_emitf(EV_TCP_CONNECTED, 0, "test");
        ASSERT(alerts_fire_count("refused") == 1);
        PASS();
    } _test_next:;
    if (saved >= 0) {
        if (dup2(saved, STDERR_FILENO) < 0) {
            fprintf(stdout, "alerts fixture: stderr restoration failed\n");
            failures++;
        }
        if (close(saved) != 0) failures++;
    }
    if (log && fclose(log) != 0) failures++;
    alerts_shutdown();
    event_clear_all_observers();
    return failures;
}

static int test_rule_name_boundary(void)
{
    int failures = 0;
    TEST("alerts: rule names require an in-field terminator") {
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        unsetenv("ZCL_ALERT_WEBHOOK_URL");
        alerts_init();
        size_t before = alerts_rule_count();
        struct alert_rule rule = {
            .trigger = EV_TCP_CONNECTED,
            .threshold = 1,
            .window_sec = 60,
            .cooldown_sec = 60,
            .enabled = true,
        };
        memset(rule.name, 'A', sizeof(rule.name));
        ASSERT(!alerts_add_rule(&rule));
        ASSERT(alerts_rule_count() == before);
        char buf[4096];
        size_t len = alerts_report_json(buf, sizeof(buf));
        ASSERT(len > 0 && len < sizeof(buf));
        struct json_value doc;
        json_init(&doc);
        ASSERT(json_read(&doc, buf, len));
        ASSERT(json_get_int(json_get(&doc, "total_rules")) == (int64_t)before);
        json_free(&doc);
        rule.name[sizeof(rule.name) - 1] = '\0';
        ASSERT(alerts_add_rule(&rule));
        ASSERT(alerts_rule_count() == before + 1);
        ASSERT(!alerts_add_rule(&rule));
        ASSERT(alerts_rule_count() == before + 1);
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
                .trigger = (enum event_type)(EV_TCP_CONNECT_ATTEMPT + i),
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

        event_emitf(EV_CONDITION_CLEARED, 0,
                    "name=other_condition cleared_count=1");
        char retained[ALERT_OPERATOR_NEEDED_DETAIL_LEN];
        int64_t retained_since = 0;
        ASSERT(alerts_operator_needed(retained, sizeof(retained), &retained_since));
        ASSERT(strcmp(retained, detail) == 0);
        ASSERT(retained_since == since);
        event_emitf(EV_CONDITION_CLEARED, 0,
                    "name=tip_not_advancing_extra cleared_count=1");
        ASSERT(alerts_operator_needed(NULL, 0, NULL));
        const char bounded_clear[] = "X name=tip_not_advancing";
        event_emit(EV_CONDITION_CLEARED, 0, bounded_clear, 1);
        ASSERT(alerts_operator_needed(NULL, 0, NULL));
        event_emitf(EV_CONDITION_CLEARED, 0,
                    "other_name=tip_not_advancing cleared_count=1");
        ASSERT(alerts_operator_needed(NULL, 0, NULL));

        /* The underlying condition resolves → latch drops automatically. */
        event_emitf(EV_CONDITION_CLEARED, 0,
                    "name=tip_not_advancing cleared_count=1");
        ASSERT(!alerts_operator_needed(NULL, 0, NULL));
        ASSERT(!alerts_operator_needed(retained, sizeof(retained), &retained_since));
        ASSERT(retained[0] == '\0');
        ASSERT(retained_since == 0);

        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "condition=tip_not_advancing terminal=0");
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
        event_emitf(EV_CONDITION_CLEARED, 0, "name=unrelated cleared_count=1");
        ASSERT(alerts_operator_needed(NULL, 0, NULL));

        alerts_shutdown();
        PASS();
    } _test_next:;
    return failures;
}

static int test_operator_needed_payload_extent(void)
{
    int failures = 0;
    TEST("alerts: operator-needed scans only the declared payload") {
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        unsetenv("ZCL_ALERT_WEBHOOK_URL");
        alerts_init();
        alerts_reset();

        char detail[ALERT_OPERATOR_NEEDED_DETAIL_LEN];
        const char backing[] = "Xterminal=0";
        event_emit(EV_OPERATOR_NEEDED, 0, backing, 1);
        ASSERT(alerts_operator_needed(detail, sizeof(detail), NULL));
        ASSERT(strcmp(detail, "X") == 0);
        alerts_operator_needed_clear();

        const char raw[1] = {'X'};
        event_emit(EV_OPERATOR_NEEDED, 0, raw, sizeof(raw));
        ASSERT(alerts_operator_needed(detail, sizeof(detail), NULL));
        ASSERT(strcmp(detail, "X") == 0);
        alerts_operator_needed_clear();

        event_emit(EV_OPERATOR_NEEDED, 0, backing, 0);
        ASSERT(alerts_operator_needed(detail, sizeof(detail), NULL));
        ASSERT(strcmp(detail, "(unspecified)") == 0);
        alerts_operator_needed_clear();

        event_emit(EV_OPERATOR_NEEDED, 0, NULL, 1);
        ASSERT(alerts_operator_needed(detail, sizeof(detail), NULL));
        ASSERT(strcmp(detail, "(unspecified)") == 0);
        alerts_operator_needed_clear();

        const char nonterminal[] = "terminal=0";
        event_emit(EV_OPERATOR_NEEDED, 0, nonterminal, sizeof(nonterminal) - 1);
        ASSERT(!alerts_operator_needed(NULL, 0, NULL));
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

static bool operator_needed_guard_page(void)
{
#ifdef _WIN32
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    size_t page = info.dwPageSize;
    if (page == 0 || page > SIZE_MAX / 2) {
        fprintf(stderr, "alerts: guard page size invalid\n"); return false;
    }
    unsigned char *region = VirtualAlloc(NULL, page * 2,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!region) { fprintf(stderr, "alerts: guard allocation failed\n"); return false; }
    DWORD old;
    bool protected = VirtualProtect(region + page, page, PAGE_NOACCESS, &old) != 0;
#else
    long native_page = sysconf(_SC_PAGESIZE);
    if (native_page <= 0 || (uintmax_t)native_page > SIZE_MAX / 2) {
        fprintf(stderr, "alerts: page size unavailable\n"); return false;
    }
    size_t page = (size_t)native_page;
    unsigned char *region = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { fprintf(stderr, "alerts: guard mapping failed\n"); return false; }
    bool protected = mprotect(region + page, page, PROT_NONE) == 0;
#endif
    bool ok = false;
    if (protected) {
        region[page - 1] = 'x';
        alerts_operator_needed_clear();
        event_emit(EV_OPERATOR_NEEDED, 0, region + page - 1, 1);
        char detail[ALERT_OPERATOR_NEEDED_DETAIL_LEN];
        ok = alerts_operator_needed(detail, sizeof(detail), NULL);
        ok = ok && strcmp(detail, "x") == 0;
    } else fprintf(stderr, "alerts: guard protection failed\n");
#ifdef _WIN32
    bool released = VirtualFree(region, 0, MEM_RELEASE) != 0;
#else
    bool released = munmap(region, page * 2) == 0;
#endif
    if (!released) fprintf(stderr, "alerts: guard release failed\n");
    return ok && released;
}

static int test_operator_needed_counted_payload(void)
{
    int failures = 0;
    TEST("alerts: operator detail and terminal marker respect counted bytes") {
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        unsetenv("ZCL_ALERT_WEBHOOK_URL");
        alerts_init();
        char detail[ALERT_OPERATOR_NEEDED_DETAIL_LEN];
        event_emit(EV_OPERATOR_NEEDED, 0, "xterminal=0", 1);
        bool span = alerts_operator_needed(detail, sizeof(detail), NULL);
        span = span && strcmp(detail, "x") == 0;
        alerts_operator_needed_clear();
        const char marker[] = { 'x', 0, 't','e','r','m','i','n','a','l','=', '0' };
        event_emit(EV_OPERATOR_NEEDED, 0, marker, sizeof(marker));
        bool suppressed = !alerts_operator_needed(NULL, 0, NULL);
        const char counted[] = { 'a', 0, 'b' };
        event_emit(EV_OPERATOR_NEEDED, 0, counted, sizeof(counted));
        bool retained = alerts_operator_needed(detail, sizeof(detail), NULL);
        retained = retained && strcmp(detail, "a\\0b") == 0;
        bool guard = operator_needed_guard_page();
        alerts_shutdown();
        ASSERT(span); ASSERT(suppressed); ASSERT(retained); ASSERT(guard);
        PASS();
    } _test_next:;
    return failures;
}

static bool operator_detail_matches(const void *payload, uint32_t len,
                                    const char *expected)
{
    char detail[ALERT_OPERATOR_NEEDED_DETAIL_LEN];
    alerts_operator_needed_clear();
    event_emit(EV_OPERATOR_NEEDED, 0, payload, len);
    bool active = alerts_operator_needed(detail, sizeof(detail), NULL);
    return active && strcmp(detail, expected) == 0 && zutf8_validate(detail);
}

static int test_operator_detail_utf8(void)
{
    int failures = 0;
    TEST("alerts: malformed counted detail is refused with the latch retained") {
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        unsetenv("ZCL_ALERT_WEBHOOK_URL");
        alerts_init();
        const unsigned char malformed[][5] = {
            { 'a', 0, 0xff }, { 'a', 0, 0xc2 },
            { 'a', 0, 0xc0, 0x80 }, { 'a', 0, 0xed, 0xa0, 0x80 }
        };
        const uint32_t lengths[] = { 3, 3, 4, 5 };
        bool refused = true;
        for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++)
            refused &= operator_detail_matches(malformed[i], lengths[i],
                "(operator detail refused: invalid UTF-8)");
        const unsigned char valid[] = { 'a', 0, 0xe2, 0x82, 0xac };
        bool retained = operator_detail_matches(valid, sizeof(valid), "a\\0\xe2\x82\xac");
        event_emit(EV_OPERATOR_NEEDED, 0, "terminal=0", 10);
        char detail[ALERT_OPERATOR_NEEDED_DETAIL_LEN];
        bool unchanged = alerts_operator_needed(detail, sizeof(detail), NULL);
        unchanged &= strcmp(detail, "a\\0\xe2\x82\xac") == 0;
        event_emit(EV_CONDITION_CLEARED, 0, NULL, 0);
        bool nameless_retained = alerts_operator_needed(detail, sizeof(detail), NULL);
        nameless_retained &= strcmp(detail, "a\\0\xe2\x82\xac") == 0;
        alerts_operator_needed_clear();
        bool cleared = !alerts_operator_needed(NULL, 0, NULL);
        alerts_shutdown();
        ASSERT(refused); ASSERT(retained); ASSERT(unchanged);
        ASSERT(nameless_retained); ASSERT(cleared);
        PASS();
    } _test_next:;
    return failures;
}

static int test_operator_detail_capacity(void)
{
    int failures = 0;
    TEST("alerts: NUL expansion and retained UTF-8 capacity are validated") {
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        unsetenv("ZCL_ALERT_WEBHOOK_URL");
        alerts_init();
        unsigned char payload[ALERT_OPERATOR_NEEDED_DETAIL_LEN + 2];
        memset(payload, 'x', sizeof(payload));
        payload[0] = 0;
        const size_t lead = ALERT_OPERATOR_NEEDED_DETAIL_LEN - 3;
        payload[lead] = 0xe2; payload[lead + 1] = 0x82; payload[lead + 2] = 0xac;
        bool split = operator_detail_matches(payload, lead + 3,
            "(operator detail refused: invalid UTF-8)");
        memset(payload, 'x', sizeof(payload));
        payload[sizeof(payload) - 1] = 0xff;
        bool suffix = operator_detail_matches(payload, sizeof(payload),
            "(operator detail refused: invalid UTF-8)");
        memset(payload, 'x', sizeof(payload));
        char expected[ALERT_OPERATOR_NEEDED_DETAIL_LEN];
        memset(expected, 'x', sizeof(expected) - 1);
        expected[sizeof(expected) - 1] = '\0';
        bool bounded = operator_detail_matches(payload, sizeof(payload), expected);
        payload[0] = 0;
        const size_t fit = ALERT_OPERATOR_NEEDED_DETAIL_LEN - 5;
        payload[fit] = 0xe2; payload[fit + 1] = 0x82; payload[fit + 2] = 0xac;
        expected[0] = '\\'; expected[1] = '0';
        memcpy(expected + sizeof(expected) - 4, "\xe2\x82\xac", 3);
        bool exact = operator_detail_matches(payload, fit + 3, expected);
        alerts_shutdown();
        ASSERT(split); ASSERT(suffix); ASSERT(bounded); ASSERT(exact);
        PASS();
    } _test_next:;
    return failures;
}

static int test_operator_detail_small_outputs(void)
{
    int failures = 0;
    TEST("alerts: smaller detail outputs refuse split UTF-8") {
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        unsetenv("ZCL_ALERT_WEBHOOK_URL");
        alerts_init();
        unsigned char payload[ALERT_OPERATOR_NEEDED_DETAIL_LEN - 1];
        memset(payload, 'x', sizeof(payload));
        payload[sizeof(payload) - 2] = 0xc2;
        payload[sizeof(payload) - 1] = 0xa2;
        event_emit(EV_OPERATOR_NEEDED, 0, payload, sizeof(payload));
        char detail[256];
        bool active = alerts_operator_needed(detail, sizeof(detail), NULL);
        bool refused = strcmp(detail, "(operator detail refused: invalid UTF-8)") == 0;
        char tiny[2];
        const unsigned char recovery[] = "local_recovery_gate\xc2\xa2";
        event_emit(EV_OPERATOR_NEEDED, 0, recovery, sizeof(recovery) - 1);
        char recovered[sizeof(recovery) - 1];
        bool cleared = alerts_operator_needed_clear_if_chain_advance_recovered(
            true, recovered, sizeof(recovered), NULL);
        bool recovery_refused = strcmp(recovered, "(operator detail ref") == 0;
        event_emit(EV_OPERATOR_NEEDED, 0, "\xc2\xa2x", 3);
        bool tiny_active = alerts_operator_needed(tiny, sizeof(tiny), NULL);
        char untouched = 'z';
        bool zero_active = alerts_operator_needed(&untouched, 0, NULL);
        bool null_active = alerts_operator_needed(NULL, sizeof(detail), NULL);
        char one[1] = {'z'};
        bool one_active = alerts_operator_needed(one, sizeof(one), NULL);
        char complete[3];
        bool complete_active = alerts_operator_needed(complete, sizeof(complete), NULL);
        alerts_shutdown();
        ASSERT(active); ASSERT(refused); ASSERT(cleared);
        ASSERT(recovery_refused); ASSERT(tiny_active); ASSERT(strcmp(tiny, "(") == 0);
        ASSERT(zero_active); ASSERT(untouched == 'z'); ASSERT(null_active);
        ASSERT(one_active); ASSERT(one[0] == '\0'); ASSERT(complete_active);
        ASSERT(strcmp(complete, "\xc2\xa2") == 0);
        PASS();
    } _test_next:;
    return failures;
}

#if !defined(_WIN32)
static int operator_status_bind(char *dir, size_t dir_cap)
{
    /* AF_UNIX caps the bound path at sizeof(sun_path) (108): a deep checkout
     * path alone (a long lane name under test-tmp) pushes a test-tmp socket
     * directory past it, so the directory is short when it must be. */
    if (!test_mksockdir(dir, dir_cap, "a63c", sizeof("s") - 1)) return -1;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    int n = snprintf(address.sun_path, sizeof(address.sun_path), "%s/s", dir);
    if (n < 0 || (size_t)n >= sizeof(address.sun_path)) return -1;
    int fd = platform_socket_open(AF_UNIX, SOCK_DGRAM, 0, true, true);
    if (fd < 0) return -1;
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        setenv("NOTIFY_SOCKET", address.sun_path, 1) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool operator_status_matches(const unsigned char *payload, uint32_t len,
                                    const char *expected)
{
    char dir[PATH_MAX] = {0};
    sd_notify_reset_for_testing();
    int fd = operator_status_bind(dir, sizeof(dir));
    bool ok = false;
    if (fd >= 0 && sd_notify_init()) {
        event_emit(EV_OPERATOR_NEEDED, 0, payload, len);
        char message[512];
        ssize_t n = recv(fd, message, sizeof(message) - 1, 0);
        if (n >= 0) {
            message[n] = '\0';
            ok = strcmp(message, expected) == 0 && zutf8_validate_n(message, n);
        }
    }
    if (fd >= 0 && close(fd) != 0) ok = false;
    test_cleanup_tmpdir(dir);
    if (dir[0] && (access(dir, F_OK) == 0 || errno != ENOENT)) ok = false;
    if (unsetenv("NOTIFY_SOCKET") != 0) ok = false;
    sd_notify_reset_for_testing();
    if (!ok) fprintf(stderr, "alerts: status fixture or counted status mismatch\n");
    return ok;
}

static int test_operator_detail_status_capacity(void)
{
    int failures = 0;
    TEST("alerts: status capacity refuses split UTF-8 and retains valid text") {
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        unsetenv("ZCL_ALERT_WEBHOOK_URL");
        alerts_init();
        unsigned char payload[230];
        memset(payload, 'x', sizeof(payload));
        payload[228] = 0xc2; payload[229] = 0xa2;
        bool split = operator_status_matches(payload, sizeof(payload),
            "STATUS=DEGRADED operator_needed: (operator detail refused: invalid UTF-8)\n");
        bool valid = operator_status_matches((const unsigned char *)"\xc2\xa2", 2,
            "STATUS=DEGRADED operator_needed: \xc2\xa2\n");
        const unsigned char malformed[] = { 'a', 0, 0xff };
        bool refused = operator_status_matches(malformed, sizeof(malformed),
            "STATUS=DEGRADED operator_needed: (operator detail refused: invalid UTF-8)\n");
        alerts_shutdown();
        ASSERT(split); ASSERT(valid); ASSERT(refused);
        PASS();
    } _test_next:;
    return failures;
}
#endif

/* ── Entry point ─────────────────────────────────────────────── */

static int64_t alerts_fixed_clock(void *self)
{
    (void)self;
    return 1700000000000;
}

int test_alerts(void);

int test_alerts(void)
{
    int failures = 0;
    static const clock_iface_t fixed_clock = {
        .now_monotonic_ns = alerts_fixed_clock,
        .now_wall_ms = alerts_fixed_clock
    };
    const clock_iface_t *saved_clock = clock_default();
    clock_set_default(&fixed_clock);
    event_log_init();

    failures += test_seed_rules_registered();
    failures += test_disable_flag();
    failures += test_threshold_fires_at_count();
    failures += test_cooldown_suppresses_repeat();
    failures += test_multi_event_threshold();
    failures += test_add_custom_rule();
    failures += test_registration_refusal();
    failures += test_rule_name_boundary();
    failures += test_report_json_shape();
    failures += test_reset_clears_state();
    failures += test_rule_table_full();
    failures += test_operator_needed_latch();
    failures += test_operator_needed_counted_payload();
    failures += test_operator_detail_utf8();
    failures += test_operator_detail_capacity();
    failures += test_operator_detail_small_outputs();
#if !defined(_WIN32)
    failures += test_operator_detail_status_capacity();
#endif
    failures += test_operator_needed_payload_extent();
    failures += test_operator_needed_chain_advance_recovery_clear();

    alerts_shutdown();
    clock_set_default(saved_clock);
    return failures;
}
