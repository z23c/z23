/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for OpenTelemetry-compatible tracing (wave 10 #2).
 *
 * Strategy: exercise the span lifecycle, attributes, parent-child
 * linkage, TLS stack, enable/disable, and edge cases. */

#include "test/test_core.h"
#include "util/trace.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

/* ── 1. Basic span creation ─────────────────────────────────── */

static int test_span_creation(void)
{
    int failures = 0;
    TEST("trace: span creation and trace/span IDs") {
        trace_set_enabled(true);
        trace_reset_thread();
        struct trace_span *s = trace_start("test.basic");
        ASSERT(s != NULL);
        /* trace_id: 32 hex chars */
        ASSERT(strlen(s->trace_id) == 32);
        /* span_id: 16 hex chars */
        ASSERT(strlen(s->span_id) == 16);
        /* Root span has no parent */
        ASSERT(s->parent_span_id[0] == '\0');
        /* Operation set */
        ASSERT(strcmp(s->operation, "test.basic") == 0);
        trace_end(s);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2. Attributes ──────────────────────────────────────────── */

static int test_attributes(void)
{
    int failures = 0;
    TEST("trace: string and int attributes") {
        trace_set_enabled(true);
        trace_reset_thread();
        struct trace_span *s = trace_start("test.attrs");
        ASSERT(s != NULL);
        trace_attr_str(s, "command", "z23 status");
        trace_attr_int(s, "height", 123456);
        ASSERT(s->attr_count == 2);
        ASSERT(!s->attrs[0].is_int);
        ASSERT(strcmp(s->attrs[0].key, "command") == 0);
        ASSERT(strcmp(s->attrs[0].str_val, "z23 status") == 0);
        ASSERT(s->attrs[1].is_int);
        ASSERT(s->attrs[1].int_val == 123456);
        trace_end(s);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. Attribute overflow ──────────────────────────────────── */

static int test_attr_overflow(void)
{
    int failures = 0;
    TEST("trace: attributes capped at TRACE_MAX_ATTRS") {
        trace_set_enabled(true);
        trace_reset_thread();
        struct trace_span *s = trace_start("test.overflow");
        ASSERT(s != NULL);
        for (int i = 0; i < TRACE_MAX_ATTRS + 5; i++) {
            char key[32];
            snprintf(key, sizeof(key), "k%d", i);
            trace_attr_int(s, key, i);
        }
        ASSERT(s->attr_count == TRACE_MAX_ATTRS);
        trace_end(s);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. Parent-child linkage ────────────────────────────────── */

static int test_parent_child(void)
{
    int failures = 0;
    TEST("trace: child span inherits trace_id, sets parent_span_id") {
        trace_set_enabled(true);
        trace_reset_thread();
        struct trace_span *parent = trace_start("test.parent");
        ASSERT(parent != NULL);

        struct trace_span *child = trace_start("test.child");
        ASSERT(child != NULL);
        /* Same trace_id */
        ASSERT(strcmp(child->trace_id, parent->trace_id) == 0);
        /* parent_span_id == parent's span_id */
        ASSERT(strcmp(child->parent_span_id, parent->span_id) == 0);
        /* Different span_ids */
        ASSERT(strcmp(child->span_id, parent->span_id) != 0);

        trace_end(child);
        trace_end(parent);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5. trace_current and trace_current_id ──────────────────── */

static int test_current(void)
{
    int failures = 0;
    TEST("trace: trace_current returns top-of-stack span") {
        trace_set_enabled(true);
        trace_reset_thread();

        /* No span active */
        ASSERT(trace_current() == NULL);
        ASSERT(strlen(trace_current_id()) == 0);

        struct trace_span *s = trace_start("test.current");
        ASSERT(trace_current() == s);
        ASSERT(strlen(trace_current_id()) == 32);

        struct trace_span *inner = trace_start("test.inner");
        ASSERT(trace_current() == inner);

        trace_end(inner);
        ASSERT(trace_current() == s);

        trace_end(s);
        ASSERT(trace_current() == NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6. Disabled tracing ────────────────────────────────────── */

static int test_disabled(void)
{
    int failures = 0;
    TEST("trace: disabled tracing returns NULL, no crash") {
        trace_reset_thread();
        trace_set_enabled(false);
        struct trace_span *s = trace_start("test.disabled");
        ASSERT(s == NULL);
        /* These should be no-ops, no crash */
        trace_attr_str(s, "key", "val");
        trace_attr_int(s, "key", 42);
        trace_set_status(s, TRACE_STATUS_ERROR);
        trace_end(s);
        /* Stack should still be empty */
        ASSERT(trace_current() == NULL);
        trace_set_enabled(true);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 7. Status setting ──────────────────────────────────────── */

static int test_status(void)
{
    int failures = 0;
    TEST("trace: status defaults to UNSET, can be set to ERROR/OK") {
        trace_set_enabled(true);
        trace_reset_thread();
        struct trace_span *s = trace_start("test.status");
        ASSERT(s != NULL);
        ASSERT(s->status == TRACE_STATUS_UNSET);
        trace_set_status(s, TRACE_STATUS_ERROR);
        ASSERT(s->status == TRACE_STATUS_ERROR);
        /* trace_end will emit with ERROR status, not auto-OK */
        trace_end(s);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 8. Three-level nesting ─────────────────────────────────── */

static int test_deep_nesting(void)
{
    int failures = 0;
    TEST("trace: three-level nesting all share same trace_id") {
        trace_set_enabled(true);
        trace_reset_thread();
        struct trace_span *a = trace_start("level.1");
        struct trace_span *b = trace_start("level.2");
        struct trace_span *c = trace_start("level.3");
        ASSERT(a && b && c);
        /* All same trace_id */
        ASSERT(strcmp(a->trace_id, b->trace_id) == 0);
        ASSERT(strcmp(b->trace_id, c->trace_id) == 0);
        /* Correct parent chain */
        ASSERT(a->parent_span_id[0] == '\0');
        ASSERT(strcmp(b->parent_span_id, a->span_id) == 0);
        ASSERT(strcmp(c->parent_span_id, b->span_id) == 0);
        trace_end(c);
        trace_end(b);
        trace_end(a);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 9. NULL-safety ─────────────────────────────────────────── */

static int test_null_safety(void)
{
    int failures = 0;
    TEST("trace: NULL span/key/val are safe") {
        trace_set_enabled(true);
        trace_reset_thread();
        /* All should be no-ops */
        trace_attr_str(NULL, "k", "v");
        trace_attr_int(NULL, "k", 1);
        trace_set_status(NULL, TRACE_STATUS_OK);
        trace_end(NULL);

        /* NULL key */
        struct trace_span *s = trace_start("test.null");
        trace_attr_str(s, NULL, "v");
        trace_attr_int(s, NULL, 1);
        ASSERT(s->attr_count == 0);

        /* NULL value */
        trace_attr_str(s, "k", NULL);
        ASSERT(s->attr_count == 1);
        ASSERT(s->attrs[0].str_val[0] == '\0');

        trace_end(s);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 10. Reset thread clears stack ──────────────────────────── */

static int test_reset_thread(void)
{
    int failures = 0;
    TEST("trace: reset_thread clears the span stack") {
        trace_set_enabled(true);
        trace_reset_thread();
        struct trace_span *s = trace_start("test.reset");
        ASSERT(trace_current() == s);
        trace_reset_thread();
        ASSERT(trace_current() == NULL);
        /* The span was leaked — end it to prevent issues */
        trace_end(s);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ────────────────────────────────────────────── */

/* The id appears under `key` exactly as the typed literal `id` (the test
 * pins the span's ids to literals; it never compares the writer to the
 * struct value it was fed).  OTLP/JSON carries hex, not base64. */
#define OTLP_T_ID "0123456789abcdef0123456789abcdef"
#define OTLP_P_ID "fedcba9876543210"
#define OTLP_C_ID "0011223344556677"

static bool otlp_field_is(const char *body, const char *key, const char *id)
{
    char want[96];
    snprintf(want, sizeof(want), "\"%s\":\"%s\"", key, id);
    return strstr(body, want) != NULL;
}

static int test_otlp_json(void)
{
    int failures = 0;
    TEST("trace: ended span renders one OTLP JSON export") {
        char body[4096];
        char root_body[4096];
        char start_nano[64];
        char end_nano[64];
        uint64_t end_us;
        trace_set_enabled(true);
        trace_reset_thread();
        struct trace_span *parent = trace_start("otlp.parent");
        struct trace_span *child = trace_start("say\"hi");
        ASSERT(parent != NULL);
        ASSERT(child != NULL);
        /* Pin the ids to typed literals so the expectations below are
         * independent of the generator. */
        snprintf(parent->trace_id, sizeof(parent->trace_id), "%s", OTLP_T_ID);
        snprintf(parent->span_id, sizeof(parent->span_id), "%s", OTLP_P_ID);
        snprintf(child->trace_id, sizeof(child->trace_id), "%s", OTLP_T_ID);
        snprintf(child->span_id, sizeof(child->span_id), "%s", OTLP_C_ID);
        snprintf(child->parent_span_id, sizeof(child->parent_span_id), "%s",
                 OTLP_P_ID);
        trace_attr_str(child, "command", "z23 status");
        trace_attr_int(child, "height", 123456);
        trace_set_status(child, TRACE_STATUS_ERROR);
        end_us = child->start_wall_us + 2500;
        ASSERT(trace_format_otlp(child, end_us, body, sizeof(body)));
        ASSERT(strstr(body, "\"resourceSpans\"") != NULL);
        ASSERT(otlp_field_is(body, "traceId", OTLP_T_ID));
        ASSERT(otlp_field_is(body, "spanId", OTLP_C_ID));
        ASSERT(otlp_field_is(body, "parentSpanId", OTLP_P_ID));
        ASSERT(strstr(body, "\"name\":\"say\\\"hi\"") != NULL);
        /* OTLP JSON enums are integers (spec, "JSON Protobuf Encoding"): ERROR is 2. */
        ASSERT(strstr(body, "\"status\":{\"code\":2}") != NULL);
        ASSERT(strstr(body, "\"stringValue\":\"z23 status\"") != NULL);
        ASSERT(strstr(body, "\"intValue\":\"123456\"") != NULL);
        snprintf(start_nano, sizeof(start_nano),
                 "\"startTimeUnixNano\":\"%llu\"",
                 (unsigned long long)(child->start_wall_us * 1000ull));
        snprintf(end_nano, sizeof(end_nano),
                 "\"endTimeUnixNano\":\"%llu\"",
                 (unsigned long long)(end_us * 1000ull));
        ASSERT(strstr(body, start_nano) != NULL);
        ASSERT(strstr(body, end_nano) != NULL);
        ASSERT(trace_format_otlp(parent, parent->start_wall_us, root_body,
                                 sizeof(root_body)));
        ASSERT(strstr(root_body, "parentSpanId") == NULL);
        trace_end(child);
        trace_end(parent);
        PASS();
    } _test_next:;
    return failures;
}

#define LOG_HEAD \
    "{\"resourceLogs\":[{\"resource\":{\"attributes\":[{\"key\":" \
    "\"service.name\",\"value\":{\"stringValue\":\""
#define LOG_MID \
    "\"}}]},\"scopeLogs\":[{\"scope\":{\"name\":\"z23\"},\"logRecords\":" \
    "[{\"timeUnixNano\":\""
#define LOG_TAIL "}]}]}]}"

static int test_otlp_log(void)
{
    int failures = 0;
    TEST("trace: OTLP log record known answers and refusals") {
        static const char exp1[] =
            LOG_HEAD "z23" LOG_MID "1000\",\"severityNumber\":9,"
            "\"severityText\":\"INFO\",\"body\":{\"stringValue\":\"hi\"},"
            "\"attributes\":[]" LOG_TAIL;
        static const char exp2[] =
            LOG_HEAD "node" LOG_MID "1700000000123456000\","
            "\"severityNumber\":17,\"severityText\":\"ERROR\","
            "\"body\":{\"stringValue\":\"bad block\"},\"attributes\":["
            "{\"key\":\"height\",\"value\":{\"stringValue\":\"42\"}},"
            "{\"key\":\"peer\",\"value\":{\"stringValue\":\"\"}}],"
            "\"traceId\":\"000102030405060708090a0b0c0d0e0f\","
            "\"spanId\":\"1011121314151617\"" LOG_TAIL;
        static const char exp3[] =
            LOG_HEAD "s\\\"v" LOG_MID "5000\",\"severityNumber\":21,"
            "\"severityText\":\"FATAL\",\"body\":{\"stringValue\":"
            "\"a\\\"b\\\\c\\nd\\u0001e\"},\"attributes\":["
            "{\"key\":\"k\\\"\\\\\",\"value\":{\"stringValue\":"
            "\"v\\n\\u001f\"}}]" LOG_TAIL;
        static const char exp4[] =
            LOG_HEAD "z23" LOG_MID "7000\",\"severityNumber\":1,"
            "\"severityText\":\"TRACE\",\"body\":{\"stringValue\":\"\"},"
            "\"attributes\":[],\"spanId\":\"1011121314151617\"" LOG_TAIL;
        char out[2048];
        struct trace_log_record r = {
            .wall_us = 1, .severity = TRACE_LOG_INFO, .body = "hi",
            .service = "z23",
        };
        size_t len;
        ASSERT(trace_format_otlp_log(&r, out, sizeof(out)));
        ASSERT(strcmp(out, exp1) == 0);

        struct trace_log_record r2 = {
            .wall_us = 1700000000123456ull, .severity = TRACE_LOG_ERROR,
            .body = "bad block",
            .trace_id = "000102030405060708090a0b0c0d0e0f",
            .span_id = "1011121314151617", .service = "node",
            .attrs = { { "height", "42" }, { "peer", "" } },
            .attr_count = 2,
        };
        ASSERT(trace_format_otlp_log(&r2, out, sizeof(out)));
        ASSERT(strcmp(out, exp2) == 0);

        struct trace_log_record r3 = {
            .wall_us = 5, .severity = TRACE_LOG_FATAL,
            .body = "a\"b\\c\nd\x01" "e", .service = "s\"v",
            .attrs = { { "k\"\\", "v\n\x1f" } }, .attr_count = 1,
        };
        ASSERT(trace_format_otlp_log(&r3, out, sizeof(out)));
        ASSERT(strcmp(out, exp3) == 0);

        struct trace_log_record r4 = {
            .wall_us = 7, .severity = TRACE_LOG_TRACE, .body = "",
            .span_id = "1011121314151617", .trace_id = "", .service = "z23",
        };
        ASSERT(trace_format_otlp_log(&r4, out, sizeof(out)));
        ASSERT(strcmp(out, exp4) == 0);

        /* Exact fit succeeds, one byte short refuses and stays in bounds. */
        len = strlen(exp2);
        memset(out, 0x5a, sizeof(out));
        ASSERT(trace_format_otlp_log(&r2, out, len + 1));
        ASSERT(strcmp(out, exp2) == 0);
        for (size_t i = len + 1; i < sizeof(out); i++) ASSERT(out[i] == 0x5a);
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&r2, out, len));
        ASSERT(out[0] == '\0');
        for (size_t i = len; i < sizeof(out); i++) ASSERT(out[i] == 0x5a);
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&r2, out, 0));
        for (size_t i = 0; i < sizeof(out); i++) ASSERT(out[i] == 0x5a);
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&r2, out, 1));
        ASSERT(out[0] == '\0');
        for (size_t i = 1; i < sizeof(out); i++) ASSERT(out[i] == 0x5a);

        /* NULL arguments. */
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(NULL, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        ASSERT(!trace_format_otlp_log(&r, NULL, sizeof(out)));
        struct trace_log_record bad = r;
        bad.body = NULL;
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&bad, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        bad = r;
        bad.service = NULL;
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&bad, out, sizeof(out)));
        ASSERT(out[0] == '\0');

        /* Malformed ids. */
        bad = r;
        bad.trace_id = "000102030405060708090a0b0c0d0e";
        ASSERT(!trace_format_otlp_log(&bad, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        bad.trace_id = "000102030405060708090a0b0c0d0e0g";
        ASSERT(!trace_format_otlp_log(&bad, out, sizeof(out)));
        bad = r;
        bad.span_id = "10111213 4151617";
        ASSERT(!trace_format_otlp_log(&bad, out, sizeof(out)));
        bad.span_id = "101112131415161718";
        ASSERT(!trace_format_otlp_log(&bad, out, sizeof(out)));

        /* Too many attributes. */
        bad = r;
        bad.attr_count = TRACE_LOG_MAX_ATTRS + 1;
        ASSERT(!trace_format_otlp_log(&bad, out, sizeof(out)));
        bad.attr_count = -1;
        ASSERT(!trace_format_otlp_log(&bad, out, sizeof(out)));
        PASS();
    } _test_next:;
    return failures;
}

/* Held-out checks derived from the trace.h header contract alone. */
static const char *held_sev_text(int n)
{
    switch (n) {
    case 1: return "TRACE";
    case 5: return "DEBUG";
    case 9: return "INFO";
    case 13: return "WARN";
    case 17: return "ERROR";
    case 21: return "FATAL";
    default: return NULL;
    }
}

static int test_otlp_log_held(void)
{
    int failures = 0;
    TEST("trace: OTLP log header rules (held-out)") {
        static char out[16384];
        static char exp[16384];
        static char big[3001];
        struct trace_log_record base = {
            .wall_us = 1, .severity = TRACE_LOG_INFO, .body = "b",
            .service = "z23",
        };
        struct trace_log_record t;
        static const int sevs[] = { 1, 5, 9, 13, 17, 21 };

        /* Every valid severity number and text. */
        for (size_t i = 0; i < sizeof(sevs) / sizeof(sevs[0]); i++) {
            t = base;
            t.severity = (enum trace_log_severity)sevs[i];
            snprintf(exp, sizeof(exp),
                     LOG_HEAD "z23" LOG_MID "1000\",\"severityNumber\":%d,"
                     "\"severityText\":\"%s\",\"body\":{\"stringValue\":"
                     "\"b\"},\"attributes\":[]" LOG_TAIL,
                     sevs[i], held_sev_text(sevs[i]));
            ASSERT(trace_format_otlp_log(&t, out, sizeof(out)));
            ASSERT(strcmp(out, exp) == 0);
        }

        /* Invalid severities refuse and leave an empty string. */
        static const int badsev[] = { 0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20,
                                      22, 24, 100, -1 };
        for (size_t i = 0; i < sizeof(badsev) / sizeof(badsev[0]); i++) {
            t = base;
            t.severity = (enum trace_log_severity)badsev[i];
            memset(out, 0x5a, sizeof(out));
            ASSERT(!trace_format_otlp_log(&t, out, sizeof(out)));
            ASSERT(out[0] == '\0');
        }

        /* wall_us overflow boundary: UINT64_MAX/1000 = 18446744073709551. */
        t = base;
        t.wall_us = 18446744073709551ull;
        ASSERT(trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(strstr(out, "\"timeUnixNano\":\"18446744073709551000\",") !=
               NULL);
        t.wall_us = 18446744073709552ull;
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        t.wall_us = UINT64_MAX;
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        t.wall_us = 0;
        ASSERT(trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(strstr(out, "\"timeUnixNano\":\"0\",") != NULL);

        /* Empty service, NULL body, empty key, NULL value, bad counts. */
        t = base; t.service = "";
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        t = base; t.service = NULL;
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        t = base; t.body = NULL;
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        t = base; t.attrs[0].key = ""; t.attrs[0].val = "v"; t.attr_count = 1;
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        t = base; t.attrs[0].key = NULL; t.attrs[0].val = "v";
        t.attr_count = 1;
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        t = base; t.attrs[0].key = "k"; t.attrs[0].val = NULL;
        t.attr_count = 1;
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        /* An invalid entry beyond attr_count is not examined. */
        t = base; t.attrs[0].key = "k"; t.attrs[0].val = "v";
        t.attrs[1].key = ""; t.attrs[1].val = NULL; t.attr_count = 1;
        ASSERT(trace_format_otlp_log(&t, out, sizeof(out)));
        t = base; t.attr_count = -1;
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        t = base; t.attr_count = INT_MIN;
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        t = base; t.attr_count = TRACE_LOG_MAX_ATTRS + 1;
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(out[0] == '\0');

        /* Exactly the maximum attribute count, in array order. */
        ASSERT(TRACE_LOG_MAX_ATTRS == 4);
        t = base;
        t.attrs[0] = (struct trace_log_attr){ "a", "1" };
        t.attrs[1] = (struct trace_log_attr){ "b", "" };
        t.attrs[2] = (struct trace_log_attr){ "c", "3" };
        t.attrs[3] = (struct trace_log_attr){ "d", "4" };
        t.attr_count = 4;
        snprintf(exp, sizeof(exp),
                 LOG_HEAD "z23" LOG_MID "1000\",\"severityNumber\":9,"
                 "\"severityText\":\"INFO\",\"body\":{\"stringValue\":"
                 "\"b\"},\"attributes\":["
                 "{\"key\":\"a\",\"value\":{\"stringValue\":\"1\"}},"
                 "{\"key\":\"b\",\"value\":{\"stringValue\":\"\"}},"
                 "{\"key\":\"c\",\"value\":{\"stringValue\":\"3\"}},"
                 "{\"key\":\"d\",\"value\":{\"stringValue\":\"4\"}}]"
                 LOG_TAIL);
        ASSERT(trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(strcmp(out, exp) == 0);

        /* Upper-case and mixed-case hex ids give the same bytes. */
        t = base;
        t.trace_id = "000102030405060708090A0B0C0D0E0F";
        t.span_id = "ABCDEF0123456789";
        snprintf(exp, sizeof(exp),
                 LOG_HEAD "z23" LOG_MID "1000\",\"severityNumber\":9,"
                 "\"severityText\":\"INFO\",\"body\":{\"stringValue\":"
                 "\"b\"},\"attributes\":[],"
                 "\"traceId\":\"000102030405060708090a0b0c0d0e0f\","
                 "\"spanId\":\"abcdef0123456789\"" LOG_TAIL);
        ASSERT(trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(strcmp(out, exp) == 0);
        t.trace_id = "000102030405060708090a0B0c0D0e0F";
        t.span_id = "abcdef0123456789";
        ASSERT(trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(strcmp(out, exp) == 0);
        /* traceId alone, then spanId alone. */
        t = base; t.trace_id = "000102030405060708090a0b0c0d0e0f";
        ASSERT(trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(strstr(out, "\"attributes\":[],\"traceId\":"
                           "\"000102030405060708090a0b0c0d0e0f\"" LOG_TAIL) != NULL);
        ASSERT(strstr(out, "spanId") == NULL);
        /* Prefix and extra-length ids refuse. */
        t = base; t.span_id = "0x10111213141516";
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        t = base; t.trace_id = "000102030405060708090a0b0c0d0e0f0";
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        t = base; t.span_id = "1011121314151";
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(out[0] == '\0');

        /* Every escape class: bytes 0x01..0x1f, then quote and backslash,
         * then 0x7f and high bytes unchanged. */
        {
            char ctl[32 + 16];
            size_t n = 0;
            for (int c = 1; c < 0x20; c++) ctl[n++] = (char)c;
            ctl[n++] = '"'; ctl[n++] = '\\';
            ctl[n++] = 0x7f; ctl[n++] = (char)0x80; ctl[n++] = (char)0xc3;
            ctl[n++] = (char)0xa9; ctl[n++] = (char)0xff;
            ctl[n] = '\0';
            t = base; t.body = ctl;
            snprintf(exp, sizeof(exp),
                     LOG_HEAD "z23" LOG_MID "1000\",\"severityNumber\":9,"
                     "\"severityText\":\"INFO\",\"body\":{\"stringValue\":"
                     "\"\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007"
                     "\\b\\t\\n\\u000b\\f\\r\\u000e\\u000f"
                     "\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016"
                     "\\u0017\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d"
                     "\\u001e\\u001f\\\"\\\\\x7f\x80\xc3\xa9\xff\"},"
                     "\"attributes\":[]" LOG_TAIL);
            ASSERT(trace_format_otlp_log(&t, out, sizeof(out)));
            ASSERT(strcmp(out, exp) == 0);
        }
        /* Escaping applies to service, keys and values alike. */
        t = base; t.service = "\t\x02\x7f";
        t.attrs[0] = (struct trace_log_attr){ "\r\x1e", "\xe2\x82\xac\f" };
        t.attr_count = 1;
        snprintf(exp, sizeof(exp),
                 LOG_HEAD "\\t\\u0002\x7f" LOG_MID "1000\","
                 "\"severityNumber\":9,\"severityText\":\"INFO\","
                 "\"body\":{\"stringValue\":\"b\"},\"attributes\":["
                 "{\"key\":\"\\r\\u001e\",\"value\":{\"stringValue\":"
                 "\"\xe2\x82\xac\\f\"}}]" LOG_TAIL);
        ASSERT(trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(strcmp(out, exp) == 0);

        /* Over-long body: fits a large buffer, refuses a small one. */
        memset(big, 'x', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        t = base; t.body = big;
        snprintf(exp, sizeof(exp),
                 LOG_HEAD "z23" LOG_MID "1000\",\"severityNumber\":9,"
                 "\"severityText\":\"INFO\",\"body\":{\"stringValue\":"
                 "\"%s\"},\"attributes\":[]" LOG_TAIL, big);
        ASSERT(trace_format_otlp_log(&t, out, sizeof(out)));
        ASSERT(strcmp(out, exp) == 0);
        size_t len = strlen(exp);
        ASSERT(len > 3000);
        memset(out, 0x5a, sizeof(out));
        ASSERT(trace_format_otlp_log(&t, out, len + 1));
        ASSERT(strcmp(out, exp) == 0);
        ASSERT(out[len + 1] == 0x5a);
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&t, out, len));
        ASSERT(out[0] == '\0');
        ASSERT(out[len] == 0x5a);
        memset(out, 0x5a, sizeof(out));
        ASSERT(!trace_format_otlp_log(&t, out, 2048));
        ASSERT(out[0] == '\0');
        ASSERT(out[2048] == 0x5a);
        /* Escaped expansion counts toward cap: 1000 x 0x01 -> 6000 bytes. */
        {
            static char ctl[1001];
            size_t baselen;
            memset(ctl, 0x01, 1000);
            ctl[1000] = '\0';
            ASSERT(trace_format_otlp_log(&base, out, sizeof(out)));
            baselen = strlen(out);
            t = base; t.body = ctl;
            memset(out, 0x5a, sizeof(out));
            ASSERT(!trace_format_otlp_log(&t, out, 5000));
            ASSERT(out[0] == '\0');
            ASSERT(trace_format_otlp_log(&t, out, sizeof(out)));
            ASSERT(strlen(out) == baselen + 5999);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* ── OTLP/JSON identifiers are hex, not base64 ──────────────────
 * Expected strings below are typed from the OpenTelemetry Protocol
 * specification, section "JSON Protobuf Encoding": traceId and spanId are
 * case-insensitive hex strings (16 bytes = 32 hex digits, 8 bytes = 16),
 * with the specification's own example
 *   {"traceId": "5B8EFFF798038103D269B633813FC60C",
 *    "spanId": "EEE19B7EC3C1B174"}
 * Our writers accept either case and emit lowercase. */

#define SPEC_TRACE_ID "5B8EFFF798038103D269B633813FC60C"
#define SPEC_SPAN_ID  "EEE19B7EC3C1B174"

static const char *const g_bad_trace_ids[] = {
    "5b8efff798038103d269b633813fc60",     /* 31 digits */
    "5b8efff798038103d269b633813fc60c0",   /* 33 digits */
    "5b8efff798038103d269b633813fc6zz",    /* 32 chars, non-hex */
    "AAECAwQFBgcICQoLDA0ODw==",            /* old base64 form, 24 chars */
    "AAECAwQFBgcICQoLDA0ODwAAAAAAAAAA",    /* base64-looking, 32 chars */
    "00000000000000000000000000000000",    /* all-zero trace id */
};

static const char *const g_bad_span_ids[] = {
    "eee19b7ec3c1b17",                     /* 15 digits */
    "eee19b7ec3c1b1740",                   /* 17 digits */
    "eee19b7ec3c1b17g",                    /* 16 chars, non-hex */
    "EBESExQVFhc=",                        /* old base64 form, 12 chars */
    "EBESExQVFhcAAAA=",                    /* base64-looking, 16 chars */
    "0000000000000000",                    /* all-zero span id */
};

#define N_BAD(a) (sizeof(a) / sizeof((a)[0]))

static int test_otlp_log_hex_spec(void)
{
    int failures = 0;
    TEST("trace: OTLP log ids are lowercase hex (spec example vector)") {
        static const char expect[] =
            LOG_HEAD "z23" LOG_MID "1000\",\"severityNumber\":9,"
            "\"severityText\":\"INFO\",\"body\":{\"stringValue\":\"hi\"},"
            "\"attributes\":[],"
            "\"traceId\":\"5b8efff798038103d269b633813fc60c\","
            "\"spanId\":\"eee19b7ec3c1b174\"" LOG_TAIL;
        struct trace_log_record r = {
            .wall_us = 1, .severity = TRACE_LOG_INFO, .body = "hi",
            .service = "z23",
            .trace_id = SPEC_TRACE_ID, .span_id = SPEC_SPAN_ID,
        };
        char out[2048];
        ASSERT(trace_format_otlp_log(&r, out, sizeof(out)));
        ASSERT(strcmp(out, expect) == 0);
        r.trace_id = "5b8efff798038103d269b633813fc60c";
        r.span_id = "eee19b7ec3c1b174";
        ASSERT(trace_format_otlp_log(&r, out, sizeof(out)));
        ASSERT(strcmp(out, expect) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_otlp_log_hex_refusals(void)
{
    int failures = 0;
    TEST("trace: OTLP log refuses wrong-length, non-hex and base64 ids") {
        char out[2048];
        struct trace_log_record r = {
            .wall_us = 1, .severity = TRACE_LOG_INFO, .body = "hi",
            .service = "z23",
        };
        for (size_t i = 0; i < N_BAD(g_bad_trace_ids); i++) {
            r.trace_id = g_bad_trace_ids[i];
            r.span_id = NULL;
            memset(out, 0x5a, sizeof(out));
            ASSERT(!trace_format_otlp_log(&r, out, sizeof(out)));
            ASSERT(out[0] == '\0');
        }
        for (size_t i = 0; i < N_BAD(g_bad_span_ids); i++) {
            r.trace_id = NULL;
            r.span_id = g_bad_span_ids[i];
            memset(out, 0x5a, sizeof(out));
            ASSERT(!trace_format_otlp_log(&r, out, sizeof(out)));
            ASSERT(out[0] == '\0');
        }
        PASS();
    } _test_next:;
    return failures;
}

static void span_with_ids(struct trace_span *s, const char *trace,
                          const char *span, const char *parent)
{
    memset(s, 0, sizeof(*s));
    snprintf(s->trace_id, sizeof(s->trace_id), "%s", trace);
    snprintf(s->span_id, sizeof(s->span_id), "%s", span);
    snprintf(s->parent_span_id, sizeof(s->parent_span_id), "%s", parent);
    snprintf(s->operation, sizeof(s->operation), "op");
    s->start_wall_us = 1;
}

static int test_otlp_span_hex_spec(void)
{
    int failures = 0;
    TEST("trace: OTLP span ids are lowercase hex (spec example vector)") {
        static const char root[] =
            "{\"resourceSpans\":[{\"scopeSpans\":[{\"scope\":{\"name\":"
            "\"z23\"},\"spans\":[{\"traceId\":"
            "\"5b8efff798038103d269b633813fc60c\",\"spanId\":"
            "\"eee19b7ec3c1b174\",\"name\":\"op\",\"startTimeUnixNano\":"
            "\"1000\",\"endTimeUnixNano\":\"3000\",\"attributes\":[],"
            "\"status\":{\"code\":0}}]}]}]}";
        static const char child[] =
            "{\"resourceSpans\":[{\"scopeSpans\":[{\"scope\":{\"name\":"
            "\"z23\"},\"spans\":[{\"traceId\":"
            "\"5b8efff798038103d269b633813fc60c\",\"spanId\":"
            "\"1011121314151617\",\"parentSpanId\":\"eee19b7ec3c1b174\","
            "\"name\":\"op\",\"startTimeUnixNano\":\"1000\","
            "\"endTimeUnixNano\":\"3000\",\"attributes\":[],"
            "\"status\":{\"code\":0}}]}]}]}";
        struct trace_span s;
        char out[2048];
        span_with_ids(&s, SPEC_TRACE_ID, SPEC_SPAN_ID, "");
        ASSERT(trace_format_otlp(&s, 3, out, sizeof(out)));
        ASSERT(strcmp(out, root) == 0);
        span_with_ids(&s, SPEC_TRACE_ID, "1011121314151617", SPEC_SPAN_ID);
        ASSERT(trace_format_otlp(&s, 3, out, sizeof(out)));
        ASSERT(strcmp(out, child) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* The span writer takes ids by fixed-size array: struct trace_span holds at
 * most 32 / 16 id characters, so an over-long id is truncated into the array
 * before the writer sees it and cannot be presented to it.  Those
 * unrepresentable rows are exercised on the log writer (which takes the ids
 * by pointer) above, not here.  Every row below reaches the span writer. */
static bool span_refused(const char *trace, const char *span,
                         const char *parent)
{
    struct trace_span s;
    char out[2048];
    span_with_ids(&s, trace, span, parent);
    return !trace_format_otlp(&s, 3, out, sizeof(out));
}

static const char *const g_span_bad_traces[] = {
    "",                                    /* empty */
    "5b8efff798038103d269b633813fc60",     /* 31 digits */
    "5b8efff798038103d269b633813fc6zz",    /* 32 chars, non-hex */
    "AAECAwQFBgcICQoLDA0ODw==",            /* old base64 form, 24 chars */
    "AAECAwQFBgcICQoLDA0ODwAAAAAAAAAA",    /* base64-looking, 32 chars */
    "00000000000000000000000000000000",    /* all-zero trace id */
};

static const char *const g_span_bad_ids[] = {
    "",                                    /* empty */
    "eee19b7ec3c1b17",                     /* 15 digits */
    "eee19b7ec3c1b17g",                    /* 16 chars, one non-hex */
    "EBESExQVFhc=",                        /* old base64 form, 12 chars */
    "EBESExQVFhcAAAA=",                    /* base64-looking, 16 chars */
    "0000000000000000",                    /* all-zero span id, and (below) all-zero parent id */
};

static int test_otlp_span_hex_refusals(void)
{
    int failures = 0;
    TEST("trace: OTLP span refuses empty, short, non-hex and base64 ids") {
        char out[2048];
        struct trace_span s;
        for (size_t i = 0; i < N_BAD(g_span_bad_traces); i++)
            ASSERT(span_refused(g_span_bad_traces[i], "eee19b7ec3c1b174", ""));
        for (size_t i = 0; i < N_BAD(g_span_bad_ids); i++) {
            ASSERT(span_refused(SPEC_TRACE_ID, g_span_bad_ids[i], ""));
            /* A parent id that is present must be valid; the empty row
             * is the root-span case, accepted below, so start at 1. */
            if (g_span_bad_ids[i][0] != '\0')
                ASSERT(span_refused(SPEC_TRACE_ID, "eee19b7ec3c1b174",
                                    g_span_bad_ids[i]));
        }
        ASSERT(!span_refused(SPEC_TRACE_ID, SPEC_SPAN_ID, ""));
        /* Empty parent id: accepted, and parentSpanId is omitted. */
        span_with_ids(&s, SPEC_TRACE_ID, SPEC_SPAN_ID, "");
        ASSERT(trace_format_otlp(&s, 3, out, sizeof(out)));
        ASSERT(strstr(out, "parentSpanId") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

#ifndef _WIN32
/* ── ZCL_OTLP_LOGS at process start ─────────────────────────── */

/* This test exists to exercise the process-start constructor in trace.c:
 * the mirror is installed before main() only when ZCL_OTLP_LOGS is "1".  A
 * unit test in this process cannot see that (the switch is resolved once
 * and the hook is reset by the test helper), so it execs a probe that links
 * the real trace.c and log_json.c, emits one log_jsonf event
 * (otlp_startup_probe) and exits 0.  log_jsonf writes its line through
 * LogPrintStr, which writes to stderr, so stderr is the stream captured.
 * The environment is built by env(1) (no shell, this process's environment
 * is never modified): "-u" removes the variable, "NAME=value" sets it. */
#define OTLP_PROBE_BIN "build/fixtures/otlp_startup_probe"
#define OTLP_PROBE_DEADLINE_MS 10000

/* Count lines of `text` containing `needle`. */
static int otlp_count_lines(const char *text, const char *needle)
{
    int count = 0;
    const char *line = text;
    while (*line != '\0') {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        char copy[4096];
        if (len >= sizeof(copy)) len = sizeof(copy) - 1;
        memcpy(copy, line, len);
        copy[len] = '\0';
        if (strstr(copy, needle) != NULL) count++;
        if (!nl) break;
        line = nl + 1;
    }
    return count;
}

/* Run the probe with the switch unset (setting NULL) or set to `setting`;
 * false when the probe is missing, cannot be run, times out or does not
 * exit 0.  `out` receives the merged stdout and stderr. */
static bool otlp_run_probe(const char *setting, char *out, size_t cap)
{
    bool timed_out = false;
    const char *unset_argv[] = { "/usr/bin/env", "-u", "ZCL_OTLP_LOGS",
                                 OTLP_PROBE_BIN, NULL };
    char assign[32];
    const char *set_argv[] = { "/usr/bin/env", assign, OTLP_PROBE_BIN, NULL };
    int rc;
    if (access(OTLP_PROBE_BIN, X_OK) != 0) return false;
    if (setting) snprintf(assign, sizeof(assign), "ZCL_OTLP_LOGS=%s", setting);
    rc = zcl_spawn_capture_merged_observed(setting ? set_argv : unset_argv,
                                           out, cap, OTLP_PROBE_DEADLINE_MS,
                                           &timed_out);
    return rc == 0 && !timed_out;
}

static int test_otlp_logs_startup(void)
{
    int failures = 0;
    TEST("trace: ZCL_OTLP_LOGS gates the mirror at process start") {
        static const char *const settings[] = { NULL, "0", "1" };
        for (size_t i = 0; i < 3; i++) {
            char out[8192];
            int want_logs = settings[i] && strcmp(settings[i], "1") == 0;
            ASSERT(otlp_run_probe(settings[i], out, sizeof(out)));
            ASSERT(otlp_count_lines(out, "\"event\":\"otlp_startup_probe\"")
                   == 1);
            ASSERT(otlp_count_lines(out, "\"event\":\"otlp_logs\"")
                   == want_logs);
            /* The hook is in place before main() only when the switch is
             * on; the log call itself is not what installed it. */
            ASSERT(otlp_count_lines(out, want_logs ? "mirror_installed=1"
                                                   : "mirror_installed=0")
                   == 1);
            if (want_logs)
                ASSERT(otlp_count_lines(out,
                    "\"body\":{\"stringValue\":\"otlp_startup_probe\"}") == 1);
        }
        PASS();
    } _test_next:;
    return failures;
}
#endif

int test_trace(void);

int test_trace(void)
{
    int failures = 0;
    failures += test_otlp_log();
    failures += test_otlp_log_held();
    failures += test_otlp_json();
    failures += test_otlp_log_hex_spec();
    failures += test_otlp_log_hex_refusals();
    failures += test_otlp_span_hex_spec();
    failures += test_otlp_span_hex_refusals();
#ifndef _WIN32
    failures += test_otlp_logs_startup();
#endif
    failures += test_span_creation();
    failures += test_attributes();
    failures += test_attr_overflow();
    failures += test_parent_child();
    failures += test_current();
    failures += test_disabled();
    failures += test_status();
    failures += test_deep_nesting();
    failures += test_null_safety();
    failures += test_reset_thread();
    return failures;
}
