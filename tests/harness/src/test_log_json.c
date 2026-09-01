/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the structured JSON log helper.  We never call the live
 * log_jsonf() (which would write into debug.log / stdout) — instead
 * we use log_json_format() which renders into a caller-supplied
 * buffer, which is what the unit tests need anyway. */

#include "test/test_core.h"
#include "util/log_json.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

static bool contains(const char *hay, const char *needle)
{
    return hay && needle && strstr(hay, needle) != NULL;
}

static int test_envelope_shape(void)
{
    int failures = 0;
    TEST("log_json: envelope has ts/level/event always") {
        char buf[1024];
        size_t n = log_json_format(buf, sizeof(buf), LOG_JSON_INFO,
                                    "boot_complete", NULL);
        ASSERT(n > 0);
        ASSERT(contains(buf, "\"ts\":\""));
        ASSERT(contains(buf, "\"level\":\"info\""));
        ASSERT(contains(buf, "\"event\":\"boot_complete\""));
        /* Single-line + trailing newline */
        ASSERT(buf[n - 1] == '\n');
        /* Exactly one newline */
        const char *first_nl = strchr(buf, '\n');
        ASSERT(first_nl == buf + n - 1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_levels(void)
{
    int failures = 0;
    TEST("log_json: levels render as info/warn/error") {
        char buf[256];
        log_json_format(buf, sizeof(buf), LOG_JSON_WARN,  "x", NULL);
        ASSERT(contains(buf, "\"level\":\"warn\""));
        log_json_format(buf, sizeof(buf), LOG_JSON_ERROR, "x", NULL);
        ASSERT(contains(buf, "\"level\":\"error\""));
        log_json_format(buf, sizeof(buf), LOG_JSON_INFO,  "x", NULL);
        ASSERT(contains(buf, "\"level\":\"info\""));
        PASS();
    } _test_next:;
    return failures;
}

static int test_fields_inserted(void)
{
    int failures = 0;
    TEST("log_json: caller-supplied fields appear after event") {
        char buf[1024];
        log_json_format(buf, sizeof(buf), LOG_JSON_INFO,
                         "peer_connected",
                         "\"peer_id\":%d,\"addr\":\"%s\"",
                         42, "1.2.3.4:8033");
        ASSERT(contains(buf, "\"event\":\"peer_connected\","));
        ASSERT(contains(buf, "\"peer_id\":42"));
        ASSERT(contains(buf, "\"addr\":\"1.2.3.4:8033\""));
        PASS();
    } _test_next:;
    return failures;
}

static int test_no_fields_no_trailing_comma(void)
{
    int failures = 0;
    TEST("log_json: NULL fields produces a clean object (no trailing comma)") {
        char buf[256];
        log_json_format(buf, sizeof(buf), LOG_JSON_INFO, "ping", NULL);
        ASSERT(contains(buf, "\"event\":\"ping\"}\n"));
        ASSERT(!contains(buf, ",}"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_escape_quotes_and_backslash(void)
{
    int failures = 0;
    TEST("log_json: escape handles quotes and backslashes") {
        char out[64];
        log_json_escape(out, sizeof(out), "he said \"hi\"");
        ASSERT(strcmp(out, "he said \\\"hi\\\"") == 0);

        log_json_escape(out, sizeof(out), "C:\\Users\\me");
        ASSERT(strcmp(out, "C:\\\\Users\\\\me") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_escape_control_chars(void)
{
    int failures = 0;
    TEST("log_json: escape handles \\n \\t \\r and low control chars") {
        char out[64];
        log_json_escape(out, sizeof(out), "line1\nline2\ttab");
        ASSERT(strcmp(out, "line1\\nline2\\ttab") == 0);

        log_json_escape(out, sizeof(out), "bell\x07");
        ASSERT(contains(out, "\\u0007"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_escape_truncation(void)
{
    int failures = 0;
    TEST("log_json: escape truncates safely on tiny buffers") {
        char out[8];
        size_t n = log_json_escape(out, sizeof(out), "hello world");
        ASSERT(n < sizeof(out));
        ASSERT(out[n] == '\0');
        PASS();
    } _test_next:;
    return failures;
}

static int test_format_truncation(void)
{
    int failures = 0;
    TEST("log_json: format truncates safely on tiny buffers") {
        char buf[32];
        size_t n = log_json_format(buf, sizeof(buf), LOG_JSON_INFO,
                                    "very_long_event_name_here",
                                    "\"x\":%d", 12345);
        ASSERT(n <= sizeof(buf) - 1);
        ASSERT(buf[n] == '\0' || buf[sizeof(buf) - 1] == '\0');
        PASS();
    } _test_next:;
    return failures;
}

static int test_event_name_escaped(void)
{
    int failures = 0;
    TEST("log_json: event name with embedded quote is escaped") {
        char buf[256];
        log_json_format(buf, sizeof(buf), LOG_JSON_INFO,
                         "weird\"event", NULL);
        ASSERT(contains(buf, "\"event\":\"weird\\\"event\""));
        PASS();
    } _test_next:;
    return failures;
}

static int test_iso8601_timestamp_shape(void)
{
    int failures = 0;
    TEST("log_json: timestamp has YYYY-MM-DDTHH:MM:SS.ffffffZ shape") {
        char buf[256];
        log_json_format(buf, sizeof(buf), LOG_JSON_INFO, "x", NULL);
        const char *ts = strstr(buf, "\"ts\":\"");
        ASSERT(ts != NULL);
        ts += 6; /* skip past `"ts":"` */
        /* Expect: 4 digits + - + 2 + - + 2 + T + 2 + : + 2 + : + 2 + . + 6 + Z */
        ASSERT(ts[4] == '-');
        ASSERT(ts[7] == '-');
        ASSERT(ts[10] == 'T');
        ASSERT(ts[13] == ':');
        ASSERT(ts[16] == ':');
        ASSERT(ts[19] == '.');
        ASSERT(ts[26] == 'Z');
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ────────────────────────────────────────────── */

int test_log_json(void);

int test_log_json(void)
{
    int failures = 0;

    failures += test_envelope_shape();
    failures += test_levels();
    failures += test_fields_inserted();
    failures += test_no_fields_no_trailing_comma();
    failures += test_escape_quotes_and_backslash();
    failures += test_escape_control_chars();
    failures += test_escape_truncation();
    failures += test_format_truncation();
    failures += test_event_name_escaped();
    failures += test_iso8601_timestamp_shape();

    return failures;
}
