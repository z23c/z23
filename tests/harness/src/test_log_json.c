/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the structured JSON log helper.  We never call the live
 * log_jsonf() (which would write into debug.log / stdout) — instead
 * we use log_json_format() which renders into a caller-supplied
 * buffer, which is what the unit tests need anyway. */

#include "test/test_core.h"
#include "util/log_json.h"
#include "util/safe_alloc.h"
#include "util/trace.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
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

/* ── OTLP log mirror (ZCL_OTLP_LOGS) ───────────────────────────
 * log_jsonf() reaches the log through LogPrintStr(), which writes to
 * stderr: redirect fd 2 into a temp file around one real emit.  Checks
 * count only lines carrying the unique event name, so an unrelated
 * stderr writer cannot change a count. */
#define PROBE_EV "u12_otlp_probe"

struct probe {
    enum log_json_level level;
    const char *fields;          /* NULL: no fields_fmt at all */
    struct trace_span *end_sp;   /* non-NULL: trace_end() instead */
};

static void probe_run(const struct probe *p)
{
    if (p->end_sp)
        trace_end(p->end_sp);
    else if (p->fields)
        log_jsonf(p->level, PROBE_EV, "%s", p->fields);
    else
        log_jsonf(p->level, PROBE_EV, NULL);
}

static bool capture_probe(const struct probe *p, char *out, size_t cap)
{
    char path[PATH_MAX];
    int tmp_fd = test_mkstemp(path, sizeof(path), "zcl_logjson");
    if (tmp_fd < 0) return false;
    int saved = dup(STDERR_FILENO);
    if (saved < 0) { close(tmp_fd); unlink(path); return false; }
    fflush(stderr);
    if (dup2(tmp_fd, STDERR_FILENO) < 0) {
        close(saved); close(tmp_fd); unlink(path);
        return false;
    }
    probe_run(p);
    fflush(stderr);
    (void)dup2(saved, STDERR_FILENO);
    close(saved);
    (void)lseek(tmp_fd, 0, SEEK_SET);
    ssize_t n = read(tmp_fd, out, cap - 1);
    close(tmp_fd);
    unlink(path);
    if (n < 0) { out[0] = '\0'; return false; }
    out[n] = '\0';
    return true;
}

/* Number of lines of hay that contain needle. */
static int lines_with(const char *hay, const char *needle)
{
    int c = 0;
    const char *p = hay;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        char *line = zcl_malloc(len + 1, "lines_with");
        if (!line) return -1;
        memcpy(line, p, len);
        line[len] = '\0';
        if (strstr(line, needle)) c++;
        free(line);
        p += len + (nl ? 1 : 0);
    }
    return c;
}

/* The otlp_logs line of cap (pointer into it), or NULL. */
static const char *otlp_line(const char *cap)
{
    const char *p = cap;
    while ((p = strstr(p, "\"event\":\"otlp_logs\"")) != NULL) {
        const char *ls = p;
        while (ls > cap && ls[-1] != '\n') ls--;
        const char *nl = strchr(ls, '\n');
        const char *end = nl ? nl : ls + strlen(ls);   /* no newline: buffer end */
        if (strstr(ls, PROBE_EV) && strstr(ls, PROBE_EV) < end)
            return ls;
        p++;
    }
    return NULL;
}

/* ZCL_OTLP_LOGS as found, kept without truncation, restored exactly. */
struct otlp_env {
    char *saved;   /* NULL: the variable was unset */
};

static bool otlp_env_save(struct otlp_env *e)
{
    const char *v = getenv("ZCL_OTLP_LOGS");
    e->saved = NULL;
    if (!v) return true;
    e->saved = zcl_malloc(strlen(v) + 1, "otlp_env_saved");
    if (!e->saved) return false;
    memcpy(e->saved, v, strlen(v) + 1);
    return true;
}

/* Always reached: tests call it after their _test_next label. */
static void otlp_env_restore(struct otlp_env *e)
{
    if (e->saved) setenv("ZCL_OTLP_LOGS", e->saved, 1);
    else unsetenv("ZCL_OTLP_LOGS");
    free(e->saved);
    e->saved = NULL;
    trace_otlp_logs_reset_for_testing();
    trace_reset_thread();
}

/* Fresh state with the switch set to val (NULL: unset), hook installed
 * by a throwaway span. */
static void otlp_env_arm(const char *val)
{
    if (val) setenv("ZCL_OTLP_LOGS", val, 1);
    else unsetenv("ZCL_OTLP_LOGS");
    trace_otlp_logs_reset_for_testing();
    trace_reset_thread();
    trace_set_enabled(true);   /* no getter exists: tracing is left enabled */
    trace_end(trace_start("arm"));
}

static int test_otlp_logs_off(void)
{
    int failures = 0;
    struct otlp_env env;
    if (!otlp_env_save(&env)) return 1;
    TEST("log_json: ZCL_OTLP_LOGS off emits exactly one line") {
        char cap[8192];
        otlp_env_arm(NULL);
        struct probe p = { LOG_JSON_WARN, "\"k\":1", NULL };
        ASSERT(capture_probe(&p, cap, sizeof(cap)));
        ASSERT(lines_with(cap, PROBE_EV) == 1);
        ASSERT(contains(cap, "\"event\":\"" PROBE_EV "\""));
        ASSERT(!contains(cap, "\"event\":\"otlp_logs\""));
        PASS();
    } _test_next:;
    otlp_env_restore(&env);
    return failures;
}

static int test_otlp_logs_in_span(void)
{
    int failures = 0;
    struct otlp_env env;
    if (!otlp_env_save(&env)) return 1;
    TEST("log_json: ZCL_OTLP_LOGS on in a span mirrors body/severity/fields/ids") {
        char cap[8192];
        char ref[2048];
        otlp_env_arm("1");
        struct trace_span *sp = trace_start("probe");
        ASSERT(sp != NULL);
        struct trace_log_record r = {
            .wall_us = 1, .severity = TRACE_LOG_WARN, .body = PROBE_EV,
            .trace_id = sp->trace_id, .span_id = sp->span_id,
            .service = "z23",
            .attrs = { { "z23.fields", "\"k\":1" } }, .attr_count = 1,
        };
        ASSERT(trace_format_otlp_log(&r, ref, sizeof(ref)));
        const char *tail = strstr(ref, "\"severityNumber\":");
        ASSERT(tail != NULL);
        struct probe p = { LOG_JSON_WARN, "\"k\":1", NULL };
        ASSERT(capture_probe(&p, cap, sizeof(cap)));
        trace_end(sp);
        ASSERT(lines_with(cap, PROBE_EV) == 2);
        const char *l2 = otlp_line(cap);
        ASSERT(l2 != NULL);
        ASSERT(contains(l2, "\"body\":{\"stringValue\":\"" PROBE_EV "\"}"));
        ASSERT(contains(l2, "\"severityNumber\":13,\"severityText\":\"WARN\""));
        ASSERT(contains(l2, "\"stringValue\":\"z23\""));
        ASSERT(contains(l2, "{\"key\":\"z23.fields\",\"value\":"
                            "{\"stringValue\":\"\\\"k\\\":1\"}}"));
        ASSERT(contains(l2, tail));
        PASS();
    } _test_next:;
    otlp_env_restore(&env);
    return failures;
}

static int test_otlp_logs_no_span(void)
{
    int failures = 0;
    struct otlp_env env;
    if (!otlp_env_save(&env)) return 1;
    TEST("log_json: ZCL_OTLP_LOGS on outside a span omits ids and empty fields") {
        char cap[8192];
        otlp_env_arm("1");
        struct probe p = { LOG_JSON_INFO, NULL, NULL };
        ASSERT(capture_probe(&p, cap, sizeof(cap)));
        ASSERT(lines_with(cap, PROBE_EV) == 2);
        const char *l2 = otlp_line(cap);
        ASSERT(l2 != NULL);
        ASSERT(contains(l2, "\"body\":{\"stringValue\":\"" PROBE_EV "\"}"));
        ASSERT(contains(l2, "\"attributes\":[]"));
        ASSERT(!contains(l2, "z23.fields"));
        ASSERT(!contains(l2, "traceId"));
        ASSERT(!contains(l2, "spanId"));
        PASS();
    } _test_next:;
    otlp_env_restore(&env);
    return failures;
}

static int test_otlp_logs_fields_dropped(void)
{
    int failures = 0;
    struct otlp_env env;
    if (!otlp_env_save(&env)) return 1;
    TEST("log_json: ZCL_OTLP_LOGS oversized fields become z23.fields_dropped") {
        char cap[8192];
        char big[1400];
        memset(big, 'x', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        otlp_env_arm("1");
        struct probe p = { LOG_JSON_INFO, big, NULL };
        ASSERT(capture_probe(&p, cap, sizeof(cap)));
        const char *l2 = otlp_line(cap);
        ASSERT(l2 != NULL);
        ASSERT(contains(l2, "{\"key\":\"z23.fields_dropped\",\"value\":"
                            "{\"stringValue\":\"true\"}}"));
        ASSERT(!contains(l2, "\"key\":\"z23.fields\""));
        ASSERT(!contains(l2, "xxxxxxxx"));
        PASS();
    } _test_next:;
    otlp_env_restore(&env);
    return failures;
}

static int test_otlp_logs_severity(void)
{
    int failures = 0;
    struct otlp_env env;
    if (!otlp_env_save(&env)) return 1;
    TEST("log_json: ZCL_OTLP_LOGS maps every level, out-of-range to INFO") {
        static const struct {
            enum log_json_level level;
            const char *want;
        } cases[] = {
            { LOG_JSON_INFO, "\"severityNumber\":9,\"severityText\":\"INFO\"" },
            { LOG_JSON_WARN, "\"severityNumber\":13,\"severityText\":\"WARN\"" },
            { LOG_JSON_ERROR, "\"severityNumber\":17,\"severityText\":\"ERROR\"" },
            { (enum log_json_level)99,
              "\"severityNumber\":9,\"severityText\":\"INFO\"" },
        };
        otlp_env_arm("1");
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            char cap[8192];
            struct probe p = { cases[i].level, NULL, NULL };
            ASSERT(capture_probe(&p, cap, sizeof(cap)));
            const char *l2 = otlp_line(cap);
            ASSERT(l2 != NULL);
            ASSERT(contains(l2, cases[i].want));
        }
        PASS();
    } _test_next:;
    otlp_env_restore(&env);
    return failures;
}

static int test_otlp_traces_not_mirrored(void)
{
    int failures = 0;
    struct otlp_env env;
    if (!otlp_env_save(&env)) return 1;
    TEST("log_json: ZCL_OTLP_LOGS on does not mirror otlp_traces") {
        char cap[8192];
        otlp_env_arm("1");
        struct trace_span *sp = trace_start("probe");
        ASSERT(sp != NULL);
        trace_set_status(sp, TRACE_STATUS_ERROR);
        struct probe p = { LOG_JSON_INFO, NULL, sp };
        ASSERT(capture_probe(&p, cap, sizeof(cap)));
        ASSERT(lines_with(cap, "\"event\":\"otlp_traces\"") == 1);
        ASSERT(lines_with(cap, "\"event\":\"otlp_logs\"") == 0);
        PASS();
    } _test_next:;
    otlp_env_restore(&env);
    return failures;
}

/* Switch set after process start, no span ever started: the reset alone
 * must install the hook.  Deliberately does not use otlp_env_arm(), which
 * starts a span. */
static int test_otlp_logs_no_span_armed(void)
{
    int failures = 0;
    struct otlp_env env;
    if (!otlp_env_save(&env)) return 1;
    TEST("log_json: ZCL_OTLP_LOGS on with no span ever started still mirrors") {
        char cap[8192];
        ASSERT(setenv("ZCL_OTLP_LOGS", "1", 1) == 0);
        trace_otlp_logs_reset_for_testing();
        trace_reset_thread();
        ASSERT(trace_current() == NULL);
        struct probe p = { LOG_JSON_INFO, NULL, NULL };
        ASSERT(capture_probe(&p, cap, sizeof(cap)));
        ASSERT(lines_with(cap, PROBE_EV) == 2);
        const char *l2 = otlp_line(cap);
        ASSERT(l2 != NULL);
        ASSERT(contains(l2, "\"body\":{\"stringValue\":\"" PROBE_EV "\"}"));
        ASSERT(!contains(l2, "traceId"));
        PASS();
    } _test_next:;
    otlp_env_restore(&env);
    return failures;
}

/* ── Mirror hook contract ───────────────────────────────────── */

static char g_hook_event[128];
static char g_hook_fields[128];
static int g_hook_calls;

static void recording_hook(enum log_json_level level, const char *event,
                           const char *fields)
{
    (void)level;
    g_hook_calls++;
    snprintf(g_hook_event, sizeof(g_hook_event), "%s", event);
    snprintf(g_hook_fields, sizeof(g_hook_fields), "%s", fields);
    /* A line emitted from inside the hook must not re-enter it. */
    log_jsonf(LOG_JSON_INFO, "u12_hook_inner", NULL);
}

static int test_mirror_hook_contract(void)
{
    int failures = 0;
    TEST("log_json: mirror hook gets truncated event + fields, no re-entry") {
        char longev[100];
        memset(longev, 'e', sizeof(longev) - 1);
        longev[sizeof(longev) - 1] = '\0';
        g_hook_calls = 0;
        log_json_set_mirror(recording_hook);
        log_jsonf(LOG_JSON_INFO, longev, "\"a\":%d", 7);
        ASSERT(g_hook_calls == 1);
        ASSERT(strlen(g_hook_event) == 63);
        ASSERT(strcmp(g_hook_fields, "\"a\":7") == 0);
        log_jsonf(LOG_JSON_INFO, NULL, NULL);
        ASSERT(g_hook_calls == 2);
        ASSERT(g_hook_event[0] == '\0' && g_hook_fields[0] == '\0');
        log_json_set_mirror(NULL);
        log_jsonf(LOG_JSON_INFO, "u12_hook_off", NULL);
        ASSERT(g_hook_calls == 2);
        PASS();
    } _test_next:;
    trace_otlp_logs_reset_for_testing();
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
    failures += test_otlp_logs_off();
    failures += test_otlp_logs_in_span();
    failures += test_otlp_logs_no_span();
    failures += test_otlp_logs_fields_dropped();
    failures += test_otlp_logs_severity();
    failures += test_otlp_traces_not_mirrored();
    failures += test_otlp_logs_no_span_armed();
    failures += test_mirror_hook_contract();

    return failures;
}
