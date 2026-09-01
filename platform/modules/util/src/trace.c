/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * OpenTelemetry-compatible distributed tracing — implementation.
 *
 * Thread-local span stack with parent-child linkage.  Each span
 * emits a single JSON line via log_jsonf() at trace_end() time.
 */

#include "platform/time_compat.h"
#include "util/trace.h"
#include "encoding/utilstrencodings.h"
#include "util/log_json.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

/* ── Random ID generation ──────────────────────────────────── */

/* Use /dev/urandom for trace/span IDs.  Falls back to time-based
 * seed if /dev/urandom is unavailable. */
static void trace_random_bytes(uint8_t *buf, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t got = fread(buf, 1, len, f);
        fclose(f);
        if (got == len) return;
    }
    /* Fallback: mix time + thread ID.  Not cryptographic but
     * sufficient for trace correlation. */
    uint64_t seed = platform_time_monotonic_us() ^ (uint64_t)(uintptr_t)pthread_self();
    for (size_t i = 0; i < len; i++) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i] = (uint8_t)(seed >> 33);
    }
}

/* ── Global enable/disable ─────────────────────────────────── */

static _Atomic bool g_trace_enabled = true;

void trace_set_enabled(bool enabled)
{
    g_trace_enabled = enabled;
}

/* Fast successful spans are dropped at trace_end() unless verbose tracing
 * is requested: status==OK spans under this duration are pure log volume
 * (rpc.dispatch alone was ~40% of the live log at INFO). Non-OK and slow
 * spans ALWAYS emit. */
#define TRACE_FAST_OK_SPAN_US 10000

static bool trace_verbose(void)
{
    /* Env-flag idiom (alerts.c ZCL_ALERTS_DISABLE); resolved once —
     * trace_end() is hot-path so getenv() must not run per span. */
    static _Atomic int cached = -1;
    int v = cached;
    if (v < 0) {
        const char *env = getenv("ZCL_TRACE_VERBOSE");
        v = (env && strcmp(env, "1") == 0) ? 1 : 0;
        cached = v;
    }
    return v == 1;
}

/* ── Thread-local span stack ───────────────────────────────── */

#define TRACE_STACK_MAX 8

struct trace_tls {
    struct trace_span *stack[TRACE_STACK_MAX];
    int depth;
};

static _Thread_local struct trace_tls tls_trace = { .depth = 0 };

/* ── Lifecycle ─────────────────────────────────────────────── */

struct trace_span *trace_start(const char *operation)
{
    if (!g_trace_enabled) return NULL;

    struct trace_span *s = zcl_malloc(sizeof(*s), "trace_span");
    if (!s) return NULL;
    memset(s, 0, sizeof(*s));

    /* Operation name */
    if (operation) {
        snprintf(s->operation, sizeof(s->operation), "%s", operation);
    }

    /* Generate span_id (8 random bytes → 16 hex chars) */
    uint8_t span_bytes[8];
    trace_random_bytes(span_bytes, sizeof(span_bytes));
    HexStr(span_bytes, sizeof(span_bytes), false, s->span_id, sizeof(s->span_id));

    /* Inherit or generate trace_id */
    struct trace_tls *t = &tls_trace;
    if (t->depth > 0 && t->stack[t->depth - 1]) {
        /* Child span — inherit trace_id, set parent */
        struct trace_span *parent = t->stack[t->depth - 1];
        memcpy(s->trace_id, parent->trace_id, sizeof(s->trace_id));
        memcpy(s->parent_span_id, parent->span_id, sizeof(s->parent_span_id));
    } else {
        /* Root span — generate new trace_id (16 random bytes → 32 hex) */
        uint8_t trace_bytes[16];
        trace_random_bytes(trace_bytes, sizeof(trace_bytes));
        HexStr(trace_bytes, sizeof(trace_bytes), false, s->trace_id, sizeof(s->trace_id));
        s->parent_span_id[0] = '\0';
    }

    /* Push onto thread-local stack */
    if (t->depth < TRACE_STACK_MAX) {
        t->stack[t->depth++] = s;
    }
    /* If stack is full we still return the span — it just won't
     * be a parent for deeper spans.  This is a safety valve, not
     * a normal path. */

    s->start_us = platform_time_monotonic_us();
    s->status = TRACE_STATUS_UNSET;
    return s;
}

void trace_attr_str(struct trace_span *s, const char *key, const char *val)
{
    if (!s || !key) return;
    if (s->attr_count >= TRACE_MAX_ATTRS) return;

    struct trace_attr *a = &s->attrs[s->attr_count++];
    snprintf(a->key, sizeof(a->key), "%s", key);
    a->is_int = false;
    if (val) {
        snprintf(a->str_val, sizeof(a->str_val), "%s", val);
    } else {
        a->str_val[0] = '\0';
    }
}

void trace_attr_int(struct trace_span *s, const char *key, int64_t val)
{
    if (!s || !key) return;
    if (s->attr_count >= TRACE_MAX_ATTRS) return;

    struct trace_attr *a = &s->attrs[s->attr_count++];
    snprintf(a->key, sizeof(a->key), "%s", key);
    a->is_int = true;
    a->int_val = val;
}

void trace_set_status(struct trace_span *s, enum trace_status status)
{
    if (!s) return;
    s->status = status;
}

void trace_end(struct trace_span *s)
{
    if (!s) return;

    uint64_t end_us = platform_time_monotonic_us();
    uint64_t duration_us = (end_us >= s->start_us)
                           ? (end_us - s->start_us) : 0;

    /* Default status to OK if unset */
    if (s->status == TRACE_STATUS_UNSET)
        s->status = TRACE_STATUS_OK;

    /* Pop from thread-local stack */
    struct trace_tls *t = &tls_trace;
    if (t->depth > 0 && t->stack[t->depth - 1] == s) {
        t->depth--;
    } else {
        /* Out-of-order end — scan the stack */
        for (int i = t->depth - 1; i >= 0; i--) {
            if (t->stack[i] == s) {
                memmove(&t->stack[i], &t->stack[i + 1],
                        (size_t)(t->depth - i - 1) * sizeof(t->stack[0]));
                t->depth--;
                break;
            }
        }
    }

    /* Drop fast successful spans (after the stack pop above so parentage
     * stays correct). A slow child forces its same-thread parent to be slow
     * too, so emitted children keep their emitted ancestors. */
    if (s->status == TRACE_STATUS_OK &&
        duration_us < TRACE_FAST_OK_SPAN_US && !trace_verbose()) {
        free(s);
        return;
    }

    /* Build attributes JSON fragment */
    char attrs_buf[1024];
    size_t pos = 0;
    for (int i = 0; i < s->attr_count && pos < sizeof(attrs_buf) - 64; i++) {
        char escaped_key[TRACE_MAX_KEY_LEN * 2];
        log_json_escape(escaped_key, sizeof(escaped_key), s->attrs[i].key);

        int n;
        if (s->attrs[i].is_int) {
            n = snprintf(attrs_buf + pos, sizeof(attrs_buf) - pos,
                         "\"%s\":%lld,",
                         escaped_key, (long long)s->attrs[i].int_val);
        } else {
            char escaped_val[TRACE_MAX_VAL_LEN * 2];
            log_json_escape(escaped_val, sizeof(escaped_val),
                           s->attrs[i].str_val);
            n = snprintf(attrs_buf + pos, sizeof(attrs_buf) - pos,
                         "\"%s\":\"%s\",",
                         escaped_key, escaped_val);
        }
        if (n > 0) pos += (size_t)n;
    }
    /* Remove trailing comma */
    if (pos > 0 && attrs_buf[pos - 1] == ',')
        attrs_buf[--pos] = '\0';
    else
        attrs_buf[pos] = '\0';

    /* Status string */
    const char *status_str = "OK";
    if (s->status == TRACE_STATUS_ERROR) status_str = "ERROR";
    else if (s->status == TRACE_STATUS_UNSET) status_str = "UNSET";

    /* Escaped operation name */
    char escaped_op[TRACE_MAX_OP_LEN * 2];
    log_json_escape(escaped_op, sizeof(escaped_op), s->operation);

    /* Emit OTLP-compatible JSON span */
    if (s->parent_span_id[0]) {
        log_jsonf(LOG_JSON_INFO, "trace_span",
                  "\"trace_id\":\"%s\","
                  "\"span_id\":\"%s\","
                  "\"parent_span_id\":\"%s\","
                  "\"operation\":\"%s\","
                  "\"duration_us\":%llu,"
                  "\"status\":\"%s\","
                  "\"attrs\":{%s}",
                  s->trace_id, s->span_id, s->parent_span_id,
                  escaped_op, (unsigned long long)duration_us,
                  status_str, attrs_buf);
    } else {
        log_jsonf(LOG_JSON_INFO, "trace_span",
                  "\"trace_id\":\"%s\","
                  "\"span_id\":\"%s\","
                  "\"operation\":\"%s\","
                  "\"duration_us\":%llu,"
                  "\"status\":\"%s\","
                  "\"attrs\":{%s}",
                  s->trace_id, s->span_id,
                  escaped_op, (unsigned long long)duration_us,
                  status_str, attrs_buf);
    }

    free(s);
}

/* ── Query ─────────────────────────────────────────────────── */

struct trace_span *trace_current(void)
{
    struct trace_tls *t = &tls_trace;
    if (t->depth > 0)
        return t->stack[t->depth - 1];
    return NULL;
}

const char *trace_current_id(void)
{
    struct trace_span *s = trace_current();
    if (s) return s->trace_id;
    return "";
}

/* ── Test support ──────────────────────────────────────────── */

void trace_reset_thread(void)
{
    tls_trace.depth = 0;
}
