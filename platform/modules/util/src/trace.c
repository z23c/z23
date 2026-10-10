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

static void trace_install_log_mirror(void);

struct trace_span *trace_start(const char *operation)
{
    trace_install_log_mirror();
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
    int64_t wall = platform_time_realtime_us();
    s->start_wall_us = (uint64_t)(wall > 0 ? wall : 0);
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

static const char *trace_otlp_status(enum trace_status status)
{
    if (status == TRACE_STATUS_ERROR) return "STATUS_CODE_ERROR";
    if (status == TRACE_STATUS_OK) return "STATUS_CODE_OK";
    return "STATUS_CODE_UNSET";
}

static bool trace_otlp_b64(const char *hex, size_t raw_len,
                           char *out, size_t cap)
{
    unsigned char raw[16];
    if (raw_len > sizeof(raw) || !hex) return false;
    if (ParseHex(hex, raw, raw_len) != raw_len) return false;
    return EncodeBase64(raw, raw_len, out, cap) > 0;
}

static bool trace_otlp_attr(const struct trace_attr *a, char *out, size_t cap)
{
    char key[TRACE_MAX_KEY_LEN * 2];
    char val[TRACE_MAX_VAL_LEN * 2];
    int n;
    log_json_escape(key, sizeof(key), a->key);
    if (a->is_int) {
        n = snprintf(out, cap,
                     "{\"key\":\"%s\",\"value\":{\"intValue\":\"%lld\"}}",
                     key, (long long)a->int_val);
    } else {
        log_json_escape(val, sizeof(val), a->str_val);
        n = snprintf(out, cap,
                     "{\"key\":\"%s\",\"value\":{\"stringValue\":\"%s\"}}",
                     key, val);
    }
    return n > 0 && (size_t)n < cap;
}

static bool trace_otlp_attrs(const struct trace_span *s, char *out, size_t cap)
{
    size_t n = 0;
    if (cap == 0) return false;
    out[0] = '\0';
    for (int i = 0; i < s->attr_count; i++) {
        char one[384];
        int w;
        if (!trace_otlp_attr(&s->attrs[i], one, sizeof(one))) return false;
        w = snprintf(out + n, cap - n, "%s%s", i ? "," : "", one);
        if (w < 0 || (size_t)w >= cap - n) return false;
        n += (size_t)w;
    }
    return true;
}

bool trace_format_otlp(const struct trace_span *s, uint64_t end_wall_us,
                       char *out, size_t cap)
{
    char trace_b64[32], span_b64[24], parent_b64[24];
    char name[TRACE_MAX_OP_LEN * 2];
    char attrs[4096];
    bool has_parent;
    uint64_t start_us, end_us;
    int n;
    if (!s || !out || cap < 64) return false;
    if (!trace_otlp_b64(s->trace_id, 16, trace_b64, sizeof(trace_b64)))
        return false;
    if (!trace_otlp_b64(s->span_id, 8, span_b64, sizeof(span_b64)))
        return false;
    has_parent = s->parent_span_id[0] != '\0';
    if (has_parent &&
        !trace_otlp_b64(s->parent_span_id, 8, parent_b64, sizeof(parent_b64)))
        return false;
    log_json_escape(name, sizeof(name), s->operation);
    if (!trace_otlp_attrs(s, attrs, sizeof(attrs))) return false;
    start_us = s->start_wall_us;
    end_us = end_wall_us < start_us ? start_us : end_wall_us;
    if (has_parent) {
        n = snprintf(out, cap,
                     "{\"resourceSpans\":[{\"scopeSpans\":[{\"scope\":"
                     "{\"name\":\"z23\"},\"spans\":[{\"traceId\":\"%s\","
                     "\"spanId\":\"%s\",\"parentSpanId\":\"%s\","
                     "\"name\":\"%s\",\"startTimeUnixNano\":\"%llu\","
                     "\"endTimeUnixNano\":\"%llu\",\"attributes\":[%s],"
                     "\"status\":{\"code\":\"%s\"}}]}]}]}",
                     trace_b64, span_b64, parent_b64, name,
                     (unsigned long long)(start_us * 1000ull),
                     (unsigned long long)(end_us * 1000ull),
                     attrs, trace_otlp_status(s->status));
    } else {
        n = snprintf(out, cap,
                     "{\"resourceSpans\":[{\"scopeSpans\":[{\"scope\":"
                     "{\"name\":\"z23\"},\"spans\":[{\"traceId\":\"%s\","
                     "\"spanId\":\"%s\",\"name\":\"%s\","
                     "\"startTimeUnixNano\":\"%llu\","
                     "\"endTimeUnixNano\":\"%llu\",\"attributes\":[%s],"
                     "\"status\":{\"code\":\"%s\"}}]}]}]}",
                     trace_b64, span_b64, name,
                     (unsigned long long)(start_us * 1000ull),
                     (unsigned long long)(end_us * 1000ull),
                     attrs, trace_otlp_status(s->status));
    }
    return n > 0 && (size_t)n < cap;
}

/* Bounded writer for trace_format_otlp_log: every byte goes through
 * trace_log_put, which refuses instead of writing past out[cap-1].  The
 * first refusal sets failed; later writes then do nothing. */
struct trace_log_out {
    char *out;
    size_t cap;
    size_t n;
    bool failed;
};

static void trace_log_put(struct trace_log_out *o, const char *s, size_t len)
{
    if (o->failed) return;
    if (len >= o->cap - o->n) {
        o->failed = true;
        return;
    }
    memcpy(o->out + o->n, s, len);
    o->n += len;
    o->out[o->n] = '\0';
}

static void trace_log_puts(struct trace_log_out *o, const char *s)
{
    trace_log_put(o, s, strlen(s));
}

/* Two-character escapes named in the header of trace_format_otlp_log. */
static const struct {
    char c;
    char esc;
} trace_log_esc_table[] = {
    { '"', '"' }, { '\\', '\\' }, { '\b', 'b' }, { '\f', 'f' },
    { '\n', 'n' }, { '\r', 'r' }, { '\t', 't' },
};

/* Escape letter for c, or '\0' when c has no two-character form. */
static char trace_log_esc_pair(unsigned char c)
{
    for (size_t i = 0; i < sizeof(trace_log_esc_table) / sizeof(trace_log_esc_table[0]); i++) {
        if ((unsigned char)trace_log_esc_table[i].c == c) return trace_log_esc_table[i].esc;
    }
    return '\0';
}

/* Escape s exactly as the header of trace_format_otlp_log specifies. */
static void trace_log_put_esc(struct trace_log_out *o, const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    for (; *p; p++) {
        char tmp[8];
        size_t len = 1;
        char esc = trace_log_esc_pair(*p);
        if (esc) {
            tmp[0] = '\\';
            tmp[1] = esc;
            len = 2;
        } else if (*p < 0x20) {
            len = (size_t)snprintf(tmp, sizeof(tmp), "\\u%04x", (unsigned)*p);
        } else {
            tmp[0] = (char)*p;
        }
        trace_log_put(o, tmp, len);
    }
}

static bool trace_log_hex_id(const char *id, size_t want)
{
    if (strlen(id) != want) return false;
    for (size_t i = 0; i < want; i++) {
        char c = id[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

static const char *trace_log_severity_text(enum trace_log_severity sev)
{
    if (sev == TRACE_LOG_TRACE) return "TRACE";
    if (sev == TRACE_LOG_DEBUG) return "DEBUG";
    if (sev == TRACE_LOG_INFO) return "INFO";
    if (sev == TRACE_LOG_WARN) return "WARN";
    if (sev == TRACE_LOG_ERROR) return "ERROR";
    if (sev == TRACE_LOG_FATAL) return "FATAL";
    return NULL;
}

static bool trace_log_check_fields(const struct trace_log_record *r)
{
    if (!r->body || !r->service || r->service[0] == '\0') return false;
    if (!trace_log_severity_text(r->severity)) return false;
    if (r->wall_us > UINT64_MAX / 1000ull) return false;
    return true;
}

static bool trace_log_check_attrs(const struct trace_log_record *r)
{
    if (r->attr_count < 0 || r->attr_count > TRACE_LOG_MAX_ATTRS) return false;
    for (int i = 0; i < r->attr_count; i++) {
        if (!r->attrs[i].key || !r->attrs[i].val || r->attrs[i].key[0] == '\0')
            return false;
    }
    return true;
}

/* Fills trace_b64 / span_b64 when the matching id is present. */
static bool trace_log_check_ids(const struct trace_log_record *r,
                                bool has_trace, bool has_span,
                                char *trace_b64, size_t trace_cap,
                                char *span_b64, size_t span_cap)
{
    if (has_trace &&
        (!trace_log_hex_id(r->trace_id, 32) ||
         !trace_otlp_b64(r->trace_id, 16, trace_b64, trace_cap)))
        return false;
    if (has_span &&
        (!trace_log_hex_id(r->span_id, 16) ||
         !trace_otlp_b64(r->span_id, 8, span_b64, span_cap)))
        return false;
    return true;
}

static void trace_log_write_head(struct trace_log_out *o,
                                 const struct trace_log_record *r)
{
    char num[32], sev_num[16];
    snprintf(num, sizeof(num), "%llu",
             (unsigned long long)(r->wall_us * 1000ull));
    snprintf(sev_num, sizeof(sev_num), "%d", (int)r->severity);
    trace_log_puts(o, "{\"resourceLogs\":[{\"resource\":{\"attributes\":"
                      "[{\"key\":\"service.name\",\"value\":"
                      "{\"stringValue\":\"");
    trace_log_put_esc(o, r->service);
    trace_log_puts(o, "\"}}]},\"scopeLogs\":[{\"scope\":"
                      "{\"name\":\"z23\"},\"logRecords\":"
                      "[{\"timeUnixNano\":\"");
    trace_log_puts(o, num);
    trace_log_puts(o, "\",\"severityNumber\":");
    trace_log_puts(o, sev_num);
    trace_log_puts(o, ",\"severityText\":\"");
    trace_log_puts(o, trace_log_severity_text(r->severity));
    trace_log_puts(o, "\",\"body\":{\"stringValue\":\"");
    trace_log_put_esc(o, r->body);
    trace_log_puts(o, "\"},\"attributes\":[");
}

static void trace_log_write_attrs(struct trace_log_out *o,
                                  const struct trace_log_record *r)
{
    for (int i = 0; i < r->attr_count; i++) {
        if (i) trace_log_puts(o, ",");
        trace_log_puts(o, "{\"key\":\"");
        trace_log_put_esc(o, r->attrs[i].key);
        trace_log_puts(o, "\",\"value\":{\"stringValue\":\"");
        trace_log_put_esc(o, r->attrs[i].val);
        trace_log_puts(o, "\"}}");
    }
    trace_log_puts(o, "]");
}

static void trace_log_write_tail(struct trace_log_out *o,
                                 bool has_trace, bool has_span,
                                 const char *trace_b64, const char *span_b64)
{
    if (has_trace) {
        trace_log_puts(o, ",\"traceId\":\"");
        trace_log_puts(o, trace_b64);
        trace_log_puts(o, "\"");
    }
    if (has_span) {
        trace_log_puts(o, ",\"spanId\":\"");
        trace_log_puts(o, span_b64);
        trace_log_puts(o, "\"");
    }
    trace_log_puts(o, "}]}]}]}");
}

/* Returns false when validation refuses the record; write refusals
 * (buffer full) are reported through o->failed by the caller. */
static bool trace_log_build(const struct trace_log_record *r,
                            struct trace_log_out *o)
{
    char trace_b64[32] = "", span_b64[24] = "";
    bool has_trace = r->trace_id && r->trace_id[0] != '\0';
    bool has_span = r->span_id && r->span_id[0] != '\0';
    if (!trace_log_check_fields(r)) return false;
    if (!trace_log_check_attrs(r)) return false;
    if (!trace_log_check_ids(r, has_trace, has_span,
                             trace_b64, sizeof(trace_b64),
                             span_b64, sizeof(span_b64)))
        return false;
    trace_log_write_head(o, r);
    trace_log_write_attrs(o, r);
    trace_log_write_tail(o, has_trace, has_span, trace_b64, span_b64);
    return true;
}

bool trace_format_otlp_log(const struct trace_log_record *r,
                           char *out, size_t cap)
{
    struct trace_log_out o;
    if (!out || cap == 0) return false;
    out[0] = '\0';
    if (!r) return false;
    o.out = out;
    o.cap = cap;
    o.n = 0;
    o.failed = false;
    if (trace_log_build(r, &o) && !o.failed) return true;
    out[0] = '\0';
    return false;
}

/* ── OTLP log mirror (ZCL_OTLP_LOGS=1, off by default) ─────────
 * Installed into log_json at process start by a constructor, and only
 * when the switch is on; trace_start() and the test reset call the same
 * install helper.  Env-flag idiom of trace_verbose(): the switch is
 * resolved once. */
static _Atomic int g_otlp_logs = -1;
static _Atomic bool g_mirror_installed = false;

static bool trace_otlp_logs_enabled(void)
{
    int v = g_otlp_logs;
    if (v < 0) {
        const char *env = getenv("ZCL_OTLP_LOGS");
        v = (env && strcmp(env, "1") == 0) ? 1 : 0;
        g_otlp_logs = v;
    }
    return v == 1;
}

/* Indexed by enum log_json_level. */
static const enum trace_log_severity trace_log_sev_map[] = {
    [LOG_JSON_INFO]  = TRACE_LOG_INFO,
    [LOG_JSON_WARN]  = TRACE_LOG_WARN,
    [LOG_JSON_ERROR] = TRACE_LOG_ERROR,
};

static enum trace_log_severity trace_log_sev_of(enum log_json_level level)
{
    if ((unsigned)level >= sizeof(trace_log_sev_map) / sizeof(trace_log_sev_map[0]))
        return TRACE_LOG_INFO;
    return trace_log_sev_map[level];
}

/* Format r and emit it as an otlp_logs line; false when it did not fit. */
static bool trace_log_emit(const struct trace_log_record *r)
{
    char doc[1024];
    if (!trace_format_otlp_log(r, doc, sizeof(doc))) return false;
    log_jsonf(LOG_JSON_INFO, "otlp_logs", "\"otlp\":%s", doc);
    return true;
}

/* log_json mirror hook: body is the event name, the rendered fields text
 * rides as one z23.fields attribute.  If that does not fit the record
 * goes out with z23.fields_dropped=true instead; if even that does not
 * fit nothing is emitted.  OTLP export lines are never mirrored. */
static void trace_log_mirror(enum log_json_level level, const char *event,
                             const char *fields)
{
    if (!trace_otlp_logs_enabled()) return;
    if (strcmp(event, "otlp_traces") == 0 || strcmp(event, "otlp_logs") == 0)
        return;
    const struct trace_span *sp = trace_current();
    int64_t now = platform_time_realtime_us();
    struct trace_log_record r = {
        .wall_us = now > 0 ? (uint64_t)now : 0,
        .severity = trace_log_sev_of(level),
        .body = event,
        .trace_id = sp ? sp->trace_id : NULL,
        .span_id = sp ? sp->span_id : NULL,
        .service = "z23",
    };
    if (fields[0] == '\0') {
        (void)trace_log_emit(&r);
        return;
    }
    r.attrs[0] = (struct trace_log_attr){ "z23.fields", fields };
    r.attr_count = 1;
    if (trace_log_emit(&r)) return;
    r.attrs[0] = (struct trace_log_attr){ "z23.fields_dropped", "true" };
    (void)trace_log_emit(&r);
}

/* Installs the hook only when the switch is on, so with it off log_jsonf()
 * pays one pointer load and nothing else.  The flag is set after the hook
 * is in place. */
static void trace_install_log_mirror(void)
{
    if (g_mirror_installed) return;
    if (!trace_otlp_logs_enabled()) return;
    log_json_set_mirror(trace_log_mirror);
    g_mirror_installed = true;
}

/* Process start: reads the switch once and installs the hook only if it
 * is on.  Same form as the constructor in engine/composition/src/runtime.c. */
__attribute__((constructor))
static void trace_otlp_logs_ctor(void)
{
    trace_install_log_mirror();
}

void trace_otlp_logs_reset_for_testing(void)
{
    g_otlp_logs = -1;
    g_mirror_installed = false;
    log_json_set_mirror(NULL);
    trace_install_log_mirror();
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

    char body[4096];
    uint64_t end_wall = 0;
    int64_t now_wall = platform_time_realtime_us();
    if (now_wall > 0)
        end_wall = (uint64_t)now_wall;
    if (trace_format_otlp(s, end_wall, body, sizeof(body)))
        log_jsonf(LOG_JSON_INFO, "otlp_traces", "\"otlp\":%s", body);

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
