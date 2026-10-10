/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * OpenTelemetry-compatible distributed tracing.
 *
 * Lightweight tracing spans compatible with W3C Trace Context and
 * OTLP JSON format.  Spans form a tree via parent_id using a
 * thread-local span stack — starting a span while another is active
 * automatically parents the new span to the current one.
 *
 * Output is emitted via log_jsonf() as "trace_span" events with
 * OTLP-compatible fields: trace_id, span_id, parent_span_id,
 * operation, duration_us, status, and up to TRACE_MAX_ATTRS
 * key-value attributes.
 *
 * Usage:
 *
 *   struct trace_span *s = trace_start("command.dispatch");
 *   trace_attr_str(s, "command", command_name);
 *   trace_attr_int(s, "args_count", nargs);
 *   // ... do work ...
 *   trace_end(s);  // emits JSON span via log_jsonf, frees span
 *
 * Thread safety: each thread has its own span stack.  The span
 * itself must only be used by the thread that created it.
 *
 * Overhead: ~200ns per span start/end (rdtsc + snprintf).  Safe
 * for hot paths at block-connect and RPC-dispatch frequency.
 */

#ifndef ZCL_UTIL_TRACE_H
#define ZCL_UTIL_TRACE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum attributes per span. */
#define TRACE_MAX_ATTRS 8

/* Maximum operation name length. */
#define TRACE_MAX_OP_LEN 64

/* Maximum attribute key length. */
#define TRACE_MAX_KEY_LEN 32

/* Maximum attribute string value length. */
#define TRACE_MAX_VAL_LEN 128

/* Span status codes (OTLP SpanStatusCode). */
enum trace_status {
    TRACE_STATUS_UNSET = 0,
    TRACE_STATUS_OK    = 1,
    TRACE_STATUS_ERROR = 2,
};

/* Attribute value (string or int). */
struct trace_attr {
    char    key[TRACE_MAX_KEY_LEN];
    bool    is_int;
    int64_t int_val;
    char    str_val[TRACE_MAX_VAL_LEN];
};

/* Opaque span handle.  Allocated by trace_start(), freed by trace_end(). */
struct trace_span {
    /* W3C Trace Context IDs — hex-encoded. */
    char trace_id[33];      /* 16 bytes → 32 hex chars + NUL */
    char span_id[17];       /* 8 bytes → 16 hex chars + NUL */
    char parent_span_id[17]; /* empty string if root span */

    char operation[TRACE_MAX_OP_LEN];
    uint64_t start_us;
    /* Wall clock at start, microseconds. OTLP timestamps use this clock,
     * not the monotonic duration clock. */
    uint64_t start_wall_us;

    struct trace_attr attrs[TRACE_MAX_ATTRS];
    int attr_count;

    enum trace_status status;
};

/* ── Lifecycle ─────────────────────────────────────────────── */

/* Start a new span.  If a span is already active on this thread,
 * the new span inherits its trace_id and sets parent_span_id.
 * Returns NULL on allocation failure — callers should NULL-check
 * but trace_attr_str/trace_end are NULL-safe. */
struct trace_span *trace_start(const char *operation);

/* Set a string attribute on the span. */
void trace_attr_str(struct trace_span *s, const char *key, const char *val);

/* Set an integer attribute on the span. */
void trace_attr_int(struct trace_span *s, const char *key, int64_t val);

/* Set span status (default UNSET → OK on trace_end if not set). */
void trace_set_status(struct trace_span *s, enum trace_status status);

/* End the span: compute duration, emit one OTLP/HTTP JSON trace export
 * via log_jsonf, pop from the thread-local stack, and free the span. */
void trace_end(struct trace_span *s);

/* Write one OTLP/HTTP JSON ExportTraceServiceRequest for `s`.
 * `end_wall_us` is the wall-clock end in microseconds, the same clock as
 * `start_wall_us`. The bytes are the published proto3 JSON mapping
 * (lowercase hex trace, span and parent span ids per the OTLP JSON
 * Protobuf encoding: 32 and 16 hex digits, NOT base64; decimal-string
 * timestamps, integer status code 0 unset, 1 ok, 2 error per the
 * rule that OTLP JSON enums are integers). Input ids must be exactly 32
 * (trace) and 16 (span, parent) hex digits of either case; any other length
 * or alphabet makes the call return false, and so does an all-zero id (the
 * trace model defines an all-zero trace id and span id as invalid); this
 * applies to trace, span and a present parent span id, and to
 * trace_format_otlp_log's ids. A root span (empty parent id) omits
 * parentSpanId. Returns false also when `out` cannot hold the document. */
bool trace_format_otlp(const struct trace_span *s, uint64_t end_wall_us,
                       char *out, size_t cap);

/* ── OTLP log records ──────────────────────────────────────── */

/* Maximum string attributes on one log record. */
#define TRACE_LOG_MAX_ATTRS 4

/* OTLP SeverityNumber values; the text is the severityText below. */
enum trace_log_severity {
    TRACE_LOG_TRACE = 1,   /* "TRACE" */
    TRACE_LOG_DEBUG = 5,   /* "DEBUG" */
    TRACE_LOG_INFO  = 9,   /* "INFO"  */
    TRACE_LOG_WARN  = 13,  /* "WARN"  */
    TRACE_LOG_ERROR = 17,  /* "ERROR" */
    TRACE_LOG_FATAL = 21,  /* "FATAL" */
};

struct trace_log_attr {
    const char *key;       /* non-NULL, non-empty */
    const char *val;       /* non-NULL, may be empty */
};

/* One log record; every pointer is caller-owned and only read. */
struct trace_log_record {
    uint64_t wall_us;               /* wall clock, microseconds since epoch */
    enum trace_log_severity severity;
    const char *body;               /* non-NULL, may be empty */
    const char *trace_id;           /* NULL or "" = absent, else 32 hex chars */
    const char *span_id;            /* NULL or "" = absent, else 16 hex chars */
    const char *service;            /* non-NULL, non-empty: service.name */
    struct trace_log_attr attrs[TRACE_LOG_MAX_ATTRS];
    int attr_count;                 /* 0..TRACE_LOG_MAX_ATTRS */
};

/* Write one OTLP/HTTP JSON ExportLogsServiceRequest for `r` into `out`
 * (NUL-terminated, no whitespace anywhere, returns true).
 *
 * Exact shape, fields in exactly this order (<..> are substitutions):
 *
 * {"resourceLogs":[{"resource":{"attributes":[{"key":"service.name",
 * "value":{"stringValue":"<service>"}}]},"scopeLogs":[{"scope":
 * {"name":"z23"},"logRecords":[{"timeUnixNano":"<ns>",
 * "severityNumber":<num>,"severityText":"<TEXT>",
 * "body":{"stringValue":"<body>"},"attributes":[<attrs>]<ids>}]}]}]}
 *
 * (shown wrapped; the real output has no newlines or spaces other than
 * those inside the substituted strings.)
 *
 *  - <ns>: wall_us * 1000 as an unsigned decimal string in quotes (the
 *    proto3 JSON mapping of fixed64), same as trace_format_otlp. If
 *    wall_us > UINT64_MAX / 1000 return false.
 *  - <num>: the enum value as a bare JSON integer; <TEXT> is the name
 *    in the enum comments. Any other severity value returns false.
 *  - <attrs>: the record attributes in array order, comma separated,
 *    each exactly {"key":"<k>","value":{"stringValue":"<v>"}}; "attributes"
 *    is always present, as [] when attr_count is 0.
 *  - <ids>: after "attributes", in this order and each only when
 *    present: ,"traceId":"<hex>"  then  ,"spanId":"<hex>". An id is
 *    its hex digits lowercased (OTLP JSON Protobuf encoding: hex, not
 *    base64), 32 digits for traceId and 16 for spanId. Upper-case input
 *    is accepted and emitted lowercase. Either may be present
 *    without the other.
 *  - Escaping of service, body, keys and values (as log_json_escape):
 *    '"' -> \" ; '\\' -> \\ ; \b \f \n \r \t -> those two-char
 *    escapes ; every other byte < 0x20 -> \u00xx with lowercase hex
 *    (e.g. 0x01 -> \u0001, 0x1f -> \u001f) ; all other bytes (including
 *    0x7f and bytes >= 0x80) are copied unchanged.
 *
 * Returns false (and never writes past out[cap-1]) when:
 *  - r or out is NULL, or r->body, r->service or an attribute key or
 *    value pointer is NULL, or service or a key is empty;
 *  - attr_count < 0 or > TRACE_LOG_MAX_ATTRS;
 *  - a non-empty id is not exactly 32 (trace) or 16 (span) characters
 *    of [0-9a-fA-F] (no spaces, no prefix, no other length);
 *  - severity or wall_us is out of range as above;
 *  - the document plus its NUL does not fit in cap, i.e. cap must be at
 *    least strlen(document) + 1; nothing is truncated silently, so
 *    over-long text is a refusal too, whatever buffers are used inside.
 * On every false return with cap > 0, out[0] is set to '\0' (a valid
 * empty string); with cap == 0 nothing is written. */
bool trace_format_otlp_log(const struct trace_log_record *r,
                           char *out, size_t cap);

/* OTLP log mirror: with ZCL_OTLP_LOGS=1, every log_jsonf() line (except
 * otlp_traces / otlp_logs) is also emitted as one OTLP log record on an
 * "otlp_logs" line; body = event name.  With the switch on, the rendered
 * fields ride as ONE escaped string attribute z23.fields (omitted when
 * empty), not as separate structured attributes.  Fields that do not fit
 * the 1024-byte OTLP record buffer are replaced by z23.fields_dropped=true
 * instead.  The hook is installed into log_json at process start by a
 * constructor, and only when the switch is on; trace_start() also calls
 * the same install helper.
 *
 * Test-only: forget the cached ZCL_OTLP_LOGS value, uninstall the hook,
 * then re-read the environment and reinstall the hook if the switch is now
 * on (so a later setenv() takes effect). */
void trace_otlp_logs_reset_for_testing(void);

/* ── Query ─────────────────────────────────────────────────── */

/* Get the current active span on this thread (top of stack).
 * Returns NULL if no span is active. */
struct trace_span *trace_current(void);

/* Get the trace_id of the current span, or empty string if none. */
const char *trace_current_id(void);

/* ── Global control ────────────────────────────────────────── */

/* Enable/disable tracing globally.  When disabled, trace_start()
 * returns NULL and no spans are emitted.  Default: enabled.
 * Env var ZCL_TRACE_ENABLED=0 disables at startup. */
void trace_set_enabled(bool enabled);

/* Reset thread-local state.  For tests only. */
void trace_reset_thread(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_UTIL_TRACE_H */
