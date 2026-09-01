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

/* End the span: compute duration, emit JSON via log_jsonf, pop from
 * thread-local stack, and free the span. */
void trace_end(struct trace_span *s);

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
