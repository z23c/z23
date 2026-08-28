/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Structured JSON logging helper.
 *
 * The legacy LogPrintf() / LogPrint() macros emit free-form printf
 * lines to the debug log.  That format is fine for humans tailing
 * `debug.log` in real time, but it makes machine consumption (Loki,
 * Vector, jq, awk, …) brittle: every grep is a new regex, every
 * field a new substring extraction, and any subtle wording change
 * silently breaks the operator's dashboard.
 *
 * `log_jsonf` writes a single-line JSON object that always carries:
 *   - "ts"     ISO-8601 microsecond timestamp (UTC, "Z" suffix)
 *   - "level"  one of "info" / "warn" / "error"
 *   - "event"  short event name (caller-supplied, e.g. "peer_connected")
 *   - <fields> caller-supplied valid JSON key/value pairs
 *
 * The fields argument is a printf-style format that the caller is
 * responsible for keeping JSON-valid.  Use `log_json_escape()` to
 * sanitise any string values that may contain quotes or backslashes.
 *
 * Example:
 *
 *   char addr[64];
 *   log_json_escape(addr, sizeof(addr), peer->addr_name);
 *   log_jsonf(LOG_JSON_INFO, "peer_connected",
 *             "\"peer_id\":%d,\"addr\":\"%s\",\"version\":%d",
 *             peer->id, addr, peer->version);
 *
 * Output:
 *
 *   {"ts":"2026-04-11T15:12:34.012345Z","level":"info",
 *    "event":"peer_connected","peer_id":7,"addr":"1.2.3.4:8033","version":170020}
 *
 * The line is appended via LogPrintStr() so it shares the same sink
 * (debug.log / stdout) as every other log message.  No new global
 * state, no thread-local buffers — re-entrancy is the same as the
 * underlying LogPrintStr().
 *
 * `log_json_escape()` performs minimal JSON-string escaping:
 * backslash, double-quote, and control characters below 0x20.  It is
 * NOT a UTF-8 validator and does not handle the surrogate pair edge
 * cases — but the strings we feed it (peer addresses, RPC method
 * names, file paths) never contain those.  Output is NUL-terminated
 * and silently truncated if it doesn't fit.
 */

#ifndef ZCL_UTIL_LOG_JSON_H
#define ZCL_UTIL_LOG_JSON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum log_json_level {
    LOG_JSON_INFO  = 0,
    LOG_JSON_WARN  = 1,
    LOG_JSON_ERROR = 2,
};

/* Emit a structured JSON line via LogPrintStr().
 *
 * `event` MUST be a stable short string (snake_case is conventional).
 * `fields_fmt` may be NULL or "" if there are no extra fields. */
__attribute__((format(printf, 3, 4)))
void log_jsonf(enum log_json_level level, const char *event,
                const char *fields_fmt, ...);

/* JSON-escape `in` into `out`.  Writes at most cap-1 bytes plus a NUL.
 * Returns the number of bytes written (excluding the NUL). */
size_t log_json_escape(char *out, size_t cap, const char *in);

/* Render the JSON line into a caller-supplied buffer instead of
 * sending it to LogPrintStr().  Used by the unit tests so they can
 * inspect the wire format without redirecting stdout.  Returns the
 * number of bytes written. */
__attribute__((format(printf, 5, 6)))
size_t log_json_format(char *buf, size_t cap, enum log_json_level level,
                        const char *event, const char *fields_fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_UTIL_LOG_JSON_H */
