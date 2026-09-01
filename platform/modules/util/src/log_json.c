/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Implementation of the structured JSON log helper. */

#include "platform/time_compat.h"
#include "util/log_json.h"
#include "util/util.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static const char *level_name(enum log_json_level level)
{
    switch (level) {
    case LOG_JSON_INFO:  return "info";
    case LOG_JSON_WARN:  return "warn";
    case LOG_JSON_ERROR: return "error";
    }
    return "info";
}

size_t log_json_escape(char *out, size_t cap, const char *in)
{
    if (!out || cap == 0) return 0;
    if (!in) { out[0] = '\0'; return 0; }

    size_t pos = 0;
    for (size_t i = 0; in[i] != '\0' && pos + 2 < cap; i++) {
        unsigned char c = (unsigned char)in[i];
        switch (c) {
        case '\\': case '"':
            if (pos + 3 >= cap) goto done;
            out[pos++] = '\\';
            out[pos++] = (char)c;
            break;
        case '\b':
            if (pos + 3 >= cap) goto done;
            out[pos++] = '\\'; out[pos++] = 'b';
            break;
        case '\f':
            if (pos + 3 >= cap) goto done;
            out[pos++] = '\\'; out[pos++] = 'f';
            break;
        case '\n':
            if (pos + 3 >= cap) goto done;
            out[pos++] = '\\'; out[pos++] = 'n';
            break;
        case '\r':
            if (pos + 3 >= cap) goto done;
            out[pos++] = '\\'; out[pos++] = 'r';
            break;
        case '\t':
            if (pos + 3 >= cap) goto done;
            out[pos++] = '\\'; out[pos++] = 't';
            break;
        default:
            if (c < 0x20) {
                if (pos + 7 >= cap) goto done;
                int n = snprintf(out + pos, cap - pos, "\\u%04x", c);
                if (n < 0 || (size_t)n >= cap - pos) goto done;
                pos += (size_t)n;
            } else {
                out[pos++] = (char)c;
            }
            break;
        }
    }
done:
    out[pos] = '\0';
    return pos;
}

/* Build the JSON line into `buf`.  Returns bytes written excluding NUL.
 * Used by both log_jsonf() (which then forwards to LogPrintStr) and the
 * unit tests (via log_json_format()). */
static size_t format_v(char *buf, size_t cap, enum log_json_level level,
                        const char *event, const char *fields_fmt,
                        va_list ap)
{
    if (!buf || cap == 0) return 0;

    /* ISO-8601 microsecond timestamp in UTC. */
    struct timespec t;
    if (platform_time_realtime_timespec(&t) != 0) {
        t.tv_sec = 0;
        t.tv_nsec = 0;
    }
    struct tm tm;
    gmtime_r(&t.tv_sec, &tm);
    char ts[64];
    int ts_n = (int)strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm);
    if (ts_n <= 0) snprintf(ts, sizeof(ts), "1970-01-01T00:00:00");

    char ev_safe[64];
    log_json_escape(ev_safe, sizeof(ev_safe), event ? event : "");

    /* Render the caller-supplied fields into a stack buffer first so
     * we know whether to emit a leading comma between "event" and the
     * fields.  An empty fields_fmt or fmt that produces nothing skips
     * the comma entirely. */
    char fields[1536];
    fields[0] = '\0';
    if (fields_fmt && *fields_fmt) {
        int fn = vsnprintf(fields, sizeof(fields), fields_fmt, ap);
        if (fn < 0) fields[0] = '\0';
    }

    int n;
    if (fields[0] != '\0') {
        n = snprintf(buf, cap,
                     "{\"ts\":\"%s.%06ldZ\",\"level\":\"%s\","
                     "\"event\":\"%s\",%s}\n",
                     ts, t.tv_nsec / 1000, level_name(level),
                     ev_safe, fields);
    } else {
        n = snprintf(buf, cap,
                     "{\"ts\":\"%s.%06ldZ\",\"level\":\"%s\","
                     "\"event\":\"%s\"}\n",
                     ts, t.tv_nsec / 1000, level_name(level), ev_safe);
    }
    if (n < 0) return 0;
    if ((size_t)n >= cap) return cap - 1;
    return (size_t)n;
}

void log_jsonf(enum log_json_level level, const char *event,
                const char *fields_fmt, ...)
{
    char line[2048];
    va_list ap;
    va_start(ap, fields_fmt);
    size_t n = format_v(line, sizeof(line), level, event, fields_fmt, ap);
    va_end(ap);
    if (n > 0) (void)LogPrintStr(line);
}

size_t log_json_format(char *buf, size_t cap, enum log_json_level level,
                        const char *event, const char *fields_fmt, ...)
{
    va_list ap;
    va_start(ap, fields_fmt);
    size_t n = format_v(buf, cap, level, event, fields_fmt, ap);
    va_end(ap);
    return n;
}
