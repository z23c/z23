/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * See lib/base/include/base/log_level.h for the contract. */

#include "base/log_level.h"
#include "base/utc_tm.h"
#include "base/stdio_lock.h"

#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static atomic_int g_zcl_log_level = ZCL_LOG_ALL;

void zcl_log_level_set(enum zcl_log_level level)
{
    atomic_store_explicit(&g_zcl_log_level, (int)level, memory_order_relaxed);
}

enum zcl_log_level zcl_log_level_get(void)
{
    return (enum zcl_log_level)
        atomic_load_explicit(&g_zcl_log_level, memory_order_relaxed);
}

bool zcl_log_level_from_string(const char *s, enum zcl_log_level *out)
{
    if (!s || !out)
        return false;

    if (!strcmp(s, "all"))   { *out = ZCL_LOG_ALL;   return true; }
    if (!strcmp(s, "info"))  { *out = ZCL_LOG_INFO;  return true; }
    if (!strcmp(s, "warn"))  { *out = ZCL_LOG_WARN;  return true; }
    if (!strcmp(s, "error")) { *out = ZCL_LOG_ERROR; return true; }
    if (!strcmp(s, "fatal")) { *out = ZCL_LOG_FATAL; return true; }
    if (!strcmp(s, "off"))   { *out = ZCL_LOG_OFF;   return true; }

    return false;
}

/* The token nodelog_controller.c parses positionally right after the
 * timestamp. Keep in sync with line_level() there. */
static const char *zcl_log_level_token(enum zcl_log_level level)
{
    switch (level) {
    case ZCL_LOG_WARN:  return "WARN";
    case ZCL_LOG_ERROR: return "ERROR";
    case ZCL_LOG_FATAL: return "FATAL";
    default:            return "INFO"; /* ZCL_LOG_INFO / ZCL_LOG_ALL / OFF */
    }
}

void zcl_log_emit_at(enum zcl_log_level level, const char *fmt, ...)
{
    /* ISO-8601 UTC, second precision: the reverse-scan parser in
     * nodelog_controller.c accepts exactly this shape at line start. */
    char ts[24];
    /* Deliberately NOT platform.clock: this sink is the bottom of the
     * logging stack — clock/rng code must be able to LOG_* without a
     * circular dependency, and small tool binaries (zclassic-cli) link
     * log_level.c without the platform clock objects. */
    time_t now = time(NULL);  // platform-ok:leaf-log-sink-no-clock-dependency
    struct tm tmv;
    if (zcl_utc_tm(now, &tmv) &&
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tmv) > 0) {
        /* ts ready */
    } else {
        memcpy(ts, "1970-01-01T00:00:00Z", sizeof("1970-01-01T00:00:00Z"));
    }

    /* One flockfile'd sequence: the prefix and the body stay a single
     * unbroken line even with many LOG_* threads racing on stderr. */
    zcl_stdio_lock(stderr);
    (void)fprintf(stderr,  // obs-ok:log-sink-is-the-observable-surface
                  "%s %s ", ts, zcl_log_level_token(level));
    va_list ap;
    va_start(ap, fmt);
    (void)vfprintf(stderr,  // obs-ok:log-sink-is-the-observable-surface
                   fmt, ap);
    va_end(ap);
    zcl_stdio_unlock(stderr);
}
