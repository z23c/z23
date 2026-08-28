/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Break a time_t into UTC calendar fields.
 *
 * This is a pure C-runtime shape conversion, not a clock read: the caller
 * supplies the instant. It lives in base so lib/base/src/log_level.c can
 * timestamp a line without depending on platform -- that sink is the bottom
 * of the logging stack, and platform's own clock code logs through it.
 * platform/time_compat.h forwards to this so there is exactly one
 * definition. */
#ifndef ZCL_BASE_UTC_TM_H
#define ZCL_BASE_UTC_TM_H

#include <stdbool.h>
#include <time.h>

static inline bool zcl_utc_tm(time_t value, struct tm *out)
{
    if (!out)
        return false;
#if defined(_WIN32)
    return gmtime_s(out, &value) == 0;
#else
    return gmtime_r(&value, out) != NULL;
#endif
}

#endif /* ZCL_BASE_UTC_TM_H */
