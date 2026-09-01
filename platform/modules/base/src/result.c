/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * struct zcl_result constructors — formats the failure message, code, and
 * originating file:line carried by every service-layer error return.
 * See platform/modules/base/include/base/result.h for the contract. */

#include "base/result.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static void zcl_result_set_literal(struct zcl_result *r, const char *message)
{
    size_t len = strlen(message);
    if (len >= sizeof(r->message))
        len = sizeof(r->message) - 1;
    memcpy(r->message, message, len);
    r->message[len] = '\0';
}

struct zcl_result zcl_result_make(int code, const char *file, int line,
                                   const char *fmt, ...)
{
    struct zcl_result r = {
        .ok          = false,
        .code        = code,
        .source_file = file,
        .source_line = line,
    };
    r.message[0] = '\0';

    if (!fmt) {
        zcl_result_set_literal(&r, "<zcl_result: missing format>");
        return r;
    }

    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(r.message, sizeof(r.message), fmt, ap);
    va_end(ap);

    if (n < 0) {
        /* Formatting failure: degrade to a safe marker so callers
         * still see a non-empty message. */
        zcl_result_set_literal(&r, "<zcl_result: vsnprintf failed>");
    } else if ((size_t)n >= sizeof(r.message)) {
        /* Truncation: keep the leading bytes vsnprintf wrote but make
         * the truncation visible so operators aren't misled by a
         * silently cut error string. */
        const char marker[] = "...[truncated]";
        size_t keep = sizeof(r.message) - sizeof(marker);
        memcpy(r.message + keep, marker, sizeof(marker));
    }

    return r;
}
