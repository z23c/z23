/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the bounds of one draining `dev land drive --prove` invocation;
 *          see native_dev_land_drain.h. */

#include "command/native_dev_land_drain.h"

#include "json/json.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <stdlib.h>

bool dl_drain_rows_in(const struct zcl_command_request *req, int *rows,
                      bool *prove)
{
    const struct json_value *m = json_get(req->input, "max_rows");
    const struct json_value *p = json_get(req->input, "prove");
    *rows = 1;
    *prove = false;
    if (p && p->type != JSON_BOOL)
        return false;
    if (p)
        *prove = json_get_bool(p);
    if (!m)
        return true;
    if (m->type != JSON_INT || json_get_int(m) < 1 ||
        json_get_int(m) > DL_DRIVE_MAX_ROWS)
        return false;
    *rows = (int)json_get_int(m);
    return true;
}

int64_t dl_drain_deadline_ms(void)
{
    const char *s = getenv("ZCL_LAND_DRIVE_BUDGET_S");
    char *end = NULL;
    long long n;
    if (!s || !*s)
        return 0;
    errno = 0;
    n = strtoll(s, &end, 10);
    if (errno || *end || n < 1 || n > 86400)
        return 0;
    return platform_time_monotonic_ms() + (int64_t)n * 1000;
}

bool dl_drain_more(int done, int max_rows, int64_t deadline_ms)
{
    return done < max_rows &&
           (deadline_ms <= 0 || platform_time_monotonic_ms() < deadline_ms);
}
