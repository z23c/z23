/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Report self-backtrace unavailability on unsupported platforms. */

#include "util/self_backtrace.h"

#include "json/json.h"

#include <errno.h>

bool self_backtrace_install(void)
{
    return true;
}

int self_backtrace_dump_all(char *path_out, size_t cap)
{
    if (path_out && cap)
        path_out[0] = '\0';
    errno = ENOTSUP;
    return -1;
}

bool self_backtrace_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);
    json_push_kv_bool(out, "installed", false);
    json_push_kv_str(out, "unavailable_reason",
                     "cross-thread signal backtraces are unavailable on this platform");
    return true;
}
