/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the non-Linux build of util/self_backtrace.h (Makefile swaps this
 * in for self_backtrace.c on any ZCL_HOST_OS != Linux). The real
 * implementation's SIGRTMIN+2 handler and thread-registry walk are Linux-
 * specific, so here install() just no-ops true, dump_all() reports ENOTSUP,
 * and dump_state_json() reports installed:false with a reason string — so
 * boot.c's "self_backtrace_install failed" WARNING path stays a warning, not
 * a build break, on hosts without the live-dump surface. */

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
