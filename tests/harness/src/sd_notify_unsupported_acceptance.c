/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Verify that Windows refuses unsupported systemd notifications. */
#if defined(_WIN32)
#include "util/sd_notify.h"

#include <stdio.h>

static bool called;
static bool must_not_run(void) { called = true; return true; }

int main(void)
{
    sd_notify_set_health_check(must_not_run);
    if (sd_notify_init() || sd_notify_is_active() ||
        sd_notify_watchdog_usec() != 0 || sd_notify_ready() ||
        sd_notify_watchdog_ping() || sd_notify_status("booting") ||
        sd_notify_extend_timeout_usec(1) || sd_notify_stopping("done") ||
        called)
        return 1;
    puts("sd_notify_unsupported_acceptance: PASS");
    return 0;
}
#else
typedef int sd_notify_windows_acceptance_not_built;
#endif
