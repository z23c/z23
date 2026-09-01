/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: implement the shared off-systemd self-respawn decision + re-exec.
 * See engine/composition/include/config/boot_self_respawn.h for the contract and the live
 * incident this closes. */

#include "config/boot_self_respawn.h"

#include "services/chain_tip_watchdog.h"   /* chain_tip_watchdog_respawn_requested */
#include "util/supervisor_backstop.h"      /* supervisor_backstop_respawn_requested */
#include "util/sd_notify.h"                 /* sd_notify_is_active */
#include "util/log_macros.h"
#include "platform/os_proc.h"               /* os_proc_exe_path */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Captured at node-mode entry (engine/entry/main.c). Only ever read/execv'd on the
 * single-threaded shutdown path, so a plain pointer is sufficient. */
static char **g_respawn_argv = NULL;

void boot_self_respawn_set_argv(char **argv)
{
    g_respawn_argv = argv;
}

bool boot_self_respawn_armed(void)
{
    bool flagged = chain_tip_watchdog_respawn_requested() ||
                   supervisor_backstop_respawn_requested();
    /* Under systemd (NOTIFY_SOCKET present) Restart=always owns respawn — never
     * self-exec there, even with a flag latched. Off systemd, re-exec is the
     * only way liveness recovery happens. */
    return flagged && !sd_notify_is_active() && g_respawn_argv != NULL;
}

void boot_self_respawn_exec_or_return(void)
{
    if (!boot_self_respawn_armed())
        return;

    char exe[4096];
    if (!os_proc_exe_path(exe, sizeof(exe))) {
        LOG_WARN("shutdown",
                 "self-respawn: could not resolve /proc/self/exe — exiting "
                 "(not looping)");
        return;
    }

    /* Keep this exact "[main] self-respawn: re-exec" prefix: the cold-start
     * stopwatch harness and boot-flight tests key off it. */
    fprintf(stderr,
            "[main] self-respawn: re-exec %s (off-systemd liveness recovery; "
            "bounded by the persisted restart budget)\n", exe);
    fflush(NULL);
    execv(exe, g_respawn_argv);
    /* execv only returns on error — fall through so a failed re-exec is at
     * worst a one-time DOWN, never a busy loop. */
    fprintf(stderr, "[main] self-respawn execv failed: %s — exiting "
            "(not looping)\n", strerror(errno));
}
