/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: implement the shared off-systemd self-respawn decision + re-exec.
 * See engine/composition/include/config/boot_self_respawn.h for the contract. */

#include "config/boot_self_respawn.h"

#include "services/chain_tip_watchdog.h"   /* chain_tip_watchdog_respawn_requested */
#include "util/supervisor_backstop.h"      /* supervisor_backstop_respawn_requested */
#include "util/sd_notify.h"                 /* sd_notify_is_active */
#include "util/log_macros.h"
#include "platform/os_proc.h"               /* os_proc_exe_path */

#include "util/shutdown_stagewatch.h"      /* exit-reason breadcrumb */

#include <errno.h>
#include <stdatomic.h>
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

/* Set from the SIGINT/SIGTERM handler: atomic bool store only (AS-safe). */
static atomic_bool g_operator_stop_noted = false;

void boot_self_respawn_note_operator_stop(void)
{
    atomic_store(&g_operator_stop_noted, true);
}

void boot_self_respawn_clear_operator_stop_for_testing(void)
{
    atomic_store(&g_operator_stop_noted, false);
}

bool boot_self_respawn_operator_stop_exit(void)
{
    if (!atomic_load(&g_operator_stop_noted) || sd_notify_is_active())
        return false;
    shutdown_stagewatch_write_exit_reason(SHUTDOWN_EXIT_REASON_OPERATOR);
    return true;
}

static bool respawn_flag_latched(void)
{
    return chain_tip_watchdog_respawn_requested() ||
           supervisor_backstop_respawn_requested();
}

bool boot_self_respawn_armed(void)
{
    bool flagged = respawn_flag_latched();
    /* An operator stop always wins: a swallowed stop used to re-exec the
     * node, which then ran on as if nothing had been asked. */
    if (atomic_load(&g_operator_stop_noted))
        return false;
    /* Under systemd (NOTIFY_SOCKET present) Restart=always owns respawn — never
     * self-exec there, even with a flag latched. Off systemd, re-exec is the
     * only way liveness recovery happens. */
    return flagged && !sd_notify_is_active() && g_respawn_argv != NULL;
}

bool boot_self_respawn_prepare_early(void)
{
    (void)sd_notify_init();
    chain_tip_watchdog_request_respawn();
    return sd_notify_is_active() || boot_self_respawn_armed();
}

/* Test seams: a hook run just before the last operator-stop check (to land a
 * stop in the window), and a replacement for execv. NULL = production. */
static void (*g_window_hook)(void) = NULL;
static int (*g_exec_fn)(const char *, char *const[]) = NULL;

void boot_self_respawn_set_test_hooks(void (*window_hook)(void),
                                      int (*exec_fn)(const char *, char *const[]))
{
    g_window_hook = window_hook;
    g_exec_fn = exec_fn;
}

/* The operator stopped this process while a respawn was latched: the shutdown
 * breadcrumb was written from the latched flag (self_respawn_*), so record it
 * as the operator stop it is. Off systemd only: nothing changes under
 * systemd. */
static void record_declined_for_operator_stop(void)
{
    if (atomic_load(&g_operator_stop_noted) && respawn_flag_latched() &&
        !sd_notify_is_active())
        shutdown_stagewatch_write_exit_reason(SHUTDOWN_EXIT_REASON_OPERATOR);
}

void boot_self_respawn_exec_or_return(void)
{
    if (!boot_self_respawn_armed()) {
        record_declined_for_operator_stop();
        return;
    }

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
    if (g_window_hook)
        g_window_hook();
    /* Last check before execv: a stop that landed after armed() above is
     * honored here. No signal mask (it would survive execv). A stop arriving
     * in the few instructions between this load and execv is still lost, as
     * on main. */
    if (atomic_load(&g_operator_stop_noted)) {
        record_declined_for_operator_stop();
        return;
    }
    if (g_exec_fn)
        (void)g_exec_fn(exe, g_respawn_argv);
    else
        execv(exe, g_respawn_argv);
    /* execv only returns on error — fall through so a failed re-exec is at
     * worst a one-time DOWN, never a busy loop. */
    fprintf(stderr, "[main] self-respawn execv failed: %s — exiting "
            "(not looping)\n", strerror(errno));
}
