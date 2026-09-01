/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: off-systemd in-process self-respawn (S7 / Pillar 7 liveness
 * recovery) — the ONE place that decides "re-exec /proc/self/exe" and does it,
 * shared by every clean-shutdown exit point so no early exit silently drops a
 * latched respawn request. */

#ifndef ZCL_CONFIG_BOOT_SELF_RESPAWN_H
#define ZCL_CONFIG_BOOT_SELF_RESPAWN_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* LIVE INCIDENT this closes: an "orderly shutdown + self-respawn" (latched by
 * the chain-tip watchdog on a genuine-liveness stall, by the supervisor
 * backstop on a frozen root sweep, or by the checkpoint-bundle install-ready
 * condition arming an install-on-next-boot) must re-exec the binary in-process
 * when there is NO systemd NOTIFY_SOCKET, so liveness recovery does not depend
 * on Restart=always. But TWO shutdown paths reach _exit() WITHOUT returning to
 * engine/entry/main.c's post-app_shutdown() re-exec:
 *   1. engine/composition/src/boot_services_shutdown.c's straggler guard — a background
 *      worker missed its bounded join window, so the destructive frees are
 *      skipped and the process _exit(0)s early (all durable state is already
 *      persisted at that point).
 *   2. (historically) a shutdown-stage deadline force-_exit()ing from the
 *      alarm handler.
 * Off systemd, either early exit left the node DOWN — the re-exec never ran.
 * This module lets those exit points honor the request themselves: re-exec is
 * strictly SAFER than the frees the straggler guard skips (execv atomically
 * discards the detached worker threads, so there is no use-after-free window),
 * and it is the exact recovery systemd's Restart=always would perform. Under
 * systemd the guard here refuses (sd_notify_is_active()==true), so Restart=
 * always stays the sole authority and no self-exec happens. */

/* Record the process argv once, at node-mode entry (engine/entry/main.c), so a later
 * re-exec can pass the identical command line. Idempotent; a NULL disarms. */
void boot_self_respawn_set_argv(char **argv);

/* True iff a self-respawn is armed right now: a respawn flag is latched
 * (chain_tip_watchdog_respawn_requested() || supervisor_backstop_respawn_
 * requested()), there is NO systemd notify socket (sd_notify_is_active()==
 * false), and argv was captured. Reads only atomics + a cached global, so it
 * is safe to call during or after app_shutdown(). */
bool boot_self_respawn_armed(void);

/* If armed(), re-exec /proc/self/exe with the captured argv (never returns on
 * success). Returns to the caller ONLY when NOT armed, or when execv failed
 * (logged) — the caller then continues to its normal exit, so a failed
 * re-exec is at worst a one-time DOWN, never a busy loop. The persisted,
 * bounded restart budget (progress.kv, reloaded by the fresh boot) bounds the
 * respawn identically to a systemd restart. */
void boot_self_respawn_exec_or_return(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONFIG_BOOT_SELF_RESPAWN_H */
