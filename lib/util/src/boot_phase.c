/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "platform/time_compat.h"
#include "util/boot_phase.h"
#include "util/boot_scan.h"
#include "util/boot_status.h"
#include "util/boot_progress.h"
#include "util/sd_notify.h"
#include "health/heartbeat.h"

/* One hour. Each throttled PROGRESS line (and phase BEGIN) tells systemd
 * the Type=notify start job is still alive so TimeoutStartSec cannot
 * SIGTERM a boot that is still scanning the block index or hydrating
 * coins. WatchdogSec does not run until READY=1. */
#define BOOT_PHASE_EXTEND_TIMEOUT_USEC (3600ULL * 1000000ULL)

static void boot_phase_notify_progress(const char *status)
{
    (void)sd_notify_init();
    if (!sd_notify_is_active())
        return;
    (void)sd_notify_status(status ? status : "booting");
    (void)sd_notify_extend_timeout_usec(BOOT_PHASE_EXTEND_TIMEOUT_USEC);
}

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BOOT_PHASE_STALL_SECS 30

static void boot_phase_on_stall(void *ctx)
{
    struct boot_phase *p = (struct boot_phase *)ctx;
    if (!p) return;
    int64_t elapsed = platform_time_monotonic_ms() - p->start_ms;
    fprintf(stderr,  // obs-ok:boot-phase-stall-observed-via-heartbeat
        "[boot-phase] STALL %s %lldms (no progress reported)\n",
        p->name, (long long)elapsed);
    fflush(stderr);
}

void boot_phase_begin(struct boot_phase *p, const char *name)
{
    if (!p) return;
    memset(p, 0, sizeof(*p));
    if (name) {
        size_t n = strlen(name);
        if (n >= BOOT_PHASE_NAME_MAX) n = BOOT_PHASE_NAME_MAX - 1;
        memcpy(p->name, name, n);
        p->name[n] = '\0';
    } else {
        snprintf(p->name, sizeof(p->name), "(unnamed)");
    }
    p->start_ms = platform_time_monotonic_ms();
    p->health_id = HEALTH_INVALID_ID;

    fprintf(stderr, "[boot-phase] BEGIN %s\n", p->name);  // obs-ok:boot-phase-trace-marker
    fflush(stderr);
    boot_phase_notify_progress(p->name);

    /* Lazy-start the heartbeat sweeper. health_start() is idempotent
     * so multiple boot phases (or other subsystems) calling it is
     * fine — only the first one spawns the thread. Production boot
     * paths don't need a separate health_start() call. */
    (void)health_start();

    /* Register so that the heartbeat sweeper fires our stall callback
     * if the phase hasn't ended within BOOT_PHASE_STALL_SECS. We do
     * not heartbeat — the entry is unregistered on phase end. */
    p->health_id = health_register(p->name, BOOT_PHASE_STALL_SECS,
                                    boot_phase_on_stall, p);
}

void boot_phase_end(struct boot_phase *p)
{
    if (!p) return;
    int64_t elapsed = platform_time_monotonic_ms() - p->start_ms;
    if (p->health_id != HEALTH_INVALID_ID) {
        health_unregister(p->health_id);
        p->health_id = HEALTH_INVALID_ID;
    }
    /* If a boot-scan counter was registered under this phase's exact name,
     * report the rows it scanned right next to the ms line so an O(chain)
     * phase is visible at a glance in node.log. Phases that count nothing
     * (fixed-size work) print the plain ms line. */
    uint64_t rows = boot_scan_value(p->name);
    if (rows > 0)
        fprintf(stderr,  // obs-ok:boot-phase-trace-marker
                "[boot-phase] END %s %lldms (%llu rows scanned)\n",
                p->name, (long long)elapsed, (unsigned long long)rows);
    else
        fprintf(stderr, "[boot-phase] END %s %lldms\n",  // obs-ok:boot-phase-trace-marker
                p->name, (long long)elapsed);
    fflush(stderr);
}

/* ──────────────────────────────────────────────────────────────────
 * Boot progress marker (the boot-liveness feed for supervisor_backstop).
 * See util/boot_phase.h for the full rationale. */

static _Atomic uint64_t g_boot_progress          = 0;
static _Atomic int64_t  g_boot_progress_log_ms   = 0;

uint64_t boot_progress_marker(void)
{
    return atomic_load_explicit(&g_boot_progress, memory_order_relaxed);
}

void boot_progress_note(const char *label, uint64_t done, uint64_t total)
{
    /* Bump the liveness counter EVERY call — this is what the
     * supervisor_backstop watches to tell a progressing boot loop apart
     * from a genuinely frozen supervisor sweep. Cheap: one relaxed add. */
    atomic_fetch_add_explicit(&g_boot_progress, 1u, memory_order_relaxed);
    boot_progress_tick(label);

    /* Operator-visible progress line, throttled to ~1/s so a loop that
     * pumps every N entries never floods node.log. The CAS ensures only
     * one caller prints per window even if boot ever pumps concurrently. */
    int64_t now  = platform_time_monotonic_ms();
    int64_t last = atomic_load_explicit(&g_boot_progress_log_ms,
                                        memory_order_relaxed);
    if (now - last < 1000)
        return;
    if (!atomic_compare_exchange_strong_explicit(
            &g_boot_progress_log_ms, &last, now,
            memory_order_relaxed, memory_order_relaxed))
        return;

    if (total > 0)
        fprintf(stderr,  // obs-ok:boot-phase-trace-marker
            "[boot-phase] PROGRESS %s %llu/%llu (%llu%%)\n",
            label ? label : "(unnamed)",
            (unsigned long long)done, (unsigned long long)total,
            (unsigned long long)(done * 100 / total));
    else
        fprintf(stderr,  // obs-ok:boot-phase-trace-marker
            "[boot-phase] PROGRESS %s %llu\n",
            label ? label : "(unnamed)", (unsigned long long)done);
    fflush(stderr);
    boot_status_heartbeat();

    char status[160];
    if (total > 0)
        snprintf(status, sizeof(status), "boot %s %llu/%llu",
                 label ? label : "(unnamed)",
                 (unsigned long long)done, (unsigned long long)total);
    else
        snprintf(status, sizeof(status), "boot %s %llu",
                 label ? label : "(unnamed)", (unsigned long long)done);
    boot_phase_notify_progress(status);
}

/* ──────────────────────────────────────────────────────────────────
 * Boot stage state machine (Campaign C1).
 *
 * Stored as a single global; boot is single-threaded by design (the
 * watchdog spawns threads only after STAGE_SERVICES_RUNNING).
 */

static enum boot_stage g_boot_stage = BOOT_STAGE_INIT;

static const char *const k_boot_stage_names[BOOT_STAGE__MAX] = {
    [BOOT_STAGE_INIT]                = "init",
    [BOOT_STAGE_DATADIR_LOCKED]      = "datadir_locked",
    [BOOT_STAGE_CRYPTO_READY]        = "crypto_ready",
    [BOOT_STAGE_DB_OPEN]             = "db_open",
    [BOOT_STAGE_WALLET_LOADED]       = "wallet_loaded",
    [BOOT_STAGE_BLOCK_INDEX_LOADED]  = "block_index_loaded",
    [BOOT_STAGE_CHAIN_TIP_RESOLVED]  = "chain_tip_resolved",
    [BOOT_STAGE_NETWORK_READY]       = "network_ready",
    [BOOT_STAGE_SERVICES_RUNNING]    = "services_running",
    [BOOT_STAGE_READY]               = "ready",
    [BOOT_STAGE_SHUTDOWN_REQUESTED]  = "shutdown_requested",
    [BOOT_STAGE_SHUTDOWN_COMPLETE]   = "shutdown_complete",
};

const char *boot_stage_name(enum boot_stage s)
{
    if (s < 0 || s >= BOOT_STAGE__MAX || !k_boot_stage_names[s])
        return "(invalid)";
    return k_boot_stage_names[s];
}

enum boot_stage boot_stage_current(void)
{
    return g_boot_stage;
}

bool boot_stage_is(enum boot_stage s)
{
    return g_boot_stage == s;
}

void boot_stage_advance_to(enum boot_stage next)
{
    if (next < 0 || next >= BOOT_STAGE__MAX) {
        fprintf(stderr,  // obs-ok:boot-stage-fatal-precedes-abort
            "[boot-stage] FATAL invalid target stage %d (max %d)\n",
            (int)next, (int)BOOT_STAGE__MAX);
        fflush(stderr);
        abort(); // abort-ok: a stage outside the enum is a caller bug, not input; the void return leaves no way to refuse it
    }

    if (next == g_boot_stage)
        return; /* idempotent no-op */

    /* Shutdown stages may be entered from any forward stage — the
     * operator can halt the node mid-boot. Within the shutdown range,
     * advance is strictly monotonic. */
    if (next == BOOT_STAGE_SHUTDOWN_REQUESTED &&
        g_boot_stage < BOOT_STAGE_SHUTDOWN_REQUESTED) {
        fprintf(stderr, "[boot-stage] %s -> %s (shutdown from %s)\n",  // obs-ok:boot-stage-trace-marker
            boot_stage_name(g_boot_stage), boot_stage_name(next),
            boot_stage_name(g_boot_stage));
        fflush(stderr);
        g_boot_stage = next;
        boot_status_note_stage((int)next);
        return;
    }

    /* Backward moves are always a misorder — abort. The whole point of
     * this state machine is to catch "we accidentally re-entered an
     * earlier phase" or "two unrelated paths advanced to incompatible
     * stages". */
    if (next < g_boot_stage) {
        fprintf(stderr,  // obs-ok:boot-stage-fatal-precedes-abort
            "[boot-stage] FATAL misorder: cannot move BACKWARD %s -> %s. "
            "See BOOT_INVARIANTS.md.\n",
            boot_stage_name(g_boot_stage), boot_stage_name(next));
        fflush(stderr);
        abort(); // abort-ok: catching a re-entered boot phase is this state machine's whole purpose; continuing runs stage work against the wrong guarantees
    }

    /* Forward by one is the normal step. */
    if (next == (enum boot_stage)(g_boot_stage + 1)) {
        fprintf(stderr, "[boot-stage] %s -> %s\n",  // obs-ok:boot-stage-trace-marker
            boot_stage_name(g_boot_stage), boot_stage_name(next));
        fflush(stderr);
        g_boot_stage = next;
        boot_status_note_stage((int)next);
        return;
    }

    /* Forward by more than one is a "skipped" stage. We log it as a
     * warning so future wiring can fill in the gap, but don't abort —
     * incremental adoption of the state machine across `app_init` is
     * the explicit goal. */
    fprintf(stderr,  // obs-ok:boot-stage-warn-incremental-wiring
        "[boot-stage] WARN forward-jump %s -> %s (skipped %d intermediate). "
        "Wire the intermediate boundaries to tighten the invariant.\n",
        boot_stage_name(g_boot_stage), boot_stage_name(next),
        (int)(next - g_boot_stage - 1));
    fflush(stderr);
    g_boot_stage = next;
    boot_status_note_stage((int)next);
}

#ifdef ZCL_TESTING
void boot_stage_reset_for_testing(void)
{
    g_boot_stage = BOOT_STAGE_INIT;
}
#endif
