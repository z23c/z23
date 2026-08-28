/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "platform/time_compat.h"
#include "platform/os_proc.h"
#include "util/boot_phase.h"
#include "util/boot_scan.h"
#include "util/boot_status.h"
#include "util/boot_progress.h"
#include "util/sd_notify.h"
#include "health/heartbeat.h"
#include "util/sync.h"

/* One hour. Each throttled PROGRESS line (and phase BEGIN) tells systemd
 * the Type=notify start job is still alive so TimeoutStartSec cannot
 * SIGTERM a boot that is still scanning the block index or hydrating
 * coins. WatchdogSec does not run until READY=1. */
#define BOOT_PHASE_EXTEND_TIMEOUT_USEC (3600ULL * 1000000ULL)

/* Say where we are WITHOUT buying more start budget.
 *
 * An extension must be EARNED by an observable change; the passage of
 * time is not evidence of progress. Splitting the status line from the
 * deadline push is what lets a stalled reporter keep narrating (which is
 * this module's whole purpose) without also making the unit's own
 * TimeoutStartSec unreachable. */
static void boot_phase_notify_status_only(const char *status)
{
    (void)sd_notify_init();
    if (!sd_notify_is_active())
        return;
    (void)sd_notify_status(status ? status : "booting");
}

static void boot_phase_notify_progress(const char *status)
{
    boot_phase_notify_status_only(status);
    if (!sd_notify_is_active())
        return;
    (void)sd_notify_extend_timeout_usec(BOOT_PHASE_EXTEND_TIMEOUT_USEC);
}

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BOOT_PHASE_STALL_SECS (BOOT_STEP_BUDGET_MS / 1000)

/* ──────────────────────────────────────────────────────────────────
 * Boot step reporter — see util/boot_phase.h for the contract and for
 * the incident that produced it. Three observations (running / slow /
 * stuck), one terminal success (done), one terminal failure (failed);
 * elapsed time alone can never produce the failure. */

static const char *const k_boot_step_state_names[BOOT_STEP_STATE__MAX] = {
    [BOOT_STEP_RUNNING] = "running",
    [BOOT_STEP_SLOW]    = "slow",
    [BOOT_STEP_STUCK]   = "stuck",
    [BOOT_STEP_DONE]    = "done",
    [BOOT_STEP_FAILED]  = "failed",
};

const char *boot_step_state_name(enum boot_step_state s)
{
    if (s < 0 || s >= BOOT_STEP_STATE__MAX || !k_boot_step_state_names[s])
        return "(invalid)";
    return k_boot_step_state_names[s];
}

const char *boot_step_state_verdict(enum boot_step_state s)
{
    switch (s) {
    case BOOT_STEP_DONE:   return "ok";
    case BOOT_STEP_FAILED: return "failure";
    case BOOT_STEP_RUNNING:
    case BOOT_STEP_SLOW:
    case BOOT_STEP_STUCK:  return "telemetry";
    default:               return "(invalid)";
    }
}

bool boot_step_state_is_failure(enum boot_step_state s)
{
    return s == BOOT_STEP_FAILED;
}

bool boot_step_state_earns_budget(enum boot_step_state s)
{
    return s == BOOT_STEP_RUNNING || s == BOOT_STEP_SLOW;
}

enum boot_step_state boot_step_classify(int64_t elapsed_ms,
                                        int64_t budget_ms,
                                        uint64_t progress_delta)
{
    if (budget_ms <= 0)
        budget_ms = BOOT_STEP_BUDGET_MS;
    if (elapsed_ms < budget_ms)
        return BOOT_STEP_RUNNING;
    /* Over budget is NOT a failure and never becomes one here. The only
     * question left is whether the step is moving. */
    return progress_delta > 0 ? BOOT_STEP_SLOW : BOOT_STEP_STUCK;
}

/* Progress evidence = the global boot-progress marker (bumped by long
 * boot loops) PLUS step-local notes. Composed, not inferred: either
 * source advancing proves the step is moving. */
static _Atomic uint64_t g_step_notes = 0;

/* ── out-of-band evidence probe (see util/boot_phase.h) ───────────
 *
 * Two atomics rather than a lock: this is read by the heartbeat sweeper
 * while the boot thread installs or clears it, and the sweeper must
 * never be able to block on the boot thread. The fn is loaded first and
 * the ctx second; a probe whose ctx is NULL is still called (the stock
 * process-I/O probe takes no ctx), so the only torn read possible is
 * "fn from before the store, ctx from after" during the single install
 * that happens immediately after boot_step_enter, on the boot thread,
 * before the step has had 30 s to stall. Callers install a probe once
 * per step and never re-point it. */
static _Atomic(boot_evidence_probe_fn) g_evidence_fn  = NULL;
static _Atomic(void *)                 g_evidence_ctx = NULL;

static void boot_step_reseed_evidence_baseline(void);

void boot_step_set_evidence_probe(boot_evidence_probe_fn fn, void *ctx)
{
    atomic_store_explicit(&g_evidence_ctx, ctx, memory_order_relaxed);
    atomic_store_explicit(&g_evidence_fn, fn, memory_order_release);
    /* Re-seed, or installing a probe would itself look like progress: the
     * step's baseline was taken with no probe (contributing 0) and the
     * first window would otherwise diff against the probe's whole absolute
     * value and grade SLOW on the strength of I/O that predates the step.
     * An extension has to be paid for by a change DURING the window. */
    boot_step_reseed_evidence_baseline();
}

uint64_t boot_evidence_probe_process_io(void *ctx)
{
    (void)ctx;
    uint64_t bytes = 0;
    if (!os_proc_io_bytes(&bytes))
        return 0;
    return bytes / (uint64_t)BOOT_EVIDENCE_IO_QUANTUM_BYTES;
}

static uint64_t boot_step_evidence_probe_value(void)
{
    boot_evidence_probe_fn fn =
        atomic_load_explicit(&g_evidence_fn, memory_order_acquire);
    if (!fn)
        return 0;
    void *ctx = atomic_load_explicit(&g_evidence_ctx, memory_order_relaxed);
    return fn(ctx);
}

static uint64_t boot_step_evidence_count(void)
{
    return boot_progress_marker() +
           atomic_load_explicit(&g_step_notes, memory_order_relaxed) +
           boot_step_evidence_probe_value();
}

/* How much progress evidence appeared since the caller last looked.
 *
 * COMPOSED from three independent sources, because no single one covers
 * the whole boot: the boot_progress marker (bumped by the long index
 * loops), step-local notes, and boot_progress_tick's timestamp (bumped
 * by reducer ingest, node_db catchup, UTXO apply and snapshot import —
 * the subsystems that are busy during service startup and that bump no
 * counter at all). Any one of them moving means the step is moving.
 * `*seen_count` / `*seen_tick` carry the caller's previous observation
 * and are updated in place. */
static uint64_t boot_step_delta(uint64_t *seen_count, int64_t *seen_tick)
{
    uint64_t count = boot_step_evidence_count();
    int64_t  tick  = boot_progress_last_us();
    uint64_t delta = count > *seen_count ? count - *seen_count : 0;
    if (tick != *seen_tick)
        delta++;
    *seen_count = count;
    *seen_tick  = tick;
    return delta;
}

void boot_step_note(void)
{
    atomic_fetch_add_explicit(&g_step_notes, 1u, memory_order_relaxed);
    boot_progress_tick("boot_step");
}

/* Emit one typed record.
 *
 * Ordering is load-bearing: the operator line and the systemd timeout
 * extension go out FIRST, and the boot_status beacon refresh last. The
 * beacon takes a lock the (possibly wedged) boot thread can be holding,
 * and this runs on the shared heartbeat sweeper — a record that must
 * never be lost cannot be sequenced behind that lock. */
static void boot_step_emit(const char *name, enum boot_step_state st,
                           int64_t elapsed_ms, int64_t budget_ms,
                           uint64_t progress_delta, unsigned report,
                           const char *reason)
{
    const char *nm = (name && name[0]) ? name : "(unnamed)";
    /* Raw stderr, NOT LOG_INFO, and deliberately so: the LOG_* macros go
     * through the -loglevel gate (base/log_level.h), and a boot-stall
     * record that an operator can silence with -loglevel=warn recreates
     * exactly the silence this module exists to end. journald timestamps
     * the line. Keep the rest of the module's raw-stderr convention too.
     *
     * `reason` is the only free-text field, so it is quoted: the record
     * stays one parseable key=value line even when the reason has
     * spaces in it. */
    fprintf(stderr,  // obs-ok:boot-step-record-observed-via-heartbeat
        "[boot-step] step=%s state=%s verdict=%s elapsed_ms=%lld "
        "budget_ms=%lld progress_delta=%llu report=%u%s%s%s\n",
        nm, boot_step_state_name(st), boot_step_state_verdict(st),
        (long long)elapsed_ms, (long long)budget_ms,
        (unsigned long long)progress_delta, report,
        reason ? " reason=\"" : "", reason ? reason : "",
        reason ? "\"" : "");
    fflush(stderr);

    if (st == BOOT_STEP_FAILED)
        return;

    /* A step that is merely SLOW must buy MORE start budget by saying so,
     * never less. This is what keeps a 7200 rpm box from being killed for
     * being honest about its disk.
     *
     * A STUCK step must NOT. STUCK is precisely "over budget AND zero
     * progress this window" (boot_step_classify), and boot_step_on_stall
     * re-arms the health ring every BOOT_PHASE_STALL_SECS, so extending
     * here would push TimeoutStartSec out by an hour every 30 s for as
     * long as the wedge lasts — making the deadline unreachable and the
     * unit's own Restart=always unable to ever recover a wedged boot.
     * That is the failure this file exists to make visible, so it must
     * not be the failure this file makes permanent.
     *
     * Withholding the extension does not kill anything: the deadline
     * simply stays where the last real progress put it, which leaves a
     * full BOOT_PHASE_EXTEND_TIMEOUT_USEC of grace measured from that
     * progress. The record above is still emitted either way — telemetry
     * is unconditional, budget is earned. */
    char status[200];
    snprintf(status, sizeof(status), "boot %s %s %llds",
             nm, boot_step_state_name(st), (long long)(elapsed_ms / 1000));
    if (boot_step_state_earns_budget(st))
        boot_phase_notify_progress(status);
    else
        boot_phase_notify_status_only(status);
    boot_status_heartbeat();
}

/* ── the tracked current step ─────────────────────────────────────
 * ONE registration for the whole boot, whose name is re-pointed at each
 * step boundary. A per-step register/unregister pair would leak a
 * phantom ring entry on every early `return false` out of the boot
 * path; this cannot. */
static zcl_mutex_t         g_step_mu;
static zcl_once_t          g_step_mu_once = ZCL_ONCE_INIT;
static char                g_step_name[BOOT_PHASE_NAME_MAX];
static int64_t             g_step_start_ms     = 0;
static uint64_t            g_step_seen_count   = 0;
static int64_t             g_step_seen_tick_us = 0;
static unsigned            g_step_reports      = 0;
static bool                g_step_active       = false;
static health_subsystem_id g_step_health_id    = HEALTH_INVALID_ID;

static void boot_step_mutex_init(void) { zcl_mutex_init(&g_step_mu); }
static void boot_step_mutex_lock(void)
{
    (void)zcl_once_call(&g_step_mu_once, boot_step_mutex_init);
    zcl_mutex_lock(&g_step_mu);
}

/* g_step_mu guards the whole record — name, clock, evidence baseline,
 * report counter — because the boot thread rewrites it at each step
 * boundary while the heartbeat sweeper reads it from another thread.
 * The critical section is a few stores and takes no other lock, so it
 * can never itself be the thing that wedges. */

/* Re-take the open step's evidence baseline. Called when a probe is
 * installed or cleared so the next window measures change since that
 * moment. No-op when no step is open — a boot_phase seeds its own
 * baseline in boot_phase_begin. */
static void boot_step_reseed_evidence_baseline(void)
{
    boot_step_mutex_lock();
    if (g_step_active)
        (void)boot_step_delta(&g_step_seen_count, &g_step_seen_tick_us);
    zcl_mutex_unlock(&g_step_mu);
}

/* One consistent snapshot of the open step, advancing its bookkeeping.
 * Returns false when no step is open. */
static bool boot_step_snapshot(char *name, size_t cap, int64_t *elapsed_ms,
                               uint64_t *delta, unsigned *report)
{
    boot_step_mutex_lock();
    if (!g_step_active) {
        zcl_mutex_unlock(&g_step_mu);
        return false;
    }
    snprintf(name, cap, "%s", g_step_name);
    *elapsed_ms = platform_time_monotonic_ms() - g_step_start_ms;
    *delta      = boot_step_delta(&g_step_seen_count, &g_step_seen_tick_us);
    *report     = ++g_step_reports;
    zcl_mutex_unlock(&g_step_mu);
    return true;
}

/* One stall report for the open step. `elapsed_override_ms >= 0` reports
 * that elapsed instead of the step's own clock — the ONLY caller that
 * passes one is the test hook, so a test need not wait out the budget.
 * Returns the state reported, or BOOT_STEP_STATE__MAX if no step is open. */
static enum boot_step_state boot_step_stall_report(int64_t elapsed_override_ms)
{
    char     name[BOOT_PHASE_NAME_MAX];
    int64_t  elapsed = 0;
    uint64_t delta   = 0;
    unsigned report  = 0;
    if (!boot_step_snapshot(name, sizeof(name), &elapsed, &delta, &report))
        return BOOT_STEP_STATE__MAX;
    if (elapsed_override_ms >= 0)
        elapsed = elapsed_override_ms;
    enum boot_step_state st =
        boot_step_classify(elapsed, BOOT_STEP_BUDGET_MS, delta);
    boot_step_emit(name, st, elapsed, BOOT_STEP_BUDGET_MS, delta, report, NULL);
    return st;
}

static void boot_step_on_stall(void *ctx)
{
    (void)ctx;
    if (boot_step_stall_report(-1) == BOOT_STEP_STATE__MAX)
        return;

    /* Re-arm. The health ring is edge-triggered: without a fresh
     * heartbeat a stalled entry fires exactly once, which is how a
     * four-hour hang produced one line and then silence. */
    health_heartbeat(g_step_health_id);
}

#ifdef ZCL_TESTING
enum boot_step_state boot_step_stall_report_for_testing(int64_t elapsed_ms)
{
    return boot_step_stall_report(elapsed_ms < 0 ? 0 : elapsed_ms);
}
#endif

static void boot_step_close(enum boot_step_state st, const char *reason)
{
    char     name[BOOT_PHASE_NAME_MAX];
    int64_t  elapsed;
    unsigned report;
    health_subsystem_id id;

    boot_step_mutex_lock();
    if (!g_step_active) {
        zcl_mutex_unlock(&g_step_mu);
        return;
    }
    g_step_active = false;
    snprintf(name, sizeof(name), "%s", g_step_name);
    elapsed = platform_time_monotonic_ms() - g_step_start_ms;
    report  = g_step_reports;
    id      = g_step_health_id;
    g_step_health_id = HEALTH_INVALID_ID;
    zcl_mutex_unlock(&g_step_mu);

    /* Outside g_step_mu — the setter re-seeds the open step's baseline and
     * takes that same non-recursive lock. Safe here because g_step_active
     * is already false, so the re-seed is a no-op. The probe belongs to the
     * step, not to boot: clearing it is what lets an early `return false`
     * out of the boot path be safe, and stops one step's evidence from
     * being read as the next step's. */
    boot_step_set_evidence_probe(NULL, NULL);

    if (id != HEALTH_INVALID_ID)
        health_unregister(id);
    boot_step_emit(name, st, elapsed, BOOT_STEP_BUDGET_MS, 0, report, reason);
}

void boot_step_enter(const char *name)
{
    /* A new step implicitly ends the previous one (which clears its
     * evidence probe). Clear again so entering a step with none open
     * also starts from a known-empty probe. */
    boot_step_close(BOOT_STEP_DONE, NULL);
    boot_step_set_evidence_probe(NULL, NULL);
    (void)health_start();  /* idempotent; only the first call spawns it */

    char nm[BOOT_PHASE_NAME_MAX];
    boot_step_mutex_lock();
    snprintf(g_step_name, sizeof(g_step_name), "%s",
             (name && name[0]) ? name : "(unnamed)");
    snprintf(nm, sizeof(nm), "%s", g_step_name);
    g_step_start_ms = platform_time_monotonic_ms();
    g_step_reports  = 0;
    g_step_active   = true;
    /* Seed the baseline so the first record diffs against THIS step's
     * start, not against zero — otherwise every step would open by
     * claiming the progress some earlier step made. */
    (void)boot_step_delta(&g_step_seen_count, &g_step_seen_tick_us);
    g_step_health_id = health_register("boot_step", BOOT_PHASE_STALL_SECS,
                                       boot_step_on_stall, NULL);
    zcl_mutex_unlock(&g_step_mu);

    boot_step_emit(nm, BOOT_STEP_RUNNING, 0, BOOT_STEP_BUDGET_MS, 0, 0, NULL);
}

void boot_step_done(void)
{
    boot_step_close(BOOT_STEP_DONE, NULL);
}

bool boot_step_fail(const char *reason)
{
    boot_step_close(BOOT_STEP_FAILED, reason ? reason : "unspecified");
    return false;  /* so a caller can report and return in one statement */
}

/* ────────────────────────────────────────────────────────────────── */

static void boot_phase_on_stall(void *ctx)
{
    struct boot_phase *p = (struct boot_phase *)ctx;
    if (!p) return;
    int64_t elapsed = platform_time_monotonic_ms() - p->start_ms;
    uint64_t delta = boot_step_delta(&p->evidence_seen, &p->evidence_tick_us);
    p->reports++;
    boot_step_emit(p->name,
                   boot_step_classify(elapsed, BOOT_STEP_BUDGET_MS, delta),
                   elapsed, BOOT_STEP_BUDGET_MS, delta, p->reports, NULL);
    /* Re-arm so an over-budget phase keeps reporting once per budget
     * window instead of going quiet after the first edge. */
    health_heartbeat(p->health_id);
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
    /* Seed the evidence baseline so the FIRST over-budget record diffs
     * against this phase's own start, not against zero (which would
     * report every phase as `slow` on the strength of progress some
     * earlier phase made). */
    (void)boot_step_delta(&p->evidence_seen, &p->evidence_tick_us);
    p->reports = 0;

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
