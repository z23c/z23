/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_phase — per-step stall logger for the boot sequence.
 *
 * A scoped wrapper around a boot step that:
 *   * logs `[boot-phase] BEGIN <name>` at start
 *   * registers a 30s stall entry in lib/health so if the phase
 *     hangs, `[boot-phase] STALL <name> <elapsed_ms>ms` appears in
 *     node.log on the heartbeat sweeper's tick (~1s after the
 *     deadline)
 *   * logs `[boot-phase] END <name> <elapsed_ms>ms` on completion,
 *     unregistering the health entry
 *
 * Usage:
 *   struct boot_phase p;
 *   boot_phase_begin(&p, "block_index_load");
 *   ... slow work ...
 *   boot_phase_end(&p);
 *
 * Before this module used the unified watchdog, every boot phase
 * spawned its own pthread that polled an atomic flag. With ~10 boot
 * phases that was 10 transient threads. After: zero. The heartbeat
 * sweeper (lib/health) does the work for all of them, and operator
 * visibility (STALL fires once per phase that exceeds 30s) is
 * preserved. */

#ifndef ZCL_BOOT_PHASE_H
#define ZCL_BOOT_PHASE_H

#include "health/heartbeat.h"

#include <stdbool.h>
#include <stdint.h>

#define BOOT_PHASE_NAME_MAX 64

struct boot_phase {
    char                name[BOOT_PHASE_NAME_MAX];
    int64_t             start_ms;
    health_subsystem_id health_id;
    /* Stall-report bookkeeping: the progress evidence as of the previous
     * report (a counter and a tick timestamp — see boot_step_delta), and
     * how many reports this phase has emitted. A phase whose evidence
     * advanced between two reports is SLOW, not STUCK — see the boot
     * step reporter below. */
    uint64_t            evidence_seen;
    int64_t             evidence_tick_us;
    unsigned            reports;
};

void boot_phase_begin(struct boot_phase *p, const char *name);
void boot_phase_end(struct boot_phase *p);

/* ──────────────────────────────────────────────────────────────────
 * Coarse-grained boot ordering invariants (Campaign C1).
 *
 * `app_init` historically grew to ~2,100 LOC of sequential side
 * effects across 30+ named `boot_step_*` functions plus inline
 * wallet/chain logic. The load-bearing ordering invariants
 * (e.g., "coins.db must commit before block_index fsync") lived in
 * commit messages, not the type system, and a misorder produced
 * silent corruption rather than a compile-time error.
 *
 * `boot_stage_advance_to()` codifies the major boundaries:
 *
 *   STAGE_INIT  → process barely up — signal handlers + log only.
 *   STAGE_DATADIR_LOCKED  → datadir picked, lock file held, chain
 *                           params selected, unclean shutdown detected.
 *   STAGE_CRYPTO_READY  → ECC + SHA self-tests passed, main_state
 *                         initialized.
 *   STAGE_DB_OPEN  → node.db + coins.db opened, migrations applied.
 *   STAGE_WALLET_LOADED  → wallet keys read, canary self-test OK,
 *                          STATE D/E/F invariants satisfied.
 *   STAGE_BLOCK_INDEX_LOADED  → block_index loaded from LevelDB.
 *   STAGE_CHAIN_TIP_RESOLVED  → tip established, CSR consistent.
 *   STAGE_NETWORK_READY  → connman + peer manager initialized.
 *   STAGE_SERVICES_RUNNING  → background services (disk monitor,
 *                             ibd throttle, db maintenance) started.
 *   STAGE_READY  → HTTPS + RPC listening, accepting requests.
 *   STAGE_SHUTDOWN_REQUESTED  → app_shutdown entered.
 *   STAGE_SHUTDOWN_COMPLETE  → resources released.
 *
 * Each `boot_stage_advance_to(next)` call asserts the current stage
 * is the immediate predecessor (or equal — idempotent re-advance is
 * a no-op). A misorder calls `abort()` with a precise diagnostic so
 * the bug surfaces at the failing call site, not as later silent
 * corruption.
 *
 * Cross-reference: BOOT_INVARIANTS.md documents what each stage
 * guarantees about global state.
 */
enum boot_stage {
    BOOT_STAGE_INIT = 0,
    BOOT_STAGE_DATADIR_LOCKED,
    BOOT_STAGE_CRYPTO_READY,
    BOOT_STAGE_DB_OPEN,
    BOOT_STAGE_WALLET_LOADED,
    BOOT_STAGE_BLOCK_INDEX_LOADED,
    BOOT_STAGE_CHAIN_TIP_RESOLVED,
    BOOT_STAGE_NETWORK_READY,
    BOOT_STAGE_SERVICES_RUNNING,
    BOOT_STAGE_READY,
    BOOT_STAGE_SHUTDOWN_REQUESTED,
    BOOT_STAGE_SHUTDOWN_COMPLETE,
    BOOT_STAGE__MAX
};

const char *boot_stage_name(enum boot_stage s);
enum boot_stage boot_stage_current(void);

/* Advance to `next`. Aborts unless the current stage is `next` (no-op)
 * or `next - 1` (normal forward step). Shutdown stages may also be
 * entered from any non-shutdown stage (operator may halt mid-boot). */
void boot_stage_advance_to(enum boot_stage next);

/* Soft check used by lint / diagnostics. Returns false (without abort)
 * if `s` is not the current stage. Use for read-only assertions. */
bool boot_stage_is(enum boot_stage s);

/* ──────────────────────────────────────────────────────────────────
 * Boot progress marker — the boot-liveness feed for supervisor_backstop.
 *
 * Long, single-threaded boot stages (e.g. the block-index load/verify
 * over ~3.1M entries) run BEFORE background threads exist (the watchdog
 * spawns children only after STAGE_SERVICES_RUNNING). During them the
 * supervisor sweep heartbeat can legitimately sit unchanged for far
 * longer than the 30 s serving-time freeze bar without anything being
 * wedged. The supervisor_backstop watches sweep-heartbeat PLUS this
 * marker, so a boot loop that bumps it at bounded chunk boundaries
 * counts as liveness and cannot be mistaken for a frozen sweep — the
 * exact false-hang that killed a healthy seed boot mid-index-verify.
 *
 * boot_progress_marker() is the monotonic counter the backstop reads.
 * boot_progress_note() bumps it (one relaxed atomic add) and, throttled
 * to ~1/s, emits a coarse `[boot-phase] PROGRESS ...` operator line so a
 * slow boot stage is visible rather than silent. Call it from inside a
 * long boot loop every N iterations, with N chosen so the interval stays
 * well under the serving freeze bar even on a slow box (e.g. every 64K
 * entries). NULL-safe label. */
uint64_t boot_progress_marker(void);
void boot_progress_note(const char *label, uint64_t done, uint64_t total);

/* ──────────────────────────────────────────────────────────────────
 * Boot step reporter — a named step reports itself while it runs.
 *
 * The defect this closes: on 2026-08-24 a node's boot stopped dead
 * inside app_init_services and stayed silent for four hours. The step
 * it died in was not even named — its elapsed time was folded into the
 * next `[boot]` marker, which is printed only AFTER the step returns.
 * A step that never returns therefore left no record at all, and the
 * only backstop was the unit's 14400 s TimeoutStartSec.
 *
 * The reporter fixes that from the other side: the step declares its
 * name on ENTRY, and the shared heartbeat sweeper prints a typed record
 * for it every BOOT_STEP_BUDGET_MS until it finishes. One record per
 * budget window, from a thread the stuck step does not own.
 *
 * THREE STATES, NEVER A SCALAR. Over-budget is not failure:
 *
 *   running  — inside its budget. Nothing is wrong.
 *   slow     — over budget, and progress evidence ADVANCED since the
 *              last record. The step is working; the box is just slow.
 *              This is the honest state of a 7200 rpm HDD node and it
 *              MUST NOT be gradeable as a failure — an SSD-shaped
 *              deadline that fails honest slow hardware is how a
 *              network centralizes.
 *   stuck    — over budget with NO progress evidence since the last
 *              record. Still only an observation: this reporter never
 *              kills, restarts, or refuses anything.
 *   done     — the step returned. Carries its elapsed time.
 *   failed   — the step reported an explicit failure. This is the ONLY
 *              state a caller may treat as a failure, and it is never
 *              inferred from elapsed time.
 *
 * Every record carries `verdict=`: `telemetry` for running/slow/stuck,
 * `ok` for done, `failure` for failed. A reader or gate that greps for
 * failure therefore cannot mistake a slow step for a broken one.
 *
 * Every non-terminal record also extends the systemd start timeout, so
 * a step that is legitimately slow buys MORE time by reporting, never
 * less. Speed and liveness stay separate composable facts: `elapsed_ms`
 * is the speed fact, the repeating record is the liveness fact.
 *
 * Record shape (one line, key=value, stable token order):
 *   [boot-step] step=<name> state=<state> verdict=<verdict>
 *               elapsed_ms=<n> budget_ms=<n> progress_delta=<n>
 *               report=<n> [reason="<text>"]
 */

#define BOOT_STEP_BUDGET_MS 30000

enum boot_step_state {
    BOOT_STEP_RUNNING = 0,
    BOOT_STEP_SLOW,
    BOOT_STEP_STUCK,
    BOOT_STEP_DONE,
    BOOT_STEP_FAILED,
    BOOT_STEP_STATE__MAX
};

/* Pure classification — no clock, no globals, no side effects. This is
 * the whole slow/stuck/failed decision and it is unit-pinned.
 * `budget_ms <= 0` falls back to BOOT_STEP_BUDGET_MS. Note that FAILED
 * is unreachable from here BY CONSTRUCTION: elapsed time can never
 * produce a failure verdict. */
enum boot_step_state boot_step_classify(int64_t elapsed_ms,
                                        int64_t budget_ms,
                                        uint64_t progress_delta);

const char *boot_step_state_name(enum boot_step_state s);
/* `telemetry` / `ok` / `failure` — the token printed as `verdict=`. */
const char *boot_step_state_verdict(enum boot_step_state s);
/* True for BOOT_STEP_FAILED and nothing else. */
bool boot_step_state_is_failure(enum boot_step_state s);

/* Enter a named step. Ends any step already open (as `done`) and starts
 * reporting this one. NULL-safe. Idempotent per name is NOT assumed —
 * each call restarts the clock. */
void boot_step_enter(const char *name);

/* Optional progress evidence from inside the current step. Any call
 * makes the next over-budget record read `slow` instead of `stuck`.
 * O(1), one relaxed atomic add, safe from any thread. The global
 * boot_progress marker counts as evidence too, so a step that already
 * calls boot_progress_note() needs nothing extra. */
void boot_step_note(void);

/* Close the current step with `done`. Safe when no step is open. */
void boot_step_done(void);

/* Close the current step with `failed` and the given reason. This is
 * the ONLY producer of `verdict=failure`, and it is reported by the
 * step itself — never inferred from elapsed time. Safe when no step is
 * open.
 *
 * ALWAYS RETURNS FALSE, so a boot exit can name its failure and return
 * in the same statement it was already returning on:
 *     if (!start_the_thing())
 *         return boot_step_fail("the_thing");                        */
bool boot_step_fail(const char *reason);

#ifdef ZCL_TESTING
/* Test-only escape hatch: reset the global stage back to INIT so unit
 * tests can exercise the advance state machine without polluting the
 * stage observed by later tests in the same process. Production code
 * MUST NOT call this — it would defeat the misorder-detection invariant.
 * Only compiled in -DZCL_TESTING builds (test_zcl, test_parallel). */
void boot_stage_reset_for_testing(void);
#endif

#endif
