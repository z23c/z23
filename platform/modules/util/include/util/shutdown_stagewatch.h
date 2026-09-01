/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Truthful, bounded shutdown watchdog.
 *
 * The old shutdown watchdog was a single global `alarm(90)` cliff: when
 * graceful teardown exceeded 90s (large final WAL checkpoint / block-index
 * flat save after a long fold), a SIGALRM handler wrote "forcing exit" and
 * `_exit(1)`. systemd read that exit code as `Result: failed` — even when the
 * work had already SUCCEEDED (e.g. a from-genesis mint whose receipts were
 * durable) and every operator-critical byte was already on stable storage.
 * Success was masked as failure, and nobody could tell WHICH stage was slow.
 *
 * This module replaces that one cliff with three things:
 *
 *   1. Per-stage instrumentation. Each teardown stage is named and timed
 *      (monotonic microseconds), logged at INFO as it completes, so the next
 *      slow stop names its stage instead of dying silently.
 *
 *   2. Per-stage deadline escalation. Each stage arms its own soft `alarm()`
 *      budget. When a stage overruns, the SIGALRM handler decides, per
 *      `shutdown_deadline_decide()`:
 *        - durability already secured  -> truthful CLEAN exit (code 0). The
 *          remaining work (compaction, cache writeback) is resumable at next
 *          boot, so stopping now is honest success.
 *        - durability NOT yet secured, durability-critical stage in flight ->
 *          grant a bounded, loudly-logged GRACE (re-arm) rather than skip a
 *          durability fsync; only after the grace budget is spent does it
 *          declare a genuinely UNCLEAN exit (code 1).
 *      Durability-critical fsyncs are NEVER skipped.
 *
 *   3. A truthful, datadir-readable verdict. On any terminal decision a small
 *      `shutdown-receipt.v1` file is written to the datadir carrying the
 *      outcome, last stage, and per-stage durations, so operators/tools read
 *      truth from the datadir, not from systemd's Result.
 *
 * Async-signal-safety: `shutdown_stagewatch_mark_durable()` and
 * `shutdown_stagewatch_on_alarm()` run from (or as) a SIGALRM handler and use
 * only async-signal-safe primitives (atomics, alarm(), write(), open()/fsync()
 * of pre-computed buffers, _exit()). No malloc, snprintf, or locks on those
 * paths. See docs/DEFENSIVE_CODING.md and the async-signal-safe shutdown
 * doctrine (pthread_create from a handler never gets CPU under load).
 */

#ifndef ZCL_SHUTDOWN_STAGEWATCH_H
#define ZCL_SHUTDOWN_STAGEWATCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SHUTDOWN_STAGEWATCH_MAX_STAGES 32
#define SHUTDOWN_STAGE_NAME_MAX        48

/* Exit-reason breadcrumb (E2 boot-loop-failsafe, docs/HANDOFF.md 2026-07):
 * a durable one-row marker, sibling to shutdown-receipt.v1, that records WHY
 * this process is about to leave — an operator/systemd-driven shutdown, or a
 * SELF-respawn requested by chain_tip_watchdog / supervisor_backstop after
 * declaring a genuine liveness stall. The live incident this closes: a
 * self-respawn requests an orderly shutdown + in-process re-exec (main.c),
 * but if a shutdown STAGE then blows its own deadline, shutdown_stagewatch_
 * on_alarm() force-_exit()s from inside app_shutdown() before main.c ever
 * reaches the re-exec — so the respawn silently never happens (or, under
 * systemd, Restart=always quietly restarts it with zero named signal that
 * this was a self-respawn attempt, not an operator restart). The next boot's
 * boot-loop detector (config/boot_loop_guard.h) reads this breadcrumb to
 * tell the two apart. NULL-safe throughout: a missing datadir/breadcrumb is
 * a logged no-op / a "no breadcrumb" read, never fatal. */
#define SHUTDOWN_EXIT_REASON_MAX 64
#define SHUTDOWN_EXIT_REASON_OPERATOR                         "operator_or_external"
#define SHUTDOWN_EXIT_REASON_SELF_RESPAWN_TIP_WATCHDOG        "self_respawn_tip_watchdog"
#define SHUTDOWN_EXIT_REASON_SELF_RESPAWN_SUPERVISOR_BACKSTOP "self_respawn_supervisor_backstop"
#define SHUTDOWN_EXIT_REASON_SELF_RESPAWN_BOTH                "self_respawn_both"

/* Per-stage record: what ran, how long, and whether it blew its budget. */
struct shutdown_stage_record {
    char    name[SHUTDOWN_STAGE_NAME_MAX];
    int64_t elapsed_us;
    bool    durability_critical;
    bool    over_budget;
};

/* Truthful terminal verdict, written into the datadir receipt. */
enum shutdown_outcome {
    SHUTDOWN_OUTCOME_CLEAN = 0,             /* full graceful teardown */
    SHUTDOWN_OUTCOME_FORCED_AFTER_DURABLE,  /* deadline hit AFTER durability — SUCCESS */
    SHUTDOWN_OUTCOME_FORCED_UNCLEAN,        /* deadline hit BEFORE durability — FAILURE */
};

/* Deadline-escalation decision (pure; the unit-tested core of the watchdog). */
enum shutdown_deadline_action {
    SHUTDOWN_DEADLINE_GRACE = 0,    /* durability unreached — re-arm, keep going */
    SHUTDOWN_DEADLINE_EXIT_CLEAN,   /* durability secured — truthful success, stop now */
    SHUTDOWN_DEADLINE_EXIT_UNCLEAN, /* durability unreached, graces spent — failure */
};

/* Pure decision function — the heart of the escalation policy.
 *
 * Given whether durability was already secured, whether the in-flight stage is
 * durability-critical, and how many graces have already been granted, decide
 * what the deadline handler should do. Invariants (asserted by the tests):
 *   - Never returns EXIT_CLEAN before durability is secured (no false success).
 *   - Never returns EXIT_UNCLEAN once durability is secured (no false failure).
 *   - Never skips a durability-critical fsync — grants bounded GRACE instead.
 */
enum shutdown_deadline_action
shutdown_deadline_decide(bool durable_secured,
                         bool current_stage_durability_critical,
                         int graces_used, int grace_max);

/* Render the v1 receipt text into buf. Returns bytes written (excl NUL), or -1
 * on overflow / bad args. Pure — used for the CLEAN path and by the tests. */
int shutdown_stagewatch_format_receipt(char *buf, size_t n,
                                       enum shutdown_outcome outcome,
                                       const char *last_stage,
                                       bool durable_secured,
                                       int64_t total_us,
                                       const struct shutdown_stage_record *stages,
                                       size_t n_stages);

/* Map an outcome to a truthful process exit code (0 = success, 1 = failure). */
int shutdown_stagewatch_exit_code(enum shutdown_outcome outcome);

/* Async-signal-safe terminal-receipt writer. Writes a minimal but truthful
 * receipt (magic/version/outcome/durable/forced_at_stage) to `fd` using only
 * write(2) of pre-computed/static buffers. Returns bytes written or -1.
 * Exposed (non-static) so the test can drive it against a temp fd without
 * raising a real signal. */
int shutdown_stagewatch_write_terminal_receipt_fd(int fd,
                                                  enum shutdown_outcome outcome,
                                                  const char *stage,
                                                  bool durable);

/* ── Live wiring ─────────────────────────────────────────────────────── */

/* Injectable monotonic clock (microseconds). NULL restores the real clock. */
typedef int64_t (*shutdown_stagewatch_clock_fn)(void);
void shutdown_stagewatch_set_clock_for_test(shutdown_stagewatch_clock_fn fn);

/* Reset all module state (tests). */
void shutdown_stagewatch_reset_for_test(void);

/* Read-only accessors for tests / diagnostics. */
size_t shutdown_stagewatch_stage_count(void);
const struct shutdown_stage_record *shutdown_stagewatch_stage(size_t i);
bool   shutdown_stagewatch_is_durable(void);

/* Begin a shutdown sequence. `datadir` (may be NULL) is where the receipt is
 * written. Records the start time and computes the receipt path once. */
void shutdown_stagewatch_begin(const char *datadir);

/* Enter a named stage: close out the previous stage (record its duration, log
 * it at INFO, flag over-budget), then, if arm_alarm, arm this stage's soft
 * deadline via alarm(budget_secs). `durability_critical` marks a stage whose
 * fsync must not be skipped under deadline pressure. */
void shutdown_stagewatch_enter(const char *stage, int budget_secs,
                               bool durability_critical, bool arm_alarm);

/* Mark the durability point: everything the operator must not lose is on
 * stable storage (coins flushed, WAL checkpointed, clean marker written).
 * Async-signal-safe. */
void shutdown_stagewatch_mark_durable(void);

/* SIGALRM-handler body. Async-signal-safe. Logs which stage overran, applies
 * shutdown_deadline_decide(), and either re-arms alarm() for a GRACE and
 * returns, or writes a terminal receipt and _exit()s with the truthful code
 * (never returning). Safe to call even if begin() was never invoked (falls
 * back to the legacy "forcing exit" + _exit(1)). */
void shutdown_stagewatch_on_alarm(void);

/* Normal (non-signal) clean completion: close the last stage, write and fsync
 * the CLEAN receipt plus its parent directory, then cancel the alarm. Returns
 * false if the receipt durability barrier could not be completed. */
bool shutdown_stagewatch_complete_clean(void);

/* Normal-context terminal failure path. Writes and fsyncs an UNCLEAN receipt,
 * cancels the alarm, and returns whether that diagnostic receipt was durable.
 * This never changes the process exit code; the caller must exit non-zero. */
bool shutdown_stagewatch_complete_unclean(void);

/* ── Exit-reason breadcrumb ──────────────────────────────────────────── */

/* Write the breadcrumb. NORMAL (non-signal) context only — call once per
 * shutdown, right after shutdown_stagewatch_begin() returns (so the path is
 * already computed) and BEFORE any stage runs, so the breadcrumb is durable
 * on disk even if a later stage's deadline forces an early _exit() from the
 * alarm handler. `reason` is truncated to fit SHUTDOWN_EXIT_REASON_MAX;
 * NULL/empty is a logged no-op. Idempotent: a later call before the next
 * begin() overwrites (tmp+rename+fsync). A NULL/never-set datadir (begin()
 * received none) is a logged no-op — this is diagnostic telemetry, never a
 * shutdown-blocking dependency. */
void shutdown_stagewatch_write_exit_reason(const char *reason);

/* Read the breadcrumb the LAST shutdown of the process that owns `datadir`
 * wrote — call this at BOOT, before this boot's own shutdown_stagewatch_
 * begin() ever runs (it does not touch or require begin()'s live state; it
 * computes its own path from `datadir`, independent of any in-process
 * lifecycle). Returns false (no breadcrumb: first-ever boot, or the file was
 * never written — `reason_out` cleared, `forced_out` set false) or true with
 * `reason_out` filled (truncated to `n`, always NUL-terminated) and
 * `forced_out` set true iff shutdown_stagewatch_on_alarm() appended a
 * forced-exit marker during that shutdown (see the alarm handler). */
bool shutdown_stagewatch_read_exit_reason(const char *datadir,
                                          char *reason_out, size_t n,
                                          bool *forced_out);

#endif /* ZCL_SHUTDOWN_STAGEWATCH_H */
