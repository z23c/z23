/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * supervisor_backstop — the watcher for the watcher (Pillar 7,
 * "supervise the supervisor").
 *
 * Why this exists
 * ----------------
 * The root zcl_supervisor thread (util/supervisor.h) drives every
 * registered child's on_tick/on_stall from ONE dispatch loop. It cannot
 * register itself on the tree it drives — a wedged supervisor can't
 * detect its own wedge — so it is a documented exemption from Gate #23
 * (tools/lint/check_thread_supervision.sh), and its only prior backstop
 * was the shutdown-path alarm() in app_shutdown_svc, which only fires
 * once shutdown has already been requested by something else. If the
 * supervisor thread itself dies, or wedges permanently inside one
 * child's on_tick, NOTHING notices: every stage that relies on the
 * supervisor driving it (reducer stages, watchdogs, health) goes quiet
 * with no named blocker — the exact silent-halt class the whole
 * supervisor design exists to prevent, just one level up.
 *
 * This module is a minimal, independent watcher:
 *   - Its own dedicated thread, its own clock (CLOCK_MONOTONIC via
 *     platform_time_monotonic_us), its own sleep loop. It does not tick
 *     on the supervisor's thread, does not hold the supervisor's lock,
 *     and is not registered as a supervisor child (that would be
 *     circular — see above).
 *   - It polls exactly ONE fact: supervisor_sweep_heartbeat(), the
 *     counter the supervisor bumps once per completed sweep_once() call
 *     (see util/supervisor.h). If the counter sits unchanged for
 *     freeze_threshold_us, the sweep thread is dead or wedged.
 *   - Two escalation paths, matching whether systemd owns restart:
 *       (a) Under systemd (NOTIFY_SOCKET present): this module logs and
 *           does nothing else. boot_sd_watchdog.c already refuses to
 *           ping WATCHDOG=1 once this same counter goes stale, so
 *           systemd's own WatchdogSec timer kills + restarts the unit —
 *           the PREFERRED path (systemd, not this thread, does the
 *           actual kill).
 *       (b) Off systemd: nothing else will ever restart the process, so
 *           this module requests an orderly shutdown + latches a
 *           self-respawn flag, mirroring chain_tip_watchdog's S7
 *           off-systemd fallback (services/chain_tip_watchdog.h). main()
 *           polls supervisor_backstop_respawn_requested() alongside
 *           chain_tip_watchdog_respawn_requested() after app_shutdown()
 *           and re-execs /proc/self/exe when either is set.
 *
 * Verify-never-trust: the most aggressive action this module can take
 * off-systemd is requesting a re-exec of the SAME binary with the SAME
 * argv — it never lowers a validation gate, and every block processed
 * after the fresh boot still goes through the full crypto pipeline. */

#ifndef ZCL_SUPERVISOR_BACKSTOP_H
#define ZCL_SUPERVISOR_BACKSTOP_H

#include <stdbool.h>
#include <stdint.h>

/* Built-in defaults, used when either argument to
 * supervisor_backstop_start() is <= 0. Poll cadence is independent of
 * (and much cheaper than) the supervisor's own 1 s tick; the freeze
 * threshold is generous — the supervisor's own children give a named
 * blocker via mundane stall detection long before 30 s in the common
 * case, so this backstop is deliberately the LAST line, not the first. */
#define SUPERVISOR_BACKSTOP_DEFAULT_POLL_US    (5  * 1000000LL)
#define SUPERVISOR_BACKSTOP_DEFAULT_FREEZE_US  (30 * 1000000LL)

/* Boot-stage-aware budget. A long single-threaded boot stage (block-index
 * load/verify over ~3.1M entries) runs BEFORE the supervisor sweep is the
 * liveness signal (background threads only spawn after
 * BOOT_STAGE_SERVICES_RUNNING), so the sweep heartbeat can legitimately
 * sit unchanged for well over the 30 s serving bar without anything being
 * wedged — treating that as a frozen sweep KILLS a healthy boot (observed
 * live: a seed boot died to a false backstop FATAL mid-index-verify).
 *
 * The backstop therefore (a) folds boot_progress_marker() into the
 * liveness signal it watches, so a boot loop that pumps progress at chunk
 * boundaries re-arms the freeze episode, and (b) scales the freeze budget
 * UP to this generous value while the process is in a PRE-serving boot
 * stage (boot_stage_current() < BOOT_STAGE_SERVICES_RUNNING). It never
 * scales DOWN: once services are running the 30 s serving bar applies
 * unchanged, so a genuinely frozen sweep during serving still dies on
 * time. This bounds — but does not disable — a truly wedged boot with no
 * sweep, no stage advance, and no loop progress (anti-silent-halt). */
#define SUPERVISOR_BACKSTOP_BOOT_FREEZE_US     (300 * 1000000LL)

/* Start the backstop watcher thread. Idempotent — a second call while
 * already running returns true without spawning another thread.
 * Pass <= 0 for either argument to use the default above. Returns false
 * only on thread-spawn failure (registry full / pthread_create error). */
bool supervisor_backstop_start(int64_t poll_interval_us,
                               int64_t freeze_threshold_us);

/* Request stop and join the watcher thread. Safe to call without a
 * prior start; safe to call multiple times. Bounded — the watcher's
 * poll loop checks the stop flag every wake, so this returns within one
 * poll interval. */
void supervisor_backstop_stop(void);

/* True once the watcher has declared the sweep counter frozen AND was
 * NOT running under systemd notify supervision at the time (so nothing
 * else will restart the process). Latched — only ever set true; a
 * fresh process boot starts false. main() checks this alongside
 * chain_tip_watchdog_respawn_requested() after app_shutdown(). */
bool supervisor_backstop_respawn_requested(void);

/* `z23 dumpstate supervisor_backstop` dumper. `out` must already
 * be JSON-initialized (json_set_object) by the caller. `key` is unused. */
struct json_value;
bool supervisor_backstop_dump_state_json(struct json_value *out,
                                         const char *key);

/* Episode state for the ONE pure decision the watcher thread makes each
 * poll — "has the heartbeat been unchanged for >= freeze_threshold_us,
 * measured from the last time THIS state observed it change?". Defined
 * unconditionally (not just under ZCL_TESTING): the production watcher
 * thread owns exactly one instance of this as local state, and the
 * ZCL_TESTING seam below lets a unit test drive the SAME decision
 * function with synthetic heartbeat/clock values instead. */
struct supervisor_backstop_state {
    uint64_t last_heartbeat;
    int64_t  last_change_us;
    bool     initialized;
    bool     already_fired;   /* edge-triggered: don't re-declare every poll */
};

#ifdef ZCL_TESTING
/* ── Test seams (compiled only into test_zcl / test_parallel) ─────────
 *
 * The pure decision the watcher thread makes each poll, factored out so
 * a unit test can drive it with synthetic heartbeat/clock values —
 * no threads, no real sleep, no re-exec, no systemd. */

/* Evaluate one poll. `state` is caller-owned scratch — zero it (or use
 * `= {0}`) to start a fresh episode. Returns true the ONE poll a freeze
 * is first declared for the current episode; a heartbeat that resumes
 * changing (or a fresh freeze after already_fired resets by moving
 * again) re-arms it. Mirrors chain_tip_watchdog's shared-decision-path
 * pattern (production tick + test seam call the same function). */
bool supervisor_backstop_test_check(struct supervisor_backstop_state *state,
                                    uint64_t heartbeat, int64_t now_us,
                                    int64_t freeze_threshold_us);

/* Boot-stage-aware variant of the decision the production thread now
 * makes each poll: combine the supervisor sweep heartbeat with the
 * boot-progress marker (either advancing re-arms the episode) and scale
 * the freeze budget up while in a pre-serving boot stage. Drive it with
 * fully synthetic (sweep_hb, boot_progress, boot_stage, clock) values so
 * a unit test can prove — with no threads/sleep — that a chunk-pumping
 * boot loop survives past the 30 s bar while a frozen sweep during
 * serving still fires at exactly the bar. `serving_threshold_us` is the
 * base (serving) bar; pass SUPERVISOR_BACKSTOP_DEFAULT_FREEZE_US for the
 * production value. */
bool supervisor_backstop_test_check_staged(
    struct supervisor_backstop_state *state,
    uint64_t sweep_hb, uint64_t boot_progress, int boot_stage,
    int64_t now_us, int64_t serving_threshold_us);

/* True when the watcher itself was unable to observe the process for an
 * entire freeze budget. Production rebases its episode after such a gap:
 * SIGSTOP/host suspension is not continuous evidence that the supervisor
 * thread was wedged. A watcher that keeps polling while the supervisor is
 * frozen still fires at the unchanged threshold. */
bool supervisor_backstop_test_observation_gap(
    int64_t previous_poll_us, int64_t now_us, int64_t freeze_threshold_us);

/* Force the boot stage the staged decision reads instead of the real
 * boot_stage_current(), so a test_poll-based escalation test is
 * deterministic regardless of how far the test binary's own boot
 * advanced. Test-only; cleared by supervisor_backstop_test_reset(). */
void supervisor_backstop_test_force_boot_stage(int boot_stage);

/* Reset all module-level state (the respawn latch + any forced
 * off-systemd override) to defaults, as if the process just started.
 * Does NOT touch or require the watcher thread. */
void supervisor_backstop_test_reset(void);

/* Force the "running off systemd" branch deterministically instead of
 * reading the real sd_notify_is_active() (some CI/dev boxes run test
 * binaries under systemd-run too). Test-only. */
void supervisor_backstop_test_force_off_systemd(bool off_systemd);

/* Drive exactly one watcher poll synchronously on the CALLING thread,
 * using the REAL supervisor_sweep_heartbeat() but an INJECTED monotonic
 * timestamp and an in/out state struct — no thread, no real sleep.
 * Lets a test assert the full escalation (respawn latch set/not-set)
 * without waiting freeze_threshold_us of real wall-clock time. */
void supervisor_backstop_test_poll(struct supervisor_backstop_state *state,
                                  int64_t now_us, int64_t freeze_threshold_us);
#endif

#endif /* ZCL_SUPERVISOR_BACKSTOP_H */
