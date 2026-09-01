/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tip-stuck watchdog. See services/chain_tip_watchdog.h. */

// one-result-type-ok:watchdog-no-fallible-surface
//
// This is a supervisor-child monitor, not a fallible service executor. It
// owns no pass/fail operation that a caller branches on. Its surfaces are:
//   - void tick / register / setters,
//   - a single coherent stats out-struct (chain_tip_watchdog_stats) returned
//     by get_stats() and projected by dump_state_json(),
//   - bool returns that are DECISIONS or PREDICATES, not lost-reason failures:
//       * wd_decide_restart() returns "did/would request shutdown"; the
//         escalation reason travels via EV_OPERATOR_NEEDED /
//         EV_CHAIN_ADVANCE_DECISION + LOG_WARN on every branch.
//       * wd_persist_load/store() degrade gracefully (no-store is not an
//         error); every real failure logs via LOG_FAIL/LOG_WARN.
//       * dump_state_json() is the mandated *_dump_state_json -> bool
//         introspection convention, which must stay bool.
// No bare-bool here strips a failure reason — they all log or carry the
// reason in an event/out-struct. Behavior bit-for-bit.

#include "platform/time_compat.h"
#include "services/chain_tip_watchdog.h"

#include "supervisors/domains.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/process_block_revalidate.h"
#include "chain/chain.h"
#include "services/sticky_escalator.h"
#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"
#include "util/sd_notify.h"
#include "util/log_macros.h"
#include "util/alerts.h"
#include "util/blocker.h"
#include "event/event.h"
#include "json/json.h"
#include "storage/progress_store.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Default escalation thresholds (seconds). */
#define CHAIN_TIP_WD_DEFAULT_MIRROR_SECS    300
#define CHAIN_TIP_WD_DEFAULT_RESERVED_SECS  600
#define CHAIN_TIP_WD_DEFAULT_RESTART_SECS  1200

/* progress.kv keys for the bounded-restart memory (see header). */
#define CHAIN_TIP_WD_KEY_STUCK_HEIGHT  "chain_tip_wd.stuck_height"
#define CHAIN_TIP_WD_KEY_RESTARTS      "chain_tip_wd.no_progress_restarts"

/* ── Module state ──────────────────────────────────────────────────── */

static struct main_state       *g_ms          = NULL;
static struct liveness_contract g_contract;
/* Atomic so an early dumpstate from another thread observes the
 * register result without a memory-ordering hazard. (Live: first dump
 * after restart returned registered=false; re-dump returned true.) */
static _Atomic supervisor_child_id g_id       = SUPERVISOR_INVALID_ID;

static _Atomic int64_t  g_highest_tip        = 0;
static _Atomic int64_t  g_last_advance_us    = 0;
static _Atomic int64_t  g_last_advance_unix  = 0;
/* Actionable-stall time is deliberately separate from last chain advance.
 * A chain can be quiet at tip for hours; when a new header finally appears,
 * the reducer gets a fresh recovery interval instead of inheriting that idle
 * time and being restarted immediately. */
static _Atomic int64_t  g_stall_start_us     = 0;
static _Atomic int      g_escalation         = 0;

static _Atomic uint64_t g_fires_mirror   = 0;
static _Atomic uint64_t g_fires_reserved = 0;
static _Atomic uint64_t g_fires_restart  = 0;
static _Atomic uint64_t g_fires_operator_needed = 0;
/* Count of tip-extension SELECTION-wedge remedies driven: a valid direct
 * successor to the frozen tip exists on the best-header chain but
 * find_most_work_chain skips it on a persisted BLOCK_FAILED_VALID mask, so the
 * watchdog drove an evidence-based process_block_revalidate of that one height
 * rather than a blind restart (which cannot clear an on-disk failure bit). */
static _Atomic uint64_t g_fires_selection_remedy = 0;
static _Atomic int64_t  g_observed_work_frontier = -1;
static _Atomic bool     g_at_observed_tip = false;
static _Atomic bool     g_at_tip_restart_counted = false;
static _Atomic uint64_t g_at_observed_tip_entries = 0;
static _Atomic uint64_t g_restarts_suppressed_at_tip = 0;
#ifdef ZCL_TESTING
/* Selection-wedge remedy test seams: suppress the real revalidate (which would
 * reach the quorum oracle / activation controller) and record the target so a
 * hermetic test can assert the remedy was driven at active_tip+1. */
static _Atomic bool    g_test_suppress_selection_remedy = false;
static _Atomic int64_t g_selection_remedy_last_target   = -1;
#endif

static _Atomic int64_t  g_thr_mirror   = CHAIN_TIP_WD_DEFAULT_MIRROR_SECS;
static _Atomic int64_t  g_thr_reserved = CHAIN_TIP_WD_DEFAULT_RESERVED_SECS;
static _Atomic int64_t  g_thr_restart  = CHAIN_TIP_WD_DEFAULT_RESTART_SECS;

/* Bounded-restart memory. Loaded from progress.kv at register(); the
 * (episode anchor, count) pair survives the restart it triggers, so a
 * fresh process knows it has already burned N restarts in this wedge
 * episode and stops thrashing once N hits the cap. -1 == "no episode
 * recorded yet". */
static _Atomic int64_t  g_persisted_stuck_height = -1;
static _Atomic int      g_no_progress_restarts   = 0;
static _Atomic bool     g_operator_needed        = false;

/* #8 — set when a genuine-liveness restart was requested while NOT under a
 * systemd notify socket, so main() self-re-execs instead of leaving a
 * directly-launched binary down. Latched (only ever set true). */
static _Atomic bool     g_respawn_requested      = false;

static int64_t mono_us_now(void)
{
    struct timespec ts;
    platform_time_monotonic_timespec(&ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/* ── Bounded-restart persistence (progress.kv) ─────────────────────────
 *
 * Storage layer is the sanctioned AR-exempt kernel primitive (same as
 * stage_cursor / legacy_bootstrap_attach) — progress_meta_set/get are the
 * approved path, no AR_*_SAVE wrapping required. Every failure path logs
 * via LOG_* per DEFENSIVE_CODING.md. progress.kv being closed (e.g. very
 * early boot, or unit tests that don't open it) is tolerated: the
 * watchdog degrades to in-memory-only counting, which is strictly safer
 * (it can only restart MORE, never skip a needed page). */

static bool wd_persist_load(void)
{
    sqlite3 *db = progress_store_db();
    if (!db) {
        /* No store yet — keep defaults. Not an error: cold boot before
         * progress.kv opens, or a build/test without it. */
        return true;
    }

    int64_t stuck = -1;
    int32_t count = 0;
    size_t got = 0;
    bool found = false;

    if (!progress_meta_get(db, CHAIN_TIP_WD_KEY_STUCK_HEIGHT,
                           &stuck, sizeof(stuck), &got, &found))
        LOG_FAIL("chain_tip_watchdog",
                 "progress_meta_get(stuck_height) failed");

    if (found && got == sizeof(stuck)) {
        atomic_store(&g_persisted_stuck_height, stuck);

        found = false; got = 0;
        if (!progress_meta_get(db, CHAIN_TIP_WD_KEY_RESTARTS,
                               &count, sizeof(count), &got, &found))
            LOG_FAIL("chain_tip_watchdog",
                     "progress_meta_get(restarts) failed");
        if (found && got == sizeof(count) && count >= 0)
            atomic_store(&g_no_progress_restarts, (int)count);
    }
    return true;
}

static bool wd_persist_store(int64_t stuck_height, int restarts)
{
    sqlite3 *db = progress_store_db();
    if (!db) {
        /* No store: degrade to in-memory counting (strictly safer — can
         * only restart MORE, never skip a needed page). Logged, not fatal. */
        LOG_WARN("chain_tip_watchdog", "[chain_tip_watchdog] WARN progress.kv not open; " "bounded-restart counter is in-memory only this run");
        return false;
    }
    int32_t count = (int32_t)restarts;
    if (!progress_meta_set(db, CHAIN_TIP_WD_KEY_STUCK_HEIGHT,
                           &stuck_height, sizeof(stuck_height)))
        LOG_FAIL("chain_tip_watchdog",
                 "progress_meta_set(stuck_height) failed");
    if (!progress_meta_set(db, CHAIN_TIP_WD_KEY_RESTARTS,
                           &count, sizeof(count)))
        LOG_FAIL("chain_tip_watchdog",
                 "progress_meta_set(restarts) failed");
    return true;
}

/* Tip advanced to `h`: only SUSTAINED progress past the episode anchor
 * proves the wedge cleared. A creeping wedge gains 1-2 blocks per
 * restart; clearing on ANY advance refreshed its budget every restart
 * — an infinite restart loop. */
static void wd_note_advance(int64_t h)
{
    int64_t stuck = atomic_load(&g_persisted_stuck_height);
    if (stuck >= 0 && h >= stuck + CHAIN_TIP_WD_EPISODE_CLEAR) {
        atomic_store(&g_persisted_stuck_height, -1);
        atomic_store(&g_no_progress_restarts, 0);
        atomic_store(&g_operator_needed, false);
        (void)wd_persist_store(-1, 0);
    }
}

/* The restart escalation decision, factored out so the supervisor tick
 * and the test seam share ONE code path. Returns true if shutdown was
 * (or would be) requested; false if the cap was hit and we paged a human
 * instead. `do_shutdown` lets test builds suppress the real syscall. */
static bool wd_decide_restart(int64_t h, int64_t age_s, bool do_shutdown,
                              bool deterministic_stall)
{
    /* Episode keying: a stuck height inside [anchor, anchor+margin] is
     * the SAME wedge creeping forward — carry the count and KEEP the
     * original anchor. Only a height outside the window (including a
     * rewind below the anchor) starts a fresh episode and budget. */
    int64_t stuck = atomic_load(&g_persisted_stuck_height);
    if (stuck < 0 || h < stuck ||
        h > stuck + CHAIN_TIP_WD_EPISODE_MARGIN) {
        atomic_store(&g_persisted_stuck_height, h);
        atomic_store(&g_no_progress_restarts, 0);
        atomic_store(&g_operator_needed, false);
        stuck = h;
    }

    int restarts = atomic_load(&g_no_progress_restarts);

    if (restarts >= CHAIN_TIP_WD_MAX_RESTARTS || deterministic_stall) {
        /* A power-cycle cannot help here: either restarting already failed
         * CHAIN_TIP_WD_MAX_RESTARTS times, OR the stall is a DETERMINISTIC
         * on-disk condition (byte-identical every boot — the class EVERY wedge
         * produces). Latching g_operator_needed=true here and emitting
         * a TERMINAL EV_OPERATOR_NEEDED ("staying up degraded for manual
         * intervention") would be a human dead-end, violating sticky invariant S2.
         *
         * Instead: hand the wedge to the top-level
         * always-terminating remedy escalator instead of dead-ending. The
         * escalator drives an ORDERED ladder (retry -> targeted re-derive ->
         * resnapshot -> reindex -> self-mint refold -> widen peers ->
         * re-bootstrap) and NEVER latches a permanent operator-needed state on
         * a recoverable class. The genuine-local-unrecoverable page (if ever
         * warranted) is now the escalator's non-latching last resort, AFTER the
         * ladder exhausts — not this reflex. g_operator_needed is kept ONLY as a
         * diagnostic "ladder engaged" bit (no longer a stop). */
        atomic_store(&g_operator_needed, true); /* diagnostic flag, not a latch */
        atomic_fetch_add(&g_fires_operator_needed, 1u);
        LOG_WARN("chain_tip_watchdog", "[chain_tip_watchdog] tip wedged at h=%lld for %llds; %s — NOT " "power-cycling; handing to the always-terminating remedy escalator", (long long)h, (long long)age_s, deterministic_stall ? "deterministic stall, a restart cannot clear it" : "restarts exhausted");
        sticky_escalator_note_stall(deterministic_stall
            ? "chain_tip_deterministic_stall"
            : "chain_tip_restarts_exhausted");
        return false;
    }

    /* Below the cap: record one more restart in this episode BEFORE
     * requesting shutdown, so the fresh process reads back the
     * incremented count. Persist the ANCHOR (not h): the anchor must
     * stay fixed while the tip creeps inside the episode window. */
    restarts += 1;
    atomic_store(&g_no_progress_restarts, restarts);
    atomic_fetch_add(&g_fires_restart, 1u);
    (void)wd_persist_store(stuck, restarts);

    LOG_WARN("chain_tip_watchdog", "[chain_tip_watchdog] requesting shutdown: h=%lld age=%llds " "(no-progress restart %d/%d in episode anchored at %lld)", (long long)h, (long long)age_s, restarts, CHAIN_TIP_WD_MAX_RESTARTS, (long long)stuck);
    event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
        "chain_tip_watchdog request_shutdown h=%lld age=%llds restart=%d/%d",
        (long long)h, (long long)age_s, restarts, CHAIN_TIP_WD_MAX_RESTARTS);

    /* The restart remedy relies on systemd
     * Restart=always to bring the process back. A directly-launched binary
     * (no NOTIFY_SOCKET) would just exit and stay DOWN, so genuine-liveness
     * recovery would never happen off systemd. When no notify socket is
     * present, latch a self-respawn request: main() re-execs /proc/self/exe
     * after the orderly shutdown so the node comes back in-process with fresh
     * state, exactly as a systemd restart would. The bounded restart budget
     * lives in progress.kv and is reloaded on the fresh boot, so self-respawn
     * is bounded identically — it cannot loop unbounded. */
    if (!sd_notify_is_active()) {
        atomic_store(&g_respawn_requested, true);
        LOG_WARN("chain_tip_watchdog", "[chain_tip_watchdog] no systemd notify socket — " "requesting in-process self-respawn so liveness recovery does " "not depend on Restart=always (S7)");
    }

    if (do_shutdown)
        thread_registry_request_shutdown();
    return true;
}

bool chain_tip_watchdog_respawn_requested(void)
{
    return atomic_load(&g_respawn_requested);
}

void chain_tip_watchdog_request_respawn(void)
{
    /* The sticky escalator's terminal refold rung armed a durable refold and is
     * about to request an orderly shutdown; latch the same self-respawn flag the
     * watchdog uses so main() re-execs off-systemd and the fresh boot runs it. */
    atomic_store(&g_respawn_requested, true);
}

/* ── Cause probe ───────────────────────────────────────────────────────
 *
 * A tip that has been constant for thr_restart seconds is not, by itself,
 * a power-cycle-clearable fault. Restarting burns the bounded budget and
 * costs peer reputation; a DETERMINISTIC stall is byte-identical every
 * boot, so a restart provably cannot clear it. Classify the cause before
 * escalating: only a stall with NO named deterministic blocker is genuine
 * liveness loss that a restart might recover. Every recognised cause is
 * named back to the caller (returned literal) so the watchdog can page +
 * log it; the probe itself takes no destructive action. The string returns
 * are process-lifetime literals — race-safe to read off-thread. */
static const char *wd_deterministic_stall_cause(void)
{
    /* (0) Tip-extension SELECTION wedge: the active tip is frozen while the
     * best-header chain is AHEAD, and the direct successor to the tip on that
     * header chain is present but carries a persisted BLOCK_FAILED_VALID mask,
     * so find_most_work_chain skips it and the active-chain most-work selector
     * keeps returning the tip. A restart cannot clear an on-disk failure bit
     * (byte-identical every boot), so this is a deterministic cause — but
     * unlike the causes below it has a TARGETED lever (evidence-based
     * revalidate of that one height, driven by wd_apply_tick). "not a stale
     * fork" is enforced by requiring the successor to build DIRECTLY on our tip
     * (pprev == tip) and the pure selector to still yield the tip (no heavier
     * eligible candidate). Named FIRST so the actionable class wins over the
     * generic deterministic causes below. */
    if (g_ms) {
        struct block_index *tip = active_chain_tip(&g_ms->chain_active);
        struct block_index *bh  = g_ms->pindex_best_header;
        if (tip && bh && bh->nHeight > tip->nHeight) {
            struct block_index *succ =
                block_index_get_ancestor(bh, tip->nHeight + 1);
            if (succ && succ->pprev == tip &&
                block_is_permanently_failed(succ)) {
                struct block_index *sel = active_chain_most_work_candidate(
                    &g_ms->chain_active, &g_ms->map_block_index);
                if (sel == NULL || sel == tip)
                    return "tip_selection_wedge";
            }
        }
    }

    /* (1) tip_finalize pinned on a persisted ok=0 precondition: the
     * successor is present but not finalizable (e.g. a persisted ok=0
     * script_validate / proof_validate row). Byte-identical every boot. */
    const char *br = tip_finalize_stage_last_blocked_reason();
    if (br && strcmp(br, "successor_pending") == 0)
        return "tip_finalize_successor_pending";

    /* (2) A latched operator-needed page is already standing — the "a halt
     * can never be silent" signal (EV_OPERATOR_NEEDED fired and not yet
     * cleared). The operator has already been told a restart won't help; a
     * fresh power-cycle would re-burn the budget against the same wedge. */
    if (alerts_operator_needed(NULL, 0, NULL))
        return "operator_needed_latched";

    /* (3) Any active PERMANENT-class typed blocker (bad PoW, malformed
     * block, consensus reject) — by definition never auto-retryable; only
     * an operator clears it. A restart re-derives the identical reject. */
    if (blocker_count_by_class(BLOCKER_PERMANENT) > 0)
        return "permanent_blocker_active";

    return NULL;  /* no named deterministic cause — genuine liveness loss */
}

/* ── Targeted tip-extension SELECTION-wedge remedy ─────────────────────
 *
 * The cause-probe named "tip_selection_wedge": a valid direct successor to the
 * frozen active tip exists on the best-header chain but find_most_work_chain
 * skips it on a persisted BLOCK_FAILED_VALID mask. Drive an evidence-based
 * revalidate of that SPECIFIC successor height (active tip + 1) — a bounded
 * re-selection, NOT a force-promote. process_block_revalidate only makes the
 * block eligible for a FULL re-validation (connect_block re-runs
 * Equihash/scripts/Sapling and re-marks FAILED if still invalid) once ≥2
 * oracles — or the local-authority pathway — agree on its hash; no consensus
 * gate is lowered. Runs on the shared supervisor thread, the same profile as
 * chain.coord_escalation's revalidate driver; process_block_revalidate
 * serializes its own block_index mutation on the activation controller mutex.
 * Bounded: wd_apply_tick calls this at most once per restart-threshold crossing
 * (the level<3 escalation guard). */
static void wd_drive_selection_remedy(void)
{
    if (!g_ms) return;
    struct block_index *tip = active_chain_tip(&g_ms->chain_active);
    if (!tip) return;
    int target = tip->nHeight + 1;
    atomic_fetch_add(&g_fires_selection_remedy, 1u);
#ifdef ZCL_TESTING
    atomic_store(&g_selection_remedy_last_target, (int64_t)target);
    if (atomic_load(&g_test_suppress_selection_remedy)) {
        LOG_INFO("chain_tip_watchdog", "[chain_tip_watchdog] selection-wedge remedy suppressed (test): would revalidate successor h=%d", target);
        return;
    }
#endif
    enum reval_result rr = process_block_revalidate(target, g_ms, NULL);
    LOG_WARN("chain_tip_watchdog", "[chain_tip_watchdog] tip-selection wedge: drove targeted revalidate of successor h=%d -> %s (NOT a blind restart)", target, reval_result_name(rr));
    event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                "chain_tip_watchdog selection_wedge_revalidate h=%d result=%s",
                target, reval_result_name(rr));
}

/* Return the highest locally evidenced height for which the node could have
 * useful chain work.  The active-chain height catches a reducer/H* lag; the
 * best-header height catches downloaded headers awaiting bodies/validation.
 * Absence of a main_state (hermetic decision tests and very early boot) is
 * UNKNOWN, never an assertion that the node is caught up. */
static bool wd_observed_work_frontier(int64_t *frontier_out)
{
    if (!frontier_out || !g_ms)
        return false;

    int64_t frontier = (int64_t)active_chain_height(&g_ms->chain_active);
    struct block_index *best_header = g_ms->pindex_best_header;
    if (best_header && (int64_t)best_header->nHeight > frontier)
        frontier = (int64_t)best_header->nHeight;
    if (frontier < 0)
        return false;
    *frontier_out = frontier;
    return true;
}

/* ── Supervisor tick ───────────────────────────────────────────────── */

/* The advance-or-escalate body, factored out so the supervisor tick and the
 * ZCL_TESTING seam share ONE code path. The production tick passes the live
 * chain height, the real monotonic clock, and do_shutdown=true; the test seam
 * injects a height + monotonic timestamp and do_shutdown=false. For the
 * production call this is byte-identical to the previous inline tick body. */
static void wd_apply_tick(int64_t h, int64_t now_us, bool do_shutdown)
{
    int64_t prev = atomic_load(&g_highest_tip);

    if (h > prev) {
        atomic_store(&g_highest_tip, h);
        atomic_store(&g_last_advance_us, now_us);
        atomic_store(&g_last_advance_unix, (int64_t)platform_time_wall_time_t());
        atomic_store(&g_stall_start_us, now_us);
        atomic_store(&g_at_observed_tip, false);
        atomic_store(&g_at_tip_restart_counted, false);
        atomic_store(&g_escalation, 0);
        /* Tip moved: if it cleared a recorded wedge episode (sustained
         * progress past the anchor), the restart worked — reset the
         * bounded-restart budget so the next hang gets a fresh round. */
        wd_note_advance(h);
        supervisor_progress(atomic_load(&g_id), h);
        return;
    }

    /* No height change is not itself a fault.  If neither active chain nor
     * best-header knowledge extends above the provable tip, there is no work
     * for a restart to unlock.  This is the normal steady state between ZCL
     * blocks.  Clear only the in-memory escalation timer; the real
     * last_advance timestamp remains truthful for diagnostics. */
    int64_t work_frontier = -1;
    bool frontier_known = wd_observed_work_frontier(&work_frontier);
    if (frontier_known)
        atomic_store(&g_observed_work_frontier, work_frontier);
    if (frontier_known && work_frontier <= h) {
        bool was_at_tip = atomic_exchange(&g_at_observed_tip, true);
        atomic_store(&g_escalation, 0);
        atomic_store(&g_stall_start_us, 0);
        if (!was_at_tip) {
            atomic_fetch_add(&g_at_observed_tip_entries, 1u);
            int64_t last_advance = atomic_load(&g_last_advance_us);
            int64_t idle_age_s = last_advance > 0
                ? (now_us - last_advance) / 1000000 : 0;
            LOG_INFO("chain_tip_watchdog",
                     "[chain_tip_watchdog] idle at observed tip: h=%lld "
                     "work_frontier=%lld idle_age=%llds; no chain work is "
                     "known above H*",
                     (long long)h, (long long)work_frontier,
                     (long long)idle_age_s);
            event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                "chain_tip_watchdog idle_at_tip h=%lld frontier=%lld "
                "idle_age=%llds",
                (long long)h, (long long)work_frontier,
                (long long)idle_age_s);
        }
        int64_t last_advance = atomic_load(&g_last_advance_us);
        int64_t idle_age_s = last_advance > 0
            ? (now_us - last_advance) / 1000000 : 0;
        int64_t restart_secs = atomic_load(&g_thr_restart);
        if (restart_secs > 0 && idle_age_s >= restart_secs &&
            !atomic_exchange(&g_at_tip_restart_counted, true)) {
            atomic_fetch_add(&g_restarts_suppressed_at_tip, 1u);
            LOG_INFO("chain_tip_watchdog",
                     "[chain_tip_watchdog] restart threshold crossed while "
                     "caught up: h=%lld work_frontier=%lld idle_age=%llds; "
                     "restart suppressed by observed-tip validation",
                     (long long)h, (long long)work_frontier,
                     (long long)idle_age_s);
            event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                "chain_tip_watchdog restart_suppressed_at_tip h=%lld "
                "frontier=%lld idle_age=%llds",
                (long long)h, (long long)work_frontier,
                (long long)idle_age_s);
        }
        supervisor_progress(atomic_load(&g_id), h);
        return;
    }

    /* Work appeared after a healthy quiet-at-tip interval.  Start the stall
     * budget NOW.  Reusing last_advance_us would charge normal chain silence
     * against the reducer and could request shutdown on the first new header. */
    bool was_at_tip = atomic_exchange(&g_at_observed_tip, false);
    atomic_store(&g_at_tip_restart_counted, false);
    int64_t stall_start = atomic_load(&g_stall_start_us);
    if (was_at_tip || stall_start == 0) {
        atomic_store(&g_stall_start_us, now_us);
        atomic_store(&g_escalation, 0);
        if (was_at_tip) {
            LOG_INFO("chain_tip_watchdog",
                     "[chain_tip_watchdog] work appeared above H*: h=%lld "
                     "work_frontier=%lld; actionable stall timer started",
                     (long long)h, (long long)work_frontier);
        }
        supervisor_progress(atomic_load(&g_id), h);
        return;
    }

    /* Tip didn't advance while work is known ahead. Compute ACTIONABLE age
     * and apply the escalation ladder. */
    int64_t age_s = (now_us - stall_start) / 1000000;
    int level = atomic_load(&g_escalation);

    int64_t thr_mirror  = atomic_load(&g_thr_mirror);
    int64_t thr_restart = atomic_load(&g_thr_restart);

    if (level < 1 && thr_mirror > 0 && age_s >= thr_mirror) {
        atomic_store(&g_escalation, 1);
        atomic_fetch_add(&g_fires_mirror, 1u);
        LOG_INFO("chain_tip_watchdog", "[chain_tip_watchdog] tip stalled: h=%lld age=%llds", (long long)h, (long long)age_s);
        event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
            "chain_tip_watchdog tip_stalled h=%lld age=%llds",
            (long long)h, (long long)age_s);
    }

    if (level < 3 && thr_restart > 0 && age_s >= thr_restart) {
        atomic_store(&g_escalation, 3);
        /* Cause-probe: classify WHY the tip is constant before escalating.
         * A stall pinned on a named deterministic cause — a persisted ok=0
         * precondition (tip_finalize successor_pending), an already-latched
         * operator_needed page, or an active PERMANENT-class blocker (bad
         * PoW / malformed block / consensus reject) — is byte-identical
         * every boot, so a process restart provably cannot clear it. Page +
         * name it and SKIP the restart power-cycle (it would only burn the
         * bounded budget and cost peer reputation). Only a stall with NO
         * named deterministic cause is genuine liveness loss that still gets
         * the bounded restart. The cause accessor returns a process-lifetime
         * string literal (race-safe to read off-thread). */
        const char *cause = wd_deterministic_stall_cause();
        bool deterministic = (cause != NULL);
        if (deterministic) {
            LOG_WARN("chain_tip_watchdog", "[chain_tip_watchdog] tip constant for %llds at h=%lld but " "deterministic blocker '%s' is named — a restart cannot clear " "it; skipping power-cycle, paging instead", (long long)age_s, (long long)h, cause);
            event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                "chain_tip_watchdog skip_restart_deterministic h=%lld age=%llds cause=%s",
                (long long)h, (long long)age_s, cause);
            /* The tip-extension SELECTION wedge has a targeted lever: drive an
             * evidence-based revalidate of the specific successor height rather
             * than only skipping the restart. Every other deterministic cause
             * falls through to the escalator hand-off in wd_decide_restart. */
            if (strcmp(cause, "tip_selection_wedge") == 0)
                wd_drive_selection_remedy();
        }
        /* Bounded path: increments the persisted no-progress counter and
         * requests shutdown; once the cap is hit it pages an operator and
         * stays up instead of power-cycling forever (see wd_decide_restart).
         * When `deterministic` it never requests shutdown — it pages an
         * operator with the named cause and stays up degraded. */
        wd_decide_restart(h, age_s, do_shutdown, deterministic);
    }

    /* Keep the supervisor's progress timer happy: we ARE ticking, just
     * not making chain progress. The escalation logic above is the
     * authoritative path; supervisor stall would be redundant noise. */
    supervisor_progress(atomic_load(&g_id), h);
}

/* The PROVABLE tip (H* = reducer_frontier_compute_hstar), NOT
 * active_chain_height. active_chain_height is the DOWNLOAD/header tip: it
 * climbs on every block admitted to the index even while the fold is frozen
 * one below it, so keying this liveness watchdog on it would false-green it
 * through the exact forward-sync wedge it exists to catch (the tip "advances"
 * by raw download churn while H* — the only height the node may serve — stays
 * stuck, so the watchdog never escalates / restarts / pages). H* only advances
 * on a real re-derived fold step, so a frozen H* is a genuine liveness loss.
 * On a transient progress.kv read failure, fall back to the active-chain
 * height rather than report a phantom 0 that would itself trip a false stall. */
static int64_t wd_provable_tip(void)
{
    sqlite3 *db = progress_store_db();
    if (db) {
        progress_store_tx_lock();
        int32_t hstar = -1;
        int32_t served_floor = -1;
        bool ok = reducer_frontier_compute_hstar(db, &hstar, &served_floor);
        progress_store_tx_unlock();
        if (ok && hstar >= 0)
            return (int64_t)hstar;
        LOG_WARN("chain_tip_watchdog",
                 "[chain_tip_watchdog] H* recompute failed — falling back to "
                 "active-chain height for this tick");
    }
    return g_ms ? (int64_t)active_chain_height(&g_ms->chain_active) : -1;
}

static void chain_tip_wd_tick(struct liveness_contract *c)
{
    (void)c;
    if (!g_ms) return;
    /* Production: provable tip H*, real monotonic clock, real shutdown. */
    wd_apply_tick(wd_provable_tip(), mono_us_now(), /*do_shutdown=*/true);
}

/* ── Public API ────────────────────────────────────────────────────── */

void chain_tip_watchdog_register(struct main_state *ms)
{
    if (!ms) return;
    if (atomic_load(&g_id) != SUPERVISOR_INVALID_ID) return;  /* idempotent */
    g_ms = ms;
    /* Reload bounded-restart memory from progress.kv. If this process is
     * the Nth restart at a deterministic wedge, this is where it learns
     * the previous N-1 restarts already failed. */
    (void)wd_persist_load();
    liveness_contract_init(&g_contract, "chain.chain_tip_watchdog");
    atomic_store(&g_contract.period_secs, (int64_t)30);
    atomic_store(&g_contract.deadline_secs, (int64_t)0);
    atomic_store(&g_contract.progress_max_quiet_us, (int64_t)0);
    g_contract.on_tick  = chain_tip_wd_tick;
    g_contract.on_stall = NULL;
    supervisor_domains_init();
    atomic_store(&g_id, supervisor_register_in_domain(g_chain_sup, &g_contract));
    if (atomic_load(&g_id) == SUPERVISOR_INVALID_ID) {
        LOG_WARN("chain_tip_watchdog", "[chain_tip_watchdog] WARN register failed");
    }
}



void chain_tip_watchdog_get_stats(struct chain_tip_watchdog_stats *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->registered = (atomic_load(&g_id) != SUPERVISOR_INVALID_ID);
    out->highest_tip = atomic_load(&g_highest_tip);
    out->last_advance_unix = atomic_load(&g_last_advance_unix);
    int64_t last = atomic_load(&g_last_advance_us);
    int64_t now = mono_us_now();
    out->age_secs = (last == 0) ? 0 : (now - last) / 1000000;
    out->escalation_level = atomic_load(&g_escalation);
    out->fires_mirror = atomic_load(&g_fires_mirror);
    out->fires_reserved = atomic_load(&g_fires_reserved);
    out->fires_restart = atomic_load(&g_fires_restart);
    out->threshold_mirror_secs = atomic_load(&g_thr_mirror);
    out->threshold_reserved_secs = atomic_load(&g_thr_reserved);
    out->threshold_restart_secs = atomic_load(&g_thr_restart);
    out->persisted_stuck_height = atomic_load(&g_persisted_stuck_height);
    out->no_progress_restarts = atomic_load(&g_no_progress_restarts);
    out->max_restarts = CHAIN_TIP_WD_MAX_RESTARTS;
    out->operator_needed = atomic_load(&g_operator_needed);
    out->fires_operator_needed = atomic_load(&g_fires_operator_needed);
    out->fires_selection_remedy = atomic_load(&g_fires_selection_remedy);
    out->observed_work_frontier =
        atomic_load(&g_observed_work_frontier);
    out->at_observed_tip = atomic_load(&g_at_observed_tip);
    out->at_observed_tip_entries =
        atomic_load(&g_at_observed_tip_entries);
    out->restarts_suppressed_at_tip =
        atomic_load(&g_restarts_suppressed_at_tip);
}

bool chain_tip_watchdog_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    struct chain_tip_watchdog_stats s;
    chain_tip_watchdog_get_stats(&s);
    json_push_kv_bool(out, "registered", s.registered);
    json_push_kv_int(out, "highest_tip", s.highest_tip);
    json_push_kv_int(out, "last_advance_unix", s.last_advance_unix);
    json_push_kv_int(out, "age_secs", s.age_secs);
    json_push_kv_int(out, "escalation_level", (int64_t)s.escalation_level);
    json_push_kv_int(out, "fires_mirror", (int64_t)s.fires_mirror);
    json_push_kv_int(out, "fires_reserved", (int64_t)s.fires_reserved);
    json_push_kv_int(out, "fires_restart", (int64_t)s.fires_restart);
    json_push_kv_int(out, "threshold_mirror_secs", s.threshold_mirror_secs);
    json_push_kv_int(out, "threshold_reserved_secs", s.threshold_reserved_secs);
    json_push_kv_int(out, "threshold_restart_secs", s.threshold_restart_secs);
    json_push_kv_int(out, "persisted_stuck_height", s.persisted_stuck_height);
    json_push_kv_int(out, "no_progress_restarts", (int64_t)s.no_progress_restarts);
    json_push_kv_int(out, "max_restarts", (int64_t)s.max_restarts);
    json_push_kv_bool(out, "operator_needed", s.operator_needed);
    json_push_kv_int(out, "fires_operator_needed",
                     (int64_t)s.fires_operator_needed);
    json_push_kv_int(out, "fires_selection_remedy",
                     (int64_t)s.fires_selection_remedy);
    json_push_kv_int(out, "observed_work_frontier",
                     s.observed_work_frontier);
    json_push_kv_bool(out, "at_observed_tip", s.at_observed_tip);
    json_push_kv_int(out, "at_observed_tip_entries",
                     (int64_t)s.at_observed_tip_entries);
    json_push_kv_int(out, "restarts_suppressed_at_tip",
                     (int64_t)s.restarts_suppressed_at_tip);
    return true;
}

#ifdef ZCL_TESTING
/* ── Test seams ──────────────────────────────────────────────────────── */

void chain_tip_watchdog_test_reset_runtime(void)
{
    /* Simulate a fresh process: zero ALL in-memory state. Does NOT touch
     * progress.kv — that's the whole point of the persistence test. */
    atomic_store(&g_highest_tip, 0);
    atomic_store(&g_last_advance_us, 0);
    atomic_store(&g_last_advance_unix, 0);
    atomic_store(&g_stall_start_us, 0);
    atomic_store(&g_escalation, 0);
    atomic_store(&g_fires_mirror, 0u);
    atomic_store(&g_fires_reserved, 0u);
    atomic_store(&g_fires_restart, 0u);
    atomic_store(&g_fires_operator_needed, 0u);
    atomic_store(&g_persisted_stuck_height, -1);
    atomic_store(&g_no_progress_restarts, 0);
    atomic_store(&g_operator_needed, false);
    atomic_store(&g_respawn_requested, false);
    atomic_store(&g_fires_selection_remedy, 0u);
    atomic_store(&g_test_suppress_selection_remedy, false);
    atomic_store(&g_selection_remedy_last_target, (int64_t)-1);
    atomic_store(&g_observed_work_frontier, -1);
    atomic_store(&g_at_observed_tip, false);
    atomic_store(&g_at_tip_restart_counted, false);
    atomic_store(&g_at_observed_tip_entries, 0u);
    atomic_store(&g_restarts_suppressed_at_tip, 0u);
}

void chain_tip_watchdog_test_load_persisted(void)
{
    (void)wd_persist_load();
}

bool chain_tip_watchdog_test_escalate_restart(int64_t h)
{
    /* do_shutdown=false: never actually kill the test process. */
    return wd_decide_restart(h, /*age_s=*/1200, /*do_shutdown=*/false,
                             /*deterministic_stall=*/false);
}

bool chain_tip_watchdog_test_escalate_deterministic(int64_t h)
{
    /* Drive the cause-probe path: a deterministic on-disk stall pages an
     * operator immediately instead of requesting a restart. do_shutdown=false. */
    return wd_decide_restart(h, /*age_s=*/1200, /*do_shutdown=*/false,
                             /*deterministic_stall=*/true);
}

void chain_tip_watchdog_test_observe_advance(int64_t h)
{
    wd_note_advance(h);
}

/* Override the escalation thresholds (seconds) so a unit test can cross the
 * mirror/restart boundaries with small injected ages. */
void chain_tip_watchdog_test_set_thresholds(int64_t mirror_secs,
                                            int64_t reserved_secs,
                                            int64_t restart_secs)
{
    atomic_store(&g_thr_mirror, mirror_secs);
    atomic_store(&g_thr_reserved, reserved_secs);
    atomic_store(&g_thr_restart, restart_secs);
}

/* Drive ONE supervisor tick with an injected stuck height `h` and an injected
 * monotonic timestamp `now_us`, running the REAL escalation ladder
 * (wd_apply_tick). do_shutdown=false suppresses the actual shutdown syscall so
 * the test process survives. */
void chain_tip_watchdog_test_tick(int64_t h, int64_t now_us, bool do_shutdown)
{
    wd_apply_tick(h, now_us, do_shutdown);
}

void chain_tip_watchdog_test_set_main_state(struct main_state *ms)
{
    g_ms = ms;
}

const char *chain_tip_watchdog_test_stall_cause(void)
{
    return wd_deterministic_stall_cause();
}

void chain_tip_watchdog_test_set_suppress_selection_remedy(bool suppress)
{
    atomic_store(&g_test_suppress_selection_remedy, suppress);
}

int64_t chain_tip_watchdog_test_selection_remedy_target(void)
{
    return atomic_load(&g_selection_remedy_last_target);
}
#endif
