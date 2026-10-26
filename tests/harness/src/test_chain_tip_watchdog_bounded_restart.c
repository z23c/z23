/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * P0 resilience test for chain_tip_watchdog's bounded-restart logic.
 *
 * Bounded-restart logic of chain_tip_watchdog. The watchdog persists
 * (stuck_height, consecutive_no_progress_restarts) in progress.kv so the
 * counter SURVIVES the restart it triggers; after CHAIN_TIP_WD_MAX_RESTARTS
 * it stops restarting and pages (EV_OPERATOR_NEEDED), staying up degraded,
 * so a DETERMINISTIC wedge cannot restart forever.
 * Coverage:
 *   (a) K no-progress restarts at the SAME height across simulated process
 *       boots → after the cap, NO further shutdown request, operator_needed
 *       fired exactly once at the cap.
 *   (b) only SUSTAINED progress (CHAIN_TIP_WD_EPISODE_CLEAR blocks past the
 *       episode anchor) resets the counter; a 1-block creep does NOT.
 *   (c) the persisted counter is what carries across boots — wiping ONLY
 *       in-memory state (not progress.kv) and reloading reproduces the count.
 *   (d) a creeping wedge (tip gains 1-2 blocks per restart, re-wedges within
 *       CHAIN_TIP_WD_EPISODE_MARGIN of the anchor) is ONE episode: the count
 *       carries, the cap still bites; outside the margin is a new episode. */

#include "test/test_core.h"
#include "test/test_block_map.h"

#include "config/boot_background_workers.h"
#include "services/chain_tip_watchdog.h"
#include "services/sticky_escalator.h"
#include "storage/progress_store.h"
#include "event/event.h"
#include "util/blocker.h"
#include "chain/chain.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define WD_CHECK(name, expr) do { \
    printf("chain_tip_wd_bounded: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static _Atomic int g_operator_events;
static _Atomic supervisor_child_id g_restart_worker_id = SUPERVISOR_INVALID_ID;
static struct liveness_contract g_restart_worker_contract;

static void wd_operator_observer(enum event_type type, uint32_t peer_id,
                                 const void *payload, uint32_t payload_len,
                                 void *ctx)
{
    (void)type; (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    atomic_fetch_add(&g_operator_events, 1);
}

/* Model one process boot: zero in-memory state, then reload the persisted
 * counters from the open progress.kv (exactly what register() does). */
static void wd_sim_boot(void)
{
    chain_tip_watchdog_test_reset_runtime();
    chain_tip_watchdog_test_load_persisted();
}

/* ── Synthetic block-index fixture for the tip-extension SELECTION wedge ──
 * Mirrors test_most_work_selector.c's mw_mk_idx: heap block_index + owned
 * hash, inserted into the map, linked by pprev, VALID_SCRIPTS + HAVE_DATA. */
static struct block_index *wd_mk_idx(struct main_state *ms, int height,
                                     uint64_t work, uint8_t seed,
                                     struct block_index *prev)
{
    struct block_index *bi = zcl_calloc(1, sizeof(*bi), "test_wd_block_index");
    struct uint256 *hp = zcl_malloc(sizeof(*hp), "test_wd_hash");
    if (!bi || !hp) { free(bi); free(hp); return NULL; }
    memset(hp, seed, sizeof(*hp));
    hp->data[0] = (uint8_t)height;
    hp->data[1] = seed;
    bi->nHeight = height;
    bi->phashBlock = hp;
    bi->pprev = prev;
    bi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    bi->nTx = 1;
    bi->nChainTx = prev ? prev->nChainTx + 1 : 1;
    arith_uint256_set_u64(&bi->nChainWork, work);
    if (!test_block_map_insert(&ms->map_block_index, hp, bi)) {
        free((void *)(uintptr_t)bi->phashBlock);
        free(bi);
        return NULL;
    }
    return bi;
}

static void wd_free_idx(struct block_index *bi)
{
    if (!bi) return;
    free((void *)(uintptr_t)bi->phashBlock);
    free(bi);
}

static int wd_check_boot_worker_supervisor_restart(void)
{
    int failures = 0;

    atomic_store(&g_restart_worker_id, SUPERVISOR_INVALID_ID);
    boot_register_worker_supervisor(&g_restart_worker_id,
                                    &g_restart_worker_contract, &g_op_sup,
                                    "op.test_restart_worker", 30, 0);
    supervisor_child_id first = atomic_load(&g_restart_worker_id);
    WD_CHECK("boot worker supervisor registers first run",
             first != SUPERVISOR_INVALID_ID);

    boot_complete_worker_supervisor(&g_restart_worker_id);
    WD_CHECK("completed boot worker releases supervisor slot",
             atomic_load(&g_restart_worker_id) == SUPERVISOR_INVALID_ID);

    boot_register_worker_supervisor(&g_restart_worker_id,
                                    &g_restart_worker_contract, &g_op_sup,
                                    "op.test_restart_worker", 30, 0);
    supervisor_child_id second = atomic_load(&g_restart_worker_id);
    WD_CHECK("boot worker supervisor re-arms after restart",
             second != SUPERVISOR_INVALID_ID &&
             !atomic_load(&g_restart_worker_contract.completed));
    boot_complete_worker_supervisor(&g_restart_worker_id);
    return failures;
}

/* Worker stall handling: a typed blocker is recorded, cleared on resume,
 * and clear is safe on an empty/NULL contract. */
static int wd_check_worker_stall_blockers(void)
{
    int failures = 0;

    sticky_escalator_test_reset();
    blocker_reset_for_testing();

    struct liveness_contract c;
    liveness_contract_init(&c, "op.test_worker");
    atomic_store(&c.stall_reason, SUPERVISOR_STALL_TIME_DEADLINE);
    worker_on_stall(&c);

    WD_CHECK("worker stall records a typed blocker",
             blocker_exists("worker.stall.op.test_worker"));
    WD_CHECK("worker stall does NOT arm sticky escalator",
             !sticky_escalator_test_armed());

    /* A recovered worker retires its own stall blocker on resume (the
     * supervisor is observe-only and never clears it). */
    boot_worker_clear_stall_blocker(&c);
    WD_CHECK("recovered worker clears its stall blocker",
             !blocker_exists("worker.stall.op.test_worker"));
    /* Idempotent + safe on an empty-name contract (no crash, no spurious
     * "worker.stall." id). */
    boot_worker_clear_stall_blocker(&c);
    {
        struct liveness_contract empty;
        liveness_contract_init(&empty, "");
        boot_worker_clear_stall_blocker(&empty);
        boot_worker_clear_stall_blocker(NULL);
    }
    WD_CHECK("clear on empty/NULL contract raises no blocker",
             !blocker_exists("worker.stall."));

    blocker_reset_for_testing();
    sticky_escalator_test_reset();
    return failures;
}

/* (a): same-height boots climb the restart counter to the cap, then the
 * watchdog pages instead of restarting. */
static int wd_check_deterministic_wedge_capped_restarts(void)
{
    int failures = 0;
    const int CAP = CHAIN_TIP_WD_MAX_RESTARTS;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "chain_tip_wd", "wedge");
    WD_CHECK("open progress.kv", progress_store_open(dir));
    atomic_store(&g_operator_events, 0);

    const int64_t STUCK_H = 3123688;  /* the live wedge height */
    bool all_restarts_requested_shutdown = true;
    int operator_pages = 0;

    /* Simulate restarts 1..CAP+2. Each iteration is a fresh process at
     * the SAME stuck height: boot (reload persisted count), then hit the
     * restart escalation. Below the cap it requests shutdown (true);
     * at/after the cap it pages instead (false). */
    for (int restart = 1; restart <= CAP + 2; restart++) {
        wd_sim_boot();
        bool requested = chain_tip_watchdog_test_escalate_restart(STUCK_H);

        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);

        if (restart <= CAP) {
            /* restarts 1..CAP: shutdown requested, counter climbs. */
            if (!requested) all_restarts_requested_shutdown = false;
            char label[96];
            snprintf(label, sizeof(label),
                     "restart %d <= cap requests shutdown", restart);
            WD_CHECK(label, requested);
            snprintf(label, sizeof(label),
                     "restart %d persisted count == %d", restart, restart);
            WD_CHECK(label, s.no_progress_restarts == restart);
            WD_CHECK("not yet operator_needed below cap",
                     !s.operator_needed);
        } else {
            /* restart CAP+1, CAP+2: NO shutdown, operator paged. */
            char label[96];
            snprintf(label, sizeof(label),
                     "restart %d > cap does NOT request shutdown", restart);
            WD_CHECK(label, !requested);
            WD_CHECK("operator_needed flag set past cap",
                     s.operator_needed);
            operator_pages++;
        }
    }

    WD_CHECK("all sub-cap restarts requested shutdown",
             all_restarts_requested_shutdown);
    /* We paged on CAP+1 and CAP+2 (two over-cap escalations). */
    WD_CHECK("paged operator on each over-cap escalation",
             operator_pages == 2);
    /* The watchdog hands an over-cap / deterministic stall to the
     * always-terminating remedy escalator (sticky_escalator_note_stall)
     * and emits no terminal EV_OPERATOR_NEEDED, so the observer sees
     * ZERO; fires_operator_needed stays as a "ladder engaged" bit. */
    WD_CHECK("watchdog does NOT emit terminal EV_OPERATOR_NEEDED "
             "(handed to escalator)",
             atomic_load(&g_operator_events) == 0);

    struct chain_tip_watchdog_stats s;
    chain_tip_watchdog_get_stats(&s);
    /* The fires_* counters are per-process (reset each simulated boot).
     * The final boot (restart CAP+2) paged exactly once and requested
     * no shutdown — so for THAT process: 0 restart fires, 1 page. */
    WD_CHECK("final process fired no shutdown request",
             s.fires_restart == 0);
    WD_CHECK("final process paged exactly once",
             s.fires_operator_needed == 1);
    WD_CHECK("persisted_stuck_height recorded",
             s.persisted_stuck_height == STUCK_H);
    WD_CHECK("max_restarts reported", s.max_restarts == CAP);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* (b): a transient hang counts one restart; only sustained advance past
 * the anchor resets the budget. */
static int wd_check_transient_hang_resets_budget(void)
{
    int failures = 0;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "chain_tip_wd", "transient");
    WD_CHECK("open progress.kv (transient)", progress_store_open(dir));

    const int64_t STUCK_H = 1000000;

    /* Restart #1 at STUCK_H — a transient hang. */
    wd_sim_boot();
    bool r1 = chain_tip_watchdog_test_escalate_restart(STUCK_H);
    WD_CHECK("transient restart 1 requests shutdown", r1);
    {
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("transient count == 1", s.no_progress_restarts == 1);
    }

    /* A 1-block creep is the creeping-wedge signature and must NOT clear
     * the budget; only sustained progress past the anchor clears. */
    wd_sim_boot();
    {
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("after reboot, count still 1 (loaded from kv)",
                 s.no_progress_restarts == 1);
    }
    chain_tip_watchdog_test_observe_advance(STUCK_H + 1);
    {
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("1-block creep keeps count",
                 s.no_progress_restarts == 1);
        WD_CHECK("1-block creep keeps episode anchor",
                 s.persisted_stuck_height == STUCK_H);
    }
    chain_tip_watchdog_test_observe_advance(
        STUCK_H + CHAIN_TIP_WD_EPISODE_CLEAR);
    {
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("sustained advance resets count to 0",
                 s.no_progress_restarts == 0);
        WD_CHECK("sustained advance clears persisted_stuck_height",
                 s.persisted_stuck_height == -1);
        WD_CHECK("sustained advance clears operator_needed",
                 !s.operator_needed);
    }

    /* The reset must SURVIVE a reboot (was it persisted?). A LATER hang
     * at a new height then gets a fresh full restart budget. */
    wd_sim_boot();
    {
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("reset persisted across reboot (count 0)",
                 s.no_progress_restarts == 0);
    }
    const int64_t NEW_STUCK = 2000000;
    bool r_new = chain_tip_watchdog_test_escalate_restart(NEW_STUCK);
    {
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("new-height hang gets fresh restart (shutdown requested)",
                 r_new);
        WD_CHECK("new-height count starts at 1",
                 s.no_progress_restarts == 1);
        WD_CHECK("new-height tracked as stuck",
                 s.persisted_stuck_height == NEW_STUCK);
    }

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* (c): the restart count and stuck height come back from progress.kv
 * after a hard close and reopen. */
static int wd_check_count_survives_store_reopen(void)
{
    int failures = 0;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "chain_tip_wd", "persist");
    WD_CHECK("open progress.kv (persist)", progress_store_open(dir));

    const int64_t STUCK_H = 42;

    wd_sim_boot();
    (void)chain_tip_watchdog_test_escalate_restart(STUCK_H);
    wd_sim_boot();
    (void)chain_tip_watchdog_test_escalate_restart(STUCK_H);
    {
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("two boots at same height → count 2",
                 s.no_progress_restarts == 2);
    }

    /* Hard close + reopen the store: the count must come back from disk,
     * not from a lingering in-memory atomic. */
    progress_store_close();
    WD_CHECK("reopen progress.kv", progress_store_open(dir));
    wd_sim_boot();
    {
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("count survives close+reopen of progress.kv",
                 s.no_progress_restarts == 2);
        WD_CHECK("stuck height survives close+reopen",
                 s.persisted_stuck_height == STUCK_H);
    }

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* (d): a tip creeping inside the episode margin stays one episode up to
 * the cap; outside the margin it re-anchors. */
static int wd_check_creeping_wedge_same_episode(void)
{
    int failures = 0;
    const int CAP = CHAIN_TIP_WD_MAX_RESTARTS;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "chain_tip_wd", "creep");
    WD_CHECK("open progress.kv (creep)", progress_store_open(dir));

    /* Each restart "helps" by 2 blocks, then the tip re-wedges. Episode
     * keying carries the count and keeps the original anchor. */
    const int64_t ANCHOR = 3132687;
    int64_t h = ANCHOR;
    for (int restart = 1; restart <= CAP; restart++) {
        wd_sim_boot();
        bool requested = chain_tip_watchdog_test_escalate_restart(h);
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        char label[96];
        snprintf(label, sizeof(label),
                 "creep restart %d <= cap requests shutdown", restart);
        WD_CHECK(label, requested);
        snprintf(label, sizeof(label),
                 "creep restart %d carries count across heights", restart);
        WD_CHECK(label, s.no_progress_restarts == restart);
        WD_CHECK("creep keeps episode anchor",
                 s.persisted_stuck_height == ANCHOR);
        h += 2;  /* tip creeps, stays inside the episode margin */
    }

    /* Over the cap, still inside the margin: page, do NOT restart. */
    wd_sim_boot();
    bool over_cap = chain_tip_watchdog_test_escalate_restart(h);
    WD_CHECK("creep over cap does NOT request shutdown", !over_cap);
    {
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("creep over cap pages operator", s.operator_needed);
    }

    /* A wedge OUTSIDE the margin is a genuinely new episode. */
    wd_sim_boot();
    const int64_t NEW_ANCHOR = ANCHOR + CHAIN_TIP_WD_EPISODE_MARGIN + 1;
    bool r_new = chain_tip_watchdog_test_escalate_restart(NEW_ANCHOR);
    {
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("outside-margin wedge requests shutdown", r_new);
        WD_CHECK("outside-margin wedge count restarts at 1",
                 s.no_progress_restarts == 1);
        WD_CHECK("outside-margin wedge re-anchors",
                 s.persisted_stuck_height == NEW_ANCHOR);
    }

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* (e): a deterministic stall pages on the first escalation and burns
 * zero restarts. */
static int wd_check_deterministic_stall_pages_immediately(void)
{
    int failures = 0;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "chain_tip_wd", "deterministic");
    WD_CHECK("open progress.kv (deterministic)", progress_store_open(dir));
    atomic_store(&g_operator_events, 0);
    sticky_escalator_test_reset();

    const int64_t STUCK_H = 3151411;  /* the live deterministic wedge */
    wd_sim_boot();
    bool requested = chain_tip_watchdog_test_escalate_deterministic(STUCK_H);

    struct chain_tip_watchdog_stats s;
    chain_tip_watchdog_get_stats(&s);
    WD_CHECK("deterministic stall does NOT request shutdown", !requested);
    WD_CHECK("deterministic stall pages operator on first escalation",
             s.operator_needed);
    WD_CHECK("deterministic stall burns ZERO restarts",
             s.no_progress_restarts == 0);
    WD_CHECK("deterministic stall fired exactly one page",
             s.fires_operator_needed == 1);
    WD_CHECK("deterministic stall requested no shutdown (0 restart fires)",
             s.fires_restart == 0);
    WD_CHECK("deterministic chain-tip stall arms sticky escalator",
             sticky_escalator_test_armed());
    /* A deterministic stall is HANDED to the remedy escalator; the
     * fires_operator_needed counter bumps but the EV_OPERATOR_NEEDED
     * observer sees ZERO from this seam. */
    WD_CHECK("deterministic stall does NOT emit terminal "
             "EV_OPERATOR_NEEDED (handed to escalator)",
             atomic_load(&g_operator_events) == 0);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    sticky_escalator_test_reset();
    return failures;
}

/* (f): the escalation ladder over injected ticks — mirror fires once,
 * the level jumps to restart, and the reserved rung stays inert. */
static int wd_check_escalation_ladder_ticks(void)
{
    int failures = 0;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "chain_tip_wd", "ladder");
    WD_CHECK("open progress.kv (ladder)", progress_store_open(dir));

    /* Capture the boot-default thresholds to restore afterwards
     * (reset_runtime does not touch them). */
    struct chain_tip_watchdog_stats def;
    chain_tip_watchdog_get_stats(&def);

    chain_tip_watchdog_test_reset_runtime();   /* fresh in-memory ladder */

    /* Tight thresholds: mirror@100s, restart@200s; reserved@150s is set
     * but must stay inert. */
    chain_tip_watchdog_test_set_thresholds(/*mirror=*/100,
                                           /*reserved=*/150,
                                           /*restart=*/200);

    const int64_t LADDER_H = 5000000;   /* a fixed stuck height */
    const int64_t US = 1000000;         /* microseconds per second */
    const int64_t T0 = 1000 * US;       /* non-zero monotonic base */

    /* Tick 1 @ T0: the tip advances (h > prev=0), seeding a NON-ZERO
     * last_advance_us. No escalation yet. */
    chain_tip_watchdog_test_tick(LADDER_H, T0, /*do_shutdown=*/false);
    {
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("seed tick: level 0", s.escalation_level == 0);
        WD_CHECK("seed tick: no mirror fire", s.fires_mirror == 0);
        WD_CHECK("seed tick: reserved inert", s.fires_reserved == 0);
        WD_CHECK("seed tick: no restart fire", s.fires_restart == 0);
    }

    /* Tick 2 @ T0+99s: same height, age 99s < mirror(100). Nothing yet —
     * proves we don't escalate one tick early. */
    chain_tip_watchdog_test_tick(LADDER_H, T0 + 99 * US, false);
    {
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("pre-mirror tick: still level 0", s.escalation_level == 0);
        WD_CHECK("pre-mirror tick: no mirror fire", s.fires_mirror == 0);
        WD_CHECK("pre-mirror tick: reserved inert", s.fires_reserved == 0);
    }

    /* Tick 3 @ T0+150s: age 150s >= mirror(100), < restart(200). Level 1
     * fires EXACTLY once. 150s == thr_reserved: the reserved rung MUST
     * stay inert (level==1, fires_reserved==0). */
    chain_tip_watchdog_test_tick(LADDER_H, T0 + 150 * US, false);
    {
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("mirror tick: level == 1", s.escalation_level == 1);
        WD_CHECK("mirror tick: mirror fired once", s.fires_mirror == 1);
        WD_CHECK("mirror tick: reserved STILL inert at thr_reserved",
                 s.fires_reserved == 0);
        WD_CHECK("mirror tick: no restart yet", s.fires_restart == 0);
    }

    /* Tick 4 @ T0+180s: still in [mirror,restart). Level holds 1; mirror
     * does NOT re-fire (the one-shot `level < 1` guard). */
    chain_tip_watchdog_test_tick(LADDER_H, T0 + 180 * US, false);
    {
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("hold tick: level holds at 1", s.escalation_level == 1);
        WD_CHECK("hold tick: mirror does not re-fire", s.fires_mirror == 1);
        WD_CHECK("hold tick: reserved inert", s.fires_reserved == 0);
    }

    /* Tick 5 @ T0+205s: age >= restart(200). Level JUMPS to 3 and the
     * bounded-restart decision fires; with no TF_BLOCKED reason the
     * stall is not deterministic (fires_restart, not the operator page). */
    chain_tip_watchdog_test_tick(LADDER_H, T0 + 205 * US, false);
    {
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("restart tick: level JUMPS to 3", s.escalation_level == 3);
        WD_CHECK("restart tick: NEVER passed through level 2",
                 s.escalation_level != 2);
        WD_CHECK("restart tick: restart decision fired once",
                 s.fires_restart == 1);
        WD_CHECK("restart tick: reserved STILL inert after restart",
                 s.fires_reserved == 0);
        WD_CHECK("restart tick: bounded counter incremented",
                 s.no_progress_restarts == 1);
        WD_CHECK("restart tick: anchored at the stuck height",
                 s.persisted_stuck_height == LADDER_H);
    }

    /* Tick 6 @ T0+240s: past restart, still stuck. Level holds 3; restart
     * does NOT re-fire (one-shot `level < 3` guard). reserved inert. */
    chain_tip_watchdog_test_tick(LADDER_H, T0 + 240 * US, false);
    {
        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("post-restart tick: level holds at 3", s.escalation_level == 3);
        WD_CHECK("post-restart tick: restart does not re-fire",
                 s.fires_restart == 1);
        WD_CHECK("post-restart tick: reserved inert to the end",
                 s.fires_reserved == 0);
    }

    progress_store_close();
    test_cleanup_tmpdir(dir);

    /* Restore the boot-default thresholds captured above. */
    chain_tip_watchdog_test_set_thresholds(def.threshold_mirror_secs,
                                           def.threshold_reserved_secs,
                                           def.threshold_restart_secs);
    return failures;
}

/* (g): a caught-up chain at H* stays up past the restart threshold;
 * new work opens a fresh stall interval. */
static int wd_check_quiet_chain_does_not_restart(void)
{
    int failures = 0;

    blocker_reset_for_testing();
    sticky_escalator_test_reset();
    chain_tip_watchdog_test_reset_runtime();

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    main_state_init(&ms);
    struct block_index *g = wd_mk_idx(&ms, 0, 1, 0x00, NULL);
    struct block_index *tip = wd_mk_idx(&ms, 1, 10, 0x51, g);
    struct block_index *next = wd_mk_idx(&ms, 2, 20, 0x52, tip);
    WD_CHECK("at-tip fixture built", g && tip && next);
    if (g && tip && next) {
        active_chain_move_window_tip(&ms.chain_active, g);
        active_chain_move_window_tip(&ms.chain_active, tip);
        ms.pindex_best_header = tip;
        chain_tip_watchdog_test_set_main_state(&ms);
        chain_tip_watchdog_test_set_thresholds(/*mirror=*/100,
                                               /*reserved=*/150,
                                               /*restart=*/200);

        const int64_t US = 1000000;
        const int64_t T0 = 1000 * US;
        chain_tip_watchdog_test_tick(1, T0, false); /* seed advance */
        chain_tip_watchdog_test_tick(1, T0 + 205 * US, false);

        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("quiet caught-up chain is classified at observed tip",
                 s.at_observed_tip);
        WD_CHECK("caught-up frontier equals H*",
                 s.observed_work_frontier == 1);
        WD_CHECK("quiet caught-up chain does not restart",
                 s.fires_restart == 0 && s.no_progress_restarts == 0);
        WD_CHECK("suppressed at-tip restart is counted",
                 s.restarts_suppressed_at_tip == 1);

        /* A header appears after the long quiet interval.  The first tick
         * starts a fresh timer; it cannot restart immediately. */
        ms.pindex_best_header = next;
        chain_tip_watchdog_test_tick(1, T0 + 206 * US, false);
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("new work exits at-tip state", !s.at_observed_tip);
        WD_CHECK("new work receives a fresh stall interval",
                 s.fires_restart == 0 && s.escalation_level == 0);

        chain_tip_watchdog_test_tick(1, T0 + 405 * US, false);
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("fresh interval does not fire one second early",
                 s.fires_restart == 0);
        chain_tip_watchdog_test_tick(1, T0 + 407 * US, false);
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("known work still stuck past fresh interval restarts",
                 s.fires_restart == 1);

        chain_tip_watchdog_test_set_main_state(NULL);
    }
    wd_free_idx(next);
    wd_free_idx(tip);
    wd_free_idx(g);
    main_state_free(&ms);
    blocker_reset_for_testing();
    sticky_escalator_test_reset();
    chain_tip_watchdog_test_reset_runtime();
    return failures;
}

/* True only when every stale-fork fixture block_index allocated. */
static bool wd_stale_fork_fixture_complete(struct block_index *g2,
                                           struct block_index *c1,
                                           struct block_index *c2,
                                           struct block_index *f1,
                                           struct block_index *f2,
                                           struct block_index *f3)
{
    return g2 && c1 && c2 && f1 && f2 && f3;
}

/* The positive tip-selection wedge on a FAILED_VALID successor, plus the
 * caught-up and clean-successor negatives. */
static int wd_check_selection_wedge_remedy_and_negatives(void)
{
    int failures = 0;

    /* Positive: FAILED_VALID direct successor above a frozen tip. */
    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    main_state_init(&ms);
    struct block_index *g  = wd_mk_idx(&ms, 0, 1,  0x00, NULL);
    struct block_index *a1 = wd_mk_idx(&ms, 1, 10, 0x0A, g);
    struct block_index *a2 = wd_mk_idx(&ms, 2, 20, 0x0B, a1);
    WD_CHECK("selection-wedge fixture built", g && a1 && a2);
    if (g && a1 && a2) {
        active_chain_move_window_tip(&ms.chain_active, g);
        active_chain_move_window_tip(&ms.chain_active, a1); /* tip = a1 */
        ms.pindex_best_header = a2;                          /* header ahead */
        a2->nStatus |= BLOCK_FAILED_VALID;                  /* skipped */

        chain_tip_watchdog_test_set_main_state(&ms);
        const char *cause = chain_tip_watchdog_test_stall_cause();
        WD_CHECK("cause-probe classifies the tip-selection wedge",
                 cause && strcmp(cause, "tip_selection_wedge") == 0);

        /* Drive the real restart-threshold ladder over the tick body with
         * the remedy suppressed: it must drive the targeted revalidate of
         * a2's height and NOT request a restart. */
        chain_tip_watchdog_test_set_suppress_selection_remedy(true);
        chain_tip_watchdog_test_set_thresholds(/*mirror=*/100,
                                               /*reserved=*/150,
                                               /*restart=*/200);
        const int64_t US = 1000000;
        const int64_t T0 = 1000 * US;
        const int64_t STUCK = 1; /* injected provable-tip for the ladder */
        chain_tip_watchdog_test_tick(STUCK, T0, /*do_shutdown=*/false);
        chain_tip_watchdog_test_tick(STUCK, T0 + 205 * US, false);

        struct chain_tip_watchdog_stats s;
        chain_tip_watchdog_get_stats(&s);
        WD_CHECK("wedge drove the selection remedy (once)",
                 s.fires_selection_remedy == 1);
        WD_CHECK("selection remedy targeted the successor height (a1+1)",
                 chain_tip_watchdog_test_selection_remedy_target() ==
                     a1->nHeight + 1);
        WD_CHECK("wedge did NOT blind-restart (0 restart fires)",
                 s.fires_restart == 0);
        WD_CHECK("wedge burned zero bounded restarts",
                 s.no_progress_restarts == 0);
        WD_CHECK("wedge handed off to the always-terminating escalator",
                 sticky_escalator_test_armed());

        /* Negative A — caught up (best-header == tip): not the wedge. */
        chain_tip_watchdog_test_reset_runtime();
        ms.pindex_best_header = a1;
        WD_CHECK("caught-up tip is NOT classified as a selection wedge",
                 !chain_tip_watchdog_test_stall_cause() ||
                 strcmp(chain_tip_watchdog_test_stall_cause(),
                        "tip_selection_wedge") != 0);

        /* Negative B — clean, selectable successor (no FAILED mask): the
         * reducer would advance; not a wedge. */
        ms.pindex_best_header = a2;
        a2->nStatus &= ~(unsigned)BLOCK_FAILED_MASK;
        WD_CHECK("clean selectable successor is NOT a selection wedge",
                 !chain_tip_watchdog_test_stall_cause() ||
                 strcmp(chain_tip_watchdog_test_stall_cause(),
                        "tip_selection_wedge") != 0);

        chain_tip_watchdog_test_set_main_state(NULL);
    }
    wd_free_idx(a2);
    wd_free_idx(a1);
    wd_free_idx(g);
    main_state_free(&ms);
    return failures;
}

    /* Negative C — stale fork: the best-header's block at tip+1 does NOT
     * build on our tip (pprev != tip), so it is not the extension class. */
static int wd_check_stale_fork_not_selection_wedge(void)
{
    int failures = 0;

    struct main_state ms2;
    memset(&ms2, 0, sizeof(ms2));
    main_state_init(&ms2);
    struct block_index *g2 = wd_mk_idx(&ms2, 0, 1,  0x00, NULL);
    struct block_index *c1 = wd_mk_idx(&ms2, 1, 10, 0x2A, g2);
    struct block_index *c2 = wd_mk_idx(&ms2, 2, 20, 0x2B, c1); /* active tip */
    struct block_index *f1 = wd_mk_idx(&ms2, 1, 11, 0x3A, g2); /* fork */
    struct block_index *f2 = wd_mk_idx(&ms2, 2, 12, 0x3B, f1);
    struct block_index *f3 = wd_mk_idx(&ms2, 3, 13, 0x3C, f2); /* header ahead */
    WD_CHECK("stale-fork fixture built",
             g2 && c1 && c2 && f1 && f2 && f3);
    if (wd_stale_fork_fixture_complete(g2, c1, c2, f1, f2, f3)) {
        active_chain_move_window_tip(&ms2.chain_active, g2);
        active_chain_move_window_tip(&ms2.chain_active, c1);
        active_chain_move_window_tip(&ms2.chain_active, c2); /* tip = c2(h2) */
        ms2.pindex_best_header = f3;                         /* fork h3 ahead */
        f3->nStatus |= BLOCK_FAILED_VALID;
        /* ancestor(f3, tip+1=3) == f3, but f3->pprev == f2 != c2 (tip): the
         * direct-child guard rejects it as a stale fork. */
        chain_tip_watchdog_test_set_main_state(&ms2);
        WD_CHECK("stale fork ahead is NOT a selection wedge",
                 !chain_tip_watchdog_test_stall_cause() ||
                 strcmp(chain_tip_watchdog_test_stall_cause(),
                        "tip_selection_wedge") != 0);
        chain_tip_watchdog_test_set_main_state(NULL);
    }
    wd_free_idx(f3);
    wd_free_idx(f2);
    wd_free_idx(f1);
    wd_free_idx(c2);
    wd_free_idx(c1);
    wd_free_idx(g2);
    main_state_free(&ms2);
    return failures;
}

/* (h) sequence: shared resets, the successor-wedge scenario, the
 * stale-fork negative, then resets again. */
static int wd_check_tip_selection_wedge(void)
{
    int failures = 0;

    blocker_reset_for_testing();
    sticky_escalator_test_reset();
    chain_tip_watchdog_test_reset_runtime();

    failures += wd_check_selection_wedge_remedy_and_negatives();
    failures += wd_check_stale_fork_not_selection_wedge();

    blocker_reset_for_testing();
    sticky_escalator_test_reset();
    chain_tip_watchdog_test_reset_runtime();
    return failures;
}

int test_chain_tip_watchdog_bounded_restart(void)
{
    printf("\n=== chain_tip_watchdog bounded-restart tests ===\n");
    int failures = 0;

    /* Observers only fire once the event log is initialized. */
    event_log_init();
    event_clear_all_observers();
    atomic_store(&g_operator_events, 0);
    event_observe(EV_OPERATOR_NEEDED, wd_operator_observer, NULL);

    /* A completed one-shot boot worker must release its registration slot so
     * a later in-process app_init can arm a fresh liveness contract. */
    failures += wd_check_boot_worker_supervisor_restart();

    /* Worker stalls are worker-scoped blockers, not chain-tip wedge causes. */
    failures += wd_check_worker_stall_blockers();

    /* ── (a) deterministic wedge: K restarts then STOP + page ───────── */
    failures += wd_check_deterministic_wedge_capped_restarts();

    /* ── (b) transient hang: 1 restart, then tip advances → reset ───── */
    failures += wd_check_transient_hang_resets_budget();

    /* ── (c) persistence carries the count across an in-memory wipe ─── */
    failures += wd_check_count_survives_store_reopen();

    /* ── (d) creeping wedge: re-stuck within the margin = SAME episode ── */
    failures += wd_check_creeping_wedge_same_episode();

    /* ── (e) deterministic stall: page on the FIRST escalation, 0 restarts ─
     *
     * A successor pinned on a deterministic precondition (a persisted ok=0
     * script row, TF_BLOCKED_SUCCESSOR_PENDING) is identical every boot, so
     * the cause-probe pages immediately and burns ZERO restarts. */
    failures += wd_check_deterministic_stall_pages_immediately();

    /* ── (f) escalation LADDER over the supervisor tick: 1 -> 3, reserved inert
     *
     * Drives the wall-clock ladder via chain_tip_watchdog_test_tick() (the
     * production wd_apply_tick body with an injected height and monotonic
     * clock; hermetic).
     *
     * Invariant under lock:
     *   - level 1 (mirror) fires exactly once at age >= thr_mirror;
     *   - level JUMPS to 3 (restart) at age >= thr_restart;
     *   - the reserved level-2 rung (g_fires_reserved) is never wired and
     *     must read 0.
     *
     * The first tick seeds g_last_advance_us, which must be NON-ZERO (0 means
     * "unseeded"), so every now_us is based at T0 > 0. */
    failures += wd_check_escalation_ladder_ticks();

    /* ── (g) a quiet, fully caught-up chain is not a liveness failure ───────
     *
     * H*, active chain and best header agree and no block arrives for longer
     * than the restart threshold: the watchdog stays up. A later new header
     * starts a fresh actionable-stall interval. */
    failures += wd_check_quiet_chain_does_not_restart();

    /* ── (h) tip-extension SELECTION wedge: cause-probe classifies it and the
     * watchdog drives a TARGETED revalidate instead of a blind restart ─────
     *
     * Active tip a1(h1); a successor a2(h2) building DIRECTLY on a1 carries a
     * persisted BLOCK_FAILED_VALID mask, so the selector keeps returning the
     * tip. A restart cannot clear that bit: the probe names
     * "tip_selection_wedge" and the tick drives process_block_revalidate(h2)
     * (suppressed here). Negative shapes (caught up, stale fork, selectable
     * successor) must NOT classify as the wedge. */
    failures += wd_check_tip_selection_wedge();

    /* Leave global state clean for the next test. */
    chain_tip_watchdog_test_reset_runtime();
    sticky_escalator_test_reset();
    blocker_reset_for_testing();
    event_clear_all_observers();

    printf("chain_tip_wd_bounded: %d failures\n", failures);
    return failures;
}
