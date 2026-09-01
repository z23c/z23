/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for chain_activation_controller — state machine + planning tests. */

#include "test/test_core.h"
#include "services/chain_activation_service.h"
#include "net/snapshot_sync_contract.h"
#include "validation/main_state.h"
#include "util/blocker.h"
#include <string.h>

/* ── Planning tests (pure function, no global state) ───────────── */

static int test_should_connect_ready(void) {
    int failures = 0;
    TEST("activation: READY + no shutdown + no anchor → DO_CONNECT") {
        struct activation_request req = {
            .source = ACTIVATION_SRC_BOOT,
            .current_state = ACTIVATION_READY,
        };
        struct activation_decision dec;
        activation_should_connect(&dec, &req);
        ASSERT(dec.result == ACTIVATION_DO_CONNECT);
        ASSERT(dec.should_activate == true);
        PASS();
    } _test_next:;
    return failures;
}

static int test_should_connect_at_tip(void) {
    int failures = 0;
    TEST("activation: AT_TIP + new block → DO_CONNECT") {
        struct activation_request req = {
            .source = ACTIVATION_SRC_NEW_BLOCK,
            .current_state = ACTIVATION_AT_TIP,
            .chain_tip_height = 3072280,
        };
        struct activation_decision dec;
        activation_should_connect(&dec, &req);
        ASSERT(dec.result == ACTIVATION_DO_CONNECT);
        ASSERT(dec.should_activate == true);
        PASS();
    } _test_next:;
    return failures;
}

static int test_skip_shutdown(void) {
    int failures = 0;
    TEST("activation: shutdown requested → SKIP_SHUTDOWN") {
        struct activation_request req = {
            .source = ACTIVATION_SRC_BOOT,
            .current_state = ACTIVATION_READY,
            .shutdown_requested = true,
        };
        struct activation_decision dec;
        activation_should_connect(&dec, &req);
        ASSERT(dec.result == ACTIVATION_SKIP_SHUTDOWN);
        ASSERT(dec.should_activate == false);
        PASS();
    } _test_next:;
    return failures;
}

static int test_skip_anchor_active(void) {
    int failures = 0;
    TEST("activation: ANCHOR_ACTIVE → SKIP_ANCHOR_BLOCKS") {
        struct activation_request req = {
            .source = ACTIVATION_SRC_NEW_BLOCK,
            .current_state = ACTIVATION_ANCHOR_ACTIVE,
            .anchor_active = true,
        };
        struct activation_decision dec;
        activation_should_connect(&dec, &req);
        ASSERT(dec.result == ACTIVATION_SKIP_ANCHOR_BLOCKS);
        ASSERT(dec.should_activate == false);
        PASS();
    } _test_next:;
    return failures;
}

static int test_skip_awaiting_utxos(void) {
    int failures = 0;
    TEST("activation: awaiting UTXOs → SKIP_AWAITING_UTXOS") {
        struct activation_request req = {
            .source = ACTIVATION_SRC_BOOT,
            .current_state = ACTIVATION_READY,
            .awaiting_utxos = true,
        };
        struct activation_decision dec;
        activation_should_connect(&dec, &req);
        ASSERT(dec.result == ACTIVATION_SKIP_AWAITING_UTXOS);
        ASSERT(dec.should_activate == false);
        PASS();
    } _test_next:;
    return failures;
}

static int test_skip_wrong_state(void) {
    int failures = 0;
    TEST("activation: BOOT_PENDING → SKIP_WRONG_STATE") {
        struct activation_request req = {
            .source = ACTIVATION_SRC_BOOT,
            .current_state = ACTIVATION_BOOT_PENDING,
        };
        struct activation_decision dec;
        activation_should_connect(&dec, &req);
        ASSERT(dec.result == ACTIVATION_SKIP_WRONG_STATE);
        ASSERT(dec.should_activate == false);
        PASS();
    } _test_next:;
    return failures;
}

static int test_skip_already_running(void) {
    int failures = 0;
    TEST("activation: CONNECTING → SKIP_ALREADY_RUNNING") {
        struct activation_request req = {
            .source = ACTIVATION_SRC_NEW_BLOCK,
            .current_state = ACTIVATION_CONNECTING,
        };
        struct activation_decision dec;
        activation_should_connect(&dec, &req);
        ASSERT(dec.result == ACTIVATION_SKIP_ALREADY_RUNNING);
        ASSERT(dec.should_activate == false);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Transition tests ──────────────────────────────────────────── */

static int test_transition_idle_to_boot(void) {
    int failures = 0;
    TEST("activation transition: IDLE → BOOT_PENDING valid") {
        ASSERT(activation_transition_valid(ACTIVATION_IDLE, ACTIVATION_BOOT_PENDING));
        PASS();
    } _test_next:;
    return failures;
}

static int test_transition_idle_to_ready_invalid(void) {
    int failures = 0;
    TEST("activation transition: IDLE → READY invalid") {
        ASSERT(!activation_transition_valid(ACTIVATION_IDLE, ACTIVATION_READY));
        PASS();
    } _test_next:;
    return failures;
}

static int test_transition_ready_to_connecting(void) {
    int failures = 0;
    TEST("activation transition: READY → CONNECTING valid") {
        ASSERT(activation_transition_valid(ACTIVATION_READY, ACTIVATION_CONNECTING));
        PASS();
    } _test_next:;
    return failures;
}

static int test_transition_connecting_to_at_tip(void) {
    int failures = 0;
    TEST("activation transition: CONNECTING → AT_TIP valid") {
        ASSERT(activation_transition_valid(ACTIVATION_CONNECTING, ACTIVATION_AT_TIP));
        PASS();
    } _test_next:;
    return failures;
}

static int test_transition_at_tip_to_connecting(void) {
    int failures = 0;
    TEST("activation transition: AT_TIP → CONNECTING valid") {
        ASSERT(activation_transition_valid(ACTIVATION_AT_TIP, ACTIVATION_CONNECTING));
        PASS();
    } _test_next:;
    return failures;
}

static int test_transition_anchor_to_connecting_invalid(void) {
    int failures = 0;
    TEST("activation transition: ANCHOR_ACTIVE → CONNECTING invalid") {
        ASSERT(!activation_transition_valid(ACTIVATION_ANCHOR_ACTIVE, ACTIVATION_CONNECTING));
        PASS();
    } _test_next:;
    return failures;
}

/* ── UTXO wipe tests ──────────────────────────────────────────── */

static int test_wipe_safe_idle(void) {
    int failures = 0;
    TEST("activation wipe: IDLE, no anchor → safe") {
        struct utxo_wipe_decision wd;
        activation_should_allow_utxo_wipe(&wd, ACTIVATION_IDLE, false);
        ASSERT(wd.safe_to_wipe == true);
        PASS();
    } _test_next:;
    return failures;
}

static int test_wipe_blocked_anchor_active(void) {
    int failures = 0;
    TEST("activation wipe: ANCHOR_ACTIVE → NOT safe") {
        struct utxo_wipe_decision wd;
        activation_should_allow_utxo_wipe(&wd, ACTIVATION_ANCHOR_ACTIVE, true);
        ASSERT(wd.safe_to_wipe == false);
        PASS();
    } _test_next:;
    return failures;
}

static int test_wipe_blocked_anchor_clearing(void) {
    int failures = 0;
    TEST("activation wipe: ANCHOR_CLEARING → NOT safe") {
        struct utxo_wipe_decision wd;
        activation_should_allow_utxo_wipe(&wd, ACTIVATION_ANCHOR_CLEARING, false);
        ASSERT(wd.safe_to_wipe == false);
        PASS();
    } _test_next:;
    return failures;
}

static int test_wipe_safe_ready(void) {
    int failures = 0;
    TEST("activation wipe: READY, no anchor → safe") {
        struct utxo_wipe_decision wd;
        activation_should_allow_utxo_wipe(&wd, ACTIVATION_READY, false);
        ASSERT(wd.safe_to_wipe == true);
        PASS();
    } _test_next:;
    return failures;
}

/* ── State name tests ──────────────────────────────────────────── */

static int test_state_names(void) {
    int failures = 0;
    TEST("activation: all state names non-NULL") {
        for (int i = 0; i < ACTIVATION_NUM_STATES; i++) {
            ASSERT(activation_state_name((enum activation_state)i) != NULL);
            ASSERT(strlen(activation_state_name((enum activation_state)i)) > 0);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_state_name_unknown(void) {
    int failures = 0;
    TEST("activation: out-of-range state returns 'unknown'") {
        ASSERT(strcmp(activation_state_name((enum activation_state)99), "unknown") == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── deferred-activation tests ──────────────────────────── */

/* Drive a real controller into CONNECTING, issue a concurrent
 * activation request, and assert that the skipped request was noted
 * on the deferred-activation counter. Pre-fix the counter stays 0 —
 * the skipped work is silently dropped and only retried when the next
 * P2P block arrives. */
static int test_deferred_increments_on_already_running(void) {
    int failures = 0;
    TEST("activation SKIP_ALREADY_RUNNING increments deferred counter") {
        /* Clear any snapshot anchor set by earlier tests — otherwise
         * the planner returns SKIP_ANCHOR_BLOCKS before reaching the
         * CONNECTING check. */
        snapsync_set_anchor(NULL);

        struct main_state ms;
        main_state_init(&ms);

        struct chain_activation_controller ctl;
        activation_controller_init(&ctl, &ms, NULL, NULL, NULL);

        /* Walk the transition table into CONNECTING. */
        ASSERT(activation_set_state(&ctl, ACTIVATION_BOOT_PENDING, "test"));
        ASSERT(activation_set_state(&ctl, ACTIVATION_READY, "test"));
        ASSERT(activation_set_state(&ctl, ACTIVATION_CONNECTING, "test"));

        /* Drain is 0 before the skipped request. */
        ASSERT(activation_drain_deferred(&ctl) == 0);

        /* Another thread would call activation_request_connect here.
         * The planner returns SKIP_ALREADY_RUNNING pre-mutex, so no
         * activate_best_chain runs — the call is safe in a unit test
         * with a zero-initialized main_state. */
        struct activation_exec_outcome out = {0};
        activation_request_connect(&ctl, ACTIVATION_SRC_NEW_BLOCK,
                                   NULL, &out);
        ASSERT(out.result == ACTIVATION_EXEC_SKIPPED);
        ASSERT(strstr(out.reason, "already running") != NULL);

        /* the skipped request must be noted so the active
         * thread can rerun activate_best_chain before releasing the
         * mutex. */
        ASSERT(activation_drain_deferred(&ctl) == 1);

        /* Drain is idempotent — second call returns 0. */
        ASSERT(activation_drain_deferred(&ctl) == 0);

        activation_controller_destroy(&ctl);
        main_state_free(&ms);
        PASS();
    } _test_next:;
    return failures;
}

static int test_deferred_accumulates_across_skips(void) {
    int failures = 0;
    TEST("activation deferred counter accumulates across concurrent skips") {
        snapsync_set_anchor(NULL);

        struct main_state ms;
        main_state_init(&ms);

        struct chain_activation_controller ctl;
        activation_controller_init(&ctl, &ms, NULL, NULL, NULL);
        ASSERT(activation_set_state(&ctl, ACTIVATION_BOOT_PENDING, "test"));
        ASSERT(activation_set_state(&ctl, ACTIVATION_READY, "test"));
        ASSERT(activation_set_state(&ctl, ACTIVATION_CONNECTING, "test"));

        struct activation_exec_outcome out = {0};
        for (int i = 0; i < 6; i++)
            activation_request_connect(&ctl, ACTIVATION_SRC_NEW_BLOCK,
                                       NULL, &out);

        ASSERT(activation_drain_deferred(&ctl) == 6);
        ASSERT(activation_drain_deferred(&ctl) == 0);

        activation_controller_destroy(&ctl);
        main_state_free(&ms);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Silent-ready guard (advance-or-named-blocker) ─────────────── */

static const struct blocker_snapshot *
find_behind_blocker(struct blocker_snapshot *snaps, int n) {
    for (int i = 0; i < n; i++)
        if (strcmp(snaps[i].id, ACTIVATION_BEHIND_BLOCKER_ID) == 0)
            return &snaps[i];
    return NULL;
}

/* When the tip is below the most-work valid-header chain and cannot advance,
 * the authority MUST register a typed blocker — never go silently "ready".
 * When caught up, the blocker MUST be cleared. This drives the exact
 * production decision (activation_eval_tip_blocker) against the live blocker
 * registry. */
static int test_behind_registers_typed_blocker(void) {
    int failures = 0;
    TEST("activation behind header chain registers a typed blocker (no silent ready)") {
        blocker_reset_for_testing();
        blocker_module_init();

        /* Tip far below the best valid header → cannot advance this tick. */
        bool behind = activation_eval_tip_blocker(/*tip_h=*/2055000,
                                                  /*best_h=*/2055950);
        ASSERT(behind == true);

        struct blocker_snapshot snaps[BLOCKER_CAP];
        int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
        const struct blocker_snapshot *b = find_behind_blocker(snaps, n);
        ASSERT(b != NULL);                       /* it is NAMED, not silent */
        ASSERT(b->class == BLOCKER_TRANSIENT);
        ASSERT(strlen(b->escape_action) > 0);    /* has an escape action */
        ASSERT(strcmp(b->escape_action, "activation_drive_connect") == 0);
        ASSERT(strstr(b->reason, "best_valid_header=2055950") != NULL);
        ASSERT(strstr(b->reason, "gap=950") != NULL);

        blocker_reset_for_testing();
        PASS();
    } _test_next:;
    return failures;
}

/* Caught up: tip == most-work header tip → blocker cleared, decision says
 * "not behind". This is the only honest "ready" path. */
static int test_caught_up_clears_blocker(void) {
    int failures = 0;
    TEST("activation caught up clears the behind-blocker") {
        blocker_reset_for_testing();
        blocker_module_init();

        /* First go behind so the blocker exists. */
        ASSERT(activation_eval_tip_blocker(2055000, 2055950) == true);
        ASSERT(blocker_exists(ACTIVATION_BEHIND_BLOCKER_ID));

        /* Now at tip (within the 100-block window). */
        bool behind = activation_eval_tip_blocker(2055950, 2055950);
        ASSERT(behind == false);
        ASSERT(!blocker_exists(ACTIVATION_BEHIND_BLOCKER_ID));

        blocker_reset_for_testing();
        PASS();
    } _test_next:;
    return failures;
}

/* ── Registration ──────────────────────────────────────────────── */

int test_chain_activation_controller(void) {
    int failures = 0;
    /* Planning tests */
    failures += test_should_connect_ready();
    failures += test_should_connect_at_tip();
    failures += test_skip_shutdown();
    failures += test_skip_anchor_active();
    failures += test_skip_awaiting_utxos();
    failures += test_skip_wrong_state();
    failures += test_skip_already_running();
    /* Transition tests */
    failures += test_transition_idle_to_boot();
    failures += test_transition_idle_to_ready_invalid();
    failures += test_transition_ready_to_connecting();
    failures += test_transition_connecting_to_at_tip();
    failures += test_transition_at_tip_to_connecting();
    failures += test_transition_anchor_to_connecting_invalid();
    /* UTXO wipe tests */
    failures += test_wipe_safe_idle();
    failures += test_wipe_blocked_anchor_active();
    failures += test_wipe_blocked_anchor_clearing();
    failures += test_wipe_safe_ready();
    /* State name tests */
    failures += test_state_names();
    failures += test_state_name_unknown();
    /* deferred-activation tests */
    failures += test_deferred_increments_on_already_running();
    failures += test_deferred_accumulates_across_skips();
    /* silent-ready guard: advance-or-named-blocker */
    failures += test_behind_registers_typed_blocker();
    failures += test_caught_up_clears_blocker();
    return failures;
}
