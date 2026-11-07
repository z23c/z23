/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the reducer drive guard's time + label surface
 * (platform/modules/util/src/reducer_drive_guard.c). The watchdog and dumpstate rely on:
 *   (a) age is 0 when inactive, >0 while a drive is active, 0 again on exit;
 *   (b) the OUTERMOST enter owns the label; nested enters do not overwrite;
 *   (c) plain reducer_drive_enter() still works and reads as "unlabeled".
 */

#include "test/test_core.h"

#include "util/reducer_drive_guard.h"
#include "services/reducer_drain.h"
#include "services/reducer_ingest_service.h"
#include "services/chain_activation_service.h"
#include "chain/chainparams.h"
#include "supervisors/staged_sync_supervisor.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "consensus/validation.h"
#include "net/msg_internal.h"
#include "primitives/block.h"
#include "storage/progress_store.h"
#include <sqlite3.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

#define RDG_CHECK(name, expr) do {                                        \
    if (expr) { printf("  reducer_drive_guard: %s... OK\n", (name)); }    \
    else { printf("  reducer_drive_guard: %s... FAIL\n", (name));         \
           failures++; }                                                  \
} while (0)

#ifdef ZCL_TESTING
static int rdg_drain_calls;
static int rdg_drain(int max_steps) { (void)max_steps; ++rdg_drain_calls; return 1; }
static uint64_t rdg_cursor(void) { return 0; }

static int rdg_gate_entrypoints(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "reducer_startup_gate", "held");
    struct main_state ms;
    main_state_init(&ms);
    bool opened = progress_store_open(dir);
    RDG_CHECK("isolated store opens", opened);
    if (!opened) { main_state_free(&ms); test_rm_rf_recursive(dir); return failures; }
    struct chain_activation_controller ctl;
    activation_controller_init(&ctl, &ms, NULL, chain_params_get(), dir);
    struct block block;
    block_init(&block);
    size_t map_before = ms.map_block_index.size;
    int height_before = active_chain_height(&ms.chain_active);
    int changes_before = sqlite3_total_changes(progress_store_db());
    reducer_startup_gate_test_reset();
    RDG_CHECK("open gate is not held", !reducer_startup_gate_held());
    RDG_CHECK("arm enters held", reducer_startup_gate_arm() && reducer_startup_gate_held());
    RDG_CHECK("second arm refused", !reducer_startup_gate_arm());
    struct activation_exec_outcome outcome;
    activation_request_connect(&ctl, ACTIVATION_SRC_NEW_BLOCK, &block, &outcome);
    RDG_CHECK("activation skips recovery", outcome.result == ACTIVATION_EXEC_SKIPPED);
    struct validation_state state;
    bool staged = reducer_stage_p2p_block_for_catchup(&ctl, &block, &state);
    RDG_CHECK("catchup intake is retryable", !staged && msg_block_validation_is_retryable(&state));
    bool ingested = reducer_ingest_block(&ctl, &block, REDUCER_SRC_P2P, false, &state);
    RDG_CHECK("normal intake is retryable", !ingested && msg_block_validation_is_retryable(&state));
    RDG_CHECK("all drains and kicks held", reducer_drain_to_convergence() == 0 &&
              reducer_drain_to_convergence_unpaced() == 0 &&
              reducer_drain_to_convergence_unbudgeted() == 0 &&
              reducer_kick(&ctl) == 0 && reducer_kick_unbudgeted(&ctl) == 0);
    reducer_publish_fully_applied_at_tip(&ctl);
    rdg_drain_calls = 0;
    bool stalled = false;
    (void)staged_sync_supervisor_test_run_stage_tick("rdg_gate", NULL, rdg_drain,
                                                      rdg_cursor, NULL, &ms, &stalled, NULL);
    RDG_CHECK("supervisor does not drain", rdg_drain_calls == 0);
    RDG_CHECK("map frontier and database unchanged", ms.map_block_index.size == map_before &&
              active_chain_height(&ms.chain_active) == height_before &&
              sqlite3_total_changes(progress_store_db()) == changes_before);
    reducer_startup_gate_seal();
    RDG_CHECK("sealed held gate cannot rearm", reducer_startup_gate_held() && !reducer_startup_gate_arm());
    reducer_startup_gate_test_reset();
    reducer_startup_gate_seal();
    RDG_CHECK("sealed open gate cannot arm", !reducer_startup_gate_held() && !reducer_startup_gate_arm());
    reducer_startup_gate_test_reset();
    block_free(&block);
    activation_controller_destroy(&ctl);
    progress_store_close();
    main_state_free(&ms);
    test_rm_rf_recursive(dir);
    return failures;
}
#endif


int test_reducer_drive_guard(void);
int test_reducer_drive_guard(void)
{
    int failures = 0;
#ifdef ZCL_TESTING
    failures += rdg_gate_entrypoints();
#endif

    RDG_CHECK("inactive: no drive at start", !reducer_drive_active());
    RDG_CHECK("inactive: age is 0", reducer_drive_age_us() == 0);
    RDG_CHECK("inactive: label is empty",
              strcmp(reducer_drive_label(), "") == 0);

    reducer_drive_enter_labeled("mint_anchor");
    RDG_CHECK("labeled enter: drive active", reducer_drive_active());
    RDG_CHECK("labeled enter: label visible",
              strcmp(reducer_drive_label(), "mint_anchor") == 0);
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
    nanosleep(&ts, NULL);
    RDG_CHECK("labeled enter: age advances", reducer_drive_age_us() > 0);

    int64_t age_before_nested = reducer_drive_age_us();
    reducer_drive_enter_labeled("nested");
    RDG_CHECK("nested enter: outermost label wins",
              strcmp(reducer_drive_label(), "mint_anchor") == 0);
    RDG_CHECK("nested enter: age monotonic from outermost entry",
              reducer_drive_age_us() >= age_before_nested);
    reducer_drive_exit();
    RDG_CHECK("nested exit: still active", reducer_drive_active());

    reducer_drive_exit();
    RDG_CHECK("outermost exit: inactive", !reducer_drive_active());
    RDG_CHECK("outermost exit: age reset to 0", reducer_drive_age_us() == 0);
    RDG_CHECK("outermost exit: label cleared",
              strcmp(reducer_drive_label(), "") == 0);

    reducer_drive_enter();
    RDG_CHECK("plain enter: reads as unlabeled",
              strcmp(reducer_drive_label(), "unlabeled") == 0);
    RDG_CHECK("plain enter: age advances from plain enter",
              reducer_drive_age_us() >= 0 && reducer_drive_active());
    reducer_drive_exit();
    RDG_CHECK("final exit: inactive", !reducer_drive_active());

    printf("=== test_reducer_drive_guard complete: %d failure(s) ===\n",
           failures);
    return failures;
}
