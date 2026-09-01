/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "framework/condition.h"
#include "net/snapshot_sync_contract.h"
#include "services/sync_monitor.h"
#include "sync/sync_state.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <string.h>

#define SCR_CHECK(name, expr) do { \
    printf("snapshot_complete_resume_condition: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

void register_snapshot_complete_resume(void);
void snapshot_complete_resume_test_reset(void);
void snapshot_complete_resume_test_set_service(struct snapshot_sync_service *svc);
int snapshot_complete_resume_test_remedy_calls(void);

static void reset_scr(struct snapshot_sync_service *svc,
                      struct main_state *ms)
{
    condition_engine_reset_for_testing();
    snapshot_complete_resume_test_reset();
    memset(svc, 0, sizeof(*svc));
    main_state_init(ms);
    sync_monitor_init();
    sync_monitor_set_context(NULL, NULL, ms);
    snapshot_complete_resume_test_set_service(svc);
}

static void cleanup_scr(struct main_state *ms)
{
    sync_monitor_set_context(NULL, NULL, NULL);
    if (sync_get_state() == SYNC_SNAPSHOT_RECEIVE ||
        sync_get_state() == SYNC_HEADERS_DOWNLOAD)
        sync_set_state(SYNC_IDLE, "test cleanup");
    condition_engine_reset_for_testing();
    snapshot_complete_resume_test_reset();
    main_state_free(ms);
}

int test_snapshot_complete_resume_condition(void)
{
    printf("\n=== snapshot_complete_resume condition tests ===\n");
    int failures = 0;

    {
        struct snapshot_sync_service svc;
        struct main_state ms;
        struct block_index genesis;
        struct block_index snap;
        struct uint256 h0 = {0};
        struct uint256 h1 = {0};
        reset_scr(&svc, &ms);
        bool ok = true;
        register_snapshot_complete_resume();

        block_index_init(&genesis);
        block_index_init(&snap);
        h0.data[0] = 1;
        h1.data[0] = 2;
        genesis.phashBlock = &h0;
        /* The snap tip's parent must carry the ADJACENT height label: in a
         * real snapshot activation the parent is the synced header at
         * h-1, and the validation-pack linkage check now (correctly)
         * refuses a tip whose pprev label is non-adjacent. */
        genesis.nHeight = 1999;
        snap.phashBlock = &h1;
        snap.nHeight = 2000;
        snap.pprev = &genesis;
        block_map_insert(&ms.map_block_index, &h0, &genesis);
        block_map_insert(&ms.map_block_index, &h1, &snap);

        svc.state = SNAPSYNC_COMPLETE;
        svc.offered_height = 2000;
        svc.offered_peer_tip_height = 2000;
        svc.offered_count = 1350000;
        svc.serving_peer_id = 31;
        memcpy(svc.offered_block_hash, h1.data, 32);

        sync_set_state(SYNC_SNAPSHOT_RECEIVE, "test stuck snapshot receive");
        condition_engine_tick();

        ok = ok && snapshot_complete_resume_test_remedy_calls() == 1;
        ok = ok && sync_get_state() == SYNC_HEADERS_DOWNLOAD;
        ok = ok && active_chain_tip(&ms.chain_active) == NULL;
        ok = ok && ms.pindex_best_header == NULL;
        ok = ok && condition_engine_get_active_count() == 1;
        SCR_CHECK("legacy complete snapshot is contained and resumes headers",
                  ok);
        cleanup_scr(&ms);
    }

    {
        struct snapshot_sync_service svc;
        struct main_state ms;
        reset_scr(&svc, &ms);
        bool ok = true;
        register_snapshot_complete_resume();

        svc.state = SNAPSYNC_COMPLETE;
        svc.offered_height = 2000;
        svc.offered_count = 1350000;
        sync_set_state(SYNC_IDLE, "test already resumed");
        condition_engine_tick();

        ok = ok && snapshot_complete_resume_test_remedy_calls() == 0;
        ok = ok && sync_get_state() == SYNC_IDLE;
        SCR_CHECK("complete snapshot outside receive state is ignored", ok);
        cleanup_scr(&ms);
    }

    return failures;
}
