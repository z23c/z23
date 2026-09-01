/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "services/chain_tip.h"
#include "validation/main_state.h"
#include "chain/chain.h"
#include "event/event.h"

#include <stdio.h>
#include <string.h>

static int g_tip_updated_count;
static int g_tip_commit_count;
static int g_last_tip_height;

static void observer(enum event_type type, uint32_t peer_id,
                     const void *payload, uint32_t payload_len, void *ctx)
{
    (void)peer_id;
    (void)payload;
    (void)payload_len;
    (void)ctx;
    if (type == EV_TIP_UPDATED) g_tip_updated_count++;
    if (type == EV_CHAIN_TIP_COMMIT) g_tip_commit_count++;
}

int test_chain_tip(void)
{
    int failures = 0;

    event_log_init();
    event_clear_observers(EV_TIP_UPDATED);
    event_clear_observers(EV_CHAIN_TIP_COMMIT);
    event_observe(EV_TIP_UPDATED, observer, NULL);
    event_observe(EV_CHAIN_TIP_COMMIT, observer, NULL);
    g_tip_updated_count = 0;
    g_tip_commit_count = 0;
    g_last_tip_height = -1;

    printf("tip_source_name: known sources... ");
    {
        if (strcmp(tip_source_name(TIP_FROM_CONNECT), "connect") == 0 &&
            strcmp(tip_source_name(TIP_FROM_SNAPSHOT), "snapshot") == 0 &&
            strcmp(tip_source_name(TIP_FROM_TEST), "test") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("chain_set_active_tip: NULL ms returns false... ");
    {
        bool r = chain_set_active_tip(NULL, NULL, TIP_FROM_TEST, "null_ms").ok;
        if (!r) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("chain_set_active_tip: set + clear emits events... ");
    {
        struct main_state ms;
        main_state_init(&ms);
        struct block_index bi;
        block_index_init(&bi);
        bi.nHeight = 5;
        struct uint256 hh = {0};
        hh.data[0] = 0xab;
        bi.phashBlock = &hh;

        int updated_before = g_tip_updated_count;
        int commit_before = g_tip_commit_count;
        bool ok1 = chain_set_active_tip(&ms, &bi,
                                        TIP_FROM_TEST, "set_h5").ok;
        bool ok2 = chain_set_active_tip(&ms, NULL,
                                        TIP_FROM_TEST, "clear").ok;

        if (ok1 && ok2 &&
            g_tip_updated_count == updated_before + 1 &&
            g_tip_commit_count == commit_before + 2)
            printf("OK\n");
        else {
            printf("FAIL (ok1=%d ok2=%d updated_delta=%d commit_delta=%d)\n",
                   ok1, ok2,
                   g_tip_updated_count - updated_before,
                   g_tip_commit_count - commit_before);
            failures++;
        }

        main_state_free(&ms);
    }

    event_clear_observers(EV_TIP_UPDATED);
    event_clear_observers(EV_CHAIN_TIP_COMMIT);
    return failures;
}
