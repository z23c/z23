/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Spec tests for peer and sync state machines. */

#include "test/test_core.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include <string.h>
#include <stdio.h>

static int g_sc_count;
static void sc_obs(enum event_type type, uint32_t peer_id,
                    const void *payload, uint32_t payload_len, void *ctx) {
    (void)type;(void)peer_id;(void)payload;(void)payload_len;(void)ctx;
    g_sc_count++;
}

int spec_state_machine(void)
{
    int failures = 0;
    printf("\n=== State Machine Specs ===\n");

    {   printf("peer: full handshake lifecycle... ");
        event_log_init();
        _Atomic enum peer_state st = PEER_DISCONNECTED;
        bool ok = peer_set_state_checked(1, &st, PEER_CONNECTING, "out");
        ok = ok && peer_set_state_checked(1, &st, PEER_CONNECTED, "tcp");
        ok = ok && peer_set_state_checked(1, &st, PEER_VERSION_SENT, "v");
        ok = ok && peer_set_state_checked(1, &st, PEER_HANDSHAKE_COMPLETE, "va");
        ok = ok && peer_set_state_checked(1, &st, PEER_ACTIVE, "relay");
        ok = ok && st == PEER_ACTIVE;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("peer: illegal transition rejected... ");
        event_log_init();
        _Atomic enum peer_state st = PEER_DISCONNECTED;
        bool ok = !peer_set_state_checked(1, &st, PEER_ACTIVE, "skip");
        ok = ok && st == PEER_DISCONNECTED;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("peer: transition_valid function... ");
        bool ok = peer_transition_valid(PEER_DISCONNECTED, PEER_CONNECTING);
        ok = ok && peer_transition_valid(PEER_CONNECTING, PEER_CONNECTED);
        ok = ok && !peer_transition_valid(PEER_DISCONNECTED, PEER_ACTIVE);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("peer: state names readable... ");
        bool ok = strcmp(peer_state_name(PEER_DISCONNECTED), "disconnected") == 0;
        ok = ok && strcmp(peer_state_name(PEER_ACTIVE), "active") == 0;
        ok = ok && strcmp(peer_state_name(PEER_BANNED), "banned") == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("peer: ban and disconnect... ");
        event_log_init();
        _Atomic enum peer_state st = PEER_ACTIVE;
        bool ok = peer_set_state_checked(1, &st, PEER_BANNED, "bad");
        ok = ok && peer_set_state_checked(1, &st, PEER_DISCONNECTED, "done");
        ok = ok && st == PEER_DISCONNECTED;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("peer: state change emits observable event... ");
        event_log_init();
        event_clear_all_observers();
        g_sc_count = 0;
        event_observe(EV_PEER_STATE_CHANGE, sc_obs, NULL);
        _Atomic enum peer_state st = PEER_DISCONNECTED;
        peer_set_state_checked(1, &st, PEER_CONNECTING, "t");
        bool ok = g_sc_count == 1;
        event_clear_all_observers();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("sync: IBD lifecycle... ");
        event_log_init();
        sync_set_state(SYNC_IDLE, "r");
        bool ok = sync_get_state() == SYNC_IDLE;
        ok = ok && sync_set_state(SYNC_FINDING_PEERS, "s");
        ok = ok && sync_set_state(SYNC_HEADERS_DOWNLOAD, "s");
        ok = ok && sync_set_state(SYNC_BLOCKS_DOWNLOAD, "s");
        ok = ok && sync_set_state(SYNC_CONNECTING_BLOCKS, "s");
        ok = ok && sync_set_state(SYNC_AT_TIP, "s");
        ok = ok && sync_get_state() == SYNC_AT_TIP;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("sync: fast sync path... ");
        event_log_init();
        sync_set_state(SYNC_IDLE, "r");
        bool ok = sync_set_state(SYNC_FINDING_PEERS, "s");
        ok = ok && sync_set_state(SYNC_SNAPSHOT_RECEIVE, "fast");
        ok = ok && sync_set_state(SYNC_CONNECTING_BLOCKS, "done");
        ok = ok && sync_set_state(SYNC_AT_TIP, "synced");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("sync: reorg and recovery... ");
        event_log_init();
        sync_set_state(SYNC_IDLE, "r");
        sync_set_state(SYNC_FINDING_PEERS, "s");
        sync_set_state(SYNC_HEADERS_DOWNLOAD, "s");
        sync_set_state(SYNC_BLOCKS_DOWNLOAD, "s");
        sync_set_state(SYNC_CONNECTING_BLOCKS, "s");
        sync_set_state(SYNC_AT_TIP, "s");
        bool ok = sync_set_state(SYNC_REORG, "fork");
        ok = ok && sync_get_state() == SYNC_REORG;
        ok = ok && sync_set_state(SYNC_AT_TIP, "resolved");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("sync: illegal transition rejected... ");
        event_log_init();
        sync_set_state(SYNC_IDLE, "r");
        bool ok = !sync_set_state(SYNC_AT_TIP, "skip");
        ok = ok && sync_get_state() == SYNC_IDLE;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("sync: state names readable... ");
        bool ok = strcmp(sync_state_name(SYNC_IDLE), "idle") == 0;
        ok = ok && strcmp(sync_state_name(SYNC_AT_TIP), "at_tip") == 0;
        ok = ok && strcmp(sync_state_name(SYNC_REORG), "reorg") == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("sync: state change observable... ");
        event_log_init();
        event_clear_all_observers();
        g_sc_count = 0;
        event_observe(EV_SYNC_STATE_CHANGE, sc_obs, NULL);
        sync_set_state(SYNC_IDLE, "r");
        sync_set_state(SYNC_FINDING_PEERS, "t");
        bool ok = g_sc_count >= 1;
        event_clear_all_observers();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("State machine: %d failures\n", failures);
    return failures;
}
