/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "conditions/peer_floor_violated.h"
#include "conditions/snapshot_offer_ready.h"
#include "conditions/sync_violation_lag.h"
#include "framework/condition.h"
#include "platform/clock.h"
#include "jobs/header_admit_stage.h"
#include "net/protocol.h"
#include "net/snapshot_sync_contract.h"
#include "services/sync_monitor.h"
#include "jobs/validate_headers_stage.h"
#include "sync/sync_state.h"
#include "validation/chainstate.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define PEER_SNAPSHOT_CHECK(name, expr) do { \
    printf("peer_snapshot_conditions: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

struct fake_clock_peer_snapshot {
    _Atomic int64_t wall_ms;
};

static int64_t fake_now_mono(void *self)
{
    (void)self;
    return 1;
}

static int64_t fake_now_wall(void *self)
{
    struct fake_clock_peer_snapshot *c =
        (struct fake_clock_peer_snapshot *)self;
    return atomic_load(&c->wall_ms);
}

static void fake_clock_install(struct fake_clock_peer_snapshot *c,
                               int64_t unix_s)
{
    atomic_store(&c->wall_ms, unix_s * 1000);
    static clock_iface_t iface;
    iface.now_monotonic_ns = fake_now_mono;
    iface.now_wall_ms = fake_now_wall;
    iface.self = c;
    clock_set_default(&iface);
}

static void fake_clock_set(struct fake_clock_peer_snapshot *c, int64_t unix_s)
{
    atomic_store(&c->wall_ms, unix_s * 1000);
}

static void reset_peer_snapshot_conditions(struct connman *cm,
                                           struct download_manager *dm,
                                           struct main_state *ms)
{
    condition_engine_reset_for_testing();
    peer_floor_violated_test_reset();
    sync_violation_lag_test_reset();
    snapshot_offer_ready_test_reset();
    memset(cm, 0, sizeof(*cm));
    memset(dm, 0, sizeof(*dm));
    memset(ms, 0, sizeof(*ms));
    zcl_mutex_init(&cm->manager.cs_nodes);
    zcl_mutex_init(&dm->cs);
    zcl_mutex_init(&ms->cs_main);
    static struct chain_params params;
    memset(&params, 0, sizeof(params));
    cm->params = &params;
    sync_monitor_init();
    sync_monitor_set_context(cm, dm, ms);
}

static void cleanup_peer_snapshot_conditions(void)
{
    condition_engine_reset_for_testing();
    sync_monitor_set_context(NULL, NULL, NULL);
    clock_reset_default();
    unsetenv("ZCL_PEERLESS_OK");
    if (sync_get_state() != SYNC_IDLE)
        sync_set_state(SYNC_IDLE, "test cleanup");
}

int test_peer_snapshot_conditions(void)
{
    printf("\n=== peer and snapshot condition tests ===\n");
    int failures = 0;

    {
        struct fake_clock_peer_snapshot clock;
        fake_clock_install(&clock, 1000);
        struct connman cm;
        struct download_manager dm;
        struct main_state ms;
        reset_peer_snapshot_conditions(&cm, &dm, &ms);
        bool ok = true;
        register_peer_floor_violated();

        struct p2p_node stuck = {0};
        stuck.id = 1;
        stuck.state = PEER_CONNECTED;
        struct p2p_node *peers[1] = { &stuck };
        cm.manager.nodes = peers;
        cm.manager.num_nodes = 1;

        condition_engine_tick();
        ok = ok && peer_floor_violated_test_remedy_calls() == 0;
        fake_clock_set(&clock, 1061);
        condition_engine_tick();
        ok = ok && peer_floor_violated_test_remedy_calls() == 1;
        ok = ok && stuck.disconnect;
        PEER_SNAPSHOT_CHECK("peer floor kicks unhealthy outbound slots", ok);
        cleanup_peer_snapshot_conditions();
    }

    {
        struct fake_clock_peer_snapshot clock;
        fake_clock_install(&clock, 2000);
        struct connman cm;
        struct download_manager dm;
        struct main_state ms;
        reset_peer_snapshot_conditions(&cm, &dm, &ms);
        bool ok = true;
        register_peer_floor_violated();
        setenv("ZCL_PEERLESS_OK", "1", 1);

        condition_engine_tick();
        fake_clock_set(&clock, 2061);
        condition_engine_tick();
        ok = ok && peer_floor_violated_test_remedy_calls() == 0;
        PEER_SNAPSHOT_CHECK("peer floor honors peerless test mode", ok);
        cleanup_peer_snapshot_conditions();
    }

    {
        struct fake_clock_peer_snapshot clock;
        fake_clock_install(&clock, 3000);
        struct connman cm;
        struct download_manager dm;
        struct main_state ms;
        reset_peer_snapshot_conditions(&cm, &dm, &ms);
        bool ok = true;
        register_sync_violation_lag();

        struct block_index tip = {0};
        tip.nHeight = 100;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);
        struct p2p_node peer = {0};
        peer.id = 1;
        peer.starting_height = 250;
        peer.state = PEER_ACTIVE;
        peer.services = NODE_NETWORK;
        struct p2p_node *peers[1] = { &peer };
        cm.manager.nodes = peers;
        cm.manager.num_nodes = 1;

        condition_engine_tick();
        ok = ok && sync_violation_lag_test_remedy_calls() == 0;
        fake_clock_set(&clock, 3601);
        condition_engine_tick();
        ok = ok && sync_violation_lag_test_remedy_calls() == 1;
        ok = ok && peer.disconnect;
        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && condition_engine_get_unresolved_count() == 0;
        condition_engine_tick();
        ok = ok && sync_violation_lag_test_remedy_calls() == 1;
        PEER_SNAPSHOT_CHECK("sync violation rotates peers and clears", ok);
        cleanup_peer_snapshot_conditions();
    }

    {
        struct fake_clock_peer_snapshot clock;
        fake_clock_install(&clock, 5000);
        struct connman cm;
        struct download_manager dm;
        struct main_state ms;
        reset_peer_snapshot_conditions(&cm, &dm, &ms);
        bool ok = true;
        register_sync_violation_lag();

        struct block_index tip1 = {0};
        tip1.nHeight = 100;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip1);
        struct p2p_node peer = {0};
        peer.id = 1;
        peer.starting_height = 250;
        peer.state = PEER_ACTIVE;
        peer.services = NODE_NETWORK;
        struct p2p_node *peers[1] = { &peer };
        cm.manager.nodes = peers;
        cm.manager.num_nodes = 1;

        condition_engine_tick();
        fake_clock_set(&clock, 5601);
        struct block_index tip2 = {0};
        tip2.nHeight = 101;  /* still >100 behind, but visibly progressing */
        tip2.pprev = &tip1;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip2);
        condition_engine_tick();
        ok = ok && sync_violation_lag_test_remedy_calls() == 0;
        ok = ok && !peer.disconnect;

        fake_clock_set(&clock, 6202);
        condition_engine_tick();
        ok = ok && sync_violation_lag_test_remedy_calls() == 1;
        ok = ok && peer.disconnect;
        PEER_SNAPSHOT_CHECK("sync violation timer resets on local progress", ok);
        cleanup_peer_snapshot_conditions();
    }

    {
        /* Regression for the missing cooldown_secs/cooldown_max_rearms: an
         * INBOUND peer stays far ahead of local height. The remedy
         * (connman_force_outbound_rotation) only disconnects OUTBOUND
         * peers, so an inbound peer that keeps reporting a high height
         * makes this a persistent, never-witnessed fault — max_attempts=1
         * is reached on the very first remedy call. Before this fix
         * cooldown_secs was 0 ("legacy"), so condition_cooldown_rearm()
         * refused to reset the attempt budget and the engine latched
         * EV_OPERATOR_NEEDED forever without ever calling the remedy again
         * (observed live: paging every 3600s for 27h, zero re-attempts).
         * Drive the same persistent lag past max_attempts and assert the
         * engine re-arms and calls the remedy again instead of latching. */
        struct fake_clock_peer_snapshot clock;
        fake_clock_install(&clock, 6000);
        struct connman cm;
        struct download_manager dm;
        struct main_state ms;
        reset_peer_snapshot_conditions(&cm, &dm, &ms);
        bool ok = true;
        register_sync_violation_lag();

        struct block_index tip = {0};
        tip.nHeight = 100;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);
        struct p2p_node peer = {0};
        peer.id = 7;
        peer.starting_height = 250;
        peer.state = PEER_ACTIVE;
        peer.services = NODE_NETWORK;
        peer.inbound = true;  /* survives connman_force_outbound_rotation */
        struct p2p_node *peers[1] = { &peer };
        cm.manager.nodes = peers;
        cm.manager.num_nodes = 1;

        condition_engine_tick();  /* primes first_seen/last_local baseline */
        ok = ok && sync_violation_lag_test_remedy_calls() == 0;

        fake_clock_set(&clock, 6601);  /* past SYNC_VIOLATION_SECS (600) */
        condition_engine_tick();  /* attempt 1/1 -- hits max_attempts */
        ok = ok && sync_violation_lag_test_remedy_calls() == 1;
        ok = ok && !peer.disconnect;  /* inbound peer is never rotated away */
        ok = ok && condition_engine_get_active_count() == 1;  /* unwitnessed */

        struct condition_runtime_snapshot snap;
        memset(&snap, 0, sizeof(snap));
        ok = ok && condition_engine_get_registered_snapshot(
                       "sync_violation_lag", &snap);
        ok = ok && snap.max_attempts == 1;
        ok = ok && snap.attempts == 1;
        ok = ok && snap.operator_needed_emitted;
        ok = ok && snap.cooldown_secs == 600;
        ok = ok && snap.cooldown_max_rearms == 0;

        /* Same fault persists well past both the engine's cooldown_secs
         * (600) and the remedy's own internal SYNC_VIOLATION_COOLDOWN_SECS
         * (3600) repeat-suppression, past max_attempts. Without
         * cooldown_secs this would stay latched at operator_needed forever
         * and the remedy would never run again. */
        fake_clock_set(&clock, 10202);
        condition_engine_tick();
        ok = ok && sync_violation_lag_test_remedy_calls() == 2;
        ok = ok && condition_engine_get_active_count() == 1;

        PEER_SNAPSHOT_CHECK(
            "sync violation lag re-arms on cooldown past max_attempts "
            "instead of latching forever",
            ok);
        cleanup_peer_snapshot_conditions();
    }

    {
        struct fake_clock_peer_snapshot clock;
        fake_clock_install(&clock, 4000);
        struct connman cm;
        struct download_manager dm;
        struct main_state ms;
        reset_peer_snapshot_conditions(&cm, &dm, &ms);
        bool ok = true;
        register_snapshot_offer_ready();

        struct block_index tip = {0};
        tip.nHeight = 100;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);

        struct snapshot_sync_service svc;
        memset(&svc, 0, sizeof(svc));
        svc.state = SNAPSYNC_NEGOTIATING;
        svc.offered_height = 2000;
        svc.offered_count = 100;
        svc.serving_peer_id = 42;
        snapshot_offer_ready_test_set_service(&svc);

        ok = ok && sync_get_state() == SYNC_IDLE;
        condition_engine_tick();
        ok = ok && snapshot_offer_ready_test_remedy_calls() == 1;
        ok = ok && sync_get_state() == SYNC_SNAPSHOT_RECEIVE;
        ok = ok && condition_engine_get_active_count() == 0;

        condition_engine_tick();
        ok = ok && snapshot_offer_ready_test_remedy_calls() == 1;
        PEER_SNAPSHOT_CHECK("snapshot offer ready reasserts snapshot receive", ok);
        cleanup_peer_snapshot_conditions();
    }

    {
        struct fake_clock_peer_snapshot clock;
        fake_clock_install(&clock, 4500);
        struct connman cm;
        struct download_manager dm;
        struct main_state ms;
        reset_peer_snapshot_conditions(&cm, &dm, &ms);
        bool ok = true;
        register_snapshot_offer_ready();

        struct block_index tip = {0};
        tip.nHeight = 100;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);

        ok = ok && sync_set_state(SYNC_FINDING_PEERS,
                                  "test snapshot at-tip setup");
        ok = ok && sync_set_state(SYNC_HEADERS_DOWNLOAD,
                                  "test snapshot at-tip setup");
        ok = ok && sync_set_state(SYNC_AT_TIP,
                                  "test snapshot at-tip setup");

        struct snapshot_sync_service svc;
        memset(&svc, 0, sizeof(svc));
        svc.state = SNAPSYNC_NEGOTIATING;
        svc.offered_height = 2000;
        svc.offered_count = 100;
        svc.serving_peer_id = 43;
        snapshot_offer_ready_test_set_service(&svc);

        condition_engine_tick();
        ok = ok && snapshot_offer_ready_test_remedy_calls() == 0;
        ok = ok && sync_get_state() == SYNC_AT_TIP;
        ok = ok && condition_engine_get_active_count() == 0;
        PEER_SNAPSHOT_CHECK("snapshot offer ready ignores at-tip state", ok);
        cleanup_peer_snapshot_conditions();
    }

    cleanup_peer_snapshot_conditions();
    return failures;
}
