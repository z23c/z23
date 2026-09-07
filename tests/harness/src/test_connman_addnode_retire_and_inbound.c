/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * connman addnode-fallback scenario checks: retire-threshold gating and
 * revival, census harvest into addrman, fixed-seed onion no-ops, relay-
 * block handshake gating, noise capability upgrade, and inbound
 * eviction/serial-dial policy.
 *
 * Split out of test_connman_addnode_fallback.c (which keeps the
 * includes, the fixture helpers shared across siblings, and the group
 * entry point) so no family member crosses the 1,500-line ceiling. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "coins/undo.h"
#include "net/connman.h"
#include "net/tor_integration.h"
#include "net/onion_v3_address.h"
#include "storage/census_read.h"
#include "util/blocker.h"
#include <unistd.h>
#include "test/test_connman_addnode_fallback_priv.h"


int check_connman_addnode_retire_both_thresholds(void)
{
    int failures = 0;
    /* ── addnode self-healing: RETIRE + HARVEST (net/connman.h) ─────────── */

    printf("connman_addnode_fallback: addnode retirement fires past BOTH "
           "thresholds and excludes it from dial rotation... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 198, 51, 100, 200, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
        }

        int64_t now = (int64_t)platform_time_wall_time_t();
        if (ok) {
            cm.addnode_tcp_failures[0] = ZCL_ADDNODE_RETIRE_MIN_TCP_FAILURES;
            cm.addnode_first_failure_ts[0] =
                now - ZCL_ADDNODE_RETIRE_MIN_WINDOW_SECS - 10;
        }

        /* Healthy outbound AT the floor: retirement is allowed to fire. */
        if (ok)
            connman_retire_dead_addnodes(&cm, (size_t)ZCL_PEER_FLOOR_HEALTHY);

        ok = ok && cm.addnode_retired[0];
        ok = ok && cm.addnode_retired_at[0] > 0;
        ok = ok && cm.addnode_retirements_total == 1;

        /* Idempotent: a second pass over an already-retired entry does not
         * double-count the lifetime counter. */
        if (ok)
            connman_retire_dead_addnodes(&cm, (size_t)ZCL_PEER_FLOOR_HEALTHY);
        ok = ok && cm.addnode_retirements_total == 1;

        /* Excluded from dial rotation: the only addnode present is retired,
         * addrman is empty, so no target is pickable. */
        if (ok) {
            struct addr_info pick;
            enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
            memset(&pick, 0, sizeof(pick));
            bool got = connman_pick_next_outbound_target(
                &cm, &cm.next_addnode_cursor, &pick, &source, NULL);
            ok = ok && !got;
        }

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_retire_needs_both_gates(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: addnode retirement needs BOTH the "
           "failure-count AND window thresholds, neither alone... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 198, 51, 100, 201, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
            test_set_ipv4(&addr, 198, 51, 100, 202, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
        }

        int64_t now = (int64_t)platform_time_wall_time_t();
        if (ok) {
            /* addnode[0]: window satisfied, count one short of the floor. */
            cm.addnode_tcp_failures[0] =
                ZCL_ADDNODE_RETIRE_MIN_TCP_FAILURES - 1;
            cm.addnode_first_failure_ts[0] =
                now - ZCL_ADDNODE_RETIRE_MIN_WINDOW_SECS - 10;
            /* addnode[1]: count satisfied, streak just started (window not
             * yet satisfied). */
            cm.addnode_tcp_failures[1] = ZCL_ADDNODE_RETIRE_MIN_TCP_FAILURES;
            cm.addnode_first_failure_ts[1] = now;
        }

        if (ok)
            connman_retire_dead_addnodes(&cm, (size_t)ZCL_PEER_FLOOR_HEALTHY);

        ok = ok && !cm.addnode_retired[0];
        ok = ok && !cm.addnode_retired[1];
        ok = ok && cm.addnode_retirements_total == 0;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_retire_suppressed_below_floor(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: addnode retirement is suppressed "
           "below the healthy-outbound floor... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 198, 51, 100, 203, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
        }

        int64_t now = (int64_t)platform_time_wall_time_t();
        if (ok) {
            cm.addnode_tcp_failures[0] = ZCL_ADDNODE_RETIRE_MIN_TCP_FAILURES;
            cm.addnode_first_failure_ts[0] =
                now - ZCL_ADDNODE_RETIRE_MIN_WINDOW_SECS - 10;
        }

        /* Below the floor (ZCL_PEER_FLOOR_HEALTHY - 1 healthy outbound):
         * this addnode is a dial-of-last-resort and must NOT be retired
         * no matter how dead it looks. */
        if (ok)
            connman_retire_dead_addnodes(
                &cm, (size_t)ZCL_PEER_FLOOR_HEALTHY - 1);
        ok = ok && !cm.addnode_retired[0];
        ok = ok && cm.addnode_retirements_total == 0;

        /* Once the floor is met, the SAME state now retires — proves the
         * suppression above was the floor guard, not some other bug. */
        if (ok)
            connman_retire_dead_addnodes(&cm, (size_t)ZCL_PEER_FLOOR_HEALTHY);
        ok = ok && cm.addnode_retired[0];

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_retire_revive_on_success(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: retired addnode revives on one "
           "successful dial... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 198, 51, 100, 204, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
        }

        int64_t now = (int64_t)platform_time_wall_time_t();
        if (ok) {
            cm.addnode_tcp_failures[0] = ZCL_ADDNODE_RETIRE_MIN_TCP_FAILURES;
            cm.addnode_first_failure_ts[0] =
                now - ZCL_ADDNODE_RETIRE_MIN_WINDOW_SECS - 10;
            connman_retire_dead_addnodes(&cm, (size_t)ZCL_PEER_FLOOR_HEALTHY);
        }
        ok = ok && cm.addnode_retired[0];

        if (ok)
            connman_record_addnode_attempt(&cm, 0, true);

        ok = ok && !cm.addnode_retired[0];
        ok = ok && cm.addnode_tcp_failures[0] == 0;
        ok = ok && cm.addnode_first_failure_ts[0] == 0;
        ok = ok && cm.addnode_backoff_sec[0] == 0;
        /* The lifetime counter is NOT decremented by a revival — it counts
         * retirement events, not "currently retired". */
        ok = ok && cm.addnode_retirements_total == 1;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_retire_revive_on_readd(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: retired addnode revives on operator "
           "addnode re-add... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct net_address addr;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        /* Loopback, unused high port: connect_node's real connect() fails
         * (refused) near-instantly instead of hanging — the revival logic
         * under test runs before that connect attempt either way. */
        test_set_ipv4(&addr, 127, 0, 0, 1, 18921);
        if (ok)
            cm.addnodes[cm.num_addnodes++] = addr;

        int64_t now = (int64_t)platform_time_wall_time_t();
        if (ok) {
            cm.addnode_tcp_failures[0] = ZCL_ADDNODE_RETIRE_MIN_TCP_FAILURES;
            cm.addnode_first_failure_ts[0] =
                now - ZCL_ADDNODE_RETIRE_MIN_WINDOW_SECS - 10;
            cm.addnode_backoff_sec[0] = 1800;
            connman_retire_dead_addnodes(&cm, (size_t)ZCL_PEER_FLOOR_HEALTHY);
        }
        ok = ok && cm.addnode_retired[0];

        if (ok)
            connman_open_connection(&cm, &addr);

        ok = ok && !cm.addnode_retired[0];
        ok = ok && cm.addnode_backoff_sec[0] == 0;
        ok = ok && cm.addnode_tcp_failures[0] == 0;
        /* Re-adding an address already on the list must never duplicate
         * the entry. */
        ok = ok && cm.num_addnodes == 1;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static bool addnode_census_found_only_good(struct connman *cm)
{
    bool found_good1 = false, found_good2 = false, found_bad = false;
    zcl_mutex_lock(&cm->manager.addrman.cs);
    for (int i = 0; i < cm->manager.addrman.id_count; i++) {
        struct addr_info *info = &cm->manager.addrman.entries[i];
        if (!info->used || !net_addr_is_ipv4(&info->addr.svc.addr))
            continue;
        const uint8_t *ip = info->addr.svc.addr.ip;
        if (ip[12] == 45 && ip[13] == 33 && ip[14] == 10) {
            if (ip[15] == 1) found_good1 = true;
            else if (ip[15] == 2) found_good2 = true;
            else if (ip[15] == 3 || ip[15] == 4) found_bad = true;
        }
    }
    zcl_mutex_unlock(&cm->manager.addrman.cs);
    return found_good1 && found_good2 && !found_bad;
}

int check_connman_addnode_census_harvest_to_addrman(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: census harvest adds proven-reachable "
           "candidates to addrman as discovery entries, not pinned "
           "addnodes... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        char tmpdir[] = "/tmp/zcl_connman_harvest_XXXXXX";
        ok = ok && mkdtemp(tmpdir) != NULL;
        if (ok)
            cm.datadir = tmpdir;

        ok = ok && census_read_test_create_schema(tmpdir);

        int64_t now = (int64_t)platform_time_wall_time_t();
        if (ok) {
            /* Two good candidates: reachable (dial_success_count>0) and a
             * recent last_success — exactly what census_read.c's
             * ev_node_census_observed fold produces for a peer we've
             * actually dialed successfully (peers_projection.c:463+). */
            struct census_node good1;
            memset(&good1, 0, sizeof(good1));
            snprintf(good1.ip, sizeof(good1.ip), "45.33.10.1");
            good1.port = 8033;
            good1.services = 1;
            good1.reported_height = 3200000;
            good1.first_seen = now - 100000;
            good1.last_seen = now - 30;
            good1.last_success = now - 30;
            good1.dial_success_count = 4;
            good1.dial_fail_count = 1;
            ok = ok && census_read_test_insert_node(tmpdir, &good1);

            struct census_node good2 = good1;
            snprintf(good2.ip, sizeof(good2.ip), "45.33.10.2");
            ok = ok && census_read_test_insert_node(tmpdir, &good2);

            /* Never-dialed: seen only via gossip, dial_success_count==0 —
             * must NOT be harvested (no proof it's actually reachable). */
            struct census_node never_dialed = good1;
            snprintf(never_dialed.ip, sizeof(never_dialed.ip), "45.33.10.3");
            never_dialed.dial_success_count = 0;
            never_dialed.last_success = 0;
            ok = ok && census_read_test_insert_node(tmpdir, &never_dialed);

            /* Stale: was reachable once, but its last success is far older
             * than ZCL_ADDNODE_HARVEST_RECENT_SUCCESS_SECS — must NOT be
             * harvested (no longer proven-live). */
            struct census_node stale = good1;
            snprintf(stale.ip, sizeof(stale.ip), "45.33.10.4");
            stale.last_seen = now - 30;   /* passes the coarse list filter */
            stale.last_success =
                now - ZCL_ADDNODE_HARVEST_RECENT_SUCCESS_SECS - 3600;
            ok = ok && census_read_test_insert_node(tmpdir, &stale);
        }

        size_t harvested = 0;
        if (ok)
            harvested = connman_harvest_census_candidates(&cm, -1);
        ok = ok && harvested == 2;

        /* Discovery candidates land in addrman, NEVER in the pinned addnode
         * list — that is the whole point of HARVEST vs a raw addnode add. */
        ok = ok && cm.num_addnodes == 0;

        ok = ok && addnode_census_found_only_good(&cm);

        connman_free(&cm);
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
        (void)system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_fixed_seeds_onion_noop(void)
{
    int failures = 0;
    printf("connman seed discovery: hardcoded fixed seeds load into addrman, "
           "onion bootstrap is a safe no-op without Tor... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        /* NULL-safety: neither entry point may crash on an unwired call. */
        connman_kick_seed_discovery(NULL);
        connman_kick_onion_seeds(NULL);

        ok = ok && addrman_size(&cm.manager.addrman) == 0;

        /* connman_kick_seed_discovery re-adds the compiled hardcoded fixed
         * seeds (in-memory only, no I/O) and re-resolves DNS seeds (a no-op
         * on mainnet today: nSeeds == 0 — see chainparams.c's DNS-seeders
         * comment). This is the fresh-node "hardcoded seed set" path a
         * genuinely offline/DNS-less node falls back to. (nFixedSeeds
         * double-books each hardcoded IP under two ports — see chainparams.c
         * — and addrman's address index keys on IP alone, so the landed
         * entry count is <= nFixedSeeds, not equal to it.) */
        connman_kick_seed_discovery(&cm);
        size_t after_fixed = addrman_size(&cm.manager.addrman);
        ok = ok && params->nFixedSeeds > 0;
        ok = ok && after_fixed > 0 && after_fixed <= (size_t)params->nFixedSeeds;

        /* connman_kick_onion_seeds is the operator/peer-of-last-resort
         * remedy for the /directory.json onion-directory bootstrap
         * (engine/conditions/src/peer_floor_violated.c). Without Tor
         * bootstrapped (the default state here) it must be a safe,
         * addrman-preserving no-op — never a crash, never a partial write. */
        ok = ok && !tor_integration_is_ready();
        connman_kick_onion_seeds(&cm);
        ok = ok && addrman_size(&cm.manager.addrman) == after_fixed;

        connman_free(&cm);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_relay_block_handshaked_only(void)
{
    int failures = 0;
    /* connman_relay_block announces a new tip to handshaked peers only, and
     * is idempotent per peer. This is the miner/submitblock announce seam:
     * a locally-accepted tip never travels the P2P receive-relay path, so
     * connman_relay_block is what makes an already-connected follower hear
     * about it. */
    printf("connman_addnode_fallback: relay_block -> handshaked peers only... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        /* Three peers: one fully handshaked (must receive the announce), one
         * still mid-handshake (must NOT), one handshaked but disconnecting
         * (must NOT). */
        struct p2p_node *ready =
            add_test_peer(&cm, 203, 0, 113, 1, PEER_HANDSHAKE_COMPLETE,
                          false, false);
        struct p2p_node *early =
            add_test_peer(&cm, 203, 0, 113, 2, PEER_CONNECTED, false, false);
        struct p2p_node *leaving =
            add_test_peer(&cm, 203, 0, 113, 3, PEER_HANDSHAKE_COMPLETE,
                          false, true);
        ok = ok && ready && early && leaving;

        struct uint256 blk;
        uint256_set_null(&blk);
        blk.data[0] = 0xab;
        blk.data[31] = 0xcd;

        if (ok) {
            connman_relay_block(&cm, &blk);
            /* Only the fully-handshaked, non-disconnecting peer is queued. */
            ok = ok && ready->inventory_to_send_count == 1;
            ok = ok && early->inventory_to_send_count == 0;
            ok = ok && leaving->inventory_to_send_count == 0;
            /* And it is a MSG_BLOCK inv for exactly this hash. */
            ok = ok && ready->inventory_to_send[0].type == MSG_BLOCK;
            ok = ok && uint256_eq(&ready->inventory_to_send[0].hash, &blk);
        }

        /* Idempotent: once the peer knows the hash, re-announcing the same
         * tip does not enqueue a duplicate inv (no announce storm). */
        if (ok) {
            p2p_node_add_inventory_known(ready, &ready->inventory_to_send[0]);
            connman_relay_block(&cm, &blk);
            ok = ok && ready->inventory_to_send_count == 1;
        }

        /* NULL args are a safe no-op, never a crash. */
        if (ok) {
            connman_relay_block(NULL, &blk);
            connman_relay_block(&cm, NULL);
        }

        connman_free(&cm);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static bool addnode_noise_first_upgrade_ok(struct connman *cm,
    struct p2p_node *node)
{
    return connman_request_noise_upgrade(cm, node) &&
           node->disconnect &&
           (node->addr.nServices & NODE_NOISE_TRANSPORT) != 0 &&
           (cm->addnodes[0].nServices & NODE_NOISE_TRANSPORT) != 0 &&
           cm->addnode_last_attempt[0] == 0 &&
           cm->addnode_backoff_sec[0] == 0;
}

int check_connman_addnode_noise_capability_upgrade(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: one-shot Noise capability upgrade... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);
        cm.manager.noise_enabled = true;

        struct net_address pinned;
        test_set_ipv4(&pinned, 127, 0, 0, 1, 18444);
        cm.addnodes[cm.num_addnodes++] = pinned;
        cm.addnode_last_attempt[0] = 99;
        cm.addnode_backoff_sec[0] = 60;
        struct p2p_node *node = add_test_peer(
            &cm, 127, 0, 0, 1, PEER_VERSION_RECEIVED, false, false);
        ok = ok && node != NULL;
        if (node) {
            node->addr.svc.port = pinned.svc.port;
            node->services |= NODE_NOISE_TRANSPORT;
            ok = ok && addnode_noise_first_upgrade_ok(&cm, node);

            /* The learned bit makes this the only reconnect request.  The
             * next dial snapshot enters Noise in net.c immediately. */
            node->disconnect = false;
            ok = ok && !connman_request_noise_upgrade(&cm, node);

            /* A non-addnode learned hop must retain the exact endpoint for
             * its one controlled Noise reconnect.  In -connect mode addrman
             * is not consulted, and without this queue entry the iterative
             * lookup would leave the candidate permanently unverified. */
            cm.num_addnodes = 0;
            node->addr.svc.port = 18445;
            node->addr.nServices &= ~NODE_NOISE_TRANSPORT;
            node->disconnect = false;
            struct net_address learned_reconnect;
            memset(&learned_reconnect, 0, sizeof(learned_reconnect));
            ok = ok && connman_request_noise_upgrade(&cm, node);
            ok = ok && connman_dht_hint_pending(&cm);
            ok = ok && connman_take_dht_hint(&cm, &learned_reconnect);
            ok = ok && net_service_eq(&learned_reconnect.svc,
                                      &node->addr.svc);
            ok = ok &&
                (learned_reconnect.nServices & NODE_NOISE_TRANSPORT) != 0;

            node->inbound = true;
            node->addr.nServices &= ~NODE_NOISE_TRANSPORT;
            ok = ok && !connman_request_noise_upgrade(&cm, node);
        }

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_evict_inbound_when_outbound(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: inbound from a host with a "
           "handshaked outbound is evicted... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct p2p_node *outbound = NULL;
        struct p2p_node *inbound = NULL;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        ok = ok && (outbound = add_test_peer(&cm, 205, 209, 104, 118,
                                             PEER_HANDSHAKE_COMPLETE,
                                             false, false)) != NULL;
        ok = ok && (inbound = add_test_peer(&cm, 205, 209, 104, 118,
                                            PEER_HANDSHAKE_COMPLETE,
                                            true, false)) != NULL;
        if (inbound)
            inbound->addr.svc.port = 49152;
        connman_evict_same_ip_inbound_when_outbound(&cm, outbound);
        ok = ok && outbound && !outbound->disconnect;
        ok = ok && inbound && inbound->disconnect;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_inbound_only_same_ip_stays(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: inbound-only same-IP stays... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct p2p_node *inbound = NULL;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        ok = ok && (inbound = add_test_peer(&cm, 140, 174, 189, 17,
                                            PEER_HANDSHAKE_COMPLETE,
                                            true, false)) != NULL;
        connman_evict_same_ip_inbound_when_outbound(&cm, inbound);
        ok = ok && inbound && !inbound->disconnect;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_operator_local_sockets_stay(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: operator-local mixed sockets stay... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct p2p_node *outbound = NULL;
        struct p2p_node *inbound = NULL;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        ok = ok && (outbound = add_test_peer(&cm, 127, 0, 0, 1,
                                             PEER_HANDSHAKE_COMPLETE,
                                             false, false)) != NULL;
        ok = ok && (inbound = add_test_peer(&cm, 127, 0, 0, 1,
                                            PEER_HANDSHAKE_COMPLETE,
                                            true, false)) != NULL;
        if (inbound)
            inbound->addr.svc.port = 49152;
        connman_evict_same_ip_inbound_when_outbound(&cm, outbound);
        ok = ok && outbound && !outbound->disconnect;
        ok = ok && inbound && !inbound->disconnect;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_feeler_does_not_evict(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: feeler outbound does not evict "
           "inbound... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct p2p_node *feeler = NULL;
        struct p2p_node *inbound = NULL;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        ok = ok && (feeler = add_test_peer(&cm, 140, 174, 189, 3,
                                           PEER_HANDSHAKE_COMPLETE,
                                           false, false)) != NULL;
        ok = ok && (inbound = add_test_peer(&cm, 140, 174, 189, 3,
                                            PEER_HANDSHAKE_COMPLETE,
                                            true, false)) != NULL;
        if (feeler)
            feeler->is_feeler = true;
        if (inbound)
            inbound->addr.svc.port = 49152;
        connman_evict_same_ip_inbound_when_outbound(&cm, feeler);
        ok = ok && inbound && !inbound->disconnect;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_unreserved_dial_serial(void)
{
    int failures = 0;
    /* free_slots/free_nodes are observations, not locked reservations. A
     * positive scheduler decision therefore admits exactly one attempt. */
    printf("connman_addnode_fallback: unreserved dial admission stays serial... ");
    {
        bool ok = true;
        size_t want_cold = connman_dial_scheduler_want_for_test(
            true, 0, true, MAX_OUTBOUND_CONNECTIONS,
            DEFAULT_MAX_PEER_CONNECTIONS);
        ok = ok && want_cold == 1;
        ok = ok && connman_dial_scheduler_want_for_test(
                       true, 0, true, 2, DEFAULT_MAX_PEER_CONNECTIONS) == 1;
        ok = ok && connman_dial_scheduler_want_for_test(
                       true, 0, true, MAX_OUTBOUND_CONNECTIONS, 1) == 1;
        ok = ok && connman_dial_scheduler_want_for_test(
                       false, 0, true, MAX_OUTBOUND_CONNECTIONS,
                       DEFAULT_MAX_PEER_CONNECTIONS) == 0;
        ok = ok && connman_dial_scheduler_want_for_test(
                       true, ZCL_PEER_FLOOR_HEALTHY, false,
                       MAX_OUTBOUND_CONNECTIONS,
                       DEFAULT_MAX_PEER_CONNECTIONS) == 1;
        ok = ok && connman_dial_scheduler_want_for_test(
                       true, 0, true, 0,
                       DEFAULT_MAX_PEER_CONNECTIONS) == 0;
        ok = ok && connman_dial_scheduler_want_for_test(
                       true, 0, true, MAX_OUTBOUND_CONNECTIONS, 0) == 0;
        if (ok) printf("OK\n");
        else {
            printf("FAIL (want_cold=%zu)\n", want_cold);
            failures++;
        }
    }
    return failures;
}

