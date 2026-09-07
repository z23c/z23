/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * connman addnode-fallback scenario checks: pre/post-handshake protocol
 * backoff, addrman-failure cooldown, failure-aware distinct batches, the
 * onion-seed last resort, IPv6/onion diversity caps, non-blocking onion
 * queues, and the reactor's cap/exhaustion gating.
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


int check_connman_addnode_prehandshake_protocol_backoff(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: pre-handshake addnode disconnect "
           "backs off as protocol failure... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 51, 178, 179, 75, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
            struct p2p_node *node = add_test_peer(
                &cm, 51, 178, 179, 75, PEER_VERSION_SENT, false, false);
            ok = ok && node != NULL;
            if (node)
                connman_note_addnode_prehandshake_disconnect(
                    &cm, node, "unit-test");
        }

        ok = ok && cm.addnode_protocol_failures[0] == 1;
        ok = ok && cm.addnode_tcp_failures[0] == 0;
        /* First PROTOCOL failure now backs off via the gentle ramp
         * (step 1 = 60s), NOT an instant 900s lockout — a transient drop
         * is re-dialed in time to fill the outbound floor. */
        ok = ok && cm.addnode_backoff_sec[0] == 60;
        ok = ok && cm.addnode_last_attempt[0] > 0;

        /* A second consecutive prehandshake (PROTOCOL) failure ramps but is
         * still well below the 1800s ceiling — proves it is no longer an
         * instant lockout. */
        struct p2p_node *node2 = add_test_peer(
            &cm, 51, 178, 179, 75, PEER_VERSION_SENT, false, false);
        if (node2)
            connman_note_addnode_prehandshake_disconnect(
                &cm, node2, "unit-test-2");
        ok = ok && cm.addnode_protocol_failures[0] == 2;
        ok = ok && cm.addnode_backoff_sec[0] == 120;   /* step 2 */
        ok = ok && cm.addnode_backoff_sec[0] < 1800;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_protocol_backoff_gt_tcp(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: protocol failures back off longer "
           "than TCP failures... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 203, 0, 113, 21, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
            test_set_ipv4(&addr, 203, 0, 113, 22, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
        }

        connman_record_addnode_failure(&cm, 0,
                                       CONNMAN_ADDNODE_FAILURE_TCP);
        connman_record_addnode_failure(&cm, 1,
                                       CONNMAN_ADDNODE_FAILURE_PROTOCOL);
        /* After ONE failure each: TCP=20 (ramp step 0), PROTOCOL=60 (ramp
         * step 1, one ahead). PROTOCOL still backs off longer than TCP —
         * the invariant this test guards — but neither is an instant
         * 900s/120s lockout. */
        ok = ok && cm.addnode_backoff_sec[0] == 20;
        ok = ok && cm.addnode_backoff_sec[1] == 60;
        ok = ok && cm.addnode_backoff_sec[1] > cm.addnode_backoff_sec[0];

        /* A genuinely dead host still reaches the 1800s ceiling: ramp a TCP
         * addnode to 7 consecutive failures (step 6 = the last ramp entry). */
        for (int f = 0; f < 6; f++)
            connman_record_addnode_failure(&cm, 0,
                                           CONNMAN_ADDNODE_FAILURE_TCP);
        ok = ok && cm.addnode_tcp_failures[0] == 7;
        ok = ok && cm.addnode_backoff_sec[0] == 1800;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static bool addnode_cool_down_picks_live_peer(struct connman *cm)
{
    struct addr_info pick;
    enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
    memset(&pick, 0, sizeof(pick));
    bool ok = connman_pick_next_outbound_target(cm,
                                               &cm->next_addnode_cursor,
                                               &pick,
                                               &source,
                                               NULL);
    ok = ok && source == CONNMAN_TARGET_ADDRMAN;
    ok = ok && net_addr_is_ipv4(&pick.addr.svc.addr);
    ok = ok && pick.addr.svc.addr.ip[12] == 81;
    ok = ok && pick.addr.svc.addr.ip[13] == 214;
    return ok;
}

int check_connman_addnode_addrman_failures_cool_down(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: addrman repeated failures cool down... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct net_addr src;
        memset(&sigs, 0, sizeof(sigs));
        net_addr_init(&src);
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 66, 70, 182, 44, 8033);
            ok = ok && addrman_add(&cm.manager.addrman, &addr, &src, 0);
            test_set_ipv4(&addr, 81, 214, 132, 20, 8033);
            ok = ok && addrman_add(&cm.manager.addrman, &addr, &src, 0);
        }

        if (ok) {
            int64_t now = (int64_t)platform_time_wall_time_t();
            for (int i = 0; i < cm.manager.addrman.id_count; i++) {
                struct addr_info *info = &cm.manager.addrman.entries[i];
                if (!info->used)
                    continue;
                if (info->addr.svc.addr.ip[12] == 66 &&
                    info->addr.svc.addr.ip[13] == 70) {
                    info->attempts = 3;
                    info->last_try = now - 120;
                }
            }
        }

        ok = ok && addnode_cool_down_picks_live_peer(&cm);

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static bool addnode_failure_aware_seed_addrs(struct connman *cm,
    struct net_addr *src, int64_t now)
{
    struct net_address addr;
    test_set_ipv4(&addr, 45, 33, 1, 1, 8033);   /* dead A */
    addr.nTime = (uint32_t)now;
    bool ok = addrman_add(&cm->manager.addrman, &addr, src, 0);
    test_set_ipv4(&addr, 51, 178, 1, 1, 8033);  /* dead B */
    addr.nTime = (uint32_t)now;
    ok = ok && addrman_add(&cm->manager.addrman, &addr, src, 0);
    test_set_ipv4(&addr, 47, 88, 1, 1, 8033);   /* live C */
    addr.nTime = (uint32_t)now;
    ok = ok && addrman_add(&cm->manager.addrman, &addr, src, 0);
    test_set_ipv4(&addr, 66, 70, 1, 1, 8033);   /* live D */
    addr.nTime = (uint32_t)now;
    ok = ok && addrman_add(&cm->manager.addrman, &addr, src, 0);
    return ok;
}

static bool addnode_failure_aware_live_pair(
    const struct connman_dial_candidate *batch, size_t n)
{
    bool saw_c = false, saw_d = false, saw_dead = false;
    for (size_t i = 0; i < n; i++) {
        uint8_t oct = batch[i].addr.svc.addr.ip[12];
        if (oct == 47) saw_c = true;
        else if (oct == 66) saw_d = true;
        else saw_dead = true;   /* 45 or 51 must never appear */
    }
    return saw_c && saw_d && !saw_dead;
}

int check_connman_addnode_failure_aware_distinct_batch(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: failure-aware backoff gathers DISTINCT "
           "live candidates and skips recently-dead ones... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct net_addr src;
        memset(&sigs, 0, sizeof(sigs));
        net_addr_init(&src);
        bool ok = connman_init(&cm, params, &sigs);

        int64_t now = (int64_t)platform_time_wall_time_t();

        /* Four addrman addresses, each in a DISTINCT /16 so the /16 diversity
         * cap never rejects them: two "dead-on-arrival" (accumulated failures,
         * last try just now → inside their backoff window) and two "live"
         * (never failed, immediately dialable). */
        ok = ok && addnode_failure_aware_seed_addrs(&cm, &src, now);

        /* A: 5 consecutive failures → 3600 s cooldown; B: 2 → 300 s. Both
         * tried "just now", so both are firmly inside their backoff windows. */
        ok = ok && test_addrman_set_fail(&cm, 45, 5, now);
        ok = ok && test_addrman_set_fail(&cm, 51, 2, now);

        /* One gather asks for a full 4-candidate batch. Only the two LIVE
         * addresses may come back — the dead ones are in failure-aware
         * backoff — and the two returned candidates must be DISTINCT. */
        struct connman_dial_candidate batch[8];
        size_t n = 0;
        if (ok) {
            n = connman_gather_dial_candidates(&cm, batch, 4);
            ok = ok && n == 2;
        }
        ok = ok && addnode_failure_aware_live_pair(batch, n);
        /* Distinct: two different services, never the same slot twice. */
        if (ok && n == 2)
            ok = ok && !net_service_eq(&batch[0].addr.svc, &batch[1].addr.svc);

        /* REFILL: B's backoff expires (last try older than its 300 s window).
         * A stays dead (3600 s window intact) and C/D were charged one attempt
         * each by the gather above (60 s cooldown, tried just now), so the only
         * candidate that may refill the floor now is B. */
        ok = ok && test_addrman_set_fail(&cm, 51, 2, now - 400);
        if (ok) {
            size_t n2 = connman_gather_dial_candidates(&cm, batch, 4);
            ok = ok && n2 == 1;
            ok = ok && batch[0].addr.svc.addr.ip[12] == 51;
        }

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_onion_seed_last_resort(void)
{
    int failures = 0;
    /* S6 (design item #S6, `sovereign-service-roadmap.md`, removed from the
     * tree — recover with `git log --follow -- docs/work/archive/sovereign-service-roadmap.md`): bootstrap
     * fallback-of-last-resort. With DNS seeds AND the operator addrman
     * file BOTH unavailable, the hardcoded chainparams onion-seed tier
     * (connman.c:281-283 run_onion_seed_pass, addrman.c addrman_add) is
     * the only remaining peer source and must still be reachable/bounded.
     *
     * The embedded Tor stub in this test binary never reports
     * tor_integration_is_ready()==true, so the live onion-directory HTTP
     * fetch (try_onion_seed_fetch -> tor_integration_fetch_onion_blocking)
     * cannot be driven end-to-end without a real bootstrapped Tor circuit
     * (see test_onion_bootstrap.c). This test instead deterministically
     * proves the two halves that make the tier a genuine last resort:
     * (1) with a chainparams copy whose DNS (nSeeds) and hardcoded IP
     *     fixed-seed (nFixedSeeds) tiers are both zeroed, and no
     *     peers.dat on disk (operator addrman file "unavailable"),
     *     connman_kick_seed_discovery + connman_load_addrman leave the
     *     node with zero outbound candidates — proving those tiers are
     *     truly exhausted, not silently still supplying peers;
     * (2) the surviving onionSeeds[] tier is non-empty, and once it
     *     contributes addrman entries (the exact effect
     *     try_onion_seed_fetch has on a successful /directory.json
     *     fetch), a single bounded connman_pick_next_outbound_target
     *     call yields a first peer from CONNMAN_TARGET_ADDRMAN — i.e.
     *     the fallback-of-last-resort tier alone is sufficient. */
    printf("connman_addnode_fallback: onion-seed tier is fallback of last "
           "resort when DNS + addrman file are both unavailable... ");
    {
        chain_params_select(CHAIN_MAIN);
        struct chain_params no_dns_no_fixed = *chain_params_get();
        no_dns_no_fixed.nSeeds = 0;
        no_dns_no_fixed.nFixedSeeds = 0;
        bool ok = no_dns_no_fixed.nOnionSeeds > 0;

        char tmpdir[] = "/tmp/zcl_connman_lastresort_XXXXXX";
        ok = ok && mkdtemp(tmpdir) != NULL;

        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        ok = ok && connman_init(&cm, &no_dns_no_fixed, &sigs);
        if (ok)
            cm.datadir = tmpdir;

        /* DNS (0 seeds) + hardcoded fixed seeds (0) contribute nothing;
         * the operator addrman file does not exist in tmpdir either. */
        if (ok)
            connman_kick_seed_discovery(&cm);
        if (ok)
            connman_load_addrman(&cm);

        struct addr_info pick;
        enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
        memset(&pick, 0, sizeof(pick));
        bool exhausted_before_onion_tier =
            ok && !connman_pick_next_outbound_target(&cm,
                                                     &cm.next_addnode_cursor,
                                                     &pick, &source, NULL);
        ok = ok && exhausted_before_onion_tier;

        /* Simulate the onion-seed tier's real effect: a successful
         * /directory.json fetch from a hardcoded .onion seed adds the
         * discovered clearnet peer via addrman_add (connman.c:232),
         * bounded by nOnionSeeds attempts (the same bound
         * run_onion_seed_pass iterates under, connman.c:282-283). */
        if (ok) {
            struct net_addr src;
            net_addr_init(&src);
            for (size_t i = 0; i < no_dns_no_fixed.nOnionSeeds; i++) {
                struct net_address addr;
                test_set_ipv4(&addr, 45, 33, (uint8_t)(i + 1), 1, 8033);
                ok = ok && addrman_add(&cm.manager.addrman, &addr, &src, 0);
            }
        }

        if (ok) {
            memset(&pick, 0, sizeof(pick));
            source = CONNMAN_TARGET_NONE;
            ok = connman_pick_next_outbound_target(&cm,
                                                    &cm.next_addnode_cursor,
                                                    &pick, &source, NULL);
            ok = ok && source == CONNMAN_TARGET_ADDRMAN;
        }

        connman_free(&cm);
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
        (void)system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static bool addnode_ipv6_onion_fixture_peers(struct connman *cm)
{
    bool ok = true;
    const unsigned char ipv6_prefix[4] = {0x26, 0x00, 0x01, 0x00};
    for (int i = 0; i < 2 && ok; i++) {
        struct net_address a;
        net_address_init(&a);
        memcpy(a.svc.addr.ip, ipv6_prefix, 4);
        a.svc.addr.ip[15] = (unsigned char)(i + 1);
        a.svc.port = 8033;
        struct p2p_node *n = p2p_node_create(
            &cm->manager, ZCL_INVALID_SOCKET, &a, "ipv6-peer", false);
        ok = ok && n != NULL;
        if (n) cm->manager.nodes[cm->manager.num_nodes++] = n;
    }
    for (int i = 0; i < 3 && ok; i++) {
        struct net_address a;
        net_address_init(&a);
        a.svc.addr.has_torv3 = true;
        memset(a.svc.addr.torv3, (int)(0xA0 + i), TORV3_ADDR_SIZE);
        a.svc.port = 8033;
        struct p2p_node *n = p2p_node_create(
            &cm->manager, ZCL_INVALID_SOCKET, &a, "onion-peer", false);
        ok = ok && n != NULL;
        if (n) cm->manager.nodes[cm->manager.num_nodes++] = n;
    }
    return ok;
}

static bool addnode_no_capped_ipv6_group_pick(struct connman *cm)
{
    struct addr_info pick;
    enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
    memset(&pick, 0, sizeof(pick));
    bool got = connman_pick_next_outbound_target(
        cm, &cm->next_addnode_cursor, &pick, &source, NULL);
    return !got; /* capped IPv6 group -> no usable candidate */
}

static bool addnode_uncapped_ipv6_group_pick(struct connman *cm)
{
    struct addr_info pick;
    enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
    memset(&pick, 0, sizeof(pick));
    bool got = connman_pick_next_outbound_target(
        cm, &cm->next_addnode_cursor, &pick, &source, NULL);
    return got && source == CONNMAN_TARGET_ADDRMAN &&
        net_addr_is_ipv6(&pick.addr.svc.addr);
}

static bool addnode_onion_cand_never_picked(struct connman *cm,
    struct net_addr *src)
{
    struct net_address cand3;
    net_address_init(&cand3);
    cand3.svc.addr.has_torv3 = true;
    memset(cand3.svc.addr.torv3, 0xCC, TORV3_ADDR_SIZE);
    cand3.svc.port = 8033;
    bool ok = addrman_add(&cm->manager.addrman, &cand3, src, 0);
    struct addr_info pick;
    enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
    memset(&pick, 0, sizeof(pick));
    bool got = connman_pick_next_outbound_target(
        cm, &cm->next_addnode_cursor, &pick, &source, NULL);
    /* Only the still-pickable cand2 (a different IPv6 group) or
     * nothing should ever come back — never the capped onion
     * candidate. addrman_select() is random, so we can't assert
     * "nothing" outright if cand2 already got consumed above;
     * assert the STRONGER invariant instead: whatever (if
     * anything) comes back is never onion. */
    ok = ok && (!got || !net_addr_is_tor(&pick.addr.svc.addr));
    return ok;
}

int check_connman_addnode_ipv6_onion_diversity_caps(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: IPv6 /32 and three-slot onion "
           "outbound diversity caps enforced... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            cm.manager.nodes = zcl_calloc(8, sizeof(*cm.manager.nodes),
                                          "connman_test_nodes_diversity");
            cm.manager.nodes_cap = 8;
        }

        /* Two already-connected outbound peers in the SAME IPv6 /32
         * group (2600:0100::/32 — a real ARIN-allocated GUA range, NOT
         * the RFC 3849 documentation prefix 2001:0db8::/32, which
         * net_addr_is_valid() deliberately rejects as non-routable and
         * would make every addrman_add() below silently fail) saturate
         * MAX_OUTBOUND_IPV6_GROUP32 (2). Three already-connected outbound
         * onion peers saturate the flat MAX_OUTBOUND_ONION (3) bucket —
         * enough for all remote edges of a four-node mesh while still
         * reserving five of eight outbound slots. Onion has no sub-grouping;
         * see
         * connman_outbound_diversity_capped()'s doc comment. */
        ok = ok && addnode_ipv6_onion_fixture_peers(&cm);

        struct net_addr src;
        net_addr_init(&src);

        /* An addrman candidate in the SAME (already-capped) IPv6 group
         * must never be picked. */
        if (ok) {
            struct net_address cand;
            net_address_init(&cand);
            cand.svc.addr.ip[0] = 0x26; cand.svc.addr.ip[1] = 0x00;
            cand.svc.addr.ip[2] = 0x01; cand.svc.addr.ip[3] = 0x00;
            cand.svc.addr.ip[15] = 3;
            cand.svc.port = 8033;
            ok = ok && addrman_add(&cm.manager.addrman, &cand, &src, 0);
        }
        ok = ok && addnode_no_capped_ipv6_group_pick(&cm);

        /* An addrman candidate in a DIFFERENT (uncapped) IPv6 group IS
         * pickable — proves the rejection above was the cap, not some
         * unrelated addrman/connman fixture bug. */
        if (ok) {
            struct net_address cand2;
            net_address_init(&cand2);
            cand2.svc.addr.ip[0] = 0x26; cand2.svc.addr.ip[1] = 0x00;
            cand2.svc.addr.ip[2] = 0x02; cand2.svc.addr.ip[3] = 0x00; /* different /32 */
            cand2.svc.addr.ip[15] = 9;
            cand2.svc.port = 8033;
            ok = ok && addrman_add(&cm.manager.addrman, &cand2, &src, 0);
        }
        ok = ok && addnode_uncapped_ipv6_group_pick(&cm);

        /* An addrman candidate that is onion (already-capped flat
         * bucket) must never be picked either. */
        ok = ok && addnode_onion_cand_never_picked(&cm, &src);

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_onion_queues_no_blocking(void)
{
    int failures = 0;
    /* Onion dial routing, no live Tor: an onion addnode is stored like any
     * other, but the connect attempt routes to the onion stream bridge,
     * which is queued on the addnode list and NOT opened via blocking
     * connect_node — onion circuits belong on the dialer thread so RPC /
     * native peers.add stay inside the 250ms FAST budget. No clearnet
     * fallback, no circuit timeout on this call, and no node is registered
     * until the dialer actually connects. */
    printf("connman_addnode_fallback: onion addnode queues without a "
           "blocking connect_node... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            uint8_t pub[32];
            for (int i = 0; i < 32; i++)
                pub[i] = (uint8_t)(0x30 + i);
            char host[ONION_V3_ADDRESS_LEN + 1];
            ok = onion_v3_address_from_pubkey(pub, host);

            struct net_address a;
            net_address_init(&a);
            ok = ok && net_addr_from_onion(host, &a.svc.addr);
            a.svc.port = 8033;

            connman_open_connection(&cm, &a);
            ok = ok && cm.num_addnodes == 1 && cm.manager.num_nodes == 0;
        }

        if (ok) connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_reactor_clamps_over_cap(void)
{
    int failures = 0;
    /* An over-cap max_connections with room left in the reactor (listen
     * sockets alone don't exhaust it) must be CLAMPED to whatever room
     * remains, not refused — a configured max_connections is a ceiling
     * request, not a start-or-die floor. Exercised via the pure admission
     * helper so this stays a fast unit test (no real reactor threads). */
    printf("connman_addnode_fallback: reactor admission clamps "
           "over-cap max_connections when room remains... ");
    {
        bool impossible = true;
        int admitted = connman_reactor_admit_for_test(
            /*listen_sockets=*/0, /*requested_max=*/REACTOR_MAX_FDS + 10,
            &impossible);
        bool ok = !impossible && admitted == REACTOR_MAX_FDS;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_reactor_passthrough_in_cap(void)
{
    int failures = 0;
    /* A config that fits within REACTOR_MAX_FDS must pass through
     * unchanged (no clamp, not impossible). */
    printf("connman_addnode_fallback: reactor admission passes through "
           "in-cap config unchanged... ");
    {
        bool impossible = true;
        int admitted = connman_reactor_admit_for_test(
            /*listen_sockets=*/2, /*requested_max=*/125, &impossible);
        bool ok = !impossible && admitted == 125;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_reactor_refuses_exhausted(void)
{
    int failures = 0;
    /* Listen sockets ALONE leaving no room for any peer connection is the
     * one genuinely impossible config: it must still refuse via
     * connman_start(), naming the PERMANENT blocker, never silently
     * clamping to zero/negative connections. */
    printf("connman_addnode_fallback: reactor bound-check refuses "
           "when listen sockets alone exhaust the reactor... ");
    {
        bool impossible = false;
        int admitted = connman_reactor_admit_for_test(
            /*listen_sockets=*/(size_t)REACTOR_MAX_FDS, /*requested_max=*/1,
            &impossible);
        bool ok = impossible;
        (void)admitted;   /* unused on the impossible path */

        blocker_reset_for_testing();
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        ok = ok && connman_init(&cm, params, &sigs);

        /* num_listen_sockets is only claimed synthetically here (no real
         * sockets were bound into cm.manager.listen_sockets, whose backing
         * array is sized far below REACTOR_MAX_FDS) — reset it to 0 before
         * connman_free() so its listen-socket teardown loop doesn't walk
         * past the real (tiny) allocation. */
        cm.manager.num_listen_sockets = REACTOR_MAX_FDS;
        cm.manager.max_connections = 1;

        bool started = connman_start(&cm);
        ok = ok && !started;
        ok = ok && blocker_exists("connman_reactor_overflow");
        ok = ok && blocker_class_for("connman_reactor_overflow") ==
                       BLOCKER_PERMANENT;
        /* Never partially started: no P2P thread should be live to join. */
        ok = ok && !cm.started;

        cm.manager.num_listen_sockets = 0;
        connman_free(&cm);
        blocker_reset_for_testing();
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_reactor_passes_default(void)
{
    int failures = 0;
    /* Sane configuration (default max_connections, no listen sockets) must
     * NOT trip the reactor bound-check — proves the admission math doesn't
     * false-positive on the ordinary boot path. */
    printf("connman_addnode_fallback: reactor bound-check passes "
           "default config... ");
    {
        blocker_reset_for_testing();
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        ok = ok && !blocker_exists("connman_reactor_overflow");
        struct connman_reactor_stats rs;
        connman_get_reactor_stats(&rs);
        ok = ok && rs.reactor_max_fds == REACTOR_MAX_FDS;

        connman_free(&cm);
        blocker_reset_for_testing();
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

