/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* The persistent outbound dial scheduler: anchors-first candidate gathering
 * plus non-blocking connect machinery, and the thread_open_connections
 * loop that drives them. Split out of connman.c (which owns lifecycle,
 * addrman persistence, seed discovery, outbound-target selection +
 * diversity-cap accounting, the socket reactor, and the message-cycle
 * thread) — pure code motion, no behavior change. See connman_internal.h
 * for the shared state/helpers this file promotes across the split. */

#define _DEFAULT_SOURCE   /* usleep */
#include "platform/time_compat.h"
#include "connman_internal.h"
#include "net/connman.h"
#include "net/onion_stream.h"
#include "net/addrman.h"
#include "net/peer_lifecycle.h"
#include "net/port_policy.h"
#include "core/random.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Persistent dial scheduler: deduplicated candidates, one attempt ──────
 *
 * The old dialer dialed serially: connect_socket_directly() blocked in
 * select() for up to DEFAULT_CONNECT_TIMEOUT (5 s) PER address, up to 3
 * attempts a loop — so a cold boot could spend ~15 s of wall time before it
 * had even 3 peers if the first candidates were slow/dead. Candidate gathering
 * remains shared by anchors, DHT hints, database-discovered ZCL23 peers,
 * addnodes, and addrman, but the owning scheduler starts only one non-blocking
 * connect at a time. This makes endpoint deduplication and recovery backoff
 * deterministic and prevents dial storms. The scheduler remains a single
 * persistent thread. */

#define ZCL_DIAL_BATCH_MAX 8   /* candidate/test buffer bound */
#define ZCL_DIAL_SCHEDULER_WIDTH 1 /* one scheduler-owned TCP attempt */

static bool connect_only_wait_needed(bool connect_only, size_t outbound,
                                     size_t addnode_count,
                                     bool dht_hint_pending)
{
    return connect_only && outbound >= addnode_count && !dht_hint_pending;
}

static bool outbound_rate_allowed(bool below_floor, bool interval_elapsed,
                                  bool dht_hint_pending)
{
    /* A chain-bound lookup hint is already a bounded, explicit dial request.
     * Do not strand it behind the 10-second background addrman cadence once
     * the healthy floor is met. All slot, dedupe and diversity gates remain. */
    return dht_hint_pending || below_floor || interval_elapsed;
}

#ifdef ZCL_TESTING
bool connman_connect_only_wait_needed_for_test(bool connect_only,
                                               size_t outbound,
                                               size_t addnode_count,
                                               bool dht_hint_pending)
{
    return connect_only_wait_needed(connect_only, outbound, addnode_count,
                                    dht_hint_pending);
}

bool connman_outbound_rate_allowed_for_test(bool below_floor,
                                            bool interval_elapsed,
                                            bool dht_hint_pending)
{
    return outbound_rate_allowed(below_floor, interval_elapsed,
                                 dht_hint_pending);
}
#endif
#define ZCL_FEELER_INTERVAL_DEFAULT_SECS 120
#define ZCL_FEELER_HANDSHAKE_BUDGET_SECS 40

/* Supervisor liveness for the outbound-dialer thread. Registered/retired
 * from connman_start()/connman_join() in connman.c (declared extern in
 * connman_internal.h); beaten from thread_open_connections() below. */
struct thread_liveness_child g_open_liveness = { .id = SUPERVISOR_INVALID_ID };

void connman_collect_healthy_anchors(struct connman *cm,
                                     struct anchor_peer_set *set)
{
    if (!set) return;
    memset(set, 0, sizeof(*set));
    if (!cm) return;

    zcl_mutex_lock(&cm->manager.cs_nodes);
    for (size_t i = 0; i < cm->manager.num_nodes &&
                       set->count < ANCHOR_PEERS_MAX; i++) {
        const struct p2p_node *n = cm->manager.nodes[i];
        if (!n || n->inbound || n->disconnect || n->is_feeler)
            continue;
        if (n->state < PEER_HANDSHAKE_COMPLETE)
            continue;
        if ((n->services & NODE_NETWORK) == 0)
            continue;
        struct anchor_peer *a = &set->peers[set->count++];
        a->addr = n->addr.svc.addr;
        a->port = n->addr.svc.port;
        a->services = n->services;
        a->last_height = n->starting_height;
        a->last_success = n->time_connected;
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);
}

/* Dialable right now: reachable ZClassic port, not one of OUR own addresses,
 * not already connected. Diversity is enforced by the batch tally below (the
 * connected-count check alone can't see in-flight dials). */
static bool connman_candidate_addr_dialable(struct connman *cm,
                                            const struct net_address *addr)
{
    if (!cm || !addr)
        return false;
    if (!zcl_net_port_is_reachable_candidate(addr->svc.port))
        return false;
    if (is_local(&cm->manager, &addr->svc))
        return false;
    if (connman_addr_is_connected(cm, addr))
        return false;
    return true;
}

static bool connman_dht_hint_dialable(struct connman *cm,
                                      const struct net_address *addr)
{
    if (!cm || !addr ||
        !zcl_net_port_is_reachable_candidate(addr->svc.port) ||
        connman_addr_is_connected(cm, addr))
        return false;
    /* Same-host acceptance nodes legitimately publish 127/8 endpoints. The
     * signed identity still cannot promote until the remote Noise static and
     * delegation match; a dishonest loopback hint costs one bounded attempt.
     * Never widen this exception beyond the existing operator-local rule. */
    return !is_local(&cm->manager, &addr->svc) ||
           net_addr_is_operator_local(&addr->svc.addr);
}

/* Next un-tried anchor as a net_address, marking it tried. Returns false once
 * every loaded anchor has had its single priority attempt. */
static bool connman_anchor_take_next(struct connman *cm, struct net_address *out)
{
    if (!cm || !out)
        return false;
    for (size_t i = 0; i < cm->anchors.count && i < ANCHOR_PEERS_MAX; i++) {
        if (cm->anchors_tried[i])
            continue;
        cm->anchors_tried[i] = true;   /* one attempt each, gate-pass or not */
        const struct anchor_peer *a = &cm->anchors.peers[i];
        net_address_init(out);
        out->svc.addr = a->addr;
        out->svc.port = a->port;
        out->nServices = a->services;
        return true;
    }
    return false;
}

/* In-batch diversity/dup tally: the connected-count caps don't see the OTHER
 * in-flight dials in this same batch, so a batch of 8 could all land in one
 * /16. Track what the batch already targets and refuse a candidate that would
 * push connected+in-batch over the cap. */
struct dial_batch_tally {
    struct net_service svcs[ZCL_DIAL_BATCH_MAX];
    size_t n;
};

static bool tally_has_service(const struct dial_batch_tally *t,
                              const struct net_service *s)
{
    for (size_t i = 0; i < t->n; i++)
        if (net_service_eq(&t->svcs[i], s))
            return true;
    return false;
}

static bool batch_diversity_ok(struct connman *cm,
                               const struct dial_batch_tally *t,
                               const struct net_addr *a)
{
    if (net_addr_is_ipv4(a)) {
        uint16_t g = ipv4_group16(a->ip);
        int inb = 0;
        for (size_t i = 0; i < t->n; i++)
            if (net_addr_is_ipv4(&t->svcs[i].addr) &&
                ipv4_group16(t->svcs[i].addr.ip) == g)
                inb++;
        return connman_outbound_group_count(cm, g) + inb <
               MAX_OUTBOUND_PER_GROUP16;
    }
    if (net_addr_is_tor(a)) {
        int inb = 0;
        for (size_t i = 0; i < t->n; i++)
            if (net_addr_is_tor(&t->svcs[i].addr))
                inb++;
        return connman_outbound_onion_count(cm) + inb < MAX_OUTBOUND_ONION;
    }
    if (net_addr_is_ipv6(a)) {
        uint32_t g = ipv6_group32(a->ip);
        int inb = 0;
        for (size_t i = 0; i < t->n; i++)
            if (net_addr_is_ipv6(&t->svcs[i].addr) &&
                ipv6_group32(t->svcs[i].addr.ip) == g)
                inb++;
        return connman_outbound_ipv6_group_count(cm, g) + inb <
               MAX_OUTBOUND_IPV6_GROUP32;
    }
    return true;
}

size_t connman_gather_dial_candidates(struct connman *cm,
                                      struct connman_dial_candidate *out,
                                      size_t max)
{
    if (!cm || !out || max == 0)
        return 0;
    if (max > ZCL_DIAL_BATCH_MAX)
        max = ZCL_DIAL_BATCH_MAX;

    struct dial_batch_tally tally;
    tally.n = 0;
    size_t n = 0;

    /* (1) Anchors first — but NOT in -connect-only mode, where the explicit
     * -connect peers are the entire outbound universe. Each anchor gets one
     * attempt (marked tried even when it fails a gate, so a dead/saturated
     * anchor can't make us spin). */
    if (!g_connect_only) {
        while (n < max) {
            struct net_address a;
            if (!connman_anchor_take_next(cm, &a))
                break;
            if (!connman_candidate_addr_dialable(cm, &a))
                continue;
            if (tally_has_service(&tally, &a.svc))
                continue;
            if (!batch_diversity_ok(cm, &tally, &a.svc.addr))
                continue;
            out[n].addr = a;
            out[n].source = CONNMAN_TARGET_ANCHOR;
            out[n].addnode_index = SIZE_MAX;
            out[n].is_feeler = false;
            tally.svcs[tally.n++] = a.svc;
            n++;
        }
    }

    /* (2) A chain-bound ZENDP resolution requested by iterative DHT lookup.
     * This queue is honored even in -connect-only mode: the operator's fixed
     * edges remain the initial topology, while a specific authenticated
     * FIND_NODE result may open one bounded, identity-checked next hop. */
    while (n < max) {
        struct net_address a;
        if (!connman_take_dht_hint(cm, &a))
            break;
        if (!connman_dht_hint_dialable(cm, &a) ||
            tally_has_service(&tally, &a.svc) ||
            (!net_addr_is_operator_local(&a.svc.addr) &&
             !batch_diversity_ok(cm, &tally, &a.svc.addr)))
            continue;
        out[n].addr = a;
        out[n].source = CONNMAN_TARGET_DHT_HINT;
        out[n].addnode_index = SIZE_MAX;
        out[n].is_feeler = false;
        tally.svcs[tally.n++] = a.svc;
        n++;
    }

    /* (3) Database-discovered ZCL23 peers, on alternating scheduler turns.
     * The alternate turns belong to addnode/addrman so a stale preferred set
     * can never starve healthy general candidates. */
    if (!g_connect_only && n < max && cm->known_zcl23_peers) {
        uint64_t zcl23_round =
            atomic_fetch_add(&cm->zcl23_preference_round, 1);
        if ((zcl23_round & 1u) == 0 &&
            connman_gather_known_zcl23_candidate(
                cm, tally.svcs, tally.n, &out[n])) {
            tally.svcs[tally.n++] = out[n].addr.svc;
            n++;
        }
    }

    /* (4) addnode / addrman via the existing selector. Bound the draws so a
     * pool that keeps returning saturated/duplicate picks can't spin, but
     * budget enough draws that a batch still fills with DISTINCT live
     * candidates when a large fraction of addrman is in failure-aware backoff
     * (each returned-but-cooling address is skipped, so too tight a cap could
     * return a short batch and leave the outbound floor unfilled while live
     * candidates remained undrawn). */
    size_t draws = 0;
    const size_t draw_cap = max * 8 + 16;
    while (n < max && draws < draw_cap) {
        draws++;
        struct addr_info info;
        enum connman_outbound_target_source src = CONNMAN_TARGET_NONE;
        size_t idx = SIZE_MAX;
        memset(&info, 0, sizeof(info));
        if (!connman_pick_next_outbound_target(cm, &cm->next_addnode_cursor,
                                               &info, &src, &idx))
            break;
        if (!connman_candidate_addr_dialable(cm, &info.addr)) {
            /* Already connected → an addnode gets its attempt marked good so
             * its cursor advances, matching the serial dialer. */
            if (src == CONNMAN_TARGET_ADDNODE &&
                connman_addr_is_connected(cm, &info.addr))
                connman_record_addnode_attempt(cm, idx, true);
            continue;
        }
        if (tally_has_service(&tally, &info.addr.svc))
            continue;
        /* Multiple explicit loopback -connect targets are distinct local
         * daemons, not a remote /16 concentration. Permit that operator-only
         * fixture shape; public addnodes and all addrman candidates retain
         * the normal diversity cap. */
        bool explicit_operator_local =
            src == CONNMAN_TARGET_ADDNODE &&
            net_addr_is_operator_local(&info.addr.svc.addr);
        if (!explicit_operator_local &&
            !batch_diversity_ok(cm, &tally, &info.addr.svc.addr))
            continue;
        out[n].addr = info.addr;
        out[n].source = src;
        out[n].addnode_index = idx;
        out[n].is_feeler = false;
        tally.svcs[tally.n++] = info.addr.svc;
        n++;
    }

    return n;
}

/* ── Feeler probes (Bitcoin Core pattern) ─────────────────────────────── */

static int64_t connman_feeler_interval_secs(void)
{
    const char *e = getenv("ZCL_FEELER_INTERVAL_SECS");
    if (e && e[0]) {
        long v = strtol(e, NULL, 10);
        if (v > 0 && v < 86400)
            return (int64_t)v;
    }
    return ZCL_FEELER_INTERVAL_DEFAULT_SECS;
}

static bool connman_feeler_in_flight(struct connman *cm)
{
    bool found = false;
    zcl_mutex_lock(&cm->manager.cs_nodes);
    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        const struct p2p_node *n = cm->manager.nodes[i];
        if (n && n->is_feeler && !n->disconnect) { found = true; break; }
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);
    return found;
}

/* Pick an addrman NEW-table address for a feeler probe. */
static bool connman_pick_feeler_target(struct connman *cm,
                                       struct net_address *out)
{
    for (int i = 0; i < 32; i++) {
        struct addr_info pick;
        memset(&pick, 0, sizeof(pick));
        if (!addrman_select(&cm->manager.addrman, /*new_only=*/true, &pick))
            return false;
        if (!connman_candidate_addr_dialable(cm, &pick.addr))
            continue;
        *out = pick.addr;
        return true;
    }
    return false;
}

/* Sweep feeler connections each open-thread iteration: a completed handshake
 * proves the address is real and speaks our protocol → mark it addrman_good
 * and disconnect; a feeler that never handshook inside the budget is dropped.
 * addrman_good is called AFTER releasing cs_nodes to avoid nesting the addrman
 * lock under cs_nodes (lock-order hygiene). */
static void connman_sweep_feelers(struct connman *cm)
{
    int64_t now = (int64_t)platform_time_wall_time_t();
    struct net_service good_svcs[ZCL_DIAL_BATCH_MAX];
    size_t ngood = 0;

    zcl_mutex_lock(&cm->manager.cs_nodes);
    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        struct p2p_node *n = cm->manager.nodes[i];
        if (!n || !n->is_feeler || n->disconnect)
            continue;
        if (n->state >= PEER_HANDSHAKE_COMPLETE) {
            if (ngood < ZCL_DIAL_BATCH_MAX)
                good_svcs[ngood++] = n->addr.svc;
            (void)p2p_node_request_disconnect(
                n, P2P_DISCONNECT_FEELER_COMPLETE,
                P2P_DISCONNECT_SOURCE_DIAL_SCHEDULER,
                n->endpoint_generation);
        } else if (now - n->time_connected > ZCL_FEELER_HANDSHAKE_BUDGET_SECS) {
            (void)p2p_node_request_disconnect(
                n, P2P_DISCONNECT_FEELER_TIMEOUT,
                P2P_DISCONNECT_SOURCE_DIAL_SCHEDULER,
                n->endpoint_generation);
        }
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);

    for (size_t i = 0; i < ngood; i++)
        addrman_good(&cm->manager.addrman, &good_svcs[i], now);
}

/* ── Batch dial: fire non-blocking connects, poll to a shared deadline ──── */

static void connman_record_dial_failure(struct connman *cm,
                                        const struct connman_dial_candidate *c)
{
    char ipbuf[NET_ADDR_STR_MAX + 1];
    net_addr_to_string(&c->addr.svc.addr, ipbuf, sizeof(ipbuf));
    if (c->source == CONNMAN_TARGET_ADDNODE) {
        connman_record_addnode_attempt(cm, c->addnode_index, false);
    } else if (c->source == CONNMAN_TARGET_ADDRMAN ||
               c->source == CONNMAN_TARGET_ZCL23_DB ||
               c->source == CONNMAN_TARGET_DHT_HINT) {
        /* A NON-feeler addrman or ZCL23 candidate was already charged exactly
         * one attempt when the shared scheduler selected it. Charging a
         * second one here double-counted every
         * TCP-refused dial, so a refused address escalated its backoff twice
         * as fast as a dead-on-arrival peer that connects TCP then stalls
         * pre-handshake (charged only once, at pick) — backwards, since the
         * stalling peer wastes far MORE of an outbound slot. Charge here ONLY
         * for feelers, which skip the pick-time path and would otherwise carry
         * no durable per-address failure ledger at all. One dial now == one
         * attempt for every source, so the failure-aware backoff ramp escalates
         * on a true consecutive-failure count. */
        if (c->is_feeler || c->source == CONNMAN_TARGET_DHT_HINT)
            addrman_attempt(&cm->manager.addrman, &c->addr.svc,
                            (int64_t)platform_time_wall_time_t());
    }
    /* ANCHOR carries no durable per-address failure ledger. */
    event_emitf(EV_TCP_CONNECT_FAILED, 0, "%s:%u", ipbuf, c->addr.svc.port);
}

/* Finish a dial whose TCP connect completed successfully: register the node,
 * flag feelers, record addnode success, note lifecycle. */
static void connman_complete_dial(struct connman *cm,
                                  struct connman_dial_candidate *c,
                                  zcl_socket_t sock)
{
    enum peer_lifecycle_source ls =
        c->source == CONNMAN_TARGET_ADDNODE ? PEER_LIFECYCLE_SOURCE_ADDNODE :
        c->source == CONNMAN_TARGET_ANCHOR  ? PEER_LIFECYCLE_SOURCE_ANCHOR  :
        c->source == CONNMAN_TARGET_ZCL23_DB ? PEER_LIFECYCLE_SOURCE_ZCL23_DB :
                                              PEER_LIFECYCLE_SOURCE_ADDRMAN;
    const char *dest = NULL;
    char destbuf[NET_SERVICE_STR_MAX + 1];
    if (c->source == CONNMAN_TARGET_ADDNODE) {
        net_service_to_string(&c->addr.svc, destbuf, sizeof(destbuf));
        dest = destbuf;
    }

    bool created = false;
    struct p2p_node *node =
        connect_node_from_socket(&cm->manager, &c->addr, dest, sock, &created);
    if (!node) {
        connman_record_dial_failure(cm, c);
        return;
    }
    /* Only flag a FRESHLY-created node as a feeler; a dedupe race returns an
     * existing real peer that must never be swept/disconnected as a feeler. */
    if (c->is_feeler && created)
        node->is_feeler = true;
    if (c->source == CONNMAN_TARGET_ADDNODE)
        connman_record_addnode_attempt(cm, c->addnode_index, true);
    peer_lifecycle_note_connected(node, ls);
    if (created) {
        char ipbuf[NET_ADDR_STR_MAX + 1];
        net_addr_to_string(&c->addr.svc.addr, ipbuf, sizeof(ipbuf));
        printf("Outbound dial: connected to %s:%u%s\n", ipbuf,
               c->addr.svc.port, c->is_feeler ? " (feeler)" : "");
    }
    connman_release_connect_node_ref(cm, node);
}

/* One in-flight non-blocking connect awaiting its writability edge. */
struct dial_inflight {
    zcl_socket_t sock;
    size_t       ci;      /* index into the candidate batch */
};

/* Fire every candidate's non-blocking connect, then poll the in-progress set
 * against ONE shared DEFAULT_CONNECT_TIMEOUT window, completing winners and
 * closing losers. Immediate (localhost) connects complete inline. */
static void connman_dial_batch(struct connman *cm,
                               struct connman_dial_candidate *batch,
                               size_t count)
{
    struct dial_inflight inflight[ZCL_DIAL_BATCH_MAX + 1];
    size_t nin = 0;

    for (size_t i = 0; i < count && !g_stop; i++) {
        struct connman_dial_candidate *c = &batch[i];
        peer_lifecycle_note_attempt(&c->addr,
            c->source == CONNMAN_TARGET_ADDNODE ? PEER_LIFECYCLE_SOURCE_ADDNODE :
            c->source == CONNMAN_TARGET_ANCHOR  ? PEER_LIFECYCLE_SOURCE_ANCHOR  :
            c->source == CONNMAN_TARGET_ZCL23_DB ? PEER_LIFECYCLE_SOURCE_ZCL23_DB :
                                                  PEER_LIFECYCLE_SOURCE_ADDRMAN);
        if (net_addr_is_tor(&c->addr.svc.addr)) {
            /* Onion candidates do NOT join the non-blocking socket race:
             * there is no fd to poll until the circuit exists, and the
             * shared 5 s clearnet window is far short of a 10-60 s circuit
             * build. They get their own blocking budget instead (capped at
             * MAX_OUTBOUND_ONION per batch by batch_diversity_ok), inline on
             * the scheduler thread — g_open_liveness is liveness-only (no
             * progress deadline), so the block trips no supervisor gate. */
            zcl_socket_t s = ZCL_INVALID_SOCKET;
            if (onion_stream_connect(&c->addr.svc, &s,
                                     ONION_STREAM_CONNECT_TIMEOUT_MS))
                connman_complete_dial(cm, c, s);   /* takes ownership of s */
            else
                connman_record_dial_failure(cm, c);
            continue;
        }
        zcl_socket_t s = ZCL_INVALID_SOCKET;
        enum zcl_connect_start st = connect_socket_start(&c->addr.svc, &s);
        if (st == ZCL_CONNECT_START_ERROR) {
            connman_record_dial_failure(cm, c);
            continue;
        }
        if (st == ZCL_CONNECT_START_CONNECTED) {
            connman_complete_dial(cm, c, s);
            continue;
        }
        inflight[nin].sock = s;
        inflight[nin].ci = i;
        nin++;
    }

    int64_t deadline_ms = platform_time_monotonic_ms() + DEFAULT_CONNECT_TIMEOUT;
    while (nin > 0 && !g_stop) {
        int64_t remaining = deadline_ms - platform_time_monotonic_ms();
        if (remaining <= 0)
            break;

        struct pollfd pfds[ZCL_DIAL_BATCH_MAX + 1];
        for (size_t i = 0; i < nin; i++) {
            pfds[i].fd = inflight[i].sock;
            pfds[i].events = POLLOUT;
            pfds[i].revents = 0;
        }
        int r = poll(pfds, nin, (int)(remaining > 1000000 ? 1000000 : remaining));
        if (r < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (r == 0)
            continue;   /* re-check the deadline */

        /* Resolve every ready fd; swap-remove from the in-flight set. */
        for (size_t i = 0; i < nin; ) {
            short re = pfds[i].revents;
            if (re == 0) { i++; continue; }
            zcl_socket_t s = inflight[i].sock;
            struct connman_dial_candidate *c = &batch[inflight[i].ci];
            bool ok = !(re & (POLLERR | POLLHUP | POLLNVAL)) &&
                      connect_socket_check(s);
            if (ok) {
                connman_complete_dial(cm, c, s);   /* takes ownership of s */
            } else {
                close_socket(&s);
                connman_record_dial_failure(cm, c);
            }
            /* swap-remove i */
            inflight[i] = inflight[nin - 1];
            pfds[i] = pfds[nin - 1];
            nin--;
        }
    }

    /* Deadline / stop: whatever is still connecting lost the race. */
    for (size_t i = 0; i < nin; i++) {
        zcl_socket_t s = inflight[i].sock;
        close_socket(&s);
        connman_record_dial_failure(cm, &batch[inflight[i].ci]);
    }
}

void *thread_open_connections(void *arg)
{
    struct connman *cm = (struct connman *)arg;

    static int64_t s_last_addrman_attempt = 0;
    uint64_t open_iterations = 0;
    thread_liveness_beat(&g_open_liveness, 0);

    while (!g_stop) {
        atomic_store_explicit(&cm->dial_scheduler_last_progress_us,
                              platform_time_monotonic_us(),
                              memory_order_relaxed);
        /* Count outbound peers in two buckets:
         *   `outbound_slot` — all non-disconnecting outbound peers,
         *     used as the upper bound on connection slots so we don't
         *     overflow MAX_OUTBOUND_CONNECTIONS.
         *   `outbound_healthy` — only outbound peers past handshake,
         *     used to decide if we need aggressive backfill. Without
         *     this distinction a node with 1 working peer + several stuck
         *     in PEER_CONNECTING reads as fully-outbound and never
         *     hunts for replacements. */
        /* Sweep any feeler probes that finished (mark good + disconnect) or
         * timed out, BEFORE counting slots — feelers never count toward the
         * outbound floor/slot budget. */
        connman_sweep_feelers(cm);

        size_t outbound_slot = 0;
        size_t outbound_healthy = 0;
        zcl_mutex_lock(&cm->manager.cs_nodes);
        for (size_t i = 0; i < cm->manager.num_nodes; i++) {
            struct p2p_node *n = cm->manager.nodes[i];
            if (n->inbound || n->disconnect || n->is_feeler) continue;
            outbound_slot++;
            if (n->state >= PEER_HANDSHAKE_COMPLETE)
                outbound_healthy++;
        }
        zcl_mutex_unlock(&cm->manager.cs_nodes);

        /* RETIRE: cheap (O(MAX_ADDNODES), no I/O) — safe every iteration.
         * Floor-guarded internally against outbound_healthy. */
        connman_retire_dead_addnodes(cm, outbound_healthy);

        size_t outbound = outbound_slot;

        if (outbound >= MAX_OUTBOUND_CONNECTIONS ||
            cm->manager.num_nodes >= (size_t)cm->manager.max_connections) {
            sleep(1);
            continue;
        }

        /* In connect-only mode maintain one outbound connection PER
         * -connect addnode (each explicit target gets its own slot), not a
         * single global connection. The old `outbound >= 1` gate stopped
         * after the FIRST addnode connected, so a second/third -connect peer
         * was never dialed despite the "1 connection per addnode" promise —
         * a single-supplier node could not fan out to its other explicit
         * peers. Multiple connections to the SAME peer still cause snapshot
         * serving to split and stall, but that is prevented by connect_node's
         * per-service dedupe, not by capping the global outbound count.
         * Bound: MAX_OUTBOUND_CONNECTIONS (checked above) still caps the
         * total, and num_addnodes <= MAX_ADDNODES. */
        if (connect_only_wait_needed(
                g_connect_only, outbound, (size_t)cm->num_addnodes,
                connman_dht_hint_pending(cm))) {
            sleep(1);
            continue;
        }

        /* Parallel batch dial. Below the healthy-peer floor (3 fully-
         * handshaked outbound) we fill many slots at once (peers stuck in
         * PEER_CONNECTING don't count, so a node with 1 working peer + several
         * stuck sockets still backfills aggressively). At/above the floor we
         * dial gently, rate-limited to one candidate per 10 s. Either way the
         * whole batch's connects run concurrently against ONE shared 5 s
         * window instead of serially, so N slow peers no longer cost N×5 s. */
        int64_t now_oc = (int64_t)platform_time_wall_time_t();
        const size_t OUTBOUND_HEALTHY_FLOOR = ZCL_PEER_FLOOR_HEALTHY;
        bool below_floor = (outbound_healthy < OUTBOUND_HEALTHY_FLOOR);
        bool rate_ok = outbound_rate_allowed(
            below_floor, now_oc - s_last_addrman_attempt >= 10,
            connman_dht_hint_pending(cm));

        /* HARVEST: below the healthy floor AND addrman itself is running
         * dry — pull proven-reachable candidates from the durable network
         * census into addrman (NEVER as pinned addnodes). Cadence-gated so
         * a persistently-hungry loop doesn't hammer the census DB every
         * ~1s tail iteration; the outcome feeds the NEXT gather call, not
         * necessarily this one. connman doesn't track chain height, so no
         * min_height filter here (-1). */
        if (below_floor &&
            now_oc - cm->last_census_harvest_ts >=
                ZCL_ADDNODE_HARVEST_INTERVAL_SECS) {
            zcl_mutex_lock(&cm->manager.addrman.cs);
            size_t am_size = addrman_size(&cm->manager.addrman);
            zcl_mutex_unlock(&cm->manager.addrman.cs);
            if (am_size < ZCL_ADDNODE_HARVEST_WEAK_ADDRMAN_THRESHOLD) {
                cm->last_census_harvest_ts = now_oc;
                connman_harvest_census_candidates(cm, -1);
            }
        }

        size_t free_slots = MAX_OUTBOUND_CONNECTIONS - outbound; /* > 0 here */
        size_t want = 0;
        if (rate_ok) {
            if (outbound_healthy == 0)
                want = free_slots;                    /* bootstrap: fill fast */
            else if (below_floor)
                want = free_slots < 4 ? free_slots : 4;
            else
                want = 1;                             /* healthy: gentle */
        }
        if (want > ZCL_DIAL_BATCH_MAX)
            want = ZCL_DIAL_BATCH_MAX;
        if (want > ZCL_DIAL_SCHEDULER_WIDTH)
            want = ZCL_DIAL_SCHEDULER_WIDTH;

        struct connman_dial_candidate batch[ZCL_DIAL_BATCH_MAX + 1];
        size_t nbatch = 0;
        if (want > 0)
            nbatch = connman_gather_dial_candidates(cm, batch, want);

        /* Feeler: at most one transient NEW-table validation probe per
         * interval, appended beyond the slot budget (feelers never occupy an
         * outbound slot). Skipped in -connect-only mode. */
        if (!g_connect_only && nbatch == 0) {
            int64_t feeler_interval = connman_feeler_interval_secs();
            if (now_oc - cm->last_feeler_ts >= feeler_interval &&
                !connman_feeler_in_flight(cm)) {
                struct net_address ftarget;
                if (connman_pick_feeler_target(cm, &ftarget)) {
                    cm->last_feeler_ts = now_oc;
                    batch[nbatch].addr = ftarget;
                    batch[nbatch].source = CONNMAN_TARGET_ADDRMAN;
                    batch[nbatch].addnode_index = SIZE_MAX;
                    batch[nbatch].is_feeler = true;
                    nbatch++;
                } else {
                    /* Nothing probeable right now — still back off the timer
                     * so we don't re-scan the NEW table every loop. */
                    cm->last_feeler_ts = now_oc;
                }
            }
        }

        if (nbatch > 0) {
            if (rate_ok)
                s_last_addrman_attempt = now_oc;
            connman_dial_batch(cm, batch, nbatch);
        }

        /* Liveness-only, not the sleep-tail's 10s cap: the batch dial above
         * can wait on connect() for up to one 5 s window. */
        thread_liveness_beat(&g_open_liveness, (int64_t)++open_iterations);

        /* Sleep based on outbound count:
         * 0 outbound: 200ms (desperate)
         * below target: 1s
         * at target: 10s (just monitoring) */
        if (outbound == 0)
            usleep(200000); /* 200ms */
        else if (outbound < MAX_OUTBOUND_CONNECTIONS)
            sleep(1);
        else
            sleep(10);
    }
    return NULL;
}
