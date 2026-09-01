/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "conditions/peer_floor_violated.h"
#include "util/log_macros.h"
#include "framework/condition.h"

#include "event/event.h"
#include "net/connman.h"
#include "platform/time_compat.h"
#include "services/block_source_policy.h"
#include "services/sync_monitor.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

/* Healthy-outbound floor: the single source of truth in net/net.h
 * (ZCL_PEER_FLOOR_HEALTHY). This condition escalates to operator_needed when
 * healthy outbound stays below it past PEER_FLOOR_TRIGGER_SECS; keep it in
 * lockstep with the connman dialer + net supervisor via the shared constant
 * (lint gate check-peer-floor-single-source). */
#define PEER_FLOOR_MIN_HEALTHY ZCL_PEER_FLOOR_HEALTHY
#define PEER_FLOOR_TRIGGER_SECS 60

static _Atomic int64_t g_first_violation_unix;
static _Atomic int g_outbound_at_detect;
static _Atomic int g_inbound_at_detect;
static _Atomic int g_local_height_at_detect;
static _Atomic int g_peer_max_at_detect;

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

static bool peerless_ok(void)
{
    const char *v = getenv("ZCL_PEERLESS_OK");
    return v && v[0] == '1' && v[1] == '\0';
}

static bool detect_peer_floor_violated(void)
{
    if (peerless_ok()) {
        atomic_store(&g_first_violation_unix, 0);
        return false;
    }

    struct connman *cm = sync_monitor_connman();
    if (!cm)
        return false;

    struct connman_outbound_health h;
    connman_get_outbound_health(cm, &h);
    if (h.healthy >= PEER_FLOOR_MIN_HEALTHY) {
        atomic_store(&g_first_violation_unix, 0);
        return false;
    }

    int64_t now = platform_time_wall_unix();
    int64_t first = atomic_load(&g_first_violation_unix);
    if (first == 0) {
        atomic_store(&g_first_violation_unix, now);
        return false;
    }
    if (now - first < PEER_FLOOR_TRIGGER_SECS)
        return false;

    struct main_state *ms = sync_monitor_main_state();
    atomic_store(&g_outbound_at_detect, (int)h.healthy);
    atomic_store(&g_inbound_at_detect, (int)h.inbound_total);
    atomic_store(&g_peer_max_at_detect, connman_max_peer_height(cm));
    atomic_store(&g_local_height_at_detect,
                 ms ? active_chain_height(&ms->chain_active) : -1);
    return true;
}

static enum condition_remedy_result remedy_peer_floor_violated(void)
{
    struct connman *cm = sync_monitor_connman();
    if (!cm)
        return COND_REMEDY_SKIP;

    /* This recovery decision is P2P-only —
     * block_source_policy_peer_floor_recovery_needed()
     * below populates ONLY in.sources[BSP_SOURCE_P2P]; the mirror/oracle
     * source slot is left zeroed/unavailable, so whether the legacy
     * zclassicd mirror/oracle is up or down never gates `recover` here. The
     * remedy (peer kicks, addnode backoff clear, seed-discovery kick, and
     * the zero_outbound onion-directory last-resort below) fires purely off
     * "healthy outbound < PEER_FLOOR_MIN_HEALTHY for
     * PEER_FLOOR_TRIGGER_SECS", oracle reachability irrelevant. */
    struct bsp_decision decision;
    bool recover = block_source_policy_peer_floor_recovery_needed(
        atomic_load(&g_outbound_at_detect),
        PEER_FLOOR_MIN_HEALTHY,
        atomic_load(&g_local_height_at_detect),
        atomic_load(&g_peer_max_at_detect),
        &decision);
    LOG_INFO("condition", "[condition:peer_floor_violated] outbound=%d inbound=%d " "peer_max=%d decision=%s reason=%s", atomic_load(&g_outbound_at_detect), atomic_load(&g_inbound_at_detect), atomic_load(&g_peer_max_at_detect), recover ? "recover" : "wait", decision.reason);
    if (!recover)
        return COND_REMEDY_SKIP;

    size_t inbound_seen = 0;
    size_t inbound_dropped = 0;
    size_t outbound_dropped = 0;
    zcl_mutex_lock(&cm->manager.cs_nodes);
    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        struct p2p_node *n = cm->manager.nodes[i];
        if (n && !n->inbound && !n->disconnect &&
            n->state < PEER_HANDSHAKE_COMPLETE) {
            /* Operator-configured -addnode peers are dial targets of last
             * resort; do not tear them down mid-handshake while the floor is
             * low. Let the normal addnode backoff/retirement logic handle a
             * persistently-failing addnode. */
            if (connman_node_is_addnode(cm, n)) {
                LOG_INFO("condition",
                         "[condition:peer_floor_violated] keeping addnode %s "
                         "in handshake (state=%s) — not dropping it",
                         n->addr_name, peer_state_name(n->state));
                continue;
            }
            (void)p2p_node_request_disconnect(
                n, P2P_DISCONNECT_POLICY_ROTATION,
                P2P_DISCONNECT_SOURCE_PEER_POLICY, n->endpoint_generation);
            outbound_dropped++;
        }
        if (n && n->inbound && !n->disconnect) {
            inbound_seen++;
            if (inbound_seen > 2) {
                (void)p2p_node_request_disconnect(
                    n, P2P_DISCONNECT_POLICY_ROTATION,
                    P2P_DISCONNECT_SOURCE_PEER_POLICY,
                    n->endpoint_generation);
                inbound_dropped++;
            }
        }
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);

    /* With zero healthy outbound there is nothing left to protect: clear
     * every addnode backoff regardless of failure mix so the dialer can
     * retry immediately. (Counter-mix gating alone permanently excluded
     * any addnode that ever logged one protocol failure — e.g. a single
     * self-induced 90s handshake timeout.) Above zero, forgive only
     * pure-TCP failure history; a protocol-failing addnode keeps its
     * backoff. */
    bool zero_outbound = connman_outbound_healthy_count(cm) == 0;
    for (int ai = 0; ai < cm->num_addnodes; ai++) {
        if (zero_outbound ||
            (cm->addnode_protocol_failures[ai] == 0 &&
             cm->addnode_tcp_failures[ai] > 0)) {
            cm->addnode_backoff_sec[ai] = 0;
            cm->addnode_last_attempt[ai] = 0;
        }
    }
    connman_kick_seed_discovery(cm);

    /* Peer-of-last-resort. When there is NOTHING outbound, the clearnet
     * fixed/DNS kick above can stay dry (eclipsed, DNS down, IPs stale).
     * Before this remedy can ever accrue toward operator_needed, exhaust
     * the onion-directory supplier set: fetch /directory.json from the
     * operator-curated + chainparams onion seeds + known zcl23 .onion
     * peers and harvest their clearnet IPs into addrman. This keeps the
     * remedy ladder always-terminating for the partitioned-node class —
     * a recovering node always has a >1 bootstrap path that does NOT
     * depend on a co-located oracle or legacy datadir. Blocking onion
     * fetches are safe here: the condition engine runs remedies on its
     * own thread, off the chain hot path. */
    if (zero_outbound)
        connman_kick_onion_seeds(cm);

    sync_monitor_kick_local_sync("condition:peer_floor_violated");
    sync_monitor_record_recovery(WATCHDOG_PEER_FLOOR,
                                 atomic_load(&g_local_height_at_detect),
                                 atomic_load(&g_peer_max_at_detect),
                                 atomic_load(&g_outbound_at_detect),
                                 "condition:peer_floor_violated");
    event_emitf(EV_SYNC_STATE_CHANGE, 0,
                "condition PEER_FLOOR drop_outbound=%zu drop_inbound=%zu",
                outbound_dropped, inbound_dropped);

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    return COND_REMEDY_OK;
}

static bool witness_peer_floor_violated(int64_t target_at_detect)
{
    (void)target_at_detect;
    if (peerless_ok())
        return true;

    struct connman *cm = sync_monitor_connman();
    if (!cm)
        return false;

    /* Peers must be restored above the floor — necessary but NOT sufficient. */
    if (connman_outbound_healthy_count(cm) < PEER_FLOOR_MIN_HEALTHY)
        return false;

    /* DOCTRINE: a peer_floor remedy only resolved the symptom if the chain
     * actually resumed making progress. Counting peers alone is a false-ok: a
     * node can hold >=3 healthy peers while the tip never moves (e.g. a
     * header-admit stall), so peer count alone must never satisfy the witness.
     *
     * Resolution = either (a) the local height advanced past the height
     * recorded at detect (chain is moving again), OR (b) there is genuinely
     * nothing to fetch — we are already at/above the best height any peer
     * advertises, so peers were the only deficit and it is now cured. If
     * peers advertise blocks beyond our tip and our tip has NOT advanced, the
     * symptom persists (something other than a peer shortage is wedging us)
     * and the witness must FAIL so attempts accrue toward operator_needed. */
    struct main_state *ms = sync_monitor_main_state();
    if (!ms)
        return false;
    int height_now = active_chain_height(&ms->chain_active);
    int height_at_detect = atomic_load(&g_local_height_at_detect);
    if (height_at_detect >= 0 && height_now > height_at_detect)
        return true; /* chain advanced — genuinely recovered */

    int peer_max = connman_max_peer_height(cm);
    /* Nothing to sync: peers offer nothing beyond what we already have. */
    return peer_max >= 0 && height_now >= peer_max;
}

static struct condition c_peer_floor_violated = {
    .name = "peer_floor_violated",
    .severity = COND_WARN,
    .poll_secs = 5,
    .backoff_secs = 60,
    /* Finite: after this many un-witnessed remedies (peers present but the
     * tip is not advancing), the engine escalates to operator_needed. The old
     * value (100000) meant a wedged-but-peered chain could never page anyone
     * — the engine just looped result=ok forever. */
    .max_attempts = 5,
    /* Continue-with-cooldown (sticky-node plan #7): a peer shortage is an
     * external-resource fault — peers can return at any time. After the 5
     * fast attempts page a human once, the engine re-arms the recovery remedy
     * every 10 minutes, UNBOUNDED (cooldown_max_rearms = 0), so a node that
     * lost all peers keeps trying to re-discover them forever instead of
     * permanently giving up. The episode resets (fresh page ladder, attempts)
     * the instant detect() goes false, i.e. peers come back above the floor. */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
    .detect = detect_peer_floor_violated,
    .remedy = remedy_peer_floor_violated,
    .witness = witness_peer_floor_violated,
    .witness_window_secs = 60,
};

void register_peer_floor_violated(void)
{
    (void)condition_register(&c_peer_floor_violated);
}

#ifdef ZCL_TESTING
void peer_floor_violated_test_reset(void)
{
    atomic_store(&g_first_violation_unix, 0);
    atomic_store(&g_outbound_at_detect, 0);
    atomic_store(&g_inbound_at_detect, 0);
    atomic_store(&g_local_height_at_detect, -1);
    atomic_store(&g_peer_max_at_detect, -1);
    atomic_store(&g_test_remedy_calls, 0);
}

int peer_floor_violated_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
