// one-result-type-ok:telemetry-fill-provider — a telemetry provider's failure
// reason does not travel in its return value, it travels in the SNAPSHOT: each
// leaf carries its own presence plus a static reason token, which is strictly
// more information than one struct zcl_result per call could hold. The bool is
// reserved for the one thing that is not a per-leaf fact — a NULL snapshot —
// and the signature is fixed by the frozen render contract
// (util/telemetry_render.h) and by the `*_dump_state_fill` shape
// check_dumper_never_blocks.sh scans for by name.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `network` telemetry provider. Contract and scope: the header.
 *
 * Three rules govern every line below, and each one is a defect this layer
 * exists to make unrepresentable:
 *
 *   1. NO FIELD NAME IS WRITTEN HERE. The setters take the member token from
 *      util/telemetry/network_fields.def; nothing in this file emits a JSON
 *      key or a string that a reader will see as a field name.
 *
 *   2. NO LEAF IS LEFT ALONE. Every leaf is written on every path — a value
 *      with its source, or an explicit UNAVAILABLE / NOT_APPLICABLE with a
 *      static reason token. A leaf nobody touched stays TELEMETRY_UNSET, which
 *      the render layer counts as a provider defect. That is the check, and it
 *      is why the early-outs below set the whole group before returning.
 *
 *   3. NO BLOCKING ACQUIRE. The node array is taken with zcl_mutex_trylock;
 *      losing the race sets the leaves behind it UNAVAILABLE rather than
 *      queueing an operator's diagnostic behind the network thread.
 */

#include "services/network_telemetry.h"
#include "base/compiler.h"

/* An upward include, deliberately.
 * rpc_net_get_connman() is the ONLY published way to reach the live connman,
 * and it is declared in the controllers layer because that is where the setter
 * that installs it lives. This provider reads it and nothing else from there.
 * The alternatives are worse: duplicating the accessor would clone the pointer
 * this whole telemetry effort exists to stop cloning, and adding a second
 * registration seam for one read would leave two places that can disagree
 * about which connman is current. Moving the accessor down into models/ or
 * lib/ is the real fix and belongs with the network layer's own ownership
 * work, not with a telemetry provider. */
#include "controllers/network_controller.h" // shape-layer-ok:telemetry-connman-accessor

#include "net/connman.h"
#include "net/net.h"
#include "net/peer_lifecycle.h"
#include "net/tor_integration.h"
#include "net/v2_transport.h"
#include "util/log_macros.h"
#include "util/sync.h"
#include "util/timedata.h"

#include <stdatomic.h>
#include <stddef.h>

/* The static reason tokens. Short, greppable, never prose and never formatted:
 * `reason` is borrowed by the render layer with program lifetime. */
#define NT_R_NO_NODE   "node_not_in_process"
#define NT_R_NODES_BUSY "connman_nodes_busy"
#define NT_R_TOR_STUB  "tor_stub_build"
#define NT_R_TOR_OFF   "onion_not_started"

/* The floor's threshold is declared in the field table as a literal, because a
 * field table is data pasted into translation units that include no node
 * headers. This assertion is the link between the two: raise
 * ZCL_PEER_FLOOR_HEALTHY and the build stops here until the table's
 * `outbound_healthy` row is raised with it. */
static_assert(ZCL_PEER_FLOOR_HEALTHY == 3,
              "network_fields.def states the outbound floor as a literal 3; "
              "update peers.outbound_floor_target's means text and this "
              "assertion together");

/* ── tor: which Tor this binary linked ───────────────────────────────────
 * The default build links vendor/tor_stub.c, which provides every symbol
 * tor_integration.c needs EXCEPT dynhost_client_fetch. tor_integration.c
 * already relies on that asymmetry (its own weak reference, "When linked
 * against libtor_stub.a, this is NULL"), so re-declaring the same weak
 * reference here is reading the existing link-time fact, not inventing a new
 * one. It is the only runtime-observable difference between the two builds,
 * and without it a stub build would report "no onion" in exactly the shape a
 * real build reports "the onion is down". */
extern int dynhost_client_fetch(const char *, uint16_t, const char *,
    void (*)(int, const uint8_t *, size_t, void *), void *, int)
    ZCL_WEAK_IMPORT;

static bool nt_real_tor_linked(void) { return dynhost_client_fetch != NULL; }

/* ── peers ───────────────────────────────────────────────────────────────
 * Split in two so each half can fail on its own: the connman half needs a
 * wired connection manager, the funnel half is a process-global counter block
 * that exists whether or not networking was constructed. Reporting them
 * together would let one absence hide the other's answer. */

/* Every connman-backed leaf, marked unreadable for one stated reason. Written
 * as one function so a leaf added to the table cannot be given a value on the
 * happy path and forgotten on this one. */
static void nt_peers_connman_unavailable(struct network_snapshot *s,
                                         const char *why)
{
    TELEMETRY_UNAVAILABLE_LEAF(s, outbound_healthy, why);
    TELEMETRY_UNAVAILABLE_LEAF(s, outbound_floor_satisfied, why);
    TELEMETRY_UNAVAILABLE_LEAF(s, outbound_total, why);
    TELEMETRY_UNAVAILABLE_LEAF(s, outbound_handshake_incomplete, why);
    TELEMETRY_UNAVAILABLE_LEAF(s, inbound_total, why);
    TELEMETRY_UNAVAILABLE_LEAF(s, healthy_group_count, why);
    TELEMETRY_UNAVAILABLE_LEAF(s, handshaked_total, why);
    TELEMETRY_UNAVAILABLE_LEAF(s, oldest_connection_age_secs, why);
    TELEMETRY_UNAVAILABLE_LEAF(s, newest_connection_age_secs, why);
}

/* The leaves that need a walk of the live node array, marked unreadable. A
 * subset of the above: connman can be wired while its node array is busy. */
static void nt_peers_walk_unavailable(struct network_snapshot *s,
                                      const char *why)
{
    TELEMETRY_UNAVAILABLE_LEAF(s, handshaked_total, why);
    TELEMETRY_UNAVAILABLE_LEAF(s, oldest_connection_age_secs, why);
    TELEMETRY_UNAVAILABLE_LEAF(s, newest_connection_age_secs, why);
}

/* One bounded pass over the node array under a TRYlock, producing the three
 * peer leaves connman's own accessors do not carry plus the three transport
 * counts. `struct connman` bounds num_nodes by the configured connection
 * ceiling, so this is O(peers) with no I/O and no nested acquire. */
struct nt_node_walk {
    bool taken;
    int64_t handshaked;
    int64_t oldest_age;
    int64_t newest_age;
    bool have_age;
    int64_t encrypted;
    int64_t plaintext;
    int64_t handshaking;
};

static void nt_walk_nodes(struct connman *cm, struct nt_node_walk *w)
{
    *w = (struct nt_node_walk){0};
    if (!cm)
        return;
    if (!zcl_mutex_trylock(&cm->manager.cs_nodes))
        return;
    w->taken = true;
    int64_t now = GetAdjustedTime();
    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        const struct p2p_node *n = cm->manager.nodes[i];
        if (!n)
            continue;
        if (atomic_load_explicit(&n->disconnect, memory_order_acquire))
            continue;
        enum peer_state st =
            atomic_load_explicit(&n->state, memory_order_acquire);
        if (st >= PEER_HANDSHAKE_COMPLETE)
            w->handshaked++;

        /* Age of a live connection. time_connected is 0 on a node that has
         * not stamped one yet; counting that as "connected at the epoch"
         * would publish a 56-year-old connection. */
        if (n->time_connected > 0 && now >= n->time_connected) {
            int64_t age = now - n->time_connected;
            if (!w->have_age) {
                w->oldest_age = age;
                w->newest_age = age;
                w->have_age = true;
            } else {
                if (age > w->oldest_age) w->oldest_age = age;
                if (age < w->newest_age) w->newest_age = age;
            }
        }

        /* What this connection NEGOTIATED, not what the build can do. A node
         * with no transport attached is carrying plaintext bytes. */
        if (!n->transport)
            w->plaintext++;
        else if (n->transport->state == V2_ESTABLISHED)
            w->encrypted++;
        else
            w->handshaking++;
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);
}

static void nt_fill_peers(struct network_snapshot *s, struct connman *cm,
                          const struct nt_node_walk *w)
{
    TELEMETRY_SET_BOOL(s, connman_wired, cm != NULL, TELEMETRY_SRC_IN_PROCESS);
    /* A compile-time constant, so it answers in every process — including the
     * one where no live count does. It is what outbound_healthy is read
     * against, and a comparison anchor with no anchor is useless. */
    TELEMETRY_SET_I64(s, outbound_floor_target, ZCL_PEER_FLOOR_HEALTHY,
                      TELEMETRY_SRC_CONFIG);

    if (!cm) {
        nt_peers_connman_unavailable(s, NT_R_NO_NODE);
        return;
    }

    struct connman_outbound_health h;
    connman_get_outbound_health(cm, &h);
    TELEMETRY_SET_I64(s, outbound_healthy, h.healthy,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_BOOL(s, outbound_floor_satisfied,
                       h.healthy >= (size_t)ZCL_PEER_FLOOR_HEALTHY,
                       TELEMETRY_SRC_DERIVED);
    TELEMETRY_SET_I64(s, outbound_total, h.outbound_total,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, outbound_handshake_incomplete, h.handshake_incomplete,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, inbound_total, h.inbound_total,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, healthy_group_count, h.healthy_ipv4_group_count,
                      TELEMETRY_SRC_IN_PROCESS);

    if (!w->taken) {
        nt_peers_walk_unavailable(s, NT_R_NODES_BUSY);
        return;
    }
    TELEMETRY_SET_I64(s, handshaked_total, w->handshaked,
                      TELEMETRY_SRC_IN_PROCESS);
    if (w->have_age) {
        TELEMETRY_SET_I64(s, oldest_connection_age_secs, w->oldest_age,
                          TELEMETRY_SRC_IN_PROCESS);
        TELEMETRY_SET_I64(s, newest_connection_age_secs, w->newest_age,
                          TELEMETRY_SRC_IN_PROCESS);
    } else {
        /* No live connection carries a timestamp, so an age is not a value
         * that failed to read — it is a value with nothing to measure. */
        TELEMETRY_NOT_APPLICABLE_LEAF(s, oldest_connection_age_secs,
                                      "no_timed_connection");
        TELEMETRY_NOT_APPLICABLE_LEAF(s, newest_connection_age_secs,
                                      "no_timed_connection");
    }
}

/* The dial funnel. peer_lifecycle's totals are a process-global counter block
 * behind a leaf mutex that is held only for a struct copy — never across I/O,
 * never nested under the reducer — so this cannot queue behind a fold. */
static void nt_fill_funnel(struct network_snapshot *s)
{
    struct peer_lifecycle_summary pl;
    peer_lifecycle_get_summary(&pl);
    TELEMETRY_SET_I64(s, dial_attempts_total, pl.attempted,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, handshakes_completed_total, pl.handshake_complete,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, pre_handshake_disconnects_total,
                      pl.pre_handshake_disconnects, TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, dial_timeouts_total, pl.timeout,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, rejected_total, pl.rejected,
                      TELEMETRY_SRC_IN_PROCESS);
}

/* ── tor ─────────────────────────────────────────────────────────────────
 * Three states, kept apart on purpose, because collapsing any two of them is
 * how a reader ends up chasing a Tor outage that cannot exist:
 *   stub build            the onion is impossible here      -> not_applicable
 *   real build, no node   this process never started Tor    -> unavailable
 *   real build, in node   whatever tor_integration reports  -> present
 */
static void nt_fill_tor(struct network_snapshot *s, bool in_node)
{
    bool real_tor = nt_real_tor_linked();
    TELEMETRY_SET_TEXT(s, tor_build, real_tor ? "real_tor" : "tor_stub",
                       TELEMETRY_SRC_CONFIG);
    if (!real_tor) {
        TELEMETRY_NOT_APPLICABLE_LEAF(s, onion_enabled, NT_R_TOR_STUB);
        TELEMETRY_NOT_APPLICABLE_LEAF(s, onion_published, NT_R_TOR_STUB);
        TELEMETRY_NOT_APPLICABLE_LEAF(s, onion_address, NT_R_TOR_STUB);
        return;
    }
    if (!in_node) {
        TELEMETRY_UNAVAILABLE_LEAF(s, onion_enabled, NT_R_NO_NODE);
        TELEMETRY_UNAVAILABLE_LEAF(s, onion_published, NT_R_NO_NODE);
        TELEMETRY_UNAVAILABLE_LEAF(s, onion_address, NT_R_NO_NODE);
        return;
    }
    bool enabled = tor_integration_is_enabled();
    TELEMETRY_SET_BOOL(s, onion_enabled, enabled, TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_BOOL(s, onion_published, tor_integration_is_ready(),
                       TELEMETRY_SRC_IN_PROCESS);
    const char *addr = tor_integration_get_onion_address();
    if (addr && addr[0])
        TELEMETRY_SET_TEXT(s, onion_address, addr, TELEMETRY_SRC_IN_PROCESS);
    else if (enabled)
        /* Tor is up and has not published a descriptor yet: a real read that
         * has no value yet, not a configuration in which the field is
         * meaningless. */
        TELEMETRY_UNAVAILABLE_LEAF(s, onion_address, "onion_not_published");
    else
        TELEMETRY_NOT_APPLICABLE_LEAF(s, onion_address, NT_R_TOR_OFF);
}

/* ── transport ───────────────────────────────────────────────────────────
 * The negotiated counts come from the same node walk the peer group used, so
 * the two halves of the reply describe one instant rather than two. */
static void nt_fill_transport(struct network_snapshot *s, struct connman *cm,
                              const struct nt_node_walk *w)
{
    if (!cm) {
        TELEMETRY_UNAVAILABLE_LEAF(s, v2_offered_by_default, NT_R_NO_NODE);
        TELEMETRY_UNAVAILABLE_LEAF(s, peers_encrypted_now, NT_R_NO_NODE);
        TELEMETRY_UNAVAILABLE_LEAF(s, peers_plaintext_now, NT_R_NO_NODE);
        TELEMETRY_UNAVAILABLE_LEAF(s, peers_handshaking_now, NT_R_NO_NODE);
        TELEMETRY_UNAVAILABLE_LEAF(s, peers_advertising_v2_now, NT_R_NO_NODE);
        TELEMETRY_UNAVAILABLE_LEAF(s, v2_advertising_high_water, NT_R_NO_NODE);
        return;
    }
    TELEMETRY_SET_BOOL(s, v2_offered_by_default, cm->manager.v2_enabled,
                       TELEMETRY_SRC_CONFIG);

    /* The advertisement census is a lock-free publication the reactor poll
     * loop updates, so it answers even when the node array is busy. */
    struct connman_v2transport_stats v2;
    connman_get_v2transport_stats(&v2);
    TELEMETRY_SET_I64(s, peers_advertising_v2_now, v2.advertising_now,
                      TELEMETRY_SRC_CACHED_PUBLICATION);
    TELEMETRY_SET_I64(s, v2_advertising_high_water, v2.advertising_high_water,
                      TELEMETRY_SRC_CACHED_PUBLICATION);

    if (!w->taken) {
        TELEMETRY_UNAVAILABLE_LEAF(s, peers_encrypted_now, NT_R_NODES_BUSY);
        TELEMETRY_UNAVAILABLE_LEAF(s, peers_plaintext_now, NT_R_NODES_BUSY);
        TELEMETRY_UNAVAILABLE_LEAF(s, peers_handshaking_now, NT_R_NODES_BUSY);
        return;
    }
    TELEMETRY_SET_I64(s, peers_encrypted_now, w->encrypted,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, peers_plaintext_now, w->plaintext,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, peers_handshaking_now, w->handshaking,
                      TELEMETRY_SRC_IN_PROCESS);
}

bool network_dump_state_fill(struct network_snapshot *snap)
{
    if (!snap)
        LOG_FAIL("network_telemetry", "fill: snapshot is NULL");

    int64_t now = telemetry_now_unix();
    if (now >= 0)
        TELEMETRY_SET_I64(snap, collected_unix, now,
                          TELEMETRY_SRC_IN_PROCESS);
    else
        TELEMETRY_UNAVAILABLE_LEAF(snap, collected_unix, "wall_clock_unset");

    /* ONE handle for the whole fill: reading it twice could straddle a
     * shutdown and produce a snapshot whose peer group came from a live
     * connection manager and whose transport group did not. */
    struct connman *cm = rpc_net_get_connman();
    struct nt_node_walk walk;
    nt_walk_nodes(cm, &walk);

    nt_fill_peers(snap, cm, &walk);
    nt_fill_funnel(snap);
    nt_fill_tor(snap, cm != NULL);
    nt_fill_transport(snap, cm, &walk);
    return true;
}
