/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * "connman" + "addrman" dumpstate subsystems — direct, low-level P2P
 * plumbing visibility that the "network" rollup (diagnostics_network.c)
 * doesn't carry: per-addnode dial ledger detail, the reactor + message-cycle
 * counters, the raw addrman bucket/candidate breakdown, and the
 * net.outbound_floor liveness contract. Before this file, `dumpstate connman`
 * and `dumpstate addrman` both returned "unknown subsystem" — an operator
 * (or agent) diagnosing a thin peer pool had no way to tell "dialer is
 * broken" apart from "addrman genuinely has nothing left to try".
 *
 * Kept as its own translation unit (not folded into diagnostics_network.c)
 * so it never collides with concurrent connman.c/connman_dialer.c work.
 * Like diagnostics_network.c, this is a pure ROLLUP: every field is read
 * from an existing owner's accessor/struct — no re-derivation, no new
 * fold, no re-walk of the message-cycle or reactor internals. The only new
 * O(n) work here is the addrman live/dead candidate tally (n = addrman
 * entries, addr_info_is_terrible() is O(1) per entry) and the addnode
 * ledger walk (n <= MAX_ADDNODES, a small fixed array).
 *
 * See CLAUDE.md "Adding state introspection".
 */

#include "controllers/diagnostics_internal.h"
#include "controllers/network_controller.h"

#include "json/json.h"
#include "net/addrman.h"
#include "net/connman.h"
#include "net/peer_lifecycle.h"
#include "util/supervisor.h"
#include "util/timedata.h"
#include "util/log_macros.h"

#include <string.h>

/* Name of the supervisor liveness contract registered by
 * net_supervisor_register() (app/supervisors/src/net_supervisor.c) and the
 * domain it lives under (app/supervisors/src/domains.c). Mirrored here (as
 * diagnostics_network.c also does) as a lookup key only — this file reads
 * the contract's already-published fields, it does not reimplement its
 * tick/stall logic. */
#define CONNMAN_DIAG_FLOOR_CHILD_NAME "net.outbound_floor"
#define CONNMAN_DIAG_FLOOR_DOMAIN "net"

static void push_connman_floor_json(struct json_value *out,
                                    int64_t fallback_healthy)
{
    struct json_value net_domain = {0};
    json_set_object(&net_domain);
    supervisor_dump_state_json(&net_domain, CONNMAN_DIAG_FLOOR_DOMAIN);

    bool found = false;
    int64_t healthy = fallback_healthy;
    int64_t last_tick_age_us = -1, deadline_secs = -1;
    int64_t ticks_run = 0, stall_fires = 0;

    const struct json_value *children = json_get(&net_domain, "children");
    if (children && children->type == JSON_ARR) {
        size_t n = json_size(children);
        for (size_t i = 0; i < n; i++) {
            const struct json_value *c = json_at(children, i);
            const struct json_value *name = c ? json_get(c, "name") : NULL;
            const char *name_str = name ? json_get_str(name) : NULL;
            if (!name_str ||
                strcmp(name_str, CONNMAN_DIAG_FLOOR_CHILD_NAME) != 0)
                continue;
            found = true;
            const struct json_value *v;
            if ((v = json_get(c, "progress_marker")))
                healthy = json_get_int(v);
            if ((v = json_get(c, "last_tick_age_us")))
                last_tick_age_us = json_get_int(v);
            if ((v = json_get(c, "deadline_secs")))
                deadline_secs = json_get_int(v);
            if ((v = json_get(c, "ticks_run")))
                ticks_run = json_get_int(v);
            if ((v = json_get(c, "stall_fires")))
                stall_fires = json_get_int(v);
            break;
        }
    }
    json_free(&net_domain);

    struct json_value pf = {0};
    json_set_object(&pf);
    json_push_kv_bool(&pf, "registered", found);
    json_push_kv_int(&pf, "healthy_outbound", healthy);
    json_push_kv_int(&pf, "last_tick_age_us", last_tick_age_us);
    json_push_kv_int(&pf, "deadline_secs", deadline_secs);
    json_push_kv_int(&pf, "ticks_run", ticks_run);
    json_push_kv_int(&pf, "stall_fires", stall_fires);
    json_push_kv(out, "floor", &pf);
    json_free(&pf);
}

static void push_addnode_entries_json(struct json_value *out,
                                      struct connman *cm)
{
    struct json_value entries = {0};
    json_set_array(&entries);

    int64_t now = GetAdjustedTime();
    for (int i = 0; i < cm->num_addnodes; i++) {
        struct json_value e = {0};
        json_set_object(&e);

        char addr_str[NET_SERVICE_STR_MAX + 1] = {0};
        net_service_to_string(&cm->addnodes[i].svc, addr_str,
                              sizeof(addr_str));

        int64_t first_failure = cm->addnode_first_failure_ts[i];
        int64_t failure_streak_secs =
            first_failure > 0 ? (now - first_failure) : -1;

        json_push_kv_int(&e, "index", (int64_t)i);
        json_push_kv_str(&e, "address", addr_str);
        json_push_kv_int(&e, "last_attempt", cm->addnode_last_attempt[i]);
        json_push_kv_int(&e, "backoff_sec", cm->addnode_backoff_sec[i]);
        json_push_kv_int(&e, "tcp_failures", cm->addnode_tcp_failures[i]);
        json_push_kv_int(&e, "protocol_failures",
                         cm->addnode_protocol_failures[i]);
        json_push_kv_int(&e, "failure_streak_secs", failure_streak_secs);
        /* RETIRE/HARVEST self-healing ledger (net/connman.h): a retired
         * addnode stays in the ledger (never removed) but is excluded from
         * dial rotation until one manual dial success or an operator
         * `addnode add` re-add revives it. */
        json_push_kv_bool(&e, "retired", cm->addnode_retired[i]);
        json_push_kv_int(&e, "retired_at", cm->addnode_retired_at[i]);

        json_push_back(&entries, &e);
        json_free(&e);
    }
    json_push_kv(out, "entries", &entries);
    json_free(&entries);
}

/* "connman" g_dumpers[] entry — the connection manager's own state: live
 * outbound/inbound counts + diversity stats (connman_get_outbound_health),
 * the addnode dial ledger (lifetime + per-index detail), the reactor
 * admission stats + message-cycle counters (both process-wide accessors,
 * no re-derivation), the net.outbound_floor supervisor contract, a quick
 * addrman size/new/tried pointer (full breakdown lives under the "addrman"
 * subsystem below), and a rollup of peer_lifecycle's own per-source
 * dial-attempt outcome fold (its "sources" array — read verbatim, not
 * recomputed here). */
bool connman_diag_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    struct connman *cm = rpc_net_get_connman();
    json_push_kv_bool(out, "wired", cm != NULL);
    if (!cm)
        return true;

    struct connman_outbound_health health;
    connman_get_outbound_health(cm, &health);

    struct json_value outbound = {0};
    json_set_object(&outbound);
    json_push_kv_int(&outbound, "total", (int64_t)health.outbound_total);
    json_push_kv_int(&outbound, "healthy", (int64_t)health.healthy);
    json_push_kv_int(&outbound, "connecting", (int64_t)health.connecting);
    json_push_kv_int(&outbound, "handshake_incomplete",
                     (int64_t)health.handshake_incomplete);
    json_push_kv_int(&outbound, "ipv4_group_count",
                     (int64_t)health.ipv4_group_count);
    json_push_kv_int(&outbound, "ipv4_max_group_size",
                     (int64_t)health.ipv4_max_group_size);
    json_push_kv_int(&outbound, "healthy_ipv4_group_count",
                     (int64_t)health.healthy_ipv4_group_count);
    json_push_kv_int(&outbound, "healthy_ipv4_max_group_size",
                     (int64_t)health.healthy_ipv4_max_group_size);
    json_push_kv(out, "outbound", &outbound);
    json_free(&outbound);

    struct json_value inbound = {0};
    json_set_object(&inbound);
    json_push_kv_int(&inbound, "total", (int64_t)health.inbound_total);
    json_push_kv_int(&inbound, "healthy", (int64_t)health.inbound_healthy);
    json_push_kv_int(&inbound, "handshake_incomplete",
                     (int64_t)health.inbound_handshake_incomplete);
    json_push_kv(out, "inbound", &inbound);
    json_free(&inbound);

    struct json_value addnode = {0};
    json_set_object(&addnode);
    json_push_kv_int(&addnode, "count", (int64_t)health.addnode_count);
    json_push_kv_int(&addnode, "backoff_active",
                     (int64_t)health.addnode_backoff_active);
    json_push_kv_int(&addnode, "backoff_max_sec",
                     (int64_t)health.addnode_backoff_max_sec);
    json_push_kv_int(&addnode, "tcp_failures", health.addnode_tcp_failures);
    json_push_kv_int(&addnode, "protocol_failures",
                     health.addnode_protocol_failures);
    json_push_kv_int(&addnode, "retired_count",
                     (int64_t)health.addnode_retired_count);
    json_push_kv_int(&addnode, "retirements_total",
                     cm->addnode_retirements_total);
    push_addnode_entries_json(&addnode, cm);
    json_push_kv(out, "addnode", &addnode);
    json_free(&addnode);

    struct json_value zcl23_db = {0};
    json_set_object(&zcl23_db);
    json_push_kv_int(&zcl23_db, "preference_rounds",
                     (int64_t)atomic_load(&cm->zcl23_preference_round));
    json_push_kv_int(&zcl23_db, "candidates_seen",
                     (int64_t)atomic_load(&cm->zcl23_candidates_seen));
    json_push_kv_int(&zcl23_db, "dials_scheduled",
                     (int64_t)atomic_load(&cm->zcl23_dials_scheduled));
    json_push_kv_int(&zcl23_db, "backoff_skips",
                     (int64_t)atomic_load(&cm->zcl23_backoff_skips));
    json_push_kv_int(&zcl23_db, "policy_skips",
                     (int64_t)atomic_load(&cm->zcl23_policy_skips));
    json_push_kv_str(&zcl23_db, "owner", "persistent_dial_scheduler");
    json_push_kv_str(&zcl23_db, "success_gate", "protocol_handshake");
    json_push_kv(out, "zcl23_db", &zcl23_db);
    json_free(&zcl23_db);

    struct connman_reactor_stats rs;
    connman_get_reactor_stats(&rs);
    struct json_value reactor = {0};
    json_set_object(&reactor);
    json_push_kv_int(&reactor, "npfds_high_water",
                     (int64_t)rs.npfds_high_water);
    json_push_kv_int(&reactor, "reactor_max_fds", (int64_t)rs.reactor_max_fds);
    json_push_kv_int(&reactor, "configured_max_connections",
                     (int64_t)rs.configured_max_connections);
    json_push_kv_int(&reactor, "configured_listen_sockets",
                     (int64_t)rs.configured_listen_sockets);
    json_push_kv(out, "reactor", &reactor);
    json_free(&reactor);

    /* v2 (Noise) transport advertisement census — observation only. The
     * default stays OFF; this is the evidence a future owner decision
     * about flipping it would need. See connman.h. */
    struct connman_v2transport_stats v2;
    connman_get_v2transport_stats(&v2);
    struct json_value v2j = {0};
    json_set_object(&v2j);
    json_push_kv_int(&v2j, "advertising_now", (int64_t)v2.advertising_now);
    json_push_kv_int(&v2j, "handshaked_now", (int64_t)v2.handshaked_now);
    json_push_kv_int(&v2j, "advertising_high_water",
                     (int64_t)v2.advertising_high_water);
    json_push_kv_int(&v2j, "advertising_observations_total",
                     (int64_t)v2.advertising_observations_total);
    json_push_kv_int(&v2j, "samples_total", (int64_t)v2.samples_total);
    json_push_kv_bool(&v2j, "default_enabled", cm->manager.v2_enabled);
    json_push_kv(out, "v2transport", &v2j);
    json_free(&v2j);

    struct connman_message_cycle_stats mc;
    connman_get_message_cycle_stats(cm, &mc);
    struct json_value msg = {0};
    json_set_object(&msg);
    json_push_kv_int(&msg, "cycles", (int64_t)mc.cycles);
    json_push_kv_int(&msg, "nodes_snapshotted", (int64_t)mc.nodes_snapshotted);
    json_push_kv_int(&msg, "send_calls", (int64_t)mc.send_calls);
    json_push_kv_int(&msg, "process_calls", (int64_t)mc.process_calls);
    json_push_kv_int(&msg, "recv_ready", (int64_t)mc.recv_ready);
    json_push_kv_int(&msg, "idle_waits", (int64_t)mc.idle_waits);
    json_push_kv_int(&msg, "wakes", (int64_t)mc.wakes);
    json_push_kv(out, "message_cycle", &msg);
    json_free(&msg);

    push_connman_floor_json(out, (int64_t)health.healthy);

    zcl_mutex_lock(&cm->manager.addrman.cs);
    int64_t am_size = (int64_t)addrman_size(&cm->manager.addrman);
    int64_t am_new = cm->manager.addrman.new_count;
    int64_t am_tried = cm->manager.addrman.tried_count;
    zcl_mutex_unlock(&cm->manager.addrman.cs);
    struct json_value am = {0};
    json_set_object(&am);
    json_push_kv_int(&am, "size", am_size);
    json_push_kv_int(&am, "new_count", am_new);
    json_push_kv_int(&am, "tried_count", am_tried);
    json_push_kv(out, "addrman_summary", &am);
    json_free(&am);

    /* Per-source dial-attempt outcomes: peer_lifecycle already folds every
     * attempt/connect/handshake/timeout/reject by source (inbound, addnode,
     * addrman, zcl23_db, manual, anchor) — read its "sources" array
     * verbatim rather than re-deriving it here. */
    struct json_value pl = {0};
    json_set_object(&pl);
    peer_lifecycle_dump_state_json(&pl, NULL);
    const struct json_value *sources = json_get(&pl, "sources");
    if (sources) {
        struct json_value copy = {0};
        json_copy(&copy, sources);
        json_push_kv(out, "dial_outcomes", &copy);
        json_free(&copy);
    }
    json_free(&pl);

    return true;
}

/* "addrman" g_dumpers[] entry — the address manager (peers.dat) itself:
 * new/tried table sizes, bucket occupancy (addrman_get_bucket_stats),
 * address-index health (the O(1) net_addr->id index), and a live-vs-dead
 * candidate tally (addr_info_is_terrible() over every used entry) so a thin
 * dial pool can be diagnosed as "addrman has nothing reachable left" versus
 * "addrman is well-stocked but the dialer isn't drawing from it". */
bool addrman_diag_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    struct connman *cm = rpc_net_get_connman();
    json_push_kv_bool(out, "wired", cm != NULL);
    if (!cm)
        return true;

    struct addr_man *am = connman_addrman(cm);
    if (!am)
        return true;

    /* Fail closed before touching a mutex that teardown may already have
     * destroyed.  Normal shutdown revokes the published connman and joins the
     * diagnostics worker first; this guard is the last-resort validation for
     * malformed fixtures or future lifecycle regressions. */
    if (!am->entries) {
        json_push_kv_bool(out, "snapshot_valid", false);
        json_push_kv_str(out, "unavailable_reason", "addrman_torn_down");
        LOG_WARN("addrman_diag",
                 "addrman snapshot refused: entries already released");
        return true;
    }

    zcl_mutex_lock(&am->cs);
    int64_t size = (int64_t)addrman_size(am);
    int64_t new_count = am->new_count;
    int64_t tried_count = am->tried_count;
    int64_t id_count = am->id_count;
    int64_t entries_cap = (int64_t)am->entries_cap;
    int64_t idx_slots = (int64_t)am->idx_slots;
    int64_t idx_live = (int64_t)am->idx_live;
    int64_t idx_tombs = (int64_t)am->idx_tombs;

    bool snapshot_valid = am->entries != NULL && am->id_count >= 0 &&
        (size_t)am->id_count <= am->entries_cap;
    if (!snapshot_valid) {
        zcl_mutex_unlock(&am->cs);
        json_push_kv_bool(out, "snapshot_valid", false);
        json_push_kv_str(out, "unavailable_reason",
                         "addrman_invariant_failed");
        json_push_kv_int(out, "id_count", id_count);
        json_push_kv_int(out, "entries_cap", entries_cap);
        LOG_WARN("addrman_diag",
                 "addrman snapshot refused: entries=%p id_count=%lld "
                 "entries_cap=%lld",
                 (void *)am->entries, (long long)id_count,
                 (long long)entries_cap);
        return true;
    }

    struct addrman_bucket_stats stats;
    addrman_get_bucket_stats(am, &stats);

    int64_t now = GetAdjustedTime();
    int64_t live = 0, dead = 0;
    for (int64_t i = 0; i < id_count; i++) {
        if (!am->entries[i].used)
            continue;
        if (addr_info_is_terrible(&am->entries[i], now))
            dead++;
        else
            live++;
    }
    zcl_mutex_unlock(&am->cs);

    json_push_kv_bool(out, "snapshot_valid", true);
    json_push_kv_int(out, "size", size);
    json_push_kv_int(out, "new_count", new_count);
    json_push_kv_int(out, "tried_count", tried_count);
    json_push_kv_int(out, "id_count", id_count);
    json_push_kv_int(out, "entries_cap", entries_cap);

    struct json_value buckets = {0};
    json_set_object(&buckets);
    json_push_kv_int(&buckets, "new_occupied", stats.new_occupied);
    json_push_kv_int(&buckets, "tried_occupied", stats.tried_occupied);
    json_push_kv_int(&buckets, "new_buckets_nonempty",
                     stats.new_buckets_nonempty);
    json_push_kv_int(&buckets, "tried_buckets_nonempty",
                     stats.tried_buckets_nonempty);
    json_push_kv_int(&buckets, "max_new_bucket_fill",
                     stats.max_new_bucket_fill);
    json_push_kv_int(&buckets, "max_tried_bucket_fill",
                     stats.max_tried_bucket_fill);
    json_push_kv(out, "buckets", &buckets);
    json_free(&buckets);

    struct json_value index = {0};
    json_set_object(&index);
    json_push_kv_int(&index, "slots", idx_slots);
    json_push_kv_int(&index, "live", idx_live);
    json_push_kv_int(&index, "tombstones", idx_tombs);
    json_push_kv(out, "address_index", &index);
    json_free(&index);

    struct json_value candidates = {0};
    json_set_object(&candidates);
    json_push_kv_int(&candidates, "live", live);
    json_push_kv_int(&candidates, "dead", dead);
    json_push_kv_int(&candidates, "total", live + dead);
    json_push_kv(out, "candidates", &candidates);
    json_free(&candidates);

    return true;
}
