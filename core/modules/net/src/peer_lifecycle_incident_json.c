/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * JSON rendering and host-group classification for the peer lifecycle
 * incidents report: turns already-gathered entry and host-group snapshots
 * into the json_value rows and readiness/severity strings the incidents
 * view returns. Nothing here reads or writes g_pl; peer_lifecycle.c gathers
 * the snapshots under g_pl.lock and calls these renderers. */

#include "peer_lifecycle_internal.h"

#include <stdio.h>
#include <string.h>

static int direction_count(int64_t inbound, int64_t outbound, int64_t unknown)
{
    int n = 0;
    if (inbound > 0)
        n++;
    if (outbound > 0)
        n++;
    if (unknown > 0)
        n++;
    return n;
}

static bool direction_mixed(int64_t inbound, int64_t outbound,
                            int64_t unknown)
{
    return direction_count(inbound, outbound, unknown) > 1;
}

static const char *direction_summary(int64_t inbound, int64_t outbound,
                                     int64_t unknown)
{
    int n = direction_count(inbound, outbound, unknown);
    if (n > 1)
        return "mixed";
    if (inbound > 0)
        return "inbound";
    if (outbound > 0)
        return "outbound";
    return "unknown";
}

static const char *host_group_direction(
    const struct peer_lifecycle_host_group *g)
{
    if (!g)
        return "unknown";
    return direction_summary(g->inbound_entries, g->outbound_entries,
                             g->unknown_entries);
}

static bool host_group_mixed_direction(
    const struct peer_lifecycle_host_group *g)
{
    if (!g)
        return false;
    return direction_mixed(g->inbound_entries, g->outbound_entries,
                           g->unknown_entries);
}

static const char *host_group_bootstrap_readiness(
    const struct peer_lifecycle_host_group *g)
{
    if (!g || g->entries <= 0)
        return "no_peer_history";
    if (g->bootstrap_useful)
        return "useful";
    if (g->handshaked_open_connections <= 0)
        return "no_current_handshaked_connection";
    if (g->handshaked_network_connections <= 0)
        return "missing_NODE_NETWORK";
    if (g->handshaked_advertised_height_connections <= 0)
        return "missing_advertised_height";
    return "split_bootstrap_capabilities";
}

static const char *host_group_advertised_height_trust(
    const struct peer_lifecycle_host_group *g)
{
    if (!g || g->handshaked_open_connections <= 0)
        return "no_current_handshaked_connection";
    if (g->handshaked_trusted_advertised_height_connections > 0)
        return "trusted";
    if (g->handshaked_advertised_height_connections <= 0)
        return "missing";
    if (g->handshaked_network_connections > 0)
        return "split_bootstrap_capabilities";
    if (g->handshaked_untrusted_advertised_height_connections > 0)
        return "untrusted_missing_NODE_NETWORK";
    return "split_bootstrap_capabilities";
}

static const char *host_group_fast_sync_readiness(
    const struct peer_lifecycle_host_group *g)
{
    if (!g || g->entries <= 0)
        return "no_peer_history";
    if (g->fast_sync_useful)
        return "useful";
    const char *bootstrap = host_group_bootstrap_readiness(g);
    if (strcmp(bootstrap, "useful") != 0)
        return bootstrap;
    return "missing_zclassic23_fast_sync";
}

void append_incident_peer_json(
    const struct peer_lifecycle_incident_pick *pick, int64_t now,
    struct json_value *arr)
{
    const struct peer_lifecycle_entry *e = pick->entry;
    struct json_value obj = {0};
    json_set_object(&obj);
    json_push_kv_int(&obj, "peer_id", e->peer_id);
    json_push_kv_str(&obj, "addr", e->addr);
    json_push_kv_str(&obj, "host", pick->host);
    json_push_kv_str(&obj, "source", peer_lifecycle_source_name(e->source));
    json_push_kv_str(&obj, "direction", entry_direction(e));
    json_push_kv_int(&obj, "incident_score", pick->score);
    json_push_kv_int(&obj, "duplicate_host_entries",
                     pick->duplicate_host_entries);
    json_push_kv_int(&obj, "reconnects", entry_reconnects(e));
    json_push_kv_int(&obj, "last_reconnect_at", e->last_reconnect_at);
    json_push_kv_int(&obj, "last_reconnect_interval_secs",
                     e->last_reconnect_interval_secs);
    json_push_kv_int(&obj, "connected", e->connected);
    json_push_kv_int(&obj, "handshake_complete", e->handshake_complete);
    json_push_kv_int(&obj, "disconnected", e->disconnected);
    json_push_kv_int(&obj, "timeout", e->timeout);
    json_push_kv_int(&obj, "rejected", e->rejected);
    json_push_kv_int(&obj, "pre_handshake_disconnects",
                     e->pre_handshake_disconnects);
    json_push_kv_bool(&obj, "connection_open", entry_connection_open(e));
    json_push_kv_bool(&obj, "current_connection_handshaked",
                      entry_current_connection_handshaked(e));
    json_push_kv_int(&obj, "handshake_age_secs",
                     entry_handshake_age_secs(e, now));
    json_push_kv_int(&obj, "services", (int64_t)e->services);
    char summary[128];
    services_summary(e->services, summary, sizeof(summary));
    json_push_kv_str(&obj, "services_summary", summary);
    json_push_kv_int(&obj, "advertised_height", e->start_height);
    json_push_kv_str(&obj, "advertised_height_trust",
                     entry_advertised_height_trust(e));
    json_push_kv_bool(&obj, "advertised_height_trusted",
                      entry_advertised_height_trusted(e));
    json_push_kv_str(&obj, "subver", e->subver);
    json_push_kv_str(&obj, "bootstrap_readiness",
                     entry_bootstrap_readiness(e));
    json_push_kv_bool(&obj, "bootstrap_useful",
                      entry_bootstrap_useful(e));
    json_push_kv_bool(&obj, "fast_sync_useful",
                      entry_fast_sync_useful(e));
    json_push_kv_str(&obj, "last_reason", e->last_reason);
    json_push_kv_str(&obj, "last_disconnect_reason", e->last_reason);
    json_push_kv_int(&obj, "last_seen", e->last_seen);
    json_push_back(arr, &obj);
    json_free(&obj);
}

static void host_group_to_json(const struct peer_lifecycle_host_group *g,
                               int64_t score, struct json_value *obj)
{
    json_set_object(obj);
    json_push_kv_str(obj, "host", g->host);
    json_push_kv_int(obj, "incident_score", score);
    json_push_kv_str(obj, "issue_class", host_group_issue_class(g));
    json_push_kv_str(obj, "next_action", host_group_next_action(g));
    json_push_kv_str(obj, "direction", host_group_direction(g));
    json_push_kv_bool(obj, "mixed_direction",
                      host_group_mixed_direction(g));
    json_push_kv_int(obj, "entries", g->entries);
    json_push_kv_int(obj, "inbound_entries", g->inbound_entries);
    json_push_kv_int(obj, "outbound_entries", g->outbound_entries);
    json_push_kv_int(obj, "unknown_entries", g->unknown_entries);
    json_push_kv_int(obj, "open_connections", g->open_connections);
    json_push_kv_str(obj, "current_open_direction",
                     direction_summary(g->open_inbound_connections,
                                       g->open_outbound_connections,
                                       g->open_unknown_connections));
    json_push_kv_bool(obj, "current_open_mixed_direction",
                      direction_mixed(g->open_inbound_connections,
                                      g->open_outbound_connections,
                                      g->open_unknown_connections));
    json_push_kv_int(obj, "current_open_inbound_connections",
                     g->open_inbound_connections);
    json_push_kv_int(obj, "current_open_outbound_connections",
                     g->open_outbound_connections);
    json_push_kv_int(obj, "current_open_unknown_connections",
                     g->open_unknown_connections);
    json_push_kv_int(obj, "handshaked_open_connections",
                     g->handshaked_open_connections);
    json_push_kv_str(obj, "current_handshaked_direction",
                     direction_summary(g->handshaked_inbound_connections,
                                       g->handshaked_outbound_connections,
                                       g->handshaked_unknown_connections));
    json_push_kv_bool(obj, "current_handshaked_mixed_direction",
                      direction_mixed(g->handshaked_inbound_connections,
                                      g->handshaked_outbound_connections,
                                      g->handshaked_unknown_connections));
    json_push_kv_int(obj, "current_handshaked_inbound_connections",
                     g->handshaked_inbound_connections);
    json_push_kv_int(obj, "current_handshaked_outbound_connections",
                     g->handshaked_outbound_connections);
    json_push_kv_int(obj, "current_handshaked_unknown_connections",
                     g->handshaked_unknown_connections);
    json_push_kv_int(obj, "handshaked_network_connections",
                     g->handshaked_network_connections);
    json_push_kv_int(obj, "handshaked_advertised_height_connections",
                     g->handshaked_advertised_height_connections);
    json_push_kv_int(obj,
                     "handshaked_trusted_advertised_height_connections",
                     g->handshaked_trusted_advertised_height_connections);
    json_push_kv_int(obj,
                     "handshaked_untrusted_advertised_height_connections",
                     g->handshaked_untrusted_advertised_height_connections);
    json_push_kv_int(obj, "handshaked_zclassic23_connections",
                     g->handshaked_zclassic23_connections);
    json_push_kv_int(obj, "bootstrap_useful_connections",
                     g->bootstrap_useful_connections);
    json_push_kv_int(obj, "fast_sync_useful_connections",
                     g->fast_sync_useful_connections);
    json_push_kv_bool(obj, "duplicate_current_connections",
                      g->open_connections > 1);
    json_push_kv_bool(obj, "duplicate_handshaked_connections",
                      g->handshaked_open_connections > 1);
    json_push_kv_int(obj, "connected", g->connected);
    json_push_kv_int(obj, "handshake_complete", g->handshake_complete);
    json_push_kv_int(obj, "active", g->active);
    json_push_kv_int(obj, "disconnected", g->disconnected);
    json_push_kv_int(obj, "timeout", g->timeout);
    json_push_kv_int(obj, "rejected", g->rejected);
    json_push_kv_int(obj, "reconnects", g->reconnects);
    json_push_kv_int(obj, "last_reconnect_at", g->last_reconnect_at);
    json_push_kv_int(obj, "last_reconnect_interval_secs",
                     g->last_reconnect_interval_secs);
    json_push_kv_int(obj, "min_reconnect_interval_secs",
                     g->min_reconnect_interval_secs);
    json_push_kv_int(obj, "max_reconnect_interval_secs",
                     g->max_reconnect_interval_secs);
    json_push_kv_int(obj, "pre_handshake_disconnects",
                     g->pre_handshake_disconnects);
    json_push_kv_int(obj, "services_or", (int64_t)g->services_or);
    char summary[128];
    services_summary(g->services_or, summary, sizeof(summary));
    json_push_kv_str(obj, "services_summary", summary);
    json_push_kv_int(obj, "max_advertised_height",
                     g->max_advertised_height);
    json_push_kv_str(obj, "advertised_height_trust",
                     host_group_advertised_height_trust(g));
    json_push_kv_str(obj, "bootstrap_readiness",
                     host_group_bootstrap_readiness(g));
    json_push_kv_str(obj, "fast_sync_readiness",
                     host_group_fast_sync_readiness(g));
    json_push_kv_bool(obj, "bootstrap_useful", g->bootstrap_useful);
    json_push_kv_bool(obj, "fast_sync_useful", g->fast_sync_useful);
    json_push_kv_int(obj, "last_seen", g->last_seen);
    json_push_kv_str(obj, "last_reason", g->last_reason);
    json_push_kv_str(obj, "last_disconnect_reason", g->last_reason);
}

void append_host_group_json(const struct peer_lifecycle_host_group *g,
                            int64_t score,
                            struct json_value *arr)
{
    struct json_value obj = {0};
    host_group_to_json(g, score, &obj);
    json_push_back(arr, &obj);
    json_free(&obj);
}

void append_primary_host_issue_json(
    const struct peer_lifecycle_host_pick *pick, struct json_value *out)
{
    struct json_value obj = {0};
    if (pick && pick->group) {
        host_group_to_json(pick->group, pick->score, &obj);
        json_push_kv_str(&obj, "status", "attention");
    } else {
        json_set_object(&obj);
        json_push_kv_str(&obj, "status", "ok");
        json_push_kv_str(&obj, "issue_class", "none");
        json_push_kv_str(&obj, "next_action", "monitor_peer_lifecycle");
    }
    json_push_kv(out, "primary_host_issue", &obj);
    json_free(&obj);
}

const char *peer_incidents_bootstrap_readiness(
    int64_t open_connections, int64_t handshaked_connections,
    int64_t bootstrap_useful_connections)
{
    if (bootstrap_useful_connections > 0)
        return "ready";
    if (open_connections <= 0)
        return "no_current_open_connection";
    if (handshaked_connections <= 0)
        return "no_current_handshaked_connection";
    return "no_bootstrap_useful_peer";
}

const char *peer_incidents_fast_sync_readiness(
    int64_t bootstrap_useful_connections, int64_t fast_sync_useful_connections,
    const char *bootstrap_readiness)
{
    if (fast_sync_useful_connections > 0)
        return "ready";
    if (bootstrap_useful_connections <= 0)
        return bootstrap_readiness ? bootstrap_readiness
                                   : "no_bootstrap_useful_peer";
    return "no_zclassic23_fast_sync_peer";
}

const char *peer_incidents_severity(
    int64_t incident_count, int64_t host_incident_count,
    int64_t duplicate_group_count)
{
    if (host_incident_count > 0 || duplicate_group_count > 0)
        return "attention";
    if (incident_count > 0)
        return "info";
    return "ok";
}

const char *peer_incidents_next_action(
    size_t host_pick_count, int64_t incident_count,
    bool bootstrap_blocked, bool fast_sync_blocked)
{
    if (host_pick_count > 0)
        return "inspect primary_host_issue and top_host_incidents";
    if (incident_count > 0)
        return "inspect top_incidents";
    if (bootstrap_blocked)
        return "add_or_fix_bootstrap_peers";
    if (fast_sync_blocked)
        return "prefer_zclassic23_fast_sync_peer";
    return "peer lifecycle has no scored incidents";
}
