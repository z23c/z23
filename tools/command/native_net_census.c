/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native command handlers for the network-omniscience operator surface:
 *   core.network.census   — paginated, filterable node list
 *   core.network.node     — everything known about one node (+ obs + edges)
 *   core.network.versions — user-agent / version distribution
 *   core.network.graph    — topology stats + our connectivity vs the census
 *
 * These open the banked census stores (<datadir>/peers_projection.db +
 * topology.db) with SQLITE_OPEN_READONLY via engine/modules/storage census_read — no
 * running node needed,
 * consensus never touched. When the indexer lane has not yet created a table,
 * every command degrades to a successful { populated:false, note:... } body
 * ("census empty: indexer not yet populated"), never an error. All output is
 * bounded by construction.
 */

#define _GNU_SOURCE
#include "command/native_command.h"

#include "kernel/command_registry.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "storage/census_read.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── shared helpers ──────────────────────────────────────────────────── */

/* Fill a successful reply body that names the store as not-yet-populated. The
 * operator gets a stable, machine-readable signal instead of an error. */
static void census_reply_not_populated(struct zcl_command_reply *reply,
                                       const char *datadir)
{
    char path[600];
    census_read_db_path(datadir, path, sizeof(path));
    (void)json_push_kv_bool(&reply->data, "populated", false);
    (void)json_push_kv_str(&reply->data, "note",
                           "census empty: indexer not yet populated");
    (void)json_push_kv_str(&reply->data, "db_path", path);
}

/* True (and body filled with the not-populated note) when the store is absent
 * or its tables do not exist yet — the caller returns immediately. */
static bool census_open_or_degrade(struct zcl_command_reply *reply,
                                   census_reader **out)
{
    const char *datadir = zcl_native_command_datadir();
    census_reader *r = NULL;
    enum census_read_status st = census_read_open(datadir, &r);
    if (st != CENSUS_READ_OK || !r) {
        census_reply_not_populated(reply, datadir);
        *out = NULL;
        return false;
    }
    *out = r;
    return true;
}

static void push_node_object(struct json_value *arr, const struct census_node *n)
{
    char endpoint[CENSUS_ENDPOINT_MAX];
    snprintf(endpoint, sizeof(endpoint), "%s:%d", n->ip, n->port);
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    (void)json_push_kv_str(&o, "endpoint", endpoint);
    (void)json_push_kv_str(&o, "ip", n->ip);
    (void)json_push_kv_int(&o, "port", n->port);
    (void)json_push_kv_str(&o, "user_agent",
                           n->user_agent[0] ? n->user_agent : "(unknown)");
    if (n->ua_truncated)
        (void)json_push_kv_bool(&o, "user_agent_truncated", true);
    if (n->ua_overflow)
        (void)json_push_kv_bool(&o, "user_agent_overflow", true);
    (void)json_push_kv_int(&o, "protocol_version", n->protocol_version);
    (void)json_push_kv_int(&o, "services", n->services);
    (void)json_push_kv_int(&o, "reported_height", n->reported_height);
    (void)json_push_kv_bool(&o, "reachable", n->reachable);
    (void)json_push_kv_int(&o, "last_seen", n->last_seen);
    (void)json_push_back(arr, &o);
    json_free(&o);
}

/* ── core.network.census ─────────────────────────────────────────────── */

void zcl_native_handle_network_census(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    census_reader *r = NULL;
    if (!census_open_or_degrade(reply, &r))
        return;

    /* Filters + paging (pedantic bounds enforced by the reader too). */
    struct census_filter f = { .min_height = -1, .seen_within_secs = -1 };
    const char *ua = json_get_str(json_get(request->input, "ua-contains"));
    if (ua && ua[0])
        f.ua_contains = ua;
    const struct json_value *mh = json_get(request->input, "min-height");
    if (mh && mh->type == JSON_INT)
        f.min_height = json_get_int(mh);
    const struct json_value *sw = json_get(request->input, "seen-within");
    if (sw && sw->type == JSON_INT) {
        f.seen_within_secs = json_get_int(sw);
        f.now_unix = platform_time_wall_unix();
    }

    int limit = CENSUS_LIST_DEFAULT_LIMIT;
    const struct json_value *lv = json_get(request->input, "limit");
    if (lv && lv->type == JSON_INT) {
        int64_t v = json_get_int(lv);
        if (v > 0)
            limit = (v > CENSUS_LIST_HARD_CAP) ? CENSUS_LIST_HARD_CAP : (int)v;
    }
    int64_t page = 0;
    const struct json_value *pv = json_get(request->input, "page");
    if (pv && pv->type == JSON_INT && json_get_int(pv) > 0)
        page = json_get_int(pv);
    int64_t offset = page * limit;

    struct census_node rows[CENSUS_LIST_HARD_CAP];
    int64_t matched = 0;
    int n = census_read_list(r, &f, offset, limit, rows,
                             CENSUS_LIST_HARD_CAP, &matched);

    (void)json_push_kv_bool(&reply->data, "populated", true);
    (void)json_push_kv_int(&reply->data, "total_nodes",
                           census_read_node_total(r));
    (void)json_push_kv_int(&reply->data, "matched", matched);
    (void)json_push_kv_int(&reply->data, "page", page);
    (void)json_push_kv_int(&reply->data, "limit", limit);
    (void)json_push_kv_int(&reply->data, "returned", n);
    (void)json_push_kv_int(&reply->data, "offset", offset);
    (void)json_push_kv_bool(&reply->data, "truncated",
                            offset + n < matched);

    struct json_value nodes;
    json_init(&nodes);
    json_set_array(&nodes);
    for (int i = 0; i < n; i++)
        push_node_object(&nodes, &rows[i]);
    (void)json_push_kv(&reply->data, "nodes", &nodes);
    json_free(&nodes);

    census_read_close(r);
}

/* ── core.network.node ───────────────────────────────────────────────── */

/* Split "ip[:port]" into ip + port (default 8033). Bounds-checked; returns
 * false on empty host or out-of-range port. */
static bool parse_target(const char *target, char *ip, size_t ip_cap, int *port)
{
    if (!target || !target[0])
        return false;
    *port = 8033;
    const char *colon = strrchr(target, ':');
    /* A bracketed [v6]:port or a bare host. Only treat the last ':' as a port
     * separator when what follows is all digits (so v6 "::1" stays a host). */
    if (colon) {
        const char *p = colon + 1;
        bool all_digits = p[0] != '\0';
        for (const char *q = p; *q; q++)
            if (*q < '0' || *q > '9') { all_digits = false; break; }
        if (all_digits) {
            long v = strtol(p, NULL, 10);
            if (v < 1 || v > 65535)
                return false;
            *port = (int)v;
            size_t hlen = (size_t)(colon - target);
            if (hlen == 0 || hlen >= ip_cap)
                return false;
            memcpy(ip, target, hlen);
            ip[hlen] = '\0';
            return true;
        }
    }
    if (strlen(target) >= ip_cap)
        return false;
    snprintf(ip, ip_cap, "%s", target);
    return true;
}

void zcl_native_handle_network_node(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *target = json_get_str(json_get(request->input, "target"));
    char ip[CENSUS_IP_MAX];
    int port = 0;
    if (!parse_target(target, ip, sizeof(ip), &port)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_TARGET",
                               "normalize", false, false,
                               "target must be ip or ip:port (port 1..65535)",
                               "core.network.node");
        return;
    }

    census_reader *r = NULL;
    if (!census_open_or_degrade(reply, &r))
        return;

    struct census_node node;
    struct census_observation obs[CENSUS_MAX_OBSERVATIONS];
    struct census_edge edges[CENSUS_MAX_EDGES];
    int obs_n = 0, edge_n = 0;
    bool found = census_read_node(r, ip, port, &node,
                                  obs, CENSUS_MAX_OBSERVATIONS, &obs_n,
                                  edges, CENSUS_MAX_EDGES, &edge_n);

    char endpoint[CENSUS_ENDPOINT_MAX];
    snprintf(endpoint, sizeof(endpoint), "%s:%d", ip, port);
    (void)json_push_kv_bool(&reply->data, "populated", true);
    (void)json_push_kv_str(&reply->data, "endpoint", endpoint);
    (void)json_push_kv_bool(&reply->data, "found", found);
    if (!found) {
        (void)json_push_kv_str(&reply->data, "note",
                               "no census row for this endpoint");
        census_read_close(r);
        return;
    }

    struct json_value census;
    json_init(&census);
    json_set_object(&census);
    (void)json_push_kv_str(&census, "ip", node.ip);
    (void)json_push_kv_int(&census, "port", node.port);
    (void)json_push_kv_str(&census, "user_agent",
                           node.user_agent[0] ? node.user_agent : "(unknown)");
    if (node.ua_truncated)
        (void)json_push_kv_bool(&census, "user_agent_truncated", true);
    if (node.ua_overflow)
        (void)json_push_kv_bool(&census, "user_agent_overflow", true);
    (void)json_push_kv_int(&census, "protocol_version", node.protocol_version);
    (void)json_push_kv_int(&census, "services", node.services);
    (void)json_push_kv_int(&census, "reported_height", node.reported_height);
    (void)json_push_kv_bool(&census, "reachable", node.reachable);
    (void)json_push_kv_int(&census, "first_seen", node.first_seen);
    (void)json_push_kv_int(&census, "last_seen", node.last_seen);
    (void)json_push_kv_int(&census, "last_success", node.last_success);
    (void)json_push_kv_int(&census, "dial_success_count",
                           node.dial_success_count);
    (void)json_push_kv_int(&census, "dial_fail_count", node.dial_fail_count);
    (void)json_push_kv(&reply->data, "census", &census);
    json_free(&census);

    struct json_value observations;
    json_init(&observations);
    json_set_array(&observations);
    for (int i = 0; i < obs_n; i++) {
        struct json_value o;
        json_init(&o);
        json_set_object(&o);
        (void)json_push_kv_int(&o, "observed_unix", obs[i].observed_unix);
        (void)json_push_kv_int(&o, "reported_height", obs[i].reported_height);
        (void)json_push_kv_int(&o, "protocol_version", obs[i].protocol_version);
        (void)json_push_kv_int(&o, "services", obs[i].services);
        (void)json_push_back(&observations, &o);
        json_free(&o);
    }
    (void)json_push_kv_int(&reply->data, "observation_count", obs_n);
    (void)json_push_kv(&reply->data, "observations", &observations);
    json_free(&observations);

    struct json_value edgesj;
    json_init(&edgesj);
    json_set_array(&edgesj);
    for (int i = 0; i < edge_n; i++) {
        struct json_value e;
        json_init(&e);
        json_set_object(&e);
        (void)json_push_kv_str(&e, "observer", edges[i].observer);
        (void)json_push_kv_str(&e, "advertised", edges[i].advertised);
        (void)json_push_kv_int(&e, "times_seen", edges[i].times_seen);
        (void)json_push_kv_int(&e, "last_advertised", edges[i].last_advertised);
        (void)json_push_back(&edgesj, &e);
        json_free(&e);
    }
    (void)json_push_kv_int(&reply->data, "edge_count", edge_n);
    (void)json_push_kv(&reply->data, "edges", &edgesj);
    json_free(&edgesj);

    census_read_close(r);
}

/* ── core.network.versions ───────────────────────────────────────────── */

void zcl_native_handle_network_versions(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    census_reader *r = NULL;
    if (!census_open_or_degrade(reply, &r))
        return;

    struct census_version_bucket buckets[CENSUS_MAX_VERSION_BUCKETS];
    int n = census_read_versions(r, buckets, CENSUS_MAX_VERSION_BUCKETS);
    int64_t total = census_read_node_total(r);

    (void)json_push_kv_bool(&reply->data, "populated", true);
    (void)json_push_kv_int(&reply->data, "total_nodes", total);
    (void)json_push_kv_int(&reply->data, "distinct_user_agents", n);
    (void)json_push_kv_str(&reply->data, "sql_fallback",
        "SELECT user_agent, COUNT(*) c, MAX(last_reported_height) "
        "FROM node_census GROUP BY user_agent ORDER BY c DESC "
        "(peers_projection.db)");

    struct json_value dist;
    json_init(&dist);
    json_set_array(&dist);
    for (int i = 0; i < n; i++) {
        struct json_value b;
        json_init(&b);
        json_set_object(&b);
        (void)json_push_kv_str(&b, "user_agent", buckets[i].user_agent);
        if (buckets[i].ua_truncated)
            (void)json_push_kv_bool(&b, "user_agent_truncated", true);
        (void)json_push_kv_int(&b, "count", buckets[i].count);
        (void)json_push_kv_int(&b, "max_reported_height",
                               buckets[i].max_reported_height);
        /* Integer share in basis points (avoids a float; 10000 = 100%). */
        int64_t share_bp = total > 0 ? (buckets[i].count * 10000) / total : 0;
        (void)json_push_kv_int(&b, "share_bp", share_bp);
        (void)json_push_back(&dist, &b);
        json_free(&b);
    }
    (void)json_push_kv(&reply->data, "distribution", &dist);
    json_free(&dist);

    census_read_close(r);
}

/* ── core.network.graph ──────────────────────────────────────────────── */

void zcl_native_handle_network_graph(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    census_reader *r = NULL;
    if (!census_open_or_degrade(reply, &r))
        return;

    struct census_graph_stats g;
    (void)census_read_graph(r, &g);

    (void)json_push_kv_bool(&reply->data, "populated", true);
    (void)json_push_kv_int(&reply->data, "node_count", g.node_count);
    (void)json_push_kv_int(&reply->data, "edge_count", g.edge_count);
    (void)json_push_kv_int(&reply->data, "observation_count",
                           g.observation_count);
    (void)json_push_kv_int(&reply->data, "advertised_endpoints_in_census",
                           g.advertised_in_census);
    (void)json_push_kv_int(&reply->data, "sweeps_total", g.sweeps_total);
    (void)json_push_kv_int(&reply->data, "last_sweep_finished_unix",
                           g.last_sweep_finished_unix);
    if (g.last_sweep_finished_unix > 0) {
        int64_t age = platform_time_wall_unix() - g.last_sweep_finished_unix;
        (void)json_push_kv_int(&reply->data, "census_age_secs",
                               age > 0 ? age : 0);
    }
    (void)json_push_kv_str(&reply->data, "sql_fallback",
        "SELECT advertised_ip, advertised_port, SUM(times_seen) FROM "
        "topology_edges GROUP BY advertised_ip, advertised_port ORDER BY 3 "
        "DESC LIMIT 10 (topology.db)");

    struct json_value top;
    json_init(&top);
    json_set_array(&top);
    for (int i = 0; i < g.top_count; i++) {
        struct json_value t;
        json_init(&t);
        json_set_object(&t);
        (void)json_push_kv_str(&t, "advertised", g.top[i].advertised);
        (void)json_push_kv_int(&t, "times_seen", g.top[i].times_seen);
        (void)json_push_kv_int(&t, "distinct_observers",
                               g.top[i].distinct_observers);
        (void)json_push_back(&top, &t);
        json_free(&t);
    }
    (void)json_push_kv(&reply->data, "top_advertised", &top);
    json_free(&top);

    census_read_close(r);
}
