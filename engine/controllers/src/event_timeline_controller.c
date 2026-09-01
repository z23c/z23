/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Semantic event timeline RPC for AI/operator diagnostics. */

#include "controllers/event_timeline_controller.h"
#include "controllers/agent_controller.h"
#include "controllers/event_timeline_filter_controller.h"
#include "controllers/strong_params.h"

#include "event/event.h"
#include "json/json.h"
#include "util/clientversion.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct timeline_category {
    const char *name;
    const char *prefix;
    const char *description;
};

static const struct timeline_category k_timeline_categories[] = {
    { "all",        "",             "all retained structured events" },
    { "tcp",        "tcp.",         "TCP connection lifecycle" },
    { "peer",       "peer.",        "peer handshakes, state, bans, and floor breaches" },
    { "message",    "msg.",         "P2P message send/receive/deserialization events" },
    { "sync",       "sync.",        "sync FSM, headers, block requests, and stale-tip events" },
    { "snapshot",   "snapsync.",    "snapshot receive/verify progress" },
    { "chain",      "chain.",       "chain tip and chain-advance decisions" },
    { "validation", "val.",         "block validation and reducer validation events" },
    { "condition",  "condition.",   "self-heal condition lifecycle and operator-needed pages" },
    { "oracle",     "oracle.",      "zclassicd oracle agreement/disagreement and halt signals" },
    { "mirror",     "mirror.",      "mirror consensus and lag-SLO signals" },
    { "boot",       "boot.",        "boot, block-index, and startup recovery events" },
    { "db",         "db.",          "database transaction and maintenance events" },
    { "wallet",     "wallet.",      "wallet key, transaction, UTXO, and backup events" },
    { "mempool",    "mempool.",     "mempool eviction and expiry events" },
    { "disk",       "disk.",        "disk pressure monitor events" },
    { "net",        "net.",         "network backpressure telemetry" },
};

static const struct timeline_category *timeline_category_find(const char *name)
{
    const char *want = (name && name[0]) ? name : "all";
    for (size_t i = 0; i < sizeof(k_timeline_categories) /
                            sizeof(k_timeline_categories[0]); i++) {
        if (strcmp(k_timeline_categories[i].name, want) == 0)
            return &k_timeline_categories[i];
    }
    return NULL;
}

static void timeline_push_categories(struct json_value *out)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < sizeof(k_timeline_categories) /
                            sizeof(k_timeline_categories[0]); i++) {
        struct json_value obj;
        json_init(&obj);
        json_set_object(&obj);
        json_push_kv_str(&obj, "name", k_timeline_categories[i].name);
        json_push_kv_str(&obj, "type_prefix", k_timeline_categories[i].prefix);
        json_push_kv_str(&obj, "description",
                         k_timeline_categories[i].description);
        json_push_back(&arr, &obj);
        json_free(&obj);
    }
    json_push_kv(out, "available_categories", &arr);
    json_free(&arr);
}

static void timeline_push_str(struct json_value *arr, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s ? s : "");
    json_push_back(arr, &v);
    json_free(&v);
}

static void timeline_push_log_references(struct json_value *out,
                                         const struct timeline_category *cat,
                                         const struct timeline_filter *f)
{
    struct json_value refs;
    char pattern[192];
    const char *cat_name = cat ? cat->name : "all";

    json_init(&refs);
    json_set_array(&refs);
    if (f && f->condition[0])
        snprintf(pattern, sizeof(pattern), "condition|%s|operator_needed",
                 f->condition);
    else if (f && f->reducer_stage[0])
        snprintf(pattern, sizeof(pattern), "%s|reducer|stage|blocker",
                 f->reducer_stage);
    else if (f && f->deploy[0])
        snprintf(pattern, sizeof(pattern), "deploy|%s|build_commit",
                 f->deploy);
    else if (strcmp(cat_name, "sync") == 0)
        snprintf(pattern, sizeof(pattern), "sync|stale|lag|blocker");
    else if (strcmp(cat_name, "peer") == 0)
        snprintf(pattern, sizeof(pattern), "peer|handshake|disconnect");
    else
        snprintf(pattern, sizeof(pattern),
                 "fail|reject|stale|breach|panic|halt|timeout|corrupt");

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "z23 getnodelog '%s'", pattern);
    timeline_push_str(&refs, cmd);
    timeline_push_str(&refs,
        "z23 eventlog <scan_count> for the raw retained ring view");
    timeline_push_str(&refs,
        "event seq cursors are in events[].seq and head_seq");
    json_push_kv(out, "log_references", &refs);
    json_free(&refs);
}

static bool timeline_type_is_problem(const char *type)
{
    if (!type)
        return false;
    return strstr(type, "fail") ||
           strstr(type, "reject") ||
           strstr(type, "stale") ||
           strstr(type, "breach") ||
           strstr(type, "panic") ||
           strstr(type, "halt") ||
           strstr(type, "timeout") ||
           strstr(type, "corrupt") ||
           strstr(type, "critical") ||
           strstr(type, "low") ||
           strstr(type, "drift") ||
           strstr(type, "misbehave") ||
           strstr(type, "banned") ||
           strstr(type, "disconnect") ||
           strstr(type, "backpressure") ||
           strstr(type, "operator_needed");
}

static void timeline_push_type_counts(struct json_value *out,
                                      const struct json_value *events,
                                      int64_t *problem_count,
                                      char *dominant_type,
                                      size_t dominant_type_len,
                                      int64_t *dominant_count)
{
    struct {
        char type[64];
        int64_t count;
        bool problem;
    } counts[64] = {0};
    size_t used = 0;
    int64_t overflow = 0;

    if (problem_count)
        *problem_count = 0;
    if (dominant_type && dominant_type_len > 0)
        dominant_type[0] = '\0';
    if (dominant_count)
        *dominant_count = 0;

    size_t n = events && events->type == JSON_ARR ? json_size(events) : 0;
    for (size_t i = 0; i < n; i++) {
        const struct json_value *ev = json_at(events, i);
        const char *type = json_get_str(json_get(ev, "type"));
        bool problem = timeline_type_is_problem(type);
        if (problem && problem_count)
            (*problem_count)++;

        size_t slot = used;
        for (size_t j = 0; j < used; j++) {
            if (strcmp(counts[j].type, type) == 0) {
                slot = j;
                break;
            }
        }
        if (slot == used) {
            if (used >= sizeof(counts) / sizeof(counts[0])) {
                overflow++;
                continue;
            }
            snprintf(counts[slot].type, sizeof(counts[slot].type), "%s", type);
            counts[slot].problem = problem;
            used++;
        }
        counts[slot].count++;
        if (dominant_count && counts[slot].count > *dominant_count) {
            *dominant_count = counts[slot].count;
            if (dominant_type && dominant_type_len > 0)
                snprintf(dominant_type, dominant_type_len, "%s",
                         counts[slot].type);
        }
    }

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < used; i++) {
        struct json_value obj;
        json_init(&obj);
        json_set_object(&obj);
        json_push_kv_str(&obj, "type", counts[i].type);
        json_push_kv_int(&obj, "count", counts[i].count);
        json_push_kv_bool(&obj, "problem", counts[i].problem);
        json_push_back(&arr, &obj);
        json_free(&obj);
    }
    json_push_kv(out, "type_counts", &arr);
    json_free(&arr);
    json_push_kv_int(out, "type_count_overflow", overflow);
}

static void timeline_push_peer_counts(struct json_value *out,
                                      const struct json_value *events,
                                      int64_t *unique_peers)
{
    struct {
        int64_t peer;
        int64_t count;
    } peers[64] = {0};
    size_t used = 0;
    int64_t overflow = 0;

    if (unique_peers)
        *unique_peers = 0;

    size_t n = events && events->type == JSON_ARR ? json_size(events) : 0;
    for (size_t i = 0; i < n; i++) {
        const struct json_value *ev = json_at(events, i);
        int64_t peer = json_get_int(json_get(ev, "peer"));
        size_t slot = used;
        for (size_t j = 0; j < used; j++) {
            if (peers[j].peer == peer) {
                slot = j;
                break;
            }
        }
        if (slot == used) {
            if (used >= sizeof(peers) / sizeof(peers[0])) {
                overflow++;
                continue;
            }
            peers[slot].peer = peer;
            used++;
        }
        peers[slot].count++;
    }
    if (unique_peers)
        *unique_peers = (int64_t)used;

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < used; i++) {
        struct json_value obj;
        json_init(&obj);
        json_set_object(&obj);
        json_push_kv_int(&obj, "peer", peers[i].peer);
        json_push_kv_int(&obj, "count", peers[i].count);
        json_push_back(&arr, &obj);
        json_free(&obj);
    }
    json_push_kv(out, "peer_counts", &arr);
    json_free(&arr);
    json_push_kv_int(out, "peer_count_overflow", overflow);
}

static const char *timeline_category_next_action(const char *category,
                                                 int64_t problem_count)
{
    if (problem_count > 0)
        return "inspect_problem_drilldowns_before_raw_logs";
    if (category && strcmp(category, "sync") == 0)
        return "compare_sync_timeline_to_reducer_frontier_and_supervisor";
    if (category && strcmp(category, "peer") == 0)
        return "inspect_peer_lifecycle_if_connections_churn";
    if (category && strcmp(category, "all") == 0)
        return "switch_to_a_specific_category_before_deep_diagnosis";
    return "continue_with_category_drilldowns_if_the_timeline_is_suspicious";
}

static void timeline_push_drilldowns(struct json_value *out,
                                     const struct timeline_category *cat,
                                     int64_t problem_count)
{
    struct json_value arr;
    const char *name = cat ? cat->name : "all";

    json_init(&arr);
    json_set_array(&arr);
    if (strcmp(name, "sync") == 0) {
        timeline_push_str(&arr, "z23 dumpstate reducer_frontier");
        timeline_push_str(&arr, "z23 dumpstate chain_advance_coordinator");
        timeline_push_str(&arr, "z23 dumpstate supervisor sync.watchdog");
        timeline_push_str(&arr, "z23 getnodelog 'sync|stale|lag|blocker'");
    } else if (strcmp(name, "peer") == 0) {
        timeline_push_str(&arr, "z23 dumpstate peer_lifecycle");
        timeline_push_str(&arr, "z23 dumpstate peers_projection");
        timeline_push_str(&arr, "z23 getnodelog 'peer|handshake|disconnect'");
    } else if (strcmp(name, "chain") == 0) {
        timeline_push_str(&arr, "z23 dumpstate chain_evidence");
        timeline_push_str(&arr, "z23 dumpstate chain_advance_coordinator");
        timeline_push_str(&arr, "z23 dumpstate reducer_frontier");
    } else if (strcmp(name, "validation") == 0) {
        timeline_push_str(&arr, "z23 dumpstate validation_pack");
        timeline_push_str(&arr, "z23 dumpstate reducer_frontier");
        timeline_push_str(&arr, "z23 dumpstate block_index");
    } else if (strcmp(name, "condition") == 0) {
        timeline_push_str(&arr, "z23 dumpstate condition_engine");
        timeline_push_str(&arr, "z23 dumpstate blocker");
        timeline_push_str(&arr, "z23 dumpstate supervisor");
    } else if (strcmp(name, "oracle") == 0 || strcmp(name, "mirror") == 0) {
        timeline_push_str(&arr, "z23 dumpstate oracle");
        timeline_push_str(&arr, "z23 dumpstate legacy_mirror");
        timeline_push_str(&arr, "z23 dumpstate quorum_oracle");
    } else if (strcmp(name, "boot") == 0) {
        timeline_push_str(&arr, "z23 dumpstate boot");
        timeline_push_str(&arr, "z23 dumpstate service_state");
        timeline_push_str(&arr, "z23 dumpstate block_index");
    } else if (strcmp(name, "db") == 0) {
        timeline_push_str(&arr, "z23 dumpstate db_maintenance");
        timeline_push_str(&arr, "z23 dumpstate progress");
        timeline_push_str(&arr, "z23 dumpstate disk_monitor");
    } else if (strcmp(name, "wallet") == 0) {
        timeline_push_str(&arr, "z23 dumpstate wallet_projection");
    } else if (strcmp(name, "disk") == 0) {
        timeline_push_str(&arr, "z23 dumpstate disk_monitor");
    } else {
        agent_push_contract_native_command_json(&arr, "statecatalog");
        timeline_push_str(&arr, "z23 timeline sync 50");
        timeline_push_str(&arr, "z23 timeline peer 50");
    }
    if (problem_count > 0)
        timeline_push_str(&arr, "z23 getnodelog 'fail|reject|stale|breach|panic|halt|timeout|corrupt'");
    json_push_kv(out, "recommended_drilldowns", &arr);
    json_free(&arr);
}

static void timeline_push_semantic_summary(struct json_value *out,
                                           const struct json_value *events,
                                           const struct timeline_category *cat)
{
    struct json_value summary;
    int64_t event_count = events && events->type == JSON_ARR
        ? (int64_t)json_size(events) : 0;
    int64_t first_seq = -1, last_seq = -1, first_ts = 0, last_ts = 0;
    int64_t problem_count = 0, unique_peers = 0, dominant_count = 0;
    char dominant_type[64] = "";

    if (event_count > 0) {
        const struct json_value *first = json_at(events, 0);
        const struct json_value *last = json_at(events,
                                               (size_t)event_count - 1u);
        first_seq = json_get_int(json_get(first, "seq"));
        last_seq = json_get_int(json_get(last, "seq"));
        first_ts = json_get_int(json_get(first, "ts"));
        last_ts = json_get_int(json_get(last, "ts"));
    }

    timeline_push_type_counts(out, events, &problem_count, dominant_type,
                              sizeof(dominant_type), &dominant_count);
    timeline_push_peer_counts(out, events, &unique_peers);

    json_init(&summary);
    json_set_object(&summary);
    json_push_kv_int(&summary, "event_count", event_count);
    json_push_kv_int(&summary, "first_seq", first_seq);
    json_push_kv_int(&summary, "last_seq", last_seq);
    json_push_kv_int(&summary, "first_ts", first_ts);
    json_push_kv_int(&summary, "last_ts", last_ts);
    json_push_kv_int(&summary, "problem_event_count", problem_count);
    json_push_kv_int(&summary, "unique_peer_count", unique_peers);
    json_push_kv_str(&summary, "dominant_type", dominant_type);
    json_push_kv_int(&summary, "dominant_type_count", dominant_count);
    json_push_kv_bool(&summary, "has_problem_events", problem_count > 0);
    json_push_kv_str(&summary, "safe_next_action",
                     timeline_category_next_action(cat ? cat->name : "all",
                                                   problem_count));
    json_push_kv(out, "semantic_summary", &summary);
    json_free(&summary);
    json_push_kv_str(out, "safe_next_action",
                     timeline_category_next_action(cat ? cat->name : "all",
                                                   problem_count));
    timeline_push_drilldowns(out, cat, problem_count);
}

bool rpc_timeline(const struct json_value *params, bool help,
                  struct json_value *result)
{
    RPC_HELP(help, result,
        "timeline ( category count ) or timeline {category,count,filters...}\n"
        "\nReturn a versioned semantic timeline over the in-memory structured\n"
        "event ring. Categories are mapped to event type prefixes server-side\n"
        "so agents do not need jq/string filters. Object form supports\n"
        "bounded server-side filters: since_secs/since_us, peer, height,\n"
        "reducer_stage/stage, condition, deploy, and lane.\n"
        "\nArguments:\n"
        "1. category  (string, optional, default=all) all|peer|sync|chain|...\n"
        "2. count     (numeric, optional, default=50, max=1000)\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.timeline.v2\", \"events\":[...] }\n");

    struct json_value embedded_params;
    json_init(&embedded_params);
    const struct json_value *effective_params = params;
    bool has_embedded_params =
        timeline_parse_embedded_object_arg(params, &embedded_params);
    if (has_embedded_params)
        effective_params = &embedded_params;

    const char *category_name = timeline_param_category(effective_params);
    struct timeline_filter filter =
        timeline_filter_from_params(effective_params);
    const struct timeline_category *cat =
        timeline_category_find(category_name);

    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.timeline.v2");
    json_push_kv_str(result, "api_version", "v1");
    json_push_kv_str(result, "build_commit", zcl_build_commit());
    json_push_kv_str(result, "source", "event_ring");
    json_push_kv_int(result, "head_seq",
                     (int64_t)event_log_head_sequence());
    json_push_kv_int(result, "retention_events", EVENT_LOG_SIZE);
    json_push_kv_str(result, "cursor_field", "events[].seq");
    json_push_kv_str(result, "native_command",
                     "z23 timeline <category> <count> or timeline '{\"category\":\"sync\",\"since_secs\":3600}'");
    json_push_kv_str(result, "filter_model",
                     "bounded_server_side_scan_then_filter");

    if (!cat) {
        json_push_kv_str(result, "status", "error");
        json_push_kv_str(result, "error", "unknown_timeline_category");
        json_push_kv_str(result, "category_requested", category_name);
        timeline_push_categories(result);
        if (has_embedded_params)
            json_free(&embedded_params);
        return true;
    }

    size_t buf_size = (size_t)filter.scan_count * 512u + 2048u;
    if (buf_size > 32u * 1024u * 1024u)
        buf_size = 32u * 1024u * 1024u;
    char *buf = zcl_malloc(buf_size, "timeline events json buf");
    if (!buf) {
        json_push_kv_str(result, "status", "error");
        json_push_kv_str(result, "error", "out_of_memory");
        if (has_embedded_params)
            json_free(&embedded_params);
        return false;
    }

    size_t w = event_dump_json_filtered(buf, buf_size,
                                        (size_t)filter.scan_count,
                                        cat->prefix);
    struct json_value scanned, events;
    json_init(&scanned);
    json_init(&events);
    bool parsed = w > 0 && w < buf_size && json_read(&scanned, buf, w);
    free(buf);
    if (!parsed || scanned.type != JSON_ARR) {
        json_free(&scanned);
        json_push_kv_str(result, "status", "error");
        json_push_kv_str(result, "error", "event_timeline_parse_failed");
        json_push_kv_int(result, "scan_count", filter.scan_count);
        if (has_embedded_params)
            json_free(&embedded_params);
        return false;
    }

    int64_t matched_before_limit = 0;
    timeline_filter_events(&scanned, &filter, &events,
                           &matched_before_limit);

    json_push_kv_str(result, "status", "ok");
    json_push_kv_str(result, "category", cat->name);
    json_push_kv_str(result, "type_prefix", cat->prefix);
    json_push_kv_str(result, "description", cat->description);
    json_push_kv_int(result, "count_requested", filter.count);
    json_push_kv_int(result, "scan_count", filter.scan_count);
    json_push_kv_int(result, "count_scanned", (int64_t)json_size(&scanned));
    json_push_kv_int(result, "matched_before_limit", matched_before_limit);
    json_push_kv_int(result, "count_returned", (int64_t)json_size(&events));
    timeline_push_filters(result, &filter);
    timeline_push_semantic_summary(result, &events, cat);
    timeline_push_log_references(result, cat, &filter);
    timeline_push_categories(result);
    json_push_kv(result, "events", &events);
    json_free(&events);
    json_free(&scanned);
    if (has_embedded_params)
        json_free(&embedded_params);
    return true;
}
