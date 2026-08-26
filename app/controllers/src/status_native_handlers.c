/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Transport-neutral operator read compositions.
 *
 * Native composition bodies for operator status, KPI, sync diagnostics,
 * blockers, timeline, diagnosis, and postmortem reads. Each returns a
 * heap-allocated JSON body or fills a contextual zcl_native_body_err. */

#include "controllers/status_native_handlers.h"
#include "controllers/native_handler_body.h"
#include "controllers/status_native_helpers.h"

#include "json/json.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "sim/postmortem.h"
#include "util/clientversion.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The legacy full-detail composition: TWELVE sequential node_rpc_call()s,
 * each re-entering the 4-worker RPC pool and racing the fold under a 10s
 * kill-timeout. Kept verbatim behind `status --full` for the cold SQLite
 * detail (nested sync/validation/health + the drill-down dumpstate bodies);
 * the default front door now takes ONE round-trip to the status_frontdoor
 * snapshot composition (see zcl_native_status_body below). */
static char *zcl_native_status_body_full(const struct json_value *args,
                                          struct zcl_native_body_err *err)
{
    (void)args;
    char *h  = node_rpc_call("getblockcount", NULL);
    char *p  = node_rpc_call("getpeerinfo", NULL);
    char *s  = node_rpc_call("syncstate", NULL);
    char *v  = node_rpc_call("validationstatus", NULL);
    char *hc = node_rpc_call("healthcheck", NULL);
    char *ci = node_rpc_call("getblockchaininfo", NULL);
    char *cac = node_rpc_call("dumpstate", "[\"chain_advance_coordinator\"]");
    char *rf = node_rpc_call("dumpstate", "[\"reducer_frontier\"]");
    char *tf = node_rpc_call("dumpstate", "[\"tip_finalize\"]");
    char *ce = node_rpc_call("dumpstate", "[\"condition_engine\"]");
    char *bl = node_rpc_call("dumpstate", "[\"blocker\"]");
    char *sv = node_rpc_call("dumpstate", "[\"sovereignty\"]");

    int pc = 0, inbound = 0, outbound = 0, zcl23_cnt = 0, magicbean_cnt = 0;
    int max_peer_height = 0;
    bool max_peer_height_known = false;
    bool peer_direction_known = false;
    struct json_value height_j, peers_j, chain_j, health_j;
    bool height_ok = status_parse_rpc_json(&height_j, h, JSON_INT) &&
                     height_j.val.i >= 0 && height_j.val.i <= INT_MAX;
    bool peers_ok = status_parse_rpc_json(&peers_j, p, JSON_ARR) &&
                    status_peer_array_is_valid(&peers_j);
    bool chain_ok = status_parse_rpc_json(&chain_j, ci, JSON_OBJ);
    const struct json_value *header_value =
        chain_ok ? json_get(&chain_j, "best_header_height") : NULL;
    bool header_ok = header_value && header_value->type == JSON_INT &&
                     header_value->val.i >= 0 &&
                     header_value->val.i <= INT_MAX;
    bool health_ok = status_parse_rpc_json(&health_j, hc, JSON_OBJ);
    if (peers_ok) {
        struct peer_survey ps;
        status_peer_survey(&peers_j, &ps);
        pc = ps.total;
        inbound = ps.inbound;
        outbound = ps.outbound;
        zcl23_cnt = ps.zcl23;
        magicbean_cnt = ps.magicbean;
        max_peer_height = ps.max_height;
        max_peer_height_known = ps.max_height_known;
        peer_direction_known = ps.direction_known;
    }

    int block_height = height_ok ? (int)height_j.val.i : 0;
    int header_height = header_ok ? (int)header_value->val.i : 0;
    const int sync_behind_threshold_blocks = 144;
    int header_gap = max_peer_height - header_height;
    if (header_gap < 0) header_gap = 0;
    bool header_gap_known = max_peer_height_known && header_ok;
    bool header_sync_behind =
        header_gap > sync_behind_threshold_blocks;
    /* Only locally validated headers define the synchronization target.
     * max_peer_height is an untrusted availability hint; one lying peer must
     * never manufacture an authoritative node gap. */
    int target_height = header_height;
    bool chain_evidence_known = height_ok && header_ok;
    bool chain_evidence_consistent =
        chain_evidence_known && block_height <= header_height;
    int sync_gap = chain_evidence_consistent
        ? target_height - block_height : 0;
    bool sync_gap_known = chain_evidence_consistent;
    bool sync_behind = sync_gap > sync_behind_threshold_blocks;

    const struct json_value *memory_value =
        health_ok ? json_get(&health_j, "memory_rss_mb") : NULL;
    const struct json_value *uptime_value =
        health_ok ? json_get(&health_j, "uptime_seconds") : NULL;
    bool memory_known = memory_value && memory_value->type == JSON_INT &&
                        memory_value->val.i >= 0;
    bool uptime_known = uptime_value && uptime_value->type == JSON_INT &&
                        uptime_value->val.i >= 0;
    const struct json_value *commit_value =
        health_ok ? json_get(&health_j, "build_commit") : NULL;
    const char *node_commit = json_get_str(commit_value);
    bool have_node_commit = node_commit && node_commit[0];

    struct json_value root;
    json_init(&root);
    json_set_object(&root);
    json_push_kv_str(&root, "execution_locus", "composite");
    status_push_int_if_known(&root, "height", height_ok, block_height);
    /* build_commit must describe the target node. The command client may run
     * a different binary, so keep its hash separate and leave the node field
     * null when target evidence is unavailable. */
    if (have_node_commit) {
        json_push_kv_str(&root, "build_commit", node_commit);
    } else {
        struct json_value unknown;
        json_init(&unknown);
        json_set_null(&unknown);
        json_push_kv(&root, "build_commit", &unknown);
        json_free(&unknown);
    }
    json_push_kv_str(&root, "build_commit_source",
                     have_node_commit ? "target_node.healthcheck"
                                      : "target_node.unavailable");
    json_push_kv_str(&root, "client_build_commit", zcl_build_commit());
    status_push_int_if_known(&root, "header_height", header_ok,
                             header_height);
    status_push_int_if_known(&root, "max_peer_height",
                             max_peer_height_known,
                             max_peer_height);
    json_push_kv_bool(&root, "max_peer_height_known",
                      max_peer_height_known);
    json_push_kv_str(&root, "max_peer_height_trust",
                     "untrusted_peer_advertisement");
    status_push_int_if_known(&root, "header_gap", header_gap_known,
                             header_gap);
    status_push_bool_if_known(&root, "header_sync_behind",
                              header_gap_known, header_sync_behind);
    status_push_int_if_known(&root, "target_height", header_ok,
                             target_height);
    json_push_kv_str(&root, "target_height_source",
                     header_ok ? "target_node.validated_header_tip"
                               : "unavailable");
    status_push_int_if_known(&root, "sync_gap", sync_gap_known, sync_gap);
    json_push_kv_int(&root, "sync_behind_threshold_blocks",
                     sync_behind_threshold_blocks);
    status_push_bool_if_known(&root, "sync_behind", sync_gap_known,
                              sync_behind);
    status_push_bool_if_known(&root, "chain_evidence_consistent",
                              chain_evidence_known,
                              chain_evidence_consistent);
    status_push_int_if_known(&root, "peers", peers_ok, pc);

    if (!height_ok)
        status_push_rpc_parse_error(&root, "height", h,
                                    "getblockcount returned invalid data");
    if (!peers_ok)
        status_push_rpc_parse_error(&root, "peers", p,
                                    "getpeerinfo returned invalid data");
    else if (!max_peer_height_known) {
        status_push_json_error(&root, "max_peer_height",
                               "no connected peer supplied a valid height claim",
                               NULL);
        status_push_json_error(&root, "header_gap",
                               "peer height claim unavailable", NULL);
    }
    if (!header_ok)
        status_push_rpc_parse_error(
            &root, "header_height", ci,
            "getblockchaininfo missing valid best_header_height");
    if (chain_evidence_known && !chain_evidence_consistent)
        status_push_json_error(
            &root, "chain_evidence",
            "served H* exceeds the locally validated header frontier",
            NULL);

    struct json_value conn;
    json_init(&conn);
    json_set_object(&conn);
    json_push_kv_bool(&conn, "known", peers_ok && peer_direction_known);
    json_push_kv_bool(&conn, "total_known", peers_ok);
    json_push_kv_bool(&conn, "direction_known", peer_direction_known);
    status_push_int_if_known(&conn, "total", peers_ok, pc);
    status_push_int_if_known(&conn, "inbound", peer_direction_known,
                             inbound);
    status_push_int_if_known(&conn, "outbound", peer_direction_known,
                             outbound);
    status_push_int_if_known(&conn, "zcl23", peers_ok, zcl23_cnt);
    status_push_int_if_known(&conn, "magicbean", peers_ok, magicbean_cnt);
    if (peers_ok && !peer_direction_known)
        status_push_json_error(&conn, "direction",
                               "peer entry missing boolean inbound field",
                               NULL);
    json_push_kv(&root, "connections", &conn);
    json_free(&conn);

    status_push_int_if_known(&root, "memory_rss_mb", memory_known,
                             memory_known ? memory_value->val.i : 0);
    status_push_int_if_known(&root, "uptime_secs", uptime_known,
                             uptime_known ? uptime_value->val.i : 0);
    if (!memory_known)
        status_push_json_error(&root, "memory_rss_mb",
                               "healthcheck missing valid nonnegative memory",
                               NULL);
    if (!uptime_known)
        status_push_json_error(&root, "uptime_secs",
                               "healthcheck missing valid nonnegative uptime",
                               NULL);
    status_push_rpc_json(&root, "sync", s, "syncstate");
    status_push_rpc_json(&root, "validation", v, "validationstatus");
    status_push_rpc_json(&root, "health", hc, "healthcheck");
    status_push_dumpstate_json(&root, "chain_advance",
                               "chain_advance_coordinator", cac);
    status_push_dumpstate_json(&root, "reducer_frontier",
                               "reducer_frontier", rf);
    status_push_dumpstate_json(&root, "tip_finalize", "tip_finalize", tf);
    status_push_dumpstate_json(&root, "condition_engine",
                               "condition_engine", ce);
    status_push_dumpstate_json(&root, "sovereignty", "sovereignty", sv);
    /* Also surface trust_mode as a flat top-level field — the operator
     * sovereignty posture (docs/work/shielded-history-importer.md
     * §5.5) is load-bearing enough to not require drilling into
     * `sovereignty.trust_mode`. Reads the just-pushed nested object rather
     * than re-parsing `sv`, so it can never disagree with it. */
    {
        const struct json_value *sov_state = json_get(&root, "sovereignty");
        const struct json_value *tm = sov_state
            ? json_get(sov_state, "trust_mode") : NULL;
        json_push_kv_str(&root, "trust_mode",
                         tm && json_get_str(tm) ? json_get_str(tm)
                                                 : "unknown");
    }
    bool blocker_fields_attached = status_push_blocker_summary(&root, bl);

    char *out = blocker_fields_attached
        ? zcl_json_value_to_body(&root, "status_body") : NULL;
    json_free(&root);
    json_free(&health_j);
    json_free(&chain_j);
    json_free(&peers_j);
    json_free(&height_j);
    free(h); free(p); free(s); free(v); free(hc); free(ci); free(cac);
    free(rf); free(tf); free(ce); free(bl); free(sv);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "malloc failed for %s", "status response");
        LOG_NULL("native.ops", "malloc failed for %s", "status response");
    }
    return out;
}

/* True when the caller asked for the legacy full document. Accepts a JSON
 * bool, a nonzero int, or the strings "true"/"1"/"yes" so it honors the flag
 * however the CLI/REST arg layer renders `--full`. */
static bool status_want_full(const struct json_value *args)
{
    const struct json_value *v = args ? json_get(args, "full") : NULL;
    if (!v)
        return false;
    if (v->type == JSON_BOOL)
        return v->val.b;
    if (v->type == JSON_INT)
        return v->val.i != 0;
    if (v->type == JSON_STR) {
        const char *s = json_get_str(v);
        return s && (strcmp(s, "true") == 0 || strcmp(s, "1") == 0 ||
                     strcmp(s, "yes") == 0);
    }
    return false;
}

/* Default front door: ONE dumpstate round-trip to the node-side
 * status_frontdoor composition, which reads only lock-free / trylock-guarded
 * in-process snapshot sources and labels every member's staleness (with a
 * degraded[] array). This never queues behind the reducer's write lock, so the
 * front door stays answerable under load — the whole point of Program O2. The
 * envelope's `state` object IS the operator body; it is returned verbatim. */
static char *status_frontdoor_body(struct zcl_native_body_err *err)
{
    char *raw = node_rpc_call("dumpstate", "[\"status_frontdoor\"]");
    struct json_value env;
    json_init(&env);
    if (!raw) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "status front door dumpstate returned null");
        LOG_NULL("native.ops", "status front door dumpstate returned null");
    }
    if (!json_read(&env, raw, strlen(raw))) {
        json_free(&env);
        free(raw);
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "status front door dumpstate returned invalid JSON");
        LOG_NULL("native.ops",
                 "status front door dumpstate returned invalid JSON");
    }
    free(raw);

    /* node_rpc_call deliberately returns transport/authentication failures as
     * valid JSON-RPC error envelopes. Preserve that precise diagnosis. A
     * hot-swap probe commonly reaches this path while the isolated dev node is
     * still starting; calling it a candidate `state` schema failure sends the
     * operator toward the wrong subsystem. */
    const struct json_value *rpc_error = json_get(&env, "error");
    if (rpc_error && rpc_error->type == JSON_OBJ) {
        const struct json_value *message_v = json_get(rpc_error, "message");
        const char *message = message_v && message_v->type == JSON_STR
            ? json_get_str(message_v) : "unnamed JSON-RPC error";
        char message_copy[181];
        snprintf(message_copy, sizeof(message_copy), "%.180s", message);
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "status front door dumpstate RPC failed: %s", message_copy);
        json_free(&env);
        LOG_NULL("native.ops", "status front door dumpstate RPC failed: %s",
                 message_copy);
    }

    const struct json_value *state = json_get(&env, "state");
    if (!state || state->type != JSON_OBJ) {
        json_free(&env);
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "status front door envelope missing state object");
        LOG_NULL("native.ops",
                 "status front door envelope missing state object");
    }

    struct json_value body;
    json_init(&body);
    json_copy(&body, state);
    json_push_kv_str(&body, "status_source", "status_frontdoor");
    json_push_kv_str(&body, "client_build_commit", zcl_build_commit());
    char *out = zcl_json_value_to_body(&body, "status_frontdoor_body");
    json_free(&body);
    json_free(&env);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "malloc failed for %s", "status front door response");
        LOG_NULL("native.ops", "malloc failed for %s",
                 "status front door response");
    }
    return out;
}

/* `z23 status` (core.status) front door. Default = the single
 * round-trip snapshot composition; `--full` = the legacy 12-call document. */
char *zcl_native_status_body(const struct json_value *args,
                             struct zcl_native_body_err *err)
{
    if (status_want_full(args))
        return zcl_native_status_body_full(args, err);
    return status_frontdoor_body(err);
}

/* core.status.brief lives in status_brief_native_handler.c (split out to
 * stay under the E1 800-line file-size ceiling). */

char *zcl_native_kpi_body(const struct json_value *args,
                          struct zcl_native_body_err *err)
{
    (void)args;
    char *height    = node_rpc_call("getblockcount",     NULL);
    char *peers     = node_rpc_call("getpeerinfo",       NULL);
    char *sync      = node_rpc_call("syncstate",         NULL);
    char *val       = node_rpc_call("validationstatus",  NULL);
    char *health    = node_rpc_call("healthcheck",       NULL);
    char *mempool   = node_rpc_call("getmempoolinfo",    NULL);
    char *wallet    = node_rpc_call("getwalletinfo",     NULL);
    char *chain     = node_rpc_call("getblockchaininfo", NULL);
    char *network   = node_rpc_call("getnetworkinfo",    NULL);

    struct json_value peers_j;
    bool peers_ok = status_parse_rpc_json(&peers_j, peers, JSON_ARR) &&
                    status_peer_array_is_valid(&peers_j);
    int64_t peer_count = peers_ok ? (int64_t)json_size(&peers_j) : 0;

    struct json_value root;
    json_init(&root);
    json_set_object(&root);
    status_push_rpc_json(&root, "height", height, "getblockcount");
    status_push_int_if_known(&root, "peer_count", peers_ok, peer_count);
    json_push_kv_bool(&root, "peer_count_known", peers_ok);
    status_push_rpc_json(&root, "peers", peers, "getpeerinfo");
    if (!peers_ok)
        status_push_rpc_parse_error(&root, "peer_count", peers,
                                    "getpeerinfo returned invalid peer array");
    status_push_rpc_json(&root, "sync", sync, "syncstate");
    status_push_rpc_json(&root, "validation", val, "validationstatus");
    status_push_rpc_json(&root, "health", health, "healthcheck");
    status_push_rpc_json(&root, "mempool", mempool, "getmempoolinfo");
    status_push_rpc_json(&root, "wallet", wallet, "getwalletinfo");
    status_push_rpc_json(&root, "chain", chain, "getblockchaininfo");
    status_push_rpc_json(&root, "network", network, "getnetworkinfo");

    free(height); free(peers); free(sync); free(val); free(health);
    free(mempool); free(wallet); free(chain); free(network);
    char *out = zcl_json_value_to_body(&root, "kpi_body");
    json_free(&root);
    json_free(&peers_j);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "malloc failed for %s", "KPI response");
        LOG_NULL("native.ops", "malloc failed for %s", "KPI response");
    }
    return out;
}

char *zcl_native_syncdiag_body(const struct json_value *args,
                               struct zcl_native_body_err *err)
{
    (void)args;
    char *diag = node_rpc_call("getsyncdiag", NULL);
    char *dl   = node_rpc_call("downloadstats", NULL);
    char *pi   = node_rpc_call("getpeerinfo", NULL);

    /* Peer-advertised height is only an availability hint. Keep it unknown
     * when the RPC/error shape is invalid; never turn an error into zero. */
    int peer_max_height = 0;
    bool peer_max_height_known = false;
    struct json_value pi_j;
    bool peers_ok = status_parse_rpc_json(&pi_j, pi, JSON_ARR) &&
                    status_peer_array_is_valid(&pi_j);
    if (peers_ok) {
        struct peer_survey ps;
        status_peer_survey(&pi_j, &ps);
        peer_max_height = ps.max_height;
        peer_max_height_known = ps.max_height_known;
    }

    struct json_value root;
    struct json_value diag_json;
    json_init(&root);
    json_set_object(&root);

    bool diag_ok = status_parse_rpc_json(&diag_json, diag, JSON_OBJ);
    if (diag_ok) {
        for (size_t i = 0; i < diag_json.num_children; i++) {
            const char *key = diag_json.keys[i];
            if (!key || strcmp(key, "peer_max_height") == 0 ||
                strcmp(key, "download") == 0)
                continue;
            json_push_kv(&root, key, &diag_json.children[i]);
        }
    } else {
        json_push_kv_str(&root, "error", "getsyncdiag RPC failed");
        status_push_rpc_parse_error(
            &root, "getsyncdiag", diag,
            diag ? "getsyncdiag RPC returned invalid data"
                 : "getsyncdiag RPC returned null");
    }

    status_push_int_if_known(&root, "peer_max_height",
                             peer_max_height_known,
                             peer_max_height);
    json_push_kv_bool(&root, "peer_max_height_known",
                      peer_max_height_known);
    json_push_kv_str(&root, "peer_max_height_trust",
                     "untrusted_peer_advertisement");
    if (!peers_ok)
        status_push_rpc_parse_error(&root, "peer_max_height", pi,
                                    "getpeerinfo returned invalid peer array");
    else if (!peer_max_height_known)
        status_push_json_error(&root, "peer_max_height",
                               "no connected peer supplied a valid height claim",
                               NULL);
    status_push_rpc_json(&root, "download", dl, "downloadstats");
    json_free(&diag_json);
    json_free(&pi_j);
    free(diag); free(dl); free(pi);
    char *out = zcl_json_value_to_body(&root, "syncdiag_body");
    json_free(&root);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "malloc failed for %s", "syncdiag response");
        LOG_NULL("native.ops", "malloc failed for %s", "syncdiag response");
    }
    return out;
}

char *zcl_native_blockers_body(const struct json_value *args,
                               struct zcl_native_body_err *err)
{
    (void)args;

    char *raw = node_rpc_call("dumpstate", "[\"blocker\"]");
    struct json_value summary;
    struct json_value dominant;
    struct json_value error;
    json_init(&summary);
    json_init(&dominant);
    json_init(&error);
    if (!status_build_blocker_summary(raw, true, &summary, &dominant,
                                      &error)) {
        const char *message = json_get_str(json_get(&error, "message"));
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "target blocker state unavailable: %s",
                 message ? message : "invalid dumpstate response");
        free(raw);
        json_free(&error);
        json_free(&dominant);
        json_free(&summary);
        LOG_NULL("native.ops", "%s", err->message);
    }

    char *out = zcl_json_value_to_body(&summary, "zcl_blockers_body");
    free(raw);
    json_free(&error);
    json_free(&dominant);
    json_free(&summary);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "malloc failed for %s", "blockers body");
        LOG_NULL("native.ops", "malloc failed for %s", "blockers body");
    }
    return out;
}

char *zcl_native_timeline_body(const struct json_value *args,
                               struct zcl_native_body_err *err)
{
    const char *category = json_get_str_or(args, "category", "all");
    int64_t count = json_get_int_or(args, "count", 50);

    struct json_value arr, obj;
    json_init(&arr);
    json_set_array(&arr);
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_str(&obj, "category",
                     (category && category[0]) ? category : "all");
    json_push_kv_int(&obj, "count", count);

    const char *str_filters[] = {
        "reducer_stage", "stage", "condition", "deploy", "lane",
    };
    const char *int_filters[] = {
        "scan_count", "scan", "since_us", "since_secs", "peer", "height",
    };
    for (size_t i = 0; i < sizeof(str_filters) / sizeof(str_filters[0]); i++) {
        const char *v = json_get_str(json_get(args, str_filters[i]));
        if (v && v[0])
            json_push_kv_str(&obj, str_filters[i], v);
    }
    for (size_t i = 0; i < sizeof(int_filters) / sizeof(int_filters[0]); i++) {
        const struct json_value *v = json_get(args, int_filters[i]);
        if (v && (v->type == JSON_INT || v->type == JSON_REAL))
            json_push_kv_int(&obj, int_filters[i], json_get_int(v));
    }
    json_push_back(&arr, &obj);

    size_t need = json_write(&arr, NULL, 0);
    char *params = zcl_malloc(need + 1u, "native timeline params");
    if (params)
        json_write(&arr, params, need + 1u);
    char *body = params ? node_rpc_call("timeline", params) : NULL;
    free(params);
    json_free(&obj);
    json_free(&arr);
    if (!body) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s returned null", "timeline");
        LOG_NULL("native.ops", "RPC %s returned null", "timeline");
    }
    return body;
}

char *zcl_native_agent_diagnose_body(const struct json_value *args,
                                     struct zcl_native_body_err *err)
{
    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, json_get_str_or(args, "mode", "brief"));
    char *params = rpc_arg_builder_to_json(&p);
    char *body = params ? node_rpc_call("agentdiagnose", params) : NULL;
    free(params);
    if (!body) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s returned null", "agentdiagnose");
        LOG_NULL("native.ops", "RPC %s returned null", "agentdiagnose");
    }
    return body;
}

char *zcl_native_postmortem_list_body(const struct json_value *args,
                                      struct zcl_native_body_err *err)
{
    const char *dir = json_get_str_or(args, "dir", NULL);
    char default_dir[512];
    if (!dir || !*dir) {
        if (zcl_postmortem_default_dir(default_dir, sizeof(default_dir)) != 0) {
            err->status = ZCL_NATIVE_BODY_INTERNAL;
            snprintf(err->message, sizeof(err->message),
                     "default postmortem dir path too long");
            LOG_NULL("native.ops", "default postmortem dir path too long");
        }
        dir = default_dir;
    }

    int64_t limit_i = json_get_int_or(args, "limit", 20);
    if (limit_i < 1) limit_i = 1;
    if (limit_i > 100) limit_i = 100;
    size_t limit = (size_t)limit_i;

    struct postmortem_summary *summaries =
        zcl_malloc(sizeof(*summaries) * limit, "native.postmortem.list");
    if (!summaries) {
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "malloc failed for %s", "postmortem summary list");
        LOG_NULL("native.ops", "malloc failed for %s (%zu bytes)",
                 "postmortem summary list", sizeof(*summaries) * limit);
    }

    size_t count = 0;
    int rc = postmortem_list(dir, summaries, limit, &count);
    if (rc != 0) {
        free(summaries);
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "postmortem list failed for %s (rc=%d)", dir, rc);
        LOG_NULL("native.ops", "postmortem list failed dir=%s rc=%d", dir, rc);
    }

    struct json_value root, arr;
    json_init(&root); json_set_object(&root);
    json_init(&arr);  json_set_array(&arr);
    size_t returned = count < limit ? count : limit;
    json_push_kv_str(&root, "dir", dir);
    json_push_kv_int(&root, "total", (int64_t)count);
    json_push_kv_int(&root, "returned", (int64_t)returned);
    json_push_kv_int(&root, "limit", (int64_t)limit);

    for (size_t i = 0; i < returned; i++) {
        struct json_value item;
        json_init(&item); json_set_object(&item);
        json_push_kv_str(&item, "path", summaries[i].path);
        json_push_kv_int(&item, "crash_unix", summaries[i].crash_unix);
        json_push_kv_int(&item, "crash_signal",
                         (int64_t)summaries[i].crash_signal);
        json_push_kv_int(&item, "capsule_bytes",
                         (int64_t)summaries[i].capsule_bytes);
        json_push_kv_int(&item, "tape_size_bytes",
                         (int64_t)summaries[i].tape_size_bytes);
        json_push_back(&arr, &item);
        json_free(&item);
    }
    json_push_kv(&root, "capsules", &arr);

    char *body = zcl_json_value_to_body(&root, "native.postmortem.list.body");
    json_free(&arr);
    json_free(&root);
    free(summaries);
    if (!body) {
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "malloc failed for %s", "postmortem list response");
        LOG_NULL("native.ops", "malloc failed for %s", "postmortem list response");
    }
    return body;
}

/* ── Tier-1 hot-swap: native.leaves generation entrypoint ──────
 * Dev-only (compiled only under -DZCL_HOTSWAP_GEN, a generation .so build;
 * expands to nothing in the node/release TU — see ZCL_HOTSWAP_EXPORT_LEAVES
 * in lib/hotswap/include/hotswap/hotswap.h). Stages every native command
 * leaf this controller owns; the resident bridge re-points them at THIS
 * TU's freshly-compiled bodies via zcl_native_bridge_run(). Probe is
 * core.status: zcl_native_status_body ignores `args` ((void)args) and
 * composes its body from unconditional RPC/dumpstate calls; per-field
 * failures are surfaced as nested "<field>_error" keys
 * (status_push_json_error in status_native_helpers.c), never a top-level
 * "error" key, so the empty-args self-test dispatch succeeds. The other
 * six leaves here also tolerate empty args (all optional/defaulted
 * params: category/count, mode, dir/limit, ...) but core.status is kept
 * as the native hot-swap probe. See
 * config/hotswap_eligible.def. */
#ifdef ZCL_HOTSWAP_GEN
#define ZCL_HOTSWAP_PROBE_LEAF "core.status"
#include "hotswap/hotswap.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

static void tramp_status(const struct zcl_command_request *request,
                         struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_status_body, reply);
}

static void tramp_status_brief(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_status_brief_body, reply);
}

static void tramp_syncdiag(const struct zcl_command_request *request,
                           struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_syncdiag_body, reply);
}

static void tramp_blockers(const struct zcl_command_request *request,
                           struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_blockers_body, reply);
}

static void tramp_timeline(const struct zcl_command_request *request,
                           struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_timeline_body, reply);
}

static void tramp_agent_diagnose(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_agent_diagnose_body, reply);
}

static void tramp_postmortem_list(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_postmortem_list_body, reply);
}

static const struct zcl_hotswap_leaf_replacement k_leaves[] = {
    { "core.status",          tramp_status },
    { "core.status.brief",    tramp_status_brief },
    { "core.sync.diagnose",   tramp_syncdiag },
    { "core.sync.blockers",   tramp_blockers },
    { "ops.timeline",         tramp_timeline },
    { "ops.diagnose",         tramp_agent_diagnose },
    { "ops.postmortem.list",  tramp_postmortem_list },
};

ZCL_HOTSWAP_EXPORT_LEAVES(k_leaves, sizeof(k_leaves) / sizeof(k_leaves[0]))
#endif /* ZCL_HOTSWAP_GEN */

/* REAL (activatable) single-handler module ABI export. Compiled only under a
 * `make hotswap-module-so HANDLER=core.status` build (-DZCL_HOTSWAP_MODULE_GEN);
 * expands to nothing in the node/release TU. The module re-points ONLY the
 * `core.status` leaf to this TU's freshly-compiled body via the same
 * zcl_native_bridge_run() seam the leaf provider uses. See hotswap_module.h and
 * hotswap_activate() (lib/hotswap). */
#ifdef ZCL_HOTSWAP_MODULE_GEN
#include "hotswap/hotswap_module.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

/* Deliberately retained in the module artifact.  The resident latency gate
 * rewrites only the fixed-width suffix, forcing twenty distinct native
 * compiles/artifacts while leaving command semantics unchanged. */
static const char zcl_hotswap_bench_marker[] __attribute__((used)) =
    "ZCL_HOTSWAP_BENCH:00000000";

static void module_tramp_status(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_status_body, reply);
}

static void module_tramp_status_brief(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_status_brief_body, reply);
}

static void module_tramp_syncdiag(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_syncdiag_body, reply);
}

static void module_tramp_blockers(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_blockers_body, reply);
}

static void module_tramp_timeline(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_timeline_body, reply);
}

static void module_tramp_agent_diagnose(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_agent_diagnose_body, reply);
}

static void module_tramp_postmortem_list(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_postmortem_list_body, reply);
}

/* Every leaf this controller owns, re-pointed in ONE all-or-nothing registry
 * batch. This mirrors k_leaves above: the generation loader has always staged
 * all seven, so the module ABI carrying only core.status was pilot batch-size
 * caution, not a safety boundary. Widening a leaf table widens BATCH SIZE, not
 * authority — every entry is still a READY read-only leaf of this same
 * allowlisted shape-leaf TU, and the registry batch commit re-checks
 * READY + EFFECT_READ + non-alias for each one independently. */
/* ops.debug.dash.kpi renders zcl_native_kpi_body, defined in THIS TU. It is
 * absent from the generation table above only because that table predates the
 * leaf; the module ABI carries it. */
static void module_tramp_kpi(const struct zcl_command_request *request,
                             struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_kpi_body, reply);
}

static const struct zcl_hotswap_leaf k_module_leaves[] = {
    { "core.status",         module_tramp_status },
    { "ops.debug.dash.kpi",  module_tramp_kpi },
    { "core.status.brief",   module_tramp_status_brief },
    { "core.sync.diagnose",  module_tramp_syncdiag },
    { "core.sync.blockers",  module_tramp_blockers },
    { "ops.timeline",        module_tramp_timeline },
    { "ops.diagnose",        module_tramp_agent_diagnose },
    { "ops.postmortem.list", module_tramp_postmortem_list },
};

/* The module's own health hook — runs before the loader publishes it. Kept
 * node-independent (no RPC): a structural OK. A behavioral precommit probe is a
 * separate concern (see docs/work/HOTSWAP.md "Known v1 TODOs"). */
static bool module_selftest_status(char *err, size_t cap)
{
    (void)err;
    (void)cap;
    return true;
}

ZCL_HOTSWAP_MODULE_LEAVES(k_module_leaves, module_selftest_status)
#endif /* ZCL_HOTSWAP_MODULE_GEN */
