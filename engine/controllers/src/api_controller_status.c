/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Compact public REST status endpoint for dashboards, website checks, and
 * native clients that do not need the full diagnostic tree. */

#include "controllers/agent_controller.h"
#include "controllers/agent_height_contract.h"
#include "controllers/agent_restart_watchdog.h"
#include "controllers/agent_resources.h"
#include "controllers/agent_security_posture.h"
#include "controllers/api_controller.h"
#include "controllers/download_stats_json.h"
#include "controllers/node_binary_identity_json.h"
#include "controllers/operator_needed_policy.h"
#include "api_controller_internal.h"
#include "config/runtime.h"
#include "event_agent_summary.h"
#include "event_agent_readiness.h"
#include "json/json.h"
#include "jobs/reducer_frontier.h"
#include "services/anchor_selfmint.h"
#include "services/node_health_service.h"
#include "sync/sync_state.h"
#include "util/blocker.h"
#include "util/clientversion.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct milestone_criterion {
    int id;
    const char *key;
    const char *title;
    const char *status;
    bool strict_pass;
    int units;
    const char *next;
    const char *proof_scope;
    const char *proof_command;
    const char *ci_gate;
    const char *primary_blocker;
    bool local_dependency_required;
    bool ci_regression_protected;
};

static const struct milestone_criterion k_mvp_criteria[] = {
    { 1, "single_binary_install",
      "Single-binary install on clean Ubuntu/Debian",
      "pass", true, 2, "keep ci-install-linger green",
      "full_operator", "make ci-install-linger", "make ci-symbol-floor",
      "none", true, true },
    { 2, "tor_onion_bootstrap",
      "Tor onion bootstrap in <60s",
      "pass", true, 2, "keep mvp-onion-local green",
      "full_operator", "make mvp-onion-local", "make mvp-onion-slice",
      "none", true, true },
    { 3, "cold_start_sync",
      "Cold-start sync to tip in <10 min",
      "partial", false, 1, "run full bundle-to-tip cold-start proof",
      "local_operator_pending", "make mvp-coldstart-to-tip-local",
      "make ci-mvp-gates",
      "full_zclassic23_to_zclassic23_sync_to_tip_not_run_passed",
      true, true },
    { 4, "shielded_receive",
      "Receive shielded payment end-to-end",
      "pass", true, 2, "keep shielded payment proof green",
      "full_operator", "make test-shielded-payment",
      "make mvp-shielded-receive-persist", "none", true, true },
    { 5, "store_flow",
      "List and sell file via store",
      "partial", false, 1, "prove live buyer over onion/file transfer",
      "hermetic_slice", "make ci-mvp-gates", "make ci-mvp-gates",
      "full_live_buyer_onion_file_transfer_not_proven", false, true },
    { 6, "seven_day_soak",
      "7-day soak with zero operator intervention",
      "partial", false, 1, "complete clean 168h soak window",
      "live_window", "make soak-evidence-report",
      "make soak-evidence-selftest", "clean_168h_soak_window_pending",
      true, true },
    { 7, "kill9_recovery",
      "Recover from kill -9 in <2 min",
      "pass", true, 2, "keep crash bootstrap and peer-tip proofs green",
      "full_operator",
      "make test-crash-bootstrap && make test-two-node-peer-tip",
      "make ci-mvp-gates", "none", true, true },
    { 8, "consensus_parity",
      "Consensus parity with zclassicd",
      "partial", false, 1, "prove exact parity over the soak window",
      "live_window", "make mvp-parity-slice", "make mvp-parity-slice",
      "exact_reference_or_zero_mismatch_soak_window_pending", true, true },
};

static void api_ascii_bar(char out[13], int done, int total)
{
    int filled = 0;
    if (total > 0)
        filled = (done * 10 + total / 2) / total;
    if (filled < 0)
        filled = 0;
    if (filled > 10)
        filled = 10;

    out[0] = '[';
    for (int i = 0; i < 10; i++)
        out[i + 1] = i < filled ? '#' : '-';
    out[11] = ']';
    out[12] = '\0';
}

static void api_push_progress_bar(struct json_value *bars,
                                  struct json_value *ascii,
                                  const char *name,
                                  int done,
                                  int total,
                                  const char *summary)
{
    char bar[13];
    char line[192];
    int percent = total > 0 ? (done * 100) / total : 0;
    api_ascii_bar(bar, done, total);
    snprintf(line, sizeof(line), "%s %s %d/%d %s",
             name, bar, done, total, summary ? summary : "");

    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_str(&obj, "bar", bar);
    json_push_kv_str(&obj, "line", line);
    json_push_kv_int(&obj, "done", done);
    json_push_kv_int(&obj, "total", total);
    json_push_kv_int(&obj, "percent", percent);
    json_push_kv_str(&obj, "summary", summary ? summary : "");
    json_push_kv(bars, name, &obj);
    json_push_kv_str(ascii, name, line);
    json_free(&obj);
}

static bool api_milestone_agent_snapshot(struct json_value *agent)
{
    struct json_value params = {0};
    json_set_array(&params);
    bool ok = agent && rpc_agent_summary(&params, false, agent) &&
              agent->type == JSON_OBJ;
    json_free(&params);
    return ok;
}

static int api_json_int_field(const struct json_value *obj, const char *key,
                              int fallback)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    if (!v || (v->type != JSON_INT && v->type != JSON_REAL))
        return fallback;
    int64_t n = json_get_int(v);
    if (n < INT32_MIN)
        return INT32_MIN;
    if (n > INT32_MAX)
        return INT32_MAX;
    return (int)n;
}

static bool api_json_has_int_field(const struct json_value *obj,
                                   const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && (v->type == JSON_INT || v->type == JSON_REAL);
}

static int api_json_nested_int_field(const struct json_value *obj,
                                     const char *parent,
                                     const char *key, int fallback)
{
    const struct json_value *p = obj ? json_get(obj, parent) : NULL;
    return api_json_int_field(p, key, fallback);
}

static bool api_json_bool_field(const struct json_value *obj, const char *key,
                                bool fallback)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    if (!v || v->type != JSON_BOOL)
        return fallback;
    return json_get_bool(v);
}

static bool api_json_has_bool_field(const struct json_value *obj,
                                    const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && v->type == JSON_BOOL;
}

static bool api_json_nested_bool_field(const struct json_value *obj,
                                       const char *parent,
                                       const char *key, bool fallback)
{
    const struct json_value *p = obj ? json_get(obj, parent) : NULL;
    return api_json_bool_field(p, key, fallback);
}

static const char *api_json_str_field(const struct json_value *obj,
                                      const char *key, const char *fallback)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    if (!v || v->type != JSON_STR || !json_get_str(v)[0])
        return fallback ? fallback : "";
    return json_get_str(v);
}

static bool api_json_has_str_field(const struct json_value *obj,
                                   const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && v->type == JSON_STR && json_get_str(v)[0];
}

static void api_milestone_require_field(bool *complete, bool present)
{
    if (complete && !present)
        *complete = false;
}

static void api_push_mvp_proof_item(struct json_value *arr,
                                    const struct milestone_criterion *c)
{
    if (!arr || !c)
        return;

    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    json_push_kv_int(&item, "criterion", c->id);
    json_push_kv_str(&item, "key", c->key);
    json_push_kv_str(&item, "status", c->status);
    json_push_kv_bool(&item, "strict_pass", c->strict_pass);
    json_push_kv_str(&item, "proof_state",
                     c->strict_pass ? "accepted" : "pending");
    json_push_kv_str(&item, "proof_scope", c->proof_scope);
    json_push_kv_str(&item, "proof_command", c->proof_command);
    json_push_kv_str(&item, "ci_gate", c->ci_gate);
    json_push_kv_bool(&item, "ci_regression_protected",
                      c->ci_regression_protected);
    json_push_kv_bool(&item, "local_dependency_required",
                      c->local_dependency_required);
    json_push_kv_str(&item, "primary_blocker", c->primary_blocker);
    json_push_kv_str(&item, "next_action", c->next);
    json_push_back(arr, &item);
    json_free(&item);
}

static void api_push_mvp_operator_proofs(
    struct json_value *result,
    const struct milestone_criterion *criteria,
    size_t criteria_count,
    int strict_pass,
    int partial_units,
    int max_units)
{
    if (!result || !criteria)
        return;

    int pending = 0;
    int live_window = 0;
    int ci_protected = 0;
    int local_dependencies = 0;
    for (size_t i = 0; i < criteria_count; i++) {
        if (!criteria[i].strict_pass)
            pending++;
        if (criteria[i].proof_scope &&
            strcmp(criteria[i].proof_scope, "live_window") == 0)
            live_window++;
        if (criteria[i].ci_regression_protected)
            ci_protected++;
        if (criteria[i].local_dependency_required)
            local_dependencies++;
    }

    struct json_value proofs;
    struct json_value items;
    json_init(&proofs);
    json_init(&items);
    json_set_object(&proofs);
    json_set_array(&items);

    json_push_kv_str(&proofs, "schema", "zcl.mvp_operator_proofs.v1");
    json_push_kv_str(&proofs, "api_version", ZCL_REST_API_VERSION);
    json_push_kv_str(&proofs, "source", "docs/MVP.md");
    json_push_kv_str(&proofs, "native_command", "z23 milestone");
    json_push_kv_str(&proofs, "alias_command", "z23 mvpstatus");
    json_push_kv_int(&proofs, "accepted_count", strict_pass);
    json_push_kv_int(&proofs, "target_count", (int64_t)criteria_count);
    json_push_kv_int(&proofs, "pending_count", pending);
    json_push_kv_int(&proofs, "live_window_count", live_window);
    json_push_kv_int(&proofs, "ci_protected_count", ci_protected);
    json_push_kv_int(&proofs, "local_dependency_count",
                     local_dependencies);
    json_push_kv_int(&proofs, "partial_progress_units", partial_units);
    json_push_kv_int(&proofs, "partial_progress_units_total", max_units);
    json_push_kv_str(&proofs, "rule",
                     "MRS increments only when a full operator proof run-passes; slice and judge gates are regression floors.");
    json_push_kv_str(&proofs, "next_command", "make mvp-verify");

    for (size_t i = 0; i < criteria_count; i++)
        api_push_mvp_proof_item(&items, &criteria[i]);
    json_push_kv(&proofs, "items", &items);
    json_free(&items);

    json_push_kv(result, "operator_proofs", &proofs);
    json_free(&proofs);
}

int64_t api_served_tip_height(void)
{
    return reducer_frontier_external_tip_height();
}

void api_milestone_status_json(struct json_value *result)
{
    struct node_health_snapshot health = {0};
    node_health_collect(&health, g_api_ctx.node_db ?
        g_api_ctx.node_db : app_runtime_node_db(), g_api_ctx.main_state);
    struct json_value agent = {0};
    bool agent_ok = api_milestone_agent_snapshot(&agent);
    const struct json_value *agent_peers = json_get(&agent, "peers");
    const struct json_value *agent_services = json_get(&agent, "services");
    const struct json_value *agent_height_contract =
        json_get(&agent, "height_contract");
    bool agent_fields_complete = agent_ok;

    api_milestone_require_field(&agent_fields_complete, api_json_has_str_field(&agent, "status"));
    api_milestone_require_field(&agent_fields_complete, api_json_has_str_field(&agent, "readiness_status"));
    api_milestone_require_field(
        &agent_fields_complete,
        api_json_has_str_field(agent_height_contract, "status"));
    api_milestone_require_field(&agent_fields_complete, api_json_has_bool_field(&agent, "healthy"));
    api_milestone_require_field(&agent_fields_complete, api_json_has_bool_field(&agent, "serving"));
    api_milestone_require_field(&agent_fields_complete, api_json_has_int_field(&agent, "served_height"));
    api_milestone_require_field(&agent_fields_complete, api_json_has_int_field(&agent, "indexed_height"));
    api_milestone_require_field(&agent_fields_complete, api_json_has_int_field(&agent, "header_height"));
    api_milestone_require_field(&agent_fields_complete,
                                api_json_has_int_field(&agent,
                                                       "peer_best_height"));
    api_milestone_require_field(&agent_fields_complete,
                                api_json_has_int_field(&agent,
                                                       "target_height"));
    api_milestone_require_field(&agent_fields_complete,
                                api_json_has_int_field(&agent, "gap"));
    api_milestone_require_field(&agent_fields_complete,
                                api_json_has_bool_field(agent_peers,
                                                        "has_peers"));
    api_milestone_require_field(&agent_fields_complete,
                                api_json_has_int_field(agent_peers, "total"));
    api_milestone_require_field(&agent_fields_complete,
                                api_json_has_bool_field(agent_services,
                                                        "tor_enabled"));
    api_milestone_require_field(&agent_fields_complete,
                                api_json_has_bool_field(agent_services,
                                                        "tor_ready"));
    api_milestone_require_field(
        &agent_fields_complete,
        api_json_has_bool_field(agent_services, "onion_service_ready"));
    api_milestone_require_field(&agent_fields_complete,
                                api_json_has_str_field(&agent, "sync_state"));

    int served_height = agent_ok
        ? api_json_int_field(&agent, "served_height",
                             (int)api_served_tip_height())
        : (int)api_served_tip_height();
    int indexed_height = agent_ok
        ? api_json_int_field(&agent, "indexed_height", health.tip_height)
        : health.tip_height;
    int target = indexed_height > served_height ? indexed_height
                                                : served_height;
    int header_height = agent_ok
        ? api_json_int_field(&agent, "header_height", health.header_height)
        : health.header_height;
    int peer_best_height = agent_ok
        ? api_json_int_field(&agent, "peer_best_height",
                             health.peer_best_height)
        : health.peer_best_height;
    if (header_height > target)
        target = header_height;
    if (peer_best_height > target)
        target = peer_best_height;
    if (agent_ok)
        target = api_json_int_field(&agent, "target_height", target);
    int gap = agent_ok
        ? api_json_int_field(&agent, "gap",
                             target > served_height ? target - served_height : 0)
        : (target > served_height ? target - served_height : 0);
    bool live_healthy = agent_ok
        ? api_json_bool_field(&agent, "healthy", false)
        : false;
    bool live_serving = agent_ok
        ? api_json_bool_field(&agent, "serving", false)
        : false;
    bool live_has_peers = agent_ok
        ? api_json_nested_bool_field(&agent, "peers", "has_peers",
                                     health.has_peers)
        : health.has_peers;
    int live_peer_count = agent_ok
        ? api_json_nested_int_field(&agent, "peers", "total",
                                    (int)health.peer_count)
        : (int)health.peer_count;
    bool tor_enabled = agent_ok
        ? api_json_nested_bool_field(&agent, "services", "tor_enabled",
                                     health.tor_enabled)
        : health.tor_enabled;
    bool tor_ready = agent_ok
        ? api_json_nested_bool_field(&agent, "services", "tor_ready",
                                     health.tor_ready)
        : health.tor_ready;
    bool onion_service_ready = agent_ok
        ? api_json_nested_bool_field(&agent, "services",
                                     "onion_service_ready",
                                     health.onion_service_ready)
        : health.onion_service_ready;
    const char *sync_state = agent_ok
        ? api_json_str_field(&agent, "sync_state",
                             sync_state_name(sync_get_state()))
        : sync_state_name(sync_get_state());
    const char *agent_status = agent_ok
        ? api_json_str_field(&agent, "status", "unavailable")
        : "unavailable";
    const char *readiness_status = agent_ok
        ? api_json_str_field(&agent, "readiness_status", "unknown")
        : "unknown";
    const char *height_status = agent_ok
        ? api_json_str_field(json_get(&agent, "height_contract"), "status",
                             "unknown")
        : "unknown";

    int systems_done = 0;
    int systems_total = 6;
    bool onion_ok = tor_enabled && tor_ready && onion_service_ready;
    if (live_serving)
        systems_done++;
    if (live_healthy)
        systems_done++;
    if (served_height > 0)
        systems_done++;
    if (gap <= 1)
        systems_done++;
    if (live_has_peers)
        systems_done++;
    if (onion_ok)
        systems_done++;

    int strict_pass = 0;
    int partial_units = 0;
    int max_units = 0;
    size_t criteria_count = sizeof(k_mvp_criteria) / sizeof(k_mvp_criteria[0]);
    for (size_t i = 0; i < criteria_count; i++) {
        if (k_mvp_criteria[i].strict_pass)
            strict_pass++;
        partial_units += k_mvp_criteria[i].units;
        max_units += 2;
    }

    json_set_object(result);
    json_push_kv_str(result, "schema", ZCL_MILESTONE_STATUS_SCHEMA);
    json_push_kv_str(result, "api_version", ZCL_REST_API_VERSION);
    json_push_kv_str(result, "milestone", "v1 MVP");
    json_push_kv_str(result, "source", "zclassic23");
    json_push_kv_str(result, "rule",
                     "MVP is achieved only when MRS reaches 8/8");
    json_push_kv_bool(result, "complete",
                      strict_pass == (int)criteria_count);
    json_push_kv_int(result, "mvp_readiness_score", strict_pass);
    json_push_kv_int(result, "target_score", (int64_t)criteria_count);
    json_push_kv_int(result, "partial_progress_units", partial_units);
    json_push_kv_int(result, "partial_progress_units_total", max_units);

    struct json_value live;
    json_init(&live);
    json_set_object(&live);
    json_push_kv_str(&live, "source",
                     agent_ok && agent_fields_complete
                         ? "agent_cached_summary"
                         : agent_ok ? "agent_cached_summary_with_fallbacks"
                                    : "node_health_collect_fallback");
    json_push_kv_str(&live, "source_schema",
                     agent_ok ? ZCL_PUBLIC_STATUS_SCHEMA
                              : "zcl.node_health_snapshot");
    json_push_kv_bool(&live, "agent_summary_available", agent_ok);
    json_push_kv_bool(&live, "agent_fields_complete",
                      agent_fields_complete);
    json_push_kv_str(&live, "fallback_source",
                     agent_ok && agent_fields_complete
                         ? "none"
                         : agent_ok ? "node_health_collect+sync_state"
                                    : "node_health_collect");
    json_push_kv_str(&live, "agent_status", agent_status);
    json_push_kv_str(&live, "readiness_status", readiness_status);
    json_push_kv_str(&live, "height_contract_status", height_status);
    json_push_kv_bool(&live, "healthy", live_healthy);
    json_push_kv_bool(&live, "serving", live_serving);
    json_push_kv_int(&live, "served_height", served_height);
    json_push_kv_int(&live, "indexed_height", indexed_height);
    json_push_kv_int(&live, "header_height", header_height);
    json_push_kv_int(&live, "peer_best_height", peer_best_height);
    json_push_kv_int(&live, "target_height", target);
    json_push_kv_int(&live, "gap", gap);
    json_push_kv_int(&live, "peers", live_peer_count);
    json_push_kv_bool(&live, "tor_enabled", tor_enabled);
    json_push_kv_bool(&live, "onion_ready", onion_ok);
    json_push_kv_str(&live, "sync_state", sync_state);
    json_push_kv(result, "live", &live);
    json_free(&live);
    json_free(&agent);

    struct json_value bars;
    struct json_value ascii;
    json_init(&bars);
    json_init(&ascii);
    json_set_object(&bars);
    json_set_object(&ascii);
    api_push_progress_bar(&bars, &ascii, "systems", systems_done,
                          systems_total, "live node runtime checks");
    api_push_progress_bar(&bars, &ascii, "goals", strict_pass,
                          (int)criteria_count, "strict MVP MRS");
    api_push_progress_bar(&bars, &ascii, "subgoals", partial_units,
                          max_units, "full plus partial proof units");
    json_push_kv(result, "bars", &bars);
    json_push_kv(result, "ascii", &ascii);
    json_free(&bars);
    json_free(&ascii);

    struct json_value criteria;
    json_init(&criteria);
    json_set_array(&criteria);
    for (size_t i = 0; i < criteria_count; i++) {
        const struct milestone_criterion *c = &k_mvp_criteria[i];
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        json_push_kv_int(&item, "id", c->id);
        json_push_kv_str(&item, "key", c->key);
        json_push_kv_str(&item, "title", c->title);
        json_push_kv_str(&item, "status", c->status);
        json_push_kv_bool(&item, "strict_pass", c->strict_pass);
        json_push_kv_int(&item, "progress_units", c->units);
        json_push_kv_int(&item, "progress_units_total", 2);
        json_push_kv_str(&item, "next", c->next);
        json_push_back(&criteria, &item);
        json_free(&item);
    }
    json_push_kv(result, "criteria", &criteria);
    json_free(&criteria);

    api_push_mvp_operator_proofs(result, k_mvp_criteria, criteria_count,
                                 strict_pass, partial_units, max_units);

    struct json_value next;
    json_init(&next);
    json_set_array(&next);
    for (size_t i = 0; i < criteria_count; i++) {
        if (k_mvp_criteria[i].strict_pass)
            continue;
        struct json_value s;
        json_init(&s);
        json_set_str(&s, k_mvp_criteria[i].next);
        json_push_back(&next, &s);
        json_free(&s);
    }
    json_push_kv(result, "next", &next);
    json_free(&next);
}

size_t api_serve_milestone(uint8_t *response, size_t response_max)
{
    if (!response || response_max == 0)
        return 0;

    struct json_value body;
    json_init(&body);
    api_milestone_status_json(&body);
    api_json_add_freshness(&body, "operator_status", -1);
    size_t n = api_json_ok(response, response_max, &body);
    json_free(&body);
    return n;
}

void api_refold_status_json(struct json_value *result)
{
    struct anchor_snapshot_status st = {0};
    bool status_ok = anchor_selfmint_snapshot_status(g_api_ctx.datadir, &st);

    json_set_object(result);
    json_push_kv_str(result, "schema", ZCL_REFOLD_STATUS_SCHEMA);
    json_push_kv_str(result, "api_version", ZCL_REST_API_VERSION);
    json_push_kv_str(result, "source", "zclassic23");
    json_push_kv_str(result, "purpose",
                     "self-verified UTXO anchor rebuild readiness");
    json_push_kv_str(result, "plain_english",
                     "Checks whether zclassic23 has rebuilt its own verified "
                     "UTXO anchor from local block history so it can stop "
                     "depending on the borrowed snapshot seed.");
    json_push_kv_str(result, "internal_mechanism", "-refold-from-anchor");
    json_push_kv_bool(result, "ready_for_refold",
                      status_ok && st.verified);
    json_push_kv_str(result, "primary_blocker",
                     status_ok && st.verified
                         ? "none"
                         : "missing_verified_anchor_snapshot");
    json_push_kv_str(result, "next_action",
                     status_ok ? st.next_action
                               : "check anchor snapshot status internals");

    struct json_value checkpoint;
    json_init(&checkpoint);
    json_set_object(&checkpoint);
    json_push_kv_bool(&checkpoint, "present", status_ok &&
                      st.checkpoint_present);
    json_push_kv_int(&checkpoint, "height", st.checkpoint_height);
    json_push_kv_int(&checkpoint, "utxo_count",
                     (int64_t)st.checkpoint_utxo_count);
    json_push_kv_int(&checkpoint, "total_supply",
                     st.checkpoint_total_supply);
    json_push_kv_str(&checkpoint, "sha3", st.checkpoint_sha3_hex);
    json_push_kv_str(&checkpoint, "block_hash",
                     st.checkpoint_block_hash_hex);
    json_push_kv(result, "checkpoint", &checkpoint);
    json_free(&checkpoint);

    struct json_value snap;
    json_init(&snap);
    json_set_object(&snap);
    json_push_kv_bool(&snap, "path_resolved", status_ok &&
                      st.path_resolved);
    json_push_kv_str(&snap, "source", status_ok ? st.path_source : "");
    json_push_kv_str(&snap, "path", status_ok ? st.path : "");
    json_push_kv_bool(&snap, "stat_present", status_ok &&
                      st.stat_present);
    json_push_kv_int(&snap, "stat_size",
                     status_ok ? st.stat_size : 0);
    json_push_kv_bool(&snap, "header_read", status_ok && st.header_read);
    json_push_kv_int(&snap, "height", st.snapshot_height);
    json_push_kv_int(&snap, "count", (int64_t)st.snapshot_count);
    json_push_kv_int(&snap, "total_supply",
                     st.snapshot_total_supply);
    json_push_kv_str(&snap, "sha3", st.snapshot_sha3_hex);
    json_push_kv_str(&snap, "block_hash", st.snapshot_block_hash_hex);
    json_push_kv_bool(&snap, "height_match", status_ok &&
                      st.height_match);
    json_push_kv_bool(&snap, "count_match", status_ok &&
                      st.count_match);
    json_push_kv_bool(&snap, "sha3_match", status_ok && st.sha3_match);
    json_push_kv_bool(&snap, "block_hash_match", status_ok &&
                      st.block_hash_match);
    json_push_kv_bool(&snap, "verified", status_ok && st.verified);
    json_push_kv_str(&snap, "verification",
                     status_ok ? st.verification : "status_error");
    if (!status_ok || st.error[0])
        json_push_kv_str(&snap, "error", status_ok ? st.error
                                                    : "status unavailable");
    json_push_kv(result, "anchor_snapshot", &snap);
    json_free(&snap);

    struct json_value commands;
    json_init(&commands);
    json_set_object(&commands);
    json_push_kv_str(&commands, "native", "z23 refold");
    json_push_kv_str(&commands, "rest", "/api/v1/refold");
    json_push_kv_str(&commands, "copy_proof",
                     "make repro-on-copy SLUG=soak-refold "
                     "REPRO_SRC=$HOME/.zclassic-c23-soak REPRO_FULL=1 "
                     "CLIMB_PAST=<checkpoint_height> "
                     "ARGS='-refold-from-anchor -nobgvalidation "
                     "-paramsdir=$$HOME/.zcash-params'");
    json_push_kv(result, "commands", &commands);
    json_free(&commands);
}

size_t api_serve_refold_status(uint8_t *response, size_t response_max)
{
    if (!response || response_max == 0)
        return 0;

    struct json_value body;
    json_init(&body);
    api_refold_status_json(&body);
    api_json_add_freshness(&body, "anchor_snapshot", -1);
    size_t n = api_json_ok(response, response_max, &body);
    json_free(&body);
    return n;
}

size_t api_serve_unsupported_version(const char *requested_version,
                                     uint8_t *response,
                                     size_t response_max)
{
    const char *requested = requested_version ? requested_version : "unknown";

    struct json_value body;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", ZCL_REST_ERROR_SCHEMA);
    json_push_kv_str(&body, "api_version", ZCL_REST_API_VERSION);
    json_push_kv_str(&body, "error", "unsupported_api_version");
    json_push_kv_str(&body, "requested_version", requested);

    struct json_value supported;
    json_init(&supported);
    json_set_array(&supported);
    struct json_value version;
    json_init(&version);
    json_set_str(&version, ZCL_REST_API_VERSION);
    json_push_back(&supported, &version);
    json_free(&version);
    json_push_kv(&body, "supported_versions", &supported);
    json_free(&supported);

    json_push_kv_str(&body, "base_path", ZCL_REST_API_BASE_PATH);
    json_push_kv_str(&body, "index", ZCL_REST_API_BASE_PATH);

    size_t n = api_json_status(response, response_max, "400 Bad Request",
                               &body);
    json_free(&body);
    return n;
}

/* Route: /api/status and /api/node/summary */
size_t api_serve_node_summary(uint8_t *response, size_t response_max)
{
    struct node_health_snapshot health = {0};
    struct node_db *ndb = g_api_ctx.node_db ? g_api_ctx.node_db : app_runtime_node_db();
    node_health_collect(&health, ndb, g_api_ctx.main_state);
    struct agent_security_posture posture; agent_security_posture_collect(&posture, ndb);
    struct blocker_snapshot blockers[BLOCKER_CAP];
    int blocker_count = blocker_snapshot_all(blockers, BLOCKER_CAP);
    const struct blocker_snapshot *dominant = blocker_select_dominant(blockers, blocker_count);
    const struct blocker_snapshot *authority_blocker = api_blocker_hard_gates_public_serving(dominant) ? dominant : NULL;
    const struct blocker_snapshot *warning_blocker = dominant && !authority_blocker ? dominant : NULL;
    struct download_stats_snapshot dl_snap;
    download_stats_snapshot_from_health(&dl_snap, &health);
    struct api_freshness_meta freshness;
    api_freshness_prepare(&freshness, "served_tip", health.tip_height);
    int64_t height = freshness.served_height;
    int64_t indexed_height = freshness.indexed_height;
    int64_t target = indexed_height > height ? indexed_height : height;
    if (health.header_height > target)
        target = health.header_height;
    if (health.peer_best_height > target)
        target = health.peer_best_height;
    int64_t gap = target > height ? target - height : 0;
    int64_t index_gap = indexed_height > height ? indexed_height - height : 0;
    const char *primary = "none";
    const char *next_endpoint = "/api/v1/agent";
    bool material_gap = gap > ZCL_NODE_HEALTH_LAG_WARN_BLOCKS;
    /* This chain only picks WHICH reason applies, from what this endpoint's
     * node_health_snapshot can actually observe. status/summary/operator_needed
     * all come back from the one policy table
     * (controllers/operator_needed_policy.def) so this endpoint and the agent
     * summary cannot answer "does an operator need to act" differently. */
    enum node_status_reason reason = ZCL_STATUS_REASON_NONE;
    if (authority_blocker) {
        reason = ZCL_STATUS_REASON_TYPED_BLOCKER;
        primary = authority_blocker->id;
        next_endpoint = "/api/v1/health";
    } else if (posture.review_required) {
        reason = ZCL_STATUS_REASON_POSTURE_REVIEW;
        primary = posture.status;
        next_endpoint = "/api/v1/health";
    } else if (!health.serving) {
        reason = health.blocking_reason[0] ? ZCL_STATUS_REASON_HEALTH_BLOCKER
                                          : ZCL_STATUS_REASON_NOT_SERVING;
        primary = health.blocking_reason[0] ? health.blocking_reason
                                            : "not_serving";
        next_endpoint = "/api/v1/health";
    } else if (!health.has_peers) {
        reason = ZCL_STATUS_REASON_NO_PEERS;
        primary = "no_peers";
        next_endpoint = "/api/v1/peers";
    } else if (material_gap &&
               (dl_snap.in_flight > 0 || dl_snap.queued > 0)) {
        reason = ZCL_STATUS_REASON_CHAIN_GAP_DOWNLOADING;
        primary = "chain_gap";
        next_endpoint = "/api/v1/downloadstats";
    } else if (material_gap) {
        reason = ZCL_STATUS_REASON_DOWNLOAD_QUEUE_IDLE;
        primary = "download_queue_idle";
        next_endpoint = "/api/v1/downloadstats";
    } else if (!health.healthy) {
        reason = ZCL_STATUS_REASON_HEALTHCHECK_UNHEALTHY;
        primary = "healthcheck_unhealthy";
        next_endpoint = "/api/v1/health";
    }
    const char *status = node_status_reason_status(reason);
    const char *summary = node_status_reason_summary(reason);
    bool operator_needed = node_status_reason_operator_needed(
        reason, (int64_t)health.warning_count);
    struct json_value body;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", ZCL_PUBLIC_STATUS_SCHEMA);
    json_push_kv_str(&body, "api_version", ZCL_REST_API_VERSION);
    json_push_kv_str(&body, "build_commit", zcl_build_commit());
    json_push_kv_str(&body, "status", status);
    bool public_serving = health.serving && !operator_needed &&
        agent_security_posture_allows_public_serving(&posture);
    json_push_kv_bool(&body, "healthy", health.healthy && public_serving); json_push_kv_bool(&body, "serving", public_serving);
    json_push_kv_bool(&body, "operator_needed", operator_needed);
    json_push_kv_bool(&body, "warning", health.warning || warning_blocker != NULL);
    json_push_kv_int(&body, "warning_count", (int64_t)health.warning_count + (warning_blocker ? 1 : 0));
    if (health.warning_reasons[0]) json_push_kv_str(&body, "warning_reasons", health.warning_reasons);
    if (warning_blocker) json_push_kv_str(&body, "typed_blocker_warning", warning_blocker->id);
    json_push_kv_bool(&body, "operator_latch_recovered",
                      health.operator_latch_recovered);
    json_push_kv_str(&body, "summary", summary);
    json_push_kv_str(&body, "primary_blocker", primary);
    json_push_kv_str(&body, "next_endpoint", next_endpoint);
    agent_push_operator_lane_fields_json(&body);
    agent_push_operator_lane_json(&body, "operator_lane");
    agent_push_readiness_contract_json(
        &body, "readiness", public_serving, health.has_peers,
        operator_needed, health.validation_pack_ok, (int)gap,
        (int)index_gap, health.log_head_gap, &posture);
    json_push_kv_int(&body, "height", height);
    api_freshness_push_json(&body, &freshness);
    json_push_kv_int(&body, "header_height", health.header_height);
    json_push_kv_int(&body, "peer_best_height", health.peer_best_height);
    json_push_kv_int(&body, "target_height", target);
    json_push_kv_int(&body, "gap", gap);
    json_push_kv_int(&body, "index_gap", index_gap);
    agent_push_height_contract_fields_json(
        &body, "height_contract", height, health.tip_height,
        health.header_height, health.peer_best_height, target, gap,
        health.log_head, health.log_head_gap);
    agent_push_security_posture_json(
        &body, "security_posture",
        g_api_ctx.node_db ? g_api_ctx.node_db : app_runtime_node_db());
    json_push_kv_str(&body, "sync_state",
                     sync_state_name(health.sync_state));
    agent_push_restart_watchdog_json(&body, "restart_watchdog", NULL);
    struct agent_resource_snapshot resources;
    agent_resource_snapshot_collect(&resources);
    agent_push_resources_json(&body, "resources", &resources);
    struct json_value peers;
    json_init(&peers);
    json_set_object(&peers);
    json_push_kv_int(&peers, "total", (int64_t)health.peer_count);
    json_push_kv_bool(&peers, "has_peers", health.has_peers);
    json_push_kv_int(&peers, "magicbean",
                     (int64_t)health.magicbean_peer_count);
    json_push_kv_int(&peers, "zclassic23",
                     (int64_t)health.zclassic_c23_peer_count);
    json_push_kv(&body, "peers", &peers);
    json_free(&peers);
    struct json_value download;
    json_init(&download);
    json_set_object(&download);
    download_stats_push_json(&download, &dl_snap, false);
    json_push_kv(&body, "download", &download);
    json_free(&download);

    struct json_value services;
    json_init(&services);
    json_set_object(&services);
    json_push_kv_bool(&services, "tor_enabled", health.tor_enabled);
    json_push_kv_bool(&services, "tor_ready", health.tor_ready);
    json_push_kv_bool(&services, "onion_service_ready",
                      health.onion_service_ready);
    json_push_kv(&body, "services", &services);
    json_free(&services);

    static const char *recommended[] = {
        "/api/v1/agent",
        "/api/v1/health",
        "/api/v1/node/status",
        "/api/v1/hodl",
        "/api/v1/factoids",
    };
    struct json_value endpoints;
    json_init(&endpoints);
    json_set_array(&endpoints);
    for (size_t i = 0; i < sizeof(recommended) / sizeof(recommended[0]); i++) {
        struct json_value item;
        json_init(&item);
        json_set_str(&item, recommended[i]);
        json_push_back(&endpoints, &item);
        json_free(&item);
    }
    json_push_kv(&body, "recommended_endpoints", &endpoints);
    json_free(&endpoints);

    size_t n = api_json_ok(response, response_max, &body);
    json_free(&body);
    return n;
}
