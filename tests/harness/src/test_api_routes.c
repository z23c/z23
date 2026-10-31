/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API route table: fixed and dynamic resource routes, route<->command parity,
 * version prefix handling, and the endpoint edge cases around them.
 */

#include "test/api_test_fixtures.h"
#include "controllers/diagnostics_controller.h"
#include "encoding/utilstrencodings.h"
#include "storage/coins_kv.h"

#include <pthread.h>
#include <stdatomic.h>

/* Current acceptance follows the native classifier; history stays visible. */
static void milestone_requires_history_basis(bool *ok,
                                             const struct json_value *root,
                                             const struct json_value *cold_start)
{
    const char *basis = json_get_str(json_get(root, "score_basis"));
    const char *cmd = json_get_str(json_get(
        json_get(root, "current_qualification"), "command"));
    const char *evidence = cold_start
        ? json_get_str(json_get(cold_start, "evidence")) : NULL;
    const char *goals = json_get_str(json_get(json_get(root, "ascii"),
                                              "goals"));
    *ok = *ok && basis &&
        strcmp(basis, "current_typed_mvp_decision") == 0 &&
        cmd && strcmp(cmd, "z23 ops state --subsystem=mvp") == 0 &&
        evidence && strcmp(evidence, "historical_report") == 0 &&
        goals && strstr(goals, "current qualified criteria") != NULL;
}

static bool milestone_item_agrees(const struct json_value *met,
                                  const struct json_value *item,
                                  const struct json_value *criterion)
{
    bool accepted = met && met->type == JSON_BOOL && json_get_bool(met);
    const char *status = accepted ? "pass" : met && met->type == JSON_BOOL ? "fail" : "unknown";
    return json_get_bool(json_get(item, "strict_pass")) == accepted &&
           json_get_bool(json_get(criterion, "strict_pass")) == accepted &&
           strcmp(json_get_str(json_get(item, "status")), status) == 0 &&
           strcmp(json_get_str(json_get(criterion, "status")), status) == 0 &&
           strcmp(json_get_str(json_get(item, "proof_state")), accepted ? "accepted" : "pending") == 0;
}

static bool milestone_summary_agrees(const struct json_value *root,
                                     const struct json_value *proofs, int count)
{
    return json_get_int(json_get(root, "mvp_readiness_score")) == count &&
           json_get_int(json_get(proofs, "accepted_count")) == count &&
           json_get_int(json_get(proofs, "pending_count")) == 8 - count &&
           json_get_bool(json_get(root, "complete")) == (count == 8) &&
           json_get_int(json_get(json_get(json_get(root, "bars"), "goals"), "done")) == count;
}

static bool milestone_agrees_with_mvp(const struct json_value *root)
{
    struct json_value native = {0};
    bool ok = mvp_dump_state_json(&native, NULL);
    const struct json_value *rows = json_get(&native, "criteria");
    const struct json_value *proofs = json_get(root, "operator_proofs");
    const struct json_value *items = json_get(proofs, "items");
    const struct json_value *criteria = json_get(root, "criteria");
    int count = (int)json_get_int(json_get(&native, "met_count"));
    ok = ok && rows && json_size(rows) == 8 && items && json_size(items) == 8;
    for (size_t i = 0; ok && i < 8; i++) {
        const struct json_value *met = json_get(json_at(rows, i), "met");
        const struct json_value *item = json_at(items, i);
        const struct json_value *criterion = json_at(criteria, i);
        ok = milestone_item_agrees(met, item, criterion);
    }
    ok = ok && milestone_summary_agrees(root, proofs, count);
    json_free(&native);
    return ok;
}

/* The earned C5 row lives at proof-item index 4 (k_mvp_criteria order);
 * the key check keeps the assertion honest across reorderings. */
static bool api_store_flow_pass(bool ok_in,
                                const struct json_value *proof_items)
{
    const struct json_value *sf;
    if (!ok_in || !proof_items)
        return false;
    sf = json_at(proof_items, 4);
    if (!sf || strcmp(json_get_str(json_get(sf, "key")), "store_flow") != 0)
        return false;
    if (strcmp(json_get_str(json_get(sf, "historical_status")), "pass") != 0 ||
        json_get_bool(json_get(sf, "strict_pass")))
        return false;
    return strcmp(json_get_str(json_get(sf, "proof_command")),
                  "tools/dev/store_onion_acceptance.sh") == 0;
}

static bool milestone_legacy_response_not_accepted(void)
{
    struct json_value root = {0};
    uint8_t response[8192];
    size_t n = api_handle_request("GET", "/api/v1/milestone", NULL, 0,
                                  response, sizeof(response));
    const char *body = api_test_body(response, n, sizeof(response));
    bool ok = n > 0 && body && json_read(&root, body, strlen(body)) &&
              milestone_agrees_with_mvp(&root);
    const struct json_value *items = json_get(json_get(&root, "operator_proofs"), "items");
    const size_t ids[] = {1, 6};
    for (size_t i = 0; ok && i < 2; i++) {
        const struct json_value *item = json_at(items, ids[i]);
        ok = item && !json_get_bool(json_get(item, "strict_pass")) &&
             strcmp(json_get_str(json_get(item, "status")), "unknown") == 0 &&
             strcmp(json_get_str(json_get(item, "proof_state")), "pending") == 0 &&
             strcmp(json_get_str(json_get(item, "historical_status")), "pass") == 0;
    }
    json_free(&root);
    return ok;
}

static bool milestone_legacy_receipts_not_accepted(void)
{
    const char *names[] = {"ZCL_ONION_RECEIPT_DIR", "ZCL_CRASH_RECEIPT_DIR"};
    char saved[2][4096];
    bool had[2];
    for (size_t i = 0; i < 2; i++) {
        const char *old = getenv(names[i]);
        had[i] = old != NULL;
        if (snprintf(saved[i], sizeof(saved[i]), "%s", old ? old : "") >=
            (int)sizeof(saved[i])) return false;
    }
    char dir[512] = {0}, path[640] = {0};
    bool ok = test_mkdtemp(dir, sizeof(dir), "api-mvp-receipts") != NULL;
    FILE *file = NULL;
    if (ok) {
        snprintf(path, sizeof(path), "%s/receipts.jsonl", dir);
        file = fopen(path, "wb");
        ok = file != NULL;
    }
    if (file) {
        ok = fprintf(file,
            "{\"schema\":\"zcl.onion_bootstrap_receipt.v1\",\"utc\":\"2000-01-01T00:00:00Z\",\"verdict\":\"PASS\",\"bootstrap_ms\":1}\n"
            "{\"schema\":\"zcl.crash_recovery_receipt.v1\",\"utc\":\"2000-01-01T00:00:00Z\",\"verdict\":\"PASS\",\"recover_ms\":1}\n") > 0;
        if (fclose(file) != 0) ok = false;
    }
    for (size_t i = 0; ok && i < 2; i++)
        ok = setenv(names[i], dir, 1) == 0;
    ok = ok && milestone_legacy_response_not_accepted();
    for (size_t i = 0; i < 2; i++) {
        int rc = had[i] ? setenv(names[i], saved[i], 1) : unsetenv(names[i]);
        if (rc != 0) ok = false;
    }
    if (path[0]) unlink(path);
    if (dir[0]) test_cleanup_tmpdir(dir);
    return ok;
}

static int milestone_legacy_receipt_test(void)
{
    bool ok = milestone_legacy_receipts_not_accepted();
    printf("api: milestone retains legacy PASS history without current acceptance... %s\n",
           ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static bool api_get_request_json(uint8_t *resp, size_t cap, const char *path,
                                 struct json_value *root, bool ok)
{
    size_t n = api_handle_request("GET", path, NULL, 0, resp, cap);
    const char *body = api_test_body(resp, n, cap);
    json_init(root);
    return ok && n > 0 && body && json_read(root, body, strlen(body));
}

static bool api_milestone_status_identity(const struct json_value *root)
{
    return strcmp(json_get_str(json_get(root, "schema")),
                  "zcl.milestone_status.v2") == 0
        && strcmp(json_get_str(json_get(root, "milestone")), "v1 MVP") == 0
        && milestone_agrees_with_mvp(root)
        && !json_get_bool(json_get(root, "complete"))
        && json_get_int(json_get(root, "historical_pass_count")) == 6
        && json_get_int(json_get(root, "target_score")) == 8;
}

static bool api_milestone_bars_criteria(bool ok,
                                        const struct json_value *ascii,
                                        const struct json_value *bars,
                                        const struct json_value *criteria,
                                        const struct json_value *operator_proofs,
                                        const struct json_value *proof_items)
{
    ok = ok && ascii && strstr(json_get_str(json_get(ascii, "goals")),
                               "current qualified criteria") != NULL;
    ok = ok && bars && strcmp(json_get_str(json_get(json_get(bars,
                              "subgoals"), "bar")), "[#########-]") == 0;
    ok = ok && criteria && json_size(criteria) == 8;
    ok = ok && operator_proofs &&
        strcmp(json_get_str(json_get(operator_proofs, "schema")),
               "zcl.mvp_operator_proofs.v1") == 0;
    ok = ok && proof_items && json_size(proof_items) == 8;
    return ok;
}

struct api_json_eq {
    const char *key;
    const char *value;
};

static bool api_milestone_fields_eq(bool ok, const struct json_value *obj,
                                    const struct api_json_eq *rows, size_t n)
{
    ok = ok && obj != NULL;
    for (size_t i = 0; i < n; i++)
        ok = ok && strcmp(json_get_str(json_get(obj, rows[i].key)),
                          rows[i].value) == 0;
    return ok;
}

static const struct api_json_eq k_api_cold_start_fields[] = {
    { "key", "cold_start_sync" },
    { "proof_command", "make mvp-coldstart-to-tip-stopwatch" },
};

static const struct api_json_eq k_api_soak_fields[] = {
    { "key", "seven_day_soak" },
    { "proof_scope", "live_window" },
    { "primary_blocker", "clean_168h_soak_window_pending" },
};

static bool api_milestone_live_objects_present(const struct json_value *live)
{
    static const char *const keys[] = {
        "agent_status", "readiness_status", "height_contract_status",
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        ok = ok && json_get(live, keys[i]) != NULL;
    return ok;
}

static bool api_milestone_fallback_source(bool ok,
                                          const struct json_value *live,
                                          bool live_full_agent,
                                          bool live_agent_fallback)
{
    if (live_full_agent)
        ok = ok && strcmp(json_get_str(json_get(live, "fallback_source")),
                          "none") == 0;
    if (live_agent_fallback)
        ok = ok && strcmp(json_get_str(json_get(live, "fallback_source")),
                          "none") != 0;
    return ok;
}

static bool api_milestone_live_summary(bool ok, const struct json_value *live,
                                       bool live_full_agent,
                                       bool live_agent_fallback)
{
    ok = ok && live && (live_full_agent || live_agent_fallback);
    ok = ok && strcmp(json_get_str(json_get(live, "source_schema")),
                      "zcl.public_status.v3") == 0;
    ok = ok && json_get_bool(json_get(live, "agent_summary_available"));
    ok = ok && json_get_bool(json_get(live, "agent_fields_complete")) ==
        live_full_agent;
    ok = api_milestone_fallback_source(ok, live, live_full_agent,
                                       live_agent_fallback);
    ok = ok && api_milestone_live_objects_present(live);
    return ok;
}

static bool api_milestone_heights_match(const struct json_value *live,
                                        const struct json_value *agent_root)
{
    static const char *const keys[] = {
        "served_height", "indexed_height", "header_height",
        "peer_best_height", "target_height", "gap",
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        ok = ok && json_get_int(json_get(live, keys[i])) ==
                    json_get_int(json_get(agent_root, keys[i]));
    return ok;
}

static bool api_milestone_live_matches_agent(bool ok, bool agent_ok,
                                             bool live_full_agent,
                                             const struct json_value *live,
                                             const struct json_value *agent_root)
{
    int64_t agent_served =
        json_get_int(json_get(agent_root, "served_height"));
    if (ok && agent_ok && live_full_agent && agent_served > 0) {
        const struct json_value *agent_peers = json_get(agent_root, "peers");
        const struct json_value *agent_services =
            json_get(agent_root, "services");
        bool agent_onion =
            json_get_bool(json_get(agent_services, "tor_enabled")) &&
            json_get_bool(json_get(agent_services, "tor_ready")) &&
            json_get_bool(json_get(agent_services, "onion_service_ready"));
        ok = api_milestone_heights_match(live, agent_root);
        ok = ok && json_get_int(json_get(live, "peers")) ==
            json_get_int(json_get(agent_peers, "total"));
        ok = ok && json_get_bool(json_get(live, "tor_enabled")) ==
            json_get_bool(json_get(agent_services, "tor_enabled"));
        ok = ok && json_get_bool(json_get(live, "onion_ready")) == agent_onion;
        ok = ok && strcmp(json_get_str(json_get(live, "sync_state")),
                          json_get_str(json_get(agent_root,
                                                "sync_state"))) == 0;
    }
    return ok;
}

static int api_milestone_ascii_bars_case(uint8_t *resp, size_t cap)
{
    printf("api: milestone endpoint returns node-computed ASCII bars... ");
    uint8_t agent_resp[65536];
    struct json_value agent_root;
    bool agent_ok = api_get_request_json(agent_resp, sizeof(agent_resp),
                                         "/api/v1/agent", &agent_root, true);
    struct json_value root;
    bool ok = api_get_request_json(resp, cap, "/api/v1/milestone", &root, true);
    const struct json_value *ascii = json_get(&root, "ascii");
    const struct json_value *bars = json_get(&root, "bars");
    const struct json_value *criteria = json_get(&root, "criteria");
    const struct json_value *operator_proofs =
        json_get(&root, "operator_proofs");
    const struct json_value *proof_items =
        operator_proofs ? json_get(operator_proofs, "items") : NULL;
    const struct json_value *cold_start =
        proof_items ? json_at(proof_items, 2) : NULL;
    const struct json_value *soak =
        proof_items ? json_at(proof_items, 5) : NULL;
    ok = api_store_flow_pass(ok, proof_items);
    const struct json_value *live = json_get(&root, "live");
    const char *live_source = json_get_str(json_get(live, "source"));
    ok = ok && api_milestone_status_identity(&root);
    milestone_requires_history_basis(&ok, &root, cold_start);
    ok = api_milestone_bars_criteria(ok, ascii, bars, criteria,
                                    operator_proofs, proof_items);
    ok = api_milestone_fields_eq(ok, cold_start, k_api_cold_start_fields,
                                 sizeof(k_api_cold_start_fields) /
                                 sizeof(k_api_cold_start_fields[0]));
    ok = api_milestone_fields_eq(ok, soak, k_api_soak_fields,
                                 sizeof(k_api_soak_fields) /
                                 sizeof(k_api_soak_fields[0]));
    bool live_full_agent = live_source &&
        strcmp(live_source, "agent_cached_summary") == 0;
    bool live_agent_fallback = live_source &&
        strcmp(live_source, "agent_cached_summary_with_fallbacks") == 0;
    ok = api_milestone_live_summary(ok, live, live_full_agent,
                                    live_agent_fallback);
    ok = api_milestone_live_matches_agent(ok, agent_ok, live_full_agent,
                                          live, &agent_root);
    json_free(&agent_root);
    json_free(&root);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); return 1; }
    return 0;
}

static bool api_refold_status_text(const struct json_value *root)
{
    return strcmp(json_get_str(json_get(root, "schema")),
                  "zcl.refold_status.v2") == 0
        && strcmp(json_get_str(json_get(root, "api_version")), "v1") == 0
        && strstr(json_get_str(json_get(root, "purpose")),
                  "UTXO anchor rebuild") != NULL
        && strstr(json_get_str(json_get(root, "plain_english")),
                  "borrowed snapshot seed") != NULL
        && strcmp(json_get_str(json_get(root, "internal_mechanism")),
                  "-refold-from-anchor") == 0
        && !json_get_bool(json_get(root, "ready_for_refold"))
        && strcmp(json_get_str(json_get(root, "primary_blocker")),
                  "missing_verified_anchor_snapshot") == 0;
}

static bool api_refold_missing_snapshot(const struct json_value *snap)
{
    static const char *false_fields[] = {
        "stat_present", "header_read", "height_match", "count_match",
        "sha3_match", "block_hash_match", "verified"
    };
    if (!snap || snap->type != JSON_OBJ)
        return false;
    for (size_t i = 0; i < sizeof(false_fields) / sizeof(false_fields[0]); i++) {
        const struct json_value *v = json_get(snap, false_fields[i]);
        if (!v || v->type != JSON_BOOL || json_get_bool(v))
            return false;
    }
    const struct json_value *size = json_get(snap, "stat_size");
    const struct json_value *verification = json_get(snap, "verification");
    const struct json_value *error = json_get(snap, "error");
    return size && size->type == JSON_INT && json_get_int(size) == 0 &&
        verification && verification->type == JSON_STR &&
        strcmp(json_get_str(verification), "missing") == 0 &&
        error && error->type == JSON_STR &&
        strcmp(json_get_str(error), "anchor snapshot candidate is absent") == 0;
}

static int api_refold_anchor_readiness_case(uint8_t *resp, size_t cap)
{
    printf("api: refold endpoint reports anchor readiness... ");
    struct json_value root;
    bool ok = api_get_request_json(resp, cap, "/api/v1/refold", &root, true);
    const struct json_value *snap = json_get(&root, "anchor_snapshot");
    const struct json_value *commands = json_get(&root, "commands");
    ok = ok && api_refold_status_text(&root);
    ok = ok && snap && json_get(snap, "path") != NULL;
    ok = ok && api_refold_missing_snapshot(snap);
    ok = ok && commands &&
         strcmp(json_get_str(json_get(commands, "native")), "z23 refold") == 0;
    json_free(&root);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); return 1; }
    return 0;
}

static bool api_rest_error_version_fields(const struct json_value *root)
{
    return strcmp(json_get_str(json_get(root, "schema")),
                  "zcl.rest_error.v1") == 0
        && strcmp(json_get_str(json_get(root, "api_version")), "v1") == 0
        && strcmp(json_get_str(json_get(root, "error")),
                  "unsupported_api_version") == 0
        && strcmp(json_get_str(json_get(root, "requested_version")),
                  "v2") == 0;
}

static int api_unsupported_version_case(uint8_t *resp, size_t cap)
{
    printf("api: unsupported version reports supported versions... ");
    size_t n = api_handle_request("GET", "/api/v2/agent", NULL, 0,
                                  resp, cap);
    const char *body = api_test_body(resp, n, cap);
    struct json_value root;
    json_init(&root);
    bool ok = n > 0 && strstr((char *)resp, "HTTP/1.1 400 Bad Request") != NULL;
    ok = ok && body && json_read(&root, body, strlen(body));
    ok = ok && api_rest_error_version_fields(&root);
    const struct json_value *supported =
        ok ? json_get(&root, "supported_versions") : NULL;
    ok = ok && json_size(supported) == 1;
    ok = ok && strcmp(json_get_str(json_at(supported, 0)), "v1") == 0;
    ok = ok && strcmp(json_get_str(json_get(&root, "base_path")),
                      "/api/v1") == 0;
    json_free(&root);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); return 1; }
    return 0;
}

struct api_route_expect {
    const char *first;
    const char *second;
    const char *third;
};

static void api_mark_matching_route(const char *first, const char *second,
                                    const char *third,
                                    const struct api_route_expect *rows,
                                    size_t nrows, bool *saw)
{
    for (size_t j = 0; j < nrows; j++) {
        if (strcmp(first, rows[j].first) != 0)
            continue;
        if (strcmp(second, rows[j].second) != 0)
            continue;
        if (rows[j].third != NULL) {
            if (third == NULL || strcmp(third, rows[j].third) != 0)
                continue;
        }
        saw[j] = true;
    }
}

static bool api_every_flag(const bool *saw, size_t n)
{
    bool ok = true;
    for (size_t i = 0; i < n; i++)
        ok = ok && saw[i];
    return ok;
}

static const struct api_route_expect k_api_controller_routes[] = {
    { "agent", "show", NULL },
    { "milestone", "show", NULL },
    { "refold", "show", NULL },
    { "blocks", "index", NULL },
    { "factoids", "show", NULL },
};

static int api_controller_route_names_case(void)
{
    printf("api: resource route table exposes controller-style names... ");
    bool saw[sizeof(k_api_controller_routes) /
             sizeof(k_api_controller_routes[0])] = {false};
    size_t nrows = sizeof(k_api_controller_routes) /
                   sizeof(k_api_controller_routes[0]);
    size_t count = api_resource_route_count();
    for (size_t i = 0; i < count; i++) {
        const char *resource = api_resource_route_resource_at(i);
        const char *action = api_resource_route_action_at(i);
        if (!resource || !action)
            continue;
        api_mark_matching_route(resource, action, NULL,
                                k_api_controller_routes, nrows, saw);
    }
    bool ok = count >= 18 && api_every_flag(saw, nrows);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); return 1; }
    return 0;
}

static int api_fixed_route_command_paths_case(void)
{
    printf("api: every fixed route has a non-NULL command_path... ");
    size_t count = api_resource_route_count();
    bool ok = count > 0;
    for (size_t i = 0; i < count; i++) {
        const char *command_path = api_resource_route_command_path_at(i);
        if (!command_path || !command_path[0]) {
            ok = false;
            break;
        }
    }
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); return 1; }
    return 0;
}

static const struct api_route_expect k_api_route_command_pairs[] = {
    { "health", "show", "ops.health" },
    { "refold", "show", "ops.recovery.status" },
};

static int api_route_command_parity_case(void)
{
    printf("api: route<->command parity holds for known pairs... ");
    bool saw[sizeof(k_api_route_command_pairs) /
             sizeof(k_api_route_command_pairs[0])] = {false};
    size_t nrows = sizeof(k_api_route_command_pairs) /
                   sizeof(k_api_route_command_pairs[0]);
    bool saw_none_reason = false;
    size_t count = api_resource_route_count();
    for (size_t i = 0; i < count; i++) {
        const char *resource = api_resource_route_resource_at(i);
        const char *action = api_resource_route_action_at(i);
        const char *command_path = api_resource_route_command_path_at(i);
        if (!resource || !action || !command_path)
            continue;
        api_mark_matching_route(resource, action, command_path,
                                k_api_route_command_pairs, nrows, saw);
        if (strncmp(command_path, "none:", 5) == 0)
            saw_none_reason = true;
    }
    bool ok = saw_none_reason && api_every_flag(saw, nrows);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); return 1; }
    return 0;
}

static const struct api_route_expect k_api_dynamic_routes[] = {
    { "/api/blocks/{height_or_hash}", "blocks", "show" },
    { "/api/block/{height_or_hash}", "blocks", "show" },
    { "/api/transactions/{txid}", "transactions", "show" },
    { "/api/tx/{txid}", "transactions", "show" },
    { "/api/addresses/{address}", "addresses", "show" },
    { "/api/address/{address}", "addresses", "show" },
    { "/api/zslp/tokens/{token_id}", "zslp_tokens", "show" },
    { "/api/zslp/tokens/{token_id}/transfers", "zslp_token_transfers", "index" },
    { "/api/files/{sha3}", "files", "show" },
    { "/api/names/{name}", "names", "show" },
    { "/api/name/{name}", "names", "show" },
    { "/api/service-operations/{operation_id}", "service_operations", "show" },
};

static int api_dynamic_route_metadata_case(void)
{
    printf("api: dynamic resource routes expose REST member metadata... ");
    bool saw[sizeof(k_api_dynamic_routes) / sizeof(k_api_dynamic_routes[0])] =
        {false};
    size_t nrows = sizeof(k_api_dynamic_routes) / sizeof(k_api_dynamic_routes[0]);
    size_t count = api_dynamic_resource_route_count();
    for (size_t i = 0; i < count; i++) {
        const char *pattern = api_dynamic_resource_route_pattern_at(i);
        const char *resource = api_dynamic_resource_route_resource_at(i);
        const char *action = api_dynamic_resource_route_action_at(i);
        if (!pattern || !resource || !action)
            continue;
        api_mark_matching_route(pattern, resource, action,
                                k_api_dynamic_routes, nrows, saw);
    }
    bool ok = count >= 16 && api_every_flag(saw, nrows);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); return 1; }
    return 0;
}

static bool api_lookup_block_tx_fields(const struct json_value *root)
{
    return json_get_int(json_get(root, "num_tx")) == 2
        && json_get_int(json_get(root, "tx_returned")) == 2
        && !json_get_bool(json_get(root, "tx_truncated"))
        && strcmp(json_get_str(json_at(json_get(root, "tx"), 0)),
                  API_TEST_TXID) == 0;
}

static bool api_lookup_blocks_show(uint8_t *resp, size_t cap, bool ok)
{
    struct json_value root;
    ok = api_get_request_json(resp, cap, "/api/v1/blocks/10", &root, ok);
    ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                      "zcl.blocks.show.v1") == 0;
    ok = ok && api_test_expect_freshness(&root, "served_height", 11, 11, true);
    ok = ok && json_get_int(json_get(&root, "height")) == 10;
    ok = ok && api_lookup_block_tx_fields(&root);
    json_free(&root);
    return ok;
}

static bool api_lookup_schema_and_int(uint8_t *resp, size_t cap, bool ok,
                                      const char *path, const char *schema,
                                      const char *field, int64_t expect)
{
    struct json_value root;
    ok = api_get_request_json(resp, cap, path, &root, ok);
    ok = ok && strcmp(json_get_str(json_get(&root, "schema")), schema) == 0;
    ok = ok && json_get_int(json_get(&root, field)) == expect;
    json_free(&root);
    return ok;
}

static bool api_lookup_transaction_show(uint8_t *resp, size_t cap, bool ok)
{
    struct json_value root;
    ok = api_get_request_json(resp, cap,
                              "/api/v1/transactions/" API_TEST_TXID,
                              &root, ok);
    ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                      "zcl.transactions.show.v1") == 0;
    ok = ok && api_test_expect_freshness(&root, "served_height", 11, 11, true);
    ok = ok && strcmp(json_get_str(json_get(&root, "txid")), API_TEST_TXID) == 0;
    const struct json_value *vout = json_get(&root, "vout");
    const struct json_value *vin = json_get(&root, "vin");
    ok = ok && json_get_int(json_get(&root, "vout_returned")) == 1;
    ok = ok && strcmp(json_get_str(json_get(json_at(vout, 0), "address")),
                      API_TEST_ADDR) == 0;
    ok = ok && json_get_int(json_get(json_at(vin, 0), "vout")) == 1;
    json_free(&root);
    return ok;
}

static bool api_lookup_address_show(uint8_t *resp, size_t cap, bool ok)
{
    struct json_value root;
    ok = api_get_request_json(resp, cap,
                              "/api/v1/addresses/" API_TEST_ADDR,
                              &root, ok);
    ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                      "zcl.addresses.show.v1") == 0;
    ok = ok && api_test_expect_freshness(&root, "utxo_projection",
                                         11, 11, true);
    ok = ok && json_get_int(json_get(&root, "balance_sat")) == 123456789;
    ok = ok && json_get_int(json_get(&root, "utxo_count")) == 1;
    const struct json_value *utxos = json_get(&root, "utxos");
    ok = ok && strcmp(json_get_str(json_get(json_at(utxos, 0), "txid")),
                      API_TEST_TXID) == 0;
    json_free(&root);
    return ok;
}

static bool api_lookup_unversioned_tx(uint8_t *resp, size_t cap, bool ok)
{
    struct json_value root;
    ok = api_get_request_json(resp, cap, "/api/tx/" API_TEST_TXID, &root, ok);
    ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                      "zcl.transactions.show.v1") == 0;
    json_free(&root);
    return ok;
}

static int api_lookup_rest_freshness_case(uint8_t *resp, size_t cap)
{
    printf("api: lookup resources emit REST schemas and freshness... ");
    reducer_frontier_provable_tip_reset();
    reducer_frontier_provable_tip_set(11);
    api_test_set_rpc_call(api_test_lookup_rpc);
    bool ok = api_lookup_blocks_show(resp, cap, true);
    ok = api_lookup_schema_and_int(resp, cap, ok, "/api/v1/block/10",
                                   "zcl.blocks.show.v1", "height", 10);
    ok = api_lookup_transaction_show(resp, cap, ok);
    ok = api_lookup_address_show(resp, cap, ok);
    ok = api_lookup_schema_and_int(resp, cap, ok,
                                   "/api/v1/address/" API_TEST_ADDR,
                                   "zcl.addresses.show.v1", "balance_sat",
                                   123456789);
    ok = api_lookup_unversioned_tx(resp, cap, ok);
    api_test_set_rpc_call(NULL);
    reducer_frontier_provable_tip_reset();
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); return 1; }
    return 0;
}

static int api_events_envelope_case(uint8_t *resp, size_t cap)
{
    printf("api: events resource emits REST envelope and freshness... ");
    event_log_init();
    progress_store_close();
    reducer_frontier_provable_tip_reset();
    api_set_state(NULL, NULL, NULL, NULL, NULL);
    event_emitf(EV_NODE_READY, 0, "height=4 peers=1");
    struct json_value root;
    bool ok = api_get_request_json(resp, cap, "/api/events?limit=5&type=sys.",
                                   &root, true);
    ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                      "zcl.events.index.v1") == 0;
    ok = ok && api_test_expect_freshness(&root, "event_projection", 0, 0, true);
    ok = ok && strcmp(json_get_str(json_get(&root, "type")), "sys.") == 0;
    ok = ok && json_get_int(json_get(&root, "limit")) == 5;
    const struct json_value *events = json_get(&root, "events");
    ok = ok && events && json_size(events) == 1;
    ok = ok && strcmp(json_get_str(json_get(json_at(events, 0), "type")),
                      "sys.ready") == 0;
    json_free(&root);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); return 1; }
    return 0;
}

/* ── /api/v1/coins/roots ─────────────────────────────────────────────── */

struct coin_roots_holder {
    atomic_int held;
    atomic_int release;
};

static void *coin_roots_hold_progress_lock(void *arg)
{
    struct coin_roots_holder *h = arg;
    progress_store_tx_lock();
    atomic_store(&h->held, 1);
    for (int i = 0; i < 5000 && !atomic_load(&h->release); i++)
        platform_sleep_ms(1);
    progress_store_tx_unlock();
    return NULL;
}

static char g_coin_roots_last[1100];

static bool coin_roots_get(const char *path, struct json_value *root,
                           char *status, size_t status_cap)
{
    uint8_t resp[16384];
    size_t n = api_handle_request("GET", path, NULL, 0, resp, sizeof(resp));
    const char *body = api_test_body(resp, n, sizeof(resp));
    snprintf(status, status_cap, "%.12s", n > 9 ? (const char *)resp + 9 : "");
    snprintf(g_coin_roots_last, sizeof(g_coin_roots_last), "%.*s",
             (int)(n < 1000 ? n : 1000), (const char *)resp);
    json_init(root);
    return n > 0 && body && json_read(root, body, strlen(body));
}

/* Entry i of "roots" has the expected height, found flag and, when found, the
 * expected root, block hash and active-chain flag. */
static bool coin_roots_entry_is(const struct json_value *root, size_t i,
                                int height, const char *want_root,
                                const char *want_hash, bool want_active)
{
    const struct json_value *e = json_at(json_get(root, "roots"), i);
    const struct json_value *rv = e ? json_get(e, "root") : NULL;
    const struct json_value *hv = e ? json_get(e, "block_hash") : NULL;
    if (!e || json_get_int(json_get(e, "height")) != height ||
        json_get_bool(json_get(e, "found")) != (want_root != NULL))
        return false;
    if (!want_root)
        return rv == NULL && hv == NULL;
    return rv && hv && strcmp(json_get_str(rv), want_root) == 0 &&
           strcmp(json_get_str(hv), want_hash) == 0 &&
           json_get_bool(json_get(e, "on_active_chain")) == want_active;
}

struct coin_roots_fx {
    char r100[65], r200[65], h100[65], h200[65], tip_hex[65];
};

static bool coin_roots_listing_case(const struct coin_roots_fx *fx)
{
    struct json_value root;
    char status[16];
    bool ok = coin_roots_get("/api/v1/coins/roots", &root, status,
                             sizeof(status));
    ok = ok && strncmp(status, "200", 3) == 0;
    ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                      "zcl.coin_roots.v1") == 0;
    ok = ok && strcmp(json_get_str(json_get(&root, "root_byte_order")),
                      "internal") == 0;
    ok = ok && strcmp(json_get_str(json_get(&root, "hash_byte_order")),
                      "display") == 0;
    ok = ok && json_get_int(json_get(&root, "tip_height")) == 350;
    ok = ok && strcmp(json_get_str(json_get(&root, "tip_hash")),
                      fx->tip_hex) == 0;
    ok = ok && json_get(&root, "full_history_validation_origin") &&
         json_get(&root, "snapshot_utxo_sha3_verified") &&
         strstr(json_get_str(json_get(&root, "comparison_note")),
                "do not prove") != NULL;
    /* 300 has only a legacy row (never served); 200 is bound to a hash that is
     * not the active chain's block; 100 is bound to the active block. */
    ok = ok && json_size(json_get(&root, "roots")) == 3 &&
         coin_roots_entry_is(&root, 0, 300, NULL, NULL, false) &&
         coin_roots_entry_is(&root, 1, 200, fx->r200, fx->h200, false) &&
         coin_roots_entry_is(&root, 2, 100, fx->r100, fx->h100, true);
    json_free(&root);
    return ok;
}

static bool coin_roots_selection_case(const struct coin_roots_fx *fx)
{
    struct json_value root;
    char status[16];
    bool ok = coin_roots_get("/api/v1/coins/roots?height=100", &root, status,
                             sizeof(status)) &&
              strncmp(status, "200", 3) == 0 &&
              json_size(json_get(&root, "roots")) == 1 &&
              coin_roots_entry_is(&root, 0, 100, fx->r100, fx->h100, true);
    json_free(&root);
    /* Above the tip: labelled, never read from the store. */
    ok = ok && coin_roots_get("/api/v1/coins/roots?height=400", &root, status,
                              sizeof(status)) &&
         json_size(json_get(&root, "roots")) == 1 &&
         coin_roots_entry_is(&root, 0, 400, NULL, NULL, false) &&
         json_get_bool(json_get(json_at(json_get(&root, "roots"), 0),
                                "above_tip"));
    json_free(&root);
    ok = ok && coin_roots_get("/api/v1/coins/roots?count=1", &root, status,
                              sizeof(status)) &&
         json_size(json_get(&root, "roots")) == 1 &&
         json_get_int(json_get(json_at(json_get(&root, "roots"), 0),
                               "height")) == 300;
    json_free(&root);
    return ok;
}

static bool coin_roots_rejects_case(void)
{
    static const char *const bad[] = {
        "/api/v1/coins/roots?count=0", "/api/v1/coins/roots?count=101",
        "/api/v1/coins/roots?count=x", "/api/v1/coins/roots?height=150",
        "/api/v1/coins/roots?height=-100", "/api/v1/coins/roots?height=",
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        struct json_value root;
        char status[16];
        ok = coin_roots_get(bad[i], &root, status, sizeof(status)) && ok &&
             strncmp(status, "400", 3) == 0 &&
             json_get_str(json_get(&root, "error")) != NULL;
        json_free(&root);
    }
    struct json_value root;
    char status[16];
    ok = coin_roots_get("/api/v1/coins/roots?count=100", &root, status,
                        sizeof(status)) && ok &&
         strncmp(status, "200", 3) == 0;
    json_free(&root);
    return ok;
}

static bool coin_roots_busy_case(void)
{
    struct coin_roots_holder h = {0};
    pthread_t t;
    struct json_value root;
    char status[16] = "";
    bool started = pthread_create(&t, NULL, coin_roots_hold_progress_lock,
                                  &h) == 0;
    for (int i = 0; started && i < 2000 && !atomic_load(&h.held); i++)
        platform_sleep_ms(1);
    bool ok = started && atomic_load(&h.held) &&
              coin_roots_get("/api/v1/coins/roots", &root, status,
                             sizeof(status));
    if (ok) {
        const char *err = json_get_str(json_get(&root, "error"));
        ok = strncmp(status, "503", 3) == 0 && err && strstr(err, "busy");
        json_free(&root);
    }
    if (started) {
        atomic_store(&h.release, 1);
        pthread_join(t, NULL);
    }
    return ok;
}

/* A record whose height has no block in the active-chain window reports
 * active_chain_unknown, never on_active_chain=false. */
static bool coin_roots_unknown_case(void)
{
    struct json_value root;
    char status[16];
    reducer_frontier_provable_tip_set(400);
    bool ok = coin_roots_get("/api/v1/coins/roots?height=400", &root, status,
                             sizeof(status)) &&
              strncmp(status, "200", 3) == 0;
    const struct json_value *e = ok ? json_at(json_get(&root, "roots"), 0)
                                    : NULL;
    ok = ok && e && json_get_bool(json_get(e, "found")) &&
         json_get_bool(json_get(e, "active_chain_unknown")) &&
         json_get(e, "on_active_chain") == NULL;
    if (status[0])
        json_free(&root);
    reducer_frontier_provable_tip_set(350);
    return ok;
}

/* A present but malformed record is a read error (500), not absence. */
static bool coin_roots_unreadable_case(sqlite3 *db)
{
    static const uint8_t bad[10] = {1};
    struct json_value root;
    char status[16];
    bool ok = progress_meta_set(db, "coin_root_v2:100", bad, sizeof(bad)) &&
              coin_roots_get("/api/v1/coins/roots?height=100", &root, status,
                             sizeof(status)) &&
              strncmp(status, "500", 3) == 0;
    json_free(&root);
    return ok;
}

static bool coin_roots_stage(bool ok, const char *name)
{
    if (!ok)
        printf("[%s failed; last response: %s] ", name, g_coin_roots_last);
    return ok;
}

/* The shared fixture chain holds 16 blocks; boundaries need heights >= 100. */
static bool coin_roots_build_chain(struct main_state *ms,
                                   struct block_index **blocks, int count)
{
    static struct uint256 hashes[351];
    struct block_index *prev = NULL;
    main_state_init(ms);
    if (count <= 0 || count > (int)(sizeof(hashes) / sizeof(hashes[0])))
        return false;
    for (int h = 0; h < count; h++) {
        prev = api_test_insert_block(ms, &hashes[h], h, prev);
        if (!prev)
            return false;
        blocks[h] = prev;
    }
    ms->pindex_best_header = prev;
    return active_chain_move_window_tip(&ms->chain_active, prev);
}

static bool coin_roots_seed(sqlite3 *db, struct block_index **blocks,
                            struct coin_roots_fx *fx)
{
    static const uint8_t k_root100[32] = { 0x58, 0x17, 0xf0, 0xec, 0x01 };
    static const uint8_t k_root200[32] = { 0xde, 0xad, 0xbe, 0xef, 0x02 };
    static const uint8_t k_legacy300[32] = { 0x99, 0x03 };
    uint8_t stale[32];
    memset(stale, 0x77, sizeof(stale));
    HexStr(k_root100, 32, false, fx->r100, sizeof(fx->r100));
    HexStr(k_root200, 32, false, fx->r200, sizeof(fx->r200));
    uint256_get_hex(blocks[100]->phashBlock, fx->h100);
    uint256_get_hex(blocks[350]->phashBlock, fx->tip_hex);
    {
        struct uint256 s;
        memcpy(s.data, stale, 32);
        uint256_get_hex(&s, fx->h200);
    }
    return coins_kv_boundary_record_set_in_tx(db, 100,
               blocks[100]->phashBlock->data, k_root100) &&
           coins_kv_boundary_record_set_in_tx(db, 200, stale, k_root200) &&
           coins_kv_boundary_root_set(db, 300, k_legacy300) &&
           coins_kv_boundary_record_set_in_tx(db, 400, stale, k_root200);
}

static int api_coin_roots_case(void)
{
    printf("api: coin roots route reports bound roots, bounds and busy... ");
    struct coin_roots_fx fx;
    memset(&fx, 0, sizeof(fx));
    char dbdir[256];
    struct main_state ms;
    struct block_index *blocks[351] = {0};

    test_reset_shared_globals();
    test_make_tmpdir(dbdir, sizeof(dbdir), "api_routes", "coin_roots");
    bool ok = coin_roots_stage(coin_roots_build_chain(&ms, blocks, 351),
                               "chain");
    ok = ok && coin_roots_stage(api_test_seed_durable_tip(dbdir, 350), "seed");
    sqlite3 *db = ok ? progress_store_db() : NULL;
    ok = ok && coin_roots_stage(db && coin_roots_seed(db, blocks, &fx),
                                "roots");
    if (ok) {
        reducer_frontier_provable_tip_set(350);
        api_set_state(&ms, NULL, NULL, NULL, dbdir);
    }
    ok = ok && coin_roots_stage(coin_roots_listing_case(&fx), "listing") &&
         coin_roots_stage(coin_roots_selection_case(&fx), "selection") &&
         coin_roots_stage(coin_roots_rejects_case(), "rejects") &&
         coin_roots_stage(coin_roots_unknown_case(), "unknown") &&
         coin_roots_stage(coin_roots_busy_case(), "busy") &&
         coin_roots_stage(coin_roots_unreadable_case(db), "unreadable");

    api_set_state(NULL, NULL, NULL, NULL, NULL);
    reducer_frontier_provable_tip_reset();
    progress_store_close();
    main_state_free(&ms);
    ok &= test_rm_rf_recursive(dbdir) == 0;
    test_reset_shared_globals();
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); return 1; }
    return 0;
}

static int api_empty_block_id_case(uint8_t *resp, size_t cap)
{
    printf("api: empty block ID not routed... ");
    size_t n = api_handle_request("GET", "/api/block/", NULL, 0, resp, cap);
    resp[n < cap ? n : cap - 1] = '\0';
    bool ok = (n > 0);
    if (ok) printf("OK (got response, %zu bytes)\n", n);
    else { printf("FAIL\n"); return 1; }
    return 0;
}

static int api_zero_length_response_case(uint8_t *resp)
{
    printf("api: zero-length response buffer returns 0... ");
    size_t n = api_handle_request("GET", "/api/blocks", NULL, 0, resp, 0);
    bool ok = (n == 0);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); return 1; }
    return 0;
}

int api_route_table_focused_tests(void)
{
    int failures = 0;
    uint8_t resp[8192];

    failures += api_milestone_ascii_bars_case(resp, sizeof(resp));

    failures += milestone_legacy_receipt_test();

    failures += api_refold_anchor_readiness_case(resp, sizeof(resp));

    failures += api_unsupported_version_case(resp, sizeof(resp));

    failures += api_controller_route_names_case();

    failures += api_fixed_route_command_paths_case();

    failures += api_route_command_parity_case();

    failures += api_dynamic_route_metadata_case();

    failures += api_lookup_rest_freshness_case(resp, sizeof(resp));

    failures += api_events_envelope_case(resp, sizeof(resp));

    failures += api_coin_roots_case();

    failures += api_empty_block_id_case(resp, sizeof(resp));
    failures += api_zero_length_response_case(resp);

    return failures;
}
