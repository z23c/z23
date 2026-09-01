/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Event log and sync state machine RPCs.
 * Canonical source for: eventlog, syncstate */

#include "controllers/event_controller.h"
#include "controllers/agent_controller.h"
#include "controllers/agent_copy_prove_controller.h"
#include "controllers/agent_test_controller.h"
#include "controllers/event_healthcheck_controller.h"
#include "controllers/event_timeline_controller.h"
#include "controllers/strong_params.h"
#include "api_controller_internal.h"
#include "event_agent_summary.h"
#include "controllers/event_operator_snapshot_controller.h"
#include "config/boot.h"
#include "services/bg_validation_service.h"
#include "services/block_index_integrity.h"
#include "services/chain_state_service.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "sync/sync_state.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "config/runtime.h"
#include "util/clientversion.h"
#include <stdlib.h>
#include <string.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"

static bool rpc_eventlog(const struct json_value *params, bool help,
                         struct json_value *result)
{
    RPC_HELP(help, result,
        "eventlog ( count )\n"
        "\nReturn recent events from the system event log.\n"
        "Every P2P message, state transition, block validation,\n"
        "and error is captured in a lock-free ring buffer.\n"
        "\nArguments:\n"
        "1. count     (numeric, optional, default=200) Number of events\n"
        "\nResult:\n"
        "  { \"sync_state\": \"...\", \"events\": [...] }\n");

    int count = 200;
    if (params && params->type == JSON_ARR && params->num_children > 0) {
        const struct json_value *v = &params->children[0];
        if (v->type == JSON_INT) count = (int)v->val.i;
        else if (v->type == JSON_REAL) count = (int)v->val.d;
    }
    if (count < 1) count = 1;
    if (count > 65536) count = 65536;

    size_t buf_size = (size_t)count * 256 + 256;
    if (buf_size > 16 * 1024 * 1024) buf_size = 16 * 1024 * 1024;
    char *buf = zcl_malloc(buf_size, "eventlog json buf");
    if (!buf) {
        json_set_str(result, "out of memory");
        return false;
    }

    size_t w = 0;
    w += (size_t)snprintf(buf + w, 256, "{\"sync_state\":\"%s\",\"events\":",
                           sync_state_name(sync_get_state()));
    w += event_dump_json(buf + w, buf_size - w, (size_t)count);
    if (w + 1 < buf_size) buf[w++] = '}';
    buf[w] = '\0';

    json_read(result, buf, w);
    free(buf);
    return true;
}

/* Last N chain.reorg_* events from the ring buffer. Same shape as
 * eventlog, but filtered to the reorg family — exposes the on-the-wire
 * EV_REORG_START / EV_REORG_DISCONNECT_FAILED / EV_REORG_RECOVERY_COMPLETE
 * stream without parsing all 200+ general events client-side. */
static bool rpc_getreorghistory(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    RPC_HELP(help, result,
        "getreorghistory ( count )\n"
        "\nReturn recent chain.reorg_* events from the system event log.\n"
        "\nArguments:\n"
        "1. count     (numeric, optional, default=50) Max events\n"
        "\nResult:\n"
        "  { \"sync_state\": \"...\", \"reorgs\": [...] }\n");

    int count = 50;
    if (params && params->type == JSON_ARR && params->num_children > 0) {
        const struct json_value *v = &params->children[0];
        if (v->type == JSON_INT) count = (int)v->val.i;
        else if (v->type == JSON_REAL) count = (int)v->val.d;
    }
    if (count < 1) count = 1;
    if (count > 1024) count = 1024;

    size_t buf_size = (size_t)count * 256 + 256;
    char *buf = zcl_malloc(buf_size, "reorghistory json buf");
    if (!buf) {
        json_set_str(result, "out of memory");
        return false;
    }

    size_t w = 0;
    w += (size_t)snprintf(buf + w, 256, "{\"sync_state\":\"%s\",\"reorgs\":",
                           sync_state_name(sync_get_state()));
    w += event_dump_json_filtered(buf + w, buf_size - w,
                                   (size_t)count, "chain.reorg_");
    if (w + 1 < buf_size) buf[w++] = '}';
    buf[w] = '\0';

    json_read(result, buf, w);
    free(buf);
    return true;
}

static bool rpc_syncstate(const struct json_value *params, bool help,
                          struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "syncstate\n"
        "\nReturn the current sync state machine state.\n"
        "\nResult:\n"
        "  { \"state\": \"...\", \"state_id\": N }\n");

    json_set_object(result);
    json_push_kv_str(result, "state", sync_state_name(sync_get_state()));
    json_push_kv_int(result, "state_id", (int64_t)sync_get_state());
    json_push_kv_bool(result, "utxo_replay_active",
                      atomic_load(&g_utxo_replay_active));
    json_push_kv_int(result, "utxo_replay_height",
                     (int64_t)atomic_load(&g_utxo_replay_height));

    struct bii_recovery_status bii;
    bii_get_recovery_status(&bii);
    struct json_value bi = {0};
    json_set_object(&bi);
    json_push_kv_str(&bi, "verdict", bii_verdict_name(bii.verdict));
    json_push_kv_str(&bi, "action", bii_recovery_action_name(bii.action));
    json_push_kv_bool(&bi, "degraded", bii.degraded);
    json_push_kv_bool(&bi, "unsafe_override", bii.unsafe_override);
    json_push_kv_int(&bi, "last_check_unix", bii.unix_time);
    if (bii.reason[0])
        json_push_kv_str(&bi, "reason", bii.reason);
    json_push_kv(result, "block_index_integrity", &bi);
    json_free(&bi);
    return true;
}

static bool rpc_api_index(const struct json_value *params, bool help,
                          struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "api\n"
        "\nReturn the versioned zclassic23 API discovery document. This is the\n"
        "same JSON body served by GET /api and GET /api/v1, without HTTP\n"
        "headers, so native clients can start with `z23 api` instead\n"
        "of a shell helper or curl.\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.rest_index.v2\", \"base_path\":\"/api/v1\", "
        "\"first_call\":\"/api/v1/agent\" }\n");

    const char *body = api_rest_index_body_json();
    if (!json_read(result, body, strlen(body))) {
        json_set_object(result);
        json_push_kv_str(result, "schema", "zcl.rest_error.v1");
        json_push_kv_str(result, "error", "api_index_parse_failed");
        return false;
    }
    return true;
}

bool rpc_app_protocols(const struct json_value *params, bool help,
                       struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "appprotocols\n"
        "\nReturn the versioned zclassic23 application-protocol catalog. This\n"
        "is the same JSON body served by GET /api/v1/protocols.\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.application_protocols.index.v2\", "
        "\"base_layer\":\"zclassic_l1\", \"protocols\":[...] }\n");

    return api_app_protocols_index_json(result);
}

bool rpc_service_catalog(const struct json_value *params, bool help,
                         struct json_value *result)
{
    RPC_HELP(help, result,
        "servicecatalog ( name )\n"
        "\nReturn the versioned zclassic23 sovereign service catalog. This\n"
        "is the same JSON body served by GET /api/v1/service-catalog. Pass\n"
        "an optional service\n"
        "name to return the same contract as GET\n"
        "/api/v1/service-catalog/{service}.\n"
        "\nArguments:\n"
        "1. name      (string, optional) Service name, e.g. bootstrap\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.service_catalog.v2\", "
        "\"base_layer\":\"zclassic_l1\", \"services\":[...] }\n"
        "  or { \"schema\":\"zcl.service_contract.v2\", \"name\":\"...\" }\n");

    const char *name = NULL;
    if (params && params->type == JSON_ARR && params->num_children > 0)
        name = json_get_str(&params->children[0]);

    if (!name || !name[0])
        return api_service_catalog_json(result);

    if (api_service_catalog_show_json(name, result))
        return true;

    api_service_catalog_error_json(name, result);
    return true;
}

static void rpc_service_operation_error_json(const char *operation_id,
                                             struct json_value *result)
{
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.service_operation_error.v1");
    json_push_kv_str(result, "api_version", ZCL_REST_API_VERSION);
    json_push_kv_str(result, "error", "operation_not_found");
    json_push_kv_str(result, "operation_id",
                     operation_id ? operation_id : "");
    json_push_kv_str(result, "operation_collection_route",
                     "/api/v1/service-operations");
    json_push_kv_str(result, "operation_route",
                     "/api/v1/service-operations/{operation_id}");
    json_push_kv_str(result, "next_action",
                     "call_serviceoperations_without_arguments_then_select_"
                     "a_listed_operation_id");
}

static void rpc_service_operation_filter_error_json(const char *message,
                                                    struct json_value *result)
{
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.service_operation_error.v1");
    json_push_kv_str(result, "api_version", ZCL_REST_API_VERSION);
    json_push_kv_str(result, "error", "invalid_filter");
    json_push_kv_str(result, "message",
                     message && message[0] ? message :
                     "invalid service operation filter");
    json_push_kv_str(result, "allowed_filters",
                     "service,write_safety,preferred_interface,status,"
                     "surface");
    json_push_kv_str(result, "example",
                     "serviceoperations service=bootstrap "
                     "write_safety=public_read_only");
}

static void rpc_service_operation_filter_arg(
    const char *arg,
    char *service,
    size_t service_len,
    char *write_safety,
    size_t write_safety_len,
    char *preferred_interface,
    size_t preferred_interface_len,
    char *status,
    size_t status_len,
    char *surface,
    size_t surface_len)
{
    char key[40];
    const char *eq;
    size_t key_len;
    const char *value;

    if (!arg || !arg[0])
        return;
    eq = strchr(arg, '=');
    if (!eq || eq == arg || !eq[1])
        return;
    key_len = (size_t)(eq - arg);
    if (key_len >= sizeof(key))
        key_len = sizeof(key) - 1;
    memcpy(key, arg, key_len);
    key[key_len] = '\0';
    value = eq + 1;

    if (strcmp(key, "service") == 0 && service && service_len > 0)
        snprintf(service, service_len, "%s", value);
    else if (strcmp(key, "write_safety") == 0 &&
             write_safety && write_safety_len > 0)
        snprintf(write_safety, write_safety_len, "%s", value);
    else if ((strcmp(key, "preferred_interface") == 0 ||
              strcmp(key, "interface") == 0) &&
             preferred_interface && preferred_interface_len > 0)
        snprintf(preferred_interface, preferred_interface_len, "%s", value);
    else if (strcmp(key, "status") == 0 && status && status_len > 0)
        snprintf(status, status_len, "%s", value);
    else if (strcmp(key, "surface") == 0 && surface && surface_len > 0)
        snprintf(surface, surface_len, "%s", value);
}

bool rpc_service_operations(const struct json_value *params, bool help,
                            struct json_value *result)
{
    RPC_HELP(help, result,
        "serviceoperations ( operation_id | key=value... )\n"
        "\nReturn the versioned zclassic23 service-operation catalog. This\n"
        "is the same JSON body served by GET /api/v1/service-operations.\n"
        "Pass an optional\n"
        "service.operation id, such as znam_names.resolve_name, to return\n"
        "the same contract as GET /api/v1/service-operations/{operation_id}.\n"
        "Pass filters as key=value pairs for a bounded collection subset.\n"
        "\nArguments:\n"
        "1. operation_id (string, optional) Stable service.operation id\n"
        "   or key=value filters: service, write_safety,\n"
        "   preferred_interface, status, surface\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.service_operations.index.v2\", "
        "\"operations\":[...] }\n"
        "  or { \"schema\":\"zcl.service_operation.v2\", "
        "\"operation_id\":\"...\" }\n");

    const char *operation_id = NULL;
    const char *service = NULL;
    const char *write_safety = NULL;
    const char *preferred_interface = NULL;
    const char *status = NULL;
    const char *surface = NULL;
    char service_buf[64] = {0};
    char write_safety_buf[40] = {0};
    char preferred_interface_buf[32] = {0};
    char status_buf[32] = {0};
    char surface_buf[16] = {0};

    if (params && params->type == JSON_OBJ) {
        operation_id = json_get_str(json_get(params, "operation_id"));
        service = json_get_str(json_get(params, "service"));
        write_safety = json_get_str(json_get(params, "write_safety"));
        preferred_interface =
            json_get_str(json_get(params, "preferred_interface"));
        status = json_get_str(json_get(params, "status"));
        surface = json_get_str(json_get(params, "surface"));
    } else if (params && params->type == JSON_ARR &&
               params->num_children > 0) {
        const char *first = json_get_str(&params->children[0]);
        if (first && first[0] && !strchr(first, '='))
            operation_id = first;
        else {
            for (size_t i = 0; i < params->num_children; i++) {
                rpc_service_operation_filter_arg(
                    json_get_str(&params->children[i]),
                    service_buf, sizeof(service_buf),
                    write_safety_buf, sizeof(write_safety_buf),
                    preferred_interface_buf,
                    sizeof(preferred_interface_buf),
                    status_buf, sizeof(status_buf),
                    surface_buf, sizeof(surface_buf));
            }
            service = service_buf;
            write_safety = write_safety_buf;
            preferred_interface = preferred_interface_buf;
            status = status_buf;
            surface = surface_buf;
        }
    }

    if (!operation_id || !operation_id[0]) {
        char err[192] = {0};
        if (api_service_operations_filtered_index_json(
                result, service, write_safety, preferred_interface, status,
                surface, err, sizeof(err)))
            return true;
        rpc_service_operation_filter_error_json(err, result);
        return true;
    }

    if (api_service_operation_show_json(operation_id, result))
        return true;

    rpc_service_operation_error_json(operation_id, result);
    return true;
}

static bool rpc_milestone_status(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "milestone\n"
        "\nReturn node-computed ASCII and JSON progress toward the next "
        "version milestone.\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.milestone_status.v2\", "
        "\"milestone\":\"v1 MVP\", \"mvp_readiness_score\":4, "
        "\"ascii\":{\"goals\":\"goals [#####-----] 4/8 ...\"} }\n");

    api_milestone_status_json(result);
    return true;
}

static bool rpc_refold_status(const struct json_value *params, bool help,
                              struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "refold\n"
        "\nReturn read-only self-verified UTXO anchor rebuild readiness. "
        "This checks whether zclassic23 has a locally rebuilt UTXO anchor "
        "that can replace the borrowed snapshot seed. Internal boot flag: "
        "-refold-from-anchor.\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.refold_status.v2\", "
        "\"ready_for_refold\":false, "
        "\"primary_blocker\":\"missing_verified_anchor_snapshot\" }\n");

    api_refold_status_json(result);
    return true;
}

static const char *rpc_proof_bundle_param(const struct json_value *params,
                                          const char *key)
{
    if (!params || !key)
        return "";
    if (params->type == JSON_OBJ)
        return json_get_str(json_get(params, key));
    if (params->type == JSON_ARR && params->num_children > 0 &&
        (strcmp(key, "anchor_datadir") == 0 ||
         strcmp(key, "datadir") == 0))
        return json_get_str(&params->children[0]);
    return "";
}

static const char *rpc_proof_bundle_anchor_datadir(
    const struct json_value *params, char *buf, size_t buf_len)
{
    const char *p = rpc_proof_bundle_param(params, "anchor_datadir");
    if (!p || !p[0])
        p = rpc_proof_bundle_param(params, "datadir");
    if (!p || !p[0])
        p = getenv("ZCL_ANCHOR_MINT_DATADIR");
    if (p && p[0])
        return p;

    const char *home = getenv("HOME");
    if (home && home[0])
        snprintf(buf, buf_len, "%s/.zclassic-c23-anchor-mint", home);
    else
        snprintf(buf, buf_len, ".zclassic-c23-anchor-mint");
    return buf;
}

static void rpc_proof_bundle_push_json(
    struct json_value *result, const char *key,
    bool (*producer)(const struct json_value *, bool, struct json_value *),
    const struct json_value *params)
{
    struct json_value child;
    json_init(&child);
    if (producer && producer(params, false, &child))
        json_push_kv(result, key, &child);
    else {
        json_set_object(&child);
        json_push_kv_str(&child, "status", "error");
        json_push_kv_str(&child, "error", "proof_bundle_producer_failed");
        json_push_kv_str(&child, "producer", key ? key : "");
        json_push_kv(result, key, &child);
    }
    json_free(&child);
}

bool rpc_agent_proof_bundle(const struct json_value *params, bool help,
                            struct json_value *result)
{
    RPC_HELP(help, result,
        "proofbundle [anchor_datadir]\n"
        "\nReturn one read-only operator evidence artifact. The bundle\n"
        "composes live agent status, MVP proof metadata, refold readiness,\n"
        "offline anchor mint status, lane topology, and dev-lane status.\n"
        "\nArguments:\n"
        "1. anchor_datadir (string, optional) Anchor mint datadir. Defaults\n"
        "   to ZCL_ANCHOR_MINT_DATADIR or ~/.zclassic-c23-anchor-mint.\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.operator_proof_bundle.v2\", "
        "\"proofs\":{...}, \"anchor_status\":{...} }\n");

    char anchor_default[600];
    const char *anchor_datadir =
        rpc_proof_bundle_anchor_datadir(params, anchor_default,
                                        sizeof(anchor_default));

    struct json_value no_params;
    struct json_value anchor_params;
    struct json_value anchor_value;
    json_init(&no_params);
    json_set_array(&no_params);
    json_init(&anchor_params);
    json_set_array(&anchor_params);
    json_init(&anchor_value);
    json_set_str(&anchor_value, anchor_datadir);
    json_push_back(&anchor_params, &anchor_value);
    json_free(&anchor_value);

    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.operator_proof_bundle.v2");
    json_push_kv_str(result, "api_version", "v1");
    json_push_kv_int(result, "captured_at_unix", platform_time_wall_unix());
    json_push_kv_str(result, "build_commit", zcl_build_commit());
    json_push_kv_str(result, "artifact_contract",
                     "read-only JSON body; redirect stdout to save it");
    json_push_kv_str(result, "anchor_datadir", anchor_datadir);

    struct json_value commands;
    json_init(&commands);
    json_set_object(&commands);
    json_push_kv_str(&commands, "native",
                     "z23 proofbundle [anchor_datadir]");
    json_push_kv_str(&commands, "save_example",
                     "build/bin/z23 proofbundle > build/proofs/operator-proof.json");
    json_push_kv_str(&commands, "anchor_status",
                     "z23 anchorstatus [anchor_datadir]");
    json_push_kv_str(&commands, "mvp_status", "z23 milestone");
    json_push_kv_str(&commands, "refold_status", "z23 refold");
    json_push_kv(result, "commands", &commands);
    json_free(&commands);

    rpc_proof_bundle_push_json(result, "agent", rpc_agent_summary,
                               &no_params);
    rpc_proof_bundle_push_json(result, "milestone",
                               rpc_milestone_status, &no_params);
    rpc_proof_bundle_push_json(result, "refold",
                               rpc_refold_status, &no_params);
    rpc_proof_bundle_push_json(result, "anchor_status",
                               rpc_agent_anchor_status, &anchor_params);
    rpc_proof_bundle_push_json(result, "lanes",
                               rpc_agent_lanes, &no_params);
    rpc_proof_bundle_push_json(result, "dev_status",
                               rpc_agent_dev_status, &no_params);

    struct json_value next;
    json_init(&next);
    json_set_array(&next);
    struct json_value item;
    json_init(&item);
    json_set_str(&item,
                 "when anchor_status.summary becomes anchor_snapshot_present, run the copy-prove refold cutover gates");
    json_push_back(&next, &item);
    json_set_str(&item,
                 "use milestone.operator_proofs.items for remaining MRS 4/8 -> 8/8 evidence");
    json_push_back(&next, &item);
    json_set_str(&item,
                 "deploy fresh development builds to the dev lane before canonical");
    json_push_back(&next, &item);
    json_free(&item);
    json_push_kv(result, "next", &next);
    json_free(&next);

    json_free(&anchor_params);
    json_free(&no_params);
    return true;
}

static bool rpc_validationstatus(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "validationstatus\n"
        "\nReturn background full validation progress.\n"
        "\nAfter fast sync (FlyClient + SHA3), the node verifies every\n"
        "historical signature, zk-SNARK proof, and Equihash solution\n"
        "in a background thread using parallel script verification.\n"
        "\nResult:\n"
        "  { \"state\": \"...\", \"verified_height\": N, \"chain_height\": N,\n"
        "    \"percent\": N.N, \"sigs_verified\": N, \"proofs_verified\": N,\n"
        "    \"blocks_per_sec\": N }\n");

    json_set_object(result);

    if (!g_bg_validation) {
        json_push_kv_str(result, "state", "not_initialized");
        return true;
    }

    struct bg_validation_progress p = bg_validation_get_progress(g_bg_validation);
    json_push_kv_str(result, "state",
                     bg_validation_state_name((enum bg_validation_state)p.state));
    json_push_kv_int(result, "verified_height", (int64_t)p.verified_height);
    json_push_kv_int(result, "chain_height", (int64_t)p.chain_height);

    double pct = 0.0;
    if (p.chain_height > 0)
        pct = 100.0 * (double)(p.verified_height + 1) / (double)(p.chain_height + 1);
    /* Format as fixed-point integer (10x percent) for JSON compatibility */
    json_push_kv_int(result, "percent_x10", (int64_t)(pct * 10.0));

    json_push_kv_int(result, "sigs_verified", p.sigs_verified);
    json_push_kv_int(result, "proofs_verified", p.proofs_verified);
    json_push_kv_int(result, "blocks_per_sec", p.blocks_per_sec);

    return true;
}

static bool rpc_resetvalidation(const struct json_value *params, bool help,
                                struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "resetvalidation\n"
        "\nReset background validation and re-verify all blocks from genesis.\n"
        "\nResult:\n"
        "  { \"reset\": true }\n");

    json_set_object(result);
    if (g_bg_validation) {
        bg_validation_reset(g_bg_validation);
        json_push_kv_bool(result, "reset", true);
    } else {
        json_push_kv_bool(result, "reset", false);
        json_push_kv_str(result, "error", "bg_validation not initialized");
    }
    return true;
}

void register_event_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "control", "eventlog",          rpc_eventlog,          true },
        { "control", "timeline",          rpc_timeline,          true },
        { "control", "api",               rpc_api_index,         true },
        { "control", "apiindex",          rpc_api_index,         true },
        { "control", "appprotocols",      rpc_app_protocols,     true },
        { "control", "protocols",         rpc_app_protocols,     true },
        { "control", "servicecatalog",    rpc_service_catalog,   true },
        { "control", "service_catalog",   rpc_service_catalog,   true },
        { "control", "serviceoperations", rpc_service_operations, true },
        { "control", "serviceoperation",  rpc_service_operations, true },
        { "control", "service_operations",rpc_service_operations, true },
        { "control", "agent",             rpc_agent_summary,     true },
        { "control", "status",            rpc_agent_summary,     true },
        { "control", "summary",           rpc_agent_summary,     true },
        { "control", "operatorsummary",   rpc_agent_summary,     true },
        { "control", "operatorsnapshot",  rpc_operator_snapshot, true },
        { "control", "agentmap",          rpc_agent_map,         true },
        { "control", "agentlanes",        rpc_agent_lanes,       true },
        { "control", "agentliveness",     rpc_agent_liveness,    true },
        { "control", "agentimpact",       rpc_agent_impact,      true },
        { "control", "agentcontracts",    rpc_agent_contracts,   true },
        { "control", "agentbuild",        rpc_agent_build,       true },
        { "control", "agentdevstatus",    rpc_agent_dev_status,  true },
        { "control", "anchorstatus",      rpc_agent_anchor_status, true },
        { "control", "proofbundle",       rpc_agent_proof_bundle, true },
        { "control", "agentinterface",    rpc_agent_interface,   true },
        { "control", "agentops",          rpc_agent_ops,         true },
        { "control", "agentdiagnose",     rpc_agent_diagnose,    true },
        { "control", "agentdeployguard",  rpc_agent_deploy_guard, true },
        { "control", "agentcopyprove",    rpc_agent_copy_prove,  true },
        { "control", "agenttest",         rpc_agent_test,        true },
        { "control", "milestone",         rpc_milestone_status,  true },
        { "control", "mvpstatus",         rpc_milestone_status,  true },
        { "control", "refold",            rpc_refold_status,     true },
        { "control", "refoldstatus",      rpc_refold_status,     true },
        { "control", "getreorghistory",   rpc_getreorghistory,   true },
        { "control", "syncstate",         rpc_syncstate,         true },
        { "control", "healthcheck",       rpc_healthcheck,       true },
        { "control", "validationstatus",  rpc_validationstatus,  true },
        { "control", "resetvalidation",   rpc_resetvalidation,   true },
    };

    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
