/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * api cases: the versioned discovery document, the application protocol catalog, and the sovereign service catalog and its operations.
 */

#include "test/syncdiag_rpc_fixture.h"

/* One assertion from the api-catalog cases. Rows are scanned in order and
 * stop at the first failure. use_flag, need_obj and need_type are the
 * leading && gates; op runs only after those gates pass. */
enum {
    SYNC_API_CAT_OP_TRUE = 1,
    SYNC_API_CAT_OP_STR_EQ,
    SYNC_API_CAT_OP_ARR_HAS,
    SYNC_API_CAT_OP_SUBSTR,
    SYNC_API_CAT_OP_BOOL,
    SYNC_API_CAT_OP_INT_GE,
    SYNC_API_CAT_OP_INT_EQ,
    SYNC_API_CAT_OP_SIZE_GE,
    SYNC_API_CAT_OP_SIZE_EQ,
    SYNC_API_CAT_OP_COUNT_EQ_SIZE,
    SYNC_API_CAT_OP_FIND
};

struct syncdiag_api_catalog_check {
    int op;
    int obj;
    int other;
    int flag;
    bool use_flag;
    bool need_obj;
    bool need_type;
    enum json_type type;
    const char *key;
    const char *str;
    int n;
};

static bool syncdiag_api_catalog_row_passes(
    const struct json_value **objs,
    const struct syncdiag_api_catalog_check *row)
{
    const struct json_value *obj = objs[row->obj];
    const struct json_value *other = objs[row->other];

    switch (row->op) {
    case SYNC_API_CAT_OP_STR_EQ:
        return strcmp(json_get_str(json_get(obj, row->key)), row->str) == 0;
    case SYNC_API_CAT_OP_ARR_HAS:
        return json_array_has_str(json_get(obj, row->key), row->str);
    case SYNC_API_CAT_OP_SUBSTR:
        return strstr(json_get_str(json_get(obj, row->key)), row->str) != NULL;
    case SYNC_API_CAT_OP_BOOL:
        return json_get_bool(json_get(obj, row->key));
    case SYNC_API_CAT_OP_INT_GE:
        return json_get_int(json_get(obj, row->key)) >= row->n;
    case SYNC_API_CAT_OP_INT_EQ:
        return json_get_int(json_get(obj, row->key)) == row->n;
    case SYNC_API_CAT_OP_SIZE_GE:
        return json_size(obj) >= (size_t)row->n;
    case SYNC_API_CAT_OP_SIZE_EQ:
        return json_size(obj) == (size_t)row->n;
    case SYNC_API_CAT_OP_COUNT_EQ_SIZE:
        return json_get_int(json_get(other, row->key)) ==
               (int64_t)json_size(obj);
    case SYNC_API_CAT_OP_FIND:
        return find_object_with_str(obj, row->key, row->str) != NULL;
    default:
        return false;
    }
}

static bool syncdiag_api_catalog_rows_pass(
    const struct json_value **objs,
    const bool *flags,
    const struct syncdiag_api_catalog_check *rows,
    size_t n)
{
    bool ok = true;

    for (size_t i = 0; ok && i < n; i++) {
        const struct syncdiag_api_catalog_check *row = &rows[i];
        bool gate = true;

        if (row->use_flag)
            gate = gate && flags[row->flag];
        if (row->need_obj)
            gate = gate && objs[row->obj] != NULL;
        if (row->need_type && gate)
            gate = objs[row->obj]->type == row->type;
        if (row->op == SYNC_API_CAT_OP_TRUE)
            ok = gate;
        else
            ok = gate && syncdiag_api_catalog_row_passes(objs, row);
    }
    return ok;
}

static int syncdiag_case_versioned_discovery(void)
{
    enum {
        OBJ_RESULT = 0,
        OBJ_RESOURCES,
        OBJ_CLI
    };
    enum { FL_EXECUTED = 0 };

    printf("api: native RPC returns versioned discovery document... ");
    struct rpc_table tbl;
    rpc_table_init(&tbl);
    register_event_rpc_commands(&tbl);
    if (rpc_is_in_warmup(NULL, 0))
        set_rpc_warmup_finished();

    struct json_value params;
    json_init(&params);
    json_set_array(&params);

    struct json_value result;
    json_init(&result);

    bool executed = rpc_table_execute(&tbl, "api", &params, &result);
    const struct json_value *resources = json_get(&result, "resources");
    const struct json_value *cli = json_get(&result, "cli");

    static const struct syncdiag_api_catalog_check head[] = {
        { .op = SYNC_API_CAT_OP_TRUE, .obj = OBJ_RESULT,
          .flag = FL_EXECUTED, .use_flag = true, .need_type = true,
          .type = JSON_OBJ },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_RESULT,
          .key = "schema", .str = "zcl.rest_index.v2" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_RESULT,
          .key = "api_version", .str = "v1" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_RESULT,
          .key = "base_path", .str = "/api/v1" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_RESULT,
          .key = "compat_base_path", .str = "/api" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_RESULT,
          .key = "first_call", .str = "/api/v1/agent" },
        { .op = SYNC_API_CAT_OP_SIZE_GE, .obj = OBJ_RESOURCES,
          .need_obj = true, .need_type = true, .type = JSON_ARR, .n = 4 },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_CLI, .need_obj = true,
          .need_type = true, .type = JSON_OBJ,
          .key = "api_command", .str = "z23 api" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_CLI,
          .key = "app_protocols_command", .str = "z23 appprotocols" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_CLI,
          .key = "service_catalog_command", .str = "z23 servicecatalog" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_CLI,
          .key = "service_operations_command",
          .str = "z23 serviceoperations [operation_id|key=value...]" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_CLI,
          .key = "first_command", .str = "z23 agent" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_CLI,
          .key = "map_command", .str = "z23 agentmap" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_CLI,
          .key = "lanes_command", .str = "z23 agentlanes" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_CLI,
          .key = "impact_command", .str = "z23 agentimpact <files...>" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_CLI,
          .key = "contracts_command", .str = "z23 agentcontracts" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_CLI,
          .key = "build_command", .str = "z23 agentbuild" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_CLI,
          .key = "interface_command", .str = "z23 agentinterface" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_CLI,
          .key = "deploy_guard_command",
          .str = "z23 agentdeployguard [action]" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_CLI,
          .key = "drilldown_command", .str = "z23 healthcheck" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_CLI,
          .key = "milestone_command", .str = "z23 milestone" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_CLI,
          .key = "refold_command", .str = "z23 refold" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_CLI,
          .key = "peer_incidents_command", .str = "z23 peerincidents" },
    };
    const struct json_value *objs[] = { &result, resources, cli };
    const bool flags[] = { executed };
    bool ok = syncdiag_api_catalog_rows_pass(
        objs, flags, head, sizeof head / sizeof head[0]);

    struct json_value alias;
    json_init(&alias);
    bool alias_executed = rpc_table_execute(&tbl, "apiindex",
                                            &params, &alias);

    static const struct syncdiag_api_catalog_check alias_rows[] = {
        { .op = SYNC_API_CAT_OP_STR_EQ, .use_flag = true, .need_type = true,
          .type = JSON_OBJ, .key = "schema", .str = "zcl.rest_index.v2" },
    };
    const struct json_value *alias_objs[] = { &alias };
    const bool alias_flags[] = { alias_executed };
    ok = ok && syncdiag_api_catalog_rows_pass(
        alias_objs, alias_flags, alias_rows,
        sizeof alias_rows / sizeof alias_rows[0]);

    json_free(&alias);
    json_free(&params);
    json_free(&result);

    int failures = 0;
    if (ok) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }
    return failures;
}

static int syncdiag_case_application_protocol_catalog(void)
{
    enum {
        OBJ_RESULT = 0,
        OBJ_PROTOCOLS,
        OBJ_ZLSP,
        OBJ_ZSLP,
        OBJ_ZNAM,
        OBJ_MARKET,
        OBJ_SCRIPT
    };

    printf("api: native RPC returns application protocol catalog... ");
    struct rpc_table tbl;
    rpc_table_init(&tbl);
    register_event_rpc_commands(&tbl);
    if (rpc_is_in_warmup(NULL, 0))
        set_rpc_warmup_finished();

    struct json_value params;
    json_init(&params);
    json_set_array(&params);

    struct json_value result;
    json_init(&result);

    bool executed = rpc_table_execute(&tbl, "appprotocols",
                                      &params, &result);
    const struct json_value *protocols =
        json_get(&result, "protocols");
    const struct json_value *zlsp =
        find_object_with_str(protocols, "name", "zlsp");
    const struct json_value *zslp =
        find_object_with_str(protocols, "name", "zslp");
    const struct json_value *znam =
        find_object_with_str(protocols, "name", "znam");
    const struct json_value *market =
        find_object_with_str(protocols, "name", "market");
    const struct json_value *script_contracts =
        find_object_with_str(protocols, "name", "script_contracts");

    static const struct syncdiag_api_catalog_check head[] = {
        { .op = SYNC_API_CAT_OP_TRUE, .obj = OBJ_RESULT,
          .use_flag = true, .need_type = true, .type = JSON_OBJ },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_RESULT,
          .key = "schema", .str = "zcl.application_protocols.index.v2" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_RESULT,
          .key = "base_layer", .str = "zclassic_l1" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_RESULT,
          .key = "service_layer", .str = "zclassic23_application_layer" },
        { .op = SYNC_API_CAT_OP_COUNT_EQ_SIZE, .obj = OBJ_PROTOCOLS,
          .other = OBJ_RESULT, .need_obj = true, .need_type = true,
          .type = JSON_ARR, .key = "protocol_count" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_ZLSP, .need_obj = true,
          .key = "status", .str = "design" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_ZLSP, .need_obj = true,
          .key = "family", .str = "application_protocol_framework" },
        { .op = SYNC_API_CAT_OP_ARR_HAS, .obj = OBJ_ZLSP, .need_obj = true,
          .key = "crud_capabilities", .str = "construct_transaction" },
        { .op = SYNC_API_CAT_OP_ARR_HAS, .obj = OBJ_ZSLP, .need_obj = true,
          .key = "crud_capabilities", .str = "read_collection" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_ZSLP, .need_obj = true,
          .key = "anchor_kind", .str = "op_return" },
        { .op = SYNC_API_CAT_OP_ARR_HAS, .obj = OBJ_ZSLP, .need_obj = true,
          .key = "object_types", .str = "token_genesis" },
        { .op = SYNC_API_CAT_OP_ARR_HAS, .obj = OBJ_ZNAM, .need_obj = true,
          .key = "ux_surfaces", .str = "identity_profile" },
        { .op = SYNC_API_CAT_OP_SUBSTR, .obj = OBJ_ZNAM, .need_obj = true,
          .key = "crypto_model", .str = "owner_authority" },
        { .op = SYNC_API_CAT_OP_ARR_HAS, .obj = OBJ_MARKET, .need_obj = true,
          .key = "object_types", .str = "signed_listing" },
        { .op = SYNC_API_CAT_OP_SUBSTR, .obj = OBJ_MARKET, .need_obj = true,
          .key = "privacy_model", .str = "allowlist" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_SCRIPT, .need_obj = true,
          .key = "anchor_kind", .str = "standard_script" },
        { .op = SYNC_API_CAT_OP_SUBSTR, .obj = OBJ_SCRIPT, .need_obj = true,
          .key = "crypto_model", .str = "legacy_valid_zclassic_script" },
    };
    const struct json_value *objs[] = {
        &result, protocols, zlsp, zslp, znam, market, script_contracts
    };
    const bool flags[] = { executed };
    bool ok = syncdiag_api_catalog_rows_pass(
        objs, flags, head, sizeof head / sizeof head[0]);

    struct json_value alias;
    json_init(&alias);
    bool alias_executed = rpc_table_execute(&tbl, "protocols",
                                            &params, &alias);

    static const struct syncdiag_api_catalog_check alias_rows[] = {
        { .op = SYNC_API_CAT_OP_STR_EQ, .use_flag = true,
          .key = "schema", .str = "zcl.application_protocols.index.v2" },
    };
    const struct json_value *alias_objs[] = { &alias };
    const bool alias_flags[] = { alias_executed };
    ok = ok && syncdiag_api_catalog_rows_pass(
        alias_objs, alias_flags, alias_rows,
        sizeof alias_rows / sizeof alias_rows[0]);

    json_free(&alias);
    json_free(&params);
    json_free(&result);

    int failures = 0;
    if (ok) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }
    return failures;
}

static int syncdiag_case_sovereign_service_catalog(void)
{
    enum {
        OBJ_RESULT = 0,
        OBJ_UX,
        OBJ_SERVICES,
        OBJ_BOOTSTRAP
    };
    enum {
        OBJ_NAMES = 0,
        OBJ_ONION,
        OBJ_CONTRACTS
    };

    printf("api: native RPC returns sovereign service catalog... ");
    struct rpc_table tbl;
    rpc_table_init(&tbl);
    register_event_rpc_commands(&tbl);
    if (rpc_is_in_warmup(NULL, 0))
        set_rpc_warmup_finished();

    struct json_value params;
    json_init(&params);
    json_set_array(&params);

    struct json_value result;
    json_init(&result);

    bool executed = rpc_table_execute(&tbl, "servicecatalog",
                                      &params, &result);
    const struct json_value *services = json_get(&result, "services");
    const struct json_value *bootstrap =
        find_object_with_str(services, "name", "bootstrap");
    const struct json_value *names =
        find_object_with_str(services, "name", "znam_names");
    const struct json_value *onion =
        find_object_with_str(services, "name", "onion_directory");
    const struct json_value *contracts =
        find_object_with_str(services, "name", "script_contracts");

    static const struct syncdiag_api_catalog_check opened[] = {
        { .op = SYNC_API_CAT_OP_TRUE, .use_flag = true, .need_type = true,
          .type = JSON_OBJ },
        { .op = SYNC_API_CAT_OP_STR_EQ,
          .key = "schema", .str = "zcl.service_catalog.v2" },
        { .op = SYNC_API_CAT_OP_STR_EQ,
          .key = "base_layer", .str = "zclassic_l1" },
    };
    const struct json_value *opened_objs[] = { &result };
    const bool executed_flag[] = { executed };
    bool ok = syncdiag_api_catalog_rows_pass(
        opened_objs, executed_flag, opened,
        sizeof opened / sizeof opened[0]);

    const struct json_value *ux = json_get(&result, "sovereign_ux");

    static const struct syncdiag_api_catalog_check listed[] = {
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_UX, .need_obj = true,
          .key = "schema", .str = "zcl.sovereign_ux_contract.v2" },
        { .op = SYNC_API_CAT_OP_ARR_HAS, .obj = OBJ_UX, .need_obj = true,
          .key = "flow", .str = "verify_service_records" },
        { .op = SYNC_API_CAT_OP_ARR_HAS, .obj = OBJ_UX, .need_obj = true,
          .key = "primary_entities", .str = "endpoint_record" },
        { .op = SYNC_API_CAT_OP_COUNT_EQ_SIZE, .obj = OBJ_SERVICES,
          .other = OBJ_RESULT, .need_obj = true, .need_type = true,
          .type = JSON_ARR, .key = "service_count" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_BOOTSTRAP,
          .need_obj = true, .key = "rest_collection",
          .str = "/api/v1/bootstrap" },
        { .op = SYNC_API_CAT_OP_ARR_HAS, .obj = OBJ_BOOTSTRAP,
          .need_obj = true, .key = "transports", .str = "p2p" },
        { .op = SYNC_API_CAT_OP_ARR_HAS, .obj = OBJ_BOOTSTRAP,
          .need_obj = true, .key = "depends_on_services",
          .str = "full_node" },
    };
    const struct json_value *listed_objs[] = {
        &result, ux, services, bootstrap
    };
    ok = ok && syncdiag_api_catalog_rows_pass(
        listed_objs, executed_flag, listed,
        sizeof listed / sizeof listed[0]);

    /* The first lookup is unused; the original still performs it here. */
    const struct json_value *bootstrap_status_op =
        find_object_with_str(json_get(bootstrap, "operations"),
                             "operation", "read_bootstrap_status");

    static const struct syncdiag_api_catalog_check name_rows[] = {
        { .op = SYNC_API_CAT_OP_STR_EQ, .need_obj = true,
          .key = "application_protocol", .str = "znam" },
        { .op = SYNC_API_CAT_OP_ARR_HAS, .need_obj = true,
          .key = "crud_capabilities", .str = "construct_transaction" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .need_obj = true,
          .key = "read_model",
          .str = "znam_projection_confirmed_chain_records" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .need_obj = true,
          .key = "write_model",
          .str = "construct_znam_op_return_transactions" },
    };
    const struct json_value *name_objs[] = { names };
    ok = ok && syncdiag_api_catalog_rows_pass(
        name_objs, executed_flag, name_rows,
        sizeof name_rows / sizeof name_rows[0]);

    const struct json_value *name_register_op =
        find_object_with_str(json_get(names, "operations"), "operation",
                             "construct_name_register");

    static const struct syncdiag_api_catalog_check register_rows[] = {
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = 0, .need_obj = true,
          .key = "rpc_method", .str = "name_register" },
        { .op = SYNC_API_CAT_OP_BOOL, .obj = 0, .need_obj = true,
          .key = "destructive" },
        { .op = SYNC_API_CAT_OP_ARR_HAS, .obj = OBJ_ONION, .need_obj = true,
          .key = "transports", .str = "onion" },
        { .op = SYNC_API_CAT_OP_SUBSTR, .obj = OBJ_CONTRACTS,
          .need_obj = true, .key = "verified_by",
          .str = "zclassic_script" },
    };
    const struct json_value *register_objs[] = {
        name_register_op, onion, contracts
    };
    ok = ok && syncdiag_api_catalog_rows_pass(
        register_objs, executed_flag, register_rows,
        sizeof register_rows / sizeof register_rows[0]);

    struct json_value alias;
    json_init(&alias);
    bool alias_executed = rpc_table_execute(&tbl, "service_catalog",
                                            &params, &alias);

    static const struct syncdiag_api_catalog_check alias_rows[] = {
        { .op = SYNC_API_CAT_OP_STR_EQ, .use_flag = true,
          .key = "schema", .str = "zcl.service_catalog.v2" },
    };
    const struct json_value *alias_objs[] = { &alias };
    const bool alias_flags[] = { alias_executed };
    ok = ok && syncdiag_api_catalog_rows_pass(
        alias_objs, alias_flags, alias_rows,
        sizeof alias_rows / sizeof alias_rows[0]);

    struct json_value one_params;
    json_init(&one_params);
    json_set_array(&one_params);
    struct json_value one_name;
    json_init(&one_name);
    json_set_str(&one_name, "bootstrap");
    json_push_back(&one_params, &one_name);
    json_free(&one_name);

    struct json_value one;
    json_init(&one);
    bool one_executed = rpc_table_execute(&tbl, "servicecatalog",
                                          &one_params, &one);

    static const struct syncdiag_api_catalog_check one_rows[] = {
        { .op = SYNC_API_CAT_OP_STR_EQ, .use_flag = true,
          .key = "schema", .str = "zcl.service_contract.v2" },
        { .op = SYNC_API_CAT_OP_STR_EQ,
          .key = "name", .str = "bootstrap" },
        { .op = SYNC_API_CAT_OP_STR_EQ,
          .key = "self_route",
          .str = "/api/v1/service-catalog/bootstrap" },
        { .op = SYNC_API_CAT_OP_ARR_HAS,
          .key = "transports", .str = "p2p" },
        { .op = SYNC_API_CAT_OP_ARR_HAS,
          .key = "depends_on_services", .str = "full_node" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .key = "read_model",
          .str = "network_bootstrap_status_and_peer_projection" },
    };
    const struct json_value *one_objs[] = { &one };
    const bool one_flags[] = { one_executed };
    ok = ok && syncdiag_api_catalog_rows_pass(
        one_objs, one_flags, one_rows, sizeof one_rows / sizeof one_rows[0]);

    bootstrap_status_op = find_object_with_str(json_get(&one,
                         "operations"), "operation",
                         "read_bootstrap_status");

    static const struct syncdiag_api_catalog_check status_rows[] = {
        { .op = SYNC_API_CAT_OP_STR_EQ, .need_obj = true,
          .key = "rpc_method", .str = "bootstrapstatus" },
    };
    const struct json_value *status_objs[] = { bootstrap_status_op };
    ok = ok && syncdiag_api_catalog_rows_pass(
        status_objs, executed_flag, status_rows,
        sizeof status_rows / sizeof status_rows[0]);

    struct json_value bad_params;
    json_init(&bad_params);
    json_set_array(&bad_params);
    struct json_value bad_name;
    json_init(&bad_name);
    json_set_str(&bad_name, "not_real");
    json_push_back(&bad_params, &bad_name);
    json_free(&bad_name);

    struct json_value bad;
    json_init(&bad);
    bool bad_executed = rpc_table_execute(&tbl, "servicecatalog",
                                          &bad_params, &bad);

    static const struct syncdiag_api_catalog_check bad_rows[] = {
        { .op = SYNC_API_CAT_OP_STR_EQ, .use_flag = true,
          .key = "schema", .str = "zcl.service_catalog_error.v1" },
        { .op = SYNC_API_CAT_OP_ARR_HAS,
          .key = "valid_services", .str = "bootstrap" },
    };
    const struct json_value *bad_objs[] = { &bad };
    const bool bad_flags[] = { bad_executed };
    ok = ok && syncdiag_api_catalog_rows_pass(
        bad_objs, bad_flags, bad_rows, sizeof bad_rows / sizeof bad_rows[0]);

    json_free(&bad);
    json_free(&bad_params);
    json_free(&one);
    json_free(&one_params);
    json_free(&alias);
    json_free(&params);
    json_free(&result);

    int failures = 0;
    if (ok) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }
    return failures;
}

static int syncdiag_case_sovereign_service_operations(void)
{
    enum {
        OBJ_RESULT = 0,
        OBJ_SUMMARY,
        OBJ_OPERATIONS,
        OBJ_BOOTSTRAP_OP,
        OBJ_NAME_OP
    };
    enum {
        OBJ_FILTERED = 0,
        OBJ_FILTERS,
        OBJ_FILTERED_SUMMARY,
        OBJ_FILTERED_OPS
    };

    printf("api: native RPC returns sovereign service operations... ");
    struct rpc_table tbl;
    rpc_table_init(&tbl);
    register_event_rpc_commands(&tbl);
    if (rpc_is_in_warmup(NULL, 0))
        set_rpc_warmup_finished();

    struct json_value params;
    json_init(&params);
    json_set_array(&params);

    struct json_value result;
    json_init(&result);

    bool executed = rpc_table_execute(&tbl, "serviceoperations",
                                      &params, &result);
    const struct json_value *summary = json_get(&result, "summary");
    const struct json_value *operations = json_get(&result, "operations");
    const struct json_value *bootstrap_op =
        find_object_with_str(operations, "operation_id",
                             "bootstrap.read_bootstrap_status");
    const struct json_value *name_op =
        find_object_with_str(operations, "operation_id",
                             "znam_names.resolve_name");

    static const struct syncdiag_api_catalog_check head[] = {
        { .op = SYNC_API_CAT_OP_TRUE, .obj = OBJ_RESULT, .use_flag = true,
          .need_type = true, .type = JSON_OBJ },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_RESULT,
          .key = "schema", .str = "zcl.service_operations.index.v2" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_RESULT,
          .key = "catalog_route", .str = "/api/v1/service-catalog" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_RESULT,
          .key = "member_route",
          .str = "/api/v1/service-operations/{operation_id}" },
        { .op = SYNC_API_CAT_OP_INT_GE, .obj = OBJ_SUMMARY, .need_obj = true,
          .key = "operation_count", .n = 20 },
        { .op = SYNC_API_CAT_OP_COUNT_EQ_SIZE, .obj = OBJ_OPERATIONS,
          .other = OBJ_RESULT, .need_obj = true, .need_type = true,
          .type = JSON_ARR, .key = "operation_count" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_BOOTSTRAP_OP,
          .need_obj = true, .key = "rest_route",
          .str = "/api/v1/bootstrap" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_BOOTSTRAP_OP,
          .need_obj = true, .key = "agent_preferred_interface",
          .str = "rest" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_NAME_OP, .need_obj = true,
          .key = "crud_capability", .str = "read_item" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_NAME_OP, .need_obj = true,
          .key = "authority", .str = "confirmed_chain_projection" },
    };
    const struct json_value *objs[] = {
        &result, summary, operations, bootstrap_op, name_op
    };
    const bool flags[] = { executed };
    bool ok = syncdiag_api_catalog_rows_pass(
        objs, flags, head, sizeof head / sizeof head[0]);

    struct json_value alias;
    json_init(&alias);
    bool alias_executed = rpc_table_execute(&tbl, "service_operations",
                                            &params, &alias);

    static const struct syncdiag_api_catalog_check alias_rows[] = {
        { .op = SYNC_API_CAT_OP_STR_EQ, .use_flag = true,
          .key = "schema", .str = "zcl.service_operations.index.v2" },
    };
    const struct json_value *alias_objs[] = { &alias };
    const bool alias_flags[] = { alias_executed };
    ok = ok && syncdiag_api_catalog_rows_pass(
        alias_objs, alias_flags, alias_rows,
        sizeof alias_rows / sizeof alias_rows[0]);

    struct json_value one_params;
    json_init(&one_params);
    json_set_array(&one_params);
    struct json_value operation_id;
    json_init(&operation_id);
    json_set_str(&operation_id, "bootstrap.read_bootstrap_status");
    json_push_back(&one_params, &operation_id);
    json_free(&operation_id);

    struct json_value one;
    json_init(&one);
    bool one_executed = rpc_table_execute(&tbl, "serviceoperation",
                                          &one_params, &one);

    static const struct syncdiag_api_catalog_check one_rows[] = {
        { .op = SYNC_API_CAT_OP_STR_EQ, .use_flag = true,
          .key = "schema", .str = "zcl.service_operation.v2" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .key = "operation_id",
          .str = "bootstrap.read_bootstrap_status" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .key = "self_route",
          .str = "/api/v1/service-operations/"
                 "bootstrap.read_bootstrap_status" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .key = "write_safety",
          .str = "public_read_only" },
    };
    const struct json_value *one_objs[] = { &one };
    const bool one_flags[] = { one_executed };
    ok = ok && syncdiag_api_catalog_rows_pass(
        one_objs, one_flags, one_rows, sizeof one_rows / sizeof one_rows[0]);

    struct json_value bad_params;
    json_init(&bad_params);
    json_set_array(&bad_params);
    struct json_value bad_id;
    json_init(&bad_id);
    json_set_str(&bad_id, "not_real.nope");
    json_push_back(&bad_params, &bad_id);
    json_free(&bad_id);

    struct json_value bad;
    json_init(&bad);
    bool bad_executed = rpc_table_execute(&tbl, "serviceoperations",
                                          &bad_params, &bad);

    static const struct syncdiag_api_catalog_check bad_rows[] = {
        { .op = SYNC_API_CAT_OP_STR_EQ, .use_flag = true,
          .key = "schema", .str = "zcl.service_operation_error.v1" },
        { .op = SYNC_API_CAT_OP_STR_EQ,
          .key = "error", .str = "operation_not_found" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .key = "operation_collection_route",
          .str = "/api/v1/service-operations" },
    };
    const struct json_value *bad_objs[] = { &bad };
    const bool bad_flags[] = { bad_executed };
    ok = ok && syncdiag_api_catalog_rows_pass(
        bad_objs, bad_flags, bad_rows, sizeof bad_rows / sizeof bad_rows[0]);

    struct json_value filtered_params;
    json_init(&filtered_params);
    json_set_array(&filtered_params);
    struct json_value filter_arg;
    json_init(&filter_arg);
    json_set_str(&filter_arg, "service=bootstrap");
    json_push_back(&filtered_params, &filter_arg);
    json_set_str(&filter_arg, "write_safety=public_read_only");
    json_push_back(&filtered_params, &filter_arg);
    json_free(&filter_arg);

    struct json_value filtered;
    json_init(&filtered);
    bool filtered_executed =
        rpc_table_execute(&tbl, "serviceoperations",
                          &filtered_params, &filtered);
    const struct json_value *filtered_filters =
        json_get(&filtered, "filters");
    const struct json_value *filtered_summary =
        json_get(&filtered, "summary");
    const struct json_value *filtered_ops =
        json_get(&filtered, "operations");

    static const struct syncdiag_api_catalog_check filtered_rows[] = {
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_FILTERED,
          .use_flag = true, .key = "schema",
          .str = "zcl.service_operations.index.v2" },
        { .op = SYNC_API_CAT_OP_BOOL, .obj = OBJ_FILTERS, .need_obj = true,
          .key = "active" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_FILTERS, .need_obj = true,
          .key = "service", .str = "bootstrap" },
        { .op = SYNC_API_CAT_OP_STR_EQ, .obj = OBJ_FILTERS, .need_obj = true,
          .key = "write_safety", .str = "public_read_only" },
        { .op = SYNC_API_CAT_OP_INT_EQ, .obj = OBJ_FILTERED_SUMMARY,
          .need_obj = true, .key = "operation_count", .n = 2 },
        { .op = SYNC_API_CAT_OP_SIZE_EQ, .obj = OBJ_FILTERED_OPS,
          .need_obj = true, .need_type = true, .type = JSON_ARR, .n = 2 },
        { .op = SYNC_API_CAT_OP_FIND, .obj = OBJ_FILTERED_OPS,
          .key = "operation_id",
          .str = "bootstrap.read_bootstrap_status" },
        { .op = SYNC_API_CAT_OP_FIND, .obj = OBJ_FILTERED_OPS,
          .key = "operation_id",
          .str = "bootstrap.list_peer_projection" },
    };
    const struct json_value *filtered_objs[] = {
        &filtered, filtered_filters, filtered_summary, filtered_ops
    };
    const bool filtered_flags[] = { filtered_executed };
    ok = ok && syncdiag_api_catalog_rows_pass(
        filtered_objs, filtered_flags, filtered_rows,
        sizeof filtered_rows / sizeof filtered_rows[0]);

    json_free(&bad);
    json_free(&bad_params);
    json_free(&filtered);
    json_free(&filtered_params);
    json_free(&one);
    json_free(&one_params);
    json_free(&alias);
    json_free(&params);
    json_free(&result);

    int failures = 0;
    if (ok) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }
    return failures;
}

int syncdiag_cases_api_catalog(void)
{
    int failures = 0;

    failures += syncdiag_case_versioned_discovery();
    failures += syncdiag_case_application_protocol_catalog();
    failures += syncdiag_case_sovereign_service_catalog();
    failures += syncdiag_case_sovereign_service_operations();
    return failures;
}
