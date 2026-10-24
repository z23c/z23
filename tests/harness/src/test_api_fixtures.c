/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Shared fixtures for the API controller test group. Declared in
 * test/api_test_fixtures.h; see that header for how the group is laid out. */

#include "test/api_test_fixtures.h"

/* Private, per-process datadir for api_set_state().
 *
 * The controller stores the pointer rather than copying, and it outlives the
 * block that set it, so this buffer has static lifetime. It replaces a bare
 * "/tmp": handlers derive "<datadir>/node.db" and hand the datadir to the
 * explorer and file controllers, which is machine-shared state a concurrent
 * copy of this suite could write underneath us. */
const char *api_test_datadir(void)
{
    static char dir[512];
    if (dir[0] == '\0') {
        test_fmt_tmpdir(dir, sizeof(dir), "api", "datadir");
        mkdir("test-tmp", 0755);
        mkdir(dir, 0755);
    }
    return dir;
}

int api_test_write_rpc(char *out, size_t outmax, const char *json)
{
    size_t len;

    if (!out || outmax == 0 || !json)
        return 0;
    len = strlen(json);
    if (len >= outmax)
        len = outmax - 1;
    memcpy(out, json, len);
    out[len] = '\0';
    return (int)len;
}

int api_test_lookup_rpc(const char *method,
                               const char *params_json,
                               char *out,
                               size_t outmax)
{
    (void)params_json;

    if (strcmp(method, "getblockhash") == 0)
        return api_test_write_rpc(out, outmax,
            "{\"result\":\"" API_TEST_BLOCK_HASH "\",\"error\":null}");
    if (strcmp(method, "getblock") == 0)
        return api_test_write_rpc(out, outmax,
            "{\"result\":{\"hash\":\"" API_TEST_BLOCK_HASH "\","
            "\"height\":10,\"time\":1700000010,\"size\":1234,"
            "\"difficulty\":12.5,\"confirmations\":2,"
            "\"merkleroot\":\"abababababababababababababababababababababababababababababababab\","
            "\"previousblockhash\":\"" API_TEST_PREV_HASH "\","
            "\"nextblockhash\":\"" API_TEST_NEXT_HASH "\","
            "\"nonce\":\"01020304\","
            "\"tx\":[\"" API_TEST_TXID "\",\"" API_TEST_TXID2 "\"]},"
            "\"error\":null}");
    if (strcmp(method, "getrawtransaction") == 0)
        return api_test_write_rpc(out, outmax,
            "{\"result\":{\"txid\":\"" API_TEST_TXID "\","
            "\"version\":4,\"size\":456,\"locktime\":0,"
            "\"confirmations\":2,\"blockhash\":\"" API_TEST_BLOCK_HASH "\","
            "\"height\":10,\"valuebalance\":0,"
            "\"vout\":[{\"n\":0,\"value\":1.25,"
            "\"scriptPubKey\":{\"addresses\":[\"" API_TEST_ADDR "\"]}}],"
            "\"vin\":[{\"txid\":\"" API_TEST_TXID2 "\",\"vout\":1}]},"
            "\"error\":null}");
    if (strcmp(method, "getaddressbalance") == 0)
        return api_test_write_rpc(out, outmax,
            "{\"result\":{\"balance\":123456789},\"error\":null}");
    if (strcmp(method, "getaddressutxos") == 0)
        return api_test_write_rpc(out, outmax,
            "{\"result\":[{\"txid\":\"" API_TEST_TXID "\","
            "\"outputIndex\":0,\"satoshis\":123456789,\"height\":10}],"
            "\"error\":null}");
    return 0;
}

const struct json_value *api_test_find_contract(
    const struct json_value *routes,
    const char *path)
{
    if (!routes || !path)
        return NULL;
    for (size_t i = 0; i < json_size(routes); i++) {
        const struct json_value *item = json_at(routes, i);
        const char *item_path = json_get_str(json_get(item, "path"));
        if (item_path && strcmp(item_path, path) == 0)
            return item;
    }
    return NULL;
}

bool api_test_contract_has_query(const struct json_value *contract,
                                        const char *name)
{
    const struct json_value *params = json_get(contract, "query_params");
    if (!params || !name)
        return false;
    for (size_t i = 0; i < json_size(params); i++) {
        const char *param = json_get_str(json_at(params, i));
        if (param && strcmp(param, name) == 0)
            return true;
    }
    return false;
}

bool api_test_contract_has_id_param(const struct json_value *contract,
                                           const char *name)
{
    const struct json_value *params = json_get(contract, "id_params");
    if (!params || !name)
        return false;
    for (size_t i = 0; i < json_size(params); i++) {
        const char *param = json_get_str(json_at(params, i));
        if (param && strcmp(param, name) == 0)
            return true;
    }
    return false;
}

bool api_test_array_has_str(const struct json_value *arr,
                                   const char *needle)
{
    if (!arr || !needle)
        return false;
    for (size_t i = 0; i < json_size(arr); i++) {
        const char *value = json_get_str(json_at(arr, i));
        if (value && strcmp(value, needle) == 0)
            return true;
    }
    return false;
}

const struct json_value *api_test_find_named(
    const struct json_value *arr,
    const char *name)
{
    if (!arr || !name)
        return NULL;
    for (size_t i = 0; i < json_size(arr); i++) {
        const struct json_value *item = json_at(arr, i);
        const char *item_name = json_get_str(json_get(item, "name"));
        if (item_name && strcmp(item_name, name) == 0)
            return item;
    }
    return NULL;
}

const struct json_value *api_test_find_str_field(
    const struct json_value *arr,
    const char *field,
    const char *value)
{
    if (!arr || !field || !value)
        return NULL;
    for (size_t i = 0; i < json_size(arr); i++) {
        const struct json_value *item = json_at(arr, i);
        const char *item_value = json_get_str(json_get(item, field));
        if (item_value && strcmp(item_value, value) == 0)
            return item;
    }
    return NULL;
}

/* True when obj's string field equals expected. The strcmp is the same call
 * the open-coded checks made, so a NULL field faults exactly as before. */
static bool api_test_field_str_is(const struct json_value *obj,
                                  const char *field, const char *expected)
{
    return strcmp(json_get_str(json_get(obj, field)), expected) == 0;
}

/* True when every named field is present on obj. */
static bool api_test_fields_present(const struct json_value *obj,
                                    const char *const *fields, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (!json_get(obj, fields[i]))
            return false;
    }
    return true;
}

/* Fields the readiness document must carry: the root object's and the
 * readiness object's. Presence only; values are checked by the caller. */
static const char *const api_test_readiness_root_fields[] = {
    "readiness_status", "chain_serving_ready", "index_projection_ready",
    "agent_work_ready", "operator_action_required", "readiness_next_action",
};

static const char *const api_test_readiness_fields[] = {
    "status", "chain_serving_ready", "index_projection_ready",
    "agent_work_ready", "operator_action_required", "tip_gap_blocks",
    "index_gap_blocks", "reducer_log_gap_blocks", "next_action", "semantics",
};

/* Fields the security posture object must carry. Presence only. */
static const char *const api_test_security_posture_fields[] = {
    "status", "review_required", "public_serving_allowed",
    "bootstrap_model", "snapshot_full_validation_complete",
    "full_history_validation_complete", "full_history_validation_origin",
    "full_history_validation_state", "anchor_cursor_known",
    "anchor_history_complete", "sprout_anchor_activation_cursor",
    "sapling_anchor_activation_cursor", "anchor_history_state",
    "nullifier_history_complete", "nullifier_activation_cursor",
    "nullifier_history_state", "next_action",
};

/* One runtime probe row must agree with its service's own probe, the route
 * contract it names and the operation it names. */
static bool api_test_runtime_probe_row_ok(
    const struct json_value *probe,
    const struct json_value *services,
    const struct json_value *operations,
    const struct json_value *route_contracts)
{
    const char *service = json_get_str(json_get(probe, "service"));
    const char *route = json_get_str(json_get(probe, "route"));
    const char *expected_schema =
        json_get_str(json_get(probe, "expected_schema"));
    const char *operation_id =
        json_get_str(json_get(probe, "operation_id"));
    const struct json_value *svc =
        api_test_find_named(services, service);
    const struct json_value *member_probe =
        svc ? json_get(svc, "runtime_probe") : NULL;
    const struct json_value *route_contract =
        api_test_find_contract(route_contracts, route);
    const struct json_value *operation =
        api_test_find_str_field(operations, "operation_id", operation_id);

    if (!svc || !member_probe || !route_contract || !operation)
        return false;
    if (!api_test_field_str_is(probe, "schema",
                               "zcl.service_runtime_probe.v1"))
        return false;
    if (!api_test_field_str_is(member_probe, "route", route))
        return false;
    if (!api_test_field_str_is(member_probe, "operation_id", operation_id))
        return false;
    if (!api_test_field_str_is(member_probe, "expected_schema",
                               expected_schema))
        return false;
    return api_test_field_str_is(route_contract, "response_schema",
                                 expected_schema);
}

bool api_test_runtime_probes_consistent(
    const struct json_value *catalog,
    const struct json_value *operations,
    const struct json_value *route_contracts)
{
    const struct json_value *services;
    const struct json_value *probes;

    if (!catalog || !operations || !route_contracts)
        return false;

    services = json_get(catalog, "services");
    probes = json_get(catalog, "runtime_probes");
    if (!services || services->type != JSON_ARR ||
        !probes || probes->type != JSON_ARR)
        return false;
    if (json_size(probes) != json_size(services))
        return false;
    if (json_get_int(json_get(catalog, "runtime_probe_count")) !=
        (int64_t)json_size(probes))
        return false;

    for (size_t i = 0; i < json_size(probes); i++) {
        if (!api_test_runtime_probe_row_ok(json_at(probes, i), services,
                                           operations, route_contracts))
            return false;
    }

    return true;
}

/* The operation and its route binding must carry every field the route
 * check compares. An empty string counts as missing. */
static bool api_test_rest_operation_fields_present(
    const struct json_value *operation,
    const struct json_value *binding)
{
    const char *operation_id =
        json_get_str(json_get(operation, "operation_id"));
    const char *service = json_get_str(json_get(operation, "service"));
    const char *rest_method =
        json_get_str(json_get(operation, "rest_method"));
    const char *rest_route =
        json_get_str(json_get(operation, "rest_route"));
    const char *output_schema =
        json_get_str(json_get(operation, "output_schema"));

    return operation_id && operation_id[0] && service && service[0] &&
           rest_method && rest_method[0] && rest_route && rest_route[0] &&
           output_schema && output_schema[0] && binding;
}

/* The route contract's own fields must agree with the operation. */
static bool api_test_route_contract_matches_operation(
    const struct json_value *operation,
    const struct json_value *route_contract)
{
    if (!api_test_field_str_is(route_contract, "method",
            json_get_str(json_get(operation, "rest_method"))))
        return false;
    if (!api_test_field_str_is(route_contract, "response_schema",
            json_get_str(json_get(operation, "output_schema"))))
        return false;
    if (!api_test_field_str_is(route_contract, "service_contract",
            json_get_str(json_get(operation, "service"))))
        return false;
    if (!api_test_field_str_is(route_contract, "service_catalog_route",
            json_get_str(json_get(operation, "service_catalog_route"))))
        return false;
    if (!api_test_field_str_is(route_contract, "service_operation_id",
            json_get_str(json_get(operation, "operation_id"))))
        return false;
    return api_test_field_str_is(route_contract, "service_operation_route",
            json_get_str(json_get(operation, "self_route")));
}

/* The service binding must name the same operation, service, route, schema
 * and catalog route as the operation. */
static bool api_test_service_binding_matches_operation(
    const struct json_value *operation,
    const struct json_value *binding)
{
    if (!api_test_field_str_is(binding, "operation_id",
            json_get_str(json_get(operation, "operation_id"))))
        return false;
    if (!api_test_field_str_is(binding, "service",
            json_get_str(json_get(operation, "service"))))
        return false;
    if (!api_test_field_str_is(binding, "rest_route",
            json_get_str(json_get(operation, "rest_route"))))
        return false;
    if (!api_test_field_str_is(binding, "output_schema",
            json_get_str(json_get(operation, "output_schema"))))
        return false;
    return api_test_field_str_is(binding, "service_catalog_route",
            json_get_str(json_get(operation, "service_catalog_route")));
}

bool api_test_rest_operation_route_matches(
    const struct json_value *operation,
    const struct json_value *route_contract,
    const char *expected_route)
{
    const struct json_value *binding;
    const char *rest_route;

    if (!operation || !route_contract || !expected_route)
        return false;

    binding = json_get(route_contract, "service_binding");
    if (!api_test_rest_operation_fields_present(operation, binding))
        return false;
    rest_route = json_get_str(json_get(operation, "rest_route"));
    if (strcmp(rest_route, expected_route) != 0)
        return false;
    if (!api_test_route_contract_matches_operation(operation, route_contract))
        return false;

    return api_test_service_binding_matches_operation(operation, binding);
}

/* Every REST-callable operation needs a route contract that matches it.
 * Sets *count to the number of REST-callable operations seen. */
static bool api_test_rest_operations_routed(
    const struct json_value *operations,
    const struct json_value *route_contracts,
    size_t *count)
{
    *count = 0;
    for (size_t i = 0; i < json_size(operations); i++) {
        const struct json_value *op = json_at(operations, i);
        const char *route = json_get_str(json_get(op, "rest_route"));
        const struct json_value *contract;

        if (!json_get_bool(json_get(op, "rest_callable")))
            continue;

        (*count)++;
        contract = api_test_find_contract(route_contracts, route);
        if (!contract ||
            !api_test_rest_operation_route_matches(op, contract, route))
            return false;
    }
    return true;
}

/* Every route contract with a service binding needs a REST-callable
 * operation that matches it. Sets *count to the number of bindings seen. */
static bool api_test_route_bindings_matched(
    const struct json_value *operations,
    const struct json_value *route_contracts,
    size_t *count)
{
    *count = 0;
    for (size_t i = 0; i < json_size(route_contracts); i++) {
        const struct json_value *contract = json_at(route_contracts, i);
        const struct json_value *binding =
            json_get(contract, "service_binding");
        const char *operation_id;
        const char *path;
        const char *alias_of;
        const char *expected_route;
        const struct json_value *op;

        if (!binding)
            continue;

        (*count)++;
        operation_id = json_get_str(json_get(binding, "operation_id"));
        op = api_test_find_str_field(operations, "operation_id",
                                     operation_id);
        path = json_get_str(json_get(contract, "path"));
        alias_of = json_get_str(json_get(contract, "legacy_alias_of"));
        expected_route = alias_of && alias_of[0] ? alias_of : path;

        if (!op || !json_get_bool(json_get(op, "rest_callable")) ||
            !api_test_rest_operation_route_matches(op, contract,
                                                   expected_route))
            return false;
    }
    return true;
}

bool api_test_rest_service_operations_bound(
    const struct json_value *operations,
    const struct json_value *route_contracts)
{
    size_t rest_operation_count = 0;
    size_t route_binding_count = 0;

    if (!operations || operations->type != JSON_ARR ||
        !route_contracts || route_contracts->type != JSON_ARR)
        return false;

    if (!api_test_rest_operations_routed(operations, route_contracts,
                                         &rest_operation_count))
        return false;
    if (!api_test_route_bindings_matched(operations, route_contracts,
                                         &route_binding_count))
        return false;

    return rest_operation_count > 0 &&
           route_binding_count >= rest_operation_count;
}

bool api_test_expect_readiness_shape(const struct json_value *root)
{
    const struct json_value *readiness = json_get(root, "readiness");
    if (!readiness || readiness->type != JSON_OBJ)
        return false;

    if (!api_test_field_str_is(readiness, "schema",
                               "zcl.agent_readiness.v1"))
        return false;
    if (!api_test_fields_present(root, api_test_readiness_root_fields,
            sizeof(api_test_readiness_root_fields) /
            sizeof(api_test_readiness_root_fields[0])))
        return false;
    if (json_get_int(json_get(readiness, "schema_version")) != 1)
        return false;

    return api_test_fields_present(readiness, api_test_readiness_fields,
            sizeof(api_test_readiness_fields) /
            sizeof(api_test_readiness_fields[0]));
}

bool api_test_expect_security_posture_shape(
    const struct json_value *root)
{
    const struct json_value *posture = json_get(root, "security_posture");
    if (!posture || posture->type != JSON_OBJ)
        return false;

    if (!api_test_field_str_is(posture, "schema",
                               "zcl.security_posture.v1"))
        return false;
    if (json_get_int(json_get(posture, "schema_version")) != 1)
        return false;
    if (!api_test_fields_present(posture, api_test_security_posture_fields,
            sizeof(api_test_security_posture_fields) /
            sizeof(api_test_security_posture_fields[0])))
        return false;

    return strstr(json_get_str(json_get(posture, "semantics")),
                  "public serving and healthy fail closed") != NULL;
}

bool api_test_expect_lane_safety_fields(
    const struct json_value *root, const char *lane,
    bool restart_ok, bool deploy_ok, bool requires,
    const char *target, const char *action)
{
    return strcmp(json_get_str(json_get(root, "operator_lane_name")),
                  lane) == 0 &&
           json_get_bool(json_get(root, "automation_restart_ok")) ==
               restart_ok &&
           json_get_bool(json_get(root, "automation_deploy_ok")) ==
               deploy_ok &&
           json_get_bool(json_get(root,
                                  "requires_operator_confirmation")) ==
               requires &&
           strcmp(json_get_str(json_get(root, "preferred_deploy_target")),
                  target) == 0 &&
           strcmp(json_get_str(json_get(root, "safe_default_action")),
                  action) == 0;
}

const struct json_value *api_test_openapi_get(
    const struct json_value *root,
    const char *path)
{
    const struct json_value *paths = json_get(root, "paths");
    const struct json_value *path_item = json_get(paths, path);
    return json_get(path_item, "get");
}

bool api_test_openapi_has_param(const struct json_value *operation,
                                       const char *name,
                                       const char *location)
{
    const struct json_value *params = json_get(operation, "parameters");
    if (!params || !name || !location)
        return false;
    for (size_t i = 0; i < json_size(params); i++) {
        const struct json_value *param = json_at(params, i);
        if (strcmp(json_get_str(json_get(param, "name")), name) == 0 &&
            strcmp(json_get_str(json_get(param, "in")), location) == 0)
            return true;
    }
    return false;
}

struct block_index *api_test_insert_block(struct main_state *ms,
                                                 struct uint256 *hash,
                                                 int height,
                                                 struct block_index *prev)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)(height & 0xff);
    hash->data[1] = (uint8_t)((height >> 8) & 0xff);
    hash->data[2] = 0x41;

    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!bi)
        return NULL;
    bi->nHeight = height;
    bi->nTime = 1000000 + (uint32_t)height * 150;
    bi->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
    bi->pprev = prev;
    return bi;
}

bool api_test_build_chain(struct main_state *ms,
                                 struct block_index **out,
                                 int count)
{
    static struct uint256 hashes[16];

    /* Initialize ms BEFORE the count check: every caller declares
     * `struct main_state ms;` uninitialized and runs main_state_free(&ms)
     * unconditionally, so a return above this line would hand
     * main_state_free() whatever the stack held. */
    main_state_init(ms);

    if (count <= 0 || count > (int)(sizeof(hashes) / sizeof(hashes[0])))
        return false;

    struct block_index *prev = NULL;
    for (int h = 0; h < count; h++) {
        out[h] = api_test_insert_block(ms, &hashes[h], h, prev);
        if (!out[h])
            return false;
        prev = out[h];
    }
    ms->pindex_best_header = out[count - 1];
    return active_chain_move_window_tip(&ms->chain_active, out[count - 1]);
}

bool api_test_seed_durable_tip(const char *dir, int height)
{
    if (!dir || height < 0)
        return false;

    progress_store_close();
    if (!progress_store_open(dir))
        return false;

    sqlite3 *db = progress_store_db();
    if (!db)
        return false;

    if (sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "work_delta_high INTEGER NOT NULL, work_delta_low INTEGER NOT NULL,"
        "utxo_size_after INTEGER NOT NULL, reorg_depth INTEGER NOT NULL,"
        "finalized_at INTEGER NOT NULL, tip_hash BLOB)",
        NULL, NULL, NULL) != SQLITE_OK)
        return false;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
        "VALUES('tip_finalize',?,0)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok)
        return false;

    uint8_t hash[32] = {0};
    hash[0] = (uint8_t)(height & 0xff);
    hash[1] = (uint8_t)((height >> 8) & 0xff);
    hash[2] = 0xA9;

    st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO tip_finalize_log "
        "(height,status,ok,work_delta_high,work_delta_low,utxo_size_after,"
        "reorg_depth,finalized_at,tip_hash) "
        "VALUES(?,'anchor',1,0,0,0,0,0,?)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash, sizeof(hash), SQLITE_TRANSIENT);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

bool api_test_init_connman_peer(struct connman *cm,
                                       struct net_address *addr,
                                       struct p2p_node **node_out,
                                       int height)
{
    if (!cm || !addr || !node_out)
        return false;
    memset(cm, 0, sizeof(*cm));
    memset(addr, 0, sizeof(*addr));
    net_manager_init(&cm->manager);
    cm->manager.nodes = zcl_calloc(1, sizeof(*cm->manager.nodes),
                                   "api_test_nodes");
    if (!cm->manager.nodes)
        return false;
    *node_out = p2p_node_create(&cm->manager, ZCL_INVALID_SOCKET, addr,
                                "api-status-peer", false);
    if (!*node_out)
        return false;
    (*node_out)->starting_height = height;
    (*node_out)->state = PEER_HANDSHAKE_COMPLETE;
    (*node_out)->services = NODE_NETWORK;
    cm->manager.nodes[0] = *node_out;
    cm->manager.num_nodes = 1;
    rpc_net_set_connman(cm);
    return true;
}

const char *api_test_body(uint8_t *resp, size_t n, size_t cap)
{
    resp[n < cap ? n : cap - 1] = '\0';
    const char *body = strstr((char *)resp, "\r\n\r\n");
    return body ? body + 4 : NULL;
}

bool api_test_expect_freshness(const struct json_value *root,
                                      const char *source_projection,
                                      int64_t served_height,
                                      int64_t indexed_height,
                                      bool fresh)
{
    if (!root || !source_projection)
        return false;
    const char *actual_source =
        json_get_str(json_get(root, "source_projection"));
    const char *actual_freshness =
        json_get_str(json_get(root, "freshness"));
    const char *actual_blocker = json_get_str(json_get(root, "blocker"));
    if (!actual_source || strcmp(actual_source, source_projection) != 0)
        return false;
    if (json_get_int(json_get(root, "served_height")) != served_height)
        return false;
    if (json_get_int(json_get(root, "indexed_height")) != indexed_height)
        return false;
    if (json_get_bool(json_get(root, "fresh")) != fresh)
        return false;
    if (fresh) {
        return actual_freshness && strcmp(actual_freshness, "fresh") == 0 &&
               actual_blocker && strcmp(actual_blocker, "none") == 0;
    }
    return actual_freshness && strcmp(actual_freshness, "fresh") != 0 &&
           actual_blocker && strcmp(actual_blocker, "none") != 0;
}

bool api_test_save_model_block(struct node_db *ndb, int height,
                                      uint8_t seed)
{
    struct db_block b;
    uint8_t solution[1] = {seed};

    memset(&b, 0, sizeof(b));
    memset(b.hash, seed, sizeof(b.hash));
    memset(b.prev_hash, seed + 1, sizeof(b.prev_hash));
    memset(b.merkle_root, seed + 2, sizeof(b.merkle_root));
    memset(b.nonce, seed + 3, sizeof(b.nonce));
    memset(b.chain_work, seed + 4, sizeof(b.chain_work));
    memset(b.sapling_root, seed + 5, sizeof(b.sapling_root));
    memset(b.sprout_root, seed + 6, sizeof(b.sprout_root));
    b.height = height;
    b.version = 4;
    b.time = (uint32_t)(1000000 + height * 75);
    b.bits = 1;
    b.solution = solution;
    b.solution_len = sizeof(solution);
    b.status = 3;
    b.num_tx = 1;
    return db_block_save(ndb, &b);
}

bool api_test_save_model_utxo(struct node_db *ndb, int height,
                                     uint8_t seed, int64_t value)
{
    struct db_utxo u;
    uint8_t script[1] = {0x51};

    memset(&u, 0, sizeof(u));
    memset(u.txid, seed, sizeof(u.txid));
    u.vout = 0;
    u.value = value;
    u.script = script;
    u.script_len = sizeof(script);
    u.script_type = SCRIPT_OTHER;
    u.height = height;
    return db_utxo_save(ndb, &u);
}
