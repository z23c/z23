/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API ZNAM name routes: the name list payload under oversized input and the
 * name show record set (service, address, and text records).
 */

#include "test/api_test_fixtures.h"
#include "base/safe_alloc.h"
#include "controllers/status_native_helpers.h"

/* Fixture cleanup without a shell: the path is absolute and may contain
 * spaces. A directory that is already gone counts as success, but only when
 * the directory itself is verified absent: the remover can also report
 * ENOENT for a nested entry while the root remains. */
static bool fixture_rm_ok(const char *dir)
{
    if (test_rm_rf_recursive(dir) == 0)
        return true;
    if (errno != ENOENT)
        return false;
    struct stat st;
    errno = 0;
    return lstat(dir, &st) != 0 && errno == ENOENT;
}

static unsigned directory_copy_blocks(const struct json_value *v)
{
    unsigned count = v && v->num_children > 0;
    for (size_t i = 0; v && i < v->num_children; i++)
        count += directory_copy_blocks(&v->children[i]);
    return count;
}

static int directory_copy_arm(unsigned event, void *ctx, void *stmt, void *time)
{
    (void)event;
    (void)time;
    const char *sql = sqlite3_sql(stmt);
    if (sql && strstr(sql, "SELECT name,coin_type,address FROM znam_addr_records")) {
        zcl_alloc_fault_fail_nth("json_copy_children", *(unsigned *)ctx);
        *(unsigned *)ctx = 0;
    }
    return 0;
}

static bool directory_copy_refuses(struct node_db *ndb, unsigned target)
{
    struct json_value result = {0};
    char err[192] = {0};
    size_t before = json_test_live_blocks();
    json_set_int(&result, 73);
    bool ok = sqlite3_trace_v2(ndb->db, SQLITE_TRACE_PROFILE,
                              directory_copy_arm, &target) == SQLITE_OK;
    bool accepted = ok && api_name_service_directory_path(
        "alice", "/api/v1/names/alice/services", &result, err, sizeof(err));
    bool consumed = target == 0 && zcl_alloc_fault_armed_label() == NULL;
    zcl_alloc_fault_clear();
    ok = sqlite3_trace_v2(ndb->db, 0, NULL, NULL) == SQLITE_OK && ok;
    ok = ok && consumed && !accepted &&
         strcmp(err, "Name service directory copy failed") == 0 &&
         result.type == JSON_INT && result.val.i == 73;
    json_free(&result);
    return ok && json_test_live_blocks() == before;
}

/* Run before address seeding: the final address scan has no rows. Count only
 * the nonempty containers copied after that scan, then target the inactive
 * copy's root and its first nested container independently. */
static bool directory_inactive_copy_cases(struct node_db *ndb)
{
    struct json_value show = {0}, base = {0}, result = {0};
    char err[192] = {0};
    rpc_name_set_state(ndb);
    bool ok = ndb->db && rpc_name_resolve_api("alice", &show) &&
              api_name_service_directory("alice", &base);
    ok = ok && json_size(json_get(&base, "records")) == 5 &&
         json_size(json_get(&base, "endpoints")) == 4;
    unsigned tail = directory_copy_blocks(json_get(&show, "text_records")) +
                    2 * directory_copy_blocks(json_get(&show, "service_records")) +
                    directory_copy_blocks(json_get(&base, "endpoints")) +
                    1 + 2 * directory_copy_blocks(&base);
    for (unsigned nested = 0; ok && nested < 2; nested++)
        ok = directory_copy_refuses(ndb, tail + 1 + nested);
    ok = ok && api_name_service_directory_path(
        "alice", "/api/v1/names/alice/services", &result, err, sizeof(err));
    for (size_t i = 0; ok && i < base.num_children; i++)
        ok = status_json_equal(&base.children[i], json_get(&result, base.keys[i]));
    ok = ok && json_get(&result, "filter_contract") && !err[0];
    json_free(&result);
    json_free(&base);
    json_free(&show);
    rpc_name_set_state(NULL);
    printf("api: inactive directory copy refuses incomplete trees... %s\n",
           ok ? "OK" : "FAIL");
    return ok;
}

static bool directory_store_status_case(const char *name,
                                       const char *status,
                                       const char *error)
{
    uint8_t response[4096] = {0};
    struct json_value root = {0};
    size_t n = api_serve_name_service_directory(
        name, "/api/v1/names/missing-name/services", NULL,
        response, sizeof(response));
    response[n < sizeof(response) ? n : sizeof(response) - 1] = '\0';
    const char *body = api_test_body(response, n, sizeof(response));
    bool ok = n > 0 && n < sizeof(response) &&
              strstr((char *)response, status) == (char *)response && body &&
              json_read(&root, body, strlen(body));
    ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                      "zcl.rest_error.v1") == 0 &&
         root.num_children == 3 &&
         strcmp(json_get_str(json_get(&root, "api_version")), "v1") == 0 &&
         strcmp(json_get_str(json_get(&root, "error")), error) == 0;
    json_free(&root);
    return ok;
}

static bool directory_diagnostic_bounds(const char *status, const char *action)
{
    char name[80], expected[192];
    memset(name, 'x', sizeof(name));
    name[0] = '"';
    name[1] = '\\';
    memcpy(name + 63, "omitted-tail", sizeof("omitted-tail"));
    snprintf(expected, sizeof(expected), "%s for '%.63s'; %s",
             status, name, action);
    const char *http = strcmp(status, "Naming store unavailable") == 0
        ? "HTTP/1.1 503 Service Unavailable" : "HTTP/1.1 404 Not Found";
    bool ok = directory_store_status_case(name, http, expected);
    static const size_t caps[] = {0, 1, 32, 256};
    for (size_t i = 0; i < sizeof(caps) / sizeof(caps[0]); i++) {
        uint8_t response[257];
        memset(response, 0xa5, sizeof(response));
        size_t n = api_serve_name_service_directory(name, "/api/v1/names/missing-name/services",
                                                   NULL, response, caps[i]);
        ok = ok && response[caps[i]] == 0xa5 &&
             (caps[i] ? n < caps[i] && response[n] == '\0' : n == 0);
    }
    return ok;
}

int api_directory_store_status_focused_tests(void)
{
    int failures = 0;
    struct name_controller_ctx saved;
    struct node_db ndb = {0};
    char dbdir[256];
    char dbpath[320];

    test_make_tmpdir(dbdir, sizeof(dbdir), "api_znam", "directory_store");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
    bool opened = node_db_open(&ndb, dbpath);
    name_controller_get_ctx(&saved);
    rpc_name_set_state(NULL);
    bool unavailable = directory_store_status_case(
        "missing-name", "HTTP/1.1 503 Service Unavailable",
        "Naming store unavailable for 'missing-name'; inspect node readiness then retry this name");
    unavailable = directory_diagnostic_bounds("Naming store unavailable",
        "inspect node readiness then retry this name") && unavailable;
    printf("api: unavailable directory store returns 503... %s\n",
           unavailable ? "OK" : "FAIL");
    failures += !unavailable;
    rpc_name_set_state(&ndb);
    bool missing = opened && directory_store_status_case(
        "missing-name", "HTTP/1.1 404 Not Found",
        "Name service directory not found for 'missing-name'; list names or resolve this name first");
    missing = directory_diagnostic_bounds("Name service directory not found",
        "list names or resolve this name first") && missing;
    rpc_name_set_state(saved.ndb);
    printf("api: missing directory name returns 404... %s\n",
           missing ? "OK" : "FAIL");
    failures += !missing;
    if (opened)
        node_db_close(&ndb);
    failures += test_rm_rf_recursive(dbdir) != 0;
    return failures;
}

static bool api_test_filtered_valid_routing(struct node_db *db)
{
    static const char *queries[] = {
        "endpoint_only=true", "transport=p2p", "valid=false",
        "transport=p2p&valid=true"
    };
    static const char *preferred[] = {"onion", "none", "none", "p2p"};
    struct znam_entry entry = {0};
    if (!db_znam_find(db, "alice", &entry))
        return false;
    snprintf(entry.name, sizeof(entry.name), "filtered-routing");
    bool ok = db_znam_save(db, &entry) &&
              db_znam_text_save(db, entry.name, "service.p2p", "peer:0") &&
              db_znam_text_save(db, entry.name, "service.onion", "alice.onion");
    for (size_t i = 0; i < sizeof(queries) / sizeof(queries[0]); i++) {
        struct json_value result = {0};
        char path[192];
        char err[192] = {0};
        if (i == 3)
            ok = db_znam_text_save(db, entry.name, "service.p2p", "peer:8033") && ok;
        snprintf(path, sizeof(path), "/api/v1/names/%s/services?%s",
                 entry.name, queries[i]);
        rpc_name_set_state(db);
        bool resolved = api_name_service_directory_path(entry.name, path,
                                                        &result, err, sizeof(err));
        rpc_name_set_state(NULL);
        const struct json_value *plan = json_get(&result, "routing_plan");
        const char *actual = json_get_str(json_get(plan, "preferred_transport"));
        const struct json_value *records = json_get(&result, "records");
        const struct json_value *p2p = api_test_find_str_field(records, "key", "service.p2p");
        const char *value = json_get_str(json_get(p2p, "value"));
        int count = i == 0 ? 2 : 1;
        ok &= resolved && !err[0] && actual && strcmp(actual, preferred[i]) == 0;
        ok &= value && strcmp(value, i == 3 ? "peer:8033" : "peer:0") == 0;
        ok &= json_size(records) == (size_t)count;
        ok &= json_size(json_get(&result, "endpoints")) == (size_t)count;
        ok &= json_get_int(json_get(&result, "service_record_count")) == count;
        ok &= json_get_int(json_get(&result, "endpoint_count")) == count;
        ok &= json_get_int(json_get(&result, "valid_endpoint_count")) == (i == 0 || i == 3);
        ok &= json_get_int(json_get(&result, "invalid_endpoint_count")) == (i != 3);
        ok &= json_get_bool(json_get(&result, "supports_direct_p2p"));
        ok &= json_get_bool(json_get(&result, "supports_onion")) == (i == 0);
        ok &= !json_get_bool(json_get(&result, "supports_bootstrap"));
        ok &= json_get_bool(json_get(plan, "requires_runtime_probe"));
        json_free(&result);
    }
    return ok;
}

/* One assertion row. Rows run in order and stop at the first failure, which
 * is the short-circuit of the original ok = ok && chains. */
enum {
    ZNAM_ROUTE_STR = 1,
    ZNAM_ROUTE_INT,
    ZNAM_ROUTE_BOOL,
    ZNAM_ROUTE_SIZE,
    ZNAM_ROUTE_NONNULL,
    ZNAM_ROUTE_CONTAINS
};

struct znam_route_check {
    unsigned kind;
    unsigned slot;
    const char *key;
    const char *str;
    int64_t num;
};

enum {
    ZNAM_IDX_ROOT = 0,
    ZNAM_IDX_NAMES,
    ZNAM_IDX_LINKS,
    ZNAM_IDX_VERIFY,
    ZNAM_IDX_LAST
};

enum {
    ZNAM_LIST_ROOT = 0,
    ZNAM_LIST_NAMES,
    ZNAM_LIST_VERIFY
};

enum {
    ZNAM_OWNER_ROOT = 0,
    ZNAM_OWNER_NAMES,
    ZNAM_OWNER_MATCH
};

enum {
    ZNAM_SVC_ROOT = 0,
    ZNAM_SVC_RECORDS,
    ZNAM_SVC_ENDPOINTS,
    ZNAM_SVC_ONION,
    ZNAM_SVC_FILTER,
    ZNAM_SVC_ALLOWED
};

enum {
    ZNAM_FILT_ROOT = 0,
    ZNAM_FILT_FILTERS,
    ZNAM_FILT_RECORDS,
    ZNAM_FILT_ENDPOINTS,
    ZNAM_FILT_P2P,
    ZNAM_FILT_PLAN
};

enum {
    ZNAM_ERR_ROOT = 0,
    ZNAM_ERR_ALLOWED
};

static bool znam_route_check_one(const struct json_value **slot,
                                 const struct znam_route_check *row)
{
    const struct json_value *obj = slot[row->slot];
    const struct json_value *field;

    if (row->kind == ZNAM_ROUTE_NONNULL)
        return obj != NULL;
    if (row->kind == ZNAM_ROUTE_SIZE)
        return json_size(obj) == (size_t)row->num;
    field = json_get(obj, row->key);
    if (row->kind == ZNAM_ROUTE_STR)
        return strcmp(json_get_str(field), row->str) == 0;
    if (row->kind == ZNAM_ROUTE_INT)
        return json_get_int(field) == row->num;
    if (row->kind == ZNAM_ROUTE_BOOL) {
        if (row->num)
            return json_get_bool(field);
        return !json_get_bool(field);
    }
    if (row->kind == ZNAM_ROUTE_CONTAINS)
        return strstr(json_get_str(field), row->str) != NULL;
    return false;
}

static bool znam_route_check_all(bool ok, const struct json_value **slot,
                                 const struct znam_route_check *rows,
                                 size_t n)
{
    for (size_t i = 0; ok && i < n; i++)
        ok = znam_route_check_one(slot, &rows[i]);
    return ok;
}

static const struct znam_route_check znam_route_index_rows[] = {
    { ZNAM_ROUTE_STR, ZNAM_IDX_ROOT, "schema", "zcl.names.index.v1", 0 },
    { ZNAM_ROUTE_INT, ZNAM_IDX_ROOT, "limit", NULL, 100 },
    { ZNAM_ROUTE_INT, ZNAM_IDX_ROOT, "count", NULL, 100 },
    { ZNAM_ROUTE_BOOL, ZNAM_IDX_ROOT, "filtered", NULL, 0 },
    { ZNAM_ROUTE_SIZE, ZNAM_IDX_NAMES, NULL, NULL, 100 },
    { ZNAM_ROUTE_NONNULL, ZNAM_IDX_LAST, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_IDX_ROOT, "source_projection",
      "znam_projection", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_IDX_LINKS, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_IDX_LINKS, "collection", "/api/v1/names", 0 },
    { ZNAM_ROUTE_STR, ZNAM_IDX_LINKS, "read", "/api/v1/names/{name}", 0 },
    { ZNAM_ROUTE_STR, ZNAM_IDX_LINKS, "protocol",
      "/api/v1/protocols/znam", 0 },
    { ZNAM_ROUTE_STR, ZNAM_IDX_LINKS, "delete",
      "not_supported_by_znam_v1", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_IDX_VERIFY, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_IDX_VERIFY, "base_layer", "zclassic_l1", 0 },
    { ZNAM_ROUTE_STR, ZNAM_IDX_VERIFY, "consensus_boundary",
      "legacy_zclassic_consensus_unchanged", 0 },
};

static const struct znam_route_check znam_route_list_rows[] = {
    { ZNAM_ROUTE_STR, ZNAM_LIST_ROOT, "schema", "zcl.names.index.v1", 0 },
    { ZNAM_ROUTE_INT, ZNAM_LIST_ROOT, "limit", NULL, 100 },
    { ZNAM_ROUTE_INT, ZNAM_LIST_ROOT, "count", NULL, 100 },
    { ZNAM_ROUTE_BOOL, ZNAM_LIST_ROOT, "filtered", NULL, 0 },
    { ZNAM_ROUTE_SIZE, ZNAM_LIST_NAMES, NULL, NULL, 100 },
    { ZNAM_ROUTE_NONNULL, ZNAM_LIST_VERIFY, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_LIST_VERIFY, "base_layer", "zclassic_l1", 0 },
};

static const struct znam_route_check znam_route_owner_rows[] = {
    { ZNAM_ROUTE_STR, ZNAM_OWNER_ROOT, "schema", "zcl.names.index.v1", 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_OWNER_ROOT, "filtered", NULL, 1 },
    { ZNAM_ROUTE_STR, ZNAM_OWNER_ROOT, "owner",
      "owner-address-for-api-route-042", 0 },
    { ZNAM_ROUTE_INT, ZNAM_OWNER_ROOT, "count", NULL, 1 },
    { ZNAM_ROUTE_SIZE, ZNAM_OWNER_NAMES, NULL, NULL, 1 },
    { ZNAM_ROUTE_NONNULL, ZNAM_OWNER_MATCH, NULL, NULL, 0 },
};

static bool znam_routes_seed_oversized(struct node_db *ndb, const char *dbpath)
{
    bool ok = node_db_open(ndb, dbpath);
    for (int i = 0; ok && i < 100; i++) {
        struct znam_entry e;
        memset(&e, 0, sizeof(e));
        snprintf(e.name, sizeof(e.name), "api-name-%03d", i);
        snprintf(e.owner_address, sizeof(e.owner_address),
                 "owner-address-for-api-route-%03d", i);
        e.target_type = ZNAM_TYPE_CONTENT;
        snprintf(e.target_value, sizeof(e.target_value),
                 "sha3:%064d:%064d", i, 1000 + i);
        memset(e.reg_txid, (uint8_t)(i + 1), sizeof(e.reg_txid));
        e.reg_height = i + 1;
        ok = db_znam_save(ndb, &e);
    }
    return ok;
}

static bool znam_routes_oversized_index(struct node_db *ndb)
{
    uint8_t big_resp[65536];
    struct json_value root;
    const struct json_value *names;
    const struct json_value *links;
    const struct json_value *verification;
    const struct json_value *last;
    const struct json_value *slot[5];
    size_t n;
    const char *body;
    bool ok;

    rpc_name_set_state(ndb);
    n = api_handle_request("GET", "/api/names", NULL, 0,
                           big_resp, sizeof(big_resp));
    big_resp[n < sizeof(big_resp) ? n : sizeof(big_resp) - 1] = '\0';
    body = api_test_body(big_resp, n, sizeof(big_resp));
    json_init(&root);
    ok = n > 16384 &&
         strstr((char *)big_resp, "HTTP/1.1 200 OK") != NULL &&
         body && json_read(&root, body, strlen(body));
    names = ok ? json_get(&root, "names") : NULL;
    links = ok ? json_get(&root, "_links") : NULL;
    verification = ok ? json_get(&root, "zcl_verification") : NULL;
    last = api_test_find_str_field(names, "name", "api-name-099");
    slot[ZNAM_IDX_ROOT] = &root;
    slot[ZNAM_IDX_NAMES] = names;
    slot[ZNAM_IDX_LINKS] = links;
    slot[ZNAM_IDX_VERIFY] = verification;
    slot[ZNAM_IDX_LAST] = last;
    ok = znam_route_check_all(ok, slot, znam_route_index_rows,
                              sizeof znam_route_index_rows /
                              sizeof znam_route_index_rows[0]);
    json_free(&root);
    return ok;
}

static bool znam_routes_name_list_all(struct node_db *ndb)
{
    struct rpc_table names_rpc;
    struct json_value params = {0};
    struct json_value rpc_result = {0};
    const struct json_value *rpc_names;
    const struct json_value *rpc_verification;
    const struct json_value *slot[3];
    const struct rpc_command *cmd;
    bool ok;

    (void)ndb;
    rpc_table_init(&names_rpc);
    register_name_rpc_commands(&names_rpc);
    cmd = rpc_table_find(&names_rpc, "name_list");
    json_set_array(&params);
    ok = cmd && cmd->actor(&params, false, &rpc_result);
    rpc_names = ok ? json_get(&rpc_result, "names") : NULL;
    rpc_verification = ok ? json_get(&rpc_result, "zcl_verification") : NULL;
    slot[ZNAM_LIST_ROOT] = &rpc_result;
    slot[ZNAM_LIST_NAMES] = rpc_names;
    slot[ZNAM_LIST_VERIFY] = rpc_verification;
    ok = znam_route_check_all(ok, slot, znam_route_list_rows,
                              sizeof znam_route_list_rows /
                              sizeof znam_route_list_rows[0]);
    json_free(&params);
    json_free(&rpc_result);
    return ok;
}

static bool znam_routes_name_list_owner(struct node_db *ndb)
{
    struct rpc_table names_rpc;
    struct json_value params = {0};
    struct json_value owner = {0};
    struct json_value rpc_result = {0};
    const struct json_value *rpc_names;
    const struct json_value *match;
    const struct json_value *slot[3];
    const struct rpc_command *cmd;
    bool ok;

    (void)ndb;
    rpc_table_init(&names_rpc);
    register_name_rpc_commands(&names_rpc);
    cmd = rpc_table_find(&names_rpc, "name_list");
    json_set_array(&params);
    json_set_str(&owner, "owner-address-for-api-route-042");
    json_push_back(&params, &owner);
    json_free(&owner);
    ok = cmd && cmd->actor(&params, false, &rpc_result);
    rpc_names = ok ? json_get(&rpc_result, "names") : NULL;
    match = api_test_find_str_field(rpc_names, "name", "api-name-042");
    slot[ZNAM_OWNER_ROOT] = &rpc_result;
    slot[ZNAM_OWNER_NAMES] = rpc_names;
    slot[ZNAM_OWNER_MATCH] = match;
    ok = znam_route_check_all(ok, slot, znam_route_owner_rows,
                              sizeof znam_route_owner_rows /
                              sizeof znam_route_owner_rows[0]);
    json_free(&params);
    json_free(&rpc_result);
    return ok;
}

static bool znam_routes_oversized_names_payload(struct node_db *ndb)
{
    bool ok = znam_routes_oversized_index(ndb);
    if (ok)
        ok = znam_routes_name_list_all(ndb);
    if (ok)
        ok = znam_routes_name_list_owner(ndb);
    rpc_name_set_state(NULL);
    node_db_close(ndb);
    return ok;
}

static bool znam_routes_oversized_names_case(void)
{
    char dbdir[256];
    char dbpath[320];
    struct node_db ndb;
    bool ok;

    memset(&ndb, 0, sizeof(ndb));
    test_make_tmpdir(dbdir, sizeof(dbdir), "api_znam", "names");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
    ok = znam_routes_seed_oversized(&ndb, dbpath);
    if (ok)
        ok = znam_routes_oversized_names_payload(&ndb);
    ok &= fixture_rm_ok(dbdir);
    return ok;
}

enum {
    ZNAM_SHOW_ROOT = 0,
    ZNAM_SHOW_TEXTS,
    ZNAM_SHOW_SERVICES,
    ZNAM_SHOW_ADDRS,
    ZNAM_SHOW_DIRECTORY,
    ZNAM_SHOW_DIR_RECORDS,
    ZNAM_SHOW_DIR_ENDPOINTS,
    ZNAM_SHOW_LINKS,
    ZNAM_SHOW_VERIFICATION,
    ZNAM_SHOW_URL,
    ZNAM_SHOW_SVC,
    ZNAM_SHOW_SVC_P2P,
    ZNAM_SHOW_SVC_BAD,
    ZNAM_SHOW_SVC_BOOT,
    ZNAM_SHOW_SVC_UNKNOWN,
    ZNAM_SHOW_SVC_PROBE,
    ZNAM_SHOW_P2P_PROBE,
    ZNAM_SHOW_P2P_VALIDATION,
    ZNAM_SHOW_P2P_ROUTING,
    ZNAM_SHOW_BAD_VALIDATION,
    ZNAM_SHOW_BAD_ROUTING,
    ZNAM_SHOW_BOOT_PROBE,
    ZNAM_SHOW_SVC_RESOLUTION,
    ZNAM_SHOW_SVC_VALIDATION,
    ZNAM_SHOW_SVC_ROUTING,
    ZNAM_SHOW_UNKNOWN_RESOLUTION,
    ZNAM_SHOW_UNKNOWN_VALIDATION,
    ZNAM_SHOW_DIR_SVC,
    ZNAM_SHOW_DIR_ENDPOINT,
    ZNAM_SHOW_BTC,
    ZNAM_SHOW_LTC,
    ZNAM_SHOW_PLAN,
    ZNAM_SHOW_COUNT
};

struct znam_show_view {
    struct json_value root;
    const struct json_value *slot[ZNAM_SHOW_COUNT];
};

static const struct znam_route_check znam_route_show_rows[] = {
    { ZNAM_ROUTE_STR, ZNAM_SHOW_ROOT, "schema", "zcl.names.show.v1", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_ROOT, "name", "alice", 0 },
    { ZNAM_ROUTE_INT, ZNAM_SHOW_ROOT, "target_type", NULL, ZNAM_TYPE_BTC },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_ROOT, "type", "bitcoin", 0 },
    { ZNAM_ROUTE_SIZE, ZNAM_SHOW_TEXTS, NULL, NULL, 6 },
    { ZNAM_ROUTE_INT, ZNAM_SHOW_ROOT, "text_record_count", NULL, 6 },
    { ZNAM_ROUTE_SIZE, ZNAM_SHOW_SERVICES, NULL, NULL, 5 },
    { ZNAM_ROUTE_INT, ZNAM_SHOW_ROOT, "service_record_count", NULL, 5 },
    { ZNAM_ROUTE_SIZE, ZNAM_SHOW_ADDRS, NULL, NULL, 2 },
    { ZNAM_ROUTE_INT, ZNAM_SHOW_ROOT, "address_record_count", NULL, 2 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_URL, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_URL, "value", "https://alice.example", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC, "value", "aliceexample.onion:8033", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC, "schema",
      "zcl.names.service_record.v1", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC, "service_name", "onion_directory", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC, "service_contract",
      "onion_directory", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC, "service_catalog_route",
      "/api/v1/service-catalog/onion_directory", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC, "recommended_operation_id",
      "onion_directory.list_onion_announcements", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC, "service_operation_route",
      "/api/v1/service-operations/"
      "onion_directory.list_onion_announcements", 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_SVC, "service_contract_known", NULL, 1 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_SVC, "service_operation_required", NULL, 1 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_SVC, "service_operation_known", NULL, 1 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC, "contract_resolution_status",
      "resolved", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_RESOLUTION, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_RESOLUTION, "schema",
      "zcl.names.service_contract_resolution.v1", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_RESOLUTION, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_RESOLUTION, "status", "resolved", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_RESOLUTION, NULL, NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_SVC_RESOLUTION, "service_contract_known",
      NULL, 1 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_RESOLUTION, NULL, NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_SVC_RESOLUTION, "operation_required",
      NULL, 1 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_RESOLUTION, NULL, NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_SVC_RESOLUTION, "service_operation_known",
      NULL, 1 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_RESOLUTION, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_RESOLUTION, "next_action",
      "run_runtime_probe_before_routing", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_PROBE, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_PROBE, "schema",
      "zcl.service_runtime_probe.v1", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_PROBE, "route",
      "/api/v1/onion/announcements", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_PROBE, "operation_id",
      "onion_directory.list_onion_announcements", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_PROBE, "expected_schema",
      "zcl.onion_announcements.index.v1", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC, "transport", "onion", 0 },
    { ZNAM_ROUTE_INT, ZNAM_SHOW_SVC, "routing_priority", NULL, 30 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_SVC, "endpoint_hint_valid", NULL, 1 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_VALIDATION, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_VALIDATION, "schema",
      "zcl.names.endpoint_validation.v1", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_VALIDATION, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_VALIDATION, "status",
      "valid_endpoint_hint", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_VALIDATION, NULL, NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_SVC_VALIDATION, "accepted", NULL, 1 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_VALIDATION, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_VALIDATION, "reason",
      "onion_host_hint_present", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_ROUTING, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_ROUTING, "schema",
      "zcl.names.endpoint_routing.v1", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_ROUTING, NULL, NULL, 0 },
    { ZNAM_ROUTE_INT, ZNAM_SHOW_SVC_ROUTING, "priority", NULL, 30 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_ROUTING, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_ROUTING, "preferred_transport",
      "onion", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_ROUTING, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_ROUTING, "fallback_transport",
      "direct_p2p_if_directory_advertises_it", 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_SVC, "chain_verified", NULL, 1 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_P2P, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_P2P, "service_name", "direct_p2p", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_P2P, "service_contract", "bootstrap", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_P2P, "recommended_operation_id",
      "bootstrap.inspect_peer_bootstrap_readiness", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_P2P, "service_operation_route",
      "/api/v1/service-operations/"
      "bootstrap.inspect_peer_bootstrap_readiness", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_P2P_PROBE, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_P2P_PROBE, "route", "/api/v1/bootstrap", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_P2P_PROBE, "operation_id",
      "bootstrap.read_bootstrap_status", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_P2P, "next_action",
      "connect_direct_p2p_and_verify_peer_readiness", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_P2P, "transport", "p2p", 0 },
    { ZNAM_ROUTE_INT, ZNAM_SHOW_SVC_P2P, "routing_priority", NULL, 10 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_SVC_P2P, "endpoint_hint_valid", NULL, 1 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_P2P_VALIDATION, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_P2P_VALIDATION, "status",
      "valid_endpoint_hint", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_P2P_VALIDATION, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_P2P_VALIDATION, "reason",
      "host_port_hint_present", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_P2P_ROUTING, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_P2P_ROUTING, "preferred_transport",
      "p2p", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_P2P_ROUTING, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_P2P_ROUTING, "fallback_transport",
      "onion", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_BAD, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_BAD, "service_name", "direct_p2p", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_BAD, NULL, NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_SVC_BAD, "endpoint_hint_valid", NULL, 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_BAD_VALIDATION, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_BAD_VALIDATION, "status",
      "invalid_endpoint_hint", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_BAD_VALIDATION, NULL, NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_BAD_VALIDATION, "accepted", NULL, 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_BAD_VALIDATION, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_BAD_VALIDATION, "reason",
      "missing_host_port", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_BAD_ROUTING, NULL, NULL, 0 },
    { ZNAM_ROUTE_INT, ZNAM_SHOW_BAD_ROUTING, "priority", NULL, 10 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_BOOT, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_BOOT, "service_name", "bootstrap", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_BOOT, "recommended_operation_id",
      "bootstrap.read_bootstrap_status", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_BOOT, "service_operation_route",
      "/api/v1/service-operations/"
      "bootstrap.read_bootstrap_status", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_BOOT_PROBE, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_BOOT_PROBE, "route",
      "/api/v1/bootstrap", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_BOOT_PROBE, "expected_schema",
      "zcl.bootstrap_status.v1", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_BOOT, "endpoint_kind",
      "bootstrap_hint", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_SVC_UNKNOWN, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_UNKNOWN, "service_contract",
      "unknown", 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_SVC_UNKNOWN, "service_contract_known",
      NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_SVC_UNKNOWN, "service_operation_required",
      NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_SVC_UNKNOWN, "service_operation_known",
      NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_SVC_UNKNOWN, "contract_resolution_status",
      "service_unknown", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_UNKNOWN_VALIDATION, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_UNKNOWN_VALIDATION, "status",
      "not_endpoint", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_UNKNOWN_RESOLUTION, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_UNKNOWN_RESOLUTION, "status",
      "service_unknown", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_UNKNOWN_RESOLUTION, NULL, NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_UNKNOWN_RESOLUTION,
      "service_contract_known", NULL, 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_UNKNOWN_RESOLUTION, NULL, NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_UNKNOWN_RESOLUTION, "operation_required",
      NULL, 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_UNKNOWN_RESOLUTION, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_UNKNOWN_RESOLUTION, "next_action",
      "inspect_service_catalog_before_trusting_chain_hint", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_BTC, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_BTC, "address", "1aliceAddress", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_LTC, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_LTC, "address", "LaliceAddress", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_DIRECTORY, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_DIRECTORY, "schema",
      "zcl.names.service_directory.v1", 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_DIRECTORY, "has_services", NULL, 1 },
    { ZNAM_ROUTE_INT, ZNAM_SHOW_DIRECTORY, "service_record_count", NULL, 5 },
    { ZNAM_ROUTE_INT, ZNAM_SHOW_DIRECTORY, "endpoint_count", NULL, 4 },
    { ZNAM_ROUTE_INT, ZNAM_SHOW_DIRECTORY, "valid_endpoint_count", NULL, 3 },
    { ZNAM_ROUTE_INT, ZNAM_SHOW_DIRECTORY, "invalid_endpoint_count",
      NULL, 1 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_DIRECTORY, "supports_onion", NULL, 1 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_DIRECTORY, "supports_direct_p2p", NULL, 1 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_DIRECTORY, "supports_bootstrap", NULL, 1 },
    { ZNAM_ROUTE_SIZE, ZNAM_SHOW_DIR_RECORDS, NULL, NULL, 5 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_DIR_SVC, NULL, NULL, 0 },
    { ZNAM_ROUTE_SIZE, ZNAM_SHOW_DIR_ENDPOINTS, NULL, NULL, 4 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_DIR_ENDPOINT, NULL, NULL, 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_PLAN, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_PLAN, "schema",
      "zcl.names.service_routing_plan.v1", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_PLAN, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_PLAN, "strategy",
      "prefer_valid_direct_p2p_then_bootstrap_then_onion", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_PLAN, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_PLAN, "preferred_transport", "p2p", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_PLAN, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_PLAN, "fallback_transport", "onion", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_PLAN, NULL, NULL, 0 },
    { ZNAM_ROUTE_INT, ZNAM_SHOW_PLAN, "valid_endpoint_count", NULL, 3 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_PLAN, NULL, NULL, 0 },
    { ZNAM_ROUTE_INT, ZNAM_SHOW_PLAN, "invalid_endpoint_count", NULL, 1 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_PLAN, NULL, NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_SHOW_PLAN, "requires_runtime_probe", NULL, 1 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_DIRECTORY, "transport_model",
      "records_advertise_tor_or_p2p_endpoints", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_DIRECTORY, "service_contract_route",
      "/api/v1/service-catalog/{service}", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_DIRECTORY, "operation_contract_route",
      "/api/v1/service-operations/{operation_id}", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_DIRECTORY, "runtime_probe_schema",
      "zcl.service_runtime_probe.v1", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_DIRECTORY, "runtime_probe_contract_field",
      "runtime_probe", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_LINKS, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_LINKS, "self", "/api/v1/names/alice", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_LINKS, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_LINKS, "services",
      "/api/v1/names/alice/services", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_LINKS, "collection", "/api/v1/names", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_LINKS, "service_directory",
      "/api/v1/names/{name}/services", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SHOW_VERIFICATION, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_VERIFICATION, "anchor",
      "confirmed_znam_op_return", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SHOW_VERIFICATION, "mutation_authority",
      "confirmed_chain_history", 0 },
};

static const struct znam_route_check znam_route_services_rows[] = {
    { ZNAM_ROUTE_STR, ZNAM_SVC_ROOT, "schema",
      "zcl.names.service_directory.v1", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SVC_ROOT, "name", "alice", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SVC_ROOT, "self_route",
      "/api/v1/names/alice/services", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SVC_ROOT, "name_route",
      "/api/v1/names/alice", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SVC_ROOT, "operation_id",
      "znam_names.resolve_service_directory", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SVC_ROOT, "operation_route",
      "/api/v1/service-operations/"
      "znam_names.resolve_service_directory", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SVC_ROOT, "source_projection",
      "znam_projection", 0 },
    { ZNAM_ROUTE_INT, ZNAM_SVC_ROOT, "service_record_count", NULL, 5 },
    { ZNAM_ROUTE_INT, ZNAM_SVC_ROOT, "endpoint_count", NULL, 4 },
    { ZNAM_ROUTE_INT, ZNAM_SVC_ROOT, "valid_endpoint_count", NULL, 3 },
    { ZNAM_ROUTE_INT, ZNAM_SVC_ROOT, "invalid_endpoint_count", NULL, 1 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SVC_RECORDS, NULL, NULL, 0 },
    { ZNAM_ROUTE_SIZE, ZNAM_SVC_RECORDS, NULL, NULL, 5 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SVC_ENDPOINTS, NULL, NULL, 0 },
    { ZNAM_ROUTE_SIZE, ZNAM_SVC_ENDPOINTS, NULL, NULL, 4 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SVC_ONION, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SVC_ONION, "contract_resolution_status",
      "resolved", 0 },
    { ZNAM_ROUTE_STR, ZNAM_SVC_ROOT, "next_action",
      "use_records_then_run_runtime_probe_before_routing", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SVC_FILTER, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SVC_FILTER, "schema",
      "zcl.query_filter_contract.v1", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SVC_FILTER, NULL, NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_SVC_FILTER, "unknown_filters_error", NULL, 1 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SVC_ALLOWED, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SVC_ALLOWED, "transport",
      "p2p,onion,p2p_or_onion,unspecified,none", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_SVC_ALLOWED, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_SVC_ALLOWED, "contract",
      "alias_for_service_contract", 0 },
};

static const struct znam_route_check znam_route_filtered_rows[] = {
    { ZNAM_ROUTE_STR, ZNAM_FILT_ROOT, "schema",
      "zcl.names.service_directory.v1", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_FILT_FILTERS, NULL, NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_FILT_FILTERS, "active", NULL, 1 },
    { ZNAM_ROUTE_NONNULL, ZNAM_FILT_FILTERS, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_FILT_FILTERS, "transport", "p2p", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_FILT_FILTERS, NULL, NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_FILT_FILTERS, "valid", NULL, 1 },
    { ZNAM_ROUTE_NONNULL, ZNAM_FILT_FILTERS, NULL, NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_FILT_FILTERS, "endpoint_only", NULL, 1 },
    { ZNAM_ROUTE_INT, ZNAM_FILT_ROOT, "service_record_count", NULL, 1 },
    { ZNAM_ROUTE_INT, ZNAM_FILT_ROOT, "endpoint_count", NULL, 1 },
    { ZNAM_ROUTE_INT, ZNAM_FILT_ROOT, "valid_endpoint_count", NULL, 1 },
    { ZNAM_ROUTE_INT, ZNAM_FILT_ROOT, "invalid_endpoint_count", NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_FILT_ROOT, "supports_direct_p2p", NULL, 1 },
    { ZNAM_ROUTE_BOOL, ZNAM_FILT_ROOT, "supports_onion", NULL, 0 },
    { ZNAM_ROUTE_BOOL, ZNAM_FILT_ROOT, "supports_bootstrap", NULL, 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_FILT_RECORDS, NULL, NULL, 0 },
    { ZNAM_ROUTE_SIZE, ZNAM_FILT_RECORDS, NULL, NULL, 1 },
    { ZNAM_ROUTE_NONNULL, ZNAM_FILT_P2P, NULL, NULL, 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_FILT_ENDPOINTS, NULL, NULL, 0 },
    { ZNAM_ROUTE_SIZE, ZNAM_FILT_ENDPOINTS, NULL, NULL, 1 },
    { ZNAM_ROUTE_NONNULL, ZNAM_FILT_PLAN, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_FILT_PLAN, "preferred_transport", "p2p", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_FILT_PLAN, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_FILT_PLAN, "fallback_transport",
      "bootstrap", 0 },
    { ZNAM_ROUTE_STR, ZNAM_FILT_ROOT, "source_projection",
      "znam_projection", 0 },
};

static const struct znam_route_check znam_route_maybe_rows[] = {
    { ZNAM_ROUTE_STR, ZNAM_ERR_ROOT, "schema", "zcl.rest_error.v1", 0 },
    { ZNAM_ROUTE_STR, ZNAM_ERR_ROOT, "error",
      "invalid_name_service_filter", 0 },
    { ZNAM_ROUTE_NONNULL, ZNAM_ERR_ALLOWED, NULL, NULL, 0 },
    { ZNAM_ROUTE_STR, ZNAM_ERR_ALLOWED, "valid", "true,false", 0 },
};

static const struct znam_route_check znam_route_tranport_rows[] = {
    { ZNAM_ROUTE_STR, ZNAM_ERR_ROOT, "error",
      "invalid_name_service_filter", 0 },
    { ZNAM_ROUTE_CONTAINS, ZNAM_ERR_ROOT, "message",
      "unknown filter 'tranport'", 0 },
};

static bool znam_routes_seed_alice(struct node_db *ndb, bool opened)
{
    bool ok = opened;
    if (ok) {
        struct znam_entry e;
        memset(&e, 0, sizeof(e));
        snprintf(e.name, sizeof(e.name), "alice");
        snprintf(e.owner_address, sizeof(e.owner_address),
                 "t1owner-for-name-show");
        e.target_type = ZNAM_TYPE_BTC;
        snprintf(e.target_value, sizeof(e.target_value),
                 "1primary-target-address");
        memset(e.reg_txid, 0x42, sizeof(e.reg_txid));
        e.reg_height = 42;
        memset(e.last_update_txid, 0x43, sizeof(e.last_update_txid));
        ok = db_znam_save(ndb, &e);
    }
    ok = ok && db_znam_text_save(ndb, "alice", "url",
                                 "https://alice.example");
    ok = ok && db_znam_text_save(ndb, "alice", "service.onion",
                                 "aliceexample.onion:8033");
    ok = ok && db_znam_text_save(ndb, "alice", "service.p2p",
                                 "192.0.2.10:8033");
    ok = ok && db_znam_text_save(ndb, "alice", "svc.direct_p2p",
                                 "missing-port");
    ok = ok && db_znam_text_save(ndb, "alice", "bootstrap",
                                 "198.51.100.20:8033");
    ok = ok && db_znam_text_save(ndb, "alice", "service.unknown",
                                 "unknown-service-metadata");
    return ok;
}

static bool znam_routes_save_alice_addrs(struct node_db *ndb, bool ok)
{
    ok = ok && db_znam_addr_save(ndb, "alice", ZNAM_TYPE_LTC,
                                 "LaliceAddress");
    ok = ok && db_znam_addr_save(ndb, "alice", ZNAM_TYPE_BTC,
                                 "1aliceAddress");
    return ok;
}

static bool znam_routes_alice_show_parse(struct node_db *ndb,
                                         struct znam_show_view *v)
{
    uint8_t resp[65536];
    size_t n;
    const char *body;
    bool ok;

    rpc_name_set_state(ndb);
    n = api_handle_request("GET", "/api/v1/names/alice",
                           NULL, 0, resp, sizeof(resp));
    rpc_name_set_state(NULL);
    body = api_test_body(resp, n, sizeof(resp));
    json_init(&v->root);
    ok = n > 0 && body && json_read(&v->root, body, strlen(body));
    v->slot[ZNAM_SHOW_ROOT] = &v->root;
    v->slot[ZNAM_SHOW_TEXTS] =
        ok ? json_get(&v->root, "text_records") : NULL;
    v->slot[ZNAM_SHOW_SERVICES] =
        ok ? json_get(&v->root, "service_records") : NULL;
    v->slot[ZNAM_SHOW_ADDRS] =
        ok ? json_get(&v->root, "address_records") : NULL;
    v->slot[ZNAM_SHOW_DIRECTORY] =
        ok ? json_get(&v->root, "service_directory") : NULL;
    v->slot[ZNAM_SHOW_DIR_RECORDS] = v->slot[ZNAM_SHOW_DIRECTORY]
        ? json_get(v->slot[ZNAM_SHOW_DIRECTORY], "records") : NULL;
    v->slot[ZNAM_SHOW_DIR_ENDPOINTS] = v->slot[ZNAM_SHOW_DIRECTORY]
        ? json_get(v->slot[ZNAM_SHOW_DIRECTORY], "endpoints") : NULL;
    return ok;
}

static void znam_routes_alice_show_links(struct znam_show_view *v, bool ok)
{
    v->slot[ZNAM_SHOW_LINKS] = ok ? json_get(&v->root, "_links") : NULL;
    v->slot[ZNAM_SHOW_VERIFICATION] =
        ok ? json_get(&v->root, "zcl_verification") : NULL;
    v->slot[ZNAM_SHOW_URL] =
        api_test_find_str_field(v->slot[ZNAM_SHOW_TEXTS], "key", "url");
    v->slot[ZNAM_SHOW_SVC] =
        api_test_find_str_field(v->slot[ZNAM_SHOW_SERVICES], "key",
                                "service.onion");
    v->slot[ZNAM_SHOW_SVC_P2P] =
        api_test_find_str_field(v->slot[ZNAM_SHOW_SERVICES], "key",
                                "service.p2p");
    v->slot[ZNAM_SHOW_SVC_BAD] =
        api_test_find_str_field(v->slot[ZNAM_SHOW_SERVICES], "key",
                                "svc.direct_p2p");
    v->slot[ZNAM_SHOW_SVC_BOOT] =
        api_test_find_str_field(v->slot[ZNAM_SHOW_SERVICES], "key",
                                "bootstrap");
    v->slot[ZNAM_SHOW_SVC_UNKNOWN] =
        api_test_find_str_field(v->slot[ZNAM_SHOW_SERVICES], "key",
                                "service.unknown");
}

static void znam_routes_alice_show_probes(struct znam_show_view *v)
{
    const struct json_value *svc = v->slot[ZNAM_SHOW_SVC];
    const struct json_value *svc_p2p = v->slot[ZNAM_SHOW_SVC_P2P];
    const struct json_value *svc_bad = v->slot[ZNAM_SHOW_SVC_BAD];
    const struct json_value *svc_boot = v->slot[ZNAM_SHOW_SVC_BOOT];

    v->slot[ZNAM_SHOW_SVC_PROBE] =
        svc ? json_get(svc, "runtime_probe") : NULL;
    v->slot[ZNAM_SHOW_P2P_PROBE] =
        svc_p2p ? json_get(svc_p2p, "runtime_probe") : NULL;
    v->slot[ZNAM_SHOW_P2P_VALIDATION] =
        svc_p2p ? json_get(svc_p2p, "endpoint_validation") : NULL;
    v->slot[ZNAM_SHOW_P2P_ROUTING] =
        svc_p2p ? json_get(svc_p2p, "endpoint_routing") : NULL;
    v->slot[ZNAM_SHOW_BAD_VALIDATION] =
        svc_bad ? json_get(svc_bad, "endpoint_validation") : NULL;
    v->slot[ZNAM_SHOW_BAD_ROUTING] =
        svc_bad ? json_get(svc_bad, "endpoint_routing") : NULL;
    v->slot[ZNAM_SHOW_BOOT_PROBE] =
        svc_boot ? json_get(svc_boot, "runtime_probe") : NULL;
}

static void znam_routes_alice_show_plans(struct znam_show_view *v)
{
    const struct json_value *svc = v->slot[ZNAM_SHOW_SVC];
    const struct json_value *svc_unknown = v->slot[ZNAM_SHOW_SVC_UNKNOWN];
    const struct json_value *directory = v->slot[ZNAM_SHOW_DIRECTORY];

    v->slot[ZNAM_SHOW_SVC_RESOLUTION] =
        svc ? json_get(svc, "contract_resolution") : NULL;
    v->slot[ZNAM_SHOW_SVC_VALIDATION] =
        svc ? json_get(svc, "endpoint_validation") : NULL;
    v->slot[ZNAM_SHOW_SVC_ROUTING] =
        svc ? json_get(svc, "endpoint_routing") : NULL;
    v->slot[ZNAM_SHOW_UNKNOWN_RESOLUTION] =
        svc_unknown ? json_get(svc_unknown, "contract_resolution") : NULL;
    v->slot[ZNAM_SHOW_UNKNOWN_VALIDATION] =
        svc_unknown ? json_get(svc_unknown, "endpoint_validation") : NULL;
    v->slot[ZNAM_SHOW_DIR_SVC] =
        api_test_find_str_field(v->slot[ZNAM_SHOW_DIR_RECORDS], "key",
                                "service.onion");
    v->slot[ZNAM_SHOW_DIR_ENDPOINT] =
        api_test_find_str_field(v->slot[ZNAM_SHOW_DIR_ENDPOINTS], "key",
                                "service.p2p");
    v->slot[ZNAM_SHOW_BTC] =
        api_test_find_str_field(v->slot[ZNAM_SHOW_ADDRS], "type", "bitcoin");
    v->slot[ZNAM_SHOW_LTC] =
        api_test_find_str_field(v->slot[ZNAM_SHOW_ADDRS], "type", "litecoin");
    v->slot[ZNAM_SHOW_PLAN] =
        directory ? json_get(directory, "routing_plan") : NULL;
}

static bool znam_routes_alice_show_record(struct node_db *ndb)
{
    struct znam_show_view v;
    bool ok;

    memset(&v, 0, sizeof v);
    ok = znam_routes_alice_show_parse(ndb, &v);
    znam_routes_alice_show_links(&v, ok);
    znam_routes_alice_show_probes(&v);
    znam_routes_alice_show_plans(&v);
    ok = znam_route_check_all(ok, v.slot, znam_route_show_rows,
                              sizeof znam_route_show_rows /
                              sizeof znam_route_show_rows[0]);
    json_free(&v.root);
    return ok;
}

static bool znam_routes_alice_services(struct node_db *ndb, bool ok)
{
    uint8_t svc_resp[65536];
    struct json_value svc_root;
    const struct json_value *svc_records;
    const struct json_value *svc_endpoints;
    const struct json_value *svc_onion;
    const struct json_value *svc_filter_contract;
    const struct json_value *svc_allowed_filters;
    const struct json_value *slot[6];
    size_t sn;
    const char *svc_body;

    rpc_name_set_state(ndb);
    sn = api_handle_request("GET", "/api/v1/names/alice/services",
                            NULL, 0, svc_resp, sizeof(svc_resp));
    rpc_name_set_state(NULL);
    svc_body = api_test_body(svc_resp, sn, sizeof(svc_resp));
    json_init(&svc_root);
    ok = ok && sn > 0 && svc_body &&
         json_read(&svc_root, svc_body, strlen(svc_body));
    svc_records = ok ? json_get(&svc_root, "records") : NULL;
    svc_endpoints = ok ? json_get(&svc_root, "endpoints") : NULL;
    svc_onion = api_test_find_str_field(svc_records, "key", "service.onion");
    svc_filter_contract = ok ? json_get(&svc_root, "filter_contract") : NULL;
    svc_allowed_filters = svc_filter_contract
        ? json_get(svc_filter_contract, "allowed_filters") : NULL;
    slot[ZNAM_SVC_ROOT] = &svc_root;
    slot[ZNAM_SVC_RECORDS] = svc_records;
    slot[ZNAM_SVC_ENDPOINTS] = svc_endpoints;
    slot[ZNAM_SVC_ONION] = svc_onion;
    slot[ZNAM_SVC_FILTER] = svc_filter_contract;
    slot[ZNAM_SVC_ALLOWED] = svc_allowed_filters;
    ok = znam_route_check_all(ok, slot, znam_route_services_rows,
                              sizeof znam_route_services_rows /
                              sizeof znam_route_services_rows[0]);
    json_free(&svc_root);
    return ok;
}

static bool znam_routes_alice_services_filtered(struct node_db *ndb, bool ok)
{
    uint8_t filtered_resp[65536];
    struct json_value filtered_root;
    const struct json_value *filters;
    const struct json_value *filtered_records;
    const struct json_value *filtered_endpoints;
    const struct json_value *filtered_p2p;
    const struct json_value *filtered_plan;
    const struct json_value *slot[6];
    size_t fn;
    const char *filtered_body;

    rpc_name_set_state(ndb);
    fn = api_handle_request(
        "GET",
        "/api/v1/names/alice/services?"
        "transport=p2p&valid=true&endpoint_only=true",
        NULL, 0, filtered_resp, sizeof(filtered_resp));
    rpc_name_set_state(NULL);
    filtered_body = api_test_body(filtered_resp, fn, sizeof(filtered_resp));
    json_init(&filtered_root);
    ok = ok && fn > 0 && filtered_body &&
         json_read(&filtered_root, filtered_body, strlen(filtered_body));
    filters = ok ? json_get(&filtered_root, "filters") : NULL;
    filtered_records = ok ? json_get(&filtered_root, "records") : NULL;
    filtered_endpoints = ok ? json_get(&filtered_root, "endpoints") : NULL;
    filtered_p2p = api_test_find_str_field(filtered_records, "key",
                                           "service.p2p");
    filtered_plan = ok ? json_get(&filtered_root, "routing_plan") : NULL;
    slot[ZNAM_FILT_ROOT] = &filtered_root;
    slot[ZNAM_FILT_FILTERS] = filters;
    slot[ZNAM_FILT_RECORDS] = filtered_records;
    slot[ZNAM_FILT_ENDPOINTS] = filtered_endpoints;
    slot[ZNAM_FILT_P2P] = filtered_p2p;
    slot[ZNAM_FILT_PLAN] = filtered_plan;
    ok = znam_route_check_all(ok, slot, znam_route_filtered_rows,
                              sizeof znam_route_filtered_rows /
                              sizeof znam_route_filtered_rows[0]);
    json_free(&filtered_root);
    return ok;
}

static bool znam_routes_read_filter_error(struct node_db *ndb, bool ok,
                                          const char *path,
                                          struct json_value *root,
                                          uint8_t *resp, size_t cap)
{
    size_t n;
    const char *body;

    rpc_name_set_state(ndb);
    n = api_handle_request("GET", path, NULL, 0, resp, cap);
    rpc_name_set_state(NULL);
    resp[n < cap ? n : cap - 1] = '\0';
    body = api_test_body(resp, n, cap);
    json_init(root);
    return ok && n > 0 &&
           strstr((char *)resp, "400 Bad Request") != NULL &&
           body && json_read(root, body, strlen(body));
}

static bool znam_routes_alice_services_invalid(struct node_db *ndb, bool ok)
{
    uint8_t invalid_resp[8192];
    struct json_value invalid_root;
    const struct json_value *allowed;
    const struct json_value *slot[2];
    const struct json_value *tranport_slot[1];

    ok = znam_routes_read_filter_error(
        ndb, ok, "/api/v1/names/alice/services?valid=maybe",
        &invalid_root, invalid_resp, sizeof(invalid_resp));
    allowed = ok ? json_get(&invalid_root, "allowed_filters") : NULL;
    slot[ZNAM_ERR_ROOT] = &invalid_root;
    slot[ZNAM_ERR_ALLOWED] = allowed;
    ok = znam_route_check_all(ok, slot, znam_route_maybe_rows,
                              sizeof znam_route_maybe_rows /
                              sizeof znam_route_maybe_rows[0]);
    json_free(&invalid_root);

    ok = znam_routes_read_filter_error(
        ndb, ok, "/api/v1/names/alice/services?tranport=p2p",
        &invalid_root, invalid_resp, sizeof(invalid_resp));
    tranport_slot[ZNAM_ERR_ROOT] = &invalid_root;
    ok = znam_route_check_all(ok, tranport_slot, znam_route_tranport_rows,
                              sizeof znam_route_tranport_rows /
                              sizeof znam_route_tranport_rows[0]);
    json_free(&invalid_root);
    return ok;
}

static bool znam_routes_alice_show_payload(struct node_db *ndb)
{
    bool ok = znam_routes_alice_show_record(ndb);
    ok = znam_routes_alice_services(ndb, ok);
    ok = znam_routes_alice_services_filtered(ndb, ok);
    return znam_routes_alice_services_invalid(ndb, ok);
}

static bool znam_routes_name_show_case(int *failures)
{
    char dbdir[256];
    char dbpath[320];
    struct node_db ndb;
    bool opened;
    bool ok;

    memset(&ndb, 0, sizeof(ndb));
    test_make_tmpdir(dbdir, sizeof(dbdir), "api_znam", "name_show");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
    opened = node_db_open(&ndb, dbpath);
    ok = znam_routes_seed_alice(&ndb, opened);
    *failures += !directory_inactive_copy_cases(&ndb);
    ok = znam_routes_save_alice_addrs(&ndb, ok);
    if (ok)
        ok = znam_routes_alice_show_payload(&ndb);
    rpc_name_set_state(NULL);
    if (opened) {
        bool routing_ok = api_test_filtered_valid_routing(&ndb);
        ok &= routing_ok;
        node_db_close(&ndb);
    }
    ok &= fixture_rm_ok(dbdir);
    return ok;
}

int api_znam_routes_focused_tests(void)
{
    int failures = 0;

    printf("api: json route emits oversized names payload safely... ");
    if (znam_routes_oversized_names_case())
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("api: name show includes service and address records... ");
    if (znam_routes_name_show_case(&failures))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    return failures;
}
