/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Focused regression tests for the shared REST query-filter engine. */

#include "test/test_core.h"

#include "controllers/api_controller.h"
#include "controllers/name_controller.h"
#include "json/json.h"
#include "models/database.h"
#include "models/znam.h"
#include "util/file_tree_ops.h"
#include "../../../engine/controllers/src/api_controller_internal.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool substrings_in_order(const char *text,
                                const char *const *needles, size_t count)
{
    const char *cursor = text;

    for (size_t i = 0; cursor && i < count; i++) {
        cursor = strstr(cursor, needles[i]);
        if (cursor)
            cursor++;
    }
    return cursor != NULL;
}

static bool http_error_has_order(const char *path, const char *error_code,
                                 const char *const *needles, size_t count)
{
    uint8_t response[16384];
    size_t len = api_handle_request("GET", path, NULL, 0,
                                    response, sizeof(response));
    const char *body;

    response[len < sizeof(response) ? len : sizeof(response) - 1] = '\0';
    body = strstr((char *)response, "\r\n\r\n");
    return len > 0 && strstr((char *)response, "400 Bad Request") &&
           body && strstr(body + 4, error_code) &&
           substrings_in_order(body + 4, needles, count);
}

static bool all_char(const char *value, char expected)
{
    if (!value)
        return false;
    for (const char *p = value; *p; p++) {
        if (*p != expected)
            return false;
    }
    return true;
}

static bool assignment_precedence_cases(void)
{
    static const struct {
        const char *contract;
        const char *path;
        const char *key;
        const char *expected;
    } cases[] = {
        { API_QUERY_FILTER_SERVICE_OPERATIONS, "/?preferred_interface=rest&interface=rpc", "preferred_interface", "rpc" },
        { API_QUERY_FILTER_SERVICE_OPERATIONS, "/?interface=rpc&preferred_interface=rest", "preferred_interface", "rest" },
        { API_QUERY_FILTER_SERVICE_OPERATIONS, "/?preferred_interface=rest&interface=", "preferred_interface", "rest" },
        { API_QUERY_FILTER_SERVICE_OPERATIONS, "/?interface=rpc&preferred_interface=", "preferred_interface", "rpc" },
        { API_QUERY_FILTER_NAME_SERVICE_DIRECTORY, "/?service_contract=bootstrap&contract=onion_directory", "service_contract", "onion_directory" },
        { API_QUERY_FILTER_NAME_SERVICE_DIRECTORY, "/?contract=onion_directory&service_contract=bootstrap", "service_contract", "bootstrap" },
        { API_QUERY_FILTER_NAME_SERVICE_DIRECTORY, "/?service_contract=bootstrap&contract=", "service_contract", "bootstrap" },
        { API_QUERY_FILTER_NAME_SERVICE_DIRECTORY, "/?contract=onion_directory&service_contract=", "service_contract", "onion_directory" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct api_query_filter filter;
        char err[64] = "sticky";

        api_query_filter_init(&filter, cases[i].contract);
        api_query_filter_from_path(&filter, cases[i].path);
        if (!api_query_filter_validate(&filter, err, sizeof(err)) ||
            strcmp(err, "sticky") != 0 || !filter.active ||
            strcmp(api_query_filter_value(&filter, cases[i].key),
                   cases[i].expected) != 0)
            return false;
    }
    return true;
}

static bool destination_cap_cases(void)
{
    static const struct {
        const char *contract;
        const char *set_key;
        const char *read_key;
        size_t max_len;
    } cases[] = {
        { API_QUERY_FILTER_SERVICE_OPERATIONS, "service", "service", 63 },
        { API_QUERY_FILTER_SERVICE_OPERATIONS, "write_safety", "write_safety", 39 },
        { API_QUERY_FILTER_SERVICE_OPERATIONS, "preferred_interface", "preferred_interface", 31 },
        { API_QUERY_FILTER_SERVICE_OPERATIONS, "interface", "preferred_interface", 31 },
        { API_QUERY_FILTER_SERVICE_OPERATIONS, "status", "status", 31 },
        { API_QUERY_FILTER_SERVICE_OPERATIONS, "surface", "surface", 15 },
        { API_QUERY_FILTER_NAME_SERVICE_DIRECTORY, "service", "service", 63 },
        { API_QUERY_FILTER_NAME_SERVICE_DIRECTORY, "service_contract", "service_contract", 63 },
        { API_QUERY_FILTER_NAME_SERVICE_DIRECTORY, "contract", "service_contract", 63 },
        { API_QUERY_FILTER_NAME_SERVICE_DIRECTORY, "transport", "transport", 31 },
        { API_QUERY_FILTER_NAME_SERVICE_DIRECTORY, "endpoint_kind", "endpoint_kind", 63 },
        { API_QUERY_FILTER_NAME_SERVICE_DIRECTORY, "valid", "valid", 7 },
        { API_QUERY_FILTER_NAME_SERVICE_DIRECTORY, "endpoint_only", "endpoint_only", 7 },
    };
    char input[160];

    memset(input, 'A', sizeof(input) - 1);
    input[sizeof(input) - 1] = '\0';
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct api_query_filter filter;
        const char *value;

        api_query_filter_init(&filter, cases[i].contract);
        api_query_filter_set(&filter, cases[i].set_key, input);
        value = api_query_filter_value(&filter, cases[i].read_key);
        if (!filter.active || strlen(value) != cases[i].max_len ||
            !all_char(value, 'A'))
            return false;
    }
    return true;
}

static bool key_cap_cases(void)
{
    static const struct {
        const char *contract;
        size_t max_len;
        const char *allowed;
    } cases[] = {
        { API_QUERY_FILTER_SERVICE_OPERATIONS, 39,
          "service, write_safety, preferred_interface, status, surface" },
        { API_QUERY_FILTER_NAME_SERVICE_DIRECTORY, 47,
          "service, service_contract, transport, endpoint_kind, valid, endpoint_only" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct api_query_filter filter;
        char key[64], stored[48], path[96], expected[384], err[384] = {0};

        memset(key, 'k', cases[i].max_len + 5);
        key[cases[i].max_len + 5] = '\0';
        memset(stored, 'k', cases[i].max_len);
        stored[cases[i].max_len] = '\0';
        snprintf(path, sizeof(path), "/?%s=value", key);
        snprintf(expected, sizeof(expected),
                 "unknown filter '%s' (allowed: %s)", stored, cases[i].allowed);
        api_query_filter_init(&filter, cases[i].contract);
        api_query_filter_from_path(&filter, path);
        if (api_query_filter_validate(&filter, err, sizeof(err)) ||
            strcmp(err, expected) != 0)
            return false;
    }
    return true;
}

static bool validation_precedence_cases(void)
{
    static const struct {
        const char *contract;
        const char *path;
        const char *expected;
    } cases[] = {
        { API_QUERY_FILTER_SERVICE_OPERATIONS,
          "/?service=bad%2Evalue&first_unknown=&second_unknown=x&status=BAD",
          "unknown filter 'first_unknown' (allowed: service, write_safety, preferred_interface, status, surface)" },
        { API_QUERY_FILTER_SERVICE_OPERATIONS, "/?service=bad%2Evalue",
          "invalid service 'bad%2Evalue' (allowed: letters,digits,underscore,dash,dot)" },
        { API_QUERY_FILTER_SERVICE_OPERATIONS, "/?service=bad+value",
          "invalid service 'bad+value' (allowed: letters,digits,underscore,dash,dot)" },
        { API_QUERY_FILTER_SERVICE_OPERATIONS, "/?service=abc=def",
          "invalid service 'abc=def' (allowed: letters,digits,underscore,dash,dot)" },
        { API_QUERY_FILTER_SERVICE_OPERATIONS, "/?preferred_interface=REST",
          "invalid preferred_interface 'REST' (allowed: rest,rpc,native_or_planned)" },
        { API_QUERY_FILTER_SERVICE_OPERATIONS, "/?surface=BAD&write_safety=BAD",
          "invalid write_safety 'BAD' (allowed: public_read_only,operator_private,operator_private_destructive)" },
        { API_QUERY_FILTER_NAME_SERVICE_DIRECTORY,
          "/?transport=P2P&empty_unknown=&later_unknown=x",
          "unknown filter 'empty_unknown' (allowed: service, service_contract, transport, endpoint_kind, valid, endpoint_only)" },
        { API_QUERY_FILTER_NAME_SERVICE_DIRECTORY, "/?transport=P2P",
          "invalid transport 'P2P' (allowed: p2p,onion,p2p_or_onion,unspecified,none)" },
        { API_QUERY_FILTER_NAME_SERVICE_DIRECTORY,
          "/?endpoint_only=maybe&transport=BAD",
          "invalid transport 'BAD' (allowed: p2p,onion,p2p_or_onion,unspecified,none)" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct api_query_filter filter;
        char err[384] = {0};

        api_query_filter_init(&filter, cases[i].contract);
        api_query_filter_from_path(&filter, cases[i].path);
        if (api_query_filter_validate(&filter, err, sizeof(err)) ||
            strcmp(err, cases[i].expected) != 0)
            return false;
    }
    return true;
}

static bool internal_contract_errors_are_logged(void)
{
    struct api_query_filter filter;
    FILE *capture = tmpfile();
    int saved_stderr = capture ? dup(STDERR_FILENO) : -1;
    char internal_err[128] = {0}, user_err[128] = {0}, log[512] = {0};
    bool internal_rejected, user_rejected;
    size_t n;

    if (!capture || saved_stderr < 0)
        goto fail;
    fflush(stderr);
    if (dup2(fileno(capture), STDERR_FILENO) < 0)
        goto fail;
    api_query_filter_init(&filter, "service_operation");
    internal_rejected = !api_query_filter_validate(
        &filter, internal_err, sizeof(internal_err));
    api_query_filter_init(&filter, API_QUERY_FILTER_SERVICE_OPERATIONS);
    api_query_filter_set(&filter, "surface", "BAD");
    user_rejected = !api_query_filter_validate(&filter, user_err,
                                                sizeof(user_err));
    fflush(stderr);
    (void)dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);
    rewind(capture);
    n = fread(log, 1, sizeof(log) - 1, capture);
    log[n] = '\0';
    fclose(capture);
    return internal_rejected && user_rejected &&
           strcmp(internal_err,
                  "unknown query-filter contract 'service_operation'") == 0 &&
           strcmp(user_err,
                  "invalid surface 'BAD' (allowed: rest,rpc)") == 0 &&
           strstr(log, "[api.query_filter]") &&
           strstr(log, "unknown query-filter contract 'service_operation'") &&
           !strstr(log, "invalid surface 'BAD'");

fail:
    if (saved_stderr >= 0)
        close(saved_stderr);
    if (capture)
        fclose(capture);
    return false;
}

static bool service_route_cases(void)
{
    static const char *const order[] = {
        "\"service\":", "\"write_safety\":", "\"preferred_interface\":",
        "\"interface\":", "\"status\":", "\"surface\":"
    };
    struct json_value root = {0};
    const struct json_value *filters;
    char err[128] = "sticky";
    bool ok = api_service_operations_index_path_json(
        "/api/v1/service-operations?interface=rpc&service&status=active",
        &root, err, sizeof(err));

    filters = ok ? json_get(&root, "filters") : NULL;
    ok = ok && strcmp(err, "sticky") == 0 && filters &&
         json_get_bool(json_get(filters, "active")) &&
         strcmp(json_get_str(json_get(filters, "preferred_interface")),
                "rpc") == 0 &&
         strcmp(json_get_str(json_get(filters, "status")), "active") == 0 &&
         json_get(filters, "interface") == NULL &&
         json_get(filters, "service") == NULL;
    json_free(&root);

    if (ok) {
        strcpy(err, "sticky");
        ok = api_service_operations_index_path_json(
            "/api/v1/service-operations?service=", &root, err, sizeof(err));
        filters = ok ? json_get(&root, "filters") : NULL;
        ok = ok && strcmp(err, "sticky") == 0 && filters &&
             !json_get_bool(json_get(filters, "active")) &&
             strcmp(json_get_str(json_get(filters, "semantics")),
                    "exact-match filters over the static operation catalog") == 0;
        json_free(&root);
    }
    return ok && http_error_has_order(
        "/api/v1/service-operations?write_safety=unsafe",
        "invalid_service_operation_filter", order,
        sizeof(order) / sizeof(order[0]));
}

static bool name_route_cases(void)
{
    static const char *const order[] = {
        "\"service\":", "\"service_contract\":", "\"contract\":",
        "\"transport\":", "\"endpoint_kind\":", "\"valid\":",
        "\"endpoint_only\":"
    };
    char dir[192], dbpath[256], err[128] = {0};
    struct node_db ndb;
    struct znam_entry entry;
    struct json_value root = {0};
    bool opened, ok;

    memset(&ndb, 0, sizeof(ndb));
    test_make_tmpdir(dir, sizeof(dir), "api_query_filters", "name_route");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    opened = node_db_open(&ndb, dbpath);
    memset(&entry, 0, sizeof(entry));
    snprintf(entry.name, sizeof(entry.name), "filtercase");
    snprintf(entry.owner_address, sizeof(entry.owner_address),
             "t1-query-filter-owner");
    entry.target_type = ZNAM_TYPE_CONTENT;
    snprintf(entry.target_value, sizeof(entry.target_value),
             "sha3:query-filter-fixture");
    memset(entry.reg_txid, 0x71, sizeof(entry.reg_txid));
    entry.reg_height = 71;
    ok = opened && db_znam_save(&ndb, &entry) &&
         db_znam_text_save(&ndb, "filtercase", "service.onion",
                           "filtercase.onion:8033");
    if (ok)
        rpc_name_set_state(&ndb);

    if (ok) {
        strcpy(err, "sticky");
        ok = api_name_service_directory_path(
            "filtercase",
            "/api/v1/names/filtercase/services?contract=onion_directory&transport=onion",
            &root, err, sizeof(err));
        const struct json_value *filters = ok ? json_get(&root, "filters") : NULL;
        ok = ok && strcmp(err, "sticky") == 0 && filters &&
             strcmp(json_get_str(json_get(filters, "service_contract")),
                    "onion_directory") == 0 &&
             json_get(filters, "contract") == NULL &&
             json_get_int(json_get(&root, "service_record_count")) == 1;
        json_free(&root);
    }
    if (ok) {
        strcpy(err, "sticky");
        ok = api_name_service_directory_path(
            "filtercase", "/api/v1/names/filtercase/services?transport=",
            &root, err, sizeof(err));
        ok = ok && strcmp(err, "sticky") == 0 &&
             json_get(&root, "filters") == NULL &&
             json_get(&root, "filter_contract") != NULL;
        json_free(&root);
    }
    if (ok) {
        strcpy(err, "lookup-first");
        ok = !api_name_service_directory_path(
            "missing-filter-name",
            "/api/v1/names/missing-filter-name/services?valid=maybe",
            &root, err, sizeof(err)) && strcmp(err, "lookup-first") == 0;
        json_free(&root);
    }
    if (ok)
        ok = http_error_has_order(
            "/api/v1/names/filtercase/services?valid=maybe",
            "invalid_name_service_filter", order,
            sizeof(order) / sizeof(order[0]));

    rpc_name_set_state(NULL);
    if (opened)
        node_db_close(&ndb);
    (void)zcl_tree_remove(dir);
    return ok;
}

int api_query_filters_focused_tests(void)
{
    printf("api: shared query-filter aliases, precedence, and bounds... ");
    bool engine_ok = assignment_precedence_cases() &&
                     destination_cap_cases() && key_cap_cases() &&
                     validation_precedence_cases() &&
                     internal_contract_errors_are_logged();
    bool service_ok = service_route_cases();
    bool name_ok = name_route_cases();

    if (engine_ok && service_ok && name_ok) {
        printf("OK\n");
        return 0;
    }
    printf("FAIL (engine=%s service=%s name=%s)\n",
           engine_ok ? "ok" : "bad", service_ok ? "ok" : "bad",
           name_ok ? "ok" : "bad");
    return 1;
}
