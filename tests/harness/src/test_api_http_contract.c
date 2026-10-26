/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API HTTP contract: argument validation, method rejection, the 404/405
 * error envelope, and the escaping of runtime strings into JSON.
 */

#include "test/api_test_fixtures.h"

static bool http_contract_null_params_return_zero(uint8_t *resp,
                                                  size_t resp_size)
{
    size_t n = api_handle_request(NULL, "/api/blocks", NULL, 0, resp, resp_size);
    bool ok = (n == 0);
    n = api_handle_request("GET", NULL, NULL, 0, resp, resp_size);
    ok = ok && (n == 0);
    n = api_handle_request("GET", "/api/blocks", NULL, 0, NULL, resp_size);
    ok = ok && (n == 0);
    return ok;
}

static bool http_contract_error_envelope_matches(const char *method,
                                                 const char *path,
                                                 const char *status_text,
                                                 const char *error,
                                                 uint8_t *resp,
                                                 size_t resp_size)
{
    size_t n = api_handle_request(method, path, NULL, 0, resp, resp_size);
    const char *body = api_test_body(resp, n, resp_size);
    struct json_value root;
    json_init(&root);
    bool ok = (n > 0 && strstr((char *)resp, status_text) != NULL &&
               body && json_read(&root, body, strlen(body)));
    ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                      "zcl.rest_error.v1") == 0;
    ok = ok && strcmp(json_get_str(json_get(&root, "api_version")),
                      "v1") == 0;
    ok = ok && strcmp(json_get_str(json_get(&root, "error")),
                      error) == 0;
    json_free(&root);
    return ok;
}

static bool http_contract_options_returns_cors_headers(uint8_t *resp,
                                                       size_t resp_size)
{
    size_t n = api_handle_request("OPTIONS", "/api/blocks", NULL, 0,
                                  resp, resp_size);
    resp[n < resp_size ? n : resp_size - 1] = '\0';
    return n > 0 && strstr((char *)resp, "Access-Control") != NULL;
}

static bool http_contract_json_error_escapes_message(uint8_t *resp,
                                                     size_t resp_size)
{
    const char *headers =
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Content-Type: engine/application/json\r\n\r\n";
    const char *msg = "bad \"msg\"\nretry";
    size_t n = api_json_error(resp, resp_size, headers, msg);
    resp[n < resp_size ? n : resp_size - 1] = '\0';
    const char *body = strstr((char *)resp, "\r\n\r\n");
    bool ok = n > 0 && body != NULL;
    struct json_value root;
    json_init(&root);
    if (ok) {
        body += 4;
        ok = json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.rest_error.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "api_version")),
                          "v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "error")),
                          msg) == 0;
    }
    json_free(&root);
    return ok;
}

static bool http_contract_json_error_truncation_returns_written(void)
{
    const char *headers = "HTTP/1.1 500\r\n\r\n";
    uint8_t tiny[48];
    memset(tiny, 0xA5, sizeof(tiny));
    size_t n = api_json_error(tiny, sizeof(tiny), headers,
                              "this message is intentionally longer than the response buffer");
    bool ok = n < sizeof(tiny) && tiny[n] == '\0';
    ok = ok && strstr((char *)tiny, "HTTP/1.1 500") != NULL;
    ok = ok && strstr((char *)tiny, "\r\n\r\n") != NULL;
    return ok;
}

static bool http_contract_health_errors_field_matches(
    const struct json_value *root, const char *msg)
{
    const struct json_value *errors = json_get(root, "errors");
    bool ok = errors != NULL;
    ok = ok && strcmp(json_get_str(json_get(errors, "last")),
                      msg) == 0;
    ok = ok && strcmp(json_get_str(json_get(errors, "last_type")),
                      event_type_name(EV_BLOCK_REJECTED)) == 0;
    return ok;
}

static bool http_contract_health_reports_not_serving(
    const struct json_value *root)
{
    bool ok = !json_get_bool(json_get(root, "serving"));
    ok = ok && json_get_int(json_get(root, "warning_count")) >= 1;
    return ok;
}

static bool http_contract_health_status_field_matches(
    const struct json_value *root)
{
    const struct json_value *status = json_get(root, "status");
    bool ok = status != NULL;
    ok = ok && !json_get_bool(json_get(status, "serving"));
    ok = ok && strcmp(json_get_str(json_get(status,
                                            "blocking_reason")),
                      "review_required_unknown") == 0;
    ok = ok && json_get_bool(json_get(status, "warning"));
    ok = ok && strstr(json_get_str(json_get(status,
                                            "warning_reasons")),
                      "recent_error") != NULL;
    return ok;
}

static bool http_contract_health_escapes_error_strings(uint8_t *resp,
                                                       size_t resp_size)
{
    test_reset_shared_globals();
    progress_store_close();
    reducer_frontier_provable_tip_reset();
    api_set_state(NULL, NULL, NULL, NULL, NULL);
    struct error_ring *er = error_ring_global();
    const char *msg = "bad \"msg\"\n\"healthy\":true";
    error_ring_init(er);
    error_ring_observer(EV_BLOCK_REJECTED, 0, msg, (uint32_t)strlen(msg),
                        er);

    size_t n = api_handle_request("GET", "/api/health", NULL, 0,
                                  resp, resp_size);
    resp[n < resp_size ? n : resp_size - 1] = '\0';
    const char *body = strstr((char *)resp, "\r\n\r\n");
    bool ok = n > 0 && body != NULL;
    ok = ok && strstr((char *)resp,
                      "HTTP/1.1 503 Service Unavailable") != NULL;
    struct json_value root;
    json_init(&root);
    if (ok) {
        body += 4;
        ok = json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.health.v1") == 0;
        ok = ok && api_test_expect_freshness(&root, "served_tip",
                                             0, 0, true);
        ok = ok && http_contract_health_errors_field_matches(&root, msg);
        ok = ok && http_contract_health_reports_not_serving(&root);
        ok = ok && http_contract_health_status_field_matches(&root);
        ok = ok && api_test_expect_security_posture_shape(&root);
    }
    json_free(&root);
    error_ring_init(er);
    api_set_state(NULL, NULL, NULL, NULL, NULL);
    reducer_frontier_provable_tip_reset();
    test_reset_shared_globals();
    return ok;
}

int api_http_contract_focused_tests(void)
{
    int failures = 0;
    uint8_t resp[8192];

    printf("api: NULL params return 0... ");
    {
        bool ok = http_contract_null_params_return_zero(resp, sizeof(resp));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: POST returns 405... ");
    {
        bool ok = http_contract_error_envelope_matches(
            "POST", "/api/blocks", "405", "Method not allowed",
            resp, sizeof(resp));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: OPTIONS returns CORS headers... ");
    {
        bool ok = http_contract_options_returns_cors_headers(resp, sizeof(resp));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: unknown endpoint returns 404... ");
    {
        bool ok = http_contract_error_envelope_matches(
            "GET", "/api/nonexistent", "404", "Unknown API endpoint",
            resp, sizeof(resp));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: json error escapes runtime message... ");
    {
        bool ok = http_contract_json_error_escapes_message(resp, sizeof(resp));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: json error truncation returns written bytes... ");
    {
        bool ok = http_contract_json_error_truncation_returns_written();
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: health escapes runtime error strings... ");
    {
        bool ok = http_contract_health_escapes_error_strings(resp, sizeof(resp));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
