/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API HTTP contract: argument validation, method rejection, the 404/405
 * error envelope, and the escaping of runtime strings into JSON.
 */

#include "test/api_test_fixtures.h"

int api_http_contract_focused_tests(void)
{
    int failures = 0;
    uint8_t resp[8192];

    printf("api: NULL params return 0... ");
    {
        size_t n = api_handle_request(NULL, "/api/blocks", NULL, 0, resp, sizeof(resp));
        bool ok = (n == 0);
        n = api_handle_request("GET", NULL, NULL, 0, resp, sizeof(resp));
        ok = ok && (n == 0);
        n = api_handle_request("GET", "/api/blocks", NULL, 0, NULL, sizeof(resp));
        ok = ok && (n == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: POST returns 405... ");
    {
        size_t n = api_handle_request("POST", "/api/blocks", NULL, 0,
                                       resp, sizeof(resp));
        const char *body = api_test_body(resp, n, sizeof(resp));
        struct json_value root;
        json_init(&root);
        bool ok = (n > 0 && strstr((char *)resp, "405") != NULL &&
                   body && json_read(&root, body, strlen(body)));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.rest_error.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "api_version")),
                          "v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "error")),
                          "Method not allowed") == 0;
        json_free(&root);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: OPTIONS returns CORS headers... ");
    {
        size_t n = api_handle_request("OPTIONS", "/api/blocks", NULL, 0,
                                       resp, sizeof(resp));
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        bool ok = (n > 0 && strstr((char *)resp, "Access-Control") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: unknown endpoint returns 404... ");
    {
        size_t n = api_handle_request("GET", "/api/nonexistent", NULL, 0,
                                       resp, sizeof(resp));
        const char *body = api_test_body(resp, n, sizeof(resp));
        struct json_value root;
        json_init(&root);
        bool ok = (n > 0 && strstr((char *)resp, "404") != NULL &&
                   body && json_read(&root, body, strlen(body)));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.rest_error.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "api_version")),
                          "v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "error")),
                          "Unknown API endpoint") == 0;
        json_free(&root);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: json error escapes runtime message... ");
    {
        const char *headers =
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: engine/application/json\r\n\r\n";
        const char *msg = "bad \"msg\"\nretry";
        size_t n = api_json_error(resp, sizeof(resp), headers, msg);
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
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
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: json error truncation returns written bytes... ");
    {
        const char *headers = "HTTP/1.1 500\r\n\r\n";
        uint8_t tiny[48];
        memset(tiny, 0xA5, sizeof(tiny));
        size_t n = api_json_error(tiny, sizeof(tiny), headers,
                                  "this message is intentionally longer than the response buffer");
        bool ok = n < sizeof(tiny) && tiny[n] == '\0';
        ok = ok && strstr((char *)tiny, "HTTP/1.1 500") != NULL;
        ok = ok && strstr((char *)tiny, "\r\n\r\n") != NULL;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: health escapes runtime error strings... ");
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
                                      resp, sizeof(resp));
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
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
            const struct json_value *errors =
                ok ? json_get(&root, "errors") : NULL;
            ok = errors != NULL;
            ok = ok && strcmp(json_get_str(json_get(errors, "last")),
                              msg) == 0;
            ok = ok && strcmp(json_get_str(json_get(errors, "last_type")),
                              event_type_name(EV_BLOCK_REJECTED)) == 0;
            ok = ok && !json_get_bool(json_get(&root, "serving"));
            ok = ok && json_get_int(json_get(&root, "warning_count")) >= 1;
            const struct json_value *status =
                ok ? json_get(&root, "status") : NULL;
            ok = ok && status != NULL;
            ok = ok && !json_get_bool(json_get(status, "serving"));
            ok = ok && strcmp(json_get_str(json_get(status,
                                                    "blocking_reason")),
                              "review_required_unknown") == 0;
            ok = ok && json_get_bool(json_get(status, "warning"));
            ok = ok && strstr(json_get_str(json_get(status,
                                                    "warning_reasons")),
                              "recent_error") != NULL;
            ok = ok && api_test_expect_security_posture_shape(&root);
        }
        json_free(&root);
        error_ring_init(er);
        api_set_state(NULL, NULL, NULL, NULL, NULL);
        reducer_frontier_provable_tip_reset();
        test_reset_shared_globals();
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
