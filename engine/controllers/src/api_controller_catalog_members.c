/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: serve static protocol and transaction-type REST member resources.
 */

#include "api_controller_internal.h"

#include "json/json.h"

size_t api_serve_protocol_member(const char *name, const char *freshness,
                                 uint8_t *response, size_t response_max)
{
    struct json_value result = {0};
    if (!api_app_protocol_show_json(name, &result)) {
        json_free(&result);
        return api_json_error(response, response_max, JSON_404_HEADERS,
                              "Protocol not found");
    }
    api_json_add_freshness(&result, freshness, -1);
    size_t n = api_json_ok(response, response_max, &result);
    json_free(&result);
    return n;
}

size_t api_serve_transaction_type_member(const char *type,
                                         const char *freshness,
                                         uint8_t *response,
                                         size_t response_max)
{
    struct json_value result = {0};
    if (!zcl_transaction_type_show_json(type, &result)) {
        json_free(&result);
        return api_json_error(response, response_max, JSON_404_HEADERS,
                              "Transaction type not found");
    }
    api_json_add_freshness(&result, freshness, -1);
    size_t n = api_json_ok(response, response_max, &result);
    json_free(&result);
    return n;
}
