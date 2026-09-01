/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Bounded, read-only observation of a co-located legacy zclassicd wallet. */

#include "services/legacy_balance_observer.h"

#include "json/json.h"
#include "base/log_macros.h"
#include "platform/time_compat.h"
#include "rpc/legacy_rpc_client.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZATOSHI_PER_ZCL 100000000LL

#ifdef ZCL_TESTING
static legacy_balance_rpc_call_fn test_rpc_call;

void legacy_balance_observer_set_test_call(legacy_balance_rpc_call_fn call)
{
    test_rpc_call = call;
}
#endif

static void observation_init(struct legacy_balance_observation *out)
{
    memset(out, 0, sizeof(*out));
    out->source = LEGACY_BALANCE_SOURCE_ZCLASSICD;
}

static struct zcl_result observation_error(
    struct legacy_balance_observation *out, int code, const char *reason)
{
    (void)snprintf(out->reason, sizeof(out->reason), "%s",
                   reason ? reason : "legacy balance observation failed");
    LOG_ERROR("legacy_balance", "%s", out->reason);
    return ZCL_ERR(code, "%s", out->reason);
}

static bool decimal_zat(const char *text, int64_t *out)
{
    if (!text || !out || text[0] < '0' || text[0] > '9')
        return false;

    uint64_t whole = 0;
    const char *p = text;
    while (*p >= '0' && *p <= '9') {
        uint64_t digit = (uint64_t)(*p++ - '0');
        if (whole > (UINT64_MAX - digit) / 10u)
            return false;
        whole = whole * 10u + digit;
    }

    uint64_t fraction = 0;
    unsigned digits = 0;
    if (*p == '.') {
        p++;
        while (*p >= '0' && *p <= '9') {
            if (digits == 8u)
                return false;
            fraction = fraction * 10u + (uint64_t)(*p++ - '0');
            digits++;
        }
        if (digits == 0u)
            return false;
    }
    if (*p != '\0')
        return false;
    while (digits++ < 8u)
        fraction *= 10u;

    if (whole > ((uint64_t)INT64_MAX - fraction) /
                    (uint64_t)ZATOSHI_PER_ZCL)
        return false;
    *out = (int64_t)(whole * (uint64_t)ZATOSHI_PER_ZCL + fraction);
    return true;
}

static struct zcl_result parse_result_object(
    const struct json_value *root, struct legacy_balance_observation *out)
{
    const struct json_value *result = json_get(root, "result");
    const struct json_value *error = json_get(root, "error");
    if (!result || result->type != JSON_OBJ ||
        (error && !json_is_null(error)))
        return observation_error(out, -2,
                                 "z_gettotalbalance returned an RPC error");

    const struct json_value *transparent = json_get(result, "transparent");
    const struct json_value *shielded = json_get(result, "private");
    const struct json_value *total = json_get(result, "total");
    if (!transparent || transparent->type != JSON_STR ||
        !shielded || shielded->type != JSON_STR ||
        !total || total->type != JSON_STR ||
        !decimal_zat(json_get_str(transparent), &out->transparent_zat) ||
        !decimal_zat(json_get_str(shielded), &out->shielded_zat) ||
        !decimal_zat(json_get_str(total), &out->total_zat))
        return observation_error(out, -2,
                                 "z_gettotalbalance amounts are invalid");

    if (out->transparent_zat > INT64_MAX - out->shielded_zat ||
        out->transparent_zat + out->shielded_zat != out->total_zat)
        return observation_error(out, -2,
                                 "z_gettotalbalance amounts are inconsistent");

    out->complete = true;
    (void)snprintf(out->reason, sizeof(out->reason),
                   "legacy zclassicd wallet observed");
    return ZCL_OK;
}

struct zcl_result legacy_balance_observation_parse(
    const char *raw_response, struct legacy_balance_observation *out)
{
    if (!out) {
        LOG_ERROR("legacy_balance", "legacy balance output is required");
        return ZCL_ERR(-1, "legacy balance output is required");
    }
    observation_init(out);
    if (!raw_response)
        return observation_error(out, -1, "legacy RPC response is required");

    const char *body = legacy_rpc_http_body(raw_response);
    if (!body)
        return observation_error(out, -2,
                                 "legacy RPC response has no HTTP body");
    struct json_value root;
    json_init(&root);
    if (!json_read(&root, body, strlen(body))) {
        json_free(&root);
        return observation_error(out, -2,
                                 "legacy RPC response is not valid JSON");
    }
    if (root.type != JSON_OBJ) {
        json_free(&root);
        return observation_error(out, -2,
                                 "legacy RPC response is not an object");
    }
    struct zcl_result result = parse_result_object(&root, out);
    json_free(&root);
    return result;
}

struct zcl_result legacy_balance_observe_with_call(
    legacy_balance_rpc_call_fn call, uint32_t timeout_ms,
    struct legacy_balance_observation *out)
{
    if (!out) {
        LOG_ERROR("legacy_balance", "legacy balance output is required");
        return ZCL_ERR(-1, "legacy balance output is required");
    }
    observation_init(out);
    if (!call || timeout_ms == 0u ||
        timeout_ms > LEGACY_BALANCE_OBSERVER_TIMEOUT_MS)
        return observation_error(out, -1,
                                 "legacy balance timeout must be 1..250 ms");

    static const char request[] =
        "{\"jsonrpc\":\"1.0\",\"id\":\"z23-holdings\","
        "\"method\":\"z_gettotalbalance\",\"params\":[]}";
    char *response = NULL;
    char err[LEGACY_BALANCE_OBSERVER_REASON_MAX + 1u] = {0};
    if (!call(request, timeout_ms, &response, err, sizeof(err))) {
        free(response);
        return observation_error(out, -3,
                                 err[0] ? err : "legacy RPC call failed");
    }

    struct zcl_result result = legacy_balance_observation_parse(response, out);
    free(response);
    if (result.ok)
        out->observed_at_unix = (int64_t)platform_time_wall_time_t();
    return result;
}

struct zcl_result legacy_balance_observe(
    struct legacy_balance_observation *out)
{
    legacy_balance_rpc_call_fn call =
        legacy_rpc_authenticated_call_with_timeout;
#ifdef ZCL_TESTING
    if (test_rpc_call)
        call = test_rpc_call;
#endif
    return legacy_balance_observe_with_call(
        call, LEGACY_BALANCE_OBSERVER_TIMEOUT_MS, out);
}
