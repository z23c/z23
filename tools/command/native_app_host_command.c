/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Owner-facing recurring hosting status and exact-intent revocation. */
#include "command/native_command.h"
#include "command/native_app_compose.h"
#include "command/native_zcode_package_copy.h"
#include "vcs/app_offer.h"
#include "json/json.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const host_notice =
    "Hosting renews public offers when enabled. Stopping does not change the carrier pin; "
    "already published offers can remain discoverable until their expiry.";

static bool host_inputs(const struct json_value *input,
                         const char **host, const char **carrier,
                         struct zcl_command_reply *reply)
{
    *host = zcl_package_copy_str(input, "host");
    *carrier = zcl_package_copy_str(input, "carrier");
    if (vcs_app_offer_hex_valid(*host, 32) && vcs_app_offer_hex_valid(*carrier, 32))
        return true;
    zcl_package_copy_fail(reply, "INVALID_HOST_INTENT", false,
        "host and carrier must identify the exact stored hosting intent", "app.host");
    return false;
}

static bool host_output(struct zcl_command_reply *reply,
                         const struct json_value *body, bool executed)
{
    return json_push_kv_str(&reply->data, "host", zcl_package_copy_str(body, "host")) &&
           json_push_kv_str(&reply->data, "carrier", zcl_package_copy_str(body, "carrier")) &&
           json_push_kv_int(&reply->data, "generation", json_get_int(json_get(body, "generation"))) &&
           json_push_kv_bool(&reply->data, "enabled", json_get_bool(json_get(body, "enabled"))) &&
           json_push_kv_int(&reply->data, "due_at", json_get_int(json_get(body, "due_at"))) &&
           json_push_kv_bool(&reply->data, "pending", json_get_bool(json_get(body, "pending"))) &&
           json_push_kv_bool(&reply->data, "executed", executed) &&
           json_push_kv_str(&reply->data, "hosting_notice", host_notice);
}

static bool host_state_valid(const struct json_value *body)
{
    const struct json_value *generation = json_get(body, "generation");
    const struct json_value *enabled = json_get(body, "enabled");
    const struct json_value *due = json_get(body, "due_at");
    const struct json_value *pending = json_get(body, "pending");
    return generation && generation->type == JSON_INT && json_get_int(generation) > 0 &&
        enabled && enabled->type == JSON_BOOL && due && due->type == JSON_INT &&
        json_get_int(due) >= 0 && pending && pending->type == JSON_BOOL;
}

static bool host_body_valid(const struct json_value *body,
                             const char *host, const char *carrier)
{
    const struct json_value *ok = json_get(body, "ok");
    const char *got_host = zcl_package_copy_str(body, "host");
    const char *got_carrier = zcl_package_copy_str(body, "carrier");
    return ok && ok->type == JSON_BOOL && json_get_bool(ok) &&
        host_state_valid(body) && got_host && got_carrier &&
        !strcmp(host, got_host) && !strcmp(carrier, got_carrier);
}

static bool host_list_item_valid(const struct json_value *item, const char **host, const char **carrier)
{
    *host = zcl_package_copy_str(item, "host"); *carrier = zcl_package_copy_str(item, "carrier");
    const char *name = zcl_package_copy_str(item, "name");
    const char *publisher = zcl_package_copy_str(item, "publisher");
    const char *root = zcl_package_copy_str(item, "package_root");
    return item && item->type == JSON_OBJ && vcs_app_offer_hex_valid(*host, 32) &&
        vcs_app_offer_hex_valid(*carrier, 32) && name && name[0] &&
        strnlen(name, VCS_PACKAGE_RELEASE_NAME_MAX + 1u) <= VCS_PACKAGE_RELEASE_NAME_MAX &&
        vcs_app_offer_hex_valid(publisher, 33) && vcs_app_offer_hex_valid(root, 32) && host_state_valid(item);
}

static bool host_list_project(struct json_value *out, const struct json_value *items)
{
    struct json_value array; json_init(&array); json_set_array(&array); bool ok = true;
    static const char *const keys[] = {"host", "carrier", "name", "publisher", "package_root", "generation", "enabled", "due_at", "pending"};
    for (size_t i = 0; ok && i < json_size(items); ++i) {
        struct json_value item; json_init(&item); json_set_object(&item);
        const struct json_value *src = json_at(items, i);
        for (size_t k = 0; ok && k < sizeof(keys)/sizeof(keys[0]); ++k)
            ok = json_push_kv(&item, keys[k], json_get(src, keys[k]));
        if (ok) ok = json_push_back(&array, &item);
        json_free(&item);
    }
    if (ok) ok = json_push_kv(out, "items", &array);
    json_free(&array); return ok;
}

static bool host_list_cursor(const struct json_value *input, const char **host, const char **carrier)
{
    const struct json_value *h = json_get(input, "after_host"), *c = json_get(input, "after_carrier");
    *host = h && h->type == JSON_STR ? json_get_str(h) : NULL;
    *carrier = c && c->type == JSON_STR ? json_get_str(c) : NULL;
    return (!h && !c) || (*host && *carrier && vcs_app_offer_hex_valid(*host, 32) && vcs_app_offer_hex_valid(*carrier, 32));
}
static bool host_list_rows(const struct json_value *items, const char **last_host, const char **last_carrier)
{
    for (size_t i = 0; i < json_size(items); ++i) {
        const char *next_host, *next_carrier;
        if (!host_list_item_valid(json_at(items, i), &next_host, &next_carrier) ||
            (*last_host && strcmp(next_host, *last_host) <= 0 &&
             (strcmp(next_host, *last_host) || strcmp(next_carrier, *last_carrier) <= 0))) return false;
        *last_host = next_host; *last_carrier = next_carrier;
    }
    return true;
}
static bool host_list_finish(struct zcl_command_reply *reply, const struct json_value *items,
                             bool more, const char *host, const char *carrier)
{
    return host_list_project(&reply->data, items) && json_push_kv_bool(&reply->data, "more", more) &&
        (!more || (json_push_kv_str(&reply->data, "next_host", host) && json_push_kv_str(&reply->data, "next_carrier", carrier)));
}
static bool host_list_output(struct zcl_command_reply *reply, const struct json_value *body,
                             const char *last_host, const char *last_carrier)
{
    const struct json_value *items = json_get(body, "items"), *more = json_get(body, "more"), *success = json_get(body, "ok");
    bool ok = success && success->type == JSON_BOOL && json_get_bool(success) && items && items->type == JSON_ARR &&
        json_size(items) <= 4 && more && more->type == JSON_BOOL && (!json_get_bool(more) || json_size(items) == 4);
    if (ok) ok = host_list_rows(items, &last_host, &last_carrier);
    if (ok) ok = host_list_finish(reply, items, json_get_bool(more), last_host, last_carrier);
    return ok;
}
void zcl_native_handle_app_host_list(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    const char *host, *carrier;
    if (!host_list_cursor(request ? request->input : NULL, &host, &carrier)) {
        zcl_package_copy_fail(reply, "BAD_CURSOR", false, "a complete host and carrier cursor is required", "app.host.list"); return;
    }
    struct json_value in, body; json_init(&body);
    const char *kv[] = {"op", "app_host_list", "after_host", host, "after_carrier", carrier};
    bool built = zcl_app_input(&in, kv, 6), ok = built && zcl_native_fleet_board_call(&in, &body, reply);
    json_free(&in);
    if (ok) ok = host_list_output(reply, &body, host, carrier);
    if (!ok && reply->status == ZCL_COMMAND_STATUS_PASSED)
        zcl_package_copy_fail(reply, "HOST_LIST_UNAVAILABLE", false, "hosting intents could not be read safely", "app.host.list");
    json_free(&body);
}

static bool host_status(const char *host, const char *carrier,
                         struct json_value *body, struct zcl_command_reply *reply)
{
    struct json_value in;
    const char *kv[] = {"op", "app_host_status", "host", host, "carrier", carrier};
    bool built = zcl_app_input(&in, kv, 6);
    bool ok = built && zcl_native_fleet_board_call(&in, body, reply);
    json_free(&in);
    if (ok && !host_body_valid(body, host, carrier)) {
        zcl_package_copy_fail(reply, "BAD_HOST_STATUS", false,
            "the node did not return the requested hosting intent", "app.host.status");
        return false;
    }
    if (!built) zcl_package_copy_fail(reply, "ALLOC", false,
        "could not prepare hosting status request", "app.host.status");
    return ok;
}

static int64_t host_generation(const struct json_value *value)
{
    if (value && value->type == JSON_INT) return json_get_int(value);
    const char *text = json_get_str(value);
    if (!text || text[0] < '0' || text[0] > '9') return 0;
    char *end;
    errno = 0;
    long long parsed = strtoll(text, &end, 10);
    return errno || *end || parsed <= 0 || parsed > INT64_MAX ? 0 : (int64_t)parsed;
}

void zcl_native_handle_app_host_status(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    const char *host, *carrier;
    if (!host_inputs(request ? request->input : NULL, &host, &carrier, reply)) return;
    struct json_value body;
    json_init(&body);
    if (host_status(host, carrier, &body, reply) && !host_output(reply, &body, false))
        zcl_package_copy_fail(reply, "ALLOC", false,
            "could not copy hosting status", "app.host.status");
    json_free(&body);
}

static bool host_stop_plan(const struct json_value *input, const char *host,
                            const char *carrier, int64_t *generation,
                            uint8_t plan[32], struct zcl_command_reply *reply, bool resume)
{
    const struct json_value *value = json_get(input, "generation");
    *generation = host_generation(value);
    if (*generation <= 0 || *generation == INT64_MAX) {
        zcl_package_copy_fail(reply, "GENERATION_REQUIRED", false,
            "use the exact generation returned by app.host.status", resume ? "app.host.resume" : "app.host.stop");
        return false;
    }
    char number[32];
    int n = snprintf(number, sizeof(number), "%lld", (long long)*generation);
    if (n <= 0 || (size_t)n >= sizeof(number)) return false;
    const char *parts[] = {host, carrier, number};
    zcl_app_plan_id(resume ? "zcl.app_host.resume.v1" : "zcl.app_host.stop.v1", parts, 3, plan);
    return true;
}

static bool host_stop_current(const char *host, const char *carrier, int64_t generation,
                               struct json_value *body, struct zcl_command_reply *reply, bool resume)
{
    if (!host_status(host, carrier, body, reply)) return false;
    const struct json_value *value = json_get(body, "generation");
    const struct json_value *enabled = json_get(body, "enabled");
    if (value && value->type == JSON_INT && json_get_int(value) == generation &&
        enabled && enabled->type == JSON_BOOL && json_get_bool(enabled) != resume) return true;
    zcl_package_copy_fail(reply, "HOST_INTENT_STALE", false,
        "hosting intent changed or is already in the requested state; read its status again", resume ? "app.host.resume" : "app.host.stop");
    return false;
}

static bool host_change_result_valid(const struct json_value *body, const char *host,
                                     const char *carrier, int64_t generation, bool resume)
{
    return host_body_valid(body, host, carrier) &&
        json_get_bool(json_get(body, "enabled")) == resume &&
        !json_get_bool(json_get(body, "pending")) &&
        (resume || json_get_int(json_get(body, "due_at")) == 0) &&
        json_get_int(json_get(body, "generation")) == generation + 1;
}

static void host_stop_commit(const struct json_value *input, const char *host,
                              const char *carrier, int64_t generation,
                              const uint8_t plan[32], struct zcl_command_reply *reply, bool resume)
{
    const char *command = resume ? "app.host.resume" : "app.host.stop";
    if (!zcl_package_copy_plan_matches(input, plan, reply, command)) return;
    struct json_value in, body;
    json_init(&body);
    const char *kv[] = {"op", resume ? "app_host_resume" : "app_host_stop", "host", host, "carrier", carrier,
                        "plan_id", zcl_package_copy_str(input, "plan_id")};
    bool built = zcl_app_input(&in, kv, 8) &&
        json_push_kv_int(&in, "generation", generation) &&
        json_push_kv_bool(&in, "confirm", true);
    if (!built) {
        zcl_package_copy_fail(reply, "ALLOC", false,
            "could not prepare hosting change request", command);
    } else if (!zcl_native_fleet_board_call(&in, &body, reply)) {
        /* A lost acknowledgement cannot prove that revocation did not commit. */
        reply->error.mutated = true;
    } else if (!host_change_result_valid(&body, host, carrier, generation, resume)) {
        zcl_package_copy_fail(reply, resume ? "RESUME_UNCONFIRMED" : "STOP_UNCONFIRMED", true,
            "the node did not confirm this exact change; read hosting status", command);
    } else if (!host_output(reply, &body, true)) {
        zcl_package_copy_fail(reply, "ALLOC", true,
            "change returned successfully but its result could not be copied; read status", command);
    }
    json_free(&in);
    json_free(&body);
}

static void host_change(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply, bool resume)
{
    const struct json_value *input = request ? request->input : NULL;
    const char *host, *carrier;
    int64_t generation;
    uint8_t plan[32];
    if (!host_inputs(input, &host, &carrier, reply) ||
        !host_stop_plan(input, host, carrier, &generation, plan, reply, resume)) return;
    struct json_value body;
    json_init(&body);
    if (host_stop_current(host, carrier, generation, &body, reply, resume)) {
        if (zcl_package_copy_confirmed(input))
            host_stop_commit(input, host, carrier, generation, plan, reply, resume);
        else if (!host_output(reply, &body, false) ||
                 !zcl_package_copy_push_root(&reply->data, "plan_id", plan))
            zcl_package_copy_fail(reply, "ALLOC", false,
                "could not prepare hosting change plan", resume ? "app.host.resume" : "app.host.stop");
    }
    json_free(&body);
}

void zcl_native_handle_app_host_stop(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{ host_change(request, reply, false); }

void zcl_native_handle_app_host_resume(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{ host_change(request, reply, true); }
