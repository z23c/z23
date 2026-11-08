/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Node-side owner operations for recurring app hosting. */
#include "config/boot_app_host.h"
#include "config/boot_fleet_board.h"
#include "boot_fleet_board_rpc_internal.h"
#include "base/hex.h"
#include "json/json.h"
#include "models/app_host_intent.h"
#include "vcs/package_store.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void fb_error(struct json_value *result, const char *code, const char *message)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", false);
    json_push_kv_str(result, "code", code);
    json_push_kv_str(result, "message", message);
}
const char *fb_str(const struct json_value *in, const char *key, const char *fallback)
{
    const char *value = json_get_str(json_get(in, key));
    return value[0] ? value : fallback;
}
int64_t fb_int(const struct json_value *in, const char *key, int64_t fallback)
{
    const struct json_value *v = json_get(in, key);
    return v && v->type == JSON_INT ? json_get_int(v) : fallback;
}
bool fb_bool(const struct json_value *in, const char *key)
{
    const struct json_value *v = json_get(in, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}
static bool fb_host_keys(const struct json_value *in, uint8_t host[32], const char **carrier)
{
    const char *host_hex = fb_str(in, "host", NULL);
    *carrier = fb_str(in, "carrier", NULL);
    return vcs_app_offer_hex_valid(host_hex, 32) && zcl_hex_decode_lower(host_hex, host, 32) &&
           vcs_app_offer_hex_valid(*carrier, 32);
}

static bool fb_host_render(struct json_value *result, const struct db_app_host_intent *row)
{
    char host[65]; zcl_hex_encode(row->binding.local_host, 32, host);
    json_set_object(result);
    return json_push_kv_bool(result, "ok", true) && json_push_kv_str(result, "host", host) &&
        json_push_kv_str(result, "carrier", row->binding.carrier_root) &&
        json_push_kv_int(result, "generation", row->generation) &&
        json_push_kv_bool(result, "enabled", row->enabled) &&
        json_push_kv_int(result, "due_at", row->due_at) &&
        json_push_kv_bool(result, "pending", row->pending);
}

static void fb_host_status(struct node_db *db, const struct json_value *in,
                           struct json_value *result)
{
    uint8_t host[32]; const char *carrier;
    struct db_app_host_intent row;
    if (!fb_host_keys(in, host, &carrier)) { fb_error(result, "BAD_INPUT", "host and carrier are required"); return; }
    if (db_app_host_intent_find(db, host, carrier, &row) != APP_HOST_OK) {
        fb_error(result, "HOST_INTENT_UNAVAILABLE", "the requested hosting intent is unavailable"); return;
    }
    if (!fb_host_render(result, &row)) fb_error(result, "ALLOC", "cannot describe hosting intent");
}

static void fb_host_stop(struct node_db *db, const struct json_value *in,
                         struct json_value *result)
{
    uint8_t host[32], expected[32], actual[32]; const char *carrier;
    const char *host_hex = fb_str(in, "host", NULL), *plan = fb_str(in, "plan_id", NULL);
    int64_t generation = fb_int(in, "generation", 0); char number[32];
    if (!fb_host_keys(in, host, &carrier) || !fb_bool(in, "confirm") || generation <= 0 ||
        generation == INT64_MAX || !vcs_app_offer_hex_valid(plan, 32) ||
        !zcl_hex_decode_lower(plan, expected, sizeof(expected))) {
        fb_error(result, "BAD_INPUT", "confirmed host, carrier, generation and plan are required"); return;
    }
    (void)snprintf(number, sizeof(number), "%lld", (long long)generation);
    const char *parts[] = {host_hex, carrier, number};
    vcs_app_plan_hash("zcl.app_host.stop.v1", parts, 3, actual);
    if (memcmp(actual, expected, sizeof(actual))) { fb_error(result, "PLAN_MISMATCH", "hosting stop plan changed"); return; }
    if (boot_app_host_stop(db, host, carrier, generation) != BOOT_APP_HOST_OK) {
        fb_error(result, "HOST_STOP_REFUSED", "hosting intent could not be stopped; read status"); return;
    }
    fb_host_status(db, in, result);
}

static void fb_host_enable(struct node_db *db, const struct json_value *in,
                           struct json_value *result, int64_t now)
{
    const char *text = fb_str(in, "offer", NULL);
    struct boot_app_host_plan plan = {0};
    if (!text || strnlen(text, ZCL_APP_OFFER_TEXT_MAX + 1u) > ZCL_APP_OFFER_TEXT_MAX ||
        !zcl_app_offer_parse(text, strlen(text), &plan.offer) || !fb_bool(in, "confirm")) {
        fb_error(result, "BAD_INPUT", "a confirmed canonical offer is required"); return;
    }
    plan.post_id = fb_str(in, "post_id", NULL); plan.post_host = fb_str(in, "post_host", NULL);
    plan.receive_plan = fb_str(in, "receive_plan", NULL); plan.datadir = fb_str(in, "datadir", NULL);
    plan.token = fb_str(in, "token", NULL); plan.expected_plan = fb_str(in, "plan_id", NULL);
    uint8_t local[32]; int64_t generation = 0;
    enum boot_app_host_result r = boot_app_host_enable(db, vcs_package_store_global(), &plan,
                                                       now, local, &generation);
    if (r != BOOT_APP_HOST_OK) { fb_error(result, "HOST_ENABLE_REFUSED", "recurring hosting could not be enabled"); return; }
    struct db_app_host_intent row;
    if (db_app_host_intent_find(db, local, plan.offer.carrier, &row) != APP_HOST_OK ||
        row.generation != generation || !fb_host_render(result, &row))
        fb_error(result, "HOST_ENABLE_UNCONFIRMED", "hosting may be enabled; read status");
}

bool boot_app_host_rpc_dispatch(struct node_db *db, const char *op,
                                 const struct json_value *in,
                                 struct json_value *result, int64_t now)
{
    if (!strcmp(op, "app_host_status")) fb_host_status(db, in, result);
    else if (!strcmp(op, "app_host_stop")) fb_host_stop(db, in, result);
    else if (!strcmp(op, "app_host_enable")) fb_host_enable(db, in, result, now);
    else return false;
    return true;
}
