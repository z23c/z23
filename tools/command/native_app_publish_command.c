/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: publish a planned signed app copy through the existing board and carrier. */
#include "command/native_command.h"
#include "command/native_app_compose.h"
#include "command/native_app_offer.h"
#include "command/native_fleet_bundle.h"
#include "command/native_zcode_package_copy.h"
#include "json/json.h"
#include "base/hex.h"
#include "platform/rng.h"
#include "platform/private_directory.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define AP_COMMAND "app.publish"
#define AP_PATH 4400
struct ap_state {
    const struct json_value *input;
    struct zcl_command_reply *reply;
    const char *name, *datadir;
    char dir[AP_PATH], path[AP_PATH], token[33], share_plan[65];
    char share_name[160], root[65], publisher[67], onion[ZCL_APP_OFFER_ONION_MAX + 1u], host[63];
    char planned_name[160], planned_publisher[67];
    uint8_t plan[32];
    bool makes_key, saves_first;
};

static bool ap_component(const char *s)
{
    if (!s || !*s || *s == '.') return false;
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
              (*s >= '0' && *s <= '9') || *s == '-' || *s == '_'))
            return false;
    return true;
}

static bool ap_cleanup(struct ap_state *s, bool mutated)
{
    bool removed = unlink(s->path) == 0 || errno == ENOENT;
    if (removed && rmdir(s->dir) == 0) return true;
    zcl_package_copy_fail(s->reply, "TEMP_CLEANUP_FAILED", mutated,
                          "private publish directory could not be removed", s->dir);
    return false;
}

static bool ap_token(struct ap_state *s)
{
    const char *given = zcl_package_copy_str(s->input, "token");
    uint8_t random[16];
    if (zcl_package_copy_confirmed(s->input)) {
        if (!given || strlen(given) != 32 || !zcl_hex_decode_lower(given, random, sizeof(random))) {
            zcl_package_copy_fail(s->reply, "BAD_TOKEN", false, "confirm requires its exact plan token", AP_COMMAND);
            return false;
        }
        (void)snprintf(s->token, sizeof(s->token), "%s", given);
    } else {
        if (!rng_host_fill(random, sizeof(random))) {
            zcl_package_copy_fail(s->reply, "RNG_UNAVAILABLE", false, "cannot generate private plan token", AP_COMMAND);
            return false;
        }
        zcl_hex_encode(random, sizeof(random), s->token);
    }
    int n = ap_component(s->name) ? snprintf(s->dir, sizeof(s->dir), "%s/.app-publish-%s", s->datadir, s->token) : -1;
    if (n <= 0 || (size_t)n >= sizeof(s->dir) ||
        snprintf(s->path, sizeof(s->path), "%s/share.z23share", s->dir) >= (int)sizeof(s->path)) {
        zcl_package_copy_fail(s->reply, "BAD_COPY", false, "invalid copy name or datadir", AP_COMMAND);
        return false;
    }
    return true;
}

static int ap_p2p_port(const struct json_value *data)
{
    const struct json_value *mapping = json_get(data, "port_mapping");
    const struct json_value *routes = json_get(mapping, "routes");
    if (!routes || routes->type != JSON_ARR) return 0;
    int port = 0;
    for (size_t i = 0; i < json_size(routes); i++) {
        const struct json_value *route = json_at(routes, i);
        const char *name = json_get_str(json_get(route, "name"));
        if (!name || strcmp(name, "p2p_tcp") != 0) continue;
        const struct json_value *value = json_get(route, "virtual_port");
        if (port || !json_get_bool_or(route, "installed", false) || !value ||
            value->type != JSON_INT || json_get_int(value) < 1 || json_get_int(value) > 65535)
            return 0;
        port = (int)json_get_int(value);
    }
    return port;
}

static bool ap_onion(struct ap_state *s)
{
    struct json_value in;
    struct zcl_command_reply inner;
    json_init(&in);
    json_set_object(&in);
    bool ok = zcl_app_offer_call("core.network.onion.status", &in, &inner);
    json_free(&in);
    const char *address = ok ? zcl_app_inner_str(&inner, "onion_address") : NULL;
    const char *state = ok ? zcl_app_inner_str(&inner, "bootstrap_state") : NULL;
    int port = ok ? ap_p2p_port(&inner.data) : 0;
    bool ready = state && strcmp(state, "ready") == 0 &&
                 json_get_bool_or(&inner.data, "p2p_publish_ready", false) &&
                 address && strlen(address) == 62 && port &&
                 zcl_fleet_bundle_peer_is_onion(address);
    if (ready) {
        (void)snprintf(s->host, sizeof(s->host), "%s", address);
        int n = snprintf(s->onion, sizeof(s->onion), "%s:%d", address, port);
        ready = n > 0 && (size_t)n < sizeof(s->onion);
    }
    zcl_command_reply_free(&inner);
    if (!ready) zcl_package_copy_fail(s->reply, "ONION_UNAVAILABLE", false,
        ok ? "node onion publication is not ready" : "node onion status is unavailable", AP_COMMAND);
    return ready;
}

static bool ap_share_input(struct ap_state *s, struct json_value *in, bool confirm)
{
    const char *kv[] = {"copy", s->name, "datadir", s->datadir, "output", s->path};
    bool ok = zcl_app_input(in, kv, 6);
    if (confirm) ok = ok && json_push_kv_str(in, "plan_id", s->share_plan) &&
                            json_push_kv_bool(in, "confirm", true);
    return ok;
}

static bool ap_plan(struct ap_state *s)
{
    struct json_value in;
    struct zcl_command_reply inner;
    bool built = ap_share_input(s, &in, false);
    bool ok = zcl_app_inner_call_built("app.share-copy", &in, built, &inner);
    const char *p = ok ? zcl_app_inner_str(&inner, "plan_id") : NULL;
    if (!p || strlen(p) != 64) {
        if (ok) zcl_package_copy_fail(s->reply, "MALFORMED_INNER", false, "share plan omitted its plan id", AP_COMMAND);
        else zcl_app_inner_fail(s->reply, &inner, false);
        zcl_command_reply_free(&inner); return false;
    }
    (void)snprintf(s->share_plan, sizeof(s->share_plan), "%s", p);
    s->makes_key = json_get_bool_or(&inner.data, "makes_key", false);
    s->saves_first = json_get_bool_or(&inner.data, "saves_first", false);
    const char *planned_name = zcl_app_inner_str(&inner, "publishes_as");
    const char *planned_publisher = zcl_app_inner_str(&inner, "publisher_fingerprint");
    if (planned_name) (void)snprintf(s->planned_name, sizeof(s->planned_name), "%s", planned_name);
    if (planned_publisher) (void)snprintf(s->planned_publisher, sizeof(s->planned_publisher), "%s", planned_publisher);
    zcl_command_reply_free(&inner);
    const char *parts[] = {s->name, s->datadir, s->path, s->share_plan, s->onion};
    zcl_app_plan_id("zcl.app_publish.plan.v1", parts, 5, s->plan);
    return true;
}

static bool ap_plan_reply(struct ap_state *s)
{
    struct json_value *d = &s->reply->data;
    return json_push_kv_str(d, "room", "apps") &&
           json_push_kv_str(d, "offer_schema", ZCL_APP_OFFER_SCHEMA) &&
           json_push_kv_str(d, "token", s->token) &&
           json_push_kv_bool(d, "makes_key", s->makes_key) &&
           json_push_kv_bool(d, "saves_first", s->saves_first) &&
           (!s->planned_name[0] || json_push_kv_str(d, "publishes_as", s->planned_name)) &&
           (!s->planned_publisher[0] || json_push_kv_str(d, "publisher_fingerprint", s->planned_publisher)) &&
           zcl_package_copy_push_root(d, "plan_id", s->plan) &&
           json_push_kv_bool(d, "executed", false);
}

static bool ap_share(struct ap_state *s)
{
    struct json_value in;
    struct zcl_command_reply inner;
    bool built = ap_share_input(s, &in, true);
    bool ok = zcl_app_inner_call_built("app.share-copy", &in, built, &inner);
    const char *name = ok ? zcl_app_inner_str(&inner, "name") : NULL;
    const char *root = ok ? zcl_app_inner_str(&inner, "package_root") : NULL;
    const char *pub = ok ? zcl_app_inner_str(&inner, "publisher_fingerprint") : NULL;
    if (!name || !root || !pub || strlen(name) >= sizeof(s->share_name) ||
        strlen(root) != 64 || strlen(pub) != 66) {
        if (ok) zcl_package_copy_fail(s->reply, "MALFORMED_INNER", true, "share omitted its signed identity", AP_COMMAND);
        else zcl_app_inner_fail(s->reply, &inner, false);
        zcl_command_reply_free(&inner); return false;
    }
    (void)snprintf(s->share_name, sizeof(s->share_name), "%s", name);
    (void)snprintf(s->root, sizeof(s->root), "%s", root);
    (void)snprintf(s->publisher, sizeof(s->publisher), "%s", pub);
    zcl_command_reply_free(&inner); return true;
}

static bool ap_verify(struct ap_state *s)
{
    struct json_value in;
    struct zcl_command_reply inner;
    const char *kv[] = {"file", s->path};
    bool built = zcl_app_input(&in, kv, 2);
    bool ok = zcl_app_inner_call_built("zcode.package.bundle.verify", &in, built, &inner);
    const char *root = ok ? zcl_app_inner_str(&inner, "package_root") : NULL;
    const char *pub = ok ? zcl_app_inner_str(&inner, "publisher_fingerprint") : NULL;
    if (!root || !pub || strcmp(s->root, root) || strcmp(s->publisher, pub)) {
        if (ok) zcl_package_copy_fail(s->reply, "IDENTITY_MISMATCH", true, "signed share identity differs from the share result", AP_COMMAND);
        else zcl_app_inner_fail(s->reply, &inner, true);
        ok = false;
    }
    zcl_command_reply_free(&inner); return ok;
}

static bool ap_carrier_fields(struct ap_state *s, struct zcl_app_offer *offer,
                              const struct zcl_command_reply *inner)
{
    const char *carrier = zcl_app_inner_str(inner, "root");
    const char *sha = zcl_app_inner_str(inner, "sha256");
    const char *onion = zcl_app_inner_str(inner, "onion");
    const struct json_value *sz = json_get(&inner->data, "size");
    if (!carrier || strlen(carrier) != 64 || !sha || strlen(sha) != 64 ||
        (onion && strcmp(onion, s->host) != 0 && strcmp(onion, s->onion) != 0) ||
        !sz || sz->type != JSON_INT)
        return false;
    (void)snprintf(offer->carrier, sizeof(offer->carrier), "%s", carrier);
    (void)snprintf(offer->sha256, sizeof(offer->sha256), "%s", sha);
    (void)snprintf(offer->onion, sizeof(offer->onion), "%s", s->onion);
    offer->size = json_get_int(sz);
    return true;
}

static bool ap_offer(struct ap_state *s, char text[ZCL_APP_OFFER_TEXT_MAX + 1u])
{
    struct json_value in;
    struct zcl_command_reply inner;
    const char *kv[] = {"file", s->path};
    bool built = zcl_app_input(&in, kv, 2);
    bool ok = built && zcl_app_offer_call(ZCL_APP_OFFER_BUNDLE_OFFER, &in, &inner);
    json_free(&in);
    if (!built) zcl_command_reply_init(&inner, "zcl.app_publish.inner.v1");
    struct zcl_app_offer offer = {0};
    if (!ok || !ap_carrier_fields(s, &offer, &inner)) {
        if (ok) zcl_package_copy_fail(s->reply, "MALFORMED_INNER", true, "carrier omitted required offer fields", AP_COMMAND);
        else zcl_app_inner_fail(s->reply, &inner, true);
        zcl_command_reply_free(&inner); return false;
    }
    (void)snprintf(offer.name, sizeof(offer.name), "%s", s->share_name);
    (void)snprintf(offer.root, sizeof(offer.root), "%s", s->root);
    (void)snprintf(offer.publisher, sizeof(offer.publisher), "%s", s->publisher);
    ok = zcl_app_offer_format(&offer, text, ZCL_APP_OFFER_TEXT_MAX + 1u);
    zcl_command_reply_free(&inner);
    if (!ok) zcl_package_copy_fail(s->reply, "OFFER_INVALID", true, "carrier returned an invalid offer", AP_COMMAND);
    return ok;
}

static void ap_post(struct ap_state *s, const char *text)
{
    struct json_value in;
    struct zcl_command_reply inner;
    const char *kv[] = {"kind", "offer", "scope", "public", "room", "apps", "text", text};
    bool built = zcl_app_input(&in, kv, 8) && json_push_kv_int(&in, "ttl", 86400);
    bool ok = built && zcl_app_offer_call(ZCL_APP_OFFER_BOARD_POST, &in, &inner);
    json_free(&in);
    if (!built) zcl_command_reply_init(&inner, "zcl.app_publish.inner.v1");
    if (!ok) zcl_app_inner_fail(s->reply, &inner, true);
    else {
        const char *id = zcl_app_inner_str(&inner, "id");
        uint8_t decoded[32];
        if (!id || !zcl_hex_decode_lower(id, decoded, sizeof(decoded))) {
            zcl_package_copy_fail(s->reply, "PUBLISH_OUTCOME_UNKNOWN", true,
                                  "board post returned no valid post id; the offer may exist", AP_COMMAND);
            zcl_command_reply_free(&inner);
            return;
        }
        char next[256];
        (void)snprintf(next, sizeof(next), "z23 app get %s", s->share_name);
        bool described = json_push_kv_str(&s->reply->data, "name", s->share_name) &&
                         json_push_kv_str(&s->reply->data, "post_id", id) &&
                         json_push_kv_str(&s->reply->data, "package_root", s->root) &&
                         json_push_kv_str(&s->reply->data, "publisher_fingerprint", s->publisher) &&
                         json_push_kv_str(&s->reply->data, "next", next) &&
                         json_push_kv_bool(&s->reply->data, "executed", true);
        if (!described) zcl_package_copy_fail(s->reply, "ALLOC", true,
                                               "offer was posted but its result could not be described", AP_COMMAND);
    }
    zcl_command_reply_free(&inner);
}

void zcl_native_handle_app_publish(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    struct ap_state s = {.input = request ? request->input : NULL, .reply = reply};
    s.name = zcl_package_copy_str(s.input, "copy");
    s.datadir = zcl_package_copy_datadir(s.input, reply, AP_COMMAND);
    if (!s.datadir || !ap_onion(&s) || !ap_token(&s) || !ap_plan(&s)) return;
    if (!zcl_package_copy_confirmed(s.input)) {
        if (!ap_plan_reply(&s)) zcl_package_copy_fail(reply, "ALLOC", false, "cannot describe publish plan", AP_COMMAND);
        return;
    }
    if (!zcl_package_copy_plan_matches(s.input, s.plan, reply, AP_COMMAND)) return;
    if (!platform_private_directory_create(s.dir)) {
        zcl_package_copy_fail(reply, "TEMP_UNAVAILABLE", false, "cannot create private publish directory", AP_COMMAND);
        return;
    }
    bool shared = ap_share(&s);
    char text[ZCL_APP_OFFER_TEXT_MAX + 1u];
    bool offered = shared && ap_verify(&s) && ap_offer(&s, text);
    if (!ap_cleanup(&s, shared || reply->error.mutated) || !offered) return;
    ap_post(&s, text);
}
