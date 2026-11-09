/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: publish a planned signed app copy through the existing board and carrier. */
#include "command/native_command.h"
#include "command/native_app_compose.h"
#include "command/native_app_offer.h"
#include "command/native_app_publish_command.h"
#include "command/native_app_share_command.h"
#include "command/app_selection.h"
#include "command/native_fleet_bundle.h"
#include "command/native_zcode_package_copy.h"
#include "json/json.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/rng.h"
#include "platform/private_directory.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
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

static bool ap_onion(struct ap_state *s)
{
    bool ok = false;
    bool ready = zcl_app_offer_local_endpoint(s->host, s->onion, &ok);
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

static bool ap_next(char *out, size_t cap, const char *name, const char *root,
                    const char *publisher, const char *id)
{
    int n = snprintf(out, cap, "z23 app get %s --root=%s --publisher=%s --offer=%s",
                     name, root, publisher, id);
    return n >= 0 && (size_t)n < cap;
}

#ifdef ZCL_TESTING
bool zcl_test_app_publish_next(char *out, size_t cap, const char *name, const char *root,
                               const char *publisher, const char *id);
bool zcl_test_app_publish_next(char *out, size_t cap, const char *name, const char *root,
                               const char *publisher, const char *id)
{
    return ap_next(out, cap, name, root, publisher, id);
}
#endif

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
        char next[512];
        if (!ap_next(next, sizeof(next), s->share_name, s->root, s->publisher, id)) {
            zcl_package_copy_fail(s->reply, "RESULT_UNAVAILABLE", true,
                                  "offer was posted but its continuation could not be described", id);
            zcl_command_reply_free(&inner);
            return;
        }
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

static bool ap_snapshot_view(struct app_confirm *v, const struct zcl_app_share_identity *id,
                             const char *onion, char *why, size_t cap)
{
    zcl_present_model_init_v1(&v->model, ZCL_PRESENT_MODEL_STATUS_CARD);
    v->window_title = "Publish this saved version";
    (void)snprintf(v->model.request_id, sizeof(v->model.request_id), "app-publish-snapshot");
    (void)snprintf(v->model.title, sizeof(v->model.title), "Publish publicly?");
    (void)snprintf(v->model.summary, sizeof(v->model.summary), "Review all pages before publishing.");
    v->model.action_count = 4;
    app_confirm_action(&v->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "cancel", "Cancel");
    app_confirm_action(&v->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&v->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&v->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "publish", "Publish");
    return app_confirm_field(&v->model, "App: ", id->name) &&
        app_confirm_field(&v->model, "Version: ", id->semver) &&
        app_confirm_field(&v->model, "Saved version: ", id->version) &&
        app_confirm_field(&v->model, "Package: ", id->package) &&
        app_confirm_field(&v->model, "Publisher: ", id->publisher) &&
        app_confirm_field(&v->model, "Release: ", id->release) &&
        app_confirm_field(&v->model, "Endpoint: ", onion) &&
        app_confirm_field(&v->model, "Public: ", "Sign and pin this saved version; post an offer to the public apps board for 24 hours.") &&
        app_confirm_prepare(v, why, cap);
}

static void ap_snapshot_facts(struct zcl_command_reply *reply,
    const struct zcl_app_share_identity *id, bool post_attempted)
{
    struct json_value *facts = NULL;
    for (size_t i = 0; i < reply->data.num_children; ++i)
        if (!strcmp(reply->data.keys[i], "failure_facts")) facts = &reply->data.children[i];
    if (!facts) {
        struct json_value empty; json_init(&empty); json_set_object(&empty);
        bool ok = json_push_kv(&reply->data, "failure_facts", &empty); json_free(&empty);
        if (ok) facts = &reply->data.children[reply->data.num_children - 1];
    }
    bool complete = facts && facts->type == JSON_OBJ &&
        json_push_kv_str(facts, "release_id", id->release) &&
        json_push_kv_str(facts, "version", id->version) &&
        json_push_kv_str(facts, "package_root", id->package) &&
        json_push_kv_str(facts, "publisher_fingerprint", id->publisher) &&
        json_push_kv_str(facts, "board_status", post_attempted ? "unknown" : "not_attempted");
    if (!complete) (void)snprintf(reply->error.evidence, sizeof(reply->error.evidence),
        "Signed release %.64s; some recovery facts could not be encoded.", id->release);
}

static void ap_snapshot_execute(struct ap_state *s, struct zcl_app_share_session *share,
    const struct zcl_app_share_identity *id)
{
    struct zcl_command_reply *reply = s->reply;
    if (!platform_private_directory_create(s->dir)) {
        zcl_package_copy_fail(reply, "TEMP_UNAVAILABLE", false, "Cannot create private publish directory", AP_COMMAND);
        return;
    }
    struct zcl_command_reply inner; zcl_command_reply_init(&inner, "zcl.app_share.v1");
    zcl_app_share_commit(share, &inner);
    bool shared = inner.status == ZCL_COMMAND_STATUS_PASSED;
    if (!shared) app_confirm_forward_failure(reply, &inner);
    if (shared) {
        (void)snprintf(s->share_name, sizeof(s->share_name), "%s", id->name);
        (void)snprintf(s->root, sizeof(s->root), "%s", id->package);
        (void)snprintf(s->publisher, sizeof(s->publisher), "%s", id->publisher);
    }
    zcl_command_reply_free(&inner);
    char text[ZCL_APP_OFFER_TEXT_MAX + 1u];
    bool offered = shared && ap_verify(s) && ap_offer(s, text);
    bool cleaned = ap_cleanup(s, shared || reply->error.mutated);
    bool post_attempted = cleaned && offered;
    if (post_attempted) ap_post(s, text);
    if (shared && reply->status != ZCL_COMMAND_STATUS_PASSED)
        ap_snapshot_facts(reply, id, post_attempted);
}

static bool ap_snapshot_confirm(struct ap_state *s, const struct zcl_app_share_identity *id,
    struct app_confirm *view, app_confirm_presenter presenter, void *context)
{
    struct zcl_command_reply *reply = s->reply;
    char why[256] = {0};
    if (strlen(id->name) >= sizeof(s->share_name) || strlen(id->package) != 64 || strlen(id->publisher) != 66) {
        zcl_package_copy_fail(reply, "SHARE_PLAN_INVALID", false, "Saved identity cannot be published", AP_COMMAND);
        return false;
    }
    if (!view || !ap_snapshot_view(view, id, s->onion, why, sizeof(why)) ||
        !app_confirm_show(view, presenter, context, why, sizeof(why))) {
        zcl_package_copy_fail(reply, "CONFIRMATION_UNAVAILABLE", false, "Cannot display the exact publish plan", AP_COMMAND);
        return false;
    }
    if (!view->confirmed) {
        if (!json_push_kv_str(&reply->data, "status", "canceled"))
            zcl_package_copy_fail(reply, "ALLOC", false, "Cannot describe cancellation", AP_COMMAND);
        return false;
    }
    char old_onion[sizeof(s->onion)], old_host[sizeof(s->host)];
    (void)snprintf(old_onion, sizeof(old_onion), "%s", s->onion);
    (void)snprintf(old_host, sizeof(old_host), "%s", s->host);
    if (!ap_onion(s)) return false;
    if (strcmp(old_onion, s->onion) || strcmp(old_host, s->host)) {
        zcl_package_copy_fail(reply, "PLAN_MISMATCH", false, "Publication endpoint changed; review again", AP_COMMAND);
        return false;
    }
    return true;
}

void zcl_native_app_publish_snapshot(const char *name, const struct app_selection *selection,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context)
{
    if (!reply || !selection) return;
    /* The private path needs only a safe component; the selection authority
     * below validates the real route, which may contain a kept: prefix. */
    struct ap_state s = {.reply = reply, .name = "snapshot", .datadir = selection->datadir};
    if (!ap_onion(&s) || !ap_token(&s)) return;
    struct zcl_app_share_session *share = zcl_app_share_prepare(name, s.path, selection, reply);
    if (!share) return;
    struct zcl_app_share_identity id; zcl_app_share_identity(share, &id);
    struct app_confirm *view = zcl_calloc(1, sizeof(*view), "app-publish-view");
    if (ap_snapshot_confirm(&s, &id, view, presenter, context)) ap_snapshot_execute(&s, share, &id);
    if (view) { app_confirm_free(view); free(view); }
    zcl_app_share_dispose(share);
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
