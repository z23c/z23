/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Browse local hosting intents and confirm exact generation revocation. */
#include "command/native_app_host_browser.h"
#include "command/app_selection.h"
#include "command/native_app_compose.h"
#include "command/native_app_confirm.h"
#include "command/native_app_receive_preview.h"
#include "command/native_app_offer.h"
#include "command/native_app_get_stage.h"
#include "command/native_zcode_package_copy.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HB_PAGES 16u
struct hb_position { char host[65], carrier[65]; };
struct hb_state {
    struct json_value page;
    struct hb_position cursors[HB_PAGES];
    size_t page_index, item_index;
    app_library_presenter presenter;
    app_confirm_presenter confirm;
    void *context;
};
static bool hb_fail(struct zcl_command_reply *reply, const char *message)
{
    zcl_package_copy_fail(reply, "HOSTING_BROWSER_UNAVAILABLE", reply->error.mutated, message, "app.library");
    return false;
}
static const char *hb_str(const struct json_value *v, const char *key)
{
    const char *s = zcl_package_copy_str(v, key); return s ? s : "";
}
static bool hb_call(const char *path, struct json_value *in, struct zcl_command_reply *outer,
                    struct zcl_command_reply *inner)
{
    bool ok = zcl_app_inner_call(path, in, inner, NULL);
    if (!ok) zcl_app_inner_fail(outer, inner, outer->error.mutated);
    return ok;
}
static bool hb_load(struct hb_state *b, struct zcl_command_reply *reply)
{
    struct json_value in; struct zcl_command_reply inner;
    const struct hb_position *cursor = &b->cursors[b->page_index];
    const char *kv[] = {"after_host", cursor->host[0] ? cursor->host : NULL,
                        "after_carrier", cursor->carrier[0] ? cursor->carrier : NULL};
    bool built = zcl_app_input(&in, kv, 4);
    if (!built) { json_free(&in); return hb_fail(reply, "Cannot prepare hosting list."); }
    bool ok = hb_call("app.host.list", &in, reply, &inner); json_free(&in);
    if (ok) {
        json_free(&b->page); b->page = inner.data; json_init(&inner.data);
        size_t n = json_size(json_get(&b->page, "items"));
        if (b->item_index >= n) b->item_index = n ? n - 1 : 0;
    }
    zcl_command_reply_free(&inner); return ok;
}
static const struct json_value *hb_item(const struct hb_state *b)
{
    return json_at(json_get(&b->page, "items"), b->item_index);
}
static void hb_model(struct hb_state *b, struct zcl_present_model_v1 *m)
{
    zcl_present_model_init_v1(m, ZCL_PRESENT_MODEL_CHOICE);
    (void)snprintf(m->request_id, sizeof(m->request_id), "hosting-browser");
    (void)snprintf(m->title, sizeof(m->title), "Hosting");
    size_t n = json_size(json_get(&b->page, "items"));
    if (!n) { (void)snprintf(m->summary, sizeof(m->summary), "No hosting intents on this node."); app_library_choice(m, "back", "Back", "Return to My Apps."); return; }
    const struct json_value *item = hb_item(b);
    (void)snprintf(m->summary, sizeof(m->summary), "%.72s — %s", hb_str(item, "name"),
        json_get_bool(json_get(item, "enabled")) ? "hosting enabled" : "hosting stopped");
    app_library_choice(m, "review", "Review hosting", "See the exact original identity and current status.");
    app_library_choice(m, "previous", "Previous", b->item_index || b->page_index ? "Browse back." : "First intent.");
    app_library_choice(m, "next", "Next", b->item_index + 1 < n || json_get_bool(json_get(&b->page, "more")) ? "Browse forward." : "Last intent.");
    app_library_choice(m, "back", "Back", "Return to My Apps.");
}
static bool hb_move(struct hb_state *b, bool next, struct zcl_command_reply *reply)
{
    size_t count = json_size(json_get(&b->page, "items"));
    if (next && b->item_index + 1 < count) { ++b->item_index; return true; }
    if (!next && b->item_index) { --b->item_index; return true; }
    if (next && json_get_bool(json_get(&b->page, "more"))) {
        if (b->page_index + 1 >= HB_PAGES) return hb_fail(reply, "Hosting list exceeds the browser page limit.");
        struct hb_position *c = &b->cursors[b->page_index + 1];
        (void)snprintf(c->host, sizeof(c->host), "%s", hb_str(&b->page, "next_host"));
        (void)snprintf(c->carrier, sizeof(c->carrier), "%s", hb_str(&b->page, "next_carrier"));
        ++b->page_index; b->item_index = 0; return hb_load(b, reply);
    }
    if (!next && b->page_index) {
        --b->page_index; if (!hb_load(b, reply)) return false;
        count = json_size(json_get(&b->page, "items")); b->item_index = count ? count - 1 : 0;
    }
    return true;
}

static bool hb_fields(struct app_confirm *view, const struct json_value *item,
                      const struct zcl_command_reply *status)
{
    char generation[32], due[32];
    (void)snprintf(generation, sizeof(generation), "%lld", (long long)json_get_int(json_get(&status->data, "generation")));
    (void)snprintf(due, sizeof(due), "%lld", (long long)json_get_int(json_get(&status->data, "due_at")));
    return app_confirm_field(&view->model, "App: ", hb_str(item, "name")) &&
        app_confirm_field(&view->model, "Publisher: ", hb_str(item, "publisher")) &&
        app_confirm_field(&view->model, "Package: ", hb_str(item, "package_root")) &&
        app_confirm_field(&view->model, "Local host: ", hb_str(item, "host")) &&
        app_confirm_field(&view->model, "Carrier: ", hb_str(item, "carrier")) &&
        app_confirm_field(&view->model, "Generation: ", generation) &&
        app_confirm_field(&view->model, "Next due (Unix): ", due) &&
        app_confirm_field(&view->model, "Pending: ", json_get_bool(json_get(&status->data, "pending")) ? "yes" : "no");
}
static bool hb_show(struct hb_state *b, const struct json_value *item,
                    const struct zcl_command_reply *status, bool *confirmed,
                    struct zcl_command_reply *reply, bool actionable)
{
    struct app_confirm *view = zcl_calloc(1, sizeof(*view), "hosting-browser/confirm");
    if (!view) return hb_fail(reply, "Cannot show hosting details.");
    bool enabled = json_get_bool(json_get(&status->data, "enabled"));
    char why[256] = {0};
    view->window_title = "Hosting";
    zcl_present_model_init_v1(&view->model, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(view->model.request_id, sizeof(view->model.request_id), "hosting-review");
    (void)snprintf(view->model.title, sizeof(view->model.title), "Original app hosting");
    const char *summary = actionable ? (enabled ?
        "Stop future renewals? This does not change the carrier pin; existing offers may remain until they expire." :
        "Resume hosting this original? The node will verify its pinned carrier and publish offers again.") :
        (enabled ? "Hosting is enabled." : "Hosting is stopped; existing offers may remain until they expire.");
    (void)snprintf(view->model.summary, sizeof(view->model.summary), "%s", summary);
    view->model.action_count = actionable ? 4 : 1;
    app_confirm_action(&view->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "cancel", "Back");
    if (actionable) {
        app_confirm_action(&view->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
        app_confirm_action(&view->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
        app_confirm_action(&view->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM,
                           enabled ? "stop" : "resume", enabled ? "Stop hosting" : "Resume hosting");
    }
    bool ok = hb_fields(view, item, status) &&
        app_confirm_prepare(view, why, sizeof(why)) && app_confirm_show(view, b->confirm, b->context, why, sizeof(why));
    *confirmed = ok && actionable && view->confirmed;
    app_confirm_free(view); free(view);
    return ok || hb_fail(reply, "Hosting details could not be displayed.");
}

static bool hb_bind_stop(const char *const kv[4], int64_t generation,
                         struct json_value *in, struct zcl_command_reply *reply, bool resume)
{
    struct zcl_command_reply plan;
    bool built = zcl_app_input(in, kv, 4) && json_push_kv_int(in, "generation", generation);
    if (!built) return hb_fail(reply, "Cannot prepare hosting change.");
    bool ok = hb_call(resume ? "app.host.resume" : "app.host.stop", in, reply, &plan);
    const char *plan_id = ok ? zcl_app_inner_str(&plan, "plan_id") : NULL;
    if (ok) ok = plan_id && json_push_kv_str(in, "plan_id", plan_id) && json_push_kv_bool(in, "confirm", true);
    zcl_command_reply_free(&plan);
    if (!ok && reply->status == ZCL_COMMAND_STATUS_PASSED) return hb_fail(reply, "Cannot bind hosting change plan.");
    return ok;
}
static bool hb_commit_stop(struct hb_state *b, const struct json_value *item,
                           struct json_value *in, struct zcl_command_reply *reply, bool resume)
{
    struct zcl_command_reply stopped;
    bool ok = hb_call(resume ? "app.host.resume" : "app.host.stop", in, reply, &stopped);
    if (!ok && stopped.error.mutated) {
        size_t used = strlen(reply->error.message);
        if (used < sizeof(reply->error.message))
            (void)snprintf(reply->error.message + used, sizeof(reply->error.message) - used,
                "; change may have completed; reopen Hosting to read status before retrying");
    }
    bool ignored = false;
    if (ok) { reply->error.mutated = true; ok = hb_show(b, item, &stopped, &ignored, reply, false); }
    zcl_command_reply_free(&stopped); return ok;
}
static bool hb_review(struct hb_state *b, struct zcl_command_reply *reply)
{
    const struct json_value *item = hb_item(b);
    const char *host = hb_str(item, "host"), *carrier = hb_str(item, "carrier");
    const char *kv[] = {"host", host, "carrier", carrier};
    struct json_value in; struct zcl_command_reply status;
    if (!zcl_app_input(&in, kv, 4)) { json_free(&in); return hb_fail(reply, "Cannot prepare hosting status."); }
    bool ok = hb_call("app.host.status", &in, reply, &status); json_free(&in);
    if (!ok) { zcl_command_reply_free(&status); return false; }
    bool resume = !json_get_bool(json_get(&status.data, "enabled"));
    int64_t generation = json_get_int(json_get(&status.data, "generation"));
    if (!hb_bind_stop(kv, generation, &in, reply, resume)) { json_free(&in); zcl_command_reply_free(&status); return false; }
    bool confirmed = false;
    ok = hb_show(b, item, &status, &confirmed, reply, true); zcl_command_reply_free(&status);
    if (!ok || !confirmed) { json_free(&in); return ok; }
    ok = hb_commit_stop(b, item, &in, reply, resume); json_free(&in); return ok;
}

static bool hb_event_valid(const struct zcl_present_model_v1 *model,
                           const struct zcl_present_window_event_v1 *event)
{
    return event->struct_size == sizeof(*event) && event->abi_version == ZCL_PRESENT_ABI_V1 &&
        (event->outcome == ZCL_PRESENT_WINDOW_DISMISSED ||
         (event->outcome == ZCL_PRESENT_WINDOW_ACTION && event->action_index < model->action_count));
}

bool app_host_browser_run(app_library_presenter presenter, app_confirm_presenter confirm,
                          void *context, struct zcl_command_reply *reply)
{
    if (!presenter || !reply) return false;
    struct hb_state b = {.presenter = presenter, .confirm = confirm, .context = context};
    json_init(&b.page);
    bool ok = hb_load(&b, reply);
    while (ok) {
        struct zcl_present_model_v1 model; struct zcl_present_window_event_v1 event = {0}; char why[256] = {0};
        hb_model(&b, &model);
        if (!zcl_present_model_validate_v1(&model, why, sizeof(why)) ||
            !presenter(context, &model, NULL, &event, why, sizeof(why)) || !hb_event_valid(&model, &event)) {
            ok = hb_fail(reply, "Hosting browser could not be displayed."); break;
        }
        if (event.outcome == ZCL_PRESENT_WINDOW_DISMISSED) break;
        const char *id = model.actions[event.action_index].id;
        if (!strcmp(id, "back")) break;
        if (!strcmp(id, "previous") || !strcmp(id, "next")) ok = hb_move(&b, !strcmp(id, "next"), reply);
        else if (!strcmp(id, "review")) { ok = hb_review(&b, reply); if (ok) ok = hb_load(&b, reply); }
        else ok = hb_fail(reply, "Hosting choice was not recognized.");
    }
    json_free(&b.page); return ok;
}

struct ho_action {
    const struct app_selection *selection;
    app_host_selection_check check;
    void *check_context, *context;
    app_confirm_presenter confirm;
    struct zcl_command_reply *reply;
    struct app_private_stage *stage;
    struct app_received_original original;
    char release[65], carrier[65], sha[65], offer[ZCL_APP_OFFER_TEXT_MAX + 1u];
    char plan[65], identity[65];
    int64_t generation;
    bool already;
};
static void ho_recovery(struct ho_action *a);
static bool ho_fail(struct ho_action *a, const char *code, bool mutated, const char *message)
{
    zcl_package_copy_fail(a->reply, code, mutated || a->reply->error.mutated, message, a->carrier[0] ? a->carrier : "app.host.local");
    return false;
}
static bool ho_offer(struct ho_action *a)
{
    struct zcl_app_offer o = {0};
    if (a->original.size > INT64_MAX) return false;
    (void)snprintf(o.name, sizeof(o.name), "%s", a->original.name);
    zcl_hex_encode(a->original.package, 32, o.root);
    zcl_hex_encode(a->original.publisher, 33, o.publisher);
    zcl_hex_encode(a->original.release, 32, a->release);
    zcl_hex_encode(a->original.carrier, 32, a->carrier);
    zcl_hex_encode(a->original.sha256, 32, a->sha);
    (void)snprintf(o.carrier, sizeof(o.carrier), "%s", a->carrier);
    (void)snprintf(o.sha256, sizeof(o.sha256), "%s", a->sha);
    (void)snprintf(o.onion, sizeof(o.onion), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:1");
    o.size = (int64_t)a->original.size;
    return zcl_app_offer_format(&o, a->offer, sizeof(a->offer));
}
static bool ho_confirm(struct ho_action *a, bool already, bool *chosen)
{
    struct app_confirm *v = zcl_calloc(1, sizeof(*v), "original-host/confirm");
    if (!v) return ho_fail(a, "OUT_OF_MEMORY", false, "Cannot prepare the original hosting choice.");
    zcl_present_model_init_v1(&v->model, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(v->model.request_id, sizeof(v->model.request_id), "library-host-original");
    (void)snprintf(v->model.title, sizeof(v->model.title), "Help share the original?");
    (void)snprintf(v->model.summary, sizeof(v->model.summary), "%s", already ? "Hosting this original is already enabled." : "Offer the original app files, not your edited version.");
    v->model.action_count = 4;
    app_confirm_action(&v->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "cancel", "Not now");
    app_confirm_action(&v->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&v->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&v->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "host", already ? "Done" : "Help share");
    char package[65], publisher[67], why[256] = {0};
    zcl_hex_encode(a->original.package, 32, package); zcl_hex_encode(a->original.publisher, 33, publisher);
    bool shown = app_confirm_field(&v->model, "Original app: ", a->original.name) &&
        app_confirm_field(&v->model, "Original publisher: ", publisher) &&
        app_confirm_field(&v->model, "Original package: ", package) &&
        app_confirm_field(&v->model, "Hosting: ", "Store the original files and use bandwidth to serve them publicly while this node runs. Offers renew until hosting is stopped.") &&
        app_confirm_field(&v->model, "Availability: ", "Discovery waits for a ready endpoint. Use Hosting in My Apps to inspect or stop.") &&
        app_confirm_prepare(v, why, sizeof(why)) && app_confirm_show(v, a->confirm, a->context, why, sizeof(why));
    *chosen = shown && v->confirmed; app_confirm_free(v); free(v);
    return shown || ho_fail(a, "PRESENTATION_FAILED", false, "The hosting choice could not be displayed.");
}
static bool ho_stage_valid(struct ho_action *a)
{
    return app_private_stage_matches(a->stage, a->sha, (int64_t)a->original.size);
}
static bool ho_pin(struct ho_action *a)
{
    struct json_value in; struct zcl_command_reply inner;
    const char *kv[] = {"file", app_private_stage_path(a->stage)};
    bool built = zcl_app_input(&in, kv, 2);
    bool ok = built && zcl_app_offer_call(ZCL_APP_OFFER_BUNDLE_OFFER, &in, &inner);
    json_free(&in); if (!built) zcl_command_reply_init(&inner, "zcl.app_host.pin.v1");
    const char *root = zcl_app_inner_str(&inner, "root"), *sha = zcl_app_inner_str(&inner, "sha256");
    const struct json_value *size = json_get(&inner.data, "size");
    ok = ok && root && sha && !strcmp(root, a->carrier) && !strcmp(sha, a->sha) &&
        size && size->type == JSON_INT && json_get_int(size) == (int64_t)a->original.size;
    zcl_command_reply_free(&inner);
    if (!built) return ho_fail(a, "HOST_PIN_UNAVAILABLE", false, "The original was not pinned; the request could not be prepared.");
    if (!ok) {
        ho_fail(a, "HOST_PIN_UNCONFIRMED", true, "The original may have been pinned; inspect hosting before retrying.");
        ho_recovery(a); return false;
    }
    a->reply->error.mutated = true; return true;
}
static bool ho_input(struct ho_action *a, struct json_value *in)
{
    const char *kv[] = {"offer", a->offer, "release_id", a->release, "datadir", a->selection->datadir};
    return zcl_app_input(in, kv, 6);
}
static bool ho_plan_state(const char *id, const struct json_value *gen,
                          const struct json_value *already)
{
    if (!id || (strcmp(id, "absent") && !vcs_app_offer_hex_valid(id, 32)) ||
        !gen || gen->type != JSON_INT || json_get_int(gen) < 0 ||
        !already || already->type != JSON_BOOL) return false;
    if (!strcmp(id, "absent") && (json_get_int(gen) != 0 || json_get_bool(already))) return false;
    return !json_get_bool(already) || json_get_int(gen) > 0;
}
static bool ho_plan_parse(struct ho_action *a, const struct zcl_command_reply *plan)
{
    const char *id = zcl_app_inner_str(plan, "identity"), *token = zcl_app_inner_str(plan, "plan_id");
    const struct json_value *gen = json_get(&plan->data, "generation");
    const struct json_value *already = json_get(&plan->data, "already_enabled");
    const struct json_value *executed = json_get(&plan->data, "executed");
    if (!ho_plan_state(id, gen, already) || !vcs_app_offer_hex_valid(token, 32) ||
        !executed || executed->type != JSON_BOOL || json_get_bool(executed)) return false;
    (void)snprintf(a->identity, sizeof(a->identity), "%s", id);
    (void)snprintf(a->plan, sizeof(a->plan), "%s", token);
    a->generation = json_get_int(gen); a->already = json_get_bool(already);
    return true;
}
static bool ho_plan(struct ho_action *a)
{
    struct json_value in; struct zcl_command_reply plan;
    bool built = ho_input(a, &in);
    bool ok = built && zcl_app_inner_call("app.host.local", &in, &plan, NULL);
    json_free(&in); if (!built) zcl_command_reply_init(&plan, "zcl.app_host.plan.v1");
    if (ok) ok = ho_plan_parse(a, &plan);
    else if (built) zcl_app_inner_fail(a->reply, &plan, false);
    zcl_command_reply_free(&plan);
    if (!ok && a->reply->status == ZCL_COMMAND_STATUS_PASSED)
        return ho_fail(a, "HOST_PLAN_UNAVAILABLE", false, "Cannot prepare an exact hosting plan.");
    return ok;
}
static void ho_recovery(struct ho_action *a)
{
    struct json_value facts; json_init(&facts); json_set_object(&facts);
    bool ok = json_push_kv_str(&facts, "carrier", a->carrier) &&
        json_push_kv_str(&facts, "guidance", "The carrier or node identity may have changed. Return to this app and review hosting status before retrying.");
    if (ok && strcmp(a->identity, "absent")) ok = json_push_kv_str(&facts, "host", a->identity);
    if (ok) (void)json_push_kv(&a->reply->data, "failure_facts", &facts);
    json_free(&facts);
}
static bool ho_commit_valid(const struct ho_action *a, const struct zcl_command_reply *result)
{
    const char *host = zcl_app_inner_str(result, "host"), *carrier = zcl_app_inner_str(result, "carrier");
    const struct json_value *gen = json_get(&result->data, "generation"), *enabled = json_get(&result->data, "enabled");
    const struct json_value *executed = json_get(&result->data, "executed");
    return vcs_app_offer_hex_valid(host, 32) && carrier && !strcmp(carrier, a->carrier) &&
        (!strcmp(a->identity, "absent") || !strcmp(host, a->identity)) && gen && gen->type == JSON_INT &&
        json_get_int(gen) > 0 && enabled && enabled->type == JSON_BOOL && json_get_bool(enabled) &&
        executed && executed->type == JSON_BOOL && json_get_bool(executed);
}
static bool ho_commit(struct ho_action *a)
{
    struct json_value in; struct zcl_command_reply result;
    bool built = ho_input(a, &in) && json_push_kv_str(&in, "plan_id", a->plan) &&
        json_push_kv_str(&in, "identity", a->identity) && json_push_kv_int(&in, "generation", a->generation) &&
        json_push_kv_bool(&in, "already_enabled", a->already) && json_push_kv_bool(&in, "confirm", true);
    bool ok = built && zcl_app_inner_call("app.host.local", &in, &result, NULL);
    json_free(&in); if (!built) zcl_command_reply_init(&result, "zcl.app_host.commit.v1");
    if (ok) ok = ho_commit_valid(a, &result);
    if (ok) {
        json_free(&a->reply->data); a->reply->data = result.data; json_init(&result.data);
        a->reply->error.mutated = true;
    }
    zcl_command_reply_free(&result);
    if (!ok) {
        ho_fail(a, "HOST_OUTCOME_UNCONFIRMED", true, "The carrier or node identity may have changed. Return to this app and review hosting status before retrying.");
        ho_recovery(a);
    }
    return ok;
}
static bool ho_notice(struct ho_action *a)
{
    struct app_confirm *v = zcl_calloc(1, sizeof(*v), "original-host/result");
    if (!v) {
        ho_fail(a, "HOST_RESULT_UNAVAILABLE", a->reply->error.mutated, "Hosting state could not be displayed; inspect Hosting before retrying.");
        ho_recovery(a); return false;
    }
    zcl_present_model_init_v1(&v->model, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(v->model.request_id, sizeof(v->model.request_id), "library-host-original-result");
    (void)snprintf(v->model.title, sizeof(v->model.title), "Original hosting enabled");
    (void)snprintf(v->model.summary, sizeof(v->model.summary), "Hosting is enabled. Public discovery waits for a ready endpoint; use Hosting in My Apps to inspect or stop it.");
    v->model.action_count = 4;
    app_confirm_action(&v->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "close", "Close");
    app_confirm_action(&v->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&v->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&v->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "done", "Done");
    char why[256] = {0};
    bool shown = app_confirm_field(&v->model, "Original app: ", a->original.name) &&
        app_confirm_field(&v->model, "Carrier: ", a->carrier) &&
        app_confirm_prepare(v, why, sizeof(why)) && app_confirm_show(v, a->confirm, a->context, why, sizeof(why));
    app_confirm_free(v); free(v);
    if (!shown) { ho_fail(a, "HOST_RESULT_UNAVAILABLE", a->reply->error.mutated, "Hosting state could not be displayed; inspect Hosting before retrying."); ho_recovery(a); }
    return shown;
}
static bool ho_already_current(struct ho_action *a)
{
    char identity[65]; (void)snprintf(identity, sizeof(identity), "%s", a->identity);
    int64_t generation = a->generation;
    if (!a->check(a->check_context, a->reply) || !app_received_original_available(a->selection) ||
        !ho_stage_valid(a) || !ho_plan(a)) return false;
    if (!a->already || strcmp(a->identity, identity) || a->generation != generation)
        return ho_fail(a, "HOST_STATE_CHANGED", false, "Hosting changed while the choice was open; inspect Hosting before continuing.");
    bool ok = json_push_kv_str(&a->reply->data, "host", a->identity) &&
        json_push_kv_str(&a->reply->data, "carrier", a->carrier) &&
        json_push_kv_int(&a->reply->data, "generation", a->generation) &&
        json_push_kv_bool(&a->reply->data, "enabled", true) && json_push_kv_bool(&a->reply->data, "executed", false);
    return ok || ho_fail(a, "HOST_RESULT_UNAVAILABLE", false, "Existing hosting state could not be retained; inspect Hosting.");
}
static bool ho_apply(struct ho_action *a, bool *canceled)
{
    bool chosen = false;
    if (!ho_confirm(a, a->already, &chosen)) return false;
    if (!chosen) { *canceled = true; return true; }
    if (a->already) return ho_already_current(a) && ho_notice(a);
    bool ok = a->check(a->check_context, a->reply) && app_received_original_available(a->selection) && ho_stage_valid(a);
    if (!ok && a->reply->status == ZCL_COMMAND_STATUS_PASSED)
        ho_fail(a, "ORIGINAL_CHANGED", false, "The selected original or staged files changed; reopen My Apps.");
    return ok && ho_pin(a) && ho_commit(a) && ho_notice(a);
}
bool app_host_original_run(const struct app_selection *selection,
    app_host_selection_check check, void *check_context,
    app_confirm_presenter confirm, void *context, bool *canceled,
    struct zcl_command_reply *reply)
{
    if (!selection || !check || !canceled || !reply) return false;
    *canceled = false;
    struct ho_action a = {.selection = selection, .check = check, .check_context = check_context,
                          .confirm = confirm, .context = context, .reply = reply};
    if (!app_received_original_available(selection)) return ho_fail(&a, "ORIGINAL_UNAVAILABLE", false, "The received original is no longer available.");
    if (!app_private_stage_open(selection->datadir, &a.stage, reply)) return false;
    bool ok = app_received_original_stage(selection, app_private_stage_path(a.stage), &a.original, reply) &&
        ho_offer(&a) && ho_stage_valid(&a) && ho_plan(&a);
    if (ok) ok = ho_apply(&a, canceled);
    char retained[4400]; (void)snprintf(retained, sizeof(retained), "%s", app_private_stage_path(a.stage));
    if (!app_private_stage_close(a.stage)) {
        zcl_package_copy_fail(reply, "TEMP_CLEANUP_FAILED", true, "Private original staging could not be safely removed.", retained);
        return false;
    }
    if (!ok && reply->status == ZCL_COMMAND_STATUS_PASSED)
        return ho_fail(&a, "ORIGINAL_UNAVAILABLE", false, "The original hosting request could not be prepared.");
    return ok;
}
