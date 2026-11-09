/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Browse local hosting intents and confirm exact generation revocation. */
#include "command/native_app_host_browser.h"
#include "command/native_app_compose.h"
#include "command/native_app_confirm.h"
#include "command/native_zcode_package_copy.h"
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
