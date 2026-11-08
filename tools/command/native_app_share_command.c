/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Native owner confirmation for sharing the exact saved Keep selection. */
#include "command/native_app_share_command.h"
#include "command/native_app_confirm.h"
#include "command/native_app_launch.h"
#include "command/native_app_personalize_command.h"
#include "command/native_zcode_package_copy.h"
#include "command/app_selection.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SH_COMMAND "app.share"
#define SH_PATH 4400
struct sh_work {
    struct app_confirm view;
    struct app_launch_env env;
    struct app_selection selection;
    char app[APP_SELECTION_ID_MAX + 1], output[SH_PATH], key[SH_PATH], publisher[67];
    char version[65], package[65], parent[65], plan[65], release[65];
    char name[256], semver[256];
};
static bool sh_fail(struct zcl_command_reply *reply, const char *code, const char *why)
{
    zcl_package_copy_fail(reply, code, false, why, SH_COMMAND); return false;
}
static bool sh_values(struct sh_work *w, const char *name, const char *output, struct zcl_command_reply *reply)
{
    if (!name || !*name || strlen(name) > APP_SELECTION_ID_MAX || !output || output[0] != '/' || strlen(output) >= sizeof(w->output))
        return sh_fail(reply, "BAD_INPUT", "Name one kept app and an absolute new output path.");
    (void)snprintf(w->app, sizeof(w->app), "%s", name);
    (void)snprintf(w->output, sizeof(w->output), "%s", output); return true;
}
static bool sh_inputs(const struct json_value *in, struct zcl_command_reply *reply)
{
    if (!in || in->type != JSON_OBJ || in->num_children != 2)
        return sh_fail(reply, "BAD_INPUT", "Name one kept app and an absolute new output path.");
    for (size_t i = 0; i < in->num_children; ++i)
        if (strcmp(in->keys[i], "name") && strcmp(in->keys[i], "output"))
            return sh_fail(reply, "BAD_INPUT", "Only name and output are accepted.");
    return true;
}
static bool sh_selection(struct sh_work *w, struct zcl_command_reply *reply)
{
    char why[256];
    if (!app_launch_env_from_process(&w->env, why, sizeof(why))) return sh_fail(reply, "STATE_FAILED", "Cannot resolve kept app state.");
    enum app_selection_result result = app_selection_load(w->env.state_dir, w->app, &w->selection);
    if (result != APP_SELECTION_OK) return sh_fail(reply, "SELECTION_UNAVAILABLE", "The kept app selection is missing or unreadable.");
    zcl_hex_encode(w->selection.version, 32, w->version);
    zcl_hex_encode(w->selection.package, 32, w->package);
    zcl_hex_encode(w->selection.parent, 32, w->parent);
    return true;
}
static bool sh_snapshot(struct sh_work *w, const struct app_selection *s, struct zcl_command_reply *reply)
{
    if (!s) return true;
    const struct app_selection *a = &w->selection;
    bool same = a->revision == s->revision && !strcmp(a->app, s->app) &&
        !strcmp(a->copy, s->copy) && !strcmp(a->datadir, s->datadir);
    const uint8_t *left[] = {a->fork, a->parent, a->version, a->package, a->env, a->dependencies, a->record, a->image};
    const uint8_t *right[] = {s->fork, s->parent, s->version, s->package, s->env, s->dependencies, s->record, s->image};
    for (size_t i = 0; same && i < 8; ++i) same = !memcmp(left[i], right[i], 32);
    return same || sh_fail(reply, "SELECTION_STALE", "The displayed saved choice changed; reopen My Apps.");
}
static bool sh_copy(struct sh_work *w, struct zcl_command_reply *reply)
{
    struct zcl_package_copy copy = {0};
    if (!zcl_package_copy_open_selected_as(w->selection.copy, ZCL_PACKAGE_COPY_READ, &copy, reply, SH_COMMAND, w->version)) return false;
    enum zcl_package_copy_adoption auth = zcl_package_copy_adopted(w->selection.datadir, &copy, NULL);
    bool ok = (auth == ZCL_PACKAGE_COPY_ADOPTED || auth == ZCL_PACKAGE_COPY_RECEIVED_TRUSTED) &&
        !memcmp(copy.fork_version, w->selection.fork, 32) && !memcmp(copy.parent_release, w->selection.parent, 32) &&
        !memcmp(copy.selected_version, w->selection.version, 32);
    zcl_package_copy_close(&copy);
    return ok || sh_fail(reply, "SELECTION_MISMATCH", "The kept copy grant or ancestry changed.");
}
static bool sh_key(struct sh_work *w, struct zcl_command_reply *reply)
{
    bool exists = false;
    if (!app_personalize_key_probe(reply, w->key, sizeof(w->key), w->publisher, &exists)) return false;
    return exists || sh_fail(reply, "SIGNING_KEY_REQUIRED", "No local signing key exists; personalize this copy first.");
}
static bool sh_call(const struct zcl_command_request *request, struct sh_work *w,
                    bool commit, struct zcl_command_reply *out)
{
    const char *path = commit ? "zcode.package.bundle.sign" : "zcode.package.share";
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    if (!spec || !spec->handler || (commit && spec->authority != ZCL_COMMAND_AUTH_OWNER)) return false;
    struct json_value in; json_init(&in); json_set_object(&in);
    bool ok = json_push_kv_str(&in, "dir", w->selection.copy) && json_push_kv_str(&in, "datadir", w->selection.datadir) &&
        json_push_kv_str(&in, "version", w->version) && json_push_kv_str(&in, "output", w->output) &&
        json_push_kv_str(&in, commit ? "expected_publisher_pubkey" : "publisher_pubkey", w->publisher);
    if (commit) ok = ok && json_push_kv_str(&in, "plan_id", w->plan) && json_push_kv_bool(&in, "confirm", true);
    if (ok) { struct zcl_command_request inner = *request; inner.spec = spec; inner.input = &in; inner.invoked_name = spec->path; spec->handler(&inner, out); }
    json_free(&in); return ok;
}
static bool sh_fact_once(struct json_value *facts, const char *key, const char *value)
{
    return json_get(facts, key) || json_push_kv_str(facts, key, value);
}
/* These backend failures occur only after publication; keep both the
 * backend's prior facts and the exact release identity in the wire error. */
static void sh_partial_facts(struct sh_work *w, struct zcl_command_reply *reply)
{
    if (strcmp(reply->error.code, "SHARE_FILE_WRITE") && strcmp(reply->error.code, "SHARE_FILE_ENCODE")) return;
    const char *reported = zcl_package_copy_str(&reply->data, "release_id");
    if (!reported || strcmp(reported, w->release)) {
        zcl_package_copy_fail(reply, "SHARE_RESULT_MISMATCH", true,
            "Publication was reported but its release identity could not be verified.", w->output);
        return;
    }
    struct json_value *facts = NULL;
    for (size_t i = 0; i < reply->data.num_children; ++i)
        if (!strcmp(reply->data.keys[i], "failure_facts")) facts = &reply->data.children[i];
    if (!facts) {
        struct json_value empty; json_init(&empty); json_set_object(&empty);
        bool ok = json_push_kv(&reply->data, "failure_facts", &empty); json_free(&empty);
        if (ok) facts = &reply->data.children[reply->data.num_children - 1];
    }
    bool complete = facts && facts->type == JSON_OBJ &&
        sh_fact_once(facts, "release_id", w->release) &&
        sh_fact_once(facts, "package_root", w->package) &&
        sh_fact_once(facts, "version", w->version) && sh_fact_once(facts, "output", w->output);
    if (!complete)
        (void)snprintf(reply->error.evidence, sizeof(reply->error.evidence),
                       "Published release %s; some failure facts could not be encoded.", w->release);
}
static bool sh_copy_field(char *out, size_t cap, const struct json_value *data, const char *key)
{
    const char *s = zcl_package_copy_str(data, key);
    if (!s || strlen(s) >= cap) return false;
    memcpy(out, s, strlen(s) + 1); return true;
}
static bool sh_plan_describe(struct sh_work *w, const struct json_value *data)
{
    return sh_copy_field(w->plan, sizeof(w->plan), data, "plan_id") &&
        sh_copy_field(w->release, sizeof(w->release), data, "signing_digest") &&
        sh_copy_field(w->name, sizeof(w->name), data, "name") &&
        sh_copy_field(w->semver, sizeof(w->semver), data, "semver") &&
        strlen(w->plan) == 64 && strlen(w->release) == 64;
}
static bool sh_plan_matches(struct sh_work *w, const struct json_value *data)
{
    char version[65], package[65], parent[65], publisher[67], output[SH_PATH];
    return sh_copy_field(version, sizeof(version), data, "version") &&
        sh_copy_field(package, sizeof(package), data, "package_root") &&
        sh_copy_field(parent, sizeof(parent), data, "parent_release_root") &&
        sh_copy_field(publisher, sizeof(publisher), data, "publisher_fingerprint") &&
        sh_copy_field(output, sizeof(output), data, "output") &&
        !strcmp(version, w->version) && !strcmp(package, w->package) &&
        !strcmp(parent, w->parent) && !strcmp(publisher, w->publisher) && !strcmp(output, w->output);
}
static bool sh_plan_fields(struct sh_work *w, const struct json_value *data)
{
    return sh_plan_describe(w, data) && sh_plan_matches(w, data);
}
static bool sh_plan(const struct zcl_command_request *request, struct sh_work *w, struct zcl_command_reply *reply)
{
    struct zcl_command_reply plan; zcl_command_reply_init(&plan, "zcl.zcode_package_share.v1");
    bool called = sh_call(request, w, false, &plan), ok = false;
    if (!called) sh_fail(reply, "SHARE_PLAN_FAILED", "The share plan could not be prepared.");
    else if (plan.status != ZCL_COMMAND_STATUS_PASSED) app_confirm_forward_failure(reply, &plan);
    else if (!(ok = sh_plan_fields(w, &plan.data))) sh_fail(reply, "SHARE_PLAN_INVALID", "The exact kept version and output could not be verified.");
    zcl_command_reply_free(&plan); return ok;
}
static bool sh_path_needs_escaping(const char *path)
{
    for (const unsigned char *p = (const unsigned char *)path; *p; ++p)
        if (*p <= 32 || *p > 126 || *p == '\\') return true;
    return false;
}

static bool sh_model(struct sh_work *w, char *why, size_t cap)
{
    w->view.window_title = "Share this app";
    struct zcl_present_model_v1 *m = &w->view.model;
    zcl_present_model_init_v1(m, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(m->request_id, sizeof(m->request_id), "share-%.12s", w->plan);
    (void)snprintf(m->title, sizeof(m->title), "Share this kept version?");
    (void)snprintf(m->summary, sizeof(m->summary), "Review all pages before sharing.");
    m->action_count = 4;
    app_confirm_action(&m->actions[0], ZCL_PRESENT_ACTION_CANCEL, "cancel", "Cancel");
    app_confirm_action(&m->actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&m->actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&m->actions[3], ZCL_PRESENT_ACTION_CONFIRM, "share", "Share file");
    bool ok = app_confirm_field(m, "App: ", w->name) && app_confirm_field(m, "Version: ", w->semver) &&
        app_confirm_field(m, "Saved version: ", w->version) && app_confirm_field(m, "Package: ", w->package) &&
        app_confirm_field(m, "Publisher: ", w->publisher) && app_confirm_field(m, "Release: ", w->release) &&
        app_confirm_path(m, "Output: ", w->output) &&
        (!sh_path_needs_escaping(w->output) || app_confirm_field(m, "Path notation: ",
            "Backslashes are doubled; other escaped bytes use backslash x and two hex digits.")) &&
        app_confirm_field(m, "Sharing: ", "Signs this saved version and creates a local share file. Nothing is sent over the network.");
    return ok && app_confirm_prepare(&w->view, why, cap);
}
static bool sh_still_selected(struct sh_work *w, struct zcl_command_reply *reply)
{
    struct app_selection now;
    if (app_selection_load(w->env.state_dir, w->app, &now) != APP_SELECTION_OK)
        return sh_fail(reply, "SELECTION_STALE", "The kept version changed; review a fresh share plan.");
    if (!sh_snapshot(w, &now, reply)) return false;
    char path[SH_PATH], pub[67]; bool exists = false;
    if (!app_personalize_key_probe(reply, path, sizeof(path), pub, &exists)) return false;
    if (!exists || strcmp(path, w->key) || strcmp(pub, w->publisher))
        return sh_fail(reply, "PUBLISHER_CHANGED", "The local signing identity changed; review a fresh share plan.");
    return true;
}
static bool sh_result_matches(const struct sh_work *w, const struct json_value *data)
{
    const char *file = zcl_package_copy_str(data, "share_file");
    const char *version = zcl_package_copy_str(data, "version");
    const char *package = zcl_package_copy_str(data, "package_root");
    const char *publisher = zcl_package_copy_str(data, "publisher_fingerprint");
    const char *release = zcl_package_copy_str(data, "release_id");
    return file && version && package && publisher && release && !strcmp(file, w->output) &&
        !strcmp(version, w->version) && !strcmp(package, w->package) &&
        !strcmp(publisher, w->publisher) && !strcmp(release, w->release);
}
static void sh_commit(const struct zcl_command_request *request, struct sh_work *w, struct zcl_command_reply *reply)
{
    if (!sh_still_selected(w, reply) || !sh_copy(w, reply)) return;
    struct zcl_command_reply result; zcl_command_reply_init(&result, "zcl.zcode_package_sign.v1");
    bool called = sh_call(request, w, true, &result);
    if (!called) sh_fail(reply, "SHARE_UNAVAILABLE", "The native signer is unavailable.");
    else if (result.status != ZCL_COMMAND_STATUS_PASSED) {
        app_confirm_forward_failure(reply, &result);
        sh_partial_facts(w, reply);
    }
    else if (!sh_result_matches(w, &result.data))
        zcl_package_copy_fail(reply, "SHARE_RESULT_MISMATCH", true, "The local share was created but its result could not be verified.", w->output);
    else { json_free(&reply->data); reply->data = result.data; json_init(&result.data); reply->error.mutated = true; }
    zcl_command_reply_free(&result);
}
static void sh_run(const struct zcl_command_request *request, struct zcl_command_reply *reply,
                   const char *name, const char *output, app_confirm_presenter presenter,
                   void *context, const struct app_selection *snapshot)
{
    if (!request || !reply) return;
    struct sh_work *w = zcl_calloc(1, sizeof(*w), "app-share");
    if (!w) { sh_fail(reply, "OUT_OF_MEMORY", "Cannot prepare sharing."); return; }
    if (sh_values(w, name, output, reply) && sh_selection(w, reply) && sh_snapshot(w, snapshot, reply) && sh_copy(w, reply) && sh_key(w, reply) && sh_plan(request, w, reply)) {
        char why[256] = {0};
        if (!sh_model(w, why, sizeof(why)) || !app_confirm_show(&w->view, presenter, context, why, sizeof(why)))
            sh_fail(reply, "CONFIRMATION_UNAVAILABLE", "The exact share plan could not be displayed.");
        else if (w->view.confirmed) sh_commit(request, w, reply);
        else if (!json_push_kv_str(&reply->data, "status", "canceled")) sh_fail(reply, "OUT_OF_MEMORY", "Cannot describe cancellation.");
    }
    app_confirm_free(&w->view); free(w);
}
static void sh_front(const struct zcl_command_request *request, struct zcl_command_reply *reply,
                     app_confirm_presenter presenter, void *context)
{
    if (!request || !reply || !sh_inputs(request->input, reply)) return;
    sh_run(request, reply, zcl_package_copy_str(request->input, "name"),
           zcl_package_copy_str(request->input, "output"), presenter, context, NULL);
}
void zcl_native_app_share_snapshot(const char *name, const char *output,
    struct zcl_command_reply *reply, const struct app_selection *selection)
{
    if (!reply) return;
    if (!selection) { zcl_package_copy_fail(reply, "SELECTION_UNAVAILABLE", false, "A saved choice is required.", SH_COMMAND); return; }
    const struct zcl_command_request request = {0};
    sh_run(&request, reply, name, output, NULL, NULL, selection);
}
void zcl_native_handle_app_share(const struct zcl_command_request *request, struct zcl_command_reply *reply)
{ sh_front(request, reply, NULL, NULL); }
#if defined(ZCL_TESTING)
void zcl_test_app_share_run(const struct zcl_command_request *request, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context)
{ if (presenter) sh_front(request, reply, presenter, context); }
#endif
