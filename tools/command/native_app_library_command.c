/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Discover and open installed and kept apps through existing authorities. */
#include "command/native_app_library_command.h"
#include "command/native_app_confirm.h"
#include "command/native_app_personalize_view.h"
#include "command/native_zcode_package_copy.h"
#include "command/app_selection.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "presentation/model_render.h"
#include "platform/os_proc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#define AL_ROWS (APP_LAUNCH_ENTRIES_MAX + APP_SELECTION_ROUTES_MAX)
struct library_row {
    struct app_launch_entry entry;
    struct app_selection selection;
    bool saved;
};
struct library {
    struct app_launch_registry registry;
    struct library_row rows[AL_ROWS];
    size_t count, index;
    unsigned page;
    char setup[ZCL_PRESENT_COPY_TEXT_MAX + 1];
    char source_version[65];
    char prepared_version[65];
    app_library_preparer preparer;
    void *prepare_context;
    bool prepared_mutated;
    unsigned preparation_count;
    struct json_value preparation;
    struct zcl_present_model_v1 model;
};
static bool al_fail(struct zcl_command_reply *reply, const char *code, const char *why)
{
    zcl_package_copy_fail(reply, code, false, why, "app.library");
    return false;
}
static bool al_add(struct library *w, const struct app_launch_env *env,
    const struct app_launch_entry *entry, struct zcl_command_reply *reply)
{
    if (w->count >= AL_ROWS) return al_fail(reply, "LIBRARY_OVERFLOW", "Too many apps to display safely.");
    struct library_row *r = &w->rows[w->count];
    r->entry = *entry;
    enum app_selection_result loaded = app_selection_load(env->state_dir, entry->id, &r->selection);
    r->saved = loaded == APP_SELECTION_OK;
    if ((!r->saved && loaded != APP_SELECTION_ABSENT) ||
        (!r->saved && app_selection_route_reserved(entry->id)))
        return al_fail(reply, "SELECTION_UNREADABLE", "A saved app cannot be read. No apps were opened.");
    if (!r->saved && !entry->installed) return true;
    ++w->count;
    return true;
}
static bool al_load(struct library *w, const struct app_launch_env *env,
    struct zcl_command_reply *reply)
{
    app_launch_registry_load(env, &w->registry);
    if (w->registry.config_error[0])
        return al_fail(reply, "CATALOG_REFUSED", w->registry.config_error);
    struct app_selection_routes routes;
    if (app_selection_routes_load(env->state_dir, &routes) != APP_SELECTION_OK)
        return al_fail(reply, "SELECTIONS_REFUSED", "Saved apps are unreadable or exceed the library limit.");
    for (unsigned i = 0; i < w->registry.count; ++i)
        if (!al_add(w, env, &w->registry.entries[i], reply)) return false;
    for (size_t i = 0; i < routes.count; ++i) {
        struct app_launch_entry entry;
        if (!app_launch_kept_entry(routes.names[i], &entry) || !al_add(w, env, &entry, reply)) return false;
    }
    return true;
}
static void al_choice(struct zcl_present_model_v1 *m, const char *id,
    const char *label, const char *value)
{
    unsigned i = m->item_count++;
    struct zcl_present_model_item_v1 *item = &m->items[i];
    item->kind = ZCL_PRESENT_ITEM_CHOICE;
    item->status = ZCL_PRESENT_STATUS_INFO;
    item->parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    (void)snprintf(item->id, sizeof(item->id), "%s", id);
    (void)snprintf(item->label, sizeof(item->label), "%s", label);
    (void)snprintf(item->value, sizeof(item->value), "%s", value);
    app_confirm_action(&m->actions[i], ZCL_PRESENT_ACTION_SELECT, id, label);
    m->action_count = m->item_count;
}
static void al_model(struct library *w)
{
    struct zcl_present_model_v1 *m = &w->model;
    zcl_present_model_init_v1(m, ZCL_PRESENT_MODEL_CHOICE);
    (void)snprintf(m->request_id, sizeof(m->request_id), "library-%zu", w->index);
    (void)snprintf(m->title, sizeof(m->title), "My Apps");
    if (!w->count) {
        (void)snprintf(m->summary, sizeof(m->summary), "No apps yet. Install an app or open a shared app to get started.");
        al_choice(m, "cancel", "Close", "Nothing will be opened.");
        return;
    }
    const struct library_row *r = &w->rows[w->index];
    const char *name = r->entry.id;
    if (r->saved) {
        const char *base = strrchr(r->selection.copy, '/');
        if (base && base[1]) name = base + 1;
    } else if (!strcmp(name, "skycombat")) name = "Sky Combat";
    char value[ZCL_PRESENT_MODEL_VALUE_MAX + 1], version[65];
    zcl_hex_encode(r->selection.version, 32, version);
    (void)snprintf(m->summary, sizeof(m->summary), "App %zu of %zu. %.72s", w->index + 1, w->count, name);
    (void)snprintf(value, sizeof(value), "%s%.12s",
        r->saved ? "Saved version " : "Installed app", r->saved ? version : "");
    al_choice(m, "choose", "Choose app", value);
    al_choice(m, "previous", "Previous app", w->index ? "Browse back." : "First app.");
    al_choice(m, "next", "Next app", w->index + 1 < w->count ? "Browse forward." : "Last app.");
    al_choice(m, "cancel", "Cancel", "Close without opening an app.");
}
static bool al_present(void *context, const struct zcl_present_model_v1 *model,
    const char *copy_text, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    (void)context;
    struct zcl_present_model_bitmap_v1 bitmap = {0};
    if (!zcl_present_model_render_v1(model, &bitmap, why, cap)) return false;
    struct zcl_present_window_v1 window = {.struct_size = sizeof(window), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "My Apps", .pixels = bitmap.pixels, .width = bitmap.width,
        .height = bitmap.height, .pixel_format = ZCL_PRESENT_RGB8, .copy_text = copy_text};
    bool ok = zcl_present_window_run_actions_v1(&window, model->action_count, NULL, NULL, event, why, cap);
    zcl_present_model_bitmap_free_v1(&bitmap);
    return ok;
}
static void al_error_view(struct library *w, const struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context)
{
    zcl_present_model_init_v1(&w->model, ZCL_PRESENT_MODEL_CHOICE);
    (void)snprintf(w->model.request_id, sizeof(w->model.request_id), "library-error");
    (void)snprintf(w->model.title, sizeof(w->model.title), "Could not open My Apps");
    (void)snprintf(w->model.summary, sizeof(w->model.summary), "%s", reply->error.message);
    al_choice(&w->model, "close", "Close", "No other app will be opened.");
    struct zcl_present_window_event_v1 event = {0};
    char why[256];
    (void)presenter(context, &w->model, NULL, &event, why, sizeof(why));
}
static bool al_event_valid(const struct zcl_present_window_event_v1 *event, uint32_t count)
{
    if (event->struct_size != sizeof(*event) || event->abi_version != ZCL_PRESENT_ABI_V1) return false;
    if (event->outcome == ZCL_PRESENT_WINDOW_DISMISSED) return true;
    return event->outcome == ZCL_PRESENT_WINDOW_ACTION && event->action_index < count;
}
static bool al_same(const struct app_selection *a, const struct app_selection *b)
{
    if (a->revision != b->revision || strcmp(a->app, b->app) ||
        strcmp(a->copy, b->copy) || strcmp(a->datadir, b->datadir)) return false;
    const uint8_t *left[] = {a->fork, a->parent, a->version, a->package, a->env, a->dependencies, a->record, a->image};
    const uint8_t *right[] = {b->fork, b->parent, b->version, b->package, b->env, b->dependencies, b->record, b->image};
    for (size_t i = 0; i < 8; ++i) if (memcmp(left[i], right[i], 32)) return false;
    return true;
}
static bool al_current(const struct library_row *row, const struct app_launch_env *env,
    struct zcl_command_reply *reply)
{
    struct app_selection now;
    enum app_selection_result loaded = app_selection_load(env->state_dir, row->entry.id, &now);
    bool same = row->saved ? loaded == APP_SELECTION_OK && al_same(&row->selection, &now)
                          : loaded == APP_SELECTION_ABSENT;
    if (!same) return al_fail(reply, "SELECTION_STALE", "Your saved choice changed. Close My Apps and open it again.");
    if (row->saved && row->selection.revision > INT64_MAX)
        return al_fail(reply, "SELECTION_UNREADABLE", "Saved selection revision is out of range.");
    return true;
}
static bool al_arguments(struct json_value *data, const char *datadir)
{
    /* The MCP parser accepts one --datadir=value argument, at most511 bytes. */
    char profile[522];
    int n = snprintf(profile, sizeof(profile), "--datadir=%s", datadir);
    if (n < 0 || (size_t)n >= sizeof(profile)) return false;
    struct json_value args = {0}, value = {0};
    json_set_array(&args);
    const char *words[] = {"mcp", "serve", profile};
    bool ok = true;
    for (size_t i = 0; ok && i < 3; ++i) {
        json_set_str(&value, words[i]);
        ok = value.type == JSON_STR && json_push_back(&args, &value);
    }
    ok = ok && json_push_kv(data, "args", &args);
    json_free(&value); json_free(&args);
    return ok;
}
static bool al_executable(char *path, size_t cap)
{
    struct stat st;
    if (!os_proc_exe_path(path, cap) || stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return false;
#if !defined(_WIN32)
    if (access(path, X_OK) != 0) return false;
#endif
    return true;
}
static bool al_setup_identity(struct json_value *data, const struct library_row *r,
    const char *source_version)
{
    char version[65];
    if (r->saved) {
        zcl_hex_encode(r->selection.version, 32, version);
        return json_push_kv_int(data, "revision", (int64_t)r->selection.revision) &&
            json_push_kv_str(data, "version", version) &&
            json_push_kv_str(data, "source_version", source_version) &&
            json_push_kv_str(data, "request", "Connect this local MCP server using command and args as literal values. Call apps_list, then app.customize with name, expected_revision equal to revision, and source_version. Verify selection_revision, kept version, and source_version separately. Include source_version in every source read and app.edit. After each edit use its returned version as the next source_version, retaining the original revision and kept version until Keep. Ask what I want to change, preview it, then wait for explicit Keep and Share. If selection changed, reopen My Apps.");
    }
    return json_push_kv_str(data, "request", "Connect this local MCP server using command and args as literal values. This installed Sky Combat has no saved selection. Help me open it and choose Make my copy before customization. Do not invent a saved revision or version. Ask what I want to change, preview it, and wait for my explicit Keep and Share choices.");
}
static bool al_setup_encode(struct library *w, const char *exe, const char *datadir,
    struct zcl_command_reply *reply)
{
    const struct library_row *r = &w->rows[w->index];
    struct json_value data = {0}; json_set_object(&data);
    bool ok = json_push_kv_str(&data, "command", exe) && al_arguments(&data, datadir) &&
        json_push_kv_str(&data, "name", r->entry.id) && al_setup_identity(&data, r, w->source_version);
    size_t n = ok ? json_write(&data, NULL, 0) : 0;
    ok = n && n < sizeof(w->setup) && json_write(&data, w->setup, sizeof(w->setup)) == n;
    json_free(&data);
    if (!ok) { w->setup[0] = 0; return al_fail(reply, "SETUP_TOO_LARGE", "Cannot copy complete AI setup safely."); }
    return true;
}
static void al_prepare_native(void *context, const struct app_selection *selection,
    struct zcl_command_reply *reply)
{
    (void)context;
    struct json_value input = {0}; json_set_object(&input);
    if (!json_push_kv_str(&input, "name", selection->app) ||
        !json_push_kv_int(&input, "expected_revision", (int64_t)selection->revision))
        al_fail(reply, "OUT_OF_MEMORY", "Cannot prepare your selected app.");
    else {
        struct zcl_command_request request = {.input = &input};
        app_personalize_view_prepare(&request, reply);
    }
    json_free(&input);
}
static bool al_prepare_source(struct library *w, const struct app_launch_env *env,
    struct zcl_command_reply *reply)
{
    const struct library_row *r = &w->rows[w->index];
    if (!r->saved) return true;
    struct zcl_command_reply prepared;
    zcl_command_reply_init(&prepared, "zcl.app_personalize.v1");
    (w->preparer ? w->preparer : al_prepare_native)(w->prepare_context, &r->selection, &prepared);
    bool ok = prepared.status == ZCL_COMMAND_STATUS_PASSED;
    const char *status = zcl_package_copy_str(&prepared.data, "status");
    if (!ok) app_confirm_forward_failure(reply, &prepared);
    else if (status && !strcmp(status, "canceled")) {
        ok = false;
        if (!json_push_kv_str(&reply->data, "status", "canceled"))
            al_fail(reply, "OUT_OF_MEMORY", "Cannot describe cancellation.");
    } else {
        const char *version = zcl_package_copy_str(&prepared.data, "version");
        uint8_t decoded[32];
        ok = version && strlen(version) == 64 && zcl_hex_decode_lower(version, decoded, 32);
        if (ok) memcpy(w->source_version, version, 65);
        else al_fail(reply, "PREPARE_FAILED", "The prepared source identity is unavailable.");
        if (prepared.error.mutated) {
            w->prepared_mutated = true;
            ++w->preparation_count;
            memcpy(w->prepared_version, w->source_version, sizeof(w->prepared_version));
            json_free(&w->preparation);
            w->preparation = prepared.data; json_init(&prepared.data);
        }
    }
    zcl_command_reply_free(&prepared);
    return ok && al_current(r, env, reply);
}
static bool al_recovery_complete(const struct json_value *facts, const struct json_value *original)
{
    const char *keys[] = {"version", "copy", "datadir"};
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); ++i) {
        const char *a = zcl_package_copy_str(facts, keys[i]);
        const char *b = zcl_package_copy_str(original, keys[i]);
        if (!a || !b || strcmp(a, b)) return false;
    }
    const char *flags[] = {"key_created", "changed"};
    for (size_t i = 0; i < sizeof(flags)/sizeof(flags[0]); ++i) {
        const struct json_value *a = json_get(facts, flags[i]);
        const struct json_value *b = json_get(original, flags[i]);
        if (!a || !b || a->type != JSON_BOOL || b->type != JSON_BOOL ||
            json_get_bool(a) != json_get_bool(b)) return false;
    }
    return true;
}
static bool al_recovery_facts(struct library *w, struct zcl_command_reply *reply, bool failed)
{
    const char *key = failed ? "failure_facts" : "preparation";
    size_t size = json_write(&w->preparation, NULL, 0);
    struct json_value *container = &reply->data;
    /* A later backend failure owns its facts. Add our previous completed
     * preparation beneath them, never replace or duplicate that object. */
    if (failed && json_get(&reply->data, key)) {
        for (size_t i = 0; i < reply->data.num_children; ++i)
            if (!strcmp(reply->data.keys[i], key)) { container = &reply->data.children[i]; break; }
        key = "library_preparation";
    }
    return size && size <= 4096u && container->type == JSON_OBJ &&
        !json_get(container, key) && json_push_kv(container, key, &w->preparation) &&
        al_recovery_complete(json_get(container, key), &w->preparation);
}
static void al_recovery(struct library *w, struct zcl_command_reply *reply)
{
    if (!w->prepared_mutated || w->preparation.type != JSON_OBJ) return;
    reply->error.mutated = true;
    bool failed = reply->status != ZCL_COMMAND_STATUS_PASSED;
    bool complete = al_recovery_facts(w, reply, failed);
    if (!complete && !failed) {
        al_fail(reply, "PREPARE_RECEIPT_FAILED", "The prepared draft receipt could not be encoded.");
        reply->error.mutated = true; failed = true;
    }
    if (failed) {
        char original[sizeof(reply->error.message)];
        memcpy(original, reply->error.message, sizeof(original));
        (void)snprintf(reply->error.message, sizeof(reply->error.message),
            "Last prepared draft %.64s was saved; AI setup stopped. %.100s",
            w->prepared_version[0] ? w->prepared_version : "(identity unavailable)", original);
        (void)snprintf(reply->error.evidence, sizeof(reply->error.evidence),
            "Last of %u completed mutating preparations: %.64s; %s. Inspect this copy before retrying.",
            w->preparation_count,
            w->prepared_version[0] ? w->prepared_version : "(identity unavailable)",
            complete ? "exact recovery facts attached" : "recovery facts could not be encoded");
    }
}
static bool al_setup(struct library *w, const struct app_launch_env *env,
    const char *exe, const char *datadir, struct zcl_command_reply *reply)
{
    const struct library_row *r = &w->rows[w->index];
    w->setup[0] = 0;
    w->source_version[0] = 0;
    if (!al_current(r, env, reply)) return false;
    if (!r->saved && (!r->entry.builtin || strcmp(r->entry.id, "skycombat"))) return true;
    char executable[APP_SELECTION_PATH_MAX];
    if (!exe) {
        if (!al_executable(executable, sizeof(executable)))
            return al_fail(reply, "SETUP_UNAVAILABLE", "Cannot identify the installed Z23 executable.");
        exe = executable;
    }
    if (r->saved) datadir = r->selection.datadir;
    if (!datadir) datadir = zcl_native_command_datadir();
    if (!datadir || !datadir[0]) return al_fail(reply, "MISSING_DATADIR", "No app profile is bound to My Apps.");
    return al_prepare_source(w, env, reply) && al_setup_encode(w, exe, datadir, reply);
}
static void al_detail_model(struct library *w)
{
    al_model(w);
    struct zcl_present_model_v1 *m = &w->model;
    m->item_count = m->action_count = 0;
    const struct library_row *r = &w->rows[w->index];
    if (w->page == 1) {
        al_choice(m, "open", "Open app", "Use this app.");
        al_choice(m, "help", "Change with your AI", "Connect your existing assistant.");
    } else {
        (void)snprintf(m->request_id, sizeof(m->request_id), "library-help");
        (void)snprintf(m->summary, sizeof(m->summary), "%s", w->setup[0]
            ? "Use your existing AI. Setup has not connected it yet."
            : "Editable source is unavailable. Ask the app author for source.");
        if (r->saved) (void)snprintf(m->summary, sizeof(m->summary),
            "%s revision %llu. AI source below; your kept app is unchanged.",
            r->entry.id, (unsigned long long)r->selection.revision);
        char version[65] = {0};
        if (r->saved) (void)snprintf(version, sizeof(version), "%s", w->source_version);
        char first[33]; (void)snprintf(first, sizeof(first), "%.32s", version);
        al_choice(m, "setup", w->setup[0] ? "Press C to copy AI setup" : "No editable source", r->saved ? first : "No saved version yet.");
        al_choice(m, "version", r->saved ? "Paste into AI; keep this open" : w->setup[0] ? "Make my copy first" : "Source needed",
            r->saved ? version + 32 : w->setup[0] ? "Open Sky Combat to make a copy." : "Ask the app author for source.");
    }
    al_choice(m, "back", "Back", "Return to your selected app.");
    al_choice(m, "cancel", "Cancel", "Close My Apps.");
}
/* Return true only while navigation should continue. Open is terminal. */
static bool al_navigate(struct library *w, unsigned action, const struct app_launch_env *env,
    const char *exe, const char *datadir, struct zcl_command_reply *reply)
{
    if (!w->page) {
        if (action == 1 && w->index) --w->index;
        if (action == 2 && w->index + 1 < w->count) ++w->index;
        if (!action) w->page = 1;
        return true;
    }
    if (action == 2) { --w->page; w->setup[0] = 0; return true; }
    if (w->page == 2) return true;
    if (action == 1) {
        if (!al_setup(w, env, exe, datadir, reply)) return false;
        w->page = 2;
        return true;
    }
    struct library_row *row = &w->rows[w->index];
    zcl_native_app_open_snapshot(env, &row->entry, row->saved ? &row->selection : NULL, reply);
    return false;
}
static void al_run(const struct app_launch_env *env, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context, const char *exe, const char *datadir,
    app_library_preparer preparer)
{
    struct library *w = zcl_calloc(1, sizeof(*w), "app-library");
    if (!w) { al_fail(reply, "OUT_OF_MEMORY", "Cannot allocate My Apps."); return; }
    w->preparer = preparer; w->prepare_context = context;
    char why[256] = {0};
    bool loaded = al_load(w, env, reply);
    while (loaded) {
        if (w->page) al_detail_model(w); else al_model(w);
        struct zcl_present_window_event_v1 event = {0};
        if (!zcl_present_model_validate_v1(&w->model, why, sizeof(why)) ||
            !presenter(context, &w->model, w->setup[0] ? w->setup : NULL, &event, why, sizeof(why))) {
            al_fail(reply, "PRESENTATION_FAILED", why); break;
        }
        if (!al_event_valid(&event, w->model.action_count)) {
            al_fail(reply, "INVALID_SELECTION", "The app selection was not recognized. Nothing was opened."); break;
        }
        if (event.outcome == ZCL_PRESENT_WINDOW_DISMISSED || !w->count || event.action_index == 3) {
            (void)json_push_kv_str(&reply->data, "status", "canceled"); break;
        }
        if (!al_navigate(w, event.action_index, env, exe, datadir, reply)) break;
    }
    al_recovery(w, reply);
    if (reply->status != ZCL_COMMAND_STATUS_PASSED) al_error_view(w, reply, presenter, context);
    json_free(&w->preparation);
    free(w);
}
void zcl_native_handle_app_library(const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    struct app_launch_env env;
    char why[256];
    if (!app_launch_env_from_process(&env, why, sizeof(why))) {
        al_fail(reply, "STATE_FAILED", why);
        struct library *w = zcl_calloc(1, sizeof(*w), "app-library-error");
        if (w) { al_error_view(w, reply, al_present, NULL); free(w); }
        return;
    }
    al_run(&env, reply, al_present, NULL, NULL, NULL, NULL);
}
#if defined(ZCL_TESTING)
void zcl_test_app_library_run(const struct app_launch_env *env,
    struct zcl_command_reply *reply, app_library_presenter presenter, void *context)
{
    al_run(env, reply, presenter, context, NULL, NULL, NULL);
}
void zcl_test_app_library_setup(const struct app_launch_env *env, const char *exe,
    const char *datadir, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context)
{
    al_run(env, reply, presenter, context, exe, datadir, NULL);
}
void zcl_test_app_library_setup_prepared(const struct app_launch_env *env, const char *exe,
    const char *datadir, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context, app_library_preparer preparer)
{
    al_run(env, reply, presenter, context, exe, datadir, preparer);
}
#endif
