/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Discover and open installed and kept apps through existing authorities. */
#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif
#include "command/native_app_library_command.h"
#include "command/native_app_confirm.h"
#include "command/native_app_discover.h"
#include "command/native_app_receive_flow.h"
#include "command/native_app_receive_preview.h"
#include "command/native_app_share_command.h"
#include "command/native_app_publish_command.h"
#include "command/native_app_share_reveal.h"
#include "command/native_app_personalize_view.h"
#include "command/native_zcode_package_copy.h"
#include "command/app_selection.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "presentation/model_render.h"
#include "zutf8/zutf8.h"
#include "platform/os_proc.h"
#include <stdio.h>
#include <errno.h>
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
    char shared_path[ZCL_PRESENT_COPY_TEXT_MAX + 1];
    app_confirm_presenter notice;
    app_library_sharer sharer;
    app_library_revealer revealer;
    char prepared_version[65];
    app_library_preparer preparer;
    void *prepare_context;
    const char *test_worker_path;
    bool prepared_mutated;
    bool error_presented;
    bool has_received;
    bool receive_current, has_discover_error, recovery_ready, recovery_kept, any_mutated, library_unavailable;
    bool receive_failure;
    bool operation_canceled;
    struct json_value receive_receipt;
    struct zcl_command_reply discover_error;
    unsigned preparation_count;
    struct json_value preparation;
    struct zcl_present_model_v1 model;
};
static bool al_fail(struct zcl_command_reply *reply, const char *code, const char *why)
{
    zcl_package_copy_fail(reply, code, reply->error.mutated, why, "app.library");
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
        al_choice(m, "home", "Back", "Return to the home menu.");
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
    al_choice(m, "home", "Back", "Return to the home menu.");
}
static void al_home(struct library *w)
{
    struct zcl_present_model_v1 *m = &w->model;
    zcl_present_model_init_v1(m, ZCL_PRESENT_MODEL_CHOICE);
    (void)snprintf(m->request_id, sizeof(m->request_id), "library-home");
    (void)snprintf(m->title, sizeof(m->title), "My Apps");
    (void)snprintf(m->summary, sizeof(m->summary), "Open your apps or discover available advertisements.");
    al_choice(m, "myapps", "My apps", "Browse installed and saved apps.");
    al_choice(m, "discover", "Discover apps", "Browse offers received by this node.");
    al_choice(m, "cancel", "Close", "Close without opening an app.");
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
static bool al_view_recovery_fields(struct zcl_present_model_v1 *m, const struct json_value *facts,
    const char *copy, const char *destination)
{
    const struct json_value *executed = json_get(facts, "executed");
    const char *state = executed && executed->type == JSON_BOOL ?
        (json_get_bool(executed) ? "The app was started." : "The app was not started.") :
        "Whether the app started is unknown.";
    return (!copy || app_confirm_field(m, "Copy: ", copy)) &&
        (!destination || app_confirm_path(m, "Destination: ", destination)) &&
        app_confirm_field(m, "Execution: ", state);
}
static bool al_received_error_view(struct library *w, const struct zcl_command_reply *reply, void *context)
{
    const struct json_value *facts = json_get(&reply->data, "failure_facts");
    if (!facts || facts->type != JSON_OBJ) facts = &reply->data;
    const char *copy = zcl_package_copy_str(facts, "copy");
    const char *destination = zcl_package_copy_str(facts, "destination");
    if (reply->error.mutated && (copy || destination)) {
        struct app_confirm *view = zcl_calloc(1, sizeof(*view), "app-library-recovery");
        if (view) {
            struct zcl_present_model_v1 *m = &view->model;
            zcl_present_model_init_v1(m, ZCL_PRESENT_MODEL_STATUS_CARD);
            (void)snprintf(m->request_id, sizeof(m->request_id), "library-recovery");
            (void)snprintf(m->title, sizeof(m->title), "Inspect the received app");
            (void)snprintf(m->summary, sizeof(m->summary), "%s", reply->error.message);
            m->action_count = 4;
            app_confirm_action(&m->actions[0], ZCL_PRESENT_ACTION_CANCEL, "close", "Close");
            app_confirm_action(&m->actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
            app_confirm_action(&m->actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
            app_confirm_action(&m->actions[3], ZCL_PRESENT_ACTION_CONFIRM, "done", "Done");
            bool ok = al_view_recovery_fields(m, facts, copy, destination);
            char why[256] = {0};
            if (ok && app_confirm_prepare(view, why, sizeof(why)) &&
                app_confirm_show(view, w->notice, context, why, sizeof(why))) {
                app_confirm_free(view); free(view); return true;
            }
            app_confirm_free(view); free(view);
        }
    }
    return false;
}
static void al_error_view(struct library *w, const struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context)
{
    if (w->receive_failure && al_received_error_view(w, reply, context)) return;
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
            json_push_kv_str(data, "request", "Register a local stdio MCP server using command and args as literal values. Call apps_list, then call z23_run with path=app.customize and input containing name, expected_revision equal to revision, and source_version. Verify selection_revision, kept version, and source_version separately. Include source_version in every source read and in the input to z23_run with path=app.edit. After each edit use its returned version as the next source_version, retaining the original revision and kept version until Keep. Ask what I want to change, preview it, then wait for explicit Keep and Share. If selection changed, use Back to refresh the app card, then open Change with your AI for fresh setup.");
    }
    return json_push_kv_str(data, "request", "Register a local stdio MCP server using command and args as literal values. This installed Sky Combat has no saved selection. Help me open it and choose Make my copy before customization. Do not invent a saved revision or version. Ask what I want to change, preview it, and wait for my explicit Keep and Share choices.");
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
    struct library *w = context;
    struct json_value input = {0}; json_set_object(&input);
    if (!json_push_kv_str(&input, "name", selection->app) ||
        !json_push_kv_int(&input, "expected_revision", (int64_t)selection->revision))
        al_fail(reply, "OUT_OF_MEMORY", "Cannot prepare your selected app.");
    else {
        struct zcl_command_request request = {.input = &input};
        app_personalize_view_prepare_present(&request, reply, w->notice, w->prepare_context);
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
    if (w->preparer) w->preparer(w->prepare_context, &r->selection, &prepared);
    else al_prepare_native(w, &r->selection, &prepared);
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
static bool al_share_path(struct library *w, const struct library_row *row, struct zcl_command_reply *reply)
{
#if !defined(_WIN32)
    const char *home = getenv("HOME"); char resolved[4096], version[65]; struct stat st;
    if (!home || home[0] != '/' || !realpath(home, resolved) || stat(resolved, &st) || !S_ISDIR(st.st_mode))
        return al_fail(reply, "HOME_UNAVAILABLE", "Cannot locate your home folder.");
    zcl_hex_encode(row->selection.version, 32, version);
    for (unsigned i = 0; i < 1000; ++i) {
        int n = snprintf(w->shared_path, sizeof(w->shared_path), "%s/z23-share-%.12s-%u.z23share", resolved, version, i);
        if (n < 0 || (size_t)n >= sizeof(w->shared_path)) return al_fail(reply, "PATH_TOO_LONG", "Home path is too long to display safely.");
        if (!zutf8_validate(w->shared_path))
            return al_fail(reply, "PATH_UNDISPLAYABLE", "Home path is not valid UTF-8.");
        if (lstat(w->shared_path, &st) != 0) {
            if (errno == ENOENT) return true;
            return al_fail(reply, "OUTPUT_UNAVAILABLE", "Cannot inspect the share destination.");
        }
    }
    return al_fail(reply, "OUTPUT_UNAVAILABLE", "No free share filename is available.");
#else
    (void)w; (void)row; return al_fail(reply, "PLATFORM_UNAVAILABLE", "Sharing is unavailable on this platform.");
#endif
}
static void al_share_notice_failure(struct library *w, struct zcl_command_reply *reply,
    const char *code, const char *message)
{
    zcl_package_copy_fail(reply, code, true, message, w->shared_path);
    struct json_value facts; json_init(&facts); json_set_object(&facts);
    if (json_push_kv_str(&facts, "output", w->shared_path)) (void)json_push_kv(&reply->data, "failure_facts", &facts);
    json_free(&facts);
}
static bool al_share_notice(struct app_confirm *view, const char *path, char *why, size_t cap)
{
    zcl_present_model_init_v1(&view->model, ZCL_PRESENT_MODEL_STATUS_CARD);
    view->window_title = "Share file ready"; view->copy_text = path;
    (void)snprintf(view->model.request_id, sizeof(view->model.request_id), "library-share-result");
    (void)snprintf(view->model.title, sizeof(view->model.title), "Share file created");
    (void)snprintf(view->model.summary, sizeof(view->model.summary),
        "Send this file to a friend. Press C to copy its location; keep this window open while pasting.");
    view->model.action_count = 4;
    app_confirm_action(&view->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "close", "Close");
    app_confirm_action(&view->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&view->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    #if defined(__APPLE__)
    app_confirm_action(&view->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "show", "Show file");
#elif defined(__linux__)
    app_confirm_action(&view->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "show", "Open folder");
#else
    app_confirm_action(&view->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "done", "Done");
#endif
    return app_confirm_path(&view->model, "Path (escaped): ", path) && app_confirm_prepare(view, why, cap);
}

static bool al_reveal_enabled(const struct app_confirm *notice)
{
#if defined(__APPLE__) || defined(__linux__)
    return notice->confirmed;
#else
    (void)notice; return false;
#endif
}
static bool al_reveal_native(void *context, const char *path)
{
    (void)context; return app_share_reveal(path);
}
static bool al_reveal_failure_notice(struct library *w)
{
    struct app_confirm *notice = zcl_calloc(1, sizeof(*notice), "library-reveal-failure");
    if (!notice) return false;
    bool shown = false;
    char why[256] = {0};
    if (al_share_notice(notice, w->shared_path, why, sizeof(why))) {
        (void)snprintf(notice->model.title, sizeof(notice->model.title), "Could not confirm opening");
        (void)snprintf(notice->model.summary, sizeof(notice->model.summary),
            "Your share file is ready. Copy its location and find it in your files.");
        app_confirm_action(&notice->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "done", "Done");
        app_confirm_free(notice); memset(notice->bitmaps, 0, sizeof(notice->bitmaps));
        if (app_confirm_prepare(notice, why, sizeof(why)))
            shown = app_confirm_show(notice, w->notice, w->prepare_context, why, sizeof(why));
    }
    app_confirm_free(notice); free(notice);
    return shown;
}
static bool al_share_result(struct library *w, struct app_confirm *notice,
    struct zcl_command_reply *reply, char *why, size_t cap)
{
    if (reply->status != ZCL_COMMAND_STATUS_PASSED) return false;
    const char *status = zcl_package_copy_str(&reply->data, "status");
    if (status && !strcmp(status, "canceled")) {
        w->operation_canceled = true;
        w->shared_path[0] = 0; json_free(&reply->data); json_init(&reply->data); json_set_object(&reply->data);
        return true;
    }
    const char *file = zcl_package_copy_str(&reply->data, "share_file");
    if (!file || strcmp(file, w->shared_path))
        zcl_package_copy_fail(reply, "SHARE_RESULT_MISMATCH", true, "Share completed but its file location could not be verified.", w->shared_path);
    else if (!app_confirm_show(notice, w->notice, w->prepare_context, why, cap))
        al_share_notice_failure(w, reply, "PRESENTATION_FAILED", "Share file created; its location is in evidence.");
    else if (al_reveal_enabled(notice) && !(w->revealer ? w->revealer : al_reveal_native)(w->prepare_context, w->shared_path)) {
        al_share_notice_failure(w, reply, "REVEAL_FAILED",
            "The share file was created, but opening its location could not be confirmed.");
        w->error_presented = al_reveal_failure_notice(w);
    }
    return false;
}

static bool al_share(struct library *w, const struct app_launch_env *env, struct zcl_command_reply *reply)
{
    const struct library_row *row = &w->rows[w->index];
    if (!row->saved) return al_fail(reply, "SELECTION_UNAVAILABLE", "Keep a version before sharing.");
    if (!al_current(row, env, reply) || !al_share_path(w, row, reply)) return false;
    struct app_confirm *notice = zcl_calloc(1, sizeof(*notice), "library-share-notice");
    char why[256] = {0};
    if (!notice) return al_fail(reply, "OUT_OF_MEMORY", "Cannot prepare share notice.");
    if (!al_share_notice(notice, w->shared_path, why, sizeof(why))) {
        app_confirm_free(notice); free(notice);
        return al_fail(reply, "PATH_UNDISPLAYABLE", "The complete share location cannot be displayed safely.");
    }
    if (w->sharer) w->sharer(w->prepare_context, &row->selection, w->shared_path, reply);
    else zcl_native_app_share_snapshot(row->entry.id, w->shared_path, reply, &row->selection);
    bool resume = al_share_result(w, notice, reply, why, sizeof(why));
    app_confirm_free(notice); free(notice);
    return resume;
}
static void al_change_choice(struct zcl_present_model_v1 *m, const struct library_row *r)
{
    if (r->saved && app_saved_draft_available(&r->selection))
        al_choice(m, "change-options", "Change", "Review unkept changes or connect your assistant.");
    else al_choice(m, "help", "Change with your AI", "Connect your existing assistant.");
}
static void al_detail_model(struct library *w)
{
    al_model(w);
    struct zcl_present_model_v1 *m = &w->model;
    m->item_count = m->action_count = 0;
    const struct library_row *r = &w->rows[w->index];
    if (w->page == 1) {
        al_choice(m, "open", "Open app", "Use this app.");
        al_change_choice(m, r);
        al_choice(m, "share", "Share this version", r->saved ? "Choose file or public offer." : "Keep a version first.");
    } else if (w->page == 7) {
        al_choice(m, "draft", "Review unkept changes", "Preview the exact saved draft before choosing Keep.");
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
    if (w->page != 1) al_choice(m, "cancel", "Cancel", "Close My Apps.");
}
/* Return true only while navigation should continue. Open is terminal. */
static void al_share_options(struct library *w)
{
    al_model(w);
    struct zcl_present_model_v1 *m = &w->model;
    m->item_count = m->action_count = 0;
    (void)snprintf(m->request_id, sizeof(m->request_id), "library-share-options");
    (void)snprintf(m->summary, sizeof(m->summary), "Choose how to share this saved version.");
    al_choice(m, "share-file", "Create share file", "Send a file to someone.");
    al_choice(m, "publish", "Publish publicly", "Offer this version on the public apps board.");
    al_choice(m, "share-back", "Back", "Return to this app.");
}
static void al_publish_notice(struct library *w, struct zcl_command_reply *reply)
{
    const char *post = zcl_package_copy_str(&reply->data, "post_id");
    const char *root = zcl_package_copy_str(&reply->data, "package_root");
    const char *next = zcl_package_copy_str(&reply->data, "next");
    struct app_confirm *v = zcl_calloc(1, sizeof(*v), "library-publish-result");
    char why[256] = {0};
    if (v) {
        zcl_present_model_init_v1(&v->model, ZCL_PRESENT_MODEL_STATUS_CARD);
        v->window_title = "Public offer published";
        v->copy_text = next;
        (void)snprintf(v->model.request_id, sizeof(v->model.request_id), "library-publish-result");
        (void)snprintf(v->model.title, sizeof(v->model.title), "Published to public apps");
        (void)snprintf(v->model.summary, sizeof(v->model.summary), "Posted on this node for up to 24 hours. Other people can discover it after their nodes receive the offer. Press C to copy a command for the recipient.");
        v->model.action_count = 4;
        app_confirm_action(&v->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "close", "Close");
        app_confirm_action(&v->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
        app_confirm_action(&v->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
        app_confirm_action(&v->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "done", "Done");
    }
    bool shown = v && post && root && next && next[0] && strlen(next) <= ZCL_PRESENT_COPY_TEXT_MAX &&
        app_confirm_field(&v->model, "Offer: ", post) &&
        app_confirm_field(&v->model, "Package: ", root) && app_confirm_prepare(v, why, sizeof(why)) &&
        app_confirm_show(v, w->notice, w->prepare_context, why, sizeof(why));
    if (v) { app_confirm_free(v); free(v); }
    if (!shown) zcl_package_copy_fail(reply, "PRESENTATION_FAILED", true,
        "Offer was published but its result could not be displayed.", post ? post : "app.publish");
}
static bool al_publish(struct library *w, const struct app_launch_env *env, struct zcl_command_reply *reply)
{
    const struct library_row *row = &w->rows[w->index];
    if (!row->saved) return al_fail(reply, "SELECTION_UNAVAILABLE", "Keep a version before publishing.");
    if (!al_current(row, env, reply)) return false;
    struct zcl_command_reply inner; zcl_command_reply_init(&inner, "zcl.app_publish.v1");
    zcl_native_app_publish_snapshot(row->entry.id, &row->selection, &inner, w->notice, w->prepare_context);
    const char *status = zcl_package_copy_str(&inner.data, "status");
    bool canceled = inner.status == ZCL_COMMAND_STATUS_PASSED && status && !strcmp(status, "canceled");
    if (canceled) { w->operation_canceled = true; zcl_command_reply_free(&inner); return true; }
    if (inner.status != ZCL_COMMAND_STATUS_PASSED) app_confirm_forward_failure(reply, &inner);
    else { json_free(&reply->data); reply->data = inner.data; json_init(&inner.data); reply->error.mutated = true; }
    zcl_command_reply_free(&inner);
    if (reply->status == ZCL_COMMAND_STATUS_PASSED) al_publish_notice(w, reply);
    return false;
}
static bool al_refresh_after_help(struct library *w, const struct app_launch_env *env,
    struct zcl_command_reply *reply)
{
    struct library_row previous = w->rows[w->index];
    w->count = 0;
    memset(&w->registry, 0, sizeof(w->registry));
    memset(w->rows, 0, sizeof(w->rows));
    if (!al_load(w, env, reply)) return false;
    for (size_t i = 0; i < w->count; ++i) {
        if (strcmp(w->rows[i].entry.id, previous.entry.id)) continue;
        w->index = i;
        bool changed = previous.saved != w->rows[i].saved ||
            (previous.saved && !al_same(&previous.selection, &w->rows[i].selection));
        if (previous.saved && !w->rows[i].saved)
            return al_fail(reply, "SELECTION_UNAVAILABLE", "The saved app is no longer available. Reopen My Apps.");
        w->page = changed ? 0 : 1;
        return true;
    }
    return al_fail(reply, "SELECTION_UNAVAILABLE", "The selected app is no longer available. Reopen My Apps.");
}
static bool al_recovery_fields(struct json_value *out, const struct json_value *source,
    const char *const *keys, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        const struct json_value *v = json_get(source, keys[i]);
        if (!v || !json_push_kv(out, keys[i], v)) return false;
    }
    return true;
}
static bool al_capture_receive(struct library *w, const struct json_value *data)
{
    static const char *const kept_keys[] = {"name", "selection_revision", "version", "image_sha3", "record_id"};
    static const char *const received_keys[] = {"destination", "release_id", "package_root", "publisher_fingerprint", "version"};
    const struct json_value *kept = json_get(data, "kept");
    const char *continuation = zcl_package_copy_str(data, "continuation");
    w->recovery_kept = continuation && !strcmp(continuation, "kept") && kept && kept->type == JSON_OBJ;
    json_free(&w->receive_receipt); json_init(&w->receive_receipt); json_set_object(&w->receive_receipt);
    bool ok = w->recovery_kept ? al_recovery_fields(&w->receive_receipt, kept, kept_keys, 5) :
        al_recovery_fields(&w->receive_receipt, data, received_keys, 5);
    size_t size = ok ? json_write(&w->receive_receipt, NULL, 0) : 0;
    return size && size <= (w->recovery_kept ? 2048u : 8192u);
}
static void al_resolve_discover_error(struct library *w)
{
    if (!w->has_discover_error) return;
    zcl_command_reply_free(&w->discover_error);
    memset(&w->discover_error, 0, sizeof(w->discover_error));
    w->has_discover_error = false;
}
static bool al_received_selection(struct library *w, const struct json_value *data,
    struct zcl_command_reply *reply)
{
    const char *continuation = zcl_package_copy_str(data, "continuation");
    if (!continuation || strcmp(continuation, "kept")) { w->page = 3; return true; }
    const struct json_value *kept = json_get(data, "kept");
    const char *name = zcl_package_copy_str(kept, "name"), *version = zcl_package_copy_str(kept, "version");
    const struct json_value *revision = json_get(kept, "selection_revision");
    if (!name || !version || !revision || revision->type != JSON_INT || revision->val.i < 1)
        return al_fail(reply, "SELECTION_UNREADABLE", "Keep completed but its exact saved selection could not be located.");
    for (size_t i = 0; i < w->count; ++i) {
        const struct library_row *row = &w->rows[i]; char actual[65];
        if (strcmp(row->entry.id, name)) continue;
        zcl_hex_encode(row->selection.version, 32, actual);
        if (!row->saved || row->selection.revision != (uint64_t)revision->val.i || strcmp(actual, version))
            return al_fail(reply, "SELECTION_STALE", "The kept selection changed. Return to My Apps and review it again.");
        w->index = i; w->page = 1; return true;
    }
    return al_fail(reply, "SELECTION_UNAVAILABLE", "The kept app is not available in My Apps.");
}
static bool al_reload(struct library *w, const struct app_launch_env *env, struct zcl_command_reply *reply)
{
    w->count = w->index = 0; memset(&w->registry, 0, sizeof(w->registry));
    memset(w->rows, 0, sizeof(w->rows));
    bool ok = al_load(w, env, reply);
    w->library_unavailable = !ok;
    if (!ok) w->count = 0;
    return ok;
}
static void al_committed_cleanup_failure(struct library *w, const struct app_launch_env *env,
    const struct zcl_command_reply *received)
{
    const char *stage = zcl_package_copy_str(&received->data, "stage");
    if (!received->error.mutated || !stage || strcmp(stage, "commit")) return;
    w->has_received = true; w->receive_current = false;
    w->recovery_ready = al_capture_receive(w, &received->data);
    struct zcl_command_reply check; zcl_command_reply_init(&check, "zcl.app_open.v1");
    bool ok = al_reload(w, env, &check) && al_received_selection(w, &received->data, &check);
    if (!ok) { w->library_unavailable = true; w->count = 0; }
    zcl_command_reply_free(&check);
}
static void al_take_discover_result(struct library *w, struct zcl_command_reply *reply,
    struct zcl_command_reply *received, bool done)
{
    if (done || received->status != ZCL_COMMAND_STATUS_PASSED || received->error.mutated) {
        bool prior = reply->error.mutated;
        zcl_command_reply_free(reply); *reply = *received;
        reply->error.mutated |= prior;
        if (done) w->has_received = w->receive_current = true;
        else w->receive_current = false;
    } else zcl_command_reply_free(received);
}
static bool al_discover(struct library *w, const struct app_launch_env *env,
    const char *datadir, app_library_presenter presenter, void *context,
    struct zcl_command_reply *reply)
{
    if (w->has_received && !w->recovery_ready)
        return al_fail(reply, "RECOVERY_TOO_LARGE", "The previous receipt cannot be safely retained while discovering another app.");
    struct zcl_command_reply received;
    zcl_command_reply_init(&received, "zcl.app_open.v1");
    if (!datadir) datadir = zcl_native_command_datadir();
    bool shown = false;
    bool done;
#ifdef ZCL_TESTING
    if (w->test_worker_path)
        done = app_discover_run_test(datadir, presenter, w->notice, context, &received, &shown, w->test_worker_path);
    else
#endif
        done = app_discover_run(datadir, presenter, w->notice, context, &received, &shown);
    w->any_mutated |= received.error.mutated;
    w->receive_failure = received.status != ZCL_COMMAND_STATUS_PASSED;
    if (done) al_resolve_discover_error(w);
    if (received.status != ZCL_COMMAND_STATUS_PASSED)
        al_committed_cleanup_failure(w, env, &received);
    if (received.status != ZCL_COMMAND_STATUS_PASSED && shown) {
        if (w->has_discover_error) zcl_command_reply_free(&w->discover_error);
        w->discover_error = received; w->has_discover_error = true;
        w->page = 3; return true;
    }
    al_take_discover_result(w, reply, &received, done);
    if (reply->status != ZCL_COMMAND_STATUS_PASSED) return false;
    if (!done) { w->page = 3; return true; }
    w->recovery_ready = al_capture_receive(w, &reply->data);
    if (!al_reload(w, env, reply)) return false;
    return al_received_selection(w, &reply->data, reply);
}
static bool al_receive_recovery(struct library *w, struct zcl_command_reply *reply)
{
    if (!w->has_received || (w->receive_current && reply->status == ZCL_COMMAND_STATUS_PASSED)) return true;
    struct json_value *container = &reply->data;
    if (reply->status != ZCL_COMMAND_STATUS_PASSED) {
        if (!json_get(container, "failure_facts")) {
            struct json_value facts; json_init(&facts); json_set_object(&facts);
            bool ok = json_push_kv(container, "failure_facts", &facts); json_free(&facts);
            if (!ok) return false;
        }
        for (size_t i = 0; i < reply->data.num_children; ++i)
            if (!strcmp(reply->data.keys[i], "failure_facts")) { container = &reply->data.children[i]; break; }
    }
    const char *key = w->recovery_kept ? "historical_keep" : "historical_receive";
    return w->recovery_ready && container->type == JSON_OBJ && !json_get(container, key) &&
        json_push_kv(container, key, &w->receive_receipt);
}
static void al_discover_error_recovery(struct library *w, struct zcl_command_reply *reply)
{
    if (!w->has_discover_error) return;
    if (reply->status == ZCL_COMMAND_STATUS_PASSED) {
        bool mutated = reply->error.mutated;
        zcl_command_reply_free(reply); *reply = w->discover_error;
        memset(&w->discover_error, 0, sizeof(w->discover_error));
        reply->error.mutated |= mutated; w->error_presented = true;
    } else {
        /* Preserve the later error as primary. */
        reply->error.mutated |= w->discover_error.error.mutated;
        w->error_presented = false;
    }
    w->receive_current = false;
}
static bool al_fact_add(struct json_value *facts, const char *key, const struct json_value *value, size_t cap)
{
    struct json_value candidate; json_init(&candidate);
    bool ok = json_copy_checked(&candidate, facts) && json_push_kv(&candidate, key, value);
    size_t bytes = ok ? json_write(&candidate, NULL, 0) : 0;
    if (bytes && bytes <= cap) { json_free(facts); *facts = candidate; return true; }
    json_free(&candidate); return false;
}
static bool al_preparation_fact(struct json_value *facts, const struct json_value *preparation, size_t cap)
{
    static const char *const keys[] = {"version", "copy", "datadir", "key_created", "changed"};
    struct json_value compact; json_init(&compact); json_set_object(&compact);
    bool ok = true;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const struct json_value *v = json_get(preparation, keys[i]);
        if (v && !json_push_kv(&compact, keys[i], v)) ok = false;
    }
    if (ok) ok = al_fact_add(facts, "library_preparation", &compact, cap);
    json_free(&compact); return ok;
}
static size_t al_scalar_size(const char *text)
{
    struct json_value value; json_init(&value); json_set_str(&value, text);
    size_t n = value.type == JSON_STR ? json_write(&value, NULL, 0) : 0;
    json_free(&value); return n;
}
static size_t al_error_reserve(const struct zcl_command_error *error)
{
    /* Reserve envelope, authority and default next action separately from
     * the actual JSON-escaped sizes of the error's string fields. */
    const char *fields[] = {error->code, error->code, error->message, error->phase, error->current_state,
        error->next_action, error->evidence, error->failure_id};
    size_t total = 1000u;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
        size_t n = al_scalar_size(fields[i]);
        if (!n || n > ZCL_COMMAND_ERROR_BUDGET - total) return ZCL_COMMAND_ERROR_BUDGET;
        total += n;
    }
    return total;
}
static size_t al_failure_facts_cap(struct zcl_command_reply *reply, bool *omitted)
{
    size_t reserve = al_error_reserve(&reply->error);
    if (reserve > ZCL_COMMAND_ERROR_BUDGET - 600u) {
        reply->error.phase[0] = reply->error.current_state[0] = reply->error.next_action[0] = 0;
        reply->error.evidence[0] = reply->error.failure_id[0] = 0;
        *omitted = true; reserve = al_error_reserve(&reply->error);
    }
    size_t cap = reserve + 50u < ZCL_COMMAND_ERROR_BUDGET ? ZCL_COMMAND_ERROR_BUDGET - reserve - 50u : 0;
    return cap > 1450u ? 1450u : cap;
}
static struct json_value *al_failure_facts(struct zcl_command_reply *reply)
{
    for (size_t i = 0; i < reply->data.num_children; ++i)
        if (!strcmp(reply->data.keys[i], "failure_facts")) return &reply->data.children[i];
    return NULL;
}
static void al_copy_failure_facts(struct json_value *facts, const struct json_value *old,
    size_t cap, bool *omitted)
{
    if (!old) return;
    if (old->type != JSON_OBJ) { *omitted = true; return; }
    for (size_t i = 0; i < old->num_children; ++i) {
        const char *key = old->keys[i];
        if (!strcmp(key, "details_unavailable")) { *omitted |= json_get_bool(&old->children[i]); continue; }
        if (json_get(facts, key)) continue;
        if (!al_fact_add(facts, key, &old->children[i], cap)) *omitted = true;
    }
}
static void al_copy_receive_locations(struct json_value *facts, const struct json_value *data,
    size_t cap, bool *omitted)
{
    const char *keys[] = {"copy", "destination"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const struct json_value *v = json_get(data, keys[i]);
        if (v && !json_get(facts, keys[i]) && !al_fact_add(facts, keys[i], v, cap)) *omitted = true;
    }
}
static void al_bound_preparation(struct library *w, struct json_value *facts,
    const struct json_value *old, size_t cap, bool *omitted)
{
    if (!w->prepared_mutated || w->preparation.type != JSON_OBJ) return;
    if (old && old->type == JSON_OBJ && al_recovery_complete(old, &w->preparation)) {
        const char *keys[] = {"version", "copy", "datadir", "key_created", "changed"};
        for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
            const struct json_value *v = json_get(old, keys[i]);
            if (!v || !al_fact_add(facts, keys[i], v, cap)) *omitted = true;
        }
        return;
    }
    const struct json_value *full = json_get(old, "library_preparation");
    if (full && al_fact_add(facts, "library_preparation", full, cap)) return;
    if (!al_preparation_fact(facts, &w->preparation, cap)) *omitted = true;
    if (full) *omitted = true;
}
static void al_bound_failure(struct library *w, struct zcl_command_reply *reply)
{
    struct json_value facts; json_init(&facts); json_set_object(&facts);
    bool omitted = false;
    size_t cap = al_failure_facts_cap(reply, &omitted);
    const char *historical = w->recovery_kept ? "historical_keep" : "historical_receive";
    if (w->has_received && w->recovery_ready &&
        !al_fact_add(&facts, historical, &w->receive_receipt, cap)) omitted = true;
    struct json_value *old = al_failure_facts(reply);
    al_bound_preparation(w, &facts, old, cap, &omitted);
    al_copy_failure_facts(&facts, old, cap, &omitted);
    if (w->receive_failure) al_copy_receive_locations(&facts, &reply->data, cap, &omitted);
    if (omitted) (void)json_push_kv_bool(&facts, "details_unavailable", true);
    if (old) { json_free(old); *old = facts; }
    else { if (!json_push_kv(&reply->data, "failure_facts", &facts)) omitted = true; json_free(&facts); }
}
static void al_bound_result(struct library *w, struct zcl_command_reply *reply, size_t data_cap)
{
    if (reply->status == ZCL_COMMAND_STATUS_PASSED) {
        size_t bytes = json_write(&reply->data, NULL, 0);
        if (!bytes || bytes > data_cap) {
            (void)al_fail(reply, "RESULT_TOO_LARGE", "The operation completed but its full result did not fit. Inspect My Apps before retrying.");
        }
    }
    if (reply->status != ZCL_COMMAND_STATUS_PASSED) al_bound_failure(w, reply);
}
static bool al_draft_action(struct library *w, const struct app_launch_env *env, struct zcl_command_reply *reply)
{
    const struct library_row *row = &w->rows[w->index];
    if (!row->saved || !al_current(row, env, reply)) return false;
    w->receive_current = false;
    struct zcl_command_reply attempt;
    zcl_command_reply_init(&attempt, "zcl.app_library.v1");
    app_saved_draft_flow_run(&row->selection, &attempt, w->notice, w->prepare_context, w->test_worker_path);
    bool prior_mutated = reply->error.mutated;
    zcl_command_reply_free(reply); *reply = attempt;
    reply->error.mutated |= prior_mutated;
    return false;
}
static bool al_needs_recovery(const char *id)
{
    return !strcmp(id, "share-file") || !strcmp(id, "publish") || !strcmp(id, "help") ||
        !strcmp(id, "open") || !strcmp(id, "draft");
}
static bool al_action(struct library *w, const char *id, const struct app_launch_env *env,
    const char *exe, const char *datadir, struct zcl_command_reply *reply)
{
    if (w->has_received && !w->recovery_ready && al_needs_recovery(id))
        return al_fail(reply, "RECOVERY_TOO_LARGE", "The previous receipt cannot be safely retained for another operation.");
    if (!strcmp(id, "change-options")) { w->page = 7; return true; }
    if (!strcmp(id, "draft")) return al_draft_action(w, env, reply);
    if (!strcmp(id, "share")) { w->page = 6; return true; }
    if (!strcmp(id, "share-back")) { w->page = 1; return true; }
    if (!strcmp(id, "share-file")) { w->receive_current = false; return al_share(w, env, reply); }
    if (!strcmp(id, "publish")) { w->receive_current = false; return al_publish(w, env, reply); }
    if (!strcmp(id, "help")) {
        w->receive_current = false;
        if (!al_setup(w, env, exe, datadir, reply)) return false;
        w->page = 2; return true;
    }
    if (!strcmp(id, "open")) {
        w->receive_current = false;
        struct library_row *row = &w->rows[w->index];
        zcl_native_app_open_snapshot(env, &row->entry, row->saved ? &row->selection : NULL, reply);
        return false;
    }
    return true;
}
static bool al_navigate(struct library *w, unsigned action, const struct app_launch_env *env,
    const char *exe, const char *datadir, struct zcl_command_reply *reply)
{
    const char *id = w->model.actions[action].id;
    if (!strcmp(id, "myapps")) {
        if (w->library_unavailable && !al_reload(w, env, reply)) return false;
        w->page = 0; return true;
    }
    if (!strcmp(id, "home")) { w->page = 3; return true; }
    if (!strcmp(id, "previous")) { if (w->index) --w->index; return true; }
    if (!strcmp(id, "next")) { if (w->index + 1 < w->count) ++w->index; return true; }
    if (!strcmp(id, "choose")) { w->page = 1; return true; }
    if (!strcmp(id, "back")) { w->setup[0] = 0; if (w->page == 2) return al_refresh_after_help(w, env, reply); if (w->page == 7) w->page = 1; else --w->page; return true; }
    return al_action(w, id, env, exe, datadir, reply);
}
static bool al_navigation_result(struct library *w, unsigned action, const struct app_launch_env *env,
    const char *exe, const char *datadir, struct zcl_command_reply *reply)
{
    w->any_mutated |= reply->error.mutated;
    const char *id = w->model.actions[action].id;
    bool operation = !strcmp(id, "open") || !strcmp(id, "share-file") ||
                     !strcmp(id, "publish") || !strcmp(id, "help") || !strcmp(id, "draft");
    w->operation_canceled = false;
    if (operation) w->receive_failure = false;
    bool next = al_navigate(w, action, env, exe, datadir, reply);
    w->any_mutated |= reply->error.mutated;
    const char *status = zcl_package_copy_str(&reply->data, "status");
    if (operation && !w->operation_canceled && reply->status == ZCL_COMMAND_STATUS_PASSED && (!status || strcmp(status, "canceled")))
        al_resolve_discover_error(w);
    return next;
}
static void al_loop(struct library *w, const struct app_launch_env *env, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context, const char *exe, const char *datadir)
{
    char why[256] = {0};
    bool loaded = al_load(w, env, reply);
    while (loaded) {
        if (w->page == 3) al_home(w);
        else if (w->page == 6) al_share_options(w);
        else if (w->page) al_detail_model(w);
        else al_model(w);
        struct zcl_present_window_event_v1 event = {0};
        if (!zcl_present_model_validate_v1(&w->model, why, sizeof(why)) ||
            !presenter(context, &w->model, w->setup[0] ? w->setup : NULL, &event, why, sizeof(why))) {
            al_fail(reply, "PRESENTATION_FAILED", why);
            break;
        }
        if (!al_event_valid(&event, w->model.action_count)) {
            al_fail(reply, "INVALID_SELECTION", "The app selection was not recognized. Nothing was opened."); break;
        }
        if (event.outcome == ZCL_PRESENT_WINDOW_DISMISSED || !strcmp(w->model.actions[event.action_index].id, "cancel")) {
            if (!w->has_received) (void)json_push_kv_str(&reply->data, "status", "canceled");
            break;
        }
        if (!strcmp(w->model.actions[event.action_index].id, "discover")) {
            if (!al_discover(w, env, datadir, presenter, context, reply)) break;
            continue;
        }
        if (!al_navigation_result(w, event.action_index, env, exe, datadir, reply)) break;
    }
}
static void al_run(const struct app_launch_env *env, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context, const char *exe, const char *datadir,
    app_library_preparer preparer, app_library_sharer sharer, app_confirm_presenter notice,
    app_library_revealer revealer, const char *test_worker_path, size_t data_cap)
{
    struct library *w = zcl_calloc(1, sizeof(*w), "app-library");
    if (!w) { al_fail(reply, "OUT_OF_MEMORY", "Cannot allocate My Apps."); return; }
    w->preparer = preparer; w->sharer = sharer; w->notice = notice; w->revealer = revealer; w->prepare_context = context;
    w->test_worker_path = test_worker_path;
    w->page = 3;
    al_loop(w, env, reply, presenter, context, exe, datadir);
    al_discover_error_recovery(w, reply);
    al_recovery(w, reply);
    reply->error.mutated |= w->has_received || w->any_mutated;
    if (!al_receive_recovery(w, reply))
        al_fail(reply, "OUT_OF_MEMORY", "Receive completed, but its receipt could not be attached.");
    reply->data_schema = "zcl.app_open.v1";
    reply->next_count = 0;
    al_bound_result(w, reply, data_cap);
    if (reply->status != ZCL_COMMAND_STATUS_PASSED && !w->error_presented) al_error_view(w, reply, presenter, context);
    json_free(&w->preparation);
    json_free(&w->receive_receipt);
    if (w->has_discover_error) zcl_command_reply_free(&w->discover_error);
    free(w);
}
static bool al_profile_input(const struct zcl_command_request *request, const char **datadir,
    struct zcl_command_reply *reply)
{
    *datadir = NULL;
    const struct json_value *value = request ? json_get(request->input, "datadir") : NULL;
    if (!value) return true;
    const char *path = json_get_str(value);
    if (!path || path[0] != '/' || strnlen(path, 4097) > 4096)
        return al_fail(reply, "BAD_INPUT", "The app profile must be an absolute bounded path.");
    *datadir = path; return true;
}
void zcl_native_handle_app_library(const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (request && ((request->budget_bytes && request->budget_bytes < ZCL_COMMAND_ERROR_BUDGET) ||
        (request->success_data_budget_provided && request->success_data_budget < 1500u))) {
        al_fail(reply, "BUDGET_TOO_SMALL", "My Apps needs enough reply space to retain recovery details."); return;
    }
    if (request && request->budget_bytes && !request->success_data_budget_provided) {
        al_fail(reply, "BUDGET_UNAVAILABLE", "My Apps needs a measured reply allowance before opening."); return;
    }
    const char *datadir;
    if (!al_profile_input(request, &datadir, reply)) return;
    struct app_launch_env env;
    char why[256];
    if (!app_launch_env_from_process(&env, why, sizeof(why))) {
        al_fail(reply, "STATE_FAILED", why);
        struct library *w = zcl_calloc(1, sizeof(*w), "app-library-error");
        if (w) { al_error_view(w, reply, al_present, NULL); free(w); }
        return;
    }
    size_t cap = request && request->success_data_budget_provided ? request->success_data_budget : 30000u;
    al_run(&env, reply, al_present, NULL, NULL, datadir, NULL, NULL, NULL, NULL, NULL, cap);
}
#if defined(ZCL_TESTING)
void zcl_test_app_library_request(const struct app_launch_env *env, const struct zcl_command_request *request,
    struct zcl_command_reply *reply, app_library_presenter presenter,
    app_confirm_presenter receive_presenter, void *context)
{
    const char *datadir;
    if (al_profile_input(request, &datadir, reply))
        al_run(env, reply, presenter, context, NULL, datadir, NULL, NULL, receive_presenter, NULL, NULL, 30000u);
}
void zcl_test_app_library_discover(const struct app_launch_env *env, const char *datadir,
    struct zcl_command_reply *reply, app_library_presenter presenter,
    app_confirm_presenter receive_presenter, void *context)
{ al_run(env, reply, presenter, context, NULL, datadir, NULL, NULL, receive_presenter, NULL, NULL, 30000u); }
void zcl_test_app_library_discover_worker(const struct app_launch_env *env, const char *datadir,
    struct zcl_command_reply *reply, app_library_presenter presenter,
    app_confirm_presenter receive_presenter, void *context, const char *worker_path)
{ al_run(env, reply, presenter, context, NULL, datadir, NULL, NULL, receive_presenter, NULL, worker_path, 30000u); }
void zcl_test_app_library_discover_worker_share(const struct app_launch_env *env, const char *datadir,
    struct zcl_command_reply *reply, app_library_presenter presenter,
    app_confirm_presenter receive_presenter, void *context, const char *worker_path,
    app_library_sharer sharer)
{ al_run(env, reply, presenter, context, NULL, datadir, NULL, sharer, receive_presenter, NULL, worker_path, 30000u); }
void zcl_test_app_library_native_at(const struct app_launch_env *env, const char *exe,
    const char *datadir, struct zcl_command_reply *reply, app_library_presenter presenter,
    void *context, app_confirm_presenter notice)
{ al_run(env, reply, presenter, context, exe, datadir, NULL, NULL, notice, NULL, NULL, 30000u); }
void zcl_test_app_library_reveal(const struct app_launch_env *env, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context, app_library_sharer sharer,
    app_confirm_presenter notice, app_library_revealer revealer)
{ al_run(env, reply, presenter, context, NULL, NULL, NULL, sharer, notice, revealer, NULL, 30000u); }
void zcl_test_app_library_refresh(const struct app_launch_env *env, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context, app_library_preparer preparer,
    app_library_sharer sharer, app_confirm_presenter notice)
{ al_run(env, reply, presenter, context, "/fixture/z23", "/fixture", preparer, sharer, notice, NULL, NULL, 30000u); }
void zcl_test_app_library_share(const struct app_launch_env *env, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context, app_library_sharer sharer, app_confirm_presenter notice)
{ al_run(env, reply, presenter, context, NULL, NULL, NULL, sharer, notice, NULL, NULL, 30000u); }
void zcl_test_app_library_run(const struct app_launch_env *env,
    struct zcl_command_reply *reply, app_library_presenter presenter, void *context)
{
    al_run(env, reply, presenter, context, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 30000u);
}
void zcl_test_app_library_setup(const struct app_launch_env *env, const char *exe,
    const char *datadir, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context)
{
    al_run(env, reply, presenter, context, exe, datadir, NULL, NULL, NULL, NULL, NULL, 30000u);
}
void zcl_test_app_library_setup_prepared(const struct app_launch_env *env, const char *exe,
    const char *datadir, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context, app_library_preparer preparer)
{
    al_run(env, reply, presenter, context, exe, datadir, preparer, NULL, NULL, NULL, NULL, 30000u);
}

#endif
