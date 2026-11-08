/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Discover and open installed and kept apps through existing authorities. */
#include "command/native_app_library_command.h"
#include "command/native_app_confirm.h"
#include "command/native_zcode_package_copy.h"
#include "command/app_selection.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "presentation/model_render.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    al_choice(m, "open", "Open app", value);
    al_choice(m, "previous", "Previous app", w->index ? "Browse back." : "First app.");
    al_choice(m, "next", "Next app", w->index + 1 < w->count ? "Browse forward." : "Last app.");
    al_choice(m, "cancel", "Cancel", "Close without opening an app.");
}
static bool al_present(void *context, const struct zcl_present_model_v1 *model,
    struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    (void)context;
    struct zcl_present_model_bitmap_v1 bitmap = {0};
    if (!zcl_present_model_render_v1(model, &bitmap, why, cap)) return false;
    struct zcl_present_window_v1 window = {.struct_size = sizeof(window), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "My Apps", .pixels = bitmap.pixels, .width = bitmap.width,
        .height = bitmap.height, .pixel_format = ZCL_PRESENT_RGB8};
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
    (void)presenter(context, &w->model, &event, why, sizeof(why));
}
static bool al_event_valid(const struct zcl_present_window_event_v1 *event, uint32_t count)
{
    if (event->struct_size != sizeof(*event) || event->abi_version != ZCL_PRESENT_ABI_V1) return false;
    if (event->outcome == ZCL_PRESENT_WINDOW_DISMISSED) return true;
    return event->outcome == ZCL_PRESENT_WINDOW_ACTION && event->action_index < count;
}
static void al_run(const struct app_launch_env *env, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context)
{
    struct library *w = zcl_calloc(1, sizeof(*w), "app-library");
    if (!w) { al_fail(reply, "OUT_OF_MEMORY", "Cannot allocate My Apps."); return; }
    char why[256] = {0};
    bool loaded = al_load(w, env, reply);
    while (loaded) {
        al_model(w);
        struct zcl_present_window_event_v1 event = {0};
        if (!zcl_present_model_validate_v1(&w->model, why, sizeof(why)) ||
            !presenter(context, &w->model, &event, why, sizeof(why))) {
            al_fail(reply, "PRESENTATION_FAILED", why); break;
        }
        if (!al_event_valid(&event, w->model.action_count)) {
            al_fail(reply, "INVALID_SELECTION", "The app selection was not recognized. Nothing was opened."); break;
        }
        if (event.outcome == ZCL_PRESENT_WINDOW_DISMISSED || !w->count || event.action_index == 3) {
            (void)json_push_kv_str(&reply->data, "status", "canceled"); break;
        }
        if (event.action_index == 1) { if (w->index) --w->index; continue; }
        if (event.action_index == 2) { if (w->index + 1 < w->count) ++w->index; continue; }
        struct library_row *row = &w->rows[w->index];
        zcl_native_app_open_snapshot(env, &row->entry, row->saved ? &row->selection : NULL, reply);
        break;
    }
    if (reply->status != ZCL_COMMAND_STATUS_PASSED) al_error_view(w, reply, presenter, context);
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
    al_run(&env, reply, al_present, NULL);
}
#if defined(ZCL_TESTING)
void zcl_test_app_library_run(const struct app_launch_env *env,
    struct zcl_command_reply *reply, app_library_presenter presenter, void *context)
{
    al_run(env, reply, presenter, context);
}
#endif
