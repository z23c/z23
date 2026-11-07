/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: `z23 app open <name>` (zcl.app_open.v1) and the launchable
 * section of `z23 app list`. Open resolves a name or alias, checks the
 * desktop session, reports a verified running copy (already_open, raised
 * only when the app declares raise support) or spawns
 * a new one and waits for its ready marker (opened); every refusal names a
 * stage with a plain message and a hint. */

#include "command/native_app_launch.h"
#include "command/app_selection.h"
#include "command/app_seed.h"
#include "command/native_app_front_door.h"
#include "command/native_app_compose.h"

#include "command/native_command.h"
#include "base/safe_alloc.h"
#include "command/native_dev_land_remote_shared.h"
#include "json/json.h"
#include "platform/process_lock.h"
#include "util/log_macros.h"

#define APP_LIST_HINT_MAX (4u * APP_LAUNCH_PATH_MAX + 128u)

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *app_open_stage_name(enum app_open_stage stage)
{
    static const char *const names[] = {
        [APP_STAGE_NONE] = "none",
        [APP_STAGE_UNKNOWN_APP] = "unknown_app",
        [APP_STAGE_NOT_INSTALLED] = "not_installed",
        [APP_STAGE_NO_DESKTOP] = "no_desktop",
        [APP_STAGE_CONFIG_REFUSED] = "config_refused",
        [APP_STAGE_STATE_FAILED] = "state_failed",
        [APP_STAGE_SPAWN_FAILED] = "spawn_failed",
        [APP_STAGE_EXITED_EARLY] = "exited_early",
        [APP_STAGE_NOT_READY] = "not_ready",
        [APP_STAGE_UNSUPPORTED] = "unsupported",
    };
    return (unsigned)stage < sizeof(names) / sizeof(names[0]) ? names[stage]
                                                              : "unknown";
}

const char *app_open_status_name(enum app_open_status status)
{
    return status == APP_OPEN_OPENED         ? "opened"
           : status == APP_OPEN_ALREADY_OPEN ? "already_open"
                                             : "failed";
}

const char *app_raise_outcome_name(enum app_raise_outcome raise)
{
    static const char *const names[] = {
        [APP_RAISE_NONE] = "none",
        [APP_RAISE_DELIVERED] = "delivered",
        [APP_RAISE_UNSUPPORTED_BY_APP] = "unsupported_by_app",
        [APP_RAISE_NO_HANDLER] = "no_handler",
        [APP_RAISE_FAILED] = "failed",
    };
    return (unsigned)raise < sizeof(names) / sizeof(names[0]) ? names[raise]
                                                             : "failed";
}

/* ── running instance ─────────────────────────────────────────────────── */

long app_launch_running_pid(const struct app_launch_env *env,
                            const struct app_launch_entry *entry,
                            const char **found_by)
{
    struct app_launch_record rec;
    char exe[APP_LAUNCH_PATH_MAX];
    uint64_t start = 0;
    *found_by = NULL;
    if (env->state_dir[0] &&
        app_launch_record_load(env->state_dir, entry->id, &rec) &&
        app_proc_identity(rec.pid, exe, &start) &&
        strcmp(exe, rec.executable) == 0 &&
        strcmp(exe, entry->executable) == 0 && start == rec.start_time) {
        *found_by = "record";
        return rec.pid;
    }
    long pid = entry->installed ? app_proc_scan(entry->executable) : 0;
    if (pid)
        *found_by = "scan";
    return pid;
}

/* ── open ─────────────────────────────────────────────────────────────── */

static void app_fail(struct app_open_result *out, enum app_open_stage stage,
                     const char *message, const char *hint)
{
    out->status = APP_OPEN_FAILED;
    out->stage = stage;
    snprintf(out->message, sizeof(out->message), "%s", message);
    snprintf(out->hint, sizeof(out->hint), "%s", hint ? hint : "");
}

static bool app_open_admit(const struct app_launch_env *env,
                           const struct app_launch_registry *reg,
                           const char *name,
                           const struct app_launch_entry **entry,
                           struct app_open_result *out)
{
    char known[256], text[384], hint[300];
    *entry = app_launch_registry_find(reg, name);
    if (!*entry) {
        (void)app_launch_known_names(reg, known, sizeof(known));
        snprintf(hint, sizeof(hint), "known apps: %s", known);
        if (reg->config_error[0]) {
            app_fail(out, APP_STAGE_CONFIG_REFUSED, reg->config_error, hint);
            return false;
        }
        if (!app_seed_web_app_note(name, text, sizeof(text)))
            snprintf(text, sizeof(text), "no app is named '%.64s'",
                     name ? name : "");
        app_fail(out, APP_STAGE_UNKNOWN_APP, text, hint);
        return false;
    }
#if defined(_WIN32)
    app_fail(out, APP_STAGE_UNSUPPORTED, "z23 app open is not available on "
             "Windows yet", "start the program from its own shortcut");
    return false;
#endif
    snprintf(out->id, sizeof(out->id), "%s", (*entry)->id);
    snprintf(out->executable, sizeof(out->executable), "%s",
             (*entry)->executable);
    if (!env->desktop) {
        app_fail(out, APP_STAGE_NO_DESKTOP,
                 "no desktop session on this host: DISPLAY and "
                 "WAYLAND_DISPLAY are both unset",
                 "run it from a terminal inside your desktop session");
        return false;
    }
    if (!(*entry)->installed) {
        snprintf(text, sizeof(text), "%s is not installed: %.200s does not "
                 "exist", (*entry)->id, (*entry)->executable);
        snprintf(hint, sizeof(hint), "%s%s",
                 (*entry)->builtin ? "build it with " : "",
                 (*entry)->build_hint);
        app_fail(out, APP_STAGE_NOT_INSTALLED, text, hint);
        return false;
    }
    return true;
}

static void app_open_raise(const struct app_launch_entry *entry, long pid,
                           const char *found_by, struct app_open_result *out)
{
    out->status = APP_OPEN_ALREADY_OPEN;
    out->pid = pid;
    out->found_by = found_by;
    if (entry->raise_sigusr1) {
        out->raise = app_proc_raise(pid, out->raise_note,
                                    sizeof(out->raise_note));
    } else {
        out->raise = APP_RAISE_UNSUPPORTED_BY_APP;
        snprintf(out->raise_note, sizeof(out->raise_note), "%s does not "
                 "declare raise support; no signal was sent", entry->id);
    }
    snprintf(out->message, sizeof(out->message), "%s is already open as pid "
             "%ld; %s", entry->id, pid, out->raise == APP_RAISE_DELIVERED
             ? "asked it to come to the front" : out->raise_note);
}

static void app_open_spawned(const struct app_launch_env *env,
                             const struct app_launch_entry *entry,
                             const struct app_spawn_outcome *sp,
                             struct app_open_result *out)
{
    struct app_launch_record rec = {0};
    char exe[APP_LAUNCH_PATH_MAX];
    out->pid = sp->pid;
    out->ready_ms = sp->ready_ms;
    out->ready_basis = entry->ready_marker[0] ? "marker" : "alive";
    out->status = APP_OPEN_OPENED;
    snprintf(rec.id, sizeof(rec.id), "%s", entry->id);
    snprintf(rec.executable, sizeof(rec.executable), "%s", entry->executable);
    rec.pid = sp->pid;
    bool saved = app_proc_identity(sp->pid, exe, &rec.start_time) &&
                 app_launch_record_save(env->state_dir, &rec);
    snprintf(out->message, sizeof(out->message), "%s opened as pid %ld in "
             "%lld ms%s", entry->id, sp->pid, (long long)sp->ready_ms,
             saved ? "" : " (pid record not saved; a later open finds it by "
                          "scanning processes)");
}

static void app_open_failed_spawn(const struct app_launch_entry *entry,
                                  const struct app_spawn_outcome *sp,
                                  int timeout_ms, struct app_open_result *out)
{
    char text[1024];
    if (!sp->pid) {
        snprintf(text, sizeof(text), "could not start %.200s: %s",
                 entry->executable, strerror(sp->spawn_errno));
        app_fail(out, APP_STAGE_SPAWN_FAILED, text,
                 "check that the file is a program for this machine");
        return;
    }
    out->pid = sp->pid;
    app_proc_log_tail(out->log_path, out->log_tail, sizeof(out->log_tail));
    if (sp->exited) {
        out->exited = true;
        out->exit_code = sp->exit_code;
        out->term_signal = sp->term_signal;
        char brief[APP_LAUNCH_BRIEF_MAX + 1];
        app_proc_log_brief(out->log_path, brief, sizeof(brief));
        snprintf(text, sizeof(text), "%s exited before its window was ready "
                 "(exit code %d, signal %d); log %.400s:\n%s", entry->id,
                 sp->exit_code, sp->term_signal, out->log_path, brief);
        app_fail(out, APP_STAGE_EXITED_EARLY, text,
                 "read log_tail: a display or GL error means the desktop "
                 "session is not reachable from here");
        return;
    }
    snprintf(text, sizeof(text), "%s did not report ready within %d ms; it is "
             "still running as pid %ld", entry->id, timeout_ms, sp->pid);
    app_fail(out, APP_STAGE_NOT_READY, text,
             "look for its window, read log_tail, or stop it and retry");
}

static bool app_state_paths(const struct app_launch_env *env,
                            const struct app_launch_entry *entry,
                            char *lock_path, size_t cap,
                            struct app_open_result *out)
{
    int a = snprintf(out->log_path, sizeof(out->log_path), "%s/%s.log",
                     env->state_dir, entry->id);
    int b = snprintf(lock_path, cap, "%s/%s.lock", env->state_dir, entry->id);
    if (a <= 0 || (size_t)a >= sizeof(out->log_path) || b <= 0 ||
        (size_t)b >= cap || !app_launch_state_dir_ready(env->state_dir)) {
        char text[384];
        snprintf(text, sizeof(text), "cannot prepare the app state directory "
                 "%.256s: %s", env->state_dir, strerror(errno));
        app_fail(out, APP_STAGE_STATE_FAILED, text,
                 "check that it is a directory you own");
        return false;
    }
    return true;
}

static void app_open_locked(const struct app_launch_env *env,
                            const struct app_launch_entry *entry,
                            struct app_open_result *out)
{
    const char *found_by = NULL;
    long pid = app_launch_running_pid(env, entry, &found_by);
    if (pid) {
        app_open_raise(entry, pid, found_by, out);
        return;
    }
    struct app_spawn_outcome sp;
    (void)app_proc_spawn_and_wait(entry, out->log_path, env->ready_timeout_ms,
                                  env->settle_ms, &sp);
    if (sp.pid && sp.ready && !sp.exited)
        app_open_spawned(env, entry, &sp, out);
    else
        app_open_failed_spawn(entry, &sp, env->ready_timeout_ms, out);
}

void app_launch_open(const struct app_launch_env *env,
                     const struct app_launch_registry *reg, const char *name,
                     struct app_open_result *out)
{
    const struct app_launch_entry *entry = NULL;
    char lock_path[APP_LAUNCH_PATH_MAX];
    struct platform_process_lock lock;
    memset(out, 0, sizeof(*out));
    if (!app_open_admit(env, reg, name, &entry, out) ||
        !app_state_paths(env, entry, lock_path, sizeof(lock_path), out))
        return;
    platform_process_lock_init(&lock);
    if (!platform_process_lock_acquire(&lock, lock_path, true)) {
        app_fail(out, APP_STAGE_STATE_FAILED, "cannot lock the app state "
                 "file", "check the app state directory permissions");
        return;
    }
    app_open_locked(env, entry, out);
    platform_process_lock_release(&lock);
    if (out->status != APP_OPEN_FAILED &&
        !zcl_dlr_file_sha256(entry->executable, out->sha256))
        out->sha256[0] = '\0';
}

/* ── replies ──────────────────────────────────────────────────────────── */

struct app_fail_class {
    enum zcl_command_status status;
    enum zcl_command_exit exit_code;
    bool retryable;
};

static struct app_fail_class app_fail_class(enum app_open_stage stage)
{
    switch (stage) {
    case APP_STAGE_UNKNOWN_APP:
        return (struct app_fail_class){ZCL_COMMAND_STATUS_FAILED,
                                       ZCL_COMMAND_EXIT_INVALID, false};
    case APP_STAGE_NOT_READY:
        return (struct app_fail_class){ZCL_COMMAND_STATUS_FAILED,
                                       ZCL_COMMAND_EXIT_TRANSIENT, true};
    case APP_STAGE_STATE_FAILED:
    case APP_STAGE_SPAWN_FAILED:
    case APP_STAGE_EXITED_EARLY:
        return (struct app_fail_class){ZCL_COMMAND_STATUS_FAILED,
                                       ZCL_COMMAND_EXIT_FAILED, false};
    default:
        return (struct app_fail_class){ZCL_COMMAND_STATUS_BLOCKED,
                                       ZCL_COMMAND_EXIT_BLOCKED, false};
    }
}

static void app_push_opt_str(struct json_value *d, const char *key,
                             const char *value)
{
    if (value && value[0])
        (void)json_push_kv_str(d, key, value);
}

static void app_render(const struct app_open_result *r,
                       struct zcl_command_reply *reply)
{
    struct json_value *d = &reply->data;
    (void)json_push_kv_str(d, "status", app_open_status_name(r->status));
    app_push_opt_str(d, "id", r->id);
    if (r->pid)
        (void)json_push_kv_int(d, "pid", r->pid);
    app_push_opt_str(d, "executable", r->executable);
    app_push_opt_str(d, "log", r->log_path);
    app_push_opt_str(d, "message", r->message);
    if (r->status == APP_OPEN_OPENED) {
        (void)json_push_kv_int(d, "ready_ms", r->ready_ms);
        (void)json_push_kv_str(d, "ready_basis", r->ready_basis);
        (void)json_push_kv_str(d, "sha256", r->sha256);
        (void)json_push_kv_str(d, "sha256_scope", "executable bytes on disk; "
                               "identity only, not a source claim");
    } else if (r->status == APP_OPEN_ALREADY_OPEN) {
        (void)json_push_kv_str(d, "raise", app_raise_outcome_name(r->raise));
        app_push_opt_str(d, "raise_note", r->raise_note);
        app_push_opt_str(d, "found_by", r->found_by);
        app_push_opt_str(d, "sha256", r->sha256);
    }
    if (r->status != APP_OPEN_FAILED)
        return;
    (void)json_push_kv_str(d, "stage", app_open_stage_name(r->stage));
    app_push_opt_str(d, "hint", r->hint);
    if (r->exited) {
        (void)json_push_kv_int(d, "exit_code", r->exit_code);
        (void)json_push_kv_int(d, "signal", r->term_signal);
    }
    app_push_opt_str(d, "log_tail", r->log_tail);
}

static void app_reply_fail(const struct app_open_result *r,
                           struct zcl_command_reply *reply)
{
    char code[32];
    struct app_fail_class c = app_fail_class(r->stage);
    const char *stage = app_open_stage_name(r->stage);
    size_t i = 0;
    for (; stage[i] && i + 1 < sizeof(code); i++)
        code[i] = (char)(stage[i] >= 'a' && stage[i] <= 'z' ? stage[i] - 32
                                                            : stage[i]);
    code[i] = '\0';
    zcl_command_reply_fail(reply, c.status, c.exit_code, code, stage,
                           c.retryable, r->pid != 0, r->message, r->hint);
    if (r->stage == APP_STAGE_UNKNOWN_APP)
        (void)zcl_command_reply_add_next(reply, "app.list", "{}",
                                         "list the launchable apps");
}

struct app_open_work {
    struct app_launch_env env;
    struct app_launch_registry reg;
    struct app_open_result result;
};

static bool app_open_has_selection(const struct json_value *input)
{
    static const char *const keys[] = {"copy", "version", "env_root",
        "dependency_root", "image_sha3", "record_id", "accept_execution"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i)
        if (json_get(input, keys[i])) return true;
    return false;
}

void zcl_native_handle_app_open(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    const char *name = json_get_str(json_get(request->input, "name"));
    char why[256];
    if (!name || !name[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_NAME",
                               "normalize", false, false,
                               "name the app to open, e.g. skycombat", "");
        return;
    }
    if (app_open_has_selection(request->input)) {
        zcl_native_handle_app_open_selected(request, reply);
        return;
    }
    if (zcl_native_app_open_kept(request, reply)) return;
    struct app_open_work *w = zcl_calloc(1, sizeof(*w), "app-open/work");
    if (!w) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "OUT_OF_MEMORY",
                               "state_failed", true, false,
                               "cannot allocate the launcher state", "");
        return;
    }
    if (!app_launch_env_from_process(&w->env, why, sizeof(why))) {
        LOG_ERROR("app-launch", "%s", why);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "STATE_FAILED",
                               "state_failed", false, false, why, "");
        free(w);
        return;
    }
    app_launch_registry_load(&w->env, &w->reg);
    app_launch_open(&w->env, &w->reg, name, &w->result);
    app_render(&w->result, reply);
    if (w->result.status == APP_OPEN_FAILED)
        app_reply_fail(&w->result, reply);
    free(w);
}

/* ── app.list launchable section ──────────────────────────────────────── */

static bool app_list_open_hint(struct json_value *item, const char *name)
{
    char command[APP_LIST_HINT_MAX];
    return zcl_app_hint(command, sizeof(command), zcl_native_command_datadir(),
                        "open %s", name) && json_push_kv_str(item, "open", command);
}

static void app_list_entry(const struct app_launch_env *env,
                           const struct app_launch_entry *e,
                           struct json_value *item)
{
    struct json_value aliases, alias;
    const char *found_by = NULL;
    json_set_object(item);
    json_init(&aliases);
    json_set_array(&aliases);
    for (unsigned a = 0; a < e->alias_count; a++) {
        json_init(&alias);
        json_set_str(&alias, e->aliases[a]);
        (void)json_push_back(&aliases, &alias);
        json_free(&alias);
    }
    (void)json_push_kv_str(item, "id", e->id);
    (void)json_push_kv(item, "aliases", &aliases);
    json_free(&aliases);
    (void)json_push_kv_str(item, "kind", "desktop");
    (void)app_list_open_hint(item, e->id);
    (void)json_push_kv_str(item, "source", e->builtin ? "builtin" : "apps.tsv");
    (void)json_push_kv_bool(item, "installed", e->installed);
    (void)json_push_kv_str(item, "raise", e->raise_sigusr1 ? "sigusr1"
                                                           : "unsupported");
    (void)json_push_kv_str(item, "path", e->executable);
    long pid = e->installed ? app_launch_running_pid(env, e, &found_by) : 0;
    struct json_value running;
    json_init(&running);
    if (pid)
        json_set_int(&running, pid);
    else
        json_set_null(&running);
    (void)json_push_kv(item, "running_pid", &running);
    json_free(&running);
    if (!e->installed)
        (void)json_push_kv_str(item, "build_hint", e->build_hint);
}

static void app_list_config(const struct app_launch_env *env,
                            const struct app_launch_registry *reg,
                            struct json_value *data)
{
    struct json_value cfg;
    json_init(&cfg);
    json_set_object(&cfg);
    (void)json_push_kv_str(&cfg, "path", env->config_path);
    (void)json_push_kv_bool(&cfg, "present", reg->config_present);
    (void)json_push_kv_bool(&cfg, "refused", reg->config_error[0] != '\0');
    app_push_opt_str(&cfg, "error", reg->config_error);
    (void)json_push_kv(data, "launchable_config", &cfg);
    json_free(&cfg);
}

static bool app_list_kept(const struct app_launch_env *env, struct json_value *list)
{
    struct app_selection_routes routes;
    if (app_selection_routes_load(env->state_dir, &routes) != APP_SELECTION_OK) return false;
    for (size_t i = 0; i < routes.count; ++i) {
        struct json_value item; json_init(&item); json_set_object(&item);
        bool ok = json_push_kv_str(&item, "id", routes.names[i]) &&
            json_push_kv_str(&item, "source", "kept") &&
            json_push_kv_str(&item, "kind", "desktop") &&
            json_push_kv_str(&item, "raise", "unsupported") &&
            json_push_kv_str(&item, "validation", "required-on-open") &&
            json_push_kv_str(&item, "ready_basis", "alive") &&
            app_list_open_hint(&item, routes.names[i]) && json_push_back(list, &item);
        json_free(&item);
        if (!ok) return false;
    }
    return true;
}

/* Offer the installed-source owner flow for the built-in game. Other catalog
 * entries retain their existing copy route. Neither hint authorizes a write. */
static void app_list_guide(const struct app_launch_registry *reg,
                           struct zcl_command_reply *reply)
{
    char input[128];
    (void)json_push_kv_str(&reply->data, "summary",
                           "launchable apps open with z23 app open NAME; "
                           "z23 app adopt --name=skycombat offers a personal copy "
                           "from its installed source");
    if (reg->count == 0)
        return;
    char text[APP_LIST_HINT_MAX];
    if (zcl_app_hint(text, sizeof(text), zcl_native_command_datadir(),
                     "open %s", reg->entries[0].id))
        (void)json_push_kv_str(&reply->data, "next", text);
    if (snprintf(input, sizeof(input), "{\"name\":\"%s\"}",
                 reg->entries[0].id) < (int)sizeof(input))
        (void)zcl_command_reply_add_next(reply, "app.open", input,
                                         "open this launchable app");
    bool installed_source = reg->entries[0].builtin &&
        !strcmp(reg->entries[0].id, "skycombat");
    if (snprintf(input, sizeof(input), "{\"%s\":\"%s\"}",
                 installed_source ? "name" : "app",
                 reg->entries[0].id) < (int)sizeof(input))
        (void)zcl_command_reply_add_next(reply,
            installed_source ? "app.adopt" : "app.copy", input,
            installed_source ? "review Make my copy, then preview and Keep" :
                               "make your own copy of it");
}

void zcl_native_handle_app_list_launchable(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct json_value list, item;
    char why[256];
    zcl_native_handle_app_list(request, reply);
    struct app_open_work *w = zcl_calloc(1, sizeof(*w), "app-list/work");
    if (!w) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "OUT_OF_MEMORY",
                               "render", true, false,
                               "cannot allocate the launchable list", "");
        return;
    }
    if (!app_launch_env_from_process(&w->env, why, sizeof(why)))
        w->env.state_dir[0] = '\0';
    app_launch_registry_load(&w->env, &w->reg);
    json_init(&list);
    json_set_array(&list);
    for (unsigned i = 0; i < w->reg.count; i++) {
        json_init(&item);
        app_list_entry(&w->env, &w->reg.entries[i], &item);
        (void)json_push_back(&list, &item);
        json_free(&item);
    }
    if (!app_list_kept(&w->env, &list) || !json_push_kv(&reply->data, "launchable", &list)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "KEPT_LIST_REFUSED", "list", false, false,
            "kept selections are unreadable, corrupt, or exceed the bounded list", w->env.state_dir);
    }
    json_free(&list);
    app_list_guide(&w->reg, reply);
    app_list_config(&w->env, &w->reg, &reply->data);
    zcl_app_list_copies(zcl_native_command_datadir(), &reply->data);
    free(w);
}
