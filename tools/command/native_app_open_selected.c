/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Open an explicitly authorized, saved personal app image. */
#include "command/native_command.h"
#include "command/native_app_launch.h"
#include "command/native_zcode_package_copy.h"
#include "command/app_image.h"
#include "command/app_selection.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/temp_directory.h"
#include "sha3/sha3.h"
#include "util/file_tree_ops.h"
#include "util/path_util.h"
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"
#include "vcs/package_store.h"
#include "vcs/vcs.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define AS_PATH 4400
#define AS_COMMAND "app.open"

struct as_open {
    const struct json_value *input;
    struct zcl_command_reply *reply;
    const char *datadir, *name, *version;
    char copy_dir[AS_PATH], scratch[PLATFORM_TEMP_PATH_MAX];
    char image[AS_PATH], log[APP_LAUNCH_PATH_MAX], datadir_real[AS_PATH], version_hex[65];
    uint64_t selection_revision;
    struct app_selection kept;
    struct zcl_package_copy copy;
    uint8_t package[32], env[32], deps[32], image_sha[32], record_id[32];
    struct app_image_build record;
    struct resident_launch launch;
    struct resident_receipt receipt;
    struct app_launch_env env_cfg;
    struct app_launch_registry registry;
    struct app_launch_entry entry;
    struct app_spawn_outcome outcome;
};

static bool as_fail(struct as_open *a, const char *code, const char *message,
                    const char *evidence)
{
    zcl_package_copy_fail(a->reply, code, false, message, evidence ? evidence : "");
    return false;
}

static bool as_root(struct as_open *a, const char *key, uint8_t out[32])
{
    const char *s = zcl_package_copy_str(a->input, key);
    if (s && strlen(s) == 64 && zcl_hex_decode_lower(s, out, 32)) return true;
    return as_fail(a, "BAD_BUILD_IDENTITY", "the selected build identity is missing or invalid", key);
}

static bool as_resolve_locations(struct as_open *a)
{
    a->name = zcl_package_copy_str(a->input, "name");
    a->version = zcl_package_copy_str(a->input, "version");
    const char *dir = zcl_package_copy_str(a->input, "copy");
    uint8_t version[32];
    if (!a->name || !a->version || strlen(a->version) != 64 || !zcl_hex_decode_lower(a->version, version, 32) || !dir || dir[0] != '/')
        return as_fail(a, "BAD_SELECTED_APP", "name, absolute copy and exact saved version are required", AS_COMMAND);
    a->datadir = zcl_package_copy_datadir(a->input, a->reply, AS_COMMAND);
    if (!a->datadir) return false;
    if (!platform_directory_canonical_real(a->datadir, a->datadir_real, sizeof(a->datadir_real)))
        return as_fail(a, "BAD_DATADIR", "datadir is unavailable", a->datadir);
    a->datadir = a->datadir_real;
    if (!platform_directory_canonical_real(dir, a->copy_dir, sizeof(a->copy_dir)))
        return as_fail(a, "COPY_MISSING", "no such copy directory", dir);
    return true;
}

static bool as_inputs(struct as_open *a)
{
    const struct json_value *consent = json_get(a->input, "accept_execution");
    if (!consent || consent->type != JSON_BOOL || !json_get_bool(consent))
        return as_fail(a, "EXECUTION_CONFIRMATION_REQUIRED", "accept execution of this exact image first", AS_COMMAND);
    if (!as_resolve_locations(a)) return false;
    return as_root(a, "env_root", a->env) && as_root(a, "dependency_root", a->deps) &&
           as_root(a, "image_sha3", a->image_sha) && as_root(a, "record_id", a->record_id);
}

static bool as_copy(struct as_open *a)
{
    if (!zcl_package_copy_open_selected(a->copy_dir, &a->copy, a->reply, AS_COMMAND, a->version)) return false;
    enum zcl_package_copy_adoption auth = zcl_package_copy_adopted(a->datadir, &a->copy, NULL);
    if (auth == ZCL_PACKAGE_COPY_ADOPTED || auth == ZCL_PACKAGE_COPY_RECEIVED_TRUSTED) return true;
    return as_fail(a, "NOT_ADOPTED", "only an adopted or trusted received copy may run", zcl_package_copy_adoption_name(auth));
}

static bool as_package(struct as_open *a)
{
    struct vcs_package_release release;
    uint8_t release_id[32], dependencies[32];
    if (zcl_package_copy_find_release(a->datadir, a->copy.parent_release, &release, release_id) != ZCL_PACKAGE_COPY_FOUND)
        return as_fail(a, "RELEASE_UNKNOWN", "the parent release is not persisted", a->datadir);
    if (!platform_temp_directory_create("z23-open-", a->scratch, sizeof(a->scratch)) ||
        vcs_tree_materialize(a->copy_dir, a->copy.selected_tree, a->scratch, VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES, 0) != VCS_OK)
        return as_fail(a, "SNAPSHOT_MATERIALIZE_FAILED", "the selected version could not be materialized", a->copy_dir);
    struct vcs_package_prepare_options options = {.dir = a->scratch, .publisher_sequence = 1,
        .reward_address = "", .chain_id = release.chain_id};
    memcpy(options.publisher_pubkey, release.publisher_pubkey, sizeof(options.publisher_pubkey));
    struct vcs_package_prepared prepared;
    char detail[256] = {0};
    vcs_package_prepared_init(&prepared);
    bool ok = vcs_package_prepare(&options, &prepared, detail, sizeof(detail)) == VCS_PACKAGE_PREPARE_OK;
    if (ok) {
        memcpy(a->package, prepared.package_root, 32);
        app_image_dependency_root(&prepared.lock, dependencies);
    }
    vcs_package_prepared_free(&prepared);
    if (!ok) return as_fail(a, "PACKAGE_INVALID", "the selected version is not a valid package", detail);
    if (memcmp(a->deps, dependencies, 32) != 0)
        return as_fail(a, "DEPENDENCY_MISMATCH", "selected version has different dependencies", AS_COMMAND);
    return true;
}

static bool as_record(struct as_open *a)
{
    char records[AS_PATH], images[AS_PATH], hex[65];
    if (!zcl_path_join(records, sizeof(records), a->datadir, "app_build/records") ||
        !zcl_path_join(images, sizeof(images), a->datadir, "app_build/images"))
        return as_fail(a, "BAD_DATADIR", "build store path is too long", a->datadir);
    bool hit = false;
    struct zcl_result result = app_image_build_load(records, a->package, a->env, a->deps, &a->record, &hit);
    if (!result.ok || !hit) return as_fail(a, "BUILD_RECORD_MISSING", "no matching valid build record", result.message);
    uint8_t id[32];
    result = app_image_build_id(&a->record, id);
    if (!result.ok || memcmp(id, a->record_id, 32) || memcmp(a->record.image_sha3, a->image_sha, 32))
        return as_fail(a, "BUILD_IDENTITY_MISMATCH", "the requested image and record do not match the saved version", AS_COMMAND);
    zcl_hex_encode(a->image_sha, 32, hex);
    if (!zcl_path_join(a->image, sizeof(a->image), images, hex))
        return as_fail(a, "BAD_IMAGE_PATH", "image path is too long", images);
    return true;
}

static bool as_catalog(struct as_open *a)
{
    char why[256] = {0};
    if (!app_launch_env_from_process(&a->env_cfg, why, sizeof(why)))
        return as_fail(a, "STATE_FAILED", "desktop launcher state is unavailable", why);
    if (app_selection_route_reserved(a->name)) {
        if (app_launch_kept_entry(a->name, &a->entry)) return true;
        return as_fail(a, "BAD_KEPT_ROUTE", "use kept: followed by a bounded lowercase app id", a->name);
    }
    app_launch_registry_load(&a->env_cfg, &a->registry);
    if (a->registry.config_error[0])
        return as_fail(a, "CONFIG_REFUSED", "the app catalog is unsafe or malformed", a->registry.config_error);
    const struct app_launch_entry *entry = app_launch_registry_find(&a->registry, a->name);
    if (!entry) return as_fail(a, "UNKNOWN_APP", "no launchable app has that name", a->name);
    a->entry = *entry;
    return true;
}

static bool as_current_revision(struct as_open *a)
{
    struct app_selection current;
    enum app_selection_result r = app_selection_load(a->env_cfg.state_dir, a->entry.id, &current);
    if (r == APP_SELECTION_ABSENT) { a->selection_revision = 0; return true; }
    if (r != APP_SELECTION_OK)
        return as_fail(a, "SELECTION_UNREADABLE", "kept selection cannot be read", a->entry.id);
    if (current.revision > INT64_MAX) return as_fail(a, "SELECTION_UNREADABLE", "selection revision is out of range", a->entry.id);
    a->selection_revision = current.revision;
    return true;
}

static bool as_desktop(struct as_open *a)
{
    if (!a->env_cfg.desktop)
        return as_fail(a, "NO_DESKTOP", "no desktop session is available", AS_COMMAND);
    if (strlen(a->image) >= sizeof(a->entry.executable))
        return as_fail(a, "BAD_IMAGE_PATH", "image path is too long for the launcher", a->image);
    memcpy(a->entry.executable, a->image, strlen(a->image) + 1);
    if (!app_launch_state_dir_ready(a->env_cfg.state_dir))
        return as_fail(a, "STATE_FAILED", "launcher state directory is unavailable", a->env_cfg.state_dir);
    int n = snprintf(a->log, sizeof(a->log), "%s/selected-XXXXXX", a->env_cfg.state_dir);
    if (n <= 0 || (size_t)n >= sizeof(a->log))
        return as_fail(a, "STATE_FAILED", "launcher log path is too long", a->env_cfg.state_dir);
    int fd = mkstemp(a->log);
    if (fd < 0) return as_fail(a, "STATE_FAILED", "cannot create launcher log", a->env_cfg.state_dir);
    close(fd);
    return true;
}

static void as_describe(struct as_open *a, struct json_value *d)
{
    (void)json_push_kv_int(d, "selection_revision", (int64_t)a->selection_revision);
    (void)json_push_kv_str(d, "copy", a->copy_dir);
    (void)json_push_kv_str(d, "datadir", a->datadir);
    (void)json_push_kv_str(d, "name", a->entry.id);
    zcl_package_copy_push_root(d, "version", a->copy.selected_version);
    zcl_package_copy_push_root(d, "package_root", a->package);
    zcl_package_copy_push_root(d, "record_id", a->record_id);
    zcl_package_copy_push_root(d, "image_sha3", a->image_sha);
    zcl_package_copy_push_root(d, "env_root", a->env);
    zcl_package_copy_push_root(d, "dependency_root", a->deps);
    (void)json_push_kv_str(d, "image_path", a->image);
    (void)json_push_kv_str(d, "log", a->log);
}

/* Only a log created for this attempt is removed when no process survives. */
static void as_unspawned_failure(struct as_open *a, const char *code,
                                 const char *message, const char *detail)
{
    if (unlink(a->log) != 0 && errno != ENOENT) {
        zcl_package_copy_fail(a->reply, "LOG_CLEANUP_FAILED", true,
                              "the failed launch left its private log", a->log);
        return;
    }
    a->log[0] = '\0';
    as_fail(a, code, message, detail);
}

static void as_failure_facts(struct as_open *a)
{
    struct json_value facts;
    json_init(&facts);
    json_set_object(&facts);
    as_describe(a, &facts);
    char token[32];
    (void)snprintf(token, sizeof(token), "%llu", (unsigned long long)a->receipt.start_token);
    (void)json_push_kv_int(&facts, "pid", a->receipt.pid);
    (void)json_push_kv_str(&facts, "start_token", token);
    (void)json_push_kv_str(&facts, "mapped_proof", a->receipt.mapped_proof);
    (void)json_push_kv_bool(&facts, "ready", a->outcome.ready);
    (void)json_push_kv_bool(&facts, "exited", a->outcome.exited);
    if (a->outcome.exited) {
        (void)json_push_kv_int(&facts, "exit_code", a->outcome.exit_code);
        (void)json_push_kv_int(&facts, "signal", a->outcome.term_signal);
    }
    char tail[APP_LAUNCH_TAIL_MAX];
    app_proc_log_tail(a->log, tail, sizeof(tail));
    (void)json_push_kv_str(&facts, "log_tail", tail);
    (void)json_push_kv(&a->reply->data, "failure_facts", &facts);
    json_free(&facts);
}

static void as_launch(struct as_open *a)
{
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    resident_launch_init(&a->launch);
    struct zcl_result result = app_image_build_prepare(&a->record, a->image, &a->launch);
    if (!result.ok) { resident_launch_close(&a->launch); as_unspawned_failure(a, "IMAGE_REFUSED", "the built image no longer matches its record", result.message); return; }
    bool spawned = app_proc_resident_spawn_and_wait(&a->entry, &a->launch, a->log,
        a->env_cfg.ready_timeout_ms, a->env_cfg.settle_ms, &a->receipt,
        &a->outcome, error, sizeof(error));
    if (!spawned) {
        if (a->outcome.pid > 0) {
            zcl_command_reply_fail(a->reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                "LAUNCH_WAIT_FAILED", "open", false, true,
                "the app started but readiness observation failed", error);
            as_failure_facts(a);
        } else {
            as_unspawned_failure(a, "SPAWN_FAILED", "the exact built image could not be started", error);
        }
        return;
    }
    struct json_value *d = &a->reply->data;
    as_describe(a, d);
    (void)json_push_kv_int(d, "pid", a->receipt.pid);
    char token[32];
    (void)snprintf(token, sizeof(token), "%llu", (unsigned long long)a->receipt.start_token);
    (void)json_push_kv_str(d, "start_token", token);
    (void)json_push_kv_str(d, "mapped_proof", a->receipt.mapped_proof);
    (void)json_push_kv_bool(d, "ready", a->outcome.ready);
    (void)json_push_kv_bool(d, "exited", a->outcome.exited);
    if (a->outcome.ready) {
        (void)json_push_kv_str(d, "status", "opened");
        (void)json_push_kv_int(d, "ready_ms", a->outcome.ready_ms);
        (void)json_push_kv_str(d, "ready_basis", a->entry.ready_marker[0] ? "marker" : "alive");
        return;
    }
    if (a->outcome.exited) {
        (void)json_push_kv_int(d, "exit_code", a->outcome.exit_code);
        (void)json_push_kv_int(d, "signal", a->outcome.term_signal);
    }
    char tail[APP_LAUNCH_TAIL_MAX];
    app_proc_log_tail(a->log, tail, sizeof(tail));
    (void)json_push_kv_str(d, "log_tail", tail);
    const char *code = a->outcome.exited ? "EXITED_EARLY" : "NOT_READY";
    zcl_command_reply_fail(a->reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                           code, "open", false, true,
                           a->outcome.exited ? "the app exited before it was ready" : "the app is still running but was not ready in time", a->log);
    as_failure_facts(a);
}

static void as_cleanup(struct as_open *a)
{
    if (a->scratch[0]) (void)zcl_tree_remove(a->scratch);
    zcl_package_copy_close(&a->copy);
    free(a);
}

static bool as_validated(struct as_open *a)
{
    return as_copy(a) && as_package(a) && as_record(a);
}

void zcl_native_handle_app_open_selected(const struct zcl_command_request *request,
                                         struct zcl_command_reply *reply)
{
    struct as_open *a = zcl_calloc(1, sizeof(*a), "app-open-selected");
    if (!a) { zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "cannot allocate selected app state", AS_COMMAND); return; }
    a->input = request->input; a->reply = reply;
    if (as_inputs(a) && as_catalog(a) && as_current_revision(a) &&
        as_validated(a) && as_desktop(a)) as_launch(a);
    as_cleanup(a);
}

static bool as_revision(struct as_open *a, uint64_t *out)
{
    const struct json_value *value = json_get(a->input, "expected_revision");
    if (!value || value->type != JSON_INT || json_get_int(value) < 0 || json_get_int(value) == INT64_MAX)
        return as_fail(a, "BAD_SELECTION_REVISION", "expected_revision must be a nonnegative, non-exhausted integer", AS_COMMAND);
    *out = (uint64_t)json_get_int(value);
    return true;
}

static bool as_make_selection(struct as_open *a, struct app_selection *s)
{
    memset(s, 0, sizeof(*s));
    if (strlen(a->copy_dir) >= sizeof(s->copy) || strlen(a->datadir) >= sizeof(s->datadir))
        return as_fail(a, "BAD_SELECTION", "copy or datadir path is too long", AS_COMMAND);
    (void)snprintf(s->app, sizeof(s->app), "%s", a->entry.id);
    (void)snprintf(s->copy, sizeof(s->copy), "%s", a->copy_dir);
    (void)snprintf(s->datadir, sizeof(s->datadir), "%s", a->datadir);
    memcpy(s->fork, a->copy.fork_version, 32); memcpy(s->parent, a->copy.parent_release, 32);
    memcpy(s->version, a->copy.selected_version, 32); memcpy(s->package, a->package, 32);
    memcpy(s->env, a->env, 32); memcpy(s->dependencies, a->deps, 32);
    memcpy(s->record, a->record_id, 32); memcpy(s->image, a->image_sha, 32);
    return true;
}

static void as_keep(struct as_open *a, uint64_t expected)
{
    struct resident_launch launch; resident_launch_init(&launch);
    struct zcl_result r = app_image_build_prepare(&a->record, a->image, &launch);
    resident_launch_close(&launch);
    if (!r.ok) { as_fail(a, "IMAGE_REFUSED", "the built image no longer matches its record", r.message); return; }
    if (!app_launch_state_dir_ready(a->env_cfg.state_dir)) { as_fail(a, "STATE_FAILED", "launcher state directory is unavailable", a->env_cfg.state_dir); return; }
    struct app_selection selection, saved;
    if (!as_make_selection(a, &selection)) return;
    enum app_selection_result result = app_selection_save(a->env_cfg.state_dir, expected, &selection, &saved);
    if (result != APP_SELECTION_OK) {
        if (result == APP_SELECTION_STALE)
            as_fail(a, "SELECTION_STALE", "kept selection changed; reload before retrying", a->entry.id);
        else
            zcl_package_copy_fail(a->reply, "SELECTION_WRITE_FAILED", true,
                "kept selection durability is unknown; reload before retrying", a->entry.id);
        return;
    }
    a->selection_revision = saved.revision;
    as_describe(a, &a->reply->data);
    (void)json_push_kv_str(&a->reply->data, "status", "kept");
}

void zcl_native_handle_app_keep(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    struct as_open *a = zcl_calloc(1, sizeof(*a), "app-keep");
    if (!a) { zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "cannot allocate app state", AS_COMMAND); return; }
    a->input = request->input; a->reply = reply;
    uint64_t expected = 0;
    if (as_inputs(a) && as_revision(a, &expected) && as_catalog(a) && as_validated(a)) as_keep(a, expected);
    as_cleanup(a);
}

static bool as_kept_input(struct as_open *a)
{
    const struct app_selection *s = &a->kept;
    (void)snprintf(a->copy_dir, sizeof(a->copy_dir), "%s", s->copy);
    (void)snprintf(a->datadir_real, sizeof(a->datadir_real), "%s", s->datadir);
    a->datadir = a->datadir_real;
    zcl_hex_encode(s->version, 32, a->version_hex); a->version = a->version_hex;
    memcpy(a->env, s->env, 32); memcpy(a->deps, s->dependencies, 32);
    memcpy(a->record_id, s->record, 32); memcpy(a->image_sha, s->image, 32);
    a->selection_revision = s->revision;
    return true;
}

/* 0 permits legacy fallback; 1 is a handled refusal; 2 has a descriptor. */
static int as_kept_catalog(struct as_open *a)
{
    if (app_selection_route_reserved(a->name)) return as_catalog(a) ? 2 : 1;
    char why[256] = {0};
    if (!app_launch_env_from_process(&a->env_cfg, why, sizeof(why))) {
        as_fail(a, "STATE_FAILED", "desktop launcher state is unavailable", why); return 1;
    }
    app_launch_registry_load(&a->env_cfg, &a->registry);
    if (a->registry.config_error[0]) {
        as_fail(a, "CONFIG_REFUSED", "the app catalog is unsafe or malformed", a->registry.config_error);
        return 1;
    }
    const struct app_launch_entry *entry = app_launch_registry_find(&a->registry, a->name);
    if (!entry) return 0;
    a->entry = *entry;
    return 2;
}
static int as_kept_load(struct as_open *a)
{
    enum app_selection_result loaded = app_selection_load(a->env_cfg.state_dir, a->entry.id, &a->kept);
    if (loaded == APP_SELECTION_ABSENT) {
        if (!app_selection_route_reserved(a->name)) return 0;
        as_fail(a, "SELECTION_REQUIRED", "this kept route has no saved selection", a->name);
        return 1;
    }
    if (loaded != APP_SELECTION_OK) {
        as_fail(a, "SELECTION_UNREADABLE", "kept selection cannot be read", a->entry.id); return 1;
    }
    if (a->kept.revision > INT64_MAX) {
        as_fail(a, "SELECTION_UNREADABLE", "selection revision is out of range", a->entry.id); return 1;
    }
    return 2;
}
static void as_kept_launch(struct as_open *a)
{
    (void)as_kept_input(a);
    if (as_validated(a)) {
        if (memcmp(a->copy.fork_version, a->kept.fork, 32) ||
            memcmp(a->copy.parent_release, a->kept.parent, 32) || memcmp(a->package, a->kept.package, 32))
            as_fail(a, "SELECTION_MISMATCH", "kept selection no longer matches its copy", a->entry.id);
        else if (as_desktop(a)) as_launch(a);
    }
}
/* Reserved routes are always handled, including missing/corrupt selections. */
bool zcl_native_app_open_kept(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply)
{
    struct as_open *a = zcl_calloc(1, sizeof(*a), "app-open-kept");
    if (!a) { zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "cannot allocate app state", AS_COMMAND); return true; }
    a->input = request->input; a->reply = reply;
    a->name = zcl_package_copy_str(a->input, "name");
    int state = as_kept_catalog(a);
    if (state == 2) state = as_kept_load(a);
    if (state == 2) as_kept_launch(a);
    as_cleanup(a);
    return state != 0;
}
