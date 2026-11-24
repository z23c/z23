/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: local task contents with durable confirmation and revision checks. */
#include "command/native_command.h"
#include "models/task_document.h"
#include "services/task_editor.h"
#include "services/task_list.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#include "platform/path_compat.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

enum { NTD_VERIFIER_MISSING = -31002 };
#if defined(ZCL_TESTING)
static _Thread_local bool ntd_force_verifier_missing;
void zcl_test_task_verifier_missing(bool missing);
void zcl_test_task_verifier_missing(bool missing) { ntd_force_verifier_missing = missing; }
#endif

static const char *ntd_string(const struct json_value *input, const char *key)
{
    const struct json_value *value = json_get(input, key);
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool ntd_integer(const struct json_value *input, const char *key, uint64_t *out)
{
    const struct json_value *value = json_get(input, key);
    if (!value || value->type != JSON_INT || json_get_int(value) < 0) return false;
    *out = (uint64_t)json_get_int(value);
    return true;
}

static struct zcl_result ntd_open(const struct json_value *input,
    struct package_resident_store *store, char directory[4096])
{
    static const char *const keys[] = { "datadir", "app", "action", "title",
        "preview_root", "preview_receipt", "preview_program" };
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); ++i) {
        const struct json_value *value = json_get(input, keys[i]);
        if (value && value->type != JSON_STR)
            return ZCL_ERR(-1, "tasks: %s must be text", keys[i]);
    }
    const char *selected = ntd_string(input, "datadir");
    const char *app = ntd_string(input, "app");
    if (!app) app = "local/tasks";
    if (selected) {
        if (!platform_path_is_absolute(selected) || strlen(selected) >= 4096)
            return ZCL_ERR(-1, "tasks: choose an absolute private data directory");
        (void)snprintf(directory, 4096, "%s", selected);
    } else if (!platform_application_state_root(directory, 4096)) {
        return ZCL_ERR(-1, "tasks: default private storage could not be opened; choose an absolute datadir");
    }
    char package_directory[4096];
    int n = snprintf(package_directory, sizeof(package_directory), "%s/zcode", directory);
    if (n < 0 || (size_t)n >= sizeof(package_directory))
        return ZCL_ERR(-1, "tasks: data directory is too long");
    if (!platform_private_directory_ensure(directory) ||
        !platform_private_directory_ensure(package_directory))
        return ZCL_ERR(-1, "tasks: private data directory could not be opened");
    return package_resident_store_open_task_app(store, directory, app);
}

static struct zcl_result ntd_candidate(const struct json_value *input,
    struct package_resident_identity *candidate)
{
    const char *root = ntd_string(input, "preview_root");
    const char *receipt = ntd_string(input, "preview_receipt");
    const char *program = ntd_string(input, "preview_program");
    if (root || receipt || program) {
        if (!root || !receipt || !program || strlen(root) != 64 || strlen(receipt) != 64 ||
            strlen(program) >= sizeof(candidate->program))
            return ZCL_ERR(-1, "tasks: select an exact installed preview program and receipt");
        (void)snprintf(candidate->package_root, sizeof(candidate->package_root), "%s", root);
        (void)snprintf(candidate->receipt_id, sizeof(candidate->receipt_id), "%s", receipt);
        (void)snprintf(candidate->program, sizeof(candidate->program), "%s", program);
    }
    return ZCL_OK;
}

static struct zcl_result ntd_missing_verifier(bool kept)
{
#if defined(_WIN32)
    (void)kept;
    return ZCL_ERR(NTD_VERIFIER_MISSING, "tasks: the confined package verifier is unavailable on Windows; your selection and tasks are unchanged");
#else
    return kept
        ? ZCL_ERR(NTD_VERIFIER_MISSING, "tasks: install the confined package verifier to reopen your kept program; your selection and tasks are unchanged")
        : ZCL_ERR(NTD_VERIFIER_MISSING, "tasks: install the confined package verifier before previewing");
#endif
}

static bool ntd_find_companion(const char *directory, char verifier[4096])
{
    const char *names[] = { "z23-package-verify-dev", "z23-package-verify",
                            "zclassic23-package-verify-dev", "zclassic23-package-verify" };
    for (unsigned i = 0; i < 4; ++i) {
        int n = snprintf(verifier, 4096, "%s/%s", directory, names[i]);
        if (n > 0 && n < 4096 && access(verifier, X_OK) == 0) return true;
    }
    return false;
}

#if defined(ZCL_TESTING)
bool zcl_test_task_find_companion(const char *directory, char verifier[4096]);
bool zcl_test_task_find_companion(const char *directory, char verifier[4096])
{ return ntd_find_companion(directory, verifier); }
#endif

static struct zcl_result ntd_verifier(const struct package_resident_record *record,
    const struct package_resident_identity *candidate, char verifier[4096])
{
#if defined(_WIN32)
    if (record->current.package_root[0] || candidate->package_root[0])
        return ntd_missing_verifier(record->current.package_root[0] != 0);
#endif
    char executable[4096];
    if (!os_proc_exe_path(executable, sizeof(executable)))
        return ZCL_ERR(-1, "tasks: cannot find the application executable");
    char *slash = strrchr(executable, '/');
    if (!slash) return ZCL_ERR(-1, "tasks: cannot find the verifier directory");
    *slash = 0;
    bool found = ntd_find_companion(executable, verifier);
#if defined(ZCL_TESTING)
    if (ntd_force_verifier_missing) found = false;
#endif
    if (!found && record->current.package_root[0])
        return ntd_missing_verifier(true);
    if (!found && candidate->package_root[0])
        return ntd_missing_verifier(false);
    if (!found) {
        int n = snprintf(verifier, 4096, "%s/z23-package-verify", executable);
        if (n < 0 || n >= 4096) return ZCL_ERR(-1, "tasks: verifier path is too long");
    }
    return ZCL_OK;
}

static struct zcl_result ntd_task_window(const struct json_value *input,
    struct package_resident_store *store, struct task_editor *editor)
{
    struct package_resident_identity candidate = {0};
    ZCL_CHECK(ntd_candidate(input, &candidate));
    struct package_resident_record record;
    ZCL_CHECK(package_resident_record_read(store, &record));
    char verifier[4096];
    ZCL_CHECK(ntd_verifier(&record, &candidate, verifier));
    struct task_update update;
    ZCL_CHECK(task_update_open(&update, editor->directory, editor->app, verifier, &candidate));
    ZCL_CHECK(task_update_check_offer(&update));
    if (record.current.package_root[0]) ZCL_CHECK(task_update_refresh(&update));
    return task_list_window_run_update(editor, &update);
}

static struct zcl_result ntd_editor(const struct json_value *input,
    struct package_resident_store *store, const char *directory, bool new_task, struct task_document *row)
{
    struct task_editor editor = {0};
    ZCL_CHECK(task_editor_open(&editor, directory, store->app));
    if (!new_task && !json_get(input, "task_id")) {
        ZCL_CHECK(ntd_task_window(input, store, &editor));
        *row = editor.saved;
        return ZCL_OK;
    }
    uint64_t id = 0;
    if (!new_task) {
        if (json_get(input, "task_id")) {
            if (!ntd_integer(input, "task_id", &id))
                return ZCL_ERR(-1, "tasks: choose a task ID");
        } else if (editor.saved.state.count) id = editor.saved.state.tasks[0].id;
    }
    ZCL_CHECK(task_editor_select(&editor, id));
    struct zcl_result result = task_editor_window_run(&editor);
    if (result.ok) *row = editor.saved;
    return result;
}

static bool ntd_interactive(const char *action)
{
    return action && (!strcmp(action, "open") || !strcmp(action, "new"));
}

static struct zcl_result ntd_change(const struct json_value *input,
    struct package_resident_store *store, const char *directory, struct task_document *row,
    bool *mutated)
{
    *mutated = false;
    const char *action = ntd_string(input, "action");
    if (!action || strcmp(action, "list") == 0) return task_document_read(store, row);
    if (ntd_interactive(action))
        return ntd_editor(input, store, directory, strcmp(action, "new") == 0, row);
    static const char *const actions[] = { "add", "edit", "complete", "reopen", "delete", "undo" };
    size_t selected = 0;
    while (selected < sizeof(actions)/sizeof(actions[0]) && strcmp(action, actions[selected]) != 0)
        ++selected;
    if (selected == sizeof(actions)/sizeof(actions[0]))
        return ZCL_ERR(-1, "tasks: unknown action");
    uint64_t revision, id = 0;
    if (!ntd_integer(input, "expected_revision", &revision))
        return ZCL_ERR(-1, "tasks: saving requires the revision you edited");
    if (selected != TASK_DOCUMENT_ADD && selected != TASK_DOCUMENT_UNDO &&
        !ntd_integer(input, "task_id", &id))
        return ZCL_ERR(-1, "tasks: choose a task ID");
    struct zcl_result result = task_document_apply(store, revision,
        (enum task_document_action)selected, id, ntd_string(input, "title"), row);
    if (result.ok) *mutated = true;
    return result;
}

static bool ntd_render(struct json_value *data, const struct task_document *row,
                        int64_t elapsed, const char *directory, const char *action)
{
    json_set_object(data);
    if (!json_push_kv_str(data, "data_directory", directory) ||
        !json_push_kv_str(data, "save_state", "Saved") ||
        !json_push_kv_int(data, "revision", (int64_t)row->state.revision) ||
        !json_push_kv_bool(data, "can_undo", row->can_undo) ||
        !json_push_kv_int(data, "operation_us", elapsed)) return false;
    /* The legacy noninteractive duration includes open/read-or-write/close.
     * A window's lifetime includes user interaction, not storage latency. */
    if (!ntd_interactive(action) && !json_push_kv_int(data, "storage_us", elapsed)) return false;
    struct json_value tasks = {0};
    json_set_array(&tasks);
    bool ok = true;
    for (uint32_t i = 0; ok && i < row->state.count; ++i) {
        const struct ta_task *task = &row->state.tasks[i];
        struct json_value item = {0};
        json_set_object(&item);
        ok = json_push_kv_int(&item, "id", (int64_t)task->id) &&
            json_push_kv_str(&item, "title", task->title) &&
            json_push_kv_bool(&item, "done", task->done != 0) && json_push_back(&tasks, &item);
        json_free(&item);
    }
    if (ok) ok = json_push_kv(data, "tasks", &tasks);
    json_free(&tasks);
    return ok;
}

static struct zcl_result ntd_offer(const struct json_value *input,
    struct package_resident_store *store, const char *directory, struct task_update_offer *out)
{
    if (strcmp(ntd_string(input, "action"), "offer-status") == 0)
        return task_update_offer_read(store, out);
    uint64_t revision;
    if (!ntd_integer(input, "expected_offer_revision", &revision))
        return ZCL_ERR(-1, "tasks: read offer-status and supply expected_offer_revision");
    struct package_resident_identity candidate = {0};
    ZCL_CHECK(ntd_candidate(input, &candidate));
    return task_update_offer_submit(store, directory, (int64_t)revision, &candidate, out);
}

/* Offering software does not disclose the user's task contents to the AI. */
static bool ntd_offer_render(struct json_value *data, const struct task_update_offer *offer,
    const char *directory, const struct package_resident_record *kept)
{
    json_set_object(data);
    return json_push_kv_str(data, "data_directory", directory) &&
        json_push_kv_bool(data, "has_kept_program", kept->generation > 0) &&
        json_push_kv_int(data, "kept_generation", kept->generation) &&
        json_push_kv_str(data, "kept_root", kept->current.package_root) &&
        json_push_kv_str(data, "kept_receipt", kept->current.receipt_id) &&
        json_push_kv_str(data, "kept_program", kept->current.program) &&
        json_push_kv_str(data, "kept_artifact_sha3", kept->current.artifact_sha3) &&
        json_push_kv_int(data, "kept_configuration_generation", kept->current.configuration_generation) &&
        json_push_kv_int(data, "offer_revision", offer->revision) &&
        json_push_kv_bool(data, "dismissed", offer->dismissed) &&
        json_push_kv_str(data, "preview_root", offer->candidate.package_root) &&
        json_push_kv_str(data, "preview_receipt", offer->candidate.receipt_id) &&
        json_push_kv_str(data, "preview_program", offer->candidate.program) &&
        json_push_kv_str(data, "artifact_sha3", offer->candidate.artifact_sha3) &&
        json_push_kv_str(data, "next_action", "In Tasks, choose More / Undo, then Updates. Try update asks permission before running.");
}

static void ntd_source_next(struct zcl_command_reply *reply, const char *directory,
    const struct package_resident_record *kept, const char *action, bool succeeded)
{
    if (!succeeded || !action || strcmp(action, "offer-status") ||
        kept->generation <= 0 || !kept->current.package_root[0]) return;
    struct json_value next_args; json_init(&next_args); json_set_object(&next_args);
    bool ok = json_push_kv_str(&next_args, "root", kept->current.package_root) &&
        json_push_kv_str(&next_args, "datadir", directory);
    char wire[sizeof(reply->next[0].input_json)];
    size_t n = ok ? json_write(&next_args, wire, sizeof(wire)) : 0;
    if (n && n < 384 && n < sizeof(wire) && !strchr(wire, '\''))
        (void)zcl_command_reply_add_next(reply, "zcode.package.checkout", wire,
            "Choose an absent destination to inspect the exact kept source without executing it.");
    json_free(&next_args);
}

static void ntd_stale_recovery(struct zcl_command_reply *reply,
    const struct json_value *input, const char *directory)
{
    const char *app = ntd_string(input, "app");
    if (!app) app = "local/tasks";
    struct json_value next; json_init(&next); json_set_object(&next);
    bool ok = json_push_kv_str(&next, "action", "list") &&
        json_push_kv_str(&next, "app", app) && json_push_kv_str(&next, "datadir", directory);
    char wire[sizeof(reply->next[0].input_json)]; size_t n = ok ? json_write(&next, wire, sizeof(wire)) : 0;
    struct json_value facts; json_init(&facts); json_set_object(&facts);
    bool safe = n && n < 384 && n < sizeof(wire) && !strchr(wire, '\'');
    bool bound = safe && json_push_kv_str(&facts, "kind", "task-stale-reload") &&
        json_push_kv_str(&facts, "app", app) &&
        json_push_kv_str(&facts, "datadir", directory) &&
        json_push_kv(&reply->data, "failure_facts", &facts);
    bool added = bound && zcl_command_reply_add_next(reply, "app.tasks", wire,
        "Reload the current tasks in this same document before saving.");
    json_free(&facts);
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action), "%s", added ?
        "Reload the current tasks using the next command before saving." :
        "Reload with app.tasks action list using the same app and datadir.");
    json_free(&next);
}

static void ntd_failure(struct zcl_command_reply *reply, const struct json_value *input,
    const char *directory, bool offering, bool mutated, struct zcl_result result)
{
    LOG_ERROR("app.tasks", "%s", result.message);
    bool verifier_missing = result.code == NTD_VERIFIER_MISSING;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
        verifier_missing ? "TASK_VERIFIER_UNAVAILABLE" : "TASK_SAVE_FAILED",
        verifier_missing ? "open" : "save", false, mutated, result.message, "app.tasks");
    if (verifier_missing) {
        reply->error.human_action_required = true;
#if defined(_WIN32)
        (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
            "Open the kept program on a supported Linux or macOS Z23 installation.");
#else
        (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
            "Reinstall the matching package verifier (z23-package-verify) alongside Z23, then reopen Tasks.");
#endif
    } else if (!offering && result.code == TASK_DOCUMENT_STALE)
        ntd_stale_recovery(reply, input, directory);
}

void zcl_native_handle_task_document(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    int64_t began = platform_time_monotonic_us();
    struct package_resident_store store = {0};
    struct task_document row;
    struct task_update_offer offer = {0};
    struct package_resident_record kept = {0};
    const char *action = ntd_string(request->input, "action");
    bool offering = action && (strcmp(action, "offer") == 0 || strcmp(action, "offer-status") == 0);
    char directory[4096];
    bool mutated = false;
    struct zcl_result result = ntd_open(request->input, &store, directory);
    if (result.ok && offering) result = package_resident_record_read(&store, &kept);
    if (result.ok) result = offering ? ntd_offer(request->input, &store, directory, &offer)
        : ntd_change(request->input, &store, directory, &row, &mutated);
    struct zcl_result closed = package_resident_store_close(&store);
    if (result.ok && !closed.ok) result = closed;
    if (result.ok) {
        bool rendered = offering ? ntd_offer_render(&reply->data, &offer, directory, &kept)
            : ntd_render(&reply->data, &row, platform_time_monotonic_us() - began, directory, action);
        if (!rendered) result = ZCL_ERR(-1, "tasks: operation completed but confirmation allocation failed; read status before retrying");
    }
    ntd_source_next(reply, directory, &kept, action, result.ok);
    if (!result.ok) ntd_failure(reply, request->input, directory, offering, mutated, result);
}
