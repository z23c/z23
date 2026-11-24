/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: prove task contents survive restart, undo and failed commits. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"
#include "base/safe_alloc.h"
#include "models/task_document.h"
#include "config/command_catalog.h"
#include "platform/state_root.h"
#include "platform/path_compat.h"
#include "services/task_editor.h"
#include "services/task_list.h"
#include "platform/time_compat.h"
#include "platform/os_proc.h"
#include "util/thread_registry.h"
#include "presentation/model_render.h"
#include "../../../contexts/explorer/modules/presentation/src/presentation_form_internal.h"
#include "../../../contexts/explorer/modules/presentation/src/presentation_focus_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

void zcl_test_task_verifier_missing(bool missing);
bool zcl_test_task_find_companion(const char *directory, char verifier[4096]);

#define TD_CHECK(label, expression) do { \
    bool ok = (expression); \
    printf("task_document: %s... %s\n", label, ok ? "OK" : "FAIL"); \
    if (!ok) ++failures; \
} while (0)

static bool td_call(struct json_value *input, struct zcl_command_reply *reply)
{
    zcl_command_reply_init(reply, "zcl.task_document.v1");
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), "app.tasks", NULL);
    if (!spec) return false;
    struct zcl_command_request request = {.spec = spec, .input = input};
    char why[256];
    if (!zcl_command_registry_input_validate(spec, input, why, sizeof(why))) return false;
    spec->handler(&request, reply); return true;
}

static int td_confirmation_fault(const char *directory)
{
    int failures = 0;
    struct json_value input; json_init(&input); json_set_object(&input);
    bool built = json_push_kv_str(&input, "datadir", directory) &&
        json_push_kv_str(&input, "app", "local/confirmation-fault") &&
        json_push_kv_str(&input, "action", "add") &&
        json_push_kv_str(&input, "title", "Persisted before confirmation") &&
        json_push_kv_int(&input, "expected_revision", 0);
    struct zcl_command_reply reply = {0};
    zcl_alloc_fault_fail_next("json_push_kv_key");
    bool called = built && td_call(&input, &reply);
    zcl_alloc_fault_clear();
    TD_CHECK("confirmation fault is reported after the operation", called &&
        reply.status == ZCL_COMMAND_STATUS_FAILED &&
        strstr(reply.error.message, "operation completed but confirmation") != NULL);
    struct package_resident_store store = {0};
    struct task_document row = {0};
    bool opened = package_resident_store_open_task_app(&store, directory, "local/confirmation-fault").ok;
    TD_CHECK("confirmation fault leaves the exact new task durable", opened &&
        task_document_read(&store, &row).ok && row.state.revision == 1 && row.state.count == 1 &&
        strcmp(row.state.tasks[0].title, "Persisted before confirmation") == 0);
    TD_CHECK("confirmation fault admits the completed mutation", called && reply.error.mutated);
    if (store.db) TD_CHECK("confirmation fault store closes", package_resident_store_close(&store).ok);
    zcl_command_reply_free(&reply);
    called = built && td_call(&input, &reply);
    TD_CHECK("stale write refuses before mutation", called &&
        reply.status == ZCL_COMMAND_STATUS_FAILED && !reply.error.mutated);
    zcl_command_reply_free(&reply); json_free(&input);
    json_init(&input); json_set_object(&input);
    built = json_push_kv_str(&input, "datadir", directory) &&
        json_push_kv_str(&input, "app", "local/confirmation-fault") &&
        json_push_kv_str(&input, "action", "list");
    zcl_alloc_fault_fail_next("json_push_kv_key");
    called = built && td_call(&input, &reply);
    zcl_alloc_fault_clear();
    TD_CHECK("read-only confirmation fault reports no mutation", called &&
        reply.status == ZCL_COMMAND_STATUS_FAILED && !reply.error.mutated &&
        strstr(reply.error.message, "operation completed but confirmation") != NULL);
    zcl_command_reply_free(&reply); json_free(&input);
    return failures;
}
static bool td_verifier_reply_ok(const struct zcl_command_reply *reply)
{
    return reply->status == ZCL_COMMAND_STATUS_FAILED &&
        strcmp(reply->error.code, "TASK_VERIFIER_UNAVAILABLE") == 0 &&
        strcmp(reply->error.phase, "open") == 0 && !reply->error.mutated &&
        reply->error.human_action_required && strstr(reply->error.next_action, "matching") != NULL &&
        strstr(reply->error.next_action, "z23-package-verify") != NULL;
}
static bool td_verifier_state_unchanged(struct package_resident_store *store,
    const struct task_document *before, const struct package_resident_record *old)
{
    struct task_document after = {0}; struct package_resident_record now = {0};
    return task_document_read(store, &after).ok && package_resident_record_read(store, &now).ok &&
        before->state.revision == after.state.revision && before->state.count == after.state.count &&
        old->generation == now.generation && package_resident_identity_equal(&old->current, &now.current);
}

static int td_verifier_discovery(const char *directory)
{
    int failures = 0;
    char folder[4096], path[4096], found[4096];
    int n = snprintf(folder, sizeof(folder), "%s/verifier-discovery", directory);
    TD_CHECK("verifier fixture path", n > 0 && (size_t)n < sizeof(folder));
    if (n <= 0 || (size_t)n >= sizeof(folder) || mkdir(folder, 0700) != 0) return failures + 1;
    n = snprintf(path, sizeof(path), "%s/z23-package-verify", folder);
    TD_CHECK("verifier path", n > 0 && (size_t)n < sizeof(path));
    if (n <= 0 || (size_t)n >= sizeof(path)) { (void)rmdir(folder); return failures + 1; }
    TD_CHECK("missing companion is not found", !zcl_test_task_find_companion(folder, found));
    FILE *f = fopen(path, "wb");
    bool created = f && fclose(f) == 0 && chmod(path, 0700) == 0;
    TD_CHECK("executable companion is found", created && zcl_test_task_find_companion(folder, found) && !strcmp(path, found));
    TD_CHECK("verifier discovery fixture removed", unlink(path) == 0 && rmdir(folder) == 0);
    return failures;
}

static int td_verifier_refusal(struct package_resident_store *store, const char *directory)
{
    int failures = 0;
    struct task_document before = {0};
    struct package_resident_record old = {0};
    TD_CHECK("verifier fixture initial state", task_document_read(store, &before).ok &&
        package_resident_record_read(store, &old).ok);
    struct json_value input = {0}; json_set_object(&input);
    const char *root = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    bool built = json_push_kv_str(&input, "datadir", directory) &&
        json_push_kv_str(&input, "action", "open") &&
        json_push_kv_str(&input, "preview_root", root) &&
        json_push_kv_str(&input, "preview_receipt", root) &&
        json_push_kv_str(&input, "preview_program", "bin/ztasks");
    struct zcl_command_reply reply = {0};
    zcl_test_task_verifier_missing(true);
    bool called = built && td_call(&input, &reply);
    zcl_test_task_verifier_missing(false);
    TD_CHECK("missing preview verifier has an actionable typed refusal", called && td_verifier_reply_ok(&reply));
    TD_CHECK("verifier refusal preserves tasks and selection", td_verifier_state_unchanged(store, &before, &old));
    zcl_command_reply_free(&reply); json_free(&input);
    return failures;
}

static bool td_noninteractive_timing(const struct json_value *data)
{
    const struct json_value *operation = json_get(data, "operation_us");
    const struct json_value *storage = json_get(data, "storage_us");
    return operation && operation->type == JSON_INT && storage && storage->type == JSON_INT &&
        json_get_int(operation) >= 0 && json_get_int(operation) == json_get_int(storage);
}

static bool td_default_call(const char *body, bool success, int64_t revision, const char *title)
{
    struct json_value input = {0};
    struct zcl_command_reply reply = {0};
    bool ok = json_read(&input, body, strlen(body)) && td_call(&input, &reply);
    ok = ok && ((reply.exit_code == 0) == success);
    if (ok && success) {
        const struct json_value *tasks = json_get(&reply.data, "tasks");
        const char *saved = json_get_str(json_get(&reply.data, "save_state"));
        const char *actual = json_get_str(json_get(json_at(tasks, 0), "title"));
        ok = saved && strcmp(saved, "Saved") == 0 &&
            td_noninteractive_timing(&reply.data) &&
            json_get_int(json_get(&reply.data, "revision")) == revision &&
            (title ? actual && strcmp(title, actual) == 0 : json_size(tasks) == 0);
    }
    zcl_command_reply_free(&reply);
    json_free(&input);
    return ok;
}

static bool td_reload_content(const struct zcl_command_reply *reply)
{
    const struct json_value *tasks = json_get(&reply->data, "tasks");
    const char *title = json_get_str(json_get(json_at(tasks, 0), "title"));
    return reply->status == ZCL_COMMAND_STATUS_PASSED &&
        json_get_int(json_get(&reply->data, "revision")) == 1 &&
        json_get_bool(json_get(&reply->data, "can_undo")) && title && !strcmp(title, "Winner");
}
static bool td_reload_check(struct zcl_command_reply *stale, const char *directory)
{
    if (stale->status == ZCL_COMMAND_STATUS_PASSED || stale->error.mutated ||
        strcmp(stale->error.code, "TASK_SAVE_FAILED") || stale->next_count != 1 ||
        strcmp(stale->next[0].command, "app.tasks")) return false;
    struct json_value input = {0};
    bool ok = json_read(&input, stale->next[0].input_json, strlen(stale->next[0].input_json));
    const char *app = json_get_str(json_get(&input, "app"));
    const char *dir = json_get_str(json_get(&input, "datadir"));
    const char *action = json_get_str(json_get(&input, "action"));
    ok = ok && app && !strcmp(app, "local/reload") && dir && !strcmp(dir, directory) &&
        action && !strcmp(action, "list");
    struct zcl_command_reply reply = {0};
    if (ok) ok = td_call(&input, &reply);
    if (ok) ok = td_reload_content(&reply);
    zcl_command_reply_free(&reply); json_free(&input); return ok;
}
static bool td_public_call(const struct json_value *input, struct json_value *out)
{
    json_set_null(out);
    const struct zcl_command_registry *registry = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(registry, "app.tasks", NULL);
    if (!spec) return false;
    struct zcl_command_context context = {.registry = registry, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    char wire[8192]; enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t n = zcl_command_registry_execute_json(registry, spec, &context, input, false,
        spec->path, "normal", 0, 0, NULL, wire, sizeof(wire), &code);
    return n && n < sizeof(wire) && json_read(out, wire, n);
}
static bool td_json_text(const struct json_value *object, const char *key, const char *expected)
{
    const char *actual = json_get_str(json_get(object, key));
    return actual && !strcmp(actual, expected);
}
static bool td_public_stale(struct json_value *input, const char *directory)
{
    struct json_value result = {0}, replay = {0};
    bool ok = td_public_call(input, &result);
    const struct json_value *error = json_get(&result, "error");
    const char *code = json_get_str(json_get(error, "code"));
    const struct json_value *next = json_at(json_get(&result, "next"), 0);
    const char *command = json_get_str(json_get(next, "command"));
    const struct json_value *next_input = json_get(next, "input");
    ok = ok && code && !strcmp(code, "TASK_SAVE_FAILED") && command && !strcmp(command, "app.tasks") &&
        next_input && td_json_text(next_input, "datadir", directory) &&
        td_json_text(next_input, "app", "local/reload") && td_json_text(next_input, "action", "list");
    if (ok) ok = td_public_call(next_input, &replay);
    if (ok) {
        const struct json_value *data = json_get(&replay, "data");
        const char *title = json_get_str(json_get(json_at(json_get(data, "tasks"), 0), "title"));
        ok = json_get_bool(json_get(&replay, "ok")) && json_get_int(json_get(data, "revision")) == 1 &&
            json_get_bool(json_get(data, "can_undo")) && title && !strcmp(title, "Winner");
    }
    json_free(&replay); json_free(&result); return ok;
}
#if defined(ZCL_TESTING)
static bool td_forged_next(struct zcl_command_reply *reply, const char *directory,
                           const char *app, const char *action)
{
    struct json_value input = {0}; json_set_object(&input);
    bool ok = json_push_kv_str(&input, "app", app) && json_push_kv_str(&input, "datadir", directory) &&
        json_push_kv_str(&input, "action", action);
    char old[sizeof(reply->next[0].input_json)];
    (void)snprintf(old, sizeof(old), "%s", reply->next[0].input_json);
    size_t n = ok ? json_write(&input, reply->next[0].input_json, sizeof(reply->next[0].input_json)) : 0;
    const struct zcl_command_registry *registry = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(registry, "app.tasks", NULL);
    char wire[8192];
    size_t len = n && spec ? zcl_command_registry_test_reply_wire(registry, spec, reply, wire, sizeof(wire)) : 0;
    ok = n && spec && len == 0;
    (void)snprintf(reply->next[0].input_json, sizeof(reply->next[0].input_json), "%s", old);
    json_free(&input); return ok;
}
static bool td_forged_reply(struct zcl_command_reply *reply)
{
    const struct zcl_command_registry *registry = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(registry, "app.tasks", NULL);
    char wire[8192], code[sizeof(reply->error.code)];
    (void)snprintf(code, sizeof(code), "%s", reply->error.code);
    reply->error.mutated = true;
    bool ok = spec && !zcl_command_registry_test_reply_wire(registry, spec, reply, wire, sizeof(wire));
    reply->error.mutated = false;
    (void)snprintf(reply->error.code, sizeof(reply->error.code), "%s", "OTHER_FAILURE");
    ok = ok && !zcl_command_registry_test_reply_wire(registry, spec, reply, wire, sizeof(wire));
    (void)snprintf(reply->error.code, sizeof(reply->error.code), "%s", code);
    return ok;
}
static bool td_forged_checks(struct zcl_command_reply *reply, const char *directory)
{
    char alternate[4096];
    int n = snprintf(alternate, sizeof(alternate), "%s/other", directory);
    return n > 0 && (size_t)n < sizeof(alternate) && td_forged_reply(reply) &&
        td_forged_next(reply, directory, "local/other", "list") &&
        td_forged_next(reply, directory, "local/reload", "delete") &&
        td_forged_next(reply, alternate, "local/reload", "list");
}
#else
static bool td_forged_checks(struct zcl_command_reply *reply, const char *directory)
{
    (void)reply; (void)directory; return true;
}
#endif
static bool td_reload_request(const char *directory, int64_t expected, bool stale)
{
    struct json_value input = {0}; json_set_object(&input);
    bool ok = json_push_kv_str(&input, "datadir", directory) && json_push_kv_str(&input, "app", "local/reload") &&
        json_push_kv_str(&input, "action", "add") && json_push_kv_str(&input, "title", "Loser") &&
        json_push_kv_int(&input, "expected_revision", expected);
    struct zcl_command_reply reply = {0};
    if (ok) ok = td_call(&input, &reply);
    if (ok && stale) ok = td_reload_check(&reply, directory) && td_public_stale(&input, directory) &&
        td_forged_checks(&reply, directory);
    else if (ok) ok = reply.status != ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated && reply.next_count == 0;
    zcl_command_reply_free(&reply); json_free(&input); return ok;
}
static bool td_unrelated_request(const char *directory)
{
    struct json_value input = {0}; json_set_object(&input);
    bool ok = json_push_kv_str(&input, "datadir", directory) && json_push_kv_str(&input, "app", "local/reload") &&
        json_push_kv_str(&input, "action", "delete") && json_push_kv_int(&input, "task_id", 999) &&
        json_push_kv_int(&input, "expected_revision", 1);
    struct zcl_command_reply reply = {0};
    if (ok) ok = td_call(&input, &reply);
    ok = ok && reply.status != ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated && reply.next_count == 0;
    zcl_command_reply_free(&reply); json_free(&input); return ok;
}
static bool td_remove_reload_fixture(const char *path)
{
    char db[4096], zcode[4096];
    int a = snprintf(db, sizeof(db), "%s/zcode/resident.db", path);
    int b = snprintf(zcode, sizeof(zcode), "%s/zcode", path);
    return a > 0 && (size_t)a < sizeof(db) && b > 0 && (size_t)b < sizeof(zcode) &&
        unlink(db) == 0 && rmdir(zcode) == 0 && rmdir(path) == 0;
}
static bool td_long_stale(const char *directory)
{
    char path[4096], part[181], app[202];
    memset(part, '\"', sizeof(part) - 1); part[sizeof(part) - 1] = 0;
    memset(app, 'a', sizeof(app) - 1); app[100] = '/'; app[sizeof(app) - 1] = 0;
    int n = snprintf(path, sizeof(path), "%s/%s", directory, part);
    if (n < 0 || (size_t)n >= sizeof(path) || mkdir(path, 0700)) return false;
    struct json_value input = {0}; json_set_object(&input);
    bool ok = json_push_kv_str(&input, "datadir", path) && json_push_kv_str(&input, "app", app) &&
        json_push_kv_str(&input, "action", "add") && json_push_kv_str(&input, "title", "One") &&
        json_push_kv_int(&input, "expected_revision", 1);
    struct zcl_command_reply reply = {0};
    if (ok) ok = td_call(&input, &reply);
    ok = ok && reply.status != ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated && reply.next_count == 0 &&
        strstr(reply.error.next_action, "same app and datadir");
    zcl_command_reply_free(&reply); json_free(&input);
    bool removed = td_remove_reload_fixture(path);
    return ok && removed;
}
static int td_stale_reload(const char *directory)
{
    int failures = 0; char path[4096];
    int n = snprintf(path, sizeof(path), "%s/reload \"profile\\name", directory);
    if (n < 0 || (size_t)n >= sizeof(path) || mkdir(path, 0700)) return 1;
    struct json_value input = {0}; json_set_object(&input);
    bool seeded = json_push_kv_str(&input, "datadir", path) && json_push_kv_str(&input, "app", "local/reload") &&
        json_push_kv_str(&input, "action", "add") && json_push_kv_str(&input, "title", "Winner") &&
        json_push_kv_int(&input, "expected_revision", 0);
    struct zcl_command_reply reply = {0};
    if (seeded) seeded = td_call(&input, &reply) && reply.status == ZCL_COMMAND_STATUS_PASSED;
    zcl_command_reply_free(&reply); json_free(&input);
    TD_CHECK("stale next reloads same escaped directory and namespace without losing Undo", seeded && td_reload_request(path, 0, true));
    TD_CHECK("exhausted revision has no stale recovery action", td_reload_request(path, INT64_MAX, false));
    TD_CHECK("unrelated failure has no stale recovery action", td_unrelated_request(path));
    TD_CHECK("oversized reload action is never truncated", td_long_stale(directory));
    TD_CHECK("reload fixture removed", td_remove_reload_fixture(path));
    return failures;
}

static int td_default_storage(const char *directory)
{
    int failures = 0;
    const char *prior = getenv("XDG_STATE_HOME");
    char *saved = prior ? strdup(prior) : NULL;
    if (prior && !saved) { perror("task_document: preserve state root"); return 1; }
    char base[4096], path[4096], root[4096];
    if (!platform_path_identity(root, sizeof(root), directory)) {
        free(saved); fprintf(stderr, "task_document: fixture identity unavailable\n"); return 1;
    }
    (void)snprintf(base, sizeof(base), "%s/default-storage", root);
    if (setenv("XDG_STATE_HOME", base, 1) != 0) { free(saved); perror("task_document: isolate state root"); return 1; }
    TD_CHECK("first launch needs no storage setup", td_default_call("{}", true, 0, NULL));
    TD_CHECK("first task saves without a datadir", td_default_call(
        "{\"action\":\"add\",\"expected_revision\":0,\"title\":\"First task\"}", true, 1, "First task"));
    TD_CHECK("edit saved in default storage", td_default_call(
        "{\"action\":\"edit\",\"expected_revision\":1,\"task_id\":1,\"title\":\"Exact edited contents!\"}", true, 2, "Exact edited contents!"));
    TD_CHECK("reopen uses the same durable contents", td_default_call("{}", true, 2, "Exact edited contents!"));
    TD_CHECK("default storage still refuses stale writes", td_default_call(
        "{\"action\":\"edit\",\"expected_revision\":1,\"task_id\":1,\"title\":\"Old edit\"}", false, 0, NULL));
    TD_CHECK("explicit relative directory never falls back", td_default_call(
        "{\"datadir\":\"relative\"}", false, 0, NULL));
    TD_CHECK("delete in default storage", td_default_call(
        "{\"action\":\"delete\",\"expected_revision\":2,\"task_id\":1}", true, 3, NULL));
    TD_CHECK("undo survives reopening default storage", td_default_call(
        "{\"action\":\"undo\",\"expected_revision\":3}", true, 4, "Exact edited contents!"));
    TD_CHECK("undo result survives another reopen", td_default_call("{}", true, 4, "Exact edited contents!"));
    struct stat info;
    bool resolved = platform_application_state_root(root, sizeof(root));
    TD_CHECK("default directory is owner private", resolved && stat(root, &info) == 0 && (info.st_mode & 077) == 0);
    (void)snprintf(path, sizeof(path), "%s/z23/dev", base);
    TD_CHECK("first task does not create developer state", access(path, F_OK) != 0);
    (void)snprintf(path, sizeof(path), "%s/z23/apps/zcode/resident.db", base);
    TD_CHECK("default fixture database removed", unlink(path) == 0);
    (void)snprintf(path, sizeof(path), "%s/z23/apps/zcode", base);
    TD_CHECK("default fixture package directory removed", rmdir(path) == 0);
    (void)snprintf(path, sizeof(path), "%s/z23/apps", base);
    TD_CHECK("default fixture app directory removed", rmdir(path) == 0);
    TD_CHECK("symlinked default root refuses", symlink(directory, path) == 0 && !platform_application_state_root(root, sizeof(root)));
    TD_CHECK("fixture link removed", unlink(path) == 0);
    (void)snprintf(path, sizeof(path), "%s/z23", base);
    TD_CHECK("default fixture parents removed", rmdir(path) == 0 && rmdir(base) == 0);
    TD_CHECK("relative default base refuses", setenv("XDG_STATE_HOME", "relative-state", 1) == 0 &&
        !platform_application_state_root(root, sizeof(root)));
    int restored = saved ? setenv("XDG_STATE_HOME", saved, 1) : unsetenv("XDG_STATE_HOME");
    TD_CHECK("caller state root restored", restored == 0);
    free(saved);
    return failures;
}

static int td_refuse_commit(void *context) { (void)context; return 1; }

static int td_actions(struct package_resident_store *store, struct task_document *row)
{
    int failures = 0;
    TD_CHECK("empty document", task_document_read(store, row).ok && row->state.count == 0);
    TD_CHECK("add durable task", task_document_apply(store, 0, TASK_DOCUMENT_ADD, 0,
        "Buy milk", row).ok && row->state.count == 1);
    uint64_t id = row->state.tasks[0].id;
    TD_CHECK("edit exact contents", task_document_apply(store, 1, TASK_DOCUMENT_EDIT, id,
        "Buy oat milk", row).ok && strcmp(row->state.tasks[0].title, "Buy oat milk") == 0);
    TD_CHECK("stale writer cannot overwrite", !task_document_apply(store, 1,
        TASK_DOCUMENT_EDIT, id, "stale", row).ok && row->state.revision == 2);
    TD_CHECK("complete", task_document_apply(store, 2, TASK_DOCUMENT_COMPLETE, id,
        NULL, row).ok && row->state.tasks[0].done == 1);
    TD_CHECK("saving the same title preserves undo", task_document_apply(store, 3,
        TASK_DOCUMENT_EDIT, id, "Buy oat milk", row).ok && row->state.revision == 3 && row->can_undo);
    TD_CHECK("repeating completion preserves undo", task_document_apply(store, 3,
        TASK_DOCUMENT_COMPLETE, id, NULL, row).ok && row->state.revision == 3);
    TD_CHECK("undo completion", task_document_apply(store, 3, TASK_DOCUMENT_UNDO, 0,
        NULL, row).ok && row->state.tasks[0].done == 0);
    TD_CHECK("delete", task_document_apply(store, 4, TASK_DOCUMENT_DELETE, id,
        NULL, row).ok && row->state.count == 0);
    return failures;
}

static int td_restart(struct package_resident_store *store,
    const char *directory, struct task_document *row)
{
    int failures = 0;
    TD_CHECK("close database", package_resident_store_close(store).ok);
    TD_CHECK("reopen same app", package_resident_store_open_app(store, directory, "local/tasks").ok);
    TD_CHECK("deletion and undo survive restart", task_document_read(store, row).ok &&
        row->state.count == 0 && row->can_undo);
    TD_CHECK("undo restores exact edited contents", task_document_apply(store, 5,
        TASK_DOCUMENT_UNDO, 0, NULL, row).ok && row->state.count == 1 &&
        strcmp(row->state.tasks[0].title, "Buy oat milk") == 0 && row->state.revision == 6);
    TD_CHECK("consumed undo refuses", !task_document_apply(store, 6,
        TASK_DOCUMENT_UNDO, 0, NULL, row).ok);
    return failures;
}

static int td_failures(struct package_resident_store *store, struct task_document *row)
{
    int failures = 0;
    uint64_t id = row->state.tasks[0].id;
    int changed_before = sqlite3_total_changes(store->db);
    sqlite3_commit_hook(store->db, td_refuse_commit, NULL);
    TD_CHECK("failed durable commit is not success", !task_document_apply(store, 6,
        TASK_DOCUMENT_EDIT, id, "must not be Saved", row).ok);
    TD_CHECK("failure was injected after the actual write", sqlite3_total_changes(store->db) > changed_before);
    sqlite3_commit_hook(store->db, NULL, NULL);
    TD_CHECK("failure retains caller contents", row->state.revision == 6 &&
        strcmp(row->state.tasks[0].title, "Buy oat milk") == 0);
    TD_CHECK("failure retains database contents", task_document_read(store, row).ok &&
        row->state.revision == 6 && strcmp(row->state.tasks[0].title, "Buy oat milk") == 0);
    TD_CHECK("invalid title refuses without edits", !task_document_apply(store, 6,
        TASK_DOCUMENT_EDIT, id, "   ", row).ok && row->state.revision == 6);
    TD_CHECK("new edit after undo remains possible", task_document_apply(store, 6,
        TASK_DOCUMENT_ADD, 0, "Second task", row).ok && row->state.tasks[1].id == 7);
    return failures;
}

static int td_isolation(struct package_resident_store *store, const char *directory)
{
    int failures = 0;
    struct package_resident_store other = {0};
    struct task_document row = {0};
    TD_CHECK("another app opens", package_resident_store_open_app(&other, directory, "local/other").ok);
    TD_CHECK("app contents are isolated", task_document_read(&other, &row).ok && row.state.count == 0);
    TD_CHECK("other app closes", package_resident_store_close(&other).ok);
    TD_CHECK("unknown schema fixture", sqlite3_exec(store->db,
        "UPDATE task_documents SET payload=x'020000000000000000000000000000000000000000000000' WHERE app='local/tasks'",
        NULL, NULL, NULL) == SQLITE_OK);
    memset(&row, 0x55, sizeof(row));
    struct task_document before = row;
    TD_CHECK("incompatible data refuses and preserves output", !task_document_read(store, &row).ok &&
        memcmp(&row, &before, sizeof(row)) == 0);
    return failures;
}
/* Simulated codec evidence: these tests prove transaction admission, not
 * confinement or compatibility of an arbitrary downloaded program. */
struct td_transition {
    struct task_document_checkpoint checkpoint;
    struct package_resident_identity target;
    unsigned checks;
};

static struct package_resident_identity td_program(char digit)
{
    struct package_resident_identity identity = { .configuration_generation = 1 };
    memset(identity.package_root, digit, 64);
    memset(identity.receipt_id, digit, 64);
    memset(identity.artifact_sha3, digit, 64);
    (void)snprintf(identity.program, sizeof(identity.program), "bin/ztasks");
    return identity;
}

static struct zcl_result td_guard(void *context, struct package_resident_store *store,
    const struct package_resident_identity *target)
{
    struct td_transition *transition = context;
    ++transition->checks;
    if (!package_resident_identity_equal(target, &transition->target))
        return ZCL_ERR(-1, "task-preview: compatibility observation names another program");
    return task_document_check_current(store, &transition->checkpoint);
}

static bool td_pending(struct package_resident_store *store,
    const struct package_resident_identity *identity, struct package_resident_record *row)
{
    return package_resident_record_begin(store, row->generation, row).ok &&
        package_resident_record_accept(store, row->revision, row->generation,
            identity, identity->artifact_sha3, 1, row).ok;
}

static struct zcl_result td_switch(struct package_resident_store *store,
    struct package_resident_record *row, struct td_transition *transition, bool rollback)
{
    const struct package_resident_guard guard = { transition, td_guard };
    if (rollback)
        return package_resident_record_rollback_checked(store, row->revision, row->generation,
            transition->target.artifact_sha3, 3, &guard, row);
    return package_resident_record_activate_checked(store, row->revision, row->generation,
        transition->target.artifact_sha3, 2, &guard, row);
}

static bool td_verifier_kept_setup(struct package_resident_store *store, const char *directory,
    struct package_resident_record *record, struct task_document *row)
{
    struct td_transition transition = {0}; transition.target = td_program('a');
    return package_resident_store_open_task_app(store, directory, "local/verifier-kept").ok &&
        task_document_apply(store, 0, TASK_DOCUMENT_ADD, 0, "retained task", row).ok &&
        package_resident_record_read(store, record).ok && task_document_capture(store, &transition.checkpoint).ok &&
        td_pending(store, &transition.target, record) && td_switch(store, record, &transition, false).ok;
}
static bool td_verifier_kept_unchanged(struct package_resident_store *store,
    const struct package_resident_record *record, const struct task_document *row)
{
    struct task_document checked = {0};
    return td_verifier_state_unchanged(store, row, record) && task_document_read(store, &checked).ok &&
        checked.state.count == 1 && strcmp(checked.state.tasks[0].title, "retained task") == 0;
}

static int td_verifier_kept_refusal(const char *directory)
{
    int failures = 0;
    struct package_resident_store store = {0};
    struct package_resident_record record = {0};
    struct task_document row = {0};
    bool ready = td_verifier_kept_setup(&store, directory, &record, &row);
    TD_CHECK("kept verifier fixture ready", ready);
    if (ready) {
        struct json_value input = {0}; json_set_object(&input);
        bool built = json_push_kv_str(&input, "datadir", directory) &&
            json_push_kv_str(&input, "app", "local/verifier-kept") && json_push_kv_str(&input, "action", "open");
        struct zcl_command_reply reply = {0};
        zcl_test_task_verifier_missing(true);
        bool called = built && td_call(&input, &reply);
        zcl_test_task_verifier_missing(false);
        TD_CHECK("missing kept verifier has actionable typed refusal", called && td_verifier_reply_ok(&reply));
        TD_CHECK("kept verifier refusal preserves task and selection", td_verifier_kept_unchanged(&store, &record, &row));
        zcl_command_reply_free(&reply); json_free(&input);
    }
    if (store.db) TD_CHECK("kept verifier fixture closes", package_resident_store_close(&store).ok);
    return failures;
}

static int td_stale_preview(struct package_resident_store *store,
    struct package_resident_record *program, struct td_transition *transition)
{
    int failures = 0;
    struct task_document edited;
    TD_CHECK("edit during preview remains durable", task_document_apply(store, 1,
        TASK_DOCUMENT_EDIT, 1, "Edited while preview ran", &edited).ok);
    struct package_resident_record before = *program;
    TD_CHECK("stale preview preserves caller result", !td_switch(store, program, transition, false).ok &&
        memcmp(program, &before, sizeof(before)) == 0);
    TD_CHECK("stale preview releases transaction", sqlite3_get_autocommit(store->db));
    struct package_resident_record observed;
    TD_CHECK("stale preview preserves working program", package_resident_record_read(store, &observed).ok &&
        package_resident_identity_equal(&observed.current, &before.current) && observed.generation == before.generation);
    TD_CHECK("refresh preview uses current edits", task_document_capture(store, &transition->checkpoint).ok &&
        strcmp(transition->checkpoint.document.state.tasks[0].title, "Edited while preview ran") == 0);
    sqlite3_commit_hook(store->db, td_refuse_commit, NULL);
    TD_CHECK("failed activation COMMIT preserves caller result", !td_switch(store, program, transition, false).ok &&
        memcmp(program, &before, sizeof(before)) == 0);
    sqlite3_commit_hook(store->db, NULL, NULL);
    TD_CHECK("failed activation preserves working program", package_resident_record_read(store, &observed).ok &&
        package_resident_identity_equal(&observed.current, &before.current) && observed.generation == before.generation);
    TD_CHECK("fresh compatible preview switches program", td_switch(store, program, transition, false).ok &&
        package_resident_identity_equal(&program->current, &transition->target));
    TD_CHECK("activation preserves current edits", task_document_read(store, &edited).ok &&
        edited.state.revision == 2 && strcmp(edited.state.tasks[0].title, "Edited while preview ran") == 0);
    return failures;
}

static int td_return_current(struct package_resident_store *store,
    struct package_resident_record *program, struct td_transition *transition)
{
    int failures = 0;
    transition->target = program->previous;
    TD_CHECK("capture return compatibility input", task_document_capture(store, &transition->checkpoint).ok);
    struct task_document edited;
    TD_CHECK("new-program edit remains durable", task_document_apply(store, 2,
        TASK_DOCUMENT_ADD, 0, "Created in new program", &edited).ok);
    TD_CHECK("reserve return without restoring old data", package_resident_record_begin(store,
        program->generation, program).ok);
    TD_CHECK("stale return refuses", !td_switch(store, program, transition, true).ok);
    TD_CHECK("refresh return uses current data", task_document_capture(store, &transition->checkpoint).ok);
    struct package_resident_identity exact = transition->target;
    transition->target = td_program('f');
    TD_CHECK("wrong program compatibility refuses", !td_switch(store, program, transition, true).ok);
    transition->target = exact;
    TD_CHECK("checked return preserves newer data and undo", td_switch(store, program, transition, true).ok &&
        package_resident_identity_equal(&program->current, &exact) && task_document_read(store, &edited).ok &&
        edited.state.count == 2 && edited.state.revision == 3 &&
        strcmp(edited.state.tasks[1].title, "Created in new program") == 0 && edited.can_undo);
    TD_CHECK("undo after return preserves durable history", task_document_apply(store, 3,
        TASK_DOCUMENT_UNDO, 0, NULL, &edited).ok && edited.state.count == 1 && edited.state.revision == 4);
    return failures;
}

static void td_interrupt_switch(void *context, int operation,
    const char *database, const char *table, sqlite3_int64 row)
{
    (void)context; (void)operation; (void)database; (void)row;
    if (strcmp(table, "resident_serving") == 0) _exit(71);
}

static bool td_crash_switch(const char *directory, bool rollback, bool before_commit)
{
    pid_t child = fork();
    if (child < 0) { perror("task-preview: fork"); return false; }
    if (child == 0) {
        struct package_resident_store store = {0};
        struct package_resident_record program;
        struct td_transition transition = {0};
        if (!package_resident_store_open_app(&store, directory, "local/updates").ok ||
            !package_resident_record_read(&store, &program).ok ||
            !task_document_capture(&store, &transition.checkpoint).ok) _exit(70);
        transition.target = rollback ? program.previous : program.pending;
        if (before_commit) sqlite3_update_hook(store.db, td_interrupt_switch, NULL);
        if (!td_switch(&store, &program, &transition, rollback).ok) _exit(70);
        _exit(72);
    }
    int status = 0;
    return waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == (before_commit ? 71 : 72);
}

static int td_interruptions(struct package_resident_store *store, const char *directory,
    struct package_resident_record *program)
{
    int failures = 0;
    struct package_resident_identity next = td_program('c');
    TD_CHECK("reserve interrupted upgrade", td_pending(store, &next, program));
    struct package_resident_identity prior = program->current;
    TD_CHECK("close before interruption experiment", package_resident_store_close(store).ok);
    TD_CHECK("interrupt upgrade after write before COMMIT", td_crash_switch(directory, false, true));
    TD_CHECK("restart after interrupted upgrade", package_resident_store_open_app(store, directory, "local/updates").ok &&
        package_resident_record_read(store, program).ok && package_resident_identity_equal(&program->current, &prior));
    TD_CHECK("close after interrupted upgrade", package_resident_store_close(store).ok);
    TD_CHECK("exit immediately after upgrade COMMIT", td_crash_switch(directory, false, false));
    TD_CHECK("restart sees committed upgrade", package_resident_store_open_app(store, directory, "local/updates").ok &&
        package_resident_record_read(store, program).ok && package_resident_identity_equal(&program->current, &next));
    TD_CHECK("reserve interrupted rollback", package_resident_record_begin(store, program->generation, program).ok);
    TD_CHECK("close before rollback interruption", package_resident_store_close(store).ok);
    TD_CHECK("interrupt rollback after write before COMMIT", td_crash_switch(directory, true, true));
    TD_CHECK("restart sees retained working program", package_resident_store_open_app(store, directory, "local/updates").ok &&
        package_resident_record_read(store, program).ok && package_resident_identity_equal(&program->current, &next));
    TD_CHECK("close after interrupted rollback", package_resident_store_close(store).ok);
    TD_CHECK("exit immediately after rollback COMMIT", td_crash_switch(directory, true, false));
    struct task_document data;
    TD_CHECK("restart sees exact prior program and latest data", package_resident_store_open_app(store, directory, "local/updates").ok &&
        package_resident_record_read(store, program).ok && package_resident_identity_equal(&program->current, &prior) &&
        task_document_read(store, &data).ok && data.state.revision == 4 && data.state.count == 1 &&
        strcmp(data.state.tasks[0].title, "Edited while preview ran") == 0);
    return failures;
}

static int td_switch_cycles(struct package_resident_store *store,
    struct package_resident_record *program)
{
    int failures = 0;
    int64_t maximum = 0;
    struct td_transition transition = {0};
    bool cycles_passed = true;
    for (unsigned cycle = 0; cycles_passed && cycle < 20; ++cycle) {
        int64_t began = platform_time_monotonic_us();
        transition.target = program->previous;
        cycles_passed = task_document_capture(store, &transition.checkpoint).ok &&
            package_resident_record_begin(store, program->generation, program).ok &&
            td_switch(store, program, &transition, true).ok &&
            package_resident_identity_equal(&program->current, &transition.target);
        int64_t elapsed = platform_time_monotonic_us() - began;
        if (elapsed > maximum) maximum = elapsed;
    }
    TD_CHECK("twenty checked program returns preserve latest data", cycles_passed &&
        transition.checkpoint.document.state.revision == 4 &&
        strcmp(transition.checkpoint.document.state.tasks[0].title, "Edited while preview ran") == 0);
    printf("task_document: checked_switch_cycles=20 max_us=%lld scope=transaction-only\n", (long long)maximum);
    return failures;
}

static int td_update_admission(const char *directory)
{
    int failures = 0;
    struct package_resident_store store = {0};
    TD_CHECK("open managed-data fixture", package_resident_store_open_app(&store, directory, "local/updates").ok);
    struct task_document data;
    struct package_resident_record program = {0};
    struct td_transition transition = { .target = td_program('a') };
    TD_CHECK("create data before first program", task_document_apply(&store, 0,
        TASK_DOCUMENT_ADD, 0, "Before preview", &data).ok);
    TD_CHECK("capture initial data", task_document_capture(&store, &transition.checkpoint).ok);
    TD_CHECK("check outside transaction refuses", !task_document_check_current(&store, &transition.checkpoint).ok);
    TD_CHECK("reserve first program", td_pending(&store, &transition.target, &program));
    TD_CHECK("missing compatibility guard refuses", !package_resident_record_activate_checked(&store,
        program.revision, program.generation, transition.target.artifact_sha3, 2, NULL, &program).ok);
    TD_CHECK("activate first checked program", td_switch(&store, &program, &transition, false).ok && transition.checks == 1);
    transition.target = td_program('b');
    TD_CHECK("reserve changed program", td_pending(&store, &transition.target, &program));
    failures += td_stale_preview(&store, &program, &transition);
    failures += td_return_current(&store, &program, &transition);
    TD_CHECK("close managed-data fixture", package_resident_store_close(&store).ok);
    TD_CHECK("restart managed-data fixture", package_resident_store_open_app(&store, directory, "local/updates").ok);
    TD_CHECK("restart keeps returned program and latest data", package_resident_record_read(&store, &program).ok &&
        package_resident_identity_equal(&program.current, &transition.target) && task_document_read(&store, &data).ok &&
        data.state.count == 1 && data.state.revision == 4 &&
        strcmp(data.state.tasks[0].title, "Edited while preview ran") == 0);
    failures += td_interruptions(&store, directory, &program);
    failures += td_switch_cycles(&store, &program);
    TD_CHECK("close restarted managed-data fixture", package_resident_store_close(&store).ok);
    return failures;
}

#define TE_CHECK(label, expression) do { \
    bool passed = (expression); \
    printf("task_editor: %s... %s\n", label, passed ? "OK" : "FAIL"); \
    if (!passed) ++failures; \
} while (0)

static bool te_summary(const struct task_editor *editor, const char *prefix)
{
    struct zcl_present_model_v1 model;
    return task_editor_model(editor, &model).ok &&
        strncmp(model.summary, prefix, strlen(prefix)) == 0;
}

static int te_visual(const struct task_editor *editor)
{
    int failures = 0;
    struct zcl_present_model_v1 model;
    struct zcl_present_model_bitmap_v1 title = {0}, action = {0}, ordinary = {0};
    char error[256] = {0};
    TE_CHECK("build native form model", task_editor_model(editor, &model).ok);
    int64_t began = platform_time_monotonic_us();
    bool first = zcl_present_model_render_editor_v1(&model, &title, error, sizeof(error));
    printf("task_editor: native_editor_frame_us=%lld\n",
        (long long)(platform_time_monotonic_us() - began));
    bool rendered = first && zcl_present_model_render_editor_v1(&model, &action, error, sizeof(error));
    TE_CHECK("render actual native form pixels headlessly", rendered);
    if (rendered) {
        bool ordinary_ok = zcl_present_model_render_v1(&model, &ordinary, error, sizeof(error));
        TE_CHECK("local editor omits technical header; ordinary form retains it", ordinary_ok &&
            memcmp(title.pixels, ordinary.pixels, 164u * 720u * 3u) != 0 &&
            strlen(model.exact_root) == 64);
        zcl_present_form_draw_state_internal(title.pixels, ZCL_PRESENT_MODEL_BITMAP_BYTES,
            &editor->form, 0, false);
        zcl_present_form_draw_state_internal(action.pixels, ZCL_PRESENT_MODEL_BITMAP_BYTES,
            &editor->form, 1, false);
        const struct zcl_present_window_v1 page = {
            .width = action.width, .height = action.height, .pixel_format = ZCL_PRESENT_RGB8 };
        zcl_present_draw_action_focus_internal(&page, action.pixels,
            action.width, action.height, 2, 0);
        TE_CHECK("moving focus changes the native pixel overlay",
            memcmp(title.pixels, action.pixels, ZCL_PRESENT_MODEL_BITMAP_BYTES) != 0);
    } else fprintf(stderr, "task_editor: render: %s\n", error);
    zcl_present_model_bitmap_free_v1(&title);
    zcl_present_model_bitmap_free_v1(&action);
    zcl_present_model_bitmap_free_v1(&ordinary);
    return failures;
}

static struct zcl_result te_wait(struct task_editor *editor)
{
    /* The deadline bounds a hung save, not save speed. */
    int64_t deadline = platform_time_monotonic_us() + INT64_C(30000000);
    while (platform_time_monotonic_us() < deadline) {
        bool changed = false;
        struct zcl_result result = task_editor_poll(editor, &changed);
        if (!result.ok || changed) return result;
        platform_sleep_ms(1);
    }
    return ZCL_ERR(-1, "task editor test: save completion not observed");
}

#if defined(ZCL_TESTING)
bool zcl_test_task_editor_window_action(struct task_editor *editor,
    enum task_editor_status painted, bool display_ok, bool close_requested, bool *back);

struct te_conflict {
    struct package_resident_store store;
    struct task_document row;
    struct task_editor a, b;
    bool back;
    char original_dir[4096];
};

static int te_conflict_save(struct te_conflict *c, const char *directory)
{
    int failures = 0;
    TE_CHECK("open conflict store", package_resident_store_open_app(&c->store, directory, "local/conflict").ok);
    TE_CHECK("create conflict task", task_document_apply(&c->store, 0, TASK_DOCUMENT_ADD, 0, "Original", &c->row).ok);
    TE_CHECK("open both editors", task_editor_open(&c->a, directory, "local/conflict").ok &&
        task_editor_open(&c->b, directory, "local/conflict").ok &&
        task_editor_select(&c->a, 1).ok && task_editor_select(&c->b, 1).ok);
    TE_CHECK("keep both drafts", task_editor_type(&c->a, 'A', false).ok && task_editor_type(&c->b, 'B', false).ok);
    TE_CHECK("discard unavailable before failure", !task_editor_discard_reload(&c->b).ok && c->b.dirty &&
        !strcmp(c->b.form.fields[0].value, "OriginalB"));
    TE_CHECK("first editor saves", task_editor_submit(&c->a, TASK_DOCUMENT_EDIT).ok && te_wait(&c->a).ok);
    TE_CHECK("stale save preserves draft", task_editor_submit(&c->b, TASK_DOCUMENT_EDIT).ok && !te_wait(&c->b).ok &&
        c->b.status == TASK_EDITOR_FAILED && c->b.dirty && !strcmp(c->b.form.fields[0].value, "OriginalB"));
    return failures;
}

static int te_conflict_guard(struct te_conflict *c)
{
    int failures = 0;
    TE_CHECK("titlebar close retries instead of discarding", !zcl_test_task_editor_window_action(&c->b,
        TASK_EDITOR_FAILED, true, true, &c->back) && c->b.pending && c->b.dirty && !te_wait(&c->b).ok &&
        !strcmp(c->b.form.fields[0].value, "OriginalB"));
    TE_CHECK("failed paint cannot authorize discard", !zcl_test_task_editor_window_action(&c->b,
        TASK_EDITOR_FAILED, false, false, &c->back) && !c->back && c->b.dirty);
    TE_CHECK("new input invalidates displayed discard", zcl_present_window_form_edit_v1(&c->b.form, 0, '!', false) &&
        !zcl_test_task_editor_window_action(&c->b, TASK_EDITOR_FAILED, true, false, &c->back) &&
        !c->back && c->b.dirty && c->b.status == TASK_EDITOR_UNSAVED && !strcmp(c->b.form.fields[0].value, "OriginalB!"));
    TE_CHECK("retry still detects stale revision", task_editor_submit(&c->b, TASK_DOCUMENT_EDIT).ok && !te_wait(&c->b).ok);
    return failures;
}

static int te_conflict_read_failure(struct te_conflict *c)
{
    int failures = 0;
    (void)snprintf(c->original_dir, sizeof(c->original_dir), "%s", c->b.directory);
    (void)snprintf(c->b.directory, sizeof(c->b.directory), "/dev/null/no-task-store");
    TE_CHECK("failed reload keeps draft and recovery available", !zcl_test_task_editor_window_action(&c->b,
        TASK_EDITOR_FAILED, true, false, &c->back) && !c->back && c->b.dirty &&
        c->b.status == TASK_EDITOR_FAILED && !strcmp(c->b.form.fields[0].value, "OriginalB!"));
    (void)snprintf(c->b.directory, sizeof(c->b.directory), "%s", c->original_dir);
    return failures;
}

static int te_conflict_discard(struct te_conflict *c)
{
    int failures = 0;
    TE_CHECK("explicit discard reloads and returns", zcl_test_task_editor_window_action(&c->b,
        TASK_EDITOR_FAILED, true, false, &c->back) && c->back && !c->b.dirty && c->b.closing &&
        c->b.saved.state.revision == c->a.saved.state.revision && c->b.saved.can_undo &&
        !strcmp(c->b.form.fields[0].value, "OriginalA"));
    TE_CHECK("reload did not write", task_document_read(&c->store, &c->row).ok &&
        c->row.state.revision == c->a.saved.state.revision && !strcmp(c->row.state.tasks[0].title, "OriginalA") && c->row.can_undo);
    return failures;
}

static int te_conflict_deleted(struct te_conflict *c, const char *directory)
{
    int failures = 0;
    TE_CHECK("reopen stale editor for delete", task_editor_open(&c->b, directory, "local/conflict").ok &&
        task_editor_select(&c->b, 1).ok && task_editor_type(&c->b, 'C', false).ok);
    TE_CHECK("delete selected task elsewhere", task_document_apply(&c->store, c->row.state.revision,
        TASK_DOCUMENT_DELETE, 1, NULL, &c->row).ok);
    TE_CHECK("deleted selection fails stale save", task_editor_submit(&c->b, TASK_DOCUMENT_EDIT).ok && !te_wait(&c->b).ok);
    c->back = false;
    TE_CHECK("discard deleted selection returns without replacement", zcl_test_task_editor_window_action(&c->b,
        TASK_EDITOR_FAILED, true, false, &c->back) && c->back && c->b.selected_id == 0 &&
        c->b.saved.state.count == 0 && c->b.saved.state.revision == c->row.state.revision && !c->b.dirty);
    TE_CHECK("deleted selection reload did not write", task_document_read(&c->store, &c->row).ok && c->row.state.count == 0 &&
        c->row.state.revision == c->b.saved.state.revision && c->row.can_undo);
    TE_CHECK("close conflict store", package_resident_store_close(&c->store).ok);
    return failures;
}

static int te_normal_back(const char *directory)
{
    int failures = 0;
    struct task_editor editor = {0};
    bool back = false;
    TE_CHECK("open ordinary editor", task_editor_open(&editor, directory, "local/normal-back").ok);
    TE_CHECK("type ordinary draft", task_editor_type(&editor, 'N', false).ok);
    TE_CHECK("ordinary Back saves instead of discarding", !zcl_test_task_editor_window_action(&editor,
        TASK_EDITOR_UNSAVED, true, false, &back) && back && editor.pending && editor.dirty);
    TE_CHECK("ordinary Back completes durable save", te_wait(&editor).ok && editor.closing && !editor.dirty &&
        editor.saved.state.count == 1 && !strcmp(editor.saved.state.tasks[0].title, "N"));
    return failures;
}

static int te_conflict_recovery(const char *directory)
{
    struct te_conflict c = {0};
    int failures = te_conflict_save(&c, directory);
    failures += te_conflict_guard(&c);
    failures += te_conflict_read_failure(&c);
    failures += te_conflict_discard(&c);
    failures += te_conflict_deleted(&c, directory);
    failures += te_normal_back(directory);
    return failures;
}

#endif

static int te_focus(struct task_editor *editor)
{
    int failures = 0;
    uint32_t focus = UINT32_MAX;
    TE_CHECK("Tab focuses first action", zcl_present_window_form_focus_step_v1(
        &editor->form, 2, 0, 1, &focus) && focus == 1);
    TE_CHECK("Shift-Tab returns to title", zcl_present_window_form_focus_step_v1(
        &editor->form, 2, focus, -1, &focus) && focus == 0);
    return failures;
}

static int te_drafts(struct task_editor *editor)
{
    int failures = 0;
    const char *title = "First";
    for (size_t i = 0; title[i]; ++i)
        TE_CHECK("shared native typing", task_editor_type(editor, (uint8_t)title[i], false).ok);
    TE_CHECK("new draft model does not say Saved", te_summary(editor, "Unsaved changes"));
    failures += te_focus(editor);
    TE_CHECK("start save without claiming Saved", task_editor_submit(editor,
        TASK_DOCUMENT_ADD).ok && editor->status == TASK_EDITOR_SAVING &&
        te_summary(editor, "Saving..."));
    TE_CHECK("typing continues after submission", task_editor_type(editor, '!', false).ok &&
        strcmp(editor->form.fields[0].value, "First!") == 0);
    TE_CHECK("older success leaves newer draft unsaved", te_wait(editor).ok &&
        editor->status == TASK_EDITOR_UNSAVED && editor->dirty &&
        te_summary(editor, "Unsaved changes") &&
        strcmp(editor->saved.state.tasks[0].title, "First") == 0 &&
        strcmp(editor->form.fields[0].value, "First!") == 0);
    TE_CHECK("closing saves latest draft", task_editor_finish(editor).ok &&
        editor->status == TASK_EDITOR_SAVED && !editor->dirty && te_summary(editor, "Saved") &&
        strcmp(editor->saved.state.tasks[0].title, "First!") == 0);
    return failures;
}

static int te_busy(struct task_editor *editor, const char *directory)
{
    int failures = 0;
    struct package_resident_store blocker = {0};
    struct zcl_result opened = package_resident_store_open_app(&blocker, directory, "local/editor");
    if (!opened.ok) { fprintf(stderr, "task_editor: blocker: %s\n", opened.message); return 1; }
    TE_CHECK("hold competing database writer", sqlite3_exec(blocker.db,
        "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK);
    TE_CHECK("edit while storage is busy", task_editor_type(editor, '?', false).ok);
    TE_CHECK("queue save while storage is busy", task_editor_submit(editor, TASK_DOCUMENT_EDIT).ok);
    int64_t began = platform_time_monotonic_us();
    bool keyboard_ok = true;
    for (unsigned i = 0; i < 1000; ++i) {
        keyboard_ok &= task_editor_type(editor, 'x', false).ok;
        keyboard_ok &= task_editor_type(editor, 0, true).ok;
    }
    printf("task_editor: keyboard_2000_events_us=%lld\n",
        (long long)(platform_time_monotonic_us() - began));
    TE_CHECK("keyboard preserves exact draft during busy save", keyboard_ok &&
        strcmp(editor->form.fields[0].value, "First!?") == 0);
    TE_CHECK("busy save reports failure and retains draft", !te_wait(editor).ok &&
        editor->status == TASK_EDITOR_FAILED && editor->failure[0] && editor->dirty &&
        te_summary(editor, "Save failed") &&
        strcmp(editor->form.fields[0].value, "First!?") == 0 &&
        strcmp(editor->saved.state.tasks[0].title, "First!") == 0);
    TE_CHECK("release competing writer", sqlite3_exec(blocker.db,
        "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK);
    TE_CHECK("close competing connection", package_resident_store_close(&blocker).ok);
    TE_CHECK("explicit save after cause clears", task_editor_submit(editor,
        TASK_DOCUMENT_EDIT).ok && task_editor_finish(editor).ok &&
        editor->status == TASK_EDITOR_SAVED);
    return failures;
}
static struct zcl_result tl_wait_test(struct task_list *list)
{
    /* The deadline bounds a hung save, not save speed. */
    int64_t end = platform_time_monotonic_us() + INT64_C(30000000);
    while (list->editor->pending && platform_time_monotonic_us() < end) {
        platform_sleep_ms(1);
        struct zcl_result result = task_list_poll(list);
        if (!result.ok) return result;
    }
    if (list->editor->pending) return ZCL_ERR(-1, "list test: save not observed");
    return ZCL_OK;
}

static bool tl_key_test(struct task_list *list, enum zcl_present_input_key key, bool shift)
{
    const struct zcl_present_input_v1 input = { .key = key, .shift = shift };
    uint32_t action = UINT32_MAX;
    return task_list_input(list, &input, &list->focus, &action);
}

static int tl_visual_test(struct task_list *list)
{
    int failures = 0;
    struct zcl_present_model_v1 model;
    struct zcl_present_model_bitmap_v1 selected = {0}, button = {0};
    char error[256];
    int64_t began = platform_time_monotonic_us();
    TE_CHECK("list input moves selection", tl_key_test(list, ZCL_PRESENT_INPUT_DOWN, false));
    bool rendered = task_list_model(list, &model).ok &&
        zcl_present_model_render_list_v1(&model, &selected, error, sizeof(error));
    printf("task_list: input_to_frame_us=%lld bitmap_bytes=%u\n",
        (long long)(platform_time_monotonic_us() - began), ZCL_PRESENT_MODEL_BITMAP_BYTES);
    TE_CHECK("list selected row has real rendered pixels", rendered);
    TE_CHECK("Tab moves from content to New", tl_key_test(list, ZCL_PRESENT_INPUT_TAB, false) && list->focus == 0);
    bool second = task_list_model(list, &model).ok &&
        zcl_present_model_render_list_v1(&model, &button, error, sizeof(error));
    TE_CHECK("list keyboard focus changes visible pixels", rendered && second &&
        memcmp(selected.pixels, button.pixels, ZCL_PRESENT_MODEL_BITMAP_BYTES) != 0);
    TE_CHECK("Shift-Tab returns focus to selected row", tl_key_test(list, ZCL_PRESENT_INPUT_TAB, true) && list->focus == UINT32_MAX);
    zcl_present_model_bitmap_free_v1(&selected);
    zcl_present_model_bitmap_free_v1(&button);
    return failures;
}

static int tl_actions_test(struct task_list *list)
{
    int failures = 0;
    struct task_editor *editor = list->editor;
    uint64_t completed_id = list->selected_id;
    TE_CHECK("complete starts asynchronous Saving", task_list_action(list, 2).ok && editor->pending && editor->status == TASK_EDITOR_SAVING);
    TE_CHECK("navigation stays responsive during save", tl_key_test(list, ZCL_PRESENT_INPUT_DOWN, false));
    uint64_t navigated_id = list->selected_id;
    TE_CHECK("save retains newer navigation selection", tl_wait_test(list).ok && list->selected_id == navigated_id);
    bool completed = false;
    for (uint32_t i = 0; i < editor->saved.state.count; ++i)
        if (editor->saved.state.tasks[i].id == completed_id) completed = editor->saved.state.tasks[i].done != 0;
    TE_CHECK("completion changed only requested task", completed);
    struct ta_state before = editor->saved.state;
    TE_CHECK("Delete key enqueues selected task removal", tl_key_test(list, ZCL_PRESENT_INPUT_DELETE, false) && editor->pending);
    TE_CHECK("deleted task is durable and undo available", tl_wait_test(list).ok && editor->saved.state.count == before.count - 1 && editor->saved.can_undo);
    const struct zcl_present_input_v1 undo = { .key = ZCL_PRESENT_INPUT_TEXT, .character = 'z', .command = true };
    uint32_t action = UINT32_MAX;
    TE_CHECK("Cmd/Ctrl+Z enqueues durable undo", task_list_input(list, &undo, &list->focus, &action) && editor->pending);
    TE_CHECK("undo restores exact contents with fresh revision", tl_wait_test(list).ok &&
        editor->saved.state.count == before.count && editor->saved.state.revision > before.revision &&
        memcmp(editor->saved.state.tasks, before.tasks, sizeof(before.tasks)) == 0);
    TE_CHECK("More exposes deletion and durable undo", task_list_action(list, 3).ok && list->menu);
    TE_CHECK("Back returns to main actions", task_list_action(list, 0).ok && !list->menu);
    return failures;
}

static bool tl_populate(struct task_editor *editor)
{
    for (unsigned i = 0; i < 12; ++i) {
        char title[32];
        (void)snprintf(title, sizeof(title), "Task %02u", i + 1);
        if (!task_editor_select(editor, 0).ok) return false;
        for (size_t j = 0; title[j]; ++j)
            if (!task_editor_type(editor, (uint8_t)title[j], false).ok) return false;
        if (!task_editor_submit(editor, TASK_DOCUMENT_ADD).ok || !task_editor_finish(editor).ok) return false;
    }
    return true;
}

static int tl_failure_test(struct task_list *list, const char *directory)
{
    int failures = 0;
    struct package_resident_store other = {0};
    struct task_document row;
    TE_CHECK("open independent task writer", package_resident_store_open_app(&other, directory, "local/list").ok);
    TE_CHECK("read independent current revision", task_document_read(&other, &row).ok);
    TE_CHECK("another window durably edits selected task", task_document_apply(&other,
        row.state.revision, TASK_DOCUMENT_EDIT, list->selected_id, "Other window edit", &row).ok);
    TE_CHECK("stale list can enqueue but cannot overwrite", task_list_action(list, 2).ok && !tl_wait_test(list).ok &&
        list->editor->status == TASK_EDITOR_FAILED);
    struct zcl_present_model_v1 model;
    TE_CHECK("failed list action never displays Saved", task_list_model(list, &model).ok &&
        strncmp(model.summary, "Save failed", 11) == 0);
    struct task_document after;
    TE_CHECK("failed list action preserves exact other-window data", task_document_read(&other, &after).ok &&
        after.state.revision == row.state.revision &&
        memcmp(after.state.tasks, row.state.tasks, sizeof(row.state.tasks)) == 0);
    TE_CHECK("independent task writer closes", package_resident_store_close(&other).ok);
    return failures;
}

#if defined(ZCL_TESTING)
bool zcl_test_task_update_completed(struct task_update *update);

static bool tl_wait_update_failure(struct task_list *list)
{
    int64_t end = platform_time_monotonic_us() + INT64_C(30000000);
    while (!zcl_test_task_update_completed(list->update) && platform_time_monotonic_us() < end)
        platform_sleep_ms(1);
    return zcl_test_task_update_completed(list->update) && !task_list_poll(list).ok;
}

static int tl_update_notice_model_test(struct task_list *list)
{
    int failures = 0;
    struct zcl_present_model_v1 model;
    TE_CHECK("local notice takes precedence", task_list_model(list, &model).ok &&
        strstr(model.summary, "Existing local action error") != NULL);
    list->notice[0] = '\0';
    TE_CHECK("hidden update failure is visible", task_list_model(list, &model).ok &&
        strstr(model.summary, list->update->message) != NULL);
    list->editor->status = TASK_EDITOR_UNSAVED;
    TE_CHECK("draft status takes precedence over update failure", task_list_model(list, &model).ok &&
        !strncmp(model.summary, "Unsaved changes", 15));
    list->editor->status = TASK_EDITOR_SAVED;
    list->update->phase = TASK_UPDATE_KEPT;
    list->update_ack_error = true;
    (void)snprintf(list->update->message, sizeof(list->update->message), "Program kept; notice could not be cleared.");
    TE_CHECK("kept acknowledgment failure remains visible", task_list_model(list, &model).ok &&
        strstr(model.summary, list->update->message) != NULL);
    list->update->phase = TASK_UPDATE_RUNNING;
    (void)snprintf(list->update->message, sizeof(list->update->message), "Preparing retry");
    TE_CHECK("retry does not retain prior failure", task_list_poll(list).ok && !list->update_ack_error &&
        task_list_model(list, &model).ok && strstr(model.summary, "notice could not be cleared") == NULL && !list->notice[0]);
    list->update->phase = TASK_UPDATE_KEPT;
    (void)snprintf(list->update->message, sizeof(list->update->message), "Current program is ready.");
    TE_CHECK("successful Keep preserves Saved summary", task_list_model(list, &model).ok &&
        !strncmp(model.summary, "Saved", 5));
    list->update->phase = TASK_UPDATE_CANCELLED;
    TE_CHECK("cancelled update preserves Saved summary", task_list_model(list, &model).ok &&
        !strncmp(model.summary, "Saved", 5));
    return failures;
}

static int tl_update_notice_test(const char *directory)
{
    int failures = 0;
    struct task_editor editor = {0};
    struct task_update update = {0};
    struct task_list list;
    TE_CHECK("open update notice fixture", task_editor_open(&editor, directory, "local/notice").ok &&
        task_update_open(&update, directory, "local/notice", "/dev/null", NULL).ok);
    task_list_init(&list, &editor);
    list.update = &update;
    struct zcl_present_model_v1 model;
    TE_CHECK("synchronous update refusal is visible without polling", !task_update_try(&update, false, false).ok &&
        update.phase == TASK_UPDATE_FAILED && !list.update_ack_error &&
        task_list_model(&list, &model).ok && strstr(model.summary, update.message) != NULL);
    list.updates = true;
    (void)snprintf(list.notice, sizeof(list.notice), "Existing local action error");
    TE_CHECK("start refused update in panel", task_update_try(&update, true, false).ok);
    TE_CHECK("panel owns its failure without overwriting local notice", tl_wait_update_failure(&list) &&
        update.phase == TASK_UPDATE_FAILED && update.message[0] &&
        !strcmp(list.notice, "Existing local action error"));
    list.updates = false;
    TE_CHECK("start refused update outside panel", task_update_try(&update, true, false).ok);
    TE_CHECK("hidden failure preserves local notice", tl_wait_update_failure(&list) &&
        update.phase == TASK_UPDATE_FAILED && !strcmp(list.notice, "Existing local action error"));
    failures += tl_update_notice_model_test(&list);
    TE_CHECK("release update fixture", task_update_finish(&update).ok);
    return failures;
}
#endif

static int tl_adopt_snapshot_test(struct task_list *list, const struct task_document *newer,
    uint64_t selected_id)
{
    int failures = 0;
    TE_CHECK("select task before its row moves", tl_key_test(list, ZCL_PRESENT_INPUT_DOWN, false) &&
        list->selected_id == selected_id);
    TE_CHECK("clean list adopts verified newer snapshot and Undo", task_list_poll(list).ok &&
        list->editor->saved.state.revision == newer->state.revision && list->editor->saved.can_undo &&
        !strcmp(list->editor->saved.state.tasks[0].title, "After") &&
        !strcmp(list->editor->saved.undo.tasks[0].title, "Second") && list->selected_id == selected_id &&
        list->selected == 0 && !list->update->pending);
    TE_CHECK("subsequent poll does not restart refresh", task_list_poll(list).ok && !list->update->pending);
    return failures;
}

static int tl_snapshot_undo_test(struct task_list *list, struct package_resident_store *store,
    struct task_document *newer, uint64_t selected_id)
{
    int failures = 0;
    TE_CHECK("Undo after adoption starts", task_list_action(list, 3).ok && task_list_action(list, 2).ok &&
        list->editor->pending && task_editor_finish(list->editor).ok);
    TE_CHECK("Undo restores newer snapshot history durably", task_document_read(store, newer).ok &&
        !strcmp(newer->state.tasks[0].title, "Second") && newer->state.revision == list->editor->saved.state.revision);
    TE_CHECK("other editor deletes selection", task_document_apply(store, newer->state.revision,
        TASK_DOCUMENT_DELETE, selected_id, NULL, newer).ok);
    list->update->active_document = *newer;
    TE_CHECK("adoption clears a deleted selection", task_list_poll(list).ok &&
        list->editor->saved.state.count == 0 && list->selected_id == 0 && !list->update->pending);
    return failures;
}

static int tl_newer_snapshot_test(const char *directory)
{
    int failures = 0;
    struct package_resident_store store = {0};
    struct task_document newer = {0};
    struct task_editor editor = {0};
    struct task_update update = {0};
    struct task_list list;
    TE_CHECK("open refresh fixture", package_resident_store_open_app(&store, directory, "local/refresh-list").ok);
    TE_CHECK("create refresh task", task_document_apply(&store, 0, TASK_DOCUMENT_ADD, 0, "Before", &newer).ok);
    TE_CHECK("create selected task", task_document_apply(&store, newer.state.revision,
        TASK_DOCUMENT_ADD, 0, "Second", &newer).ok);
    uint64_t selected_id = newer.state.tasks[1].id;
    TE_CHECK("open older list snapshot", task_editor_open(&editor, directory, "local/refresh-list").ok &&
        task_editor_select(&editor, selected_id).ok);
    struct task_document older = editor.saved;
    task_list_init(&list, &editor);
    list.update = &update;
    TE_CHECK("other editor removes preceding task", task_document_apply(&store, newer.state.revision,
        TASK_DOCUMENT_DELETE, 1, NULL, &newer).ok);
    TE_CHECK("other editor advances durable state", task_document_apply(&store, newer.state.revision,
        TASK_DOCUMENT_EDIT, selected_id, "After", &newer).ok && newer.can_undo);
    update.active_document = newer;
    update.active_valid = true;
    TE_CHECK("dirty draft is not replaced", task_editor_type(&editor, '!', false).ok &&
        task_list_poll(&list).ok && editor.saved.state.revision < newer.state.revision &&
        editor.dirty && !strcmp(editor.form.fields[0].value, "Second!") && !update.pending);
    TE_CHECK("reopen clean older list", task_editor_open(&editor, directory, "local/refresh-list").ok);
    editor.saved = older;
    task_list_init(&list, &editor);
    list.update = &update;
    failures += tl_adopt_snapshot_test(&list, &newer, selected_id);
    failures += tl_snapshot_undo_test(&list, &store, &newer, selected_id);
    TE_CHECK("close refresh fixture", package_resident_store_close(&store).ok);
    return failures;
}

static bool tl_empty_summary(struct task_list *list, const char *expected)
{
    struct zcl_present_model_v1 model; char why[256];
    return task_list_model(list, &model).ok && zcl_present_model_validate_v1(&model, why, sizeof(why)) &&
        !strcmp(model.summary, expected);
}
static int tl_empty_render_test(struct task_list *list)
{
    const char *fallback = "Saved. No tasks yet - choose New task.";
    struct task_update update = {0}; int failures = 0;
    list->update = &update; update.active_valid = true; update.active_document = list->editor->saved;
    (void)snprintf(update.active, sizeof(update.active), "Your workshop is ready. Add your first task.\n");
    TE_CHECK("kept empty render is displayed", tl_empty_summary(list, "Your workshop is ready. Add your first task."));
    update.active_valid = false;
    TE_CHECK("unverified render falls back", tl_empty_summary(list, fallback));
    update.active_valid = true; ++update.active_document.state.last_write;
    TE_CHECK("different saved state falls back", tl_empty_summary(list, fallback));
    update.active_document = list->editor->saved; ++update.active_document.undo.revision;
    TE_CHECK("different Undo snapshot falls back", tl_empty_summary(list, fallback));
    update.active_document = list->editor->saved;
    (void)snprintf(update.active, sizeof(update.active), "first\nsecond\n");
    TE_CHECK("multiline render falls back", tl_empty_summary(list, fallback));
    (void)snprintf(update.active, sizeof(update.active), "bad\033text\n");
    TE_CHECK("control render falls back", tl_empty_summary(list, fallback));
    memset(update.active, 'x', sizeof(update.active));
    TE_CHECK("unterminated render falls back", tl_empty_summary(list, fallback));
    (void)snprintf(update.active, sizeof(update.active), "valid\n");
    (void)snprintf(list->notice, sizeof(list->notice), "notice");
    struct zcl_present_model_v1 model;
    TE_CHECK("notice retains priority", task_list_model(list, &model).ok && strstr(model.summary, "notice"));
    list->notice[0] = 0; list->update = NULL;
    return failures;
}

static int tl_acceptance(const char *directory)
{
    int failures = 0;
    struct task_editor editor = {0};
    TE_CHECK("open empty task-list store", task_editor_open(&editor, directory, "local/list").ok);
    struct task_list list;
    task_list_init(&list, &editor);
    struct zcl_present_model_v1 model;
    char error[256];
    TE_CHECK("empty list validates with obvious New action", task_list_model(&list, &model).ok &&
        zcl_present_model_validate_v1(&model, error, sizeof(error)) && strcmp(model.actions[0].label, "New task") == 0);
    failures += tl_empty_render_test(&list);
    TE_CHECK("create twelve durable tasks", tl_populate(&editor) && editor.saved.state.count == 12);
    task_list_refresh(&list);
    TE_CHECK("End scrolls selected row into viewport", tl_key_test(&list, ZCL_PRESENT_INPUT_END, false) && list.selected == 11 && list.first == 4);
    TE_CHECK("Home restores first row and viewport", tl_key_test(&list, ZCL_PRESENT_INPUT_HOME, false) && list.selected == 0 && list.first == 0);
    failures += tl_visual_test(&list);
    failures += tl_actions_test(&list);
    struct task_editor reopened = {0};
    TE_CHECK("reopen retains exact list contents", task_editor_open(&reopened, directory, "local/list").ok &&
        reopened.saved.state.count == editor.saved.state.count &&
        memcmp(reopened.saved.state.tasks, editor.saved.state.tasks, sizeof(editor.saved.state.tasks)) == 0);
    failures += tl_failure_test(&list, directory);
#if defined(ZCL_TESTING)
    failures += tl_update_notice_test(directory);
#endif
    failures += tl_newer_snapshot_test(directory);
    TE_CHECK("list releases its save worker", task_editor_finish(&editor).ok && !editor.pending);
    return failures;
}

static int td_editor_acceptance(const char *directory)
{
    int failures = 0;
    size_t fd_before = 0, fd_after = 0;
    int threads_before = thread_registry_live_count();
    int rows_before = thread_registry_unreaped_count();
    TE_CHECK("observe initial descriptor count", os_proc_open_fd_count(&fd_before));
    struct task_editor editor = {0};
    struct zcl_result opened = task_editor_open(&editor, directory, "local/editor");
    if (!opened.ok) { fprintf(stderr, "task_editor: open: %s\n", opened.message); return 1; }
    failures += tl_acceptance(directory);
    failures += te_drafts(&editor);
    failures += te_busy(&editor, directory);
#if defined(ZCL_TESTING)
    failures += te_conflict_recovery(directory);
#endif
    struct task_editor reopened = {0};
    TE_CHECK("restart keeps exact latest editor contents", task_editor_open(&reopened,
        directory, "local/editor").ok && reopened.saved.state.count == 1 &&
        strcmp(reopened.saved.state.tasks[0].title, "First!?") == 0);
    TE_CHECK("select the reopened task", task_editor_select(&reopened,
        reopened.saved.state.tasks[0].id).ok);
    failures += te_visual(&reopened);
    TE_CHECK("request close without blocking or early Saved",
        task_editor_type(&reopened, '+', false).ok && task_editor_request_close(&reopened).ok &&
        reopened.closing && reopened.pending && te_summary(&reopened, "Saving..."));
    TE_CHECK("native close becomes ready only after durable completion", te_wait(&reopened).ok &&
        reopened.closing && !reopened.pending && !reopened.dirty &&
        te_summary(&reopened, "Saved") && strcmp(reopened.saved.state.tasks[0].title, "First!?+") == 0);
    TE_CHECK("finish prior editor", task_editor_finish(&editor).ok);
    TE_CHECK("finish reopened editor", task_editor_finish(&reopened).ok);
    TE_CHECK("save workers leave descriptor count unchanged",
        os_proc_open_fd_count(&fd_after) && fd_before == fd_after);
    TE_CHECK("save workers retain no thread or join ownership",
        thread_registry_live_count() == threads_before &&
        thread_registry_unreaped_count() == rows_before);
    return failures;
}

static bool td_schema_seed(const char *path)
{
    sqlite3 *db = NULL;
    bool ok = sqlite3_open(path, &db) == SQLITE_OK;
    if (ok) ok = sqlite3_exec(db, "CREATE TABLE fixture_seed(v); CREATE INDEX task_documents ON fixture_seed(v)", NULL, NULL, NULL) == SQLITE_OK;
    if (db && sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}

static bool td_schema_rolled_back(const char *path)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *s = NULL;
    bool ok = sqlite3_open(path, &db) == SQLITE_OK;
    if (ok) ok = sqlite3_prepare_v2(db, "SELECT count(*) FROM sqlite_master WHERE name = 'resident_serving'", -1, &s, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_step(s) == SQLITE_ROW && sqlite3_column_int(s, 0) == 0;
    if (s && sqlite3_finalize(s) != SQLITE_OK) ok = false;
    if (db && sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}

static bool td_atomic_schema(const char *root)
{
    char dir[256], sub[320], path[384];
    (void)snprintf(dir, sizeof(dir), "%s/atomic", root);
    if (mkdir(dir, 0700) != 0) return false;
    (void)snprintf(sub, sizeof(sub), "%s/zcode", dir);
    (void)snprintf(path, sizeof(path), "%s/zcode/resident.db", dir);
    bool ok = mkdir(sub, 0700) == 0 && td_schema_seed(path);
    struct package_resident_store store = {0};
    if (ok) ok = !package_resident_store_open_task_app(&store, dir, "local/tasks").ok && !store.db;
    if (ok) ok = td_schema_rolled_back(path);
    if (unlink(path) != 0 || rmdir(sub) != 0 || rmdir(dir) != 0) ok = false;
    return ok;
}

#endif

int test_task_document(void)
{
#if defined(_WIN32)
    struct package_resident_store store = {0};
    struct task_document row = {0};
    return task_document_read(&store, &row).ok ? 1 : 0;
#else
    int failures = 0;
    /* The resident store rejects writable ancestors. Shared checkout parents
     * can be group-writable, so this security fixture uses the same private
     * system-temp boundary as test_package_resident_record and removes it. */
    char directory[] = "/tmp/z23-task-document-XXXXXX", path[256];
    if (!mkdtemp(directory)) { perror("task_document: mkdtemp"); return 1; }
    (void)snprintf(path, sizeof(path), "%s/zcode", directory);
    if (mkdir(path, 0700) != 0) { perror("task_document: mkdir"); return 1; }
    TD_CHECK("task schema failure rolls back resident schema", td_atomic_schema(directory));
    struct package_resident_store store = {0};
    struct task_document row = {0};
    struct zcl_result opened = package_resident_store_open_task_app(&store, directory, "local/tasks");
    if (!opened.ok) { fprintf(stderr, "task_document: open: %s\n", opened.message); return 1; }
    sqlite3_stmt *schema = NULL;
    TD_CHECK("task schema present immediately after open",
        sqlite3_prepare_v2(store.db, "SELECT app, payload, undo FROM task_documents",
            -1, &schema, NULL) == SQLITE_OK);
    TD_CHECK("task schema statement finalized", sqlite3_finalize(schema) == SQLITE_OK);
    failures += td_verifier_discovery(directory);
    failures += td_verifier_refusal(&store, directory);
    failures += td_verifier_kept_refusal(directory);
    failures += td_default_storage(directory);
    failures += td_stale_reload(directory);
    failures += td_confirmation_fault(directory);
    failures += td_actions(&store, &row);
    failures += td_restart(&store, directory, &row);
    failures += td_failures(&store, &row);
    failures += td_update_admission(directory);
    failures += td_editor_acceptance(directory);
    failures += td_isolation(&store, directory);
    TD_CHECK("final close", package_resident_store_close(&store).ok);
    (void)snprintf(path, sizeof(path), "%s/zcode/resident.db", directory);
    TD_CHECK("fixture database removed", unlink(path) == 0);
    (void)snprintf(path, sizeof(path), "%s/zcode", directory);
    TD_CHECK("fixture directories removed", rmdir(path) == 0 && rmdir(directory) == 0);
    return failures;
#endif
}
