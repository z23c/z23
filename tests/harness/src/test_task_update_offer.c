/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: verify inert proposals survive restart and reject stale writers. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"
#include "models/task_update_offer.h"
#include "models/task_document.h"
#include "services/task_list.h"
#include "config/command_catalog.h"
#include "platform/temp_directory.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <paths.h>
#include <sys/stat.h>
#include <unistd.h>

#define OFFER_CHECK(label, expression) do { \
    bool ok = (expression); \
    printf("task_update_offer: %s... %s\n", label, ok ? "OK" : "FAIL"); \
    if (!ok) ++failures; \
} while (0)

static int offer_refuse_commit(void *context) { (void)context; return 1; }

static int offer_panel_reopen(const char *directory, struct package_resident_store *store,
    const struct package_resident_identity *first, const struct package_resident_identity *second)
{
    int failures = 0;
    struct task_update_offer row = {0};
    struct task_update explicit_update = {0}, reopened = {0};
    OFFER_CHECK("reopen discovers newer", task_update_open(&reopened, directory, store->app, "/missing/verifier", NULL).ok &&
        task_update_check_offer(&reopened).ok && package_resident_identity_equal(&reopened.candidate, second));
    OFFER_CHECK("explicit selection takes priority", task_update_open(&explicit_update, directory, store->app, "/missing/verifier", first).ok &&
        task_update_check_offer(&explicit_update).ok && package_resident_identity_equal(&explicit_update.candidate, first));
    OFFER_CHECK("nonexistent installed artifact refused", !task_update_offer_submit(store, directory, 2, first, &row).ok &&
        task_update_offer_read(store, &row).ok && row.revision == 2);
    return failures;
}

static int offer_panel_discard(struct package_resident_store *store,
    const struct package_resident_identity *second, struct task_list *list, struct task_update *update)
{
    int failures = 0;
    struct task_update_offer row = {0};
    OFFER_CHECK("cancel returns control", task_list_action(list, 1).ok && !list->permission && !update->offer_locked && !update->pending);
    OFFER_CHECK("discard old preserves newer", task_list_action(list, 3).ok && task_update_offer_read(store, &row).ok &&
        row.revision == 2 && !row.dismissed && package_resident_identity_equal(&row.candidate, second));
    return failures;
}

static int offer_panel_consent(const char *directory, struct package_resident_store *store,
    const struct package_resident_identity *first, const struct package_resident_identity *second,
    struct task_list *list, struct task_update *update)
{
    int failures = 0;
    struct task_update_offer row = {0};
    OFFER_CHECK("consent locks offer", task_list_action(list, 0).ok && list->permission && update->offer_locked && !update->pending);
    OFFER_CHECK("newer offer cannot replace consent", task_update_offer_save(store, 1, second, &row).ok &&
        task_update_check_offer(update).ok && package_resident_identity_equal(&update->candidate, first));
    failures += offer_panel_discard(store, second, list, update);
    failures += offer_panel_reopen(directory, store, first, second);
    return failures;
}

static int offer_panel(const char *directory, struct package_resident_store *store,
    const struct package_resident_identity *first, const struct package_resident_identity *second)
{
    int failures = 0;
    struct task_update_offer row = {0};
    struct task_update update = {0};
    struct task_editor editor = {0};
    struct task_list list;
    OFFER_CHECK("panel owner opens empty", task_update_open(&update, directory, store->app, "/missing/verifier", NULL).ok &&
        task_editor_open(&editor, directory, store->app).ok);
    task_list_init(&list, &editor); list.update = &update;
    OFFER_CHECK("offer after open", task_update_offer_save(store, 0, first, &row).ok);
    OFFER_CHECK("More Updates discovers offer", task_list_action(&list, 3).ok && task_list_action(&list, 3).ok &&
        list.updates && package_resident_identity_equal(&update.candidate, first) && !update.pending);
    failures += offer_panel_consent(directory, store, first, second, &list, &update);
    OFFER_CHECK("editor finished", task_editor_finish(&editor).ok);
    return failures;
}

static bool offer_empty_text(const struct json_value *data, const char *key)
{
    const char *value = json_get_str(json_get(data, key));
    return value && !*value;
}

static bool offer_empty_status(const struct json_value *data)
{
    const struct json_value *kept = json_get(data, "has_kept_program");
    return !json_get(data, "tasks") && json_get_int(json_get(data, "offer_revision")) == 0 &&
        kept && !json_get_bool(kept) && json_get_int(json_get(data, "kept_generation")) == 0 &&
        json_get_int(json_get(data, "kept_configuration_generation")) == 0 &&
        offer_empty_text(data, "kept_root") && offer_empty_text(data, "kept_receipt") &&
        offer_empty_text(data, "kept_program") && offer_empty_text(data, "kept_artifact_sha3");
}

static bool offer_command(const char *directory, const char *action, bool success)
{
    char body[2048];
    int n = strcmp(action, "offer-status") == 0
        ? snprintf(body, sizeof(body), "{\"datadir\":\"%s\",\"app\":\"local/command-offer\",\"action\":\"offer-status\"}", directory)
        : snprintf(body, sizeof(body), "{\"datadir\":\"%s\",\"app\":\"local/command-offer\",\"action\":\"offer\",\"expected_offer_revision\":0,\"preview_root\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"preview_receipt\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"preview_program\":\"bin/ztasks\"}", directory);
    struct json_value input = {0};
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), "app.tasks", NULL);
    struct zcl_command_request request = { .spec = spec, .input = &input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.task_document.v1");
    char error[256] = {0};
    bool ok = n > 0 && (size_t)n < sizeof(body) && spec && json_read(&input, body, (size_t)n) &&
        zcl_command_registry_input_validate(spec, &input, error, sizeof(error));
    if (!ok) fprintf(stderr, "task-update-offer %s: registry refused: %s\n", action, error);
    if (ok) spec->handler(&request, &reply);
    ok = ok && ((reply.exit_code == 0) == success);
    if (ok && !success) ok = strcmp(reply.error.code, "TASK_SAVE_FAILED") == 0 && reply.error.message[0];
    if (!ok) fprintf(stderr, "task-update-offer %s: reply exit=%d code=%s message=%s\n",
                     action, reply.exit_code, reply.error.code, reply.error.message);
    if (ok && success) ok = offer_empty_status(&reply.data);
    zcl_command_reply_free(&reply); json_free(&input);
    return ok;
}

static int offer_invalid_candidates(struct package_resident_store *store,
    struct task_update_offer *row, const struct package_resident_identity *first)
{
    int failures = 0;
    struct package_resident_identity invalid = *first;
    invalid.package_root[0] = 'A';
    OFFER_CHECK("reject uppercase digest", !task_update_offer_save(store, 2, &invalid, row).ok);
    invalid = *first; (void)snprintf(invalid.program, sizeof(invalid.program), "bin/../bad");
    OFFER_CHECK("reject unsafe program", !task_update_offer_save(store, 2, &invalid, row).ok);
    invalid = *first; invalid.configuration_generation = -1;
    OFFER_CHECK("reject negative configuration", !task_update_offer_save(store, 2, &invalid, row).ok);
    return failures;
}

static int offer_model_basics(struct package_resident_store *store, struct task_update_offer *row,
    struct task_update_offer *observed, struct package_resident_record *before,
    struct task_document *tasks, const struct package_resident_identity *first,
    const struct package_resident_identity *second)
{
    int failures = 0;
    OFFER_CHECK("fresh", task_update_offer_read(store, row).ok && row->revision == 0 && row->dismissed);
    OFFER_CHECK("task fixture", task_document_apply(store, 0, TASK_DOCUMENT_ADD, 0, "Retain me", tasks).ok);
    OFFER_CHECK("acceptance before", package_resident_record_read(store, before).ok);
    OFFER_CHECK("save", task_update_offer_save(store, 0, first, row).ok && row->revision == 1 && !row->dismissed);
    struct zcl_result stale = task_update_offer_save(store, 0, second, observed);
    OFFER_CHECK("stale save", !stale.ok && stale.code == TASK_UPDATE_OFFER_STALE);
    OFFER_CHECK("replace", task_update_offer_save(store, 1, second, row).ok && row->revision == 2);
    stale = task_update_offer_dismiss(store, 1, observed);
    OFFER_CHECK("stale dismissal preserves replacement", !stale.ok && stale.code == TASK_UPDATE_OFFER_STALE &&
        task_update_offer_read(store, observed).ok && !observed->dismissed &&
        package_resident_identity_equal(&observed->candidate, second));
    failures += offer_invalid_candidates(store, row, first);
    return failures;
}

static int offer_unchanged_checks(struct package_resident_store *store,
    const struct package_resident_record *before, struct package_resident_record *after,
    struct task_document *tasks)
{
    int failures = 0;
    OFFER_CHECK("acceptance unchanged", package_resident_record_read(store, after).ok &&
        before->revision == after->revision && before->generation == after->generation &&
        package_resident_identity_equal(&before->current, &after->current));
    OFFER_CHECK("tasks unchanged", task_document_read(store, tasks).ok && tasks->state.revision == 1 &&
        tasks->state.count == 1 && strcmp(tasks->state.tasks[0].title, "Retain me") == 0);
    return failures;
}

static int offer_commit_checks(struct package_resident_store *store, struct task_update_offer *row,
    struct task_update_offer *observed, const struct package_resident_record *before,
    struct package_resident_record *after, struct task_document *tasks,
    const struct package_resident_identity *second)
{
    int failures = 0;
    sqlite3_commit_hook(store->db, offer_refuse_commit, NULL);
    struct zcl_result refused = task_update_offer_dismiss(store, 2, row);
    sqlite3_commit_hook(store->db, NULL, NULL);
    OFFER_CHECK("failed commit preserves offer", !refused.ok && task_update_offer_read(store, observed).ok &&
        observed->revision == 2 && !observed->dismissed && package_resident_identity_equal(&observed->candidate, second));
    OFFER_CHECK("dismiss", task_update_offer_dismiss(store, 2, row).ok && row->revision == 3 && row->dismissed);
    failures += offer_unchanged_checks(store, before, after, tasks);
    return failures;
}

static int offer_command_checks(const char *directory)
{
    int failures = 0;
    OFFER_CHECK("native status omits task contents", offer_command(directory, "offer-status", true));
    OFFER_CHECK("native invalid offer refused", offer_command(directory, "offer", false));
    OFFER_CHECK("native invalid offer leaves no record", offer_command(directory, "offer-status", true));
    return failures;
}

static int offer_restart_checks(const char *directory, char *path, size_t path_size,
    struct package_resident_store *store, struct task_update_offer *row,
    const struct package_resident_identity *second)
{
    int failures = 0;
    OFFER_CHECK("close", package_resident_store_close(store).ok);
    OFFER_CHECK("restart", package_resident_store_open_app(store, directory, "local/tasks").ok &&
        task_update_offer_read(store, row).ok && row->revision == 3 && row->dismissed &&
        package_resident_identity_equal(&row->candidate, second));
    OFFER_CHECK("final close", package_resident_store_close(store).ok);
    (void)snprintf(path, path_size, "%s/zcode/resident.db", directory);
    OFFER_CHECK("remove database", unlink(path) == 0);
    (void)snprintf(path, path_size, "%s/zcode", directory);
    OFFER_CHECK("remove fixture", rmdir(path) == 0 && rmdir(directory) == 0);
    return failures;
}

int test_task_update_offer(void)
{
    int failures = 0;
    /* The resident-store gate rejects group-writable checkout ancestors.
     * Use an isolated owner-private child of the system temp directory, as
     * the resident fixtures do; the store still validates all ancestors. */
    char temporary[PLATFORM_TEMP_PATH_MAX], directory[PATH_MAX], path[PATH_MAX + 32];
    if (!platform_temp_directory_create_under(_PATH_TMP, "z23-task-offer-", temporary, sizeof(temporary))) {
        perror("task-update-offer: private temp"); return 1;
    }
    if (!realpath(temporary, directory)) {
        perror("task-update-offer: realpath"); (void)test_rm_rf_recursive(temporary); return 1;
    }
    (void)snprintf(path, sizeof(path), "%s/zcode", directory);
    if (mkdir(path, 0700) != 0) {
        perror("task-update-offer: mkdir"); (void)test_rm_rf_recursive(directory); return 1;
    }
    struct package_resident_store store = {0}, other = {0};
    struct task_update_offer row = {0}, observed = {0};
    struct package_resident_record before = {0}, after = {0};
    struct task_document tasks = {0};
    struct package_resident_identity first = {0}, second = {0};
    memset(first.package_root, 'a', 64); memset(first.receipt_id, 'b', 64);
    memset(first.artifact_sha3, 'c', 64);
    (void)snprintf(first.program, sizeof(first.program), "bin/ztasks");
    first.configuration_generation = 1;
    second = first; second.artifact_sha3[0] = 'd';
    failures += offer_command_checks(directory);
    struct zcl_result opened = package_resident_store_open_app(&other, directory, "local/panel");
    OFFER_CHECK("panel app open", opened.ok);
    if (!opened.ok) { fprintf(stderr, "task-update-offer: panel open: %s\n", opened.message); goto open_failed; }
    failures += offer_panel(directory, &other, &first, &second);
    OFFER_CHECK("panel app close", package_resident_store_close(&other).ok);
    opened = package_resident_store_open_app(&store, directory, "local/tasks");
    OFFER_CHECK("open", opened.ok);
    if (!opened.ok) { fprintf(stderr, "task-update-offer: open: %s\n", opened.message); goto open_failed; }
    failures += offer_model_basics(&store, &row, &observed, &before, &tasks, &first, &second);
    opened = package_resident_store_open_app(&other, directory, "local/other");
    OFFER_CHECK("other app open", opened.ok);
    if (!opened.ok) { fprintf(stderr, "task-update-offer: other open: %s\n", opened.message); goto open_failed; }
    OFFER_CHECK("app isolation", task_update_offer_read(&other, &observed).ok && observed.revision == 0 && observed.dismissed);
    OFFER_CHECK("other close", package_resident_store_close(&other).ok);
    failures += offer_commit_checks(&store, &row, &observed, &before, &after, &tasks, &second);
    failures += offer_restart_checks(directory, path, sizeof(path), &store, &row, &second);
    return failures;
open_failed:
    if (!package_resident_store_close(&other).ok) ++failures;
    if (!package_resident_store_close(&store).ok) ++failures;
    if (test_rm_rf_recursive(directory) != 0) {
        fprintf(stderr, "task-update-offer: fixture cleanup failed: %s\n", directory);
        ++failures;
    }
    return failures;
}
#else
int test_task_update_offer(void) { return 0; }
#endif
