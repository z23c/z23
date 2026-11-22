/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: keep task typing independent of durable database writes. */
#include "services/task_editor.h"
#include "base/safe_alloc.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One finite transaction per window-owned job, never a resident service.
 * The editor retains the tid and joins it on completion or close. */
// supervisor-ok:window-owned-bounded-save

struct task_editor_save {
    pthread_t thread;
    atomic_bool completed;
    enum task_document_action action;
    uint64_t revision, id, serial;
    char directory[4096], app[256], title[TA_TITLE];
    struct task_document saved;
    struct zcl_result result;
};

static struct zcl_result te_failure(struct task_editor *editor,
                                     struct zcl_result result)
{
    editor->status = TASK_EDITOR_FAILED;
    editor->closing = false;
    (void)snprintf(editor->failure, sizeof(editor->failure), "%s", result.message);
    LOG_ERROR("task-editor", "%s", result.message);
    return result;
}

static void *te_write(void *opaque)
{
    struct task_editor_save *job = opaque;
    struct package_resident_store store = {0};
    job->result = package_resident_store_open_task_app(&store, job->directory, job->app);
    if (job->result.ok)
        job->result = task_document_apply(&store, job->revision, job->action,
            job->id, job->title, &job->saved);
    struct zcl_result closed = package_resident_store_close(&store);
    if (job->result.ok && !closed.ok) job->result = closed;
    /* SQLite work is complete before publication. The owner retains the
     * thread and its result until the registered worker has been joined. */
    atomic_store_explicit(&job->completed, true, memory_order_release);
    return NULL;
}

static const struct ta_task *te_selected(const struct task_editor *editor, uint64_t id)
{
    for (uint32_t i = 0; i < editor->saved.state.count; ++i)
        if (editor->saved.state.tasks[i].id == id) return &editor->saved.state.tasks[i];
    return NULL;
}

static void te_observe(struct task_editor *editor)
{
    if (strcmp(editor->observed, editor->form.fields[0].value) == 0) return;
    (void)snprintf(editor->observed, sizeof(editor->observed), "%s",
                   editor->form.fields[0].value);
    if (editor->edit_serial != UINT64_MAX) ++editor->edit_serial;
    editor->dirty = true;
    editor->failure[0] = '\0';
    editor->status = editor->pending ? TASK_EDITOR_SAVING : TASK_EDITOR_UNSAVED;
}

static void te_title(struct task_editor *editor)
{
    const struct ta_task *task = te_selected(editor, editor->selected_id);
    if (!task) editor->selected_id = 0;
    (void)snprintf(editor->form.fields[0].value,
        sizeof(editor->form.fields[0].value), "%s", task ? task->title : "");
    (void)snprintf(editor->observed, sizeof(editor->observed), "%s",
                   editor->form.fields[0].value);
}

static struct zcl_result te_read(const char *directory, const char *app, struct task_document *saved)
{
    struct package_resident_store store = {0};
    struct zcl_result result = package_resident_store_open_task_app(&store, directory, app);
    if (result.ok) result = task_document_read(&store, saved);
    struct zcl_result closed = package_resident_store_close(&store);
    if (result.ok && !closed.ok) result = closed;
    return result;
}

struct zcl_result task_editor_open(struct task_editor *editor,
    const char *directory, const char *app)
{
    if (!editor || !directory || !app || strlen(directory) >= sizeof(editor->directory) ||
        strlen(app) >= sizeof(editor->app))
        return ZCL_ERR(-1, "task-editor: bounded application directory and identity required");
    struct task_document saved;
    struct zcl_result result = te_read(directory, app, &saved);
    if (!result.ok) return result;
    *editor = (struct task_editor){ .saved = saved, .status = TASK_EDITOR_SAVED };
    editor->form = (struct zcl_present_window_form_v1){
        .struct_size = sizeof(editor->form), .abi_version = ZCL_PRESENT_ABI_V1,
        .field_count = 1 };
    editor->form.fields[0].flags = ZCL_PRESENT_WINDOW_FORM_REQUIRED;
    (void)snprintf(editor->directory, sizeof(editor->directory), "%s", directory);
    (void)snprintf(editor->app, sizeof(editor->app), "%s", app);
    return ZCL_OK;
}

struct zcl_result task_editor_select(struct task_editor *editor, uint64_t id)
{
    if (!editor || editor->pending || editor->dirty)
        return ZCL_ERR(-1, "task-editor: save the current draft before changing selection");
    if (id && !te_selected(editor, id))
        return ZCL_ERR(-1, "task-editor: selected task no longer exists");
    editor->selected_id = id;
    editor->closing = false;
    te_title(editor);
    editor->failure[0] = '\0';
    editor->status = TASK_EDITOR_SAVED;
    return ZCL_OK;
}

struct zcl_result task_editor_type(struct task_editor *editor,
    uint8_t character, bool backspace)
{
    if (!editor || editor->edit_serial == UINT64_MAX)
        return ZCL_ERR(-1, "task-editor: edit state is unavailable or exhausted");
    if (!zcl_present_window_form_edit_v1(&editor->form, 0, character, backspace))
        return ZCL_OK;
    te_observe(editor);
    return ZCL_OK;
}

struct zcl_result task_editor_submit(struct task_editor *editor,
    enum task_document_action action)
{
    if (!editor || editor->pending)
        return ZCL_ERR(-1, "task-editor: a save is already pending");
    te_observe(editor);
    if (editor->edit_serial == UINT64_MAX)
        return te_failure(editor, ZCL_ERR(-1, "task-editor: edit sequence exhausted; preserve the draft"));
    bool title_action = action == TASK_DOCUMENT_ADD || action == TASK_DOCUMENT_EDIT;
    if (!title_action && editor->dirty)
        return ZCL_ERR(-1, "task-editor: save the current title before this action");
    if (title_action && !ta_title_valid(editor->form.fields[0].value))
        return te_failure(editor, ZCL_ERR(-1,
            "Enter visible task text, up to 95 Basic Latin characters."));
    struct task_editor_save *job = zcl_calloc(1, sizeof(*job), "task save worker");
    if (!job) return te_failure(editor, ZCL_ERR(-1, "task-editor: save allocation failed"));
    job->action = action;
    job->revision = editor->saved.state.revision;
    job->id = editor->selected_id;
    job->serial = editor->edit_serial;
    (void)snprintf(job->directory, sizeof(job->directory), "%s", editor->directory);
    (void)snprintf(job->app, sizeof(job->app), "%s", editor->app);
    if (title_action) memcpy(job->title, editor->form.fields[0].value,
        strlen(editor->form.fields[0].value) + 1);
    atomic_init(&job->completed, false);
    // thread-supervision-ok:bounded-one-shot owner joins this finite SQLite transaction
    int rc = thread_registry_spawn("task-save", te_write, job, &job->thread);
    if (rc) {
        free(job);
        return te_failure(editor, ZCL_ERR(rc, "task-editor: could not start save worker"));
    }
    editor->pending = job;
    editor->status = TASK_EDITOR_SAVING;
    editor->failure[0] = '\0';
    return ZCL_OK;
}

static struct zcl_result te_receive(struct task_editor *editor)
{
    struct task_editor_save *job = editor->pending;
    int rc = pthread_join(job->thread, NULL);
    if (rc) return te_failure(editor, ZCL_ERR(rc, "task-editor: save worker release failed"));
    struct zcl_result result = job->result;
    if (result.ok) {
        editor->saved = job->saved;
        if (job->action == TASK_DOCUMENT_ADD) editor->selected_id = job->revision + 1;
        editor->dirty = editor->edit_serial == UINT64_MAX || editor->edit_serial != job->serial;
        if (!editor->dirty) te_title(editor);
        editor->status = editor->dirty ? TASK_EDITOR_UNSAVED : TASK_EDITOR_SAVED;
    }
    editor->pending = NULL;
    free(job);
    return result.ok ? result : te_failure(editor, result);
}

struct zcl_result task_editor_poll(struct task_editor *editor, bool *changed)
{
    if (!editor || !changed) return ZCL_ERR(-1, "task-editor: completion output required");
    te_observe(editor);
    *changed = false;
    if (editor->pending && atomic_load_explicit(&editor->pending->completed,
                                               memory_order_acquire)) {
        *changed = true;
        ZCL_CHECK(te_receive(editor));
    }
    if (editor->closing && !editor->pending && editor->dirty)
        return task_editor_submit(editor,
            editor->selected_id ? TASK_DOCUMENT_EDIT : TASK_DOCUMENT_ADD);
    return ZCL_OK;
}

struct zcl_result task_editor_request_close(struct task_editor *editor)
{
    if (!editor) return ZCL_ERR(-1, "task-editor: owner required");
    te_observe(editor);
    editor->closing = true;
    if (editor->pending || !editor->dirty) return ZCL_OK;
    return task_editor_submit(editor,
        editor->selected_id ? TASK_DOCUMENT_EDIT : TASK_DOCUMENT_ADD);
}

struct zcl_result task_editor_discard_reload(struct task_editor *editor)
{
    if (!editor || editor->pending || editor->status != TASK_EDITOR_FAILED)
        return ZCL_ERR(-1, "task-editor: discard is available after a failed save");
    struct task_document saved;
    struct zcl_result result = te_read(editor->directory, editor->app, &saved);
    if (!result.ok) return te_failure(editor, result);
    editor->saved = saved;
    te_title(editor);
    editor->dirty = false;
    editor->failure[0] = '\0';
    editor->status = TASK_EDITOR_SAVED;
    editor->closing = true;
    return ZCL_OK;
}

struct zcl_result task_editor_finish(struct task_editor *editor)
{
    if (!editor) return ZCL_ERR(-1, "task-editor: owner required");
    te_observe(editor);
    if (editor->pending) ZCL_CHECK(te_receive(editor));
    if (editor->dirty) {
        ZCL_CHECK(task_editor_submit(editor,
            editor->selected_id ? TASK_DOCUMENT_EDIT : TASK_DOCUMENT_ADD));
        ZCL_CHECK(te_receive(editor));
    }
    return ZCL_OK;
}
