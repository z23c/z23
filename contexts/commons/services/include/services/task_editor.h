/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: native task drafts with asynchronous durable confirmation. */
#ifndef ZCL_SERVICES_TASK_EDITOR_H
#define ZCL_SERVICES_TASK_EDITOR_H
#include "models/task_document.h"
#include "presentation/presentation.h"
#include "presentation/model.h"

struct task_editor_save;
/* NEW is a new task with nothing durable yet; a draft is unsaved exactly while
 * its title differs from the saved one. */
enum task_editor_status { TASK_EDITOR_SAVED, TASK_EDITOR_UNSAVED,
                          TASK_EDITOR_SAVING, TASK_EDITOR_FAILED, TASK_EDITOR_NEW };
struct task_editor {
    struct task_document saved;
    struct zcl_present_window_form_v1 form;
    struct task_editor_save *pending;
    uint64_t selected_id, edit_serial;
    bool dirty, closing;
    char observed[ZCL_PRESENT_WINDOW_FORM_VALUE_MAX + 1u];
    enum task_editor_status status;
    char directory[4096], app[256], failure[ZCL_RESULT_MSG_MAX];
};
/* The host has already created the private application directory. */
struct zcl_result task_editor_open(struct task_editor *editor,
    const char *directory, const char *app);
struct zcl_result task_editor_select(struct task_editor *editor, uint64_t id);
struct zcl_result task_editor_type(struct task_editor *editor,
    uint8_t character, bool backspace);
/* ADD/EDIT use the current title draft; other actions require a saved draft. */
struct zcl_result task_editor_submit(struct task_editor *editor,
    enum task_document_action action);
/* Never waits for database work. A completed older save cannot mark a newer
 * draft Saved. Changed reports a consumed completion, including failure. */
struct zcl_result task_editor_poll(struct task_editor *editor, bool *changed);
struct zcl_result task_editor_request_close(struct task_editor *editor);
/* Explicit failed-save recovery: reload durable state before discarding a draft. */
struct zcl_result task_editor_discard_reload(struct task_editor *editor);
struct zcl_result task_editor_model(const struct task_editor *editor,
    struct zcl_present_model_v1 *model);
struct zcl_result task_editor_window_run(struct task_editor *editor);
struct zcl_result task_editor_window_back(struct task_editor *editor, bool *back);
/* Close calls this on the owner thread: finish the pending save, then commit
 * a newer draft once. Failure retains the draft and asks the host to stay open. */
struct zcl_result task_editor_finish(struct task_editor *editor);
#endif
