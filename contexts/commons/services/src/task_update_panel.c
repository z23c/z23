/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: the native Try, Keep and Go back user actions. */
#include "services/task_list.h"
#include <stdio.h>
#include <string.h>

bool task_update_panel_input(struct task_list *list,
    const struct zcl_present_input_v1 *input, uint32_t *focus, uint32_t *action)
{
    if (input->key == ZCL_PRESENT_INPUT_TAB) {
        uint32_t current = *focus < 4 ? *focus : 3;
        *focus = (current + (input->shift ? 3u : 1u)) % 4u;
    } else if (input->key == ZCL_PRESENT_INPUT_ENTER) {
        *action = *focus < 4 ? *focus : 0;
    } else if (input->key == ZCL_PRESENT_INPUT_UP) {
        if (list->first) --list->first;
    } else if (input->key == ZCL_PRESENT_INPUT_DOWN) {
        if (list->first + TASK_LIST_ROWS < TA_MAX_TASKS) ++list->first;
    } else return false; // raw-return-ok:native-window-handles-other-panel-input
    list->focus = *focus;
    list->repaint = true;
    return true;
}

static struct zcl_result tup_ready(struct task_list *list, uint32_t action)
{
    struct task_update *update = list->update;
        if (action == 0) return task_update_keep(update);
        if (action == 1) return task_update_discard(update);
        if (action == 2) { list->permission = 1; update->offer_locked = true; }
        if (action == 3) list->updates = false;
    return ZCL_OK;
}

struct zcl_result task_update_panel_action(struct task_list *list, uint32_t action)
{
    struct task_update *update = list->update;
    list->repaint = true;
    if (list->permission) {
        unsigned permission = list->permission;
        list->permission = 0;
        update->offer_locked = false;
        if (action == 0) return task_update_try(update, true, permission == 2);
        if (action == 2) list->updates = false;
        return ZCL_OK;
    }
    if (update->pending) {
        if (action == 0) task_update_cancel(update);
        else if (action == 1) list->updates = false;
        else return ZCL_ERR(-1, "Wait for this preview to finish, or cancel it.");
    } else if (update->ready) {
        return tup_ready(list, action);
    } else {
        if (action == 0) {
            if (!update->candidate.package_root[0])
                return ZCL_ERR(-1, "No update is waiting. Ask your AI to offer an installed update, then reopen Updates.");
            list->permission = 1; update->offer_locked = true;
        }
        if (action == 1) { list->permission = 2; update->offer_locked = true; }
        if (action == 2) list->updates = false;
        if (action == 3) return task_update_discard(update);
    }
    return ZCL_OK;
}

static void tup_rows(const struct task_list *list, struct zcl_present_model_v1 *model)
{
    const struct task_update *update = list->update;
    model->item_count = 0;
    const char *line = update->ready ? update->preview : update->active;
    for (uint32_t i = 0; *line && i < list->first; ++i) {
        const char *end = strchr(line, '\n');
        line = end ? end + 1 : line + strlen(line);
    }
    while (*line && model->item_count < TASK_LIST_ROWS) {
        const char *end = strchr(line, '\n');
        size_t length = end ? (size_t)(end - line) : strlen(line);
        struct zcl_present_model_item_v1 *item = &model->items[model->item_count++];
        *item = (struct zcl_present_model_item_v1){ .kind = ZCL_PRESENT_ITEM_TABLE_ROW,
            .parent_index = ZCL_PRESENT_MODEL_PARENT_NONE, .status = ZCL_PRESENT_STATUS_INFO };
        (void)snprintf(item->id, sizeof(item->id), "preview-%u", model->item_count);
        (void)snprintf(item->label, sizeof(item->label), "%s", update->ready ? "Preview" : "Current");
        (void)snprintf(item->value, sizeof(item->value), "%.*s", (int)length, line);
        line += length + (end ? 1u : 0u);
    }
}

void task_update_panel_model(const struct task_list *list, struct zcl_present_model_v1 *model)
{
    const struct task_update *update = list->update;
    (void)snprintf(model->title, sizeof(model->title), "%s",
        list->permission ? "Allow this program to run?" : "Try / Keep / Go back");
    const char *summary = list->permission
        ? "Runs separately with copies of tasks and undo. No live data access. Going back checks current data before switching."
        : update->message;
    (void)snprintf(model->summary, sizeof(model->summary), "%s", summary);
    tup_rows(list, model);
    const char *const confirm[] = { "Allow preview", "Cancel", "Tasks", "Cancel" };
    const char *const running[] = { "Cancel preview", "Tasks", "Please wait", "Please wait" };
    const char *const ready[] = { "Keep", "Discard", "Try again", "Tasks" };
    const char *const idle[] = { "Try update", "Go back", "Tasks", "Discard" };
    const char *const *labels = list->permission ? confirm : update->pending ? running : update->ready ? ready : idle;
    for (unsigned i = 0; i < 4; ++i)
        (void)snprintf(model->actions[i].label, sizeof(model->actions[i].label), "%s", labels[i]);
    if (list->permission == 2)
        (void)snprintf(model->actions[0].label, sizeof(model->actions[0].label), "Allow and go back");
}

/* The confined program supplies the visible text; host IDs still own actions.
 * A stale render is never used to label a newer task selection. */
void task_update_row(const struct task_list *list, uint32_t index,
                     struct zcl_present_model_item_v1 *item)
{
    const struct task_update *update = list->update;
    if (!update || !update->active_valid || update->active_revision != list->editor->saved.state.revision) return;
    const char *line = update->active;
    for (uint32_t i = 0; i < index; ++i) {
        const char *end = strchr(line, '\n');
        if (!end) return;
        line = end + 1;
    }
    const char *space = strchr(line, ' '), *end = strchr(line, '\n');
    if (!space || !end || space > end) return;
    (void)snprintf(item->label, sizeof(item->label), "Task");
    (void)snprintf(item->value, sizeof(item->value), "%.*s", (int)(end - space - 1), space + 1);
}
