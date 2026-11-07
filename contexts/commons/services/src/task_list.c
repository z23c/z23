/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: keep list selection responsive while durable task actions run. */
#include "services/task_list.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <string.h>

static void tl_select(struct task_list *list, uint32_t selected)
{
    uint32_t count = list->editor->saved.state.count;
    list->selected = count ? (selected < count ? selected : count - 1) : 0;
    list->selected_id = count ? list->editor->saved.state.tasks[list->selected].id : 0;
    if (list->selected < list->first) list->first = list->selected;
    if (list->selected >= list->first + TASK_LIST_ROWS)
        list->first = list->selected - TASK_LIST_ROWS + 1;
    list->repaint = true;
}

void task_list_refresh(struct task_list *list)
{
    if (!list || !list->editor) { LOG_ERROR("task-list", "refresh requires an owner"); return; }
    uint32_t selected = list->selected;
    for (uint32_t i = 0; i < list->editor->saved.state.count; ++i)
        if (list->editor->saved.state.tasks[i].id == list->selected_id) selected = i;
    tl_select(list, selected);
}

void task_list_init(struct task_list *list, struct task_editor *editor)
{
    if (!list || !editor) { LOG_ERROR("task-list", "initialization requires an owner"); return; }
    *list = (struct task_list){ .editor = editor, .focus = UINT32_MAX };
    tl_select(list, 0);
}

static struct zcl_result tl_failure(struct task_list *list, struct zcl_result result)
{
    list->repaint = true;
    (void)snprintf(list->notice, sizeof(list->notice), "%.127s", result.message);
    LOG_ERROR("task-list", "%s", result.message);
    return result;
}

static struct zcl_result tl_write(struct task_list *list, enum task_document_action action)
{
    struct task_editor *editor = list->editor;
    if (editor->pending) return tl_failure(list, ZCL_ERR(-1, "Wait for the current save."));
    if (action != TASK_DOCUMENT_UNDO && !list->selected_id)
        return tl_failure(list, ZCL_ERR(-1, "Add a task first."));
    struct zcl_result result = task_editor_select(editor, list->selected_id);
    if (result.ok) result = task_editor_submit(editor, action);
    if (!result.ok) return tl_failure(list, result);
    list->notice[0] = '\0';
    list->repaint = true;
    return ZCL_OK;
}

static struct zcl_result tl_edit(struct task_list *list, bool new_task)
{
    if (list->editor->pending) return tl_failure(list, ZCL_ERR(-1, "Wait for the current save."));
    if (!new_task && !list->selected_id)
        return tl_failure(list, ZCL_ERR(-1, "Choose a task to edit."));
    list->new_task = new_task;
    list->open_editor = true;
    return ZCL_OK;
}

static struct zcl_result tl_menu(struct task_list *list, uint32_t action)
{
    if (action == 0) {
        list->menu = false;
        list->repaint = true;
        return ZCL_OK;
    }
    if (action == 1) return tl_write(list, TASK_DOCUMENT_DELETE);
    if (action == 2) return tl_write(list, TASK_DOCUMENT_UNDO);
    if (list->update) {
        ZCL_CHECK(task_update_check_offer(list->update));
        list->updates = true; list->repaint = true; list->focus = 0; list->first = 0;
        return ZCL_OK;
    }
    return tl_edit(list, false);
}

struct zcl_result task_list_action(struct task_list *list, uint32_t action)
{
    if (!list || !list->editor) return ZCL_ERR(-1, "task-list: durable editor required");
    if (action >= 4) return tl_failure(list, ZCL_ERR(-1, "Unknown task action."));
    if (list->updates && list->update) return task_update_panel_action(list, action);
    if (list->menu) return tl_menu(list, action);
    if (action == 3) {
        list->menu = true;
        list->repaint = true;
        return ZCL_OK;
    }
    if (action == 2) {
        bool done = list->selected_id && list->editor->saved.state.tasks[list->selected].done;
        return tl_write(list, done ? TASK_DOCUMENT_REOPEN : TASK_DOCUMENT_COMPLETE);
    }
    return tl_edit(list, action == 0);
}

struct zcl_result task_list_poll(struct task_list *list)
{
    if (!list || !list->editor) return ZCL_ERR(-1, "task-list: durable editor required");
    bool changed = false;
    struct zcl_result result = task_editor_poll(list->editor, &changed);
    if (changed) {
        task_list_refresh(list);
        if (result.ok) list->notice[0] = '\0';
    }
    if (!result.ok) return tl_failure(list, result);
    if (list->update) {
        bool updated = false;
        result = task_update_poll(list->update, &updated);
        list->repaint |= updated;
        if (!result.ok) return tl_failure(list, result);
        if (list->update->active_valid && !list->update->pending &&
            list->update->active_revision != list->editor->saved.state.revision)
            return task_update_refresh(list->update);
    }
    return ZCL_OK;
}

static bool tl_shortcut(struct task_list *list, const struct zcl_present_input_v1 *input)
{
    struct zcl_result result = ZCL_OK;
    if (input->command && (input->character == 'z' || input->character == 'Z'))
        result = tl_write(list, TASK_DOCUMENT_UNDO);
    else if (input->command && (input->character == 'n' || input->character == 'N'))
        result = tl_edit(list, true);
    else if (input->key == ZCL_PRESENT_INPUT_DELETE && list->focus == UINT32_MAX)
        result = tl_write(list, TASK_DOCUMENT_DELETE);
    else return false; // raw-return-ok:unhandled-local-input
    if (!result.ok) LOG_ERROR("task-list", "%s", result.message);
    return true;
}

static bool tl_move(struct task_list *list, const struct zcl_present_input_v1 *input)
{
    uint32_t count = list->editor->saved.state.count, next = list->selected;
    if (!count) return false; // raw-return-ok:empty-local-list
    switch (input->key) {
    case ZCL_PRESENT_INPUT_UP: if (next) --next; break;
    case ZCL_PRESENT_INPUT_DOWN: if (next + 1 < count) ++next; break;
    case ZCL_PRESENT_INPUT_HOME: next = 0; break;
    case ZCL_PRESENT_INPUT_END: next = count - 1; break;
    case ZCL_PRESENT_INPUT_PAGE_UP: next = next > TASK_LIST_ROWS ? next - TASK_LIST_ROWS : 0; break;
    case ZCL_PRESENT_INPUT_PAGE_DOWN: next += TASK_LIST_ROWS; break;
    default: return false; // raw-return-ok:unhandled-local-input
    }
    list->focus = UINT32_MAX;
    tl_select(list, next);
    return true;
}

static bool tl_click(struct task_list *list, const struct zcl_present_input_v1 *input)
{
    if (input->key != ZCL_PRESENT_INPUT_CLICK || input->x < 36 || input->x >= 684 ||
        input->y < TASK_LIST_TOP || input->y >= TASK_LIST_TOP + TASK_LIST_ROWS * TASK_LIST_ROW_HEIGHT)
        return false; // raw-return-ok:outside-local-list
    uint32_t row = (input->y - TASK_LIST_TOP) / TASK_LIST_ROW_HEIGHT;
    if (list->first + row < list->editor->saved.state.count) tl_select(list, list->first + row);
    list->focus = UINT32_MAX;
    return true;
}

static bool tl_activate_key(const struct task_list *list,
    const struct zcl_present_input_v1 *input, uint32_t *action)
{
    if (list->focus != UINT32_MAX) return false; // raw-return-ok:content-not-focused
    if (input->key == ZCL_PRESENT_INPUT_ENTER) *action = list->updates ? 0 : list->menu ? 3 : 1;
    else if (input->key == ZCL_PRESENT_INPUT_TEXT && input->character == ' ')
        *action = list->menu ? 3 : 2;
    else return false; // raw-return-ok:unhandled-local-input
    return true;
}

static bool tl_input_valid(const struct task_list *list, const struct zcl_present_input_v1 *input,
    const uint32_t *focus, const uint32_t *action)
{
    return list && list->editor && input && focus && action;
}

bool task_list_input(void *context, const struct zcl_present_input_v1 *input,
                     uint32_t *focus, uint32_t *action)
{
    struct task_list *list = context;
    if (!tl_input_valid(list, input, focus, action)) {
        LOG_ERROR("task-list", "input requires an owner and outputs");
        return false;
    }
    list->focus = *focus;
    if (list->updates && list->update)
        return task_update_panel_input(list, input, focus, action);
    bool consumed = true;
    if (input->key == ZCL_PRESENT_INPUT_TAB) {
        uint32_t index = list->focus == UINT32_MAX ? 0 : list->focus + 1;
        index = (index + (input->shift ? 4 : 1)) % 5;
        list->focus = index ? index - 1 : UINT32_MAX;
    } else if (tl_click(list, input)) {
        /* Selection changed through the same source-space row geometry. */
    } else if (tl_activate_key(list, input, action)) {
        /* Enter edits; Space toggles completion through the same action. */
    } else if (!tl_shortcut(list, input) && !tl_move(list, input)) {
        consumed = false;
    }
    *focus = list->focus;
    list->repaint |= consumed;
    return consumed;
}

static void tl_model_rows(const struct task_list *list, struct zcl_present_model_v1 *model)
{
    uint32_t count = list->editor->saved.state.count;
    for (uint32_t i = list->first; i < count && model->item_count < TASK_LIST_ROWS; ++i) {
        struct zcl_present_model_item_v1 *item = &model->items[model->item_count++];
        const struct ta_task *task = &list->editor->saved.state.tasks[i];
        item->kind = ZCL_PRESENT_ITEM_TABLE_ROW;
        item->parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
        item->flags = i == list->selected && list->focus == UINT32_MAX ? ZCL_PRESENT_ITEM_SELECTED : 0;
        item->status = task->done ? ZCL_PRESENT_STATUS_GREEN : ZCL_PRESENT_STATUS_INFO;
        (void)snprintf(item->id, sizeof(item->id), "task-%llu", (unsigned long long)task->id);
        (void)snprintf(item->label, sizeof(item->label), "%s", task->done ? "Completed" : "Open");
        (void)snprintf(item->value, sizeof(item->value), "%s", task->title);
        task_update_row(list, i, item);
    }
}

static void tl_model_actions(const struct task_list *list, struct zcl_present_model_v1 *model)
{
    model->action_count = 4;
    const char *const normal[] = {"New task", "Edit", "Complete", "More / Undo"};
    const char *const menu[] = {"Back", "Delete", "Undo", "Edit"};
    for (unsigned i = 0; i < 4; ++i) {
        model->actions[i] = (struct zcl_present_model_action_v1){ .kind = ZCL_PRESENT_ACTION_SELECT };
        (void)snprintf(model->actions[i].id, sizeof(model->actions[i].id), "action-%u", i);
        (void)snprintf(model->actions[i].label, sizeof(model->actions[i].label), "%s", list->menu ? menu[i] : normal[i]);
    }
    if (!list->menu && list->selected_id && list->editor->saved.state.tasks[list->selected].done)
        (void)snprintf(model->actions[2].label, sizeof(model->actions[2].label), "Reopen");
    if (list->menu && list->update)
        (void)snprintf(model->actions[3].label, sizeof(model->actions[3].label), "Updates");
}

struct zcl_result task_list_model(const struct task_list *list, struct zcl_present_model_v1 *model)
{
    if (!list || !list->editor || !model) return ZCL_ERR(-1, "task-list: visual owner and output required");
    ZCL_CHECK(task_editor_model(list->editor, model));
    model->kind = ZCL_PRESENT_MODEL_TABLE;
    model->item_count = 0;
    memset(model->items, 0, sizeof(model->items));
    uint32_t count = list->editor->saved.state.count;
    (void)snprintf(model->title, sizeof(model->title), "Tasks (%u)", count);
    if (list->notice[0]) {
        char status[sizeof(model->summary)];
        (void)snprintf(status, sizeof(status), "%s", model->summary);
        (void)snprintf(model->summary, sizeof(model->summary), "%.128s: %.127s", status, list->notice);
    } else if (!count && list->editor->status == TASK_EDITOR_SAVED)
        (void)snprintf(model->summary, sizeof(model->summary), "Saved. No tasks yet - choose New task.");
    tl_model_rows(list, model);
    tl_model_actions(list, model);
    if (list->updates && list->update) task_update_panel_model(list, model);
    return ZCL_OK;
}
