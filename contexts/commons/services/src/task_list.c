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

/* A held refusal or a report has been read once the user acts again. */
static void tl_read_notice(struct task_list *list)
{
    if (!list->notice_held && !list->notice_report) return;
    list->notice_held = false;
    list->notice_report = false;
    list->notice[0] = '\0';
    list->repaint = true;
}

static struct zcl_result tl_report(struct task_list *list, struct zcl_result result,
    const char *text)
{
    list->repaint = true;
    list->notice_held = true;
    list->notice_report = false;
    (void)snprintf(list->notice, sizeof(list->notice), "%.127s", text);
    LOG_ERROR("task-list", "%s", result.message);
    return result;
}

/* The save worker names its origin first; the user needs only the reason. */
static const char *tl_reason(const char *text)
{
    if (strncmp(text, "task-", 5) != 0) return text;
    size_t i = 5;
    while ((text[i] >= 'a' && text[i] <= 'z') || text[i] == '-') ++i;
    return text[i] == ':' && text[i + 1] == ' ' ? text + i + 2 : text;
}

/* Writes a reason into a 128-byte buffer, starting it with a capital. */
static void tl_plain(char *out, const char *text)
{
    (void)snprintf(out, 128, "%.127s", text);
    if (*out >= 'a' && *out <= 'z') *out = (char)(*out - 'a' + 'A');
}

/* A refused action stays visible until the next input. */
static struct zcl_result tl_failure(struct task_list *list, struct zcl_result result)
{
    char reason[128];
    tl_plain(reason, tl_reason(result.message));
    return tl_report(list, result, reason);
}

/* A failed save leaves later actions chosen against state that never landed. */
static struct zcl_result tl_save_failed(struct task_list *list, struct zcl_result result)
{
    if (!list->queued) return tl_failure(list, result);
    char reason[128], text[128];
    tl_plain(reason, tl_reason(result.message));
    (void)snprintf(text, sizeof(text), "%.89s; %u later action%s not applied",
        reason, list->queued, list->queued == 1u ? "" : "s");
    list->queued = 0;
    return tl_report(list, result, text);
}

/* One action through the same select-and-save path, now or when drained.
 * Undo names no task: the row it was pressed on may be gone by the time a
 * waiting Undo applies. */
static struct zcl_result tl_apply(struct task_list *list, uint64_t id,
    enum task_document_action action)
{
    struct task_editor *editor = list->editor;
    struct zcl_result result = ZCL_OK;
    if (action != TASK_DOCUMENT_UNDO) result = task_editor_select(editor, id);
    if (result.ok) result = task_editor_submit(editor, action);
    if (!result.ok) return tl_save_failed(list, result);
    /* Delete and Undo change what the user sees without a row saying so. */
    list->announce = action == TASK_DOCUMENT_DELETE ? "Deleted. Cmd/Ctrl+Z undoes."
        : action == TASK_DOCUMENT_UNDO ? "Undone." : NULL;
    list->repaint = true;
    return ZCL_OK;
}

/* A queued toggle is read against the state the previous save produced. */
static enum task_document_action tl_fresh(const struct task_list *list, uint64_t id,
    enum task_document_action action)
{
    if (action != TASK_DOCUMENT_COMPLETE && action != TASK_DOCUMENT_REOPEN) return action;
    const struct task_document *saved = &list->editor->saved;
    for (uint32_t i = 0; i < saved->state.count; ++i)
        if (saved->state.tasks[i].id == id)
            return saved->state.tasks[i].done ? TASK_DOCUMENT_REOPEN : TASK_DOCUMENT_COMPLETE;
    return action;
}

/* An action on a task that does not exist can never apply, so it is refused
 * before it could wait behind a save. */
static struct zcl_result tl_write(struct task_list *list, enum task_document_action action)
{
    struct task_editor *editor = list->editor;
    if (action != TASK_DOCUMENT_UNDO && !list->selected_id)
        return tl_failure(list, ZCL_ERR(-1, "Add a task first."));
    if (editor->pending) {
        if (list->queued == TASK_LIST_QUEUED_MAX)
            return tl_failure(list, ZCL_ERR(-1, "Wait for the current save."));
        /* Undo ignores the id, so it is not bound to the row chosen then. */
        list->queue[list->queued++] = (struct task_list_queued){
            .id = action == TASK_DOCUMENT_UNDO ? 0 : list->selected_id, .action = action };
        return ZCL_OK;
    }
    list->notice[0] = '\0';
    list->notice_held = false;
    list->notice_report = false;
    return tl_apply(list, list->selected_id, action);
}

/* The oldest waiting action starts once the editor is idle, so each one is
 * read against the state the previous save produced. */
static struct zcl_result tl_drain(struct task_list *list)
{
    if (!list->queued || list->editor->pending) return ZCL_OK;
    struct task_list_queued next = list->queue[0];
    --list->queued;
    memmove(list->queue, list->queue + 1, list->queued * sizeof(list->queue[0]));
    return tl_apply(list, next.id, tl_fresh(list, next.id, next.action));
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
    tl_read_notice(list);
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

static void tl_adopt_update(struct task_list *list)
{
    struct task_editor *editor = list->editor;
    if (list->update->active_document.state.revision > editor->saved.state.revision &&
        !editor->pending && !editor->dirty && !editor->closing && editor->status == TASK_EDITOR_SAVED) {
        editor->saved = list->update->active_document;
        task_list_refresh(list);
    }
}

static void tl_update_result(struct task_list *list, struct zcl_result result, bool updated)
{
    bool previous = list->update_ack_error;
    if (!result.ok) list->update_ack_error = list->update->phase == TASK_UPDATE_KEPT;
    else if (updated || list->update->pending || list->update->phase == TASK_UPDATE_RUNNING ||
             list->update->phase == TASK_UPDATE_KEEPING || list->update->phase == TASK_UPDATE_CANCELLED)
        list->update_ack_error = false;
    if (previous != list->update_ack_error) list->repaint = true;
}

/* A landed save refreshes the rows and reports what it did until the next
 * input. A refusal already shown is not displaced. */
static void tl_landed(struct task_list *list, bool ok)
{
    task_list_refresh(list);
    if (!ok || list->notice_held) { list->announce = NULL; return; }
    list->notice[0] = '\0';
    list->notice_report = list->announce != NULL;
    if (list->announce)
        (void)snprintf(list->notice, sizeof(list->notice), "%.127s", list->announce);
    list->announce = NULL;
}

struct zcl_result task_list_poll(struct task_list *list)
{
    if (!list || !list->editor) return ZCL_ERR(-1, "task-list: durable editor required");
    bool changed = false;
    struct zcl_result result = task_editor_poll(list->editor, &changed);
    if (changed) tl_landed(list, result.ok);
    if (!result.ok) return tl_save_failed(list, result);
    result = tl_drain(list);
    if (!result.ok) return result;
    if (list->update) {
        bool updated = false;
        result = task_update_poll(list->update, &updated);
        list->repaint |= updated;
        tl_update_result(list, result, updated);
        if (!result.ok) { list->repaint = true; return result; }
        if (list->update->active_valid && !list->update->pending) {
            tl_adopt_update(list);
            if (list->update->active_document.state.revision < list->editor->saved.state.revision) {
                result = task_update_refresh(list->update);
                tl_update_result(list, result, false);
                if (!result.ok) list->repaint = true;
                return result;
            }
        }
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

/* With no tasks there are no rows for Tab to stop on. */
static void tl_tab(struct task_list *list, const struct zcl_present_input_v1 *input)
{
    uint32_t index = list->focus == UINT32_MAX ? 0 : list->focus + 1;
    index = (index + (input->shift ? 4 : 1)) % 5;
    if (!index && !list->editor->saved.state.count) index = input->shift ? 4 : 1;
    list->focus = index ? index - 1 : UINT32_MAX;
}

bool task_list_input(void *context, const struct zcl_present_input_v1 *input,
                     uint32_t *focus, uint32_t *action)
{
    struct task_list *list = context;
    if (!tl_input_valid(list, input, focus, action)) {
        LOG_ERROR("task-list", "input requires an owner and outputs");
        return false;
    }
    tl_read_notice(list);
    list->focus = *focus;
    if (list->updates && list->update)
        return task_update_panel_input(list, input, focus, action);
    bool consumed = true;
    if (input->key == ZCL_PRESENT_INPUT_TAB) {
        tl_tab(list, input);
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

static bool tl_update_ack_error_visible(const struct task_list *list)
{
    return !list->updates && list->update && list->update->message[0] &&
        list->editor->status == TASK_EDITOR_SAVED &&
        (list->update->phase == TASK_UPDATE_FAILED ||
         (list->update->phase == TASK_UPDATE_KEPT && list->update_ack_error));
}

/* The confined render belongs only to the exact state and Undo it observed. */
static bool tl_same_state(const struct ta_state *a, const struct ta_state *b)
{
    unsigned char left[TA_PAYLOAD], right[TA_PAYLOAD]; uint32_t ln = 0, rn = 0;
    return ta_state_encode(a, left, &ln) && ta_state_encode(b, right, &rn) &&
        ln == rn && !memcmp(left, right, ln);
}
static bool tl_empty_render(const struct task_list *list, struct zcl_present_model_v1 *model)
{
    const struct task_update *update = list->update;
    const struct task_document *saved = &list->editor->saved;
    if (!update || !update->active_valid || update->active_document.state.count ||
        update->active_document.can_undo != saved->can_undo ||
        !tl_same_state(&update->active_document.state, &saved->state) ||
        !tl_same_state(&update->active_document.undo, &saved->undo)) return false;
    const char *end = memchr(update->active, 0, sizeof(update->active));
    if (!end) return false;
    size_t n = (size_t)(end - update->active);
    if (n && update->active[n - 1] == '\n') --n;
    if (!n || n >= sizeof(model->summary)) return false;
    for (size_t i = 0; i < n; ++i)
        if ((unsigned char)update->active[i] < 32 || (unsigned char)update->active[i] > 126) return false;
    memcpy(model->summary, update->active, n); model->summary[n] = 0;
    return true;
}

/* Once the rows no longer all show, the title counts what it hides. */
static void tl_title(const struct task_list *list, struct zcl_present_model_v1 *model)
{
    uint32_t count = list->editor->saved.state.count, first = list->first + 1u;
    if (count <= TASK_LIST_ROWS) {
        (void)snprintf(model->title, sizeof(model->title), "Tasks (%u)", count);
        return;
    }
    (void)snprintf(model->title, sizeof(model->title), "Tasks (%u), showing %u-%u",
        count, first, first + TASK_LIST_ROWS <= count ? first + TASK_LIST_ROWS - 1u : count);
}

/* A notice or a failure is shown beside the save state: a failure as its
 * reason, a notice as the list wrote it. */
static void tl_summary(const struct task_list *list, struct zcl_present_model_v1 *model)
{
    const struct task_editor *editor = list->editor;
    uint32_t count = editor->saved.state.count;
    if (!list->notice[0] && !editor->failure[0]) {
        if (tl_update_ack_error_visible(list))
            (void)snprintf(model->summary, sizeof(model->summary), "%.255s", list->update->message);
        else if (!count && editor->status == TASK_EDITOR_SAVED && !tl_empty_render(list, model))
            (void)snprintf(model->summary, sizeof(model->summary), "Saved. No tasks yet - choose New task.");
        return;
    }
    /* The editor's summary opens with its save state, before the first colon. */
    char status[64], reason[128];
    (void)snprintf(status, sizeof(status), "%.63s", model->summary);
    char *colon = strstr(status, ": ");
    if (colon) *colon = '\0';
    /* A notice is the list's own sentence; only a failure needs its reason made plain. */
    if (list->notice[0]) (void)snprintf(reason, sizeof(reason), "%.127s", list->notice);
    else tl_plain(reason, tl_reason(editor->failure));
    (void)snprintf(model->summary, sizeof(model->summary), "%.63s: %.127s", status, reason);
}

struct zcl_result task_list_model(const struct task_list *list, struct zcl_present_model_v1 *model)
{
    if (!list || !list->editor || !model) return ZCL_ERR(-1, "task-list: visual owner and output required");
    ZCL_CHECK(task_editor_model(list->editor, model));
    model->kind = ZCL_PRESENT_MODEL_TABLE;
    model->item_count = 0;
    memset(model->items, 0, sizeof(model->items));
    tl_title(list, model);
    tl_summary(list, model);
    tl_model_rows(list, model);
    tl_model_actions(list, model);
    if (list->updates && list->update) task_update_panel_model(list, model);
    return ZCL_OK;
}
