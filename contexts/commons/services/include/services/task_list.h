/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: task-list selection and actions over the durable editor owner. */
#ifndef ZCL_SERVICES_TASK_LIST_H
#define ZCL_SERVICES_TASK_LIST_H
#include "services/task_editor.h"
#include "services/task_update.h"
enum { TASK_LIST_ROWS = 8, TASK_LIST_TOP = 184, TASK_LIST_ROW_HEIGHT = 45 };
/* Actions chosen while a save is pending wait here and apply in order. */
#define TASK_LIST_QUEUED_MAX 8u
struct task_list_queued { uint64_t id; enum task_document_action action; };
struct task_list {
    struct task_editor *editor;
    struct task_update *update;
    unsigned permission;
    bool updates;
    uint32_t selected, first, focus;
    uint64_t selected_id;
    bool menu, repaint, closing, open_editor, new_task, update_ack_error;
    char notice[128];
    struct task_list_queued queue[TASK_LIST_QUEUED_MAX];
    uint32_t queued;
    bool notice_held;
};
void task_list_init(struct task_list *list, struct task_editor *editor);
void task_list_refresh(struct task_list *list);
struct zcl_result task_list_action(struct task_list *list, uint32_t action);
struct zcl_result task_list_poll(struct task_list *list);
bool task_list_input(void *context, const struct zcl_present_input_v1 *input,
                     uint32_t *focus, uint32_t *action);
struct zcl_result task_list_model(const struct task_list *list,
                                 struct zcl_present_model_v1 *model);
struct zcl_result task_list_window_run(struct task_editor *editor);
struct zcl_result task_list_window_run_update(struct task_editor *editor, struct task_update *update);
struct zcl_result task_update_panel_action(struct task_list *list, uint32_t action);
void task_update_panel_model(const struct task_list *list, struct zcl_present_model_v1 *model);
bool task_update_panel_input(struct task_list *list,
    const struct zcl_present_input_v1 *input, uint32_t *focus, uint32_t *action);
void task_update_row(const struct task_list *list, uint32_t index,
                     struct zcl_present_model_item_v1 *item);
#endif
