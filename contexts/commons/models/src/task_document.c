/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: atomically save task contents and undo through ActiveRecord. */
#include "models/task_document.h"
#include "models/activerecord.h"
#include "models/query_builder.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(task_document)

static struct zcl_result td_sql(struct package_resident_store *store, const char *sql)
{
    if (sqlite3_exec(store->db, sql, NULL, NULL, NULL) != SQLITE_OK)
        return ZCL_ERR(-1, "task-save: %s", sqlite3_errmsg(store->db));
    return ZCL_OK;
}

static bool td_valid(const struct task_document *row, struct ar_errors *errors)
{
    unsigned char bytes[TA_PAYLOAD];
    uint32_t length;
    ar_errors_clear(errors);
    validates_custom(errors, row && row->state.revision <= INT64_MAX &&
        ta_state_encode(&row->state, bytes, &length), "state", "invalid task contents");
    if (row && row->can_undo)
        validates_custom(errors, ta_state_encode(&row->undo, bytes, &length),
            "undo", "invalid prior contents");
    return !ar_errors_any(errors);
}

static struct zcl_result td_ready(struct package_resident_store *store)
{
    if (!store || !store->db || !store->app[0])
        return ZCL_ERR(-1, "task-document: an open named application store is required");
    return td_sql(store, qb_schema_sql(QB_S_task_documents_create));
}

static bool td_decode(sqlite3_stmt *s, struct task_document *row)
{
    if (sqlite3_column_type(s, 0) != SQLITE_BLOB ||
        sqlite3_column_type(s, 1) != SQLITE_BLOB) return false;
    int length = sqlite3_column_bytes(s, 0), undo_length = sqlite3_column_bytes(s, 1);
    if (length < 24 || length > (int)TA_PAYLOAD ||
        undo_length < 0 || undo_length > (int)TA_PAYLOAD) return false;
    if (!ta_state_decode(sqlite3_column_blob(s, 0), (uint32_t)length, &row->state)) {
        LOG_ERROR("task-read", "canonical task decoder rejected stored contents");
        return false;
    }
    row->can_undo = undo_length != 0;
    return !row->can_undo || ta_state_decode(sqlite3_column_blob(s, 1),
        (uint32_t)undo_length, &row->undo);
}

struct zcl_result task_document_read(struct package_resident_store *store,
                                     struct task_document *out)
{
    if (!out) return ZCL_ERR(-1, "task-read: output is required");
    ZCL_CHECK(td_ready(store));
    struct qb q;
    qb_select(&q, QB_T_task_documents);
    const enum qb_column columns[] = { QB_C_task_documents_payload, QB_C_task_documents_undo };
    qb_select_columns(&q, columns, 2);
    qb_where_text(&q, QB_C_task_documents_app, QB_EQ, store->app);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(store, &q, s)) return ZCL_ERR(-1, "task-read: query refused");
    struct task_document row = {0};
    int rc = AR_STEP_ROW_READONLY(s);
    bool valid = rc == SQLITE_DONE || (rc == SQLITE_ROW && td_decode(s, &row));
    int finalized = sqlite3_finalize(s);
    struct ar_errors errors;
    if (!valid || finalized != SQLITE_OK || !td_valid(&row, &errors))
        return ZCL_ERR(-1, "task-read: incompatible or damaged task data; contents retained");
    *out = row;
    return ZCL_OK;
}

static bool td_save(struct package_resident_store *store, const struct task_document *row)
{
    AR_BEGIN_SAVE(db_task_document_callbacks(), "task_document", row, td_valid);
    unsigned char bytes[TA_PAYLOAD], undo[TA_PAYLOAD];
    uint32_t length, undo_length = 0;
    if (!ta_state_encode(&row->state, bytes, &length) ||
        (row->can_undo && !ta_state_encode(&row->undo, undo, &undo_length))) {
        LOG_ERROR("task-save", "canonical task encoder rejected pending contents");
        return false;
    }
    struct qb q;
    qb_insert(&q, QB_T_task_documents, QB_INSERT_PLAIN);
    qb_value_text(&q, QB_C_task_documents_app, store->app);
    qb_value_blob(&q, QB_C_task_documents_payload, bytes, length);
    qb_value_blob(&q, QB_C_task_documents_undo, undo, undo_length);
    const enum qb_column conflict[] = { QB_C_task_documents_app };
    qb_on_conflict_do_update(&q, conflict, 1);
    qb_conflict_set_excluded(&q, QB_C_task_documents_payload);
    qb_conflict_set_excluded(&q, QB_C_task_documents_undo);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(store, &q, s)) return false;
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    AR_FINISH_SAVE(db_task_document_callbacks(), row, ok);
}

static struct zcl_result td_edit(struct task_document *row,
    enum task_document_action action, uint64_t id, const char *title)
{
    struct ta_state *state = &row->state;
    if ((action == TASK_DOCUMENT_ADD || action == TASK_DOCUMENT_EDIT) && !ta_title_valid(title))
        return ZCL_ERR(-1, "task-edit: enter a visible title of at most 95 Basic Latin characters");
    uint32_t index = 0;
    while (index < state->count && state->tasks[index].id != id) ++index;
    if (action == TASK_DOCUMENT_ADD) {
        if (state->count == TA_MAX_TASKS) return ZCL_ERR(-1, "task-add: task limit reached");
        index = state->count++;
        state->tasks[index] = (struct ta_task){ .id = state->revision + 1 };
    } else if (index == state->count) return ZCL_ERR(-1, "task-edit: task no longer exists");
    struct ta_task *task = &state->tasks[index];
    switch (action) {
    case TASK_DOCUMENT_ADD:
    case TASK_DOCUMENT_EDIT: memcpy(task->title, title, strlen(title) + 1); break;
    case TASK_DOCUMENT_COMPLETE: task->done = 1; break;
    case TASK_DOCUMENT_REOPEN: task->done = 0; break;
    case TASK_DOCUMENT_DELETE:
        memmove(task, task + 1, (state->count - index - 1) * sizeof(*task));
        --state->count;
        break;
    default: return ZCL_ERR(-1, "task-edit: unknown action");
    }
    return ZCL_OK;
}

static bool td_state_equal(const struct ta_state *a, const struct ta_state *b)
{
    unsigned char first[TA_PAYLOAD], second[TA_PAYLOAD];
    uint32_t first_length, second_length;
    return ta_state_encode(a, first, &first_length) &&
        ta_state_encode(b, second, &second_length) && first_length == second_length &&
        memcmp(first, second, first_length) == 0;
}

static struct zcl_result td_change(struct package_resident_store *store, struct task_document *row,
    enum task_document_action action, uint64_t id, const char *title)
{
    uint64_t revision = row->state.revision + 1;
    if (action == TASK_DOCUMENT_UNDO) {
        if (!row->can_undo) return ZCL_ERR(-1, "task-undo: nothing to undo");
        row->state = row->undo;
        row->can_undo = false;
    } else {
        struct ta_state before = row->state;
        ZCL_CHECK(td_edit(row, action, id, title));
        if (td_state_equal(&before, &row->state)) return ZCL_OK;
        row->undo = before;
        row->can_undo = true;
    }
    row->state.revision = revision;
    row->state.last_write = revision;
    if (!td_save(store, row)) return ZCL_ERR(-1, "task-save: write failed; prior data retained");
    return ZCL_OK;
}

struct zcl_result task_document_apply(struct package_resident_store *store,
    uint64_t expected_revision, enum task_document_action action,
    uint64_t task_id, const char *title, struct task_document *out)
{
    if (!out) return ZCL_ERR(-1, "task-save: output is required");
    ZCL_CHECK(td_ready(store));
    ZCL_CHECK(td_sql(store, "BEGIN IMMEDIATE"));
    struct task_document row;
    struct zcl_result result = task_document_read(store, &row);
    if (result.ok && (row.state.revision != expected_revision || expected_revision >= INT64_MAX))
        result = ZCL_ERR(-1, "task-save: stale or exhausted revision; reload before saving");
    if (result.ok) result = td_change(store, &row, action, task_id, title);
    if (result.ok) result = td_sql(store, "COMMIT");
    if (!result.ok && !sqlite3_get_autocommit(store->db)) {
        struct zcl_result rollback = td_sql(store, "ROLLBACK");
        if (!rollback.ok) return rollback;
    }
    if (result.ok) *out = row;
    return result;
}

struct zcl_result task_document_capture(struct package_resident_store *store,
    struct task_document_checkpoint *out)
{
    if (!out) return ZCL_ERR(-1, "task-preview: checkpoint output required");
    struct task_document_checkpoint checkpoint = {0};
    ZCL_CHECK(task_document_read(store, &checkpoint.document));
    (void)snprintf(checkpoint.app, sizeof(checkpoint.app), "%s", store->app);
    *out = checkpoint;
    return ZCL_OK;
}

struct zcl_result task_document_check_current(struct package_resident_store *store,
    const struct task_document_checkpoint *checkpoint)
{
    if (!store || !store->db || !checkpoint || sqlite3_get_autocommit(store->db))
        return ZCL_ERR(-1, "task-preview: current-data check requires the program-switch transaction");
    if (!memchr(checkpoint->app, 0, sizeof(checkpoint->app)) ||
        strcmp(store->app, checkpoint->app) != 0)
        return ZCL_ERR(-1, "task-preview: checkpoint belongs to another app");
    struct task_document current;
    ZCL_CHECK(task_document_read(store, &current));
    const struct task_document *expected = &checkpoint->document;
    if (!td_state_equal(&current.state, &expected->state) ||
        current.can_undo != expected->can_undo ||
        (current.can_undo && !td_state_equal(&current.undo, &expected->undo)))
        return ZCL_ERR(-1, "task-preview-stale: your tasks changed; preview the current data before switching programs");
    return ZCL_OK;
}
