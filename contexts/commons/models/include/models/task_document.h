/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: durable user task contents independent of program generations. */
#ifndef ZCL_MODELS_TASK_DOCUMENT_H
#define ZCL_MODELS_TASK_DOCUMENT_H
#include "models/package_resident.h"
#include "../../../packages/ztasks/include/ztasks/ztasks.h"

struct task_document {
    struct ta_state state;
    struct ta_state undo;
    bool can_undo;
};
/* An observation for preview admission, not an install/execute permission or
 * evidence that another program understands these bytes. Includes durable undo. */
struct task_document_checkpoint {
    char app[256];
    struct task_document document;
};
/* Distinguishes a revision conflict from exhaustion and other failures. */
enum { TASK_DOCUMENT_STALE = -31001 };
enum task_document_action {
    TASK_DOCUMENT_ADD, TASK_DOCUMENT_EDIT, TASK_DOCUMENT_COMPLETE,
    TASK_DOCUMENT_REOPEN, TASK_DOCUMENT_DELETE, TASK_DOCUMENT_UNDO
};
/* Read refuses unknown or corrupt schemas and never overwrites out on failure. */
struct zcl_result task_document_read(struct package_resident_store *store,
    struct task_document *out);
/* Success means SQLite committed under the resident store's EXTRA durability.
 * A stale revision, invalid edit or failed commit preserves the prior document
 * and out. Undo is durable and restores contents with a NEW revision. */
struct zcl_result task_document_apply(struct package_resident_store *store,
    uint64_t expected_revision, enum task_document_action action,
    uint64_t task_id, const char *title, struct task_document *out);
struct zcl_result task_document_capture(struct package_resident_store *store,
    struct task_document_checkpoint *out);
/* Use from a trusted resident transition guard. Requires its open transaction;
 * refuses any intervening edit, even an undo back to the same visible contents. */
struct zcl_result task_document_check_current(struct package_resident_store *store,
    const struct task_document_checkpoint *checkpoint);
#endif
