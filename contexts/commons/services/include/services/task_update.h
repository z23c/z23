/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: permissioned task program previews over host-owned durable data. */
#ifndef ZCL_SERVICES_TASK_UPDATE_H
#define ZCL_SERVICES_TASK_UPDATE_H
#include "models/task_document.h"
#include "models/task_update_offer.h"
struct task_update_job;
struct task_update_images;
enum task_update_phase { TASK_UPDATE_IDLE, TASK_UPDATE_RUNNING, TASK_UPDATE_READY,
    TASK_UPDATE_KEEPING, TASK_UPDATE_KEPT, TASK_UPDATE_CANCELLED, TASK_UPDATE_FAILED };
enum task_update_step { TASK_UPDATE_STORAGE, TASK_UPDATE_VERIFY, TASK_UPDATE_DATA,
    TASK_UPDATE_SNAPSHOT, TASK_UPDATE_INPUTS, TASK_UPDATE_EXECUTE,
    TASK_UPDATE_COMPATIBILITY, TASK_UPDATE_CLEANUP, TASK_UPDATE_COMMIT,
    TASK_UPDATE_STEP_COUNT };
struct task_update {

    char directory[4096], app[256], verifier[4096];
    struct package_resident_identity candidate;
    int64_t offer_revision;
    bool candidate_explicit, offer_locked;
    struct task_update_job *pending, *ready;
    struct task_update_images *images;
    enum task_update_phase phase;
    char preview[4096], active[4096], message[256];
    uint64_t active_revision;
    bool active_valid;
    int64_t elapsed_us, helper_startup_us, confined_us;
    enum task_update_step step;
    int64_t step_us[TASK_UPDATE_STEP_COUNT];
};
struct zcl_result task_update_open(struct task_update *update, const char *directory,
    const char *app, const char *verifier, const struct package_resident_identity *candidate);
/* Permission belongs to this exact user action. No execution when false. */
struct zcl_result task_update_try(struct task_update *update, bool permission, bool go_back);
struct zcl_result task_update_keep(struct task_update *update);
void task_update_cancel(struct task_update *update);
struct zcl_result task_update_poll(struct task_update *update, bool *changed);
struct zcl_result task_update_finish(struct task_update *update);
/* Previously kept program: refresh its view from current host-owned data. */
struct zcl_result task_update_refresh(struct task_update *update);
/* Resolve installed bytes before recording an inert proposal. Never executes. */
struct zcl_result task_update_offer_submit(struct package_resident_store *store,
    const char *directory, int64_t expected_revision,
    const struct package_resident_identity *candidate, struct task_update_offer *out);
/* On-demand discovery; consent and running/ready previews pin their selection. */
struct zcl_result task_update_check_offer(struct task_update *update);
struct zcl_result task_update_acknowledge_offer(struct task_update *update);
struct zcl_result task_update_discard(struct task_update *update);
#endif
