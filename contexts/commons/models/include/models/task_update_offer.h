/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: inert, app-scoped proposed task program. */
#ifndef ZCL_MODELS_TASK_UPDATE_OFFER_H
#define ZCL_MODELS_TASK_UPDATE_OFFER_H
#include "models/package_resident.h"
enum { TASK_UPDATE_OFFER_STALE = -2 };
struct task_update_offer {
    int64_t revision;
    bool dismissed;
    struct package_resident_identity candidate;
};
struct zcl_result task_update_offer_read(struct package_resident_store *store,
    struct task_update_offer *out);
struct zcl_result task_update_offer_save(struct package_resident_store *store,
    int64_t expected_revision, const struct package_resident_identity *candidate,
    struct task_update_offer *out);
struct zcl_result task_update_offer_dismiss(struct package_resident_store *store,
    int64_t expected_revision, struct task_update_offer *out);
#endif
