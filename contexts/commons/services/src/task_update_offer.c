/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: deliver verified inert proposals to the existing task preview owner. */
#include "services/task_update.h"
#include "services/package_resident.h"
#include "base/hex.h"
#include <stdio.h>
#include <string.h>

struct zcl_result task_update_offer_submit(struct package_resident_store *store,
    const char *directory, int64_t expected_revision,
    const struct package_resident_identity *candidate, struct task_update_offer *out)
{
    uint8_t root[32], receipt[32];
    if (!directory || !candidate || !out || expected_revision < 0 ||
        !memchr(candidate->package_root, 0, sizeof(candidate->package_root)) ||
        !memchr(candidate->receipt_id, 0, sizeof(candidate->receipt_id)) ||
        !memchr(candidate->program, 0, sizeof(candidate->program)) ||
        !zcl_hex_decode_lower(candidate->package_root, root, sizeof(root)) ||
        !zcl_hex_decode_lower(candidate->receipt_id, receipt, sizeof(receipt)))
        return ZCL_ERR(-1, "Choose an exact installed update and the last offer revision.");
    struct package_resident_artifact artifact;
    ZCL_CHECK(package_resident_artifact_read(directory, root, receipt, candidate->program, &artifact));
    struct package_resident_identity exact = *candidate;
    (void)snprintf(exact.artifact_sha3, sizeof(exact.artifact_sha3), "%s", artifact.accepted.image_sha3_hex);
    exact.configuration_generation = 1;
    return task_update_offer_save(store, expected_revision, &exact, out);
}

static struct zcl_result tuo_load(const struct task_update *update,
    struct task_update_offer *offer, struct package_resident_record *current)
{
    struct package_resident_store store = {0};
    struct zcl_result result = package_resident_store_open_app(&store, update->directory, update->app);
    if (result.ok) result = task_update_offer_read(&store, offer);
    if (result.ok) result = package_resident_record_read(&store, current);
    struct zcl_result closed = package_resident_store_close(&store);
    if (result.ok && !closed.ok) result = closed;
    return result;
}

struct zcl_result task_update_check_offer(struct task_update *update)
{
    if (!update) return ZCL_ERR(-1, "Task update owner required.");
    if (update->offer_locked || update->pending || update->ready || update->candidate_explicit)
        return ZCL_OK;
    struct task_update_offer offer = {0};
    struct package_resident_record current = {0};
    ZCL_CHECK(tuo_load(update, &offer, &current));
    bool available = offer.revision && !offer.dismissed &&
        !package_resident_identity_equal(&offer.candidate, &current.current);
    update->candidate = available ? offer.candidate : (struct package_resident_identity){0};
    update->offer_revision = available ? offer.revision : 0;
    update->phase = TASK_UPDATE_IDLE;
    (void)snprintf(update->message, sizeof(update->message), "%s", available
        ? "An update is ready to try. Nothing runs until you allow its preview."
        : "No new update is waiting. Your AI can offer an installed update while Tasks stays open.");
    return ZCL_OK;
}

struct zcl_result task_update_acknowledge_offer(struct task_update *update)
{
    if (!update) return ZCL_ERR(-1, "Task update owner required.");
    if (!update->offer_revision) return ZCL_OK;
    struct package_resident_store store = {0};
    struct task_update_offer dismissed;
    struct zcl_result result = package_resident_store_open_app(&store, update->directory, update->app);
    if (result.ok) {
        result = task_update_offer_dismiss(&store, update->offer_revision, &dismissed);
        /* A newer offer belongs to its author; keeping or discarding this
         * older preview must leave that newer proposal available. */
        if (result.code == TASK_UPDATE_OFFER_STALE) result = ZCL_OK;
    }
    struct zcl_result closed = package_resident_store_close(&store);
    if (result.ok && !closed.ok) result = closed;
    if (result.ok) update->offer_revision = 0;
    return result;
}

struct zcl_result task_update_discard(struct task_update *update)
{
    if (!update || update->pending) return ZCL_ERR(-1, "Wait for the preview to finish or cancel it first.");
    ZCL_CHECK(task_update_acknowledge_offer(update));
    task_update_cancel(update);
    update->candidate = (struct package_resident_identity){0};
    update->candidate_explicit = false;
    (void)snprintf(update->message, sizeof(update->message), "Update discarded. Your working program and tasks are unchanged.");
    return ZCL_OK;
}
