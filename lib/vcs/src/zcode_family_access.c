/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: local-sovereignty + Family admission composite access seam. */

#include "vcs/zcode_family_admission.h"

#include "base/bytes.h"
#include "base/safe_alloc.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

struct family_access_snapshot {
    struct vcs_zcode_family_admission_projection_entry_v1 *entries;
    size_t count;
    uint8_t root[32];
};

struct vcs_zcode_family_access_service {
    pthread_mutex_t lock;
    _Atomic uint64_t generation;
    _Atomic bool active;
    struct family_access_snapshot snapshot;
};

static bool access_zero(const uint8_t root[32])
{
    return !zcl_bytes_any_set(root, 32);
}

static enum vcs_zcode_sovereignty_action access_local_action(
    enum vcs_zcode_family_access_action_v1 action)
{
    switch (action) {
    case VCS_ZCODE_FAMILY_ACTION_DISCOVER:
        return VCS_ZCODE_SOVEREIGNTY_DISCOVER;
    case VCS_ZCODE_FAMILY_ACTION_INDEX:
    case VCS_ZCODE_FAMILY_ACTION_SEARCH:
        return VCS_ZCODE_SOVEREIGNTY_INDEX;
    case VCS_ZCODE_FAMILY_ACTION_FETCH:
        return VCS_ZCODE_SOVEREIGNTY_FETCH;
    case VCS_ZCODE_FAMILY_ACTION_STORE:
    case VCS_ZCODE_FAMILY_ACTION_REPLICATE:
    case VCS_ZCODE_FAMILY_ACTION_STORAGE_ACK:
        return VCS_ZCODE_SOVEREIGNTY_STORE;
    case VCS_ZCODE_FAMILY_ACTION_SHOW:
    case VCS_ZCODE_FAMILY_ACTION_REST:
    case VCS_ZCODE_FAMILY_ACTION_PREVIEW:
    case VCS_ZCODE_FAMILY_ACTION_SERVE:
    case VCS_ZCODE_FAMILY_ACTION_DOWNLOAD:
        return VCS_ZCODE_SOVEREIGNTY_SERVE;
    case VCS_ZCODE_FAMILY_ACTION_DHT_ADVERTISE:
    case VCS_ZCODE_FAMILY_ACTION_DHT_FORWARD:
    case VCS_ZCODE_FAMILY_ACTION_PROVIDER_RENEW:
    case VCS_ZCODE_FAMILY_ACTION_PROTOCOL_FRAME:
        return VCS_ZCODE_SOVEREIGNTY_FORWARD;
    case VCS_ZCODE_FAMILY_ACTION_INSTALL:
    case VCS_ZCODE_FAMILY_ACTION_BUILD:
    case VCS_ZCODE_FAMILY_ACTION_RUN:
    case VCS_ZCODE_FAMILY_ACTION_EXECUTE:
        return VCS_ZCODE_SOVEREIGNTY_EXECUTE;
    case VCS_ZCODE_FAMILY_ACTION_COUNT:
        break;
    }
    return VCS_ZCODE_SOVEREIGNTY_ACTION_COUNT;
}

static bool request_subject_binds_content(
    const struct vcs_zcode_family_access_request_v1 *request)
{
    return memcmp(request->subject.semantic_root,
                  request->content_root, 32) == 0 ||
           memcmp(request->subject.transport_root,
                  request->content_root, 32) == 0 ||
           memcmp(request->subject.package_root,
                  request->content_root, 32) == 0;
}

static bool request_extras_zero(
    const struct vcs_zcode_family_access_request_v1 *request)
{
    return access_zero(request->provider_root) && !request->expected_bytes &&
           !request->byte_budget && !request->expires_height &&
           !request->expires_mtp && !request->current_height &&
           !request->current_mtp && !request->control_bytes &&
           !request->control_kind && !request->operator_authorized &&
           !request->redacted;
}

static bool request_family_public_valid(
    const struct vcs_zcode_family_access_request_v1 *request)
{
    return request->action != VCS_ZCODE_FAMILY_ACTION_PROTOCOL_FRAME &&
           zcl_bytes_any_set(request->content_root, 32) &&
           zcl_bytes_any_set(request->dependency_closure_root, 32) &&
           request_subject_binds_content(request) &&
           request_extras_zero(request);
}

static bool request_intake_valid(
    const struct vcs_zcode_family_access_request_v1 *request)
{
    bool action_ok = request->action == VCS_ZCODE_FAMILY_ACTION_FETCH ||
                     request->action == VCS_ZCODE_FAMILY_ACTION_STORE;
    return action_ok && zcl_bytes_any_set(request->content_root, 32) &&
           zcl_bytes_any_set(request->dependency_closure_root, 32) &&
           zcl_bytes_any_set(request->provider_root, 32) &&
           request_subject_binds_content(request) &&
           request->expected_bytes > 0 &&
           request->expected_bytes <= request->byte_budget &&
           request->byte_budget <= VCS_ZCODE_FAMILY_INTAKE_MAX_BYTES &&
           request->current_height > 0 && request->current_mtp > 0 &&
           request->current_height <= request->expires_height &&
           request->current_mtp <= request->expires_mtp &&
           !request->control_bytes && !request->control_kind &&
           !request->operator_authorized && !request->redacted;
}

static bool request_diagnostic_valid(
    const struct vcs_zcode_family_access_request_v1 *request)
{
    bool action_ok = request->action == VCS_ZCODE_FAMILY_ACTION_SHOW ||
                     request->action == VCS_ZCODE_FAMILY_ACTION_REST;
    return action_ok && zcl_bytes_any_set(request->content_root, 32) &&
           zcl_bytes_any_set(request->dependency_closure_root, 32) &&
           request_subject_binds_content(request) &&
           request->operator_authorized && request->redacted &&
           access_zero(request->provider_root) && !request->expected_bytes &&
           !request->byte_budget && !request->expires_height &&
           !request->expires_mtp && !request->current_height &&
           !request->current_mtp && !request->control_bytes &&
           !request->control_kind;
}

static bool request_control_valid(
    const struct vcs_zcode_family_access_request_v1 *request)
{
    return request->action == VCS_ZCODE_FAMILY_ACTION_PROTOCOL_FRAME &&
           request->control_kind >= VCS_ZCODE_FAMILY_CONTROL_DHT_QUERY &&
           request->control_kind <=
               VCS_ZCODE_FAMILY_CONTROL_MODERATION_DISCOVERY &&
           request->control_bytes > 0 &&
           request->control_bytes <= VCS_ZCODE_FAMILY_CONTROL_MAX_BYTES &&
           access_zero(request->content_root) &&
           access_zero(request->dependency_closure_root) &&
           access_zero(request->provider_root) && !request->expected_bytes &&
           !request->byte_budget && !request->expires_height &&
           !request->expires_mtp && !request->current_height &&
           !request->current_mtp && !request->operator_authorized &&
           !request->redacted;
}

static bool request_valid(
    const struct vcs_zcode_family_access_request_v1 *request)
{
    if (!request || request->action >= VCS_ZCODE_FAMILY_ACTION_COUNT)
        return false;
    switch (request->intent) {
    case VCS_ZCODE_FAMILY_INTENT_FAMILY_PUBLIC:
        return request_family_public_valid(request);
    case VCS_ZCODE_FAMILY_INTENT_MODERATION_INTAKE:
        return request_intake_valid(request);
    case VCS_ZCODE_FAMILY_INTENT_EXACT_ROOT_DIAGNOSTIC:
        return request_diagnostic_valid(request);
    case VCS_ZCODE_FAMILY_INTENT_PROTOCOL_CONTROL:
        return request_control_valid(request);
    }
    return false;
}

struct vcs_zcode_family_access_service *vcs_zcode_family_access_service_create(
    void)
{
    struct vcs_zcode_family_access_service *service =
        zcl_calloc(1, sizeof(*service), "family access service");
    if (!service) return NULL;
    if (pthread_mutex_init(&service->lock, NULL) != 0) {
        free(service);
        return NULL;
    }
    atomic_init(&service->generation, 0);
    atomic_init(&service->active, false);
    return service;
}

void vcs_zcode_family_access_service_free(
    struct vcs_zcode_family_access_service *service)
{
    if (!service) return;
    (void)pthread_mutex_lock(&service->lock);
    free(service->snapshot.entries);
    service->snapshot.entries = NULL;
    service->snapshot.count = 0;
    (void)pthread_mutex_unlock(&service->lock);
    (void)pthread_mutex_destroy(&service->lock);
    free(service);
}

enum vcs_zcode_family_admission_error
vcs_zcode_family_access_service_publish(
    struct vcs_zcode_family_access_service *service,
    const struct vcs_zcode_family_admission_projection *projection)
{
    if (!service || !projection) return VCS_ZCODE_FAMILY_ADMISSION_NULL;
    size_t count = vcs_zcode_family_admission_projection_count_v1(projection);
    struct vcs_zcode_family_admission_projection_entry_v1 *entries = NULL;
    if (count) {
        entries = zcl_calloc(count, sizeof(*entries),
                             "family access snapshot entries");
        if (!entries) return VCS_ZCODE_FAMILY_ADMISSION_NOMEM;
        for (size_t i = 0; i < count; i++) {
            const struct vcs_zcode_family_admission_projection_entry_v1 *src =
                vcs_zcode_family_admission_projection_at_v1(projection, i);
            if (!src) {
                free(entries);
                return VCS_ZCODE_FAMILY_ADMISSION_CHAIN;
            }
            entries[i] = *src;
        }
    }
    uint8_t root[32];
    vcs_zcode_family_admission_projection_root_v1(projection, root);
    (void)pthread_mutex_lock(&service->lock);
    uint64_t generation = atomic_load_explicit(
        &service->generation, memory_order_relaxed);
    if (generation == UINT64_MAX) {
        (void)pthread_mutex_unlock(&service->lock);
        free(entries);
        return VCS_ZCODE_FAMILY_ADMISSION_OVERFLOW;
    }
    free(service->snapshot.entries);
    service->snapshot.entries = entries;
    service->snapshot.count = count;
    memcpy(service->snapshot.root, root, 32);
    atomic_store_explicit(&service->generation, generation + 1u,
                          memory_order_release);
    (void)pthread_mutex_unlock(&service->lock);
    return VCS_ZCODE_FAMILY_ADMISSION_OK;
}

enum vcs_zcode_family_admission_error
vcs_zcode_family_access_service_set_active(
    struct vcs_zcode_family_access_service *service, bool active)
{
    if (!service) return VCS_ZCODE_FAMILY_ADMISSION_NULL;
    (void)pthread_mutex_lock(&service->lock);
    bool prior = atomic_load_explicit(&service->active, memory_order_relaxed);
    uint64_t generation = atomic_load_explicit(
        &service->generation, memory_order_relaxed);
    if (prior != active && generation == UINT64_MAX) {
        (void)pthread_mutex_unlock(&service->lock);
        return VCS_ZCODE_FAMILY_ADMISSION_OVERFLOW;
    }
    if (prior != active) {
        atomic_store_explicit(&service->active, active, memory_order_release);
        atomic_store_explicit(&service->generation, generation + 1u,
                              memory_order_release);
    }
    (void)pthread_mutex_unlock(&service->lock);
    return VCS_ZCODE_FAMILY_ADMISSION_OK;
}

uint64_t vcs_zcode_family_access_service_generation(
    const struct vcs_zcode_family_access_service *service)
{
    return service ? atomic_load_explicit(&service->generation,
                                           memory_order_acquire) : 0;
}

bool vcs_zcode_family_access_service_active(
    const struct vcs_zcode_family_access_service *service)
{
    return service && atomic_load_explicit(&service->active,
                                           memory_order_acquire);
}

static const struct vcs_zcode_family_admission_projection_entry_v1 *
snapshot_find(const struct family_access_snapshot *snapshot,
              const uint8_t content_root[32], const uint8_t closure_root[32])
{
    size_t low = 0, high = snapshot->count;
    while (low < high) {
        size_t mid = low + (high - low) / 2u;
        const struct vcs_zcode_family_admission_projection_entry_v1 *entry =
            &snapshot->entries[mid];
        int cmp = memcmp(entry->content_root, content_root, 32);
        if (cmp == 0)
            cmp = memcmp(entry->dependency_closure_root, closure_root, 32);
        if (cmp < 0) low = mid + 1u;
        else if (cmp > 0) high = mid;
        else return entry;
    }
    return NULL;
}

static enum vcs_zcode_family_access_reason_v1 allowed_intent_reason(
    enum vcs_zcode_family_access_intent_v1 intent)
{
    switch (intent) {
    case VCS_ZCODE_FAMILY_INTENT_MODERATION_INTAKE:
        return VCS_ZCODE_FAMILY_ACCESS_MODERATION_INTAKE;
    case VCS_ZCODE_FAMILY_INTENT_EXACT_ROOT_DIAGNOSTIC:
        return VCS_ZCODE_FAMILY_ACCESS_EXACT_ROOT_DIAGNOSTIC;
    case VCS_ZCODE_FAMILY_INTENT_PROTOCOL_CONTROL:
        return VCS_ZCODE_FAMILY_ACCESS_PROTOCOL_CONTROL;
    case VCS_ZCODE_FAMILY_INTENT_FAMILY_PUBLIC:
        break;
    }
    return VCS_ZCODE_FAMILY_ACCESS_INVALID;
}

struct vcs_zcode_family_access_decision_v1 vcs_zcode_family_access_decide_v1(
    struct vcs_zcode_family_access_service *service,
    vcs_zcode_sovereignty_decide_fn local_decide, void *local_ctx,
    const struct vcs_zcode_family_access_request_v1 *request)
{
    struct vcs_zcode_family_access_decision_v1 decision = {0};
    if (!service || !local_decide || !request_valid(request)) return decision;
    enum vcs_zcode_sovereignty_action local_action =
        access_local_action(request->action);
    if (local_action == VCS_ZCODE_SOVEREIGNTY_ACTION_COUNT ||
        !local_decide(local_ctx, local_action, &request->subject)) {
        decision.reason = VCS_ZCODE_FAMILY_ACCESS_LOCAL_BLOCK;
        return decision;
    }
    (void)pthread_mutex_lock(&service->lock);
    decision.admission_generation = atomic_load_explicit(
        &service->generation, memory_order_relaxed);
    decision.enforcement_active = atomic_load_explicit(
        &service->active, memory_order_relaxed);
    memcpy(decision.projection_root, service->snapshot.root, 32);
    if (!decision.enforcement_active) {
        decision.allow = true;
        decision.reason = VCS_ZCODE_FAMILY_ACCESS_INACTIVE;
    } else if (request->intent != VCS_ZCODE_FAMILY_INTENT_FAMILY_PUBLIC) {
        decision.allow = true;
        decision.reason = allowed_intent_reason(request->intent);
    } else if (!zcl_bytes_any_set(service->snapshot.root, 32)) {
        decision.reason = VCS_ZCODE_FAMILY_ACCESS_NO_PROJECTION;
    } else {
        const struct vcs_zcode_family_admission_projection_entry_v1 *entry =
            snapshot_find(&service->snapshot, request->content_root,
                          request->dependency_closure_root);
        if (entry && entry->family_public) {
            decision.allow = true;
            decision.reason = VCS_ZCODE_FAMILY_ACCESS_FAMILY_PUBLIC;
            memcpy(decision.admission_root, entry->admission_root, 32);
        } else {
            decision.reason = VCS_ZCODE_FAMILY_ACCESS_NOT_ADMITTED;
            if (entry) memcpy(decision.admission_root,
                              entry->admission_root, 32);
        }
    }
    (void)pthread_mutex_unlock(&service->lock);
    return decision;
}

bool vcs_zcode_family_access_bind_v1(
    const struct vcs_zcode_family_access_request_v1 *request,
    const struct vcs_zcode_family_access_decision_v1 *decision,
    struct vcs_zcode_family_access_binding_v1 *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!request || !decision || !out || !decision->allow ||
        !request_valid(request))
        return false;
    out->admission_generation = decision->admission_generation;
    out->action = request->action;
    out->intent = request->intent;
    memcpy(out->projection_root, decision->projection_root, 32);
    memcpy(out->content_root, request->content_root, 32);
    memcpy(out->dependency_closure_root,
           request->dependency_closure_root, 32);
    return true;
}

struct vcs_zcode_family_access_decision_v1 vcs_zcode_family_access_recheck_v1(
    struct vcs_zcode_family_access_service *service,
    vcs_zcode_sovereignty_decide_fn local_decide, void *local_ctx,
    const struct vcs_zcode_family_access_request_v1 *request,
    const struct vcs_zcode_family_access_binding_v1 *binding)
{
    struct vcs_zcode_family_access_decision_v1 invalid = {0};
    if (!request || !binding || request->action != binding->action ||
        request->intent != binding->intent ||
        memcmp(request->content_root, binding->content_root, 32) != 0 ||
        memcmp(request->dependency_closure_root,
               binding->dependency_closure_root, 32) != 0)
        return invalid;
    struct vcs_zcode_family_access_decision_v1 decision =
        vcs_zcode_family_access_decide_v1(
            service, local_decide, local_ctx, request);
    decision.generation_changed =
        decision.admission_generation != binding->admission_generation ||
        memcmp(decision.projection_root, binding->projection_root, 32) != 0;
    return decision;
}
