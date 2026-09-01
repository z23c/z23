/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Host-owned transactional activation for the stable App ABI. */

#include "framework/app_platform.h"

#include "util/safe_alloc.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct zcl_app_runtime_v1 {
    pthread_mutex_t lock;
    struct zcl_app_host_v1 host;
    uint64_t allowed_capabilities;
    char build_identity[65];
    const struct zcl_app_manifest_v1 *active;
    zcl_app_state_handle state;
    uint64_t generation;
    uint32_t schema;
};

static bool runtime_reject(char *why, size_t why_sz, const char *message)
{
    if (why && why_sz)
        (void)snprintf(why, why_sz, "%s", message ? message : "invalid");
    return false;
}
static void activation_receipt_init(
    struct zcl_app_activation_receipt_v1 *receipt)
{
    memset(receipt, 0, sizeof(*receipt));
    receipt->struct_size = sizeof(*receipt);
    receipt->rolled_back = true;
    (void)snprintf(receipt->phase, sizeof(receipt->phase), "%s", "validate");
}

static bool activation_refuse(
    struct zcl_app_activation_receipt_v1 *receipt, const char *phase,
    const char *message)
{
    receipt->ok = false;
    receipt->rolled_back = true;
    (void)snprintf(receipt->phase, sizeof(receipt->phase), "%s",
                   phase ? phase : "activate");
    (void)snprintf(receipt->error, sizeof(receipt->error), "%s",
                   message && message[0] ? message : "app activation refused");
    return false;
}

struct zcl_app_runtime_v1 *zcl_app_runtime_v1_create(
    const struct zcl_app_host_v1 *host, uint64_t allowed_capabilities,
    const char *build_identity, char *why, size_t why_sz)
{
    if (why && why_sz) why[0] = 0;
    if (!host || host->struct_size < sizeof(*host) ||
        host->abi_version != ZCL_APP_HOST_ABI_V1 || !build_identity ||
        !build_identity[0] || strlen(build_identity) >= 65 ||
        (allowed_capabilities & ~host->capabilities) != 0) {
        (void)runtime_reject(why, why_sz,
                     "host ABI, capability ceiling, or build identity invalid");
        return NULL;
    }
    if ((allowed_capabilities & ZCL_APP_CAP_RESIDENT_STATE) &&
        (!host->state_open || !host->state_read || !host->state_write)) {
        (void)runtime_reject(why, why_sz,
                     "resident-state capability lacks host-owned state hooks");
        return NULL;
    }
    struct zcl_app_runtime_v1 *runtime =
        zcl_calloc(1, sizeof(*runtime), "app live-generation runtime");
    if (!runtime) {
        (void)runtime_reject(why, why_sz, "app runtime allocation failed");
        return NULL;
    }
    if (pthread_mutex_init(&runtime->lock, NULL) != 0) {
        free(runtime);
        (void)runtime_reject(why, why_sz, "app runtime lock initialization failed");
        return NULL;
    }
    runtime->host = *host;
    runtime->allowed_capabilities = allowed_capabilities;
    (void)snprintf(runtime->build_identity,
                   sizeof(runtime->build_identity), "%s", build_identity);
    return runtime;
}

void zcl_app_runtime_v1_destroy(struct zcl_app_runtime_v1 *runtime)
{
    if (!runtime)
        return;
    (void)pthread_mutex_destroy(&runtime->lock);
    free(runtime);
}

bool zcl_app_runtime_v1_activate(
    struct zcl_app_runtime_v1 *runtime,
    const struct zcl_app_manifest_v1 *candidate,
    struct zcl_app_activation_receipt_v1 *receipt)
{
    if (!receipt)
        return false;
    activation_receipt_init(receipt);
    if (!runtime)
        return activation_refuse(receipt, "validate", "runtime is null");

    pthread_mutex_lock(&runtime->lock);
    receipt->generation = runtime->generation;
    receipt->from_schema = runtime->schema;
    receipt->to_schema = candidate ? candidate->state_schema_version : 0;
    char why[ZCL_APP_ERROR_MAX + 1] = {0};
    if (!zcl_app_manifest_v1_validate(
            candidate, runtime->allowed_capabilities,
            runtime->build_identity, why, sizeof(why))) {
        pthread_mutex_unlock(&runtime->lock);
        return activation_refuse(receipt, "validate", why);
    }
    if (runtime->active &&
        strcmp(runtime->active->app_id, candidate->app_id) != 0) {
        pthread_mutex_unlock(&runtime->lock);
        return activation_refuse(receipt, "identity",
                                 "candidate app_id differs from active slot");
    }
    if (candidate->state_schema_version < runtime->schema ||
        (runtime->schema > 0 && candidate->state_schema_version == 0)) {
        pthread_mutex_unlock(&runtime->lock);
        return activation_refuse(receipt, "migration",
                                 "live schema rollback or removal is refused");
    }

    struct zcl_app_error hook_error = {0};
    if (candidate->self_test(&runtime->host, &hook_error) != 0) {
        pthread_mutex_unlock(&runtime->lock);
        return activation_refuse(
            receipt, "self_test",
            hook_error.message[0] ? hook_error.message
                                  : "candidate self-test failed");
    }

    bool migration_needed = candidate->state_schema_version != runtime->schema;
    zcl_app_state_handle state = runtime->state;
    const struct zcl_app_migration_v1 *migration = candidate->migration;
    if (migration_needed) {
        if (!migration || migration->from_schema != runtime->schema ||
            migration->to_schema != candidate->state_schema_version) {
            pthread_mutex_unlock(&runtime->lock);
            return activation_refuse(
                receipt, "migration",
                "migration schema endpoints do not match active and candidate");
        }
        if (state == 0 &&
            runtime->host.state_open(runtime->host.host_context,
                                     candidate->app_id, runtime->schema,
                                     &state, &hook_error) != 0) {
            pthread_mutex_unlock(&runtime->lock);
            return activation_refuse(
                receipt, "state_open",
                hook_error.message[0] ? hook_error.message
                                      : "host state_open failed");
        }
        hook_error = (struct zcl_app_error){0};
        if (migration->prepare(&runtime->host, state, &hook_error) != 0) {
            pthread_mutex_unlock(&runtime->lock);
            return activation_refuse(
                receipt, "migration_prepare",
                hook_error.message[0] ? hook_error.message
                                      : "migration prepare failed");
        }
        receipt->migration_prepared = true;
    }

    if (runtime->active) {
        hook_error = (struct zcl_app_error){0};
        if (runtime->active->quiesce(&runtime->host, 200,
                                     &hook_error) != 0) {
            if (receipt->migration_prepared)
                migration->abort(&runtime->host, state);
            pthread_mutex_unlock(&runtime->lock);
            return activation_refuse(
                receipt, "quiesce",
                hook_error.message[0] ? hook_error.message
                                      : "active generation did not quiesce");
        }
    }

    if (migration_needed) {
        hook_error = (struct zcl_app_error){0};
        if (migration->commit(&runtime->host, state, &hook_error) != 0) {
            migration->abort(&runtime->host, state);
            pthread_mutex_unlock(&runtime->lock);
            return activation_refuse(
                receipt, "migration_commit",
                hook_error.message[0] ? hook_error.message
                                      : "migration commit failed");
        }
        receipt->migration_committed = true;
    }

    runtime->active = candidate;
    runtime->state = state;
    runtime->schema = candidate->state_schema_version;
    runtime->generation++;
    receipt->ok = true;
    receipt->rolled_back = false;
    receipt->generation = runtime->generation;
    (void)snprintf(receipt->phase, sizeof(receipt->phase), "%s", "committed");
    receipt->error[0] = 0;
    pthread_mutex_unlock(&runtime->lock);
    return true;
}

const struct zcl_app_manifest_v1 *zcl_app_runtime_v1_active(
    struct zcl_app_runtime_v1 *runtime, uint64_t *generation_out,
    uint32_t *schema_out)
{
    if (!runtime)
        return NULL;
    pthread_mutex_lock(&runtime->lock);
    const struct zcl_app_manifest_v1 *active = runtime->active;
    if (generation_out) *generation_out = runtime->generation;
    if (schema_out) *schema_out = runtime->schema;
    pthread_mutex_unlock(&runtime->lock);
    return active;
}
