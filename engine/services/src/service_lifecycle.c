/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Runtime lifecycle for declared services. See services/service_lifecycle.h
 * for the contract. The transition rules live in the pure kernel table
 * (zcl_service_lifecycle_next_v1); this file only records which state each
 * declared service is in, why it is blocked when it is, and how many times it
 * has moved. */

#include "services/service_lifecycle.h"

#include "config/service_binding_catalog.h"
#include "json/json.h"
#include "services/service_token_gate.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define SVCLC_LOG "service.lifecycle"

struct service_lifecycle_row {
    uint32_t binding_id;
    uint32_t state;
    uint64_t transitions;
    uint64_t fault_count;
    char name[ZCL_SERVICE_BINDING_NAME_MAX + 1u];
    char reason[SERVICE_LIFECYCLE_REASON_MAX];
};

static pthread_mutex_t g_svclc_lock = PTHREAD_MUTEX_INITIALIZER;
static struct service_lifecycle_row g_rows[ZCL_SERVICE_BINDING_CATALOG_MAX];
static size_t g_row_count;
static bool g_initialized;

/* Caller holds g_svclc_lock. */
static struct service_lifecycle_row *svclc_row(const char *name)
{
    if (!name || !name[0])
        return NULL;
    for (size_t i = 0; i < g_row_count; i++) {
        if (strncmp(g_rows[i].name, name, sizeof(g_rows[i].name)) == 0)
            return &g_rows[i];
    }
    return NULL;
}

struct zcl_result service_lifecycle_init(void)
{
    size_t bad_index = 0;
    enum zcl_service_binding_result check =
        zcl_service_binding_catalog_check_v1(&bad_index);
    if (check != ZCL_SERVICE_BINDING_OK)
        return ZCL_ERR(SERVICE_LIFECYCLE_ERR_CATALOG,
                       "declared service catalog rejected at index %zu (%s)",
                       bad_index, zcl_service_binding_result_name_v1(check));

    size_t count = 0;
    const struct zcl_service_binding_v1 *catalog =
        zcl_service_binding_catalog_v1(&count);
    if (!catalog || count == 0 || count > ZCL_SERVICE_BINDING_CATALOG_MAX)
        return ZCL_ERR(SERVICE_LIFECYCLE_ERR_CATALOG,
                       "declared service catalog is unusable (count=%zu)",
                       count);

    pthread_mutex_lock(&g_svclc_lock);
    memset(g_rows, 0, sizeof(g_rows));
    for (size_t i = 0; i < count; i++) {
        g_rows[i].binding_id = catalog[i].binding_id;
        g_rows[i].state = ZCL_SERVICE_LIFECYCLE_DECLARED;
        (void)snprintf(g_rows[i].name, sizeof(g_rows[i].name), "%s",
                       catalog[i].name);
    }
    g_row_count = count;
    g_initialized = true;
    pthread_mutex_unlock(&g_svclc_lock);
    return ZCL_OK;
}

/* Apply one event under the lock. `reason` is stored when moving to BLOCKED
 * and cleared on every other transition. */
static struct zcl_result svclc_apply(const char *name, uint32_t event,
                                     const char *reason)
{
    pthread_mutex_lock(&g_svclc_lock);
    if (!g_initialized) {
        pthread_mutex_unlock(&g_svclc_lock);
        return ZCL_ERR(SERVICE_LIFECYCLE_ERR_UNINITIALIZED,
                       "service lifecycle registry is not initialized");
    }
    struct service_lifecycle_row *row = svclc_row(name);
    if (!row) {
        pthread_mutex_unlock(&g_svclc_lock);
        return ZCL_ERR(SERVICE_LIFECYCLE_ERR_UNKNOWN_SERVICE,
                       "no such declared service '%s'", name ? name : "");
    }
    uint32_t next = 0;
    if (!zcl_service_lifecycle_next_v1(row->state, event, &next)) {
        const char *from = zcl_service_lifecycle_name_v1(row->state);
        pthread_mutex_unlock(&g_svclc_lock);
        return ZCL_ERR(SERVICE_LIFECYCLE_ERR_TRANSITION,
                       "service '%s': transition refused from state '%s'",
                       name, from);
    }
    row->state = next;
    row->transitions++;
    if (next == ZCL_SERVICE_LIFECYCLE_BLOCKED) {
        row->fault_count++;
        (void)snprintf(row->reason, sizeof(row->reason), "%s",
                       reason && reason[0] ? reason : "unnamed_fault");
    } else {
        row->reason[0] = '\0';
    }
    pthread_mutex_unlock(&g_svclc_lock);
    return ZCL_OK;
}

struct zcl_result service_lifecycle_register(const char *name)
{
    if (!zcl_service_binding_find_v1(name))
        return ZCL_ERR(SERVICE_LIFECYCLE_ERR_UNKNOWN_SERVICE,
                       "'%s' is not a declared service", name ? name : "");
    return svclc_apply(name, ZCL_SERVICE_EVENT_REGISTER, NULL);
}

struct zcl_result service_lifecycle_start(const char *name,
                                          struct node_db *ndb,
                                          int32_t tip_height)
{
    const struct zcl_service_binding_v1 *binding =
        zcl_service_binding_find_v1(name);
    if (!binding)
        return ZCL_ERR(SERVICE_LIFECYCLE_ERR_UNKNOWN_SERVICE,
                       "'%s' is not a declared service", name ? name : "");
    /* The token binding is the admission rule, evaluated before the state
     * moves. A denied verdict is a named fault, not a quiet refusal. */
    struct service_gate_verdict verdict;
    struct zcl_result evaluated = service_token_gate_evaluate(
        ndb, binding, tip_height, NULL, &verdict);
    if (!evaluated.ok) {
        ZCL_IGNORE_RESULT(svclc_apply(name, ZCL_SERVICE_EVENT_FAULT,
                                       "gate_evaluation_failed"),
                           "the caller already has the harder failure");
        return evaluated;
    }
    if (!verdict.granted) {
        ZCL_IGNORE_RESULT(
            svclc_apply(name, ZCL_SERVICE_EVENT_FAULT,
                        service_gate_reason_name(verdict.reason)),
            "the denial below is the reportable failure");
        return ZCL_ERR(SERVICE_LIFECYCLE_ERR_GATE_DENIED,
                       "service '%s': token gate denied: %s "
                       "(balance %lld < %llu at h=%d)",
                       name, service_gate_reason_name(verdict.reason),
                       (long long)verdict.balance,
                       (unsigned long long)verdict.threshold,
                       verdict.snapshot_height);
    }
    return svclc_apply(name, ZCL_SERVICE_EVENT_START, NULL);
}

struct zcl_result service_lifecycle_stop(const char *name)
{
    ZCL_CHECK(svclc_apply(name, ZCL_SERVICE_EVENT_STOP, NULL));
    /* No worker to drain: pass straight through STOPPING so a stopped
     * service never sits in a state nothing will advance. */
    return svclc_apply(name, ZCL_SERVICE_EVENT_EXIT, NULL);
}

struct zcl_result service_lifecycle_remove(const char *name)
{
    return svclc_apply(name, ZCL_SERVICE_EVENT_REMOVE, NULL);
}

struct zcl_result service_lifecycle_state(const char *name,
                                          uint32_t *out_state,
                                          char *out_reason, size_t reason_sz)
{
    if (!out_state)
        return ZCL_ERR(SERVICE_LIFECYCLE_ERR_ARGUMENT,
                       "service lifecycle state: out_state is NULL");
    pthread_mutex_lock(&g_svclc_lock);
    struct service_lifecycle_row *row = g_initialized ? svclc_row(name) : NULL;
    if (!row) {
        pthread_mutex_unlock(&g_svclc_lock);
        return ZCL_ERR(SERVICE_LIFECYCLE_ERR_UNKNOWN_SERVICE,
                       "no such declared service '%s'", name ? name : "");
    }
    *out_state = row->state;
    if (out_reason && reason_sz)
        (void)snprintf(out_reason, reason_sz, "%s", row->reason);
    pthread_mutex_unlock(&g_svclc_lock);
    return ZCL_OK;
}

bool service_lifecycle_dump_state_json(struct json_value *out, const char *key)
{
    if (!out)
        LOG_RETURN(false, SVCLC_LOG, "dump_state: out is NULL");
    json_set_object(out);

    struct service_lifecycle_row snapshot[ZCL_SERVICE_BINDING_CATALOG_MAX];
    size_t count = 0;
    bool initialized = false;
    pthread_mutex_lock(&g_svclc_lock);
    initialized = g_initialized;
    count = g_row_count;
    memcpy(snapshot, g_rows, sizeof(snapshot));
    pthread_mutex_unlock(&g_svclc_lock);

    (void)json_push_kv_bool(out, "initialized", initialized);
    (void)json_push_kv_str(out, "schema", ZCL_SERVICE_BINDING_SCHEMA_NAME);

    struct json_value services;
    json_init(&services);
    json_set_array(&services);
    size_t shown = 0;
    for (size_t i = 0; i < count; i++) {
        if (key && key[0] && strcmp(key, snapshot[i].name) != 0)
            continue;
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        (void)json_push_kv_str(&item, "service", snapshot[i].name);
        (void)json_push_kv_int(&item, "binding_id",
                               (int64_t)snapshot[i].binding_id);
        (void)json_push_kv_str(&item, "state",
                               zcl_service_lifecycle_name_v1(
                                   snapshot[i].state));
        (void)json_push_kv_str(&item, "blocker", snapshot[i].reason);
        (void)json_push_kv_int(&item, "transitions",
                               (int64_t)snapshot[i].transitions);
        (void)json_push_kv_int(&item, "fault_count",
                               (int64_t)snapshot[i].fault_count);
        (void)json_push_back(&services, &item);
        json_free(&item);
        shown++;
    }
    (void)json_push_kv(out, "services", &services);
    (void)json_push_kv_int(out, "declared", (int64_t)count);
    (void)json_push_kv_int(out, "shown", (int64_t)shown);
    json_free(&services);
    return true;
}
