/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: execute durable wallet intents off the RPC request thread. */

#include "services/vault_intent_async_service.h"

#include "json/json.h"
#include "models/database.h"
#include "models/vault_intent.h"
#include "platform/time_compat.h"
#include "services/agent_session_service.h"
#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VIA_MAX 64
#define VIA_PROGRESS_QUIET_US ((int64_t)11 * 60 * 1000 * 1000)

struct via_job {
    struct node_db *ndb;
    vault_intent_async_execute_fn execute;
    uint8_t plan_id[32];
    char plan_hex[65];
    char wallet_scope[5];
};

static pthread_mutex_t g_via_lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t g_via_ids[VIA_MAX][32];
static bool g_via_used[VIA_MAX];
static _Atomic int g_via_active;
static _Atomic int64_t g_via_completed;
static _Atomic supervisor_child_id g_via_supervisor_id =
    SUPERVISOR_INVALID_ID;
static struct liveness_contract g_via_contract;

static void via_supervisor_tick(struct liveness_contract *contract)
{
    (void)contract;
    supervisor_child_id id = atomic_load(&g_via_supervisor_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    if (atomic_load(&g_via_active) == 0)
        supervisor_progress_idle(id);
    supervisor_tick(id);
}

static void via_supervisor_stall(struct liveness_contract *contract)
{
    LOG_WARN("vault_intent_async",
             "worker completion stalled: active=%d completed=%lld reason=%s",
             atomic_load(&g_via_active),
             (long long)atomic_load(&g_via_completed),
             contract ? supervisor_stall_reason_name(
                 (enum supervisor_stall_reason)
                     atomic_load(&contract->stall_reason)) : "unknown");
}

static struct zcl_result via_supervisor_register(void)
{
    if (atomic_load(&g_via_supervisor_id) != SUPERVISOR_INVALID_ID)
        return ZCL_OK;
    supervisor_domains_init();
    liveness_contract_init(&g_via_contract, "op.vault_intent_async");
    atomic_store(&g_via_contract.period_secs, 5);
    g_via_contract.on_tick = via_supervisor_tick;
    g_via_contract.on_stall = via_supervisor_stall;
    supervisor_child_id id =
        supervisor_register_in_domain(g_op_sup, &g_via_contract);
    if (id == SUPERVISOR_INVALID_ID)
        return ZCL_ERR(-1, "vault intent async supervisor registration failed");
    atomic_store(&g_via_supervisor_id, id);
    supervisor_progress(id, atomic_load(&g_via_completed));
    supervisor_tick(id);
    supervisor_set_progress_max_quiet(id, VIA_PROGRESS_QUIET_US);
    return ZCL_OK;
}

static int via_slot_claim(const uint8_t plan_id[32], bool *duplicate)
{
    int free_slot = -1;
    *duplicate = false;
    (void)pthread_mutex_lock(&g_via_lock);
    for (int i = 0; i < VIA_MAX; i++) {
        if (g_via_used[i] && memcmp(g_via_ids[i], plan_id, 32) == 0) {
            *duplicate = true;
            (void)pthread_mutex_unlock(&g_via_lock);
            return i;
        }
        if (!g_via_used[i] && free_slot < 0)
            free_slot = i;
    }
    if (free_slot >= 0) {
        memcpy(g_via_ids[free_slot], plan_id, 32);
        g_via_used[free_slot] = true;
        (void)atomic_fetch_add(&g_via_active, 1);
    }
    (void)pthread_mutex_unlock(&g_via_lock);
    return free_slot;
}

static void via_slot_release(const uint8_t plan_id[32])
{
    (void)pthread_mutex_lock(&g_via_lock);
    for (int i = 0; i < VIA_MAX; i++) {
        if (g_via_used[i] && memcmp(g_via_ids[i], plan_id, 32) == 0) {
            g_via_used[i] = false;
            memset(g_via_ids[i], 0, sizeof(g_via_ids[i]));
            (void)atomic_fetch_sub(&g_via_active, 1);
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_via_lock);
}

static bool via_error_retryable(const char *code)
{
    if (!code || !code[0])
        return false;
    return strcmp(code, "MONEY_STATE_NOT_CURRENT") == 0 ||
           strcmp(code, "COMMIT_BUSY") == 0 ||
           strcmp(code, "WALLET_UNAVAILABLE") == 0 ||
           strcmp(code, "WALLET_NOT_ENCRYPTED") == 0 ||
           strcmp(code, "WALLET_LOCKED") == 0 ||
           strcmp(code, "WALLET_PERSISTENCE_UNHEALTHY") == 0 ||
           strcmp(code, "ENCRYPTED_BACKUP_REQUIRED") == 0 ||
           strcmp(code, "SOVEREIGNTY_GATE") == 0 ||
           strcmp(code, "NOTE_RESERVATION_FAILED") == 0;
}

static void *via_commit_thread(void *opaque)
{
    struct via_job *job = opaque;
    while (!thread_registry_shutdown_requested()) {
        int64_t now = (int64_t)platform_time_wall_time_t();
        (void)vault_intent_expire_due(job->ndb, now);
        struct vault_intent_row current;
        if (!vault_intent_find(job->ndb, job->plan_id, &current) ||
            (current.state != VAULT_INTENT_PLANNED &&
             current.state != VAULT_INTENT_PROVING))
            break;
        struct json_value input, result;
        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "wallet_scope", job->wallet_scope);
        (void)json_push_kv_str(&input, "plan_id", job->plan_hex);
        (void)json_push_kv_bool(&input, "confirm", true);
        json_init(&result);
        (void)job->execute(&input, &result);
        json_free(&input);

        bool ok = json_get_bool(json_get(&result, "ok"));
        const char *reported = json_get_str(json_get(&result, "code"));
        char code[VAULT_INTENT_ERROR_MAX + 1] = { 0 };
        if (reported)
            (void)snprintf(code, sizeof(code), "%s", reported);
        json_free(&result);
        if (ok)
            break;

        const bool retry = via_error_retryable(code);
        if (!retry) {
            if (job->ndb && job->ndb->open)
                (void)vault_intent_record_planned_error(
                    job->ndb, job->plan_id,
                    code[0] ? code : "ASYNC_COMMIT_FAILED",
                    (int64_t)platform_time_wall_time_t());
            break;
        }
        platform_sleep_ms(1000);
    }
    /* The bounded-session debit is part of the intent's durable state, not
     * the process-local worker. On every exit, settle it from that state:
     * PLANNED/terminal pre-broadcast rows may be credited, while PROVING or
     * any network-observed state is deliberately retained for recovery. */
    if (!agent_session_service_release_bound_intent(job->ndb, job->plan_id))
        LOG_ERROR("vault_intent_async",
                  "bounded intent debit settlement failed");
    via_slot_release(job->plan_id);
    int64_t completed = atomic_fetch_add(&g_via_completed, 1) + 1;
    supervisor_child_id id = atomic_load(&g_via_supervisor_id);
    if (id != SUPERVISOR_INVALID_ID) {
        supervisor_progress(id, completed);
        supervisor_tick(id);
    }
    memset(job, 0, sizeof(*job));
    free(job);
    return NULL;
}

struct zcl_result vault_intent_async_start(
    struct node_db *ndb, const struct vault_intent_row *row,
    const char *plan_hex, bool mark_queued,
    vault_intent_async_execute_fn execute, bool *duplicate_out)
{
    if (!ndb || !ndb->open || !row || !plan_hex || strlen(plan_hex) != 64 ||
        !execute || !duplicate_out)
        return ZCL_ERR(-1, "complete async intent inputs are required");
    *duplicate_out = false;
    struct zcl_result supervised = via_supervisor_register();
    if (!supervised.ok)
        return supervised;

    int slot = via_slot_claim(row->plan_id, duplicate_out);
    if (*duplicate_out)
        return ZCL_OK;
    if (slot < 0)
        return ZCL_ERR(-2, "all %d async wallet worker slots are active",
                       VIA_MAX);

    struct via_job *job = zcl_malloc(sizeof(*job), "via_job");
    if (!job) {
        via_slot_release(row->plan_id);
        return ZCL_ERR(-2, "async wallet worker allocation failed");
    }
    memset(job, 0, sizeof(*job));
    job->ndb = ndb;
    job->execute = execute;
    memcpy(job->plan_id, row->plan_id, sizeof(job->plan_id));
    (void)snprintf(job->plan_hex, sizeof(job->plan_hex), "%s", plan_hex);
    (void)snprintf(job->wallet_scope, sizeof(job->wallet_scope), "%s",
                   row->wallet_scope);
    if (mark_queued && !vault_intent_record_planned_error(
            ndb, row->plan_id, "ASYNC_QUEUED",
            (int64_t)platform_time_wall_time_t())) {
        via_slot_release(row->plan_id);
        memset(job, 0, sizeof(*job)); free(job);
        return ZCL_ERR(-3, "durable async queue marker could not be persisted");
    }
    /* supervised:op.vault_intent_async */
    if (thread_registry_spawn("zcl_vi_commit", via_commit_thread,
                              job, NULL) != 0) {
        via_slot_release(row->plan_id);
        (void)vault_intent_record_planned_error(
            ndb, row->plan_id, "ASYNC_SPAWN_FAILED",
            (int64_t)platform_time_wall_time_t());
        memset(job, 0, sizeof(*job)); free(job);
        return ZCL_ERR(-2, "asynchronous wallet worker could not start");
    }
    return ZCL_OK;
}

struct zcl_result vault_intent_async_recover(
    struct node_db *ndb, vault_intent_async_execute_fn execute)
{
    if (!ndb || !ndb->open || !execute)
        return ZCL_ERR(-1, "open node_db and execute callback are required");
    struct vault_intent_row *rows = zcl_calloc(
        100, sizeof(*rows), "vault intent async recovery rows");
    if (!rows)
        return ZCL_ERR(-2, "queued vault intent workspace allocation failed");
    int n = vault_intent_list(ndb, rows, 100);
    if (n < 0) {
        free(rows);
        return ZCL_ERR(-2, "queued vault intent scan failed");
    }
    for (int i = 0; i < n; i++) {
        if (rows[i].state != VAULT_INTENT_PLANNED ||
            strcmp(rows[i].error_code, "ASYNC_QUEUED") != 0)
            continue;
        char plan_hex[65];
        for (size_t j = 0; j < 32; j++)
            (void)snprintf(plan_hex + j * 2, 3, "%02x", rows[i].plan_id[j]);
        bool duplicate = false;
        struct zcl_result started = vault_intent_async_start(
            ndb, &rows[i], plan_hex, false, execute, &duplicate);
        if (!started.ok) {
            free(rows);
            return started;
        }
    }
    free(rows);
    return ZCL_OK;
}
