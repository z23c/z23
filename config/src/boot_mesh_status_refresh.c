/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded, sync-subordinate refresh of paired-machine status. */

#include "config/boot_mesh_status.h"

#include "config/boot_internal.h"
#include "config/db_service.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "models/database.h"
#include "models/mesh_machine_observation.h"
#include "models/mesh_pairing.h"
#include "services/disk_monitor.h"
#include "supervisors/domains.h"
#include "sync/sync_state.h"
#include "util/log_macros.h"
#include "util/mem_pressure.h"
#include "util/supervisor.h"
#include "util/sync.h"
#include "platform/time_compat.h"

#include <limits.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define MESH_REFRESH_PAIRING_MAX 64u
#define MESH_REFRESH_INFLIGHT_MAX 2u
#define MESH_REFRESH_OK_INTERVAL_S 15
#define MESH_REFRESH_BACKOFF_S 30

static_assert(MESH_REFRESH_INFLIGHT_MAX <= MESH_STATUS_PENDING_MAX);

struct mesh_refresh_slot {
    bool used;
    char pairing_id[MESH_PAIRING_ID_HEX + 1];
    uint8_t request_id[32];
};

struct mesh_refresh_cooldown {
    bool used;
    char pairing_id[MESH_PAIRING_ID_HEX + 1];
    int64_t next_attempt;
};

struct mesh_refresh_write {
    struct db_mesh_machine_observation row;
};

static zcl_mutex_t g_refresh_lock;
static _Atomic int g_refresh_lock_state;
static struct boot_svc_ctx *g_refresh_svc;
static struct liveness_contract g_refresh_contract;
static supervisor_child_id g_refresh_child = SUPERVISOR_INVALID_ID;
static struct mesh_refresh_slot g_refresh_slots[MESH_REFRESH_INFLIGHT_MAX];
static struct mesh_refresh_cooldown
    g_refresh_cooldowns[MESH_REFRESH_PAIRING_MAX];
static int64_t g_refresh_last_admit;
static uint64_t g_refresh_completed;

static void refresh_lock(void)
{
    if (atomic_load_explicit(&g_refresh_lock_state, memory_order_acquire) != 2) {
        int expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &g_refresh_lock_state, &expected, 1, memory_order_acq_rel,
                memory_order_acquire)) {
            zcl_mutex_init(&g_refresh_lock);
            atomic_store_explicit(&g_refresh_lock_state, 2,
                                  memory_order_release);
        } else {
            while (atomic_load_explicit(&g_refresh_lock_state,
                                        memory_order_acquire) != 2)
                ;
        }
    }
    zcl_mutex_lock(&g_refresh_lock);
}

static bool refresh_row_from_receipt(
    const struct mesh_status_receipt_v1 *receipt,
    struct db_mesh_machine_observation *row)
{
    if (!receipt || !row || receipt->observed_unix > INT64_MAX ||
        receipt->expires_unix > INT64_MAX)
        return false;
    memset(row, 0, sizeof(*row));
    zcl_hex_encode(receipt->pairing_id, 32, row->pairing_id);
    if (mesh_status_receipt_v1_encode(
            receipt, row->receipt_wire, sizeof(row->receipt_wire),
            &row->receipt_len) != MESH_STATUS_PROTO_OK ||
        mesh_status_receipt_v1_root(receipt, row->receipt_root) !=
            MESH_STATUS_PROTO_OK)
        return false;
    row->status = receipt->status;
    row->observed_unix = (int64_t)receipt->observed_unix;
    row->expires_unix = (int64_t)receipt->expires_unix;
    row->received_unix = (int64_t)platform_time_wall_time_t();
    return row->received_unix > 0;
}

static bool refresh_write_run(struct node_db *ndb, void *opaque)
{
    struct mesh_refresh_write *write = opaque;
    return ndb && write &&
           db_mesh_machine_observation_save(ndb, &write->row);
}

bool boot_mesh_status_receipt_persist(
    struct db_service *dbsvc,
    const struct mesh_status_receipt_v1 *receipt)
{
    struct mesh_refresh_write write;
    if (!dbsvc || !refresh_row_from_receipt(receipt, &write.row))
        return false;
    return db_service_run_write(dbsvc, refresh_write_run, &write);
}

static void refresh_write_free(void *opaque)
{
    free(opaque);
}

static bool refresh_enqueue_receipt(struct db_service *dbsvc,
                                    const struct mesh_status_receipt_v1 *receipt)
{
    struct mesh_refresh_write *write =
        zcl_calloc(1, sizeof(*write), "mesh_status.refresh_write");
    if (!write)
        return false;
    if (!refresh_row_from_receipt(receipt, &write->row)) {
        free(write);
        return false;
    }
    return db_service_enqueue_write(dbsvc, refresh_write_run, write,
                                    refresh_write_free);
}

static struct mesh_refresh_cooldown *refresh_cooldown(const char *pairing_id)
{
    struct mesh_refresh_cooldown *free_slot = NULL;
    for (size_t i = 0; i < MESH_REFRESH_PAIRING_MAX; i++) {
        struct mesh_refresh_cooldown *entry = &g_refresh_cooldowns[i];
        if (entry->used && strcmp(entry->pairing_id, pairing_id) == 0)
            return entry;
        if (!entry->used && !free_slot)
            free_slot = entry;
    }
    if (free_slot) {
        free_slot->used = true;
        memcpy(free_slot->pairing_id, pairing_id, MESH_PAIRING_ID_HEX + 1u);
    }
    return free_slot;
}

static bool refresh_inflight(const char *pairing_id)
{
    for (size_t i = 0; i < MESH_REFRESH_INFLIGHT_MAX; i++)
        if (g_refresh_slots[i].used &&
            strcmp(g_refresh_slots[i].pairing_id, pairing_id) == 0)
            return true;
    return false;
}

static bool refresh_gate(bool running, int sync_state, int disk_level,
                         int memory_level, bool long_db_operation,
                         bool db_service_started,
                         const struct node_db_status *status)
{
    return running && sync_state == SYNC_AT_TIP &&
           disk_level == DISK_MONITOR_OK && memory_level < MEM_HIGH &&
           !long_db_operation && db_service_started && status &&
           status->open && !status->tx_open && !status->turbo_mode &&
           status->sync_pending_blocks == 0;
}

static bool refresh_resources_allow(struct boot_svc_ctx *svc)
{
    if (!svc)
        return false;
    struct node_db *ndb = boot_node_db(svc);
    struct db_service *dbsvc = boot_db_service(svc);
    if (!ndb || !dbsvc)
        return false;
    struct node_db_status status;
    node_db_get_status(ndb, &status);
    return refresh_gate(boot_running(svc), sync_get_state(),
                        disk_monitor_level(), mem_pressure_current(),
                        node_db_long_op_active(NULL, NULL),
                        db_service_is_started(dbsvc), &status);
}

#ifdef ZCL_TESTING
bool boot_mesh_status_refresh_test_gate(
    bool running, int sync_state, int disk_level, int memory_level,
    bool long_db_operation, bool db_service_started,
    const struct node_db_status *db_status)
{
    return refresh_gate(running, sync_state, disk_level, memory_level,
                        long_db_operation, db_service_started, db_status);
}
#endif

static void refresh_poll(struct boot_svc_ctx *svc, int64_t now)
{
    for (size_t i = 0; i < MESH_REFRESH_INFLIGHT_MAX; i++) {
        struct mesh_refresh_slot *slot = &g_refresh_slots[i];
        if (!slot->used)
            continue;
        struct mesh_status_receipt_v1 receipt;
        enum boot_mesh_status_poll_state state =
            boot_mesh_status_poll(slot->request_id, &receipt);
        if (state == MESH_STATUS_POLL_PENDING)
            continue;
        struct mesh_refresh_cooldown *cooldown =
            refresh_cooldown(slot->pairing_id);
        if ((state == MESH_STATUS_POLL_OK ||
             state == MESH_STATUS_POLL_REFUSED) &&
            refresh_enqueue_receipt(boot_db_service(svc), &receipt)) {
            if (cooldown)
                cooldown->next_attempt = now + MESH_REFRESH_OK_INTERVAL_S;
            memset(slot, 0, sizeof(*slot));
            g_refresh_completed++;
            supervisor_progress(g_refresh_child,
                                (int64_t)g_refresh_completed);
        } else if (state == MESH_STATUS_POLL_EXPIRED ||
                   state == MESH_STATUS_POLL_UNKNOWN) {
            if (cooldown)
                cooldown->next_attempt = now + MESH_REFRESH_BACKOFF_S;
            memset(slot, 0, sizeof(*slot));
        }
    }
}

static void refresh_begin_one(struct boot_svc_ctx *svc, int64_t now)
{
    if (now <= g_refresh_last_admit)
        return;
    struct mesh_refresh_slot *slot = NULL;
    for (size_t i = 0; i < MESH_REFRESH_INFLIGHT_MAX; i++)
        if (!g_refresh_slots[i].used) {
            slot = &g_refresh_slots[i];
            break;
        }
    if (!slot)
        return;
    struct db_mesh_pairing rows[MESH_REFRESH_PAIRING_MAX];
    int count = db_mesh_pairing_list(boot_node_db(svc), rows,
                                     MESH_REFRESH_PAIRING_MAX);
    if (count <= 0)
        return;
    struct db_mesh_pairing *choice = NULL;
    struct mesh_refresh_cooldown *choice_cooldown = NULL;
    for (int i = 0; i < count; i++) {
        if (!mesh_pairing_allows(&rows[i], MESH_PAIRING_CAP_STATUS_READ, now) ||
            refresh_inflight(rows[i].pairing_id))
            continue;
        struct mesh_refresh_cooldown *cooldown =
            refresh_cooldown(rows[i].pairing_id);
        if (!cooldown || cooldown->next_attempt > now)
            continue;
        if (!choice || cooldown->next_attempt < choice_cooldown->next_attempt) {
            choice = &rows[i];
            choice_cooldown = cooldown;
        }
    }
    if (!choice)
        return;
    g_refresh_last_admit = now;
    enum boot_mesh_status_begin_result began =
        boot_mesh_status_begin(choice->pairing_id, slot->request_id);
    if (began == MESH_STATUS_BEGIN_OK) {
        slot->used = true;
        memcpy(slot->pairing_id, choice->pairing_id,
               MESH_PAIRING_ID_HEX + 1u);
    } else {
        choice_cooldown->next_attempt = now + MESH_REFRESH_BACKOFF_S;
    }
}

static void refresh_tick(struct liveness_contract *contract)
{
    (void)contract;
    refresh_lock();
    struct boot_svc_ctx *svc = g_refresh_svc;
    if (!svc) {
        zcl_mutex_unlock(&g_refresh_lock);
        return;
    }
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (now > 0)
        refresh_poll(svc, now);
    if (now > 0 && refresh_resources_allow(svc))
        refresh_begin_one(svc, now);
    else
        supervisor_progress_idle(g_refresh_child);
    zcl_mutex_unlock(&g_refresh_lock);
}

void boot_mesh_status_refresh_start(struct boot_svc_ctx *svc)
{
    if (!svc)
        return;
    refresh_lock();
    if (g_refresh_child != SUPERVISOR_INVALID_ID || g_refresh_svc) {
        zcl_mutex_unlock(&g_refresh_lock);
        LOG_ERROR("net.mesh_status", "refresh already started");
        return;
    }
    g_refresh_svc = svc;
    memset(g_refresh_slots, 0, sizeof(g_refresh_slots));
    memset(g_refresh_cooldowns, 0, sizeof(g_refresh_cooldowns));
    g_refresh_last_admit = 0;
    g_refresh_completed = 0;
    liveness_contract_init(&g_refresh_contract, "net.mesh_status_refresh");
    g_refresh_contract.on_tick = refresh_tick;
    supervisor_domains_init();
    g_refresh_child = supervisor_register_in_domain(g_net_sup,
                                                     &g_refresh_contract);
    if (g_refresh_child != SUPERVISOR_INVALID_ID) {
        supervisor_set_period(g_refresh_child, 1);
        supervisor_set_deadline(g_refresh_child, 30);
        supervisor_set_progress_exempt(
            g_refresh_child, "paired peers may be absent indefinitely");
    } else {
        g_refresh_svc = NULL;
        LOG_ERROR("net.mesh_status", "refresh supervisor register failed");
    }
    zcl_mutex_unlock(&g_refresh_lock);
}

void boot_mesh_status_refresh_shutdown(void)
{
    refresh_lock();
    supervisor_child_id child = g_refresh_child;
    g_refresh_child = SUPERVISOR_INVALID_ID;
    g_refresh_svc = NULL;
    memset(g_refresh_slots, 0, sizeof(g_refresh_slots));
    memset(g_refresh_cooldowns, 0, sizeof(g_refresh_cooldowns));
    zcl_mutex_unlock(&g_refresh_lock);
    if (child != SUPERVISOR_INVALID_ID)
        supervisor_unregister(child);
    /* Barrier with a callback already snapshotted by the supervisor. */
    refresh_lock();
    zcl_mutex_unlock(&g_refresh_lock);
}
