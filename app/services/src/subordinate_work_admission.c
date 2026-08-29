/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Shared live-fact observation and pure subordinate-work admission. */

#include "services/subordinate_work_admission.h"

#include "models/database.h"
#include "services/disk_monitor.h"
#include "sync/sync_state.h"
#include "util/mem_pressure.h"

#include <string.h>

const char *subordinate_work_refusal_token(enum subordinate_work_refusal reason)
{
    switch (reason) {
    case SUBORDINATE_WORK_NOT_OBSERVED: return "not_observed";
    case SUBORDINATE_WORK_ADMIT: return "admit";
    case SUBORDINATE_WORK_STOPPING: return "stopping";
    case SUBORDINATE_WORK_SYNC_NOT_AT_TIP: return "sync_not_at_tip";
    case SUBORDINATE_WORK_DISK_PRESSURE: return "disk_pressure";
    case SUBORDINATE_WORK_MEMORY_PRESSURE: return "memory_pressure";
    case SUBORDINATE_WORK_DB_LONG_OPERATION: return "db_long_operation";
    case SUBORDINATE_WORK_PERSISTENCE_UNAVAILABLE:
        return "persistence_unavailable";
    case SUBORDINATE_WORK_DB_CLOSED: return "db_closed";
    case SUBORDINATE_WORK_DB_TRANSACTION: return "db_transaction";
    case SUBORDINATE_WORK_DB_TURBO: return "db_turbo";
    case SUBORDINATE_WORK_DB_PENDING_BLOCKS: return "db_pending_blocks";
    }
    return "invalid_facts";
}

enum subordinate_work_refusal subordinate_work_admission_decide(
    const struct subordinate_work_facts *facts)
{
    if (!facts)
        return SUBORDINATE_WORK_NOT_OBSERVED;
    if (!facts->running)
        return SUBORDINATE_WORK_STOPPING;
    if (!facts->sync_at_tip)
        return SUBORDINATE_WORK_SYNC_NOT_AT_TIP;
    if (!facts->disk_clear)
        return SUBORDINATE_WORK_DISK_PRESSURE;
    if (!facts->memory_clear)
        return SUBORDINATE_WORK_MEMORY_PRESSURE;
    if (!facts->db_long_operation_clear)
        return SUBORDINATE_WORK_DB_LONG_OPERATION;
    if (!facts->persistence_ready)
        return SUBORDINATE_WORK_PERSISTENCE_UNAVAILABLE;
    if (!facts->db_open)
        return SUBORDINATE_WORK_DB_CLOSED;
    if (!facts->db_transaction_clear)
        return SUBORDINATE_WORK_DB_TRANSACTION;
    if (!facts->db_turbo_clear)
        return SUBORDINATE_WORK_DB_TURBO;
    if (!facts->db_pending_blocks_clear)
        return SUBORDINATE_WORK_DB_PENDING_BLOCKS;
    return SUBORDINATE_WORK_ADMIT;
}

struct zcl_result subordinate_work_admission_observe(
    bool running, bool persistence_ready, struct node_db *ndb,
    struct subordinate_work_facts *out)
{
    if (!out)
        return ZCL_ERR(-1, "subordinate work observation requires output");
    memset(out, 0, sizeof(*out));
    struct node_db_status status;
    memset(&status, 0, sizeof(status));
    if (ndb)
        node_db_get_status(ndb, &status);
    out->running = running;
    out->sync_at_tip = sync_get_state() == SYNC_AT_TIP;
    out->disk_clear = disk_monitor_level() == DISK_MONITOR_OK;
    out->memory_clear = mem_pressure_current() < MEM_HIGH;
    out->db_long_operation_clear = !node_db_long_op_active(NULL, NULL);
    out->persistence_ready = persistence_ready;
    out->db_open = status.open;
    out->db_transaction_clear = !status.tx_open;
    out->db_turbo_clear = !status.turbo_mode;
    out->db_pending_blocks_clear = status.sync_pending_blocks == 0;
    return ZCL_OK;
}
