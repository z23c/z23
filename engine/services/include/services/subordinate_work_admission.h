/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: One fail-closed admission decision for blockchain-subordinate work. */

#ifndef ZCL_SERVICES_SUBORDINATE_WORK_ADMISSION_H
#define ZCL_SERVICES_SUBORDINATE_WORK_ADMISSION_H

#include "base/result.h"

#include <stdbool.h>

struct node_db;

enum subordinate_work_refusal {
    SUBORDINATE_WORK_NOT_OBSERVED = 0,
    SUBORDINATE_WORK_ADMIT,
    SUBORDINATE_WORK_STOPPING,
    SUBORDINATE_WORK_SYNC_NOT_AT_TIP,
    SUBORDINATE_WORK_DISK_PRESSURE,
    SUBORDINATE_WORK_MEMORY_PRESSURE,
    SUBORDINATE_WORK_DB_LONG_OPERATION,
    SUBORDINATE_WORK_PERSISTENCE_UNAVAILABLE,
    SUBORDINATE_WORK_DB_CLOSED,
    SUBORDINATE_WORK_DB_TRANSACTION,
    SUBORDINATE_WORK_DB_TURBO,
    SUBORDINATE_WORK_DB_PENDING_BLOCKS,
};

struct subordinate_work_facts {
    bool running;
    bool sync_at_tip;
    bool disk_clear;
    bool memory_clear;
    bool db_long_operation_clear;
    bool persistence_ready;
    bool db_open;
    bool db_transaction_clear;
    bool db_turbo_clear;
    bool db_pending_blocks_clear;
};

const char *subordinate_work_refusal_token(enum subordinate_work_refusal reason);

enum subordinate_work_refusal subordinate_work_admission_decide(
    const struct subordinate_work_facts *facts);

/* Observe the shared live facts. `persistence_ready` names the caller's
 * required durable writer: the DB service for asynchronous mesh writes, or
 * the canonical open handle for the build worker. */
struct zcl_result subordinate_work_admission_observe(
    bool running, bool persistence_ready, struct node_db *ndb,
    struct subordinate_work_facts *out);

#endif /* ZCL_SERVICES_SUBORDINATE_WORK_ADMISSION_H */
