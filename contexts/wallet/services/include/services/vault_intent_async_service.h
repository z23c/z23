/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Durable asynchronous execution for wallet transaction intents. */
#ifndef ZCL_SERVICES_VAULT_INTENT_ASYNC_SERVICE_H
#define ZCL_SERVICES_VAULT_INTENT_ASYNC_SERVICE_H

#include "base/result.h"

#include <stdbool.h>

struct json_value;
struct node_db;
struct vault_intent_row;

typedef bool (*vault_intent_async_execute_fn)(
    const struct json_value *input, struct json_value *result);

/* Start or deduplicate one process-local worker. The vault intent itself is
 * the durable job record; no second operation ledger is created. */
struct zcl_result vault_intent_async_start(
    struct node_db *ndb, const struct vault_intent_row *row,
    const char *plan_hex, bool mark_queued,
    vault_intent_async_execute_fn execute, bool *duplicate_out);

/* Requeue restart-surviving PLANNED rows carrying ASYNC_QUEUED. */
struct zcl_result vault_intent_async_recover(
    struct node_db *ndb, vault_intent_async_execute_fn execute);

#endif
