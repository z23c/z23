/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private/mixed Sapling routes for the durable vault-intent lifecycle. */
#ifndef ZCL_VAULT_INTENT_PRIVATE_H
#define ZCL_VAULT_INTENT_PRIVATE_H

#include <stdbool.h>

struct json_value;
struct vault_intent_row;
struct wallet_rpc_context;
struct wallet_tx;
struct transaction;

bool vault_intent_private_plan(const struct json_value *input,
                               struct json_value *result);
bool vault_intent_private_build_prepared(
    struct wallet_rpc_context *ctx, const struct vault_intent_row *row,
    struct wallet_tx *wtx, struct json_value *result);

/* Reject a prepared shielded transaction whose anchor is not currently
 * admissible. Planning uses this before reserving funds; commit repeats it
 * before persisting exact bytes. The JSON error is stable and actionable. */
bool vault_intent_private_requirements_current(
    struct wallet_rpc_context *ctx, const struct transaction *tx,
    struct json_value *result);

#endif
