/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: publish one exact prepared vault transaction restart-safely. */
#ifndef ZCL_VAULT_INTENT_PUBLISH_H
#define ZCL_VAULT_INTENT_PUBLISH_H

#include <stdbool.h>
#include <stdint.h>

struct json_value;
struct wallet_rpc_context;
struct wallet_tx;

/* Convert wallet_commit_transaction()'s bounded mempool result into a stable,
 * public status code.  The free-form diagnostic remains log-only; agents can
 * branch on this code without parsing prose. */
const char *vault_intent_mempool_error_code(int result_code,
                                             const char *message);

bool vault_intent_publish_prepared(struct wallet_rpc_context *ctx,
                                   const uint8_t id[32],
                                   struct wallet_tx *wtx, int64_t now,
                                   struct json_value *result);

/* Load and re-admit the exact signed bytes of a durable mempool-accepted
 * intent when a restart left them absent from the current mempool. */
bool vault_intent_republish_durable(struct wallet_rpc_context *ctx,
                                    const uint8_t id[32], int64_t now,
                                    struct json_value *result);

#endif
