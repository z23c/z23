/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: register the durable transaction-intent wallet RPC surface. */
#ifndef ZCL_VAULT_INTENT_CONTROLLER_H
#define ZCL_VAULT_INTENT_CONTROLLER_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
struct rpc_table;
struct json_value;
struct wallet_rpc_context;
struct vault_intent_row;
struct main_state;
#define VAULT_INTENT_TRANSPARENT_APPLICATION "vault_transparent"
void register_vault_intent_rpc_commands(struct rpc_table *table);
void register_vault_intent_async_rpc_commands(struct rpc_table *table);
bool vault_intent_parse_zcl_amount(const char *text, int64_t *out_zat);
bool vault_intent_idempotency_key_valid(const char *key);
bool vault_intent_context_ready(struct wallet_rpc_context *ctx,
                                struct json_value *out);
/* Stable failure envelope shared by plan, commit, submit, fanout, and
 * publication adapters.  `code` remains for wire compatibility while
 * `error_code` and the recovery fields make retry behavior explicit. */
void vault_intent_error_response(struct json_value *out, const char *code,
                                 const char *message);
void vault_intent_digest_payload(const uint8_t *raw, size_t len,
                                 const struct vault_intent_row *row,
                                 uint8_t out[32]);
void vault_intent_render_row(struct wallet_rpc_context *ctx,
                             struct json_value *out,
                             const struct vault_intent_row *row);
void vault_intent_refresh_state(struct wallet_rpc_context *ctx,
                                struct vault_intent_row *row, int64_t now);
/* Fanout validates the encrypted-backup gate before creating its durable
 * receive keys. This continuation repeats every other plan gate but does not
 * reject those newly-created keys merely because they postdate that preflight.
 * Commit still performs the normal current-backup gate, so the owner must back
 * up the exact destinations before any value can move. */
bool vault_intent_plan_transparent_fanout_continuation(
    const struct json_value *params, struct json_value *result);
bool vault_intent_transparent_shape_matches(
    const struct vault_intent_row *row, size_t output_count,
    int64_t output_value_zat);
bool vault_intent_fanout_plan_rpc(const struct json_value *params, bool help,
                                  struct json_value *result);
bool vault_intent_commit_input(const struct json_value *input,
                               struct json_value *result);
bool vault_intent_prepared_retry_allowed(
    const struct vault_intent_row *row, bool prepared_raw);
bool vault_intent_anchor_current(const struct wallet_rpc_context *ctx,
                                 const struct vault_intent_row *row);
bool vault_intent_chain_confirmation(struct main_state *ms,
                                     const uint8_t block_hash[32],
                                     int32_t *height_out,
                                     int32_t *confirmations_out);
#endif
