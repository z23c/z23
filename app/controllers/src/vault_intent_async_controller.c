/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: thin RPC adapter for durable asynchronous vault intents. */

#include "controllers/vault_intent_controller.h"
#include "controllers/vault_intent_publish.h"

#include "controllers/native_handler_body.h"
#include "controllers/strong_params.h"
#include "controllers/wallet_helpers.h"
#include "base/safe_alloc.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "models/vault_intent.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "services/vault_intent_async_service.h"
#include "services/wallet_money_service.h"
#include "util/log_macros.h"

#include <string.h>

static void via_error(struct json_value *out, const char *code,
                      const char *message)
{
    vault_intent_error_response(out, code, message);
}

static bool via_unhex(const char *text, uint8_t out[32])
{
    return text && strlen(text) == 64 && IsHex(text) &&
           ParseHex(text, out, 32) == 32;
}

static bool via_input(const struct json_value *input, uint8_t id[32],
                      const char **scope, const char **hex,
                      struct json_value *result)
{
    *hex = input ? json_get_str(json_get(input, "plan_id")) : NULL;
    *scope = input ? json_get_str(json_get(input, "wallet_scope")) : NULL;
    if (!input || !wallet_money_scope_valid(*scope) ||
        !json_get_bool_or(input, "confirm", false) ||
        !via_unhex(*hex, id)) {
        via_error(result, "CONFIRM_REQUIRED",
                  "wallet_scope, plan_id, and confirm:true are required");
        return false;
    }
    return true;
}

static bool via_scope_matches(const struct vault_intent_row *row,
                              const char *scope, struct json_value *result)
{
    if (row->wallet_scope[0] && strcmp(row->wallet_scope, scope) == 0)
        return true;
    via_error(result, row->wallet_scope[0] ? "WALLET_SCOPE_MISMATCH"
                                          : "LEGACY_PLAN_UNBOUND",
              "the plan is not bound to the explicitly targeted wallet scope");
    return false;
}

/* Queueing and cancellation mutate only the durable intent ledger. Spend
 * readiness belongs to the worker immediately before claim/sign/broadcast;
 * making an RPC caller wait for wallet health, backup, sovereignty, or a
 * money snapshot defeats the purpose of the asynchronous boundary. */
static struct wallet_rpc_context *via_storage_context(
    struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    if (ctx && ctx->node_db && ctx->node_db->open)
        return ctx;
    via_error(result, "WALLET_UNAVAILABLE",
              "the durable wallet intent ledger is unavailable");
    return NULL;
}

static bool rpc_via_submit(const struct json_value *params, bool help,
                           struct json_value *result)
{
    RPC_HELP(help, result,
             "vault_intent_submit {wallet_scope,plan_id,confirm:true}\n");
    const struct json_value *input = json_at(params, 0);
    uint8_t id[32]; const char *scope = NULL; const char *hex = NULL;
    if (!via_input(input, id, &scope, &hex, result))
        return true;
    struct wallet_rpc_context *ctx = via_storage_context(result);
    if (!ctx)
        return true;
    struct vault_intent_row row;
    if (!vault_intent_find(ctx->node_db, id, &row)) {
        via_error(result, "PLAN_NOT_FOUND", "no durable plan has that id");
        return true;
    }
    if (!via_scope_matches(&row, scope, result))
        return true;
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (row.state == VAULT_INTENT_PLANNED && row.expires_at <= now) {
        (void)vault_intent_expire_due(ctx->node_db, now);
        (void)vault_intent_find(ctx->node_db, id, &row);
    }
    if (row.state >= VAULT_INTENT_MEMPOOL_ACCEPTED &&
        row.state <= VAULT_INTENT_FINALIZED) {
        json_set_object(result); (void)json_push_kv_bool(result, "ok", true);
        vault_intent_render_row(ctx, result, &row);
        (void)json_push_kv_str(result, "operation_id", hex);
        (void)json_push_kv_str(result, "operation_status", "complete");
        (void)json_push_kv_bool(result, "idempotent_submit", true);
        return true;
    }
    if (row.state != VAULT_INTENT_PLANNED &&
        row.state != VAULT_INTENT_PROVING) {
        via_error(result, "PLAN_NOT_SUBMITTABLE",
                  vault_intent_state_name(row.state));
        return true;
    }
    bool duplicate = false;
    struct zcl_result started = vault_intent_async_start(
        ctx->node_db, &row, hex, row.state == VAULT_INTENT_PLANNED,
        vault_intent_commit_input, &duplicate);
    if (!started.ok) {
        via_error(result, started.code == -3 ? "QUEUE_PERSIST_FAILED"
                                            : "ASYNC_CAPACITY",
                  started.message);
        return true;
    }
    (void)vault_intent_find(ctx->node_db, id, &row);
    json_set_object(result); (void)json_push_kv_bool(result, "ok", true);
    vault_intent_render_row(ctx, result, &row);
    (void)json_push_kv_str(result, "operation_id", hex);
    (void)json_push_kv_str(result, "operation_status", "queued");
    (void)json_push_kv_bool(result, "durable", true);
    (void)json_push_kv_bool(result, "idempotent_submit", duplicate);
    (void)json_push_kv_str(result, "status_command", "vault.intent.status");
    return true;
}

static bool rpc_via_cancel(const struct json_value *params, bool help,
                           struct json_value *result)
{
    RPC_HELP(help, result,
             "vault_intent_cancel {wallet_scope,plan_id,confirm:true}\n");
    const struct json_value *input = json_at(params, 0);
    uint8_t id[32]; const char *scope = NULL; const char *hex = NULL;
    if (!via_input(input, id, &scope, &hex, result))
        return true;
    struct wallet_rpc_context *ctx = via_storage_context(result);
    if (!ctx)
        return true;
    struct vault_intent_row row;
    if (!vault_intent_find(ctx->node_db, id, &row)) {
        via_error(result, "PLAN_NOT_FOUND", "no durable plan has that id");
        return true;
    }
    if (!via_scope_matches(&row, scope, result))
        return true;
    bool replay = row.state == VAULT_INTENT_FAILED &&
                  strcmp(row.error_code, "CANCELLED_BY_OWNER") == 0;
    if (!replay && !vault_intent_cancel_planned(
            ctx->node_db, id, (int64_t)platform_time_wall_time_t())) {
        via_error(result, "CANCEL_UNSAFE",
                  "only an unclaimed planned intent can be cancelled");
        return true;
    }
    (void)vault_intent_find(ctx->node_db, id, &row);
    json_set_object(result); (void)json_push_kv_bool(result, "ok", true);
    vault_intent_render_row(ctx, result, &row);
    (void)json_push_kv_str(result, "operation_id", hex);
    (void)json_push_kv_bool(result, "idempotent_cancel", replay);
    return true;
}

static void via_recover_mempool_intents(struct node_db *ndb)
{
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    if (!ctx)
        return;
    struct vault_intent_row *rows = zcl_calloc(
        100, sizeof(*rows), "vault intent mempool recovery rows");
    if (!rows) {
        LOG_WARN("vault_intent", "startup exact-transaction restore "
                 "deferred: recovery row allocation failed");
        return;
    }
    int count = vault_intent_list(ndb, rows, 100);
    if (count < 0) {
        LOG_WARN("vault_intent", "startup exact-transaction restore "
                 "deferred: durable intent scan failed");
        free(rows);
        return;
    }
    for (int i = 0; i < count; i++) {
        if (rows[i].state != VAULT_INTENT_MEMPOOL_ACCEPTED ||
            !rows[i].wallet_scope[0])
            continue;
        struct json_value result;
        json_init(&result);
        if (!vault_intent_republish_durable(
                ctx, rows[i].plan_id,
                (int64_t)platform_time_wall_time_t(), &result)) {
            const char *code = json_get_str(json_get(&result, "code"));
            LOG_WARN("vault_intent",
                     "startup exact-transaction restore deferred: %s",
                     code && code[0] ? code : "UNKNOWN");
        }
        json_free(&result);
    }
    free(rows);
}

#if defined(_WIN32) && defined(__clang__)
/* This registrar also performs bounded startup recovery. Keep that recovery
 * graph out of Clang's Windows whole-program inliner so its caller does not
 * acquire a roughly 1.6 MiB native stack frame. */
__attribute__((optnone))
#elif defined(_WIN32) && defined(__GNUC__)
__attribute__((optimize("no-inline", "no-inline-functions",
                        "no-inline-small-functions")))
#endif
void register_vault_intent_async_rpc_commands(struct rpc_table *table)
{
    const struct rpc_command commands[] = {
        { "wallet", "vault_intent_submit", rpc_via_submit, false },
        { "wallet", "vault_intent_cancel", rpc_via_cancel, false },
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(table, &commands[i]);

    struct node_db *ndb = wallet_rpc_node_db();
    if (!ndb || !ndb->open)
        return;
    via_recover_mempool_intents(ndb);
    struct zcl_result recovered = vault_intent_async_recover(
        ndb, vault_intent_commit_input);
    if (!recovered.ok)
        LOG_WARN("vault_intent", "async recovery deferred: %s",
                 recovered.message);
}
