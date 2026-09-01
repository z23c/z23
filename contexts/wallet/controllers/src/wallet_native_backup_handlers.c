/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: owner-gated wallet backup native commands and stdin-only,
 * invocation-scoped backup-password transport. */

#include "controllers/wallet_native_handlers.h"

#include "base/cleanse.h"
#include "command/native_command.h"
#include "controllers/rpc_params.h"
#include "json/json.h"

#include <stdlib.h>
#include <string.h>

void zcl_native_handle_wallet_backup_now(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    bool confirm = json_get_bool_or(request->input, "confirm", false);
    const char *password = json_get_str(json_get(request->input, "password"));
    if (password && password[0] && !zcl_native_input_was_stdin()) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_DENIED, "STDIN_REQUIRED",
                 "backup password is accepted only through --input=-",
                 "core.wallet.backup.now");
        return;
    }
    char token[17];
    wnh_plan_token(token, "backup-now", "", "");

    /* Never echo a password into commit_input. Commit callers provide the
     * invocation-scoped password again through stdin. */
    if (!confirm) {
        const char *env_password = getenv("WALLET_BACKUP_PASSWORD");
        bool encrypted = (password && password[0]) ||
            (env_password && env_password[0]);
        struct json_value ci;
        json_init(&ci);
        json_set_object(&ci);
        (void)json_push_kv_bool(&ci, "confirm", true);
        char commit[128];
        bool encoded = wnh_commit_input(&ci, commit, sizeof(commit));
        json_free(&ci);
        if (!encoded) {
            wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "PLAN_TOO_LARGE",
                     "exact backup commit input exceeds its budget", "confirm");
            return;
        }
        (void)json_push_kv_bool(&reply->data, "encrypted", encrypted);
        (void)json_push_kv_str(&reply->data, "warning",
            encrypted
                ? "commit writes every wallet key to a backup file, "
                  "encrypted under an invocation-scoped stdin password or "
                  "WALLET_BACKUP_PASSWORD"
                : "commit writes every wallet key to a backup file IN THE "
                  "CLEAR (WALLET_BACKUP_PASSWORD is not set)");
        wnh_emit_plan(reply, request->spec->path, "backup-now", token, commit);
        return;
    }

    struct rpc_arg_builder params;
    rpc_arg_builder_init(&params);
    if (password && password[0])
        rpc_arg_builder_push_str(&params, password);
    char *params_json = rpc_arg_builder_to_json(&params);
    if (!params_json) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                 "could not encode wallet backup request", "walletbackupnow");
        return;
    }
    struct json_value body;
    bool called = wnh_call_rpc(reply, "walletbackupnow", params_json, &body);
    if (password && password[0])
        memory_cleanse(params_json, strlen(params_json));
    free(params_json);
    if (!called)
        return;
    (void)json_push_kv(&reply->data, "backup", &body);
    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    (void)json_push_kv_bool(&reply->data, "created", true);
    (void)json_push_kv_str(&reply->data, "plan_token", token);
    reply->error.mutated = true;
    json_free(&body);
}
