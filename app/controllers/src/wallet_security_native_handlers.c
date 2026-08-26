/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Canonical native custody surface. Secret inputs are accepted only through
 * --input=-; argv and environment transport are refused before RPC dispatch. */

#include "controllers/wallet_native_handlers.h"
#include "command/native_command.h"
#include "controllers/rpc_params.h"
#include "json/json.h"

#include <stdlib.h>

static bool wallet_security_secret_input(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (zcl_native_input_was_stdin())
        return true;
    wnh_fail(reply, ZCL_COMMAND_EXIT_DENIED, "STDIN_REQUIRED",
             "passphrase input is accepted only through --input=-",
             request && request->spec ? request->spec->path : "wallet.security");
    return false;
}

static void wallet_security_copy_status(struct zcl_command_reply *reply,
                                        const char *method,
                                        const char *params)
{
    struct json_value body;
    if (!wnh_call_rpc(reply, method, params, &body))
        return;
    if (body.type != JSON_OBJ) {
        json_free(&body);
        wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "BAD_WALLET_SECURITY_BODY",
                 "wallet security RPC did not return an object", method);
        return;
    }
    for (size_t i = 0; i < body.num_children; i++) {
        struct json_value copy;
        json_init(&copy);
        json_copy(&copy, &body.children[i]);
        (void)json_push_kv(&reply->data, body.keys[i], &copy);
        json_free(&copy);
    }
    json_free(&body);
}

void zcl_native_handle_wallet_security_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    wallet_security_copy_status(reply, "walletlockstatus", NULL);
}

void zcl_native_handle_wallet_security_lock(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    wallet_security_copy_status(reply, "walletlock", NULL);
    reply->error.mutated = true;
}

void zcl_native_handle_wallet_security_unlock(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!wallet_security_secret_input(request, reply))
        return;
    const char *pass = json_get_str(json_get(request->input, "passphrase"));
    int64_t timeout = json_get_int_or(request->input, "timeout_seconds", 300);
    if (!pass || !pass[0]) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_PASSPHRASE",
                 "passphrase is required", "passphrase");
        return;
    }
    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, pass);
    rpc_arg_builder_push_int(&p, timeout);
    char *params = rpc_arg_builder_to_json(&p);
    if (!params) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                 "could not encode wallet unlock request", "walletunlock");
        return;
    }
    wallet_security_copy_status(reply, "walletunlock", params);
    free(params);
    reply->error.mutated = true;
}

void zcl_native_handle_wallet_security_encrypt(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!wallet_security_secret_input(request, reply))
        return;
    const char *pass = json_get_str(json_get(request->input, "passphrase"));
    if (!pass || !pass[0]) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_PASSPHRASE",
                 "passphrase is required", "passphrase");
        return;
    }
    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, pass);
    char *params = rpc_arg_builder_to_json(&p);
    if (!params) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                 "could not encode wallet encryption request", "walletencrypt");
        return;
    }
    wallet_security_copy_status(reply, "walletencrypt", params);
    free(params);
    reply->error.mutated = true;
}

/* ── Hot-swappable leaves ──────────────────────────────────────────────────
 * The wallet's READ-ONLY security posture: whether a keystore exists and
 * whether it is locked. Every other leaf in this file — lock, unlock,
 * encrypt — changes keystore state and is deliberately absent from both
 * tables. Read-only is the whole reason this one may move at runtime. */
#ifdef ZCL_HOTSWAP_GEN
#define ZCL_HOTSWAP_PROBE_LEAF "core.wallet.security.status"
#include "hotswap/hotswap.h"
static const struct zcl_hotswap_leaf_replacement k_wallet_security_leaves[] = {
    { "core.wallet.security.status", zcl_native_handle_wallet_security_status },
};
ZCL_HOTSWAP_EXPORT_LEAVES(
    k_wallet_security_leaves,
    sizeof(k_wallet_security_leaves) / sizeof(k_wallet_security_leaves[0]))
#endif /* ZCL_HOTSWAP_GEN */

#ifdef ZCL_HOTSWAP_MODULE_GEN
#include "hotswap/hotswap_module.h"
#include <stdio.h>
static const struct zcl_hotswap_leaf k_wallet_security_module_leaves[] = {
    { "core.wallet.security.status", zcl_native_handle_wallet_security_status },
};
static bool wallet_security_module_selftest(char *error, size_t error_cap)
{
    const size_t n = sizeof(k_wallet_security_module_leaves) /
                     sizeof(k_wallet_security_module_leaves[0]);
    for (size_t i = 0; i < n; i++) {
        if (!k_wallet_security_module_leaves[i].name ||
            !k_wallet_security_module_leaves[i].name[0] ||
            !k_wallet_security_module_leaves[i].fn) {
            if (error && error_cap)
                (void)snprintf(error, error_cap,
                               "wallet security leaf %zu has no name or no "
                               "body",
                               i);
            return false;
        }
    }
    return true;
}
ZCL_HOTSWAP_MODULE_LEAVES(k_wallet_security_module_leaves,
                          wallet_security_module_selftest)
#endif /* ZCL_HOTSWAP_MODULE_GEN */
