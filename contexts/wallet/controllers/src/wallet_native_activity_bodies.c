/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native bodies for core.wallet.summary and core.wallet.history. Each asks
 * the running node (walletsummary, wallethistory), which owns the wallet and
 * viewing keys, and forwards the typed reply unchanged. */

#include "controllers/wallet_native_handlers.h"

#include "json/json.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *wnh_activity_call(const char *method, const char *params,
                               struct zcl_native_body_err *err)
{
    char *out = node_rpc_call(method, params);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message), "RPC %s failed", method);
        LOG_NULL("native.wallet", "RPC %s failed", method);
    }
    return out;
}

char *zcl_native_wallet_summary_body(const struct json_value *args,
                                     struct zcl_native_body_err *err)
{
    (void)args;
    return wnh_activity_call("walletsummary", "[]", err);
}

char *zcl_native_wallet_history_body(const struct json_value *args,
                                     struct zcl_native_body_err *err)
{
    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_int(&p, json_get_int_or(args, "limit", 10));
    rpc_arg_builder_push_str(&p, json_get_str_or(args, "cursor", ""));
    rpc_arg_builder_push_str(&p, json_get_str_or(args, "txid", ""));
    char *params = rpc_arg_builder_to_json(&p);
    char *out = params ? wnh_activity_call("wallethistory", params, err) : NULL;
    free(params);
    return out;
}

char *zcl_native_wallet_latest_body(const struct json_value *args,
                                    struct zcl_native_body_err *err)
{
    (void)args;
    return wnh_activity_call("walletlatestaddress", "[]", err);
}
