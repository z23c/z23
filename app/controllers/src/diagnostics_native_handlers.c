/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native argument parsing and RPC composition for diagnostic commands. See
 * controllers/native_handler_body.h for the failure contract. */

#include "controllers/diagnostics_native_handlers.h"

#include "json/json.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>

/* SELECT-only SQL passthrough to node.db. Marked destructive in middleware
 * not because it mutates (it can't) but because arbitrary scans against a
 * 100M-row table can be expensive. */
char *zcl_native_sql_body(const struct json_value *args,
                           struct zcl_native_body_err *err)
{
    const char *sql = json_get_str(json_get(args, "sql"));

    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, sql ? sql : "");
    rpc_arg_builder_push_int(&p, json_get_int_or(args, "limit", 10));
    char *pjson = rpc_arg_builder_to_json(&p);

    char *out = pjson ? node_rpc_call("dbquery", pjson) : NULL;
    free(pjson);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s returned null", "dbquery");
        LOG_NULL("native.diag", "RPC %s returned null", "dbquery");
    }
    return out;
}

/* Reverse-scan node.log via getnodelog RPC. Server-side regex match + level
 * filter. Timestamp filtering is exact for lines that carry a supported
 * timestamp; legacy undated lines remain eligible and are counted in the
 * result metadata. Bounded memory: chunks the live log and stops at
 * max_lines. */
char *zcl_native_node_log_body(const struct json_value *args,
                                struct zcl_native_body_err *err)
{
    const char *pattern = json_get_str(json_get(args, "pattern"));
    const char *level = json_get_str(json_get(args, "level"));

    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, pattern ? pattern : "");
    rpc_arg_builder_push_int(&p, json_get_int_or(args, "since_secs", 300));
    rpc_arg_builder_push_int(&p, json_get_int_or(args, "max_lines",   50));
    rpc_arg_builder_push_str(&p, level && level[0] ? level : "all");
    char *pjson = rpc_arg_builder_to_json(&p);

    char *out = pjson ? node_rpc_call("getnodelog", pjson) : NULL;
    free(pjson);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s returned null", "getnodelog");
        LOG_NULL("native.diag", "RPC %s returned null", "getnodelog");
    }
    return out;
}

/* Tier-1 hot-swap. The resident-owned ops.logs probe case supplies a fixed,
 * bounded pattern/window/row limit. Parsing, authentication and log I/O remain
 * in static RPC code; this replacement owns request composition only. */
#ifdef ZCL_HOTSWAP_GEN
#define ZCL_HOTSWAP_PROBE_LEAF "ops.logs"
#include "hotswap/hotswap.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

static void tramp_node_logs(const struct zcl_command_request *request,
                            struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_node_log_body, reply);
}

static const struct zcl_hotswap_leaf_replacement k_leaves[] = {
    { "ops.logs", tramp_node_logs },
};

ZCL_HOTSWAP_EXPORT_LEAVES(k_leaves, sizeof(k_leaves) / sizeof(k_leaves[0]))
#endif /* ZCL_HOTSWAP_GEN */

/* REAL (activatable) module ABI export. This TU has been a row in
 * config/hotswap_swappable.def since that manifest was written, but carried
 * only the generation-loader block above — so `make hotswap-module-so
 * FILE=.../diagnostics_native_handlers.c` produced a .so with no
 * `zcl_hotswap_module` symbol and the loader refused it at stage=symbol. The
 * allowlist row was a claim, not an admission; nothing in the tree ever
 * dlopen'd an artifact, so no gate could see it. tools/dev/hotswap-verify.sh
 * now does, and this block is what makes the row true. */
#ifdef ZCL_HOTSWAP_MODULE_GEN
#include "hotswap/hotswap_module.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

static void module_tramp_node_logs(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_node_log_body, reply);
}

/* The module's own health hook — runs before the loader publishes it. Kept
 * node-independent (no RPC): a structural OK. */
static bool module_selftest_node_logs(char *err, size_t cap)
{
    (void)err;
    (void)cap;
    return true;
}

/* core.storage.query composes a bounded dbquery RPC request exactly as ops.logs
 * composes getnodelog: the SQL text and row limit are forwarded as arguments
 * and the resident RPC handler keeps the database access and its
 * authorization. The swappable body owns request composition only. */
static void module_tramp_storage_query(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_sql_body, reply);
}

static const struct zcl_hotswap_leaf k_module_leaves[] = {
    { "ops.logs",           module_tramp_node_logs },
    { "core.storage.query", module_tramp_storage_query },
};

ZCL_HOTSWAP_MODULE_LEAVES(k_module_leaves, module_selftest_node_logs)
#endif /* ZCL_HOTSWAP_MODULE_GEN */
