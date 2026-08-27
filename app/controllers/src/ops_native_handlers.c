/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Transport-neutral operator rollup-dashboard bodies.
 *
 * Native bodies for operator snapshot, summary, milestone, mirror, and
 * self-heal reads. Each returns heap-allocated JSON or fills a contextual
 * zcl_native_body_err after logging the failure. */

#include "controllers/ops_native_handlers.h"
#include "controllers/native_handler_body.h"
#include "controllers/status_native_helpers.h"

#include "json/json.h"
#include "controllers/rpc_client.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "validation/process_block.h"

#include <stdio.h>
#include <stdlib.h>

/* Forward the raw body of a no-argument, read-only RPC. The node RPC returns
 * the composition already, so the only failure this body distinguishes is a
 * null response; a returned RPC-level
 * error object is forwarded verbatim for the bridge to surface. */
static char *ops_rpc_passthrough_body(const char *method,
                                      struct zcl_native_body_err *err)
{
    char *raw = node_rpc_call(method, NULL);
    if (!raw) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        (void)snprintf(err->message, sizeof(err->message),
                       "RPC %s returned null", method);
        LOG_NULL("ops.native", "RPC %s returned null", method);
    }
    return raw;
}

char *zcl_native_operator_snapshot_body(const struct json_value *args,
                                        struct zcl_native_body_err *err)
{
    (void)args;
    return ops_rpc_passthrough_body("operatorsnapshot", err);
}

char *zcl_native_operator_summary_body(const struct json_value *args,
                                       struct zcl_native_body_err *err)
{
    (void)args;
    char *raw = node_rpc_call("operatorsnapshot", NULL);
    struct json_value root;
    if (!status_parse_rpc_json(&root, raw, JSON_OBJ)) {
        json_free(&root);
        free(raw);
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        (void)snprintf(err->message, sizeof(err->message),
                       "operatorsnapshot returned null or an error");
        LOG_NULL("ops.native",
                 "operatorsnapshot returned null or an error");
    }
    const struct json_value *summary = json_get(&root, "summary");
    if (!summary || summary->type != JSON_OBJ) {
        json_free(&root);
        free(raw);
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        (void)snprintf(err->message, sizeof(err->message),
                       "operatorsnapshot response has no summary object");
        LOG_NULL("ops.native",
                 "operatorsnapshot response has no summary object");
    }
    char *body = zcl_json_value_to_body((struct json_value *)summary,
                                        "native_operator_summary_body");
    json_free(&root);
    free(raw);
    if (!body) {
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        (void)snprintf(err->message, sizeof(err->message),
                       "malloc failed for %s", "operator summary response");
        LOG_NULL("ops.native", "malloc failed for %s",
                 "operator summary response");
    }
    return body;
}

char *zcl_native_milestone_body(const struct json_value *args,
                                struct zcl_native_body_err *err)
{
    (void)args;
    return ops_rpc_passthrough_body("milestone", err);
}

char *zcl_native_mirror_status_body(const struct json_value *args,
                                    struct zcl_native_body_err *err)
{
    (void)args;
    return ops_rpc_passthrough_body("getmirrorstatus", err);
}

char *zcl_native_self_heal_stats_body(const struct json_value *args,
                                      struct zcl_native_body_err *err)
{
    (void)args;
    struct self_heal_scan_stats stats;
    process_block_self_heal_stats_snapshot(&stats);

    char *out = zcl_malloc(512, "self_heal_stats_body");
    if (!out) {
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        (void)snprintf(err->message, sizeof(err->message),
                       "malloc failed for %s", "self-heal stats response");
        LOG_NULL("ops.native", "malloc failed for %s",
                 "self-heal stats response");
    }
    (void)snprintf(out, 512,
        "{"
        "\"tx_index_hits\":%llu,"
        "\"scan_hits\":%llu,"
        "\"scan_exhausted\":%llu,"
        "\"scan_blocks_checked_total\":%llu,"
        "\"scan_depth_limit\":%d"
        "}",
        (unsigned long long)stats.tx_index_hits,
        (unsigned long long)stats.scan_hits,
        (unsigned long long)stats.scan_exhausted,
        (unsigned long long)stats.scan_blocks_checked_total,
        process_block_self_heal_scan_depth_limit());
    return out;
}

/* ── Tier-1 hot-swap: native.leaves generation entrypoint ──────────────────
 * Dev-only (compiled only under -DZCL_HOTSWAP_GEN; expands to nothing in the
 * node/release TU). Stages every native command leaf this controller owns.
 *
 * All five bodies are no-argument read projections ((void)args) over operator
 * rollups the node already computes: four forward a read-only node RPC
 * verbatim, and self-heal reads a counter snapshot. None decides a consensus
 * rule, validates a block, or touches a state root — process_block's self-heal
 * stats are observability counters reached through a snapshot accessor.
 * ops.debug.dash.summary is the declared probe: it ignores args and its
 * declared output schema is zcl.operator_summary.v1. */
#ifdef ZCL_HOTSWAP_GEN
#define ZCL_HOTSWAP_PROBE_LEAF "ops.debug.dash.summary"
#include "hotswap/hotswap.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

ZCL_HOTSWAP_TRAMPOLINE(tramp_operator_snapshot, zcl_native_operator_snapshot_body)

ZCL_HOTSWAP_TRAMPOLINE(tramp_operator_summary, zcl_native_operator_summary_body)

ZCL_HOTSWAP_TRAMPOLINE(tramp_milestone, zcl_native_milestone_body)

ZCL_HOTSWAP_TRAMPOLINE(tramp_mirror_status, zcl_native_mirror_status_body)

ZCL_HOTSWAP_TRAMPOLINE(tramp_self_heal_stats, zcl_native_self_heal_stats_body)

static const struct zcl_hotswap_leaf_replacement k_leaves[] = { /* hotswap-static-ok: leaf registration tables are immutable */    { "ops.debug.dash.snapshot",  tramp_operator_snapshot },
    { "ops.debug.dash.summary",   tramp_operator_summary },
    { "ops.debug.dash.milestone", tramp_milestone },
    { "ops.debug.dash.mirror",    tramp_mirror_status },
    { "ops.debug.dash.selfheal",  tramp_self_heal_stats },
};

ZCL_HOTSWAP_EXPORT_LEAVES(k_leaves, sizeof(k_leaves) / sizeof(k_leaves[0]))
#endif /* ZCL_HOTSWAP_GEN */

/* REAL (activatable) multi-leaf module ABI export. All five leaves are
 * re-pointed in ONE all-or-nothing registry batch; every body is defined in
 * THIS TU, so each one is genuinely recompiled by the swap rather than merely
 * re-dispatched into resident code. */
#ifdef ZCL_HOTSWAP_MODULE_GEN
#include "hotswap/hotswap_module.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

ZCL_HOTSWAP_TRAMPOLINE(module_tramp_operator_snapshot, zcl_native_operator_snapshot_body)

ZCL_HOTSWAP_TRAMPOLINE(module_tramp_operator_summary, zcl_native_operator_summary_body)

ZCL_HOTSWAP_TRAMPOLINE(module_tramp_milestone, zcl_native_milestone_body)

ZCL_HOTSWAP_TRAMPOLINE(module_tramp_mirror_status, zcl_native_mirror_status_body)

ZCL_HOTSWAP_TRAMPOLINE(module_tramp_self_heal_stats, zcl_native_self_heal_stats_body)

/* The module's own health hook — runs before the loader publishes it. Kept
 * node-independent (no RPC): a structural OK. */
static bool module_selftest_ops_dash(char *err, size_t cap)
{
    (void)err;
    (void)cap;
    return true;
}

static const struct zcl_hotswap_leaf k_module_leaves[] = { /* hotswap-static-ok: immutable leaf registration tables */    { "ops.debug.dash.snapshot",  module_tramp_operator_snapshot },
    { "ops.debug.dash.summary",   module_tramp_operator_summary },
    { "ops.debug.dash.milestone", module_tramp_milestone },
    { "ops.debug.dash.mirror",    module_tramp_mirror_status },
    { "ops.debug.dash.selfheal",  module_tramp_self_heal_stats },
};

ZCL_HOTSWAP_MODULE_LEAVES(k_module_leaves, module_selftest_ops_dash)
#endif /* ZCL_HOTSWAP_MODULE_GEN */
