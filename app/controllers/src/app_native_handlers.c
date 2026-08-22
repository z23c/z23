/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native bodies for read-only ZCL application commands. See
 * controllers/native_handler_body.h for their shared contract.
 *
 * Scope: the READ surface only (names resolve/list, tokens list, message
 * inbox, market list/status, swap chains/list). The destructive app-layer
 * commands stay PLANNED native leaves (fail-closed) in
 * config/commands/app_features.def until the app-write plan/commit handshake
 * lands — the wallet-send precedent (config/commands/core.def). */

#include "controllers/app_native_handlers.h"

#include "json/json.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* One shared tail for the parameter-free 1:1 RPC proxies: call the backing
 * method with no params and surface a NULL RPC result as a body failure. */
static char *app_native_rpc_noargs(const char *method,
                                   struct zcl_native_body_err *err)
{
    char *out = node_rpc_call(method, NULL);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s returned null", method);
        LOG_NULL("native.app", "RPC %s returned null", method);
    }
    return out;
}

/* ── ZSLP tokens ────────────────────────────────────────────── */

char *zcl_native_zslp_listtokens_body(const struct json_value *args,
                                      struct zcl_native_body_err *err)
{
    (void)args;
    char *raw = app_native_rpc_noargs("zslp_listtokens", err);
    if (!raw)
        return NULL;
    /* The RPC answers a bare array, but the native body contract requires
     * an object — wrap it as {"tokens":[...]} (the storebuy_catalog
     * "products" convention). The RPC/REST shape is unchanged. A non-array
     * body (the legacy string error convention) passes through untouched so
     * the bridge surfaces the handler's own message. */
    struct json_value doc;
    if (!json_read(&doc, raw, strlen(raw)) || doc.type != JSON_ARR) {
        json_free(&doc);
        return raw;
    }
    free(raw);
    struct json_value wrapped;
    json_init(&wrapped);
    json_set_object(&wrapped);
    (void)json_push_kv(&wrapped, "tokens", &doc);
    json_free(&doc);
    size_t need = json_write(&wrapped, NULL, 0);
    char *out = zcl_malloc(need + 1, "native.tokens_list");
    if (out)
        (void)json_write(&wrapped, out, need + 1);
    json_free(&wrapped);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "could not serialize the wrapped token index");
        LOG_NULL("native.app", "tokens.list wrap alloc failed (%zu bytes)",
                 need + 1);
    }
    return out;
}

/* ── Names (ZNAM) ───────────────────────────────────────────── */

char *zcl_native_name_resolve_body(const struct json_value *args,
                                   struct zcl_native_body_err *err)
{
    const char *n = json_get_str(json_get(args, "name"));
    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, n);
    char *params = rpc_arg_builder_to_json(&p);
    char *out = params ? node_rpc_call("name_resolve", params) : NULL;
    free(params);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s failed: name=%s", "name_resolve", n ? n : "(null)");
        LOG_NULL("native.app", "RPC %s failed: name=%s", "name_resolve",
                 n ? n : "(null)");
    }
    return out;
}

char *zcl_native_name_list_body(const struct json_value *args,
                                struct zcl_native_body_err *err)
{
    (void)args;
    return app_native_rpc_noargs("name_list", err);
}

/* ── Messaging (ZMSG) ───────────────────────────────────────── */

/* Native inbox is the full inbox, newest first. The native command's optional
 * `unread_only` boolean filter is intentionally not carried onto the native
 * leaf: the registry input validator only admits a fixed set of boolean keys
 * (verbose/confirm/relink_generation), so an `unread_only` bool would be
 * rejected before dispatch. The full inbox is the honest bounded read. */
char *zcl_native_msg_inbox_body(const struct json_value *args,
                                struct zcl_native_body_err *err)
{
    (void)args;
    char *raw = app_native_rpc_noargs("msg_inbox", err);
    if (!raw)
        return NULL;
    /* msg_inbox is an RPC/REST array, while native handler bodies are
     * objects. Preserve the message rows and make the native index shape
     * explicit instead of letting the bridge reject every valid inbox. */
    struct json_value doc;
    json_init(&doc);
    if (!json_read(&doc, raw, strlen(raw)) || doc.type != JSON_ARR) {
        json_free(&doc);
        return raw;
    }
    free(raw);
    struct json_value wrapped;
    json_init(&wrapped);
    json_set_object(&wrapped);
    (void)json_push_kv(&wrapped, "messages", &doc);
    json_free(&doc);
    size_t need = json_write(&wrapped, NULL, 0);
    char *out = zcl_malloc(need + 1, "native.messaging_inbox");
    if (out)
        (void)json_write(&wrapped, out, need + 1);
    json_free(&wrapped);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "could not serialize the wrapped message inbox");
        LOG_NULL("native.app", "messaging.inbox wrap alloc failed (%zu bytes)",
                 need + 1);
    }
    return out;
}

/* ── File market ────────────────────────────────────────────── */

char *zcl_native_zmarket_list_body(const struct json_value *args,
                                   struct zcl_native_body_err *err)
{
    /* Optional per-request view override {"profile":"open"} (the def row
     * admits the profile key): forwarded as the RPC's first positional
     * argument. The RPC answers the filtered listing object {offers,
     * offer_count, hidden_count, profile} — already an object, so the
     * native body contract needs no wrapper. A non-object body (the legacy
     * string error convention) passes through untouched so the bridge
     * surfaces the handler's own message. */
    const char *profile = NULL;
    if (args) {
        const struct json_value *p = json_get(args, "profile");
        if (p && p->type == JSON_STR)
            profile = json_get_str(p);
    }
    if (!profile || !profile[0])
        return app_native_rpc_noargs("zmarket_list", err);
    struct rpc_arg_builder params;
    rpc_arg_builder_init(&params);
    rpc_arg_builder_push_str(&params, profile);
    char *params_json = rpc_arg_builder_to_json(&params);
    char *out = params_json ? node_rpc_call("zmarket_list", params_json)
                            : NULL;
    free(params_json);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s returned null", "zmarket_list");
        LOG_NULL("native.app", "RPC zmarket_list returned null");
    }
    return out;
}

char *zcl_native_zmarket_status_body(const struct json_value *args,
                                     struct zcl_native_body_err *err)
{
    (void)args;
    return app_native_rpc_noargs("zmarket_status", err);
}

char *zcl_native_zmarket_content_list_body(
    const struct json_value *args, struct zcl_native_body_err *err)
{
    (void)args;
    return app_native_rpc_noargs("zmarket_content_list", err);
}

/* ── Atomic swaps (ZSWP) ────────────────────────────────────── */

char *zcl_native_swap_chains_body(const struct json_value *args,
                                  struct zcl_native_body_err *err)
{
    (void)args;
    return app_native_rpc_noargs("swap_chains", err);
}

char *zcl_native_swap_list_body(const struct json_value *args,
                                struct zcl_native_body_err *err)
{
    const struct json_value *st = json_get(args, "state");
    char *out;
    if (st) {
        struct rpc_arg_builder p;
        rpc_arg_builder_init(&p);
        rpc_arg_builder_push_str(&p, json_get_str(st));
        char *params = rpc_arg_builder_to_json(&p);
        out = params ? node_rpc_call("swap_list", params) : NULL;
        free(params);
    } else {
        out = node_rpc_call("swap_list", NULL);
    }
    if (!out) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s returned null", "swap_list");
        LOG_NULL("native.app", "RPC %s returned null", "swap_list");
    }
    return out;
}

/* ── Tier-1 hot-swap: native.leaves generation entrypoint ──────
 * Dev-only (compiled only under -DZCL_HOTSWAP_GEN, a generation .so build;
 * expands to nothing in the node/release TU — see ZCL_HOTSWAP_EXPORT_LEAVES
 * in lib/hotswap/include/hotswap/hotswap.h). Stages every native command leaf
 * this controller owns; the resident bridge re-points them at THIS TU's
 * freshly-compiled bodies via zcl_native_bridge_run(). Probe is
 * app.names.list: zcl_native_name_list_body ignores `args` ((void)args) and
 * unconditionally calls name_list with no params, forwarding the node's body
 * verbatim (no top-level "error" key is synthesized on success), so the
 * empty-args self-test dispatch the generation loader runs succeeds. The other
 * seven leaves are equally args-free (or take one optional/required string) and
 * would work as probes too; app.names.list is kept as the pilot probe to match
 * the read-only name-list leaf.
 * See config/hotswap_eligible.def. */
#ifdef ZCL_HOTSWAP_GEN
#define ZCL_HOTSWAP_PROBE_LEAF "app.names.list"
#include "hotswap/hotswap.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

static void tramp_name_list(const struct zcl_command_request *request,
                            struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_name_list_body, reply);
}

static void tramp_name_resolve(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_name_resolve_body, reply);
}

static void tramp_tokens(const struct zcl_command_request *request,
                         struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_zslp_listtokens_body, reply);
}

static void tramp_msg_inbox(const struct zcl_command_request *request,
                            struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_msg_inbox_body, reply);
}

static void tramp_market_list(const struct zcl_command_request *request,
                              struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_zmarket_list_body, reply);
}

static void tramp_market_status(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_zmarket_status_body, reply);
}

static void tramp_market_content_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_zmarket_content_list_body,
                          reply);
}

static void tramp_swap_chains(const struct zcl_command_request *request,
                              struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_swap_chains_body, reply);
}

static void tramp_swap_list(const struct zcl_command_request *request,
                            struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_swap_list_body, reply);
}

static const struct zcl_hotswap_leaf_replacement k_leaves[] = {
    { "app.names.list",      tramp_name_list },
    { "app.names.resolve",   tramp_name_resolve },
    { "app.tokens.list",     tramp_tokens },
    { "app.messaging.inbox", tramp_msg_inbox },
    { "app.market.list",     tramp_market_list },
    { "app.market.status",   tramp_market_status },
    { "app.market.content.list", tramp_market_content_list },
    { "app.swap.chains",     tramp_swap_chains },
    { "app.swap.list",       tramp_swap_list },
};

ZCL_HOTSWAP_EXPORT_LEAVES(k_leaves, sizeof(k_leaves) / sizeof(k_leaves[0]))
#endif /* ZCL_HOTSWAP_GEN */

/* REAL (activatable) single-handler module ABI export. Compiled only under a
 * `make hotswap-module-so HANDLER=app.names.list` build
 * (-DZCL_HOTSWAP_MODULE_GEN); expands to nothing in the node/release TU. The
 * module re-points ONLY the `app.names.list` leaf to this TU's
 * freshly-compiled body via the same zcl_native_bridge_run() seam the leaf
 * provider uses. See hotswap_module.h and hotswap_activate() (lib/hotswap). */
#ifdef ZCL_HOTSWAP_MODULE_GEN
#include "hotswap/hotswap_module.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

static void module_tramp_name_list(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_name_list_body, reply);
}

/* The module's own health hook — runs before the loader publishes it. Kept
 * node-independent (no RPC): a structural OK. */
static bool module_selftest_name_list(char *err, size_t cap)
{
    (void)err;
    (void)cap;
    return true;
}

ZCL_HOTSWAP_MODULE("app.names.list", module_tramp_name_list,
                   module_selftest_name_list)
#endif /* ZCL_HOTSWAP_MODULE_GEN */
