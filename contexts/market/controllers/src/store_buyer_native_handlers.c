/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Registry handlers for the app.store.* buyer leaves.
 *
 * Each one proxies a storebuy_* RPC over the loopback client, because the
 * buying work has to happen inside the node: placing an order mints a
 * one-time Sapling payment address and paying spends, and a typed command
 * runs in a short-lived process with neither a wallet nor an open database.
 *
 * The one thing this file owns that the RPC layer does not is the typed
 * envelope. The storebuy_* methods answer a refusal as a SUCCESSFUL call
 * carrying {ok:false, code, message} — that is deliberate, so "the node said
 * no, and here is exactly why" survives the transport. This file turns that
 * `code` back into a reply status and exit code, so an agent branching on
 * PROVER_UNAVAILABLE versus PAYMENT_NOT_CONFIRMED versus HASH_MISMATCH never
 * has to read prose.
 *
 * Bound in engine/composition/commands/store.def. */

#include "controllers/native_handler_body.h" /* json_get_bool_or */
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "command/native_command.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/log_macros.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SBN_TAG "native.app.store"

/* How one refusal code lands in the typed envelope. INVALID means the caller
 * asked for something that does not exist; BLOCKED means the node is
 * unwilling or not ready and the same call may work later; FAILED means the
 * step was attempted and did not produce what it promises. */
struct sbn_code_map {
    const char *code;
    enum zcl_command_status status;
    enum zcl_command_exit exit_code;
};

static const struct sbn_code_map g_sbn_codes[] = { /* hotswap-static-ok: leaf registration tables are immutable */    { "INVALID_ARGS",          ZCL_COMMAND_STATUS_FAILED,  ZCL_COMMAND_EXIT_INVALID },
    { "UNKNOWN_PRODUCT",       ZCL_COMMAND_STATUS_FAILED,  ZCL_COMMAND_EXIT_INVALID },
    { "UNKNOWN_PURCHASE",      ZCL_COMMAND_STATUS_FAILED,  ZCL_COMMAND_EXIT_INVALID },
    { "MAINNET_REFUSED",       ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_DENIED },
    { "SPEND_REFUSED",         ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_DENIED },
    { "PROVER_UNAVAILABLE",    ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED },
    { "INSUFFICIENT_FUNDS",    ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED },
    { "PAYMENT_NOT_CONFIRMED", ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_TRANSIENT },
    { "ALREADY_PAID",          ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED },
    { "NODE_DB_UNAVAILABLE",   ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED },
    { "ORDER_CREATE_FAILED",   ZCL_COMMAND_STATUS_FAILED,  ZCL_COMMAND_EXIT_FAILED },
    { "DELIVERY_FAILED",       ZCL_COMMAND_STATUS_FAILED,  ZCL_COMMAND_EXIT_FAILED },
    { "HASH_MISMATCH",         ZCL_COMMAND_STATUS_FAILED,  ZCL_COMMAND_EXIT_FAILED },
    { "WRITE_FAILED",          ZCL_COMMAND_STATUS_FAILED,  ZCL_COMMAND_EXIT_FAILED },
    { "INTERNAL",              ZCL_COMMAND_STATUS_FAILED,  ZCL_COMMAND_EXIT_INTERNAL },
};

static void sbn_fail(struct zcl_command_reply *reply,
                     enum zcl_command_status status,
                     enum zcl_command_exit exit_code, const char *code,
                     const char *phase, const char *message,
                     const char *evidence)
{
    LOG_ERROR(SBN_TAG, "%s: %s (%s)", code, message,
              evidence && evidence[0] ? evidence : "-");
    zcl_command_reply_fail(reply, status, exit_code, code, phase, false, false,
                           message, evidence ? evidence : "");
}

/* Copy every top-level member of an RPC result object onto the reply data,
 * minus the envelope fields the typed reply expresses structurally. */
static void sbn_merge(struct json_value *dst, const struct json_value *src)
{
    if (!src || src->type != JSON_OBJ)
        return;
    for (size_t i = 0; i < src->num_children; i++) {
        const char *k = src->keys ? src->keys[i] : NULL;
        if (!k || !k[0] || strcmp(k, "ok") == 0 || strcmp(k, "code") == 0)
            continue;
        (void)json_push_kv(dst, k, &src->children[i]);
    }
}

/* Call one storebuy_* method and hand back the parsed body, or render the
 * failure and return false. `doc` is only valid (and only needs freeing)
 * when this returns true. */
static bool sbn_call(struct zcl_command_reply *reply, const char *method,
                     const char *params, struct json_value *doc)
{
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call(method, params);
    if (!raw) {
        sbn_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_TRANSIENT,
                 "NODE_UNAVAILABLE", "dispatch", "the node did not answer",
                 method);
        return false;
    }
    bool parsed = json_read(doc, raw, strlen(raw));
    free(raw);
    if (!parsed) {
        json_free(doc);
        sbn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "BAD_RPC_BODY", "serialize", "the node returned an "
                 "unparseable body", method);
        return false;
    }
    /* A bare string body is this RPC layer's shape for a handler refusal
     * (engine/modules/rpc/src/httpserver.c) — the storebuy_* methods only produce that
     * for a malformed call, so it is a caller error, not a node state. */
    if (doc->type == JSON_STR) {
        char msg[256];
        const char *why = json_get_str(doc);
        (void)snprintf(msg, sizeof(msg), "%s",
                       why && why[0] ? why : "the node rejected the call");
        json_free(doc);
        sbn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "BAD_REQUEST", "normalize", msg, method);
        return false;
    }
    if (doc->type != JSON_OBJ) {
        json_free(doc);
        sbn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "BAD_RPC_BODY", "serialize", "the node returned a "
                 "non-object body", method);
        return false;
    }
    const struct json_value *err = json_get(doc, "error");
    if (err && !json_is_null(err)) {
        char msg[256];
        const char *why = err->type == JSON_OBJ
                              ? json_get_str(json_get(err, "message"))
                              : json_get_str(err);
        (void)snprintf(msg, sizeof(msg), "%s",
                       why && why[0] ? why : "the node reported an error");
        json_free(doc);
        sbn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                 "STORE_RPC_ERROR", "execute", msg, method);
        return false;
    }

    /* The refusal envelope: a successful call that reports a refusal. */
    if (!json_get_bool_or(doc, "ok", false)) {
        const char *code = json_get_str(json_get(doc, "code"));
        const char *message = json_get_str(json_get(doc, "message"));
        const char *detail = json_get_str(json_get(doc, "detail"));
        char msg[320];
        (void)snprintf(msg, sizeof(msg), "%s%s%s",
                       message && message[0] ? message : "the store refused",
                       detail && detail[0] ? " — " : "",
                       detail && detail[0] ? detail : "");
        enum zcl_command_status status = ZCL_COMMAND_STATUS_FAILED;
        enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_FAILED;
        for (size_t i = 0; i < sizeof(g_sbn_codes) / sizeof(g_sbn_codes[0]);
             i++) {
            if (code && strcmp(code, g_sbn_codes[i].code) == 0) {
                status = g_sbn_codes[i].status;
                exit_code = g_sbn_codes[i].exit_code;
                break;
            }
        }
        char code_buf[64];
        (void)snprintf(code_buf, sizeof(code_buf), "%s",
                       code && code[0] ? code : "STORE_REFUSED");
        json_free(doc);
        sbn_fail(reply, status, exit_code, code_buf, "execute", msg, method);
        return false;
    }
    return true;
}

/* ── app.store.catalog ──────────────────────────────────────────────── */

void zcl_native_handle_store_catalog(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    struct json_value doc;
    json_init(&doc);
    if (!sbn_call(reply, "storebuy_catalog", NULL, &doc))
        return;
    sbn_merge(&reply->data, &doc);
    json_free(&doc);
}

/* ── app.store.order ────────────────────────────────────────────────── */

void zcl_native_handle_store_order(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *in = request->input;
    int64_t product_id = json_get_int_or(in, "product_id", 0);
    const char *addr = json_get_str(json_get(in, "customer_address"));
    const char *out_path = json_get_str(json_get(in, "output_path"));
    const char *pay_kind = json_get_str(json_get(in, "payment_kind"));

    if (product_id <= 0) {
        sbn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "INVALID_PRODUCT_ID", "normalize",
                 "product_id must be a positive integer", "product_id");
        return;
    }
    if (!addr || !addr[0]) {
        sbn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_CUSTOMER_ADDRESS", "normalize",
                 "customer_address is required — it is where the merchant "
                 "mints the access token that unlocks the file",
                 "customer_address");
        return;
    }

    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_int(&p, product_id);
    rpc_arg_builder_push_str(&p, addr);
    /* Positional RPC: payment_kind sits in slot 4, so an absent output_path
     * still has to occupy slot 3 when a kind was given. */
    if ((out_path && out_path[0]) || (pay_kind && pay_kind[0]))
        rpc_arg_builder_push_str(&p, out_path ? out_path : "");
    if (pay_kind && pay_kind[0])
        rpc_arg_builder_push_str(&p, pay_kind);
    char *params = rpc_arg_builder_to_json(&p);
    if (!params) {
        sbn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "ARG_BUILD_FAILED", "normalize",
                 "could not encode the storebuy_order parameters",
                 "app.store.order");
        return;
    }
    struct json_value doc;
    json_init(&doc);
    bool ok = sbn_call(reply, "storebuy_order", params, &doc);
    free(params);
    if (!ok)
        return;
    sbn_merge(&reply->data, &doc);
    json_free(&doc);
    reply->error.mutated = true;
}

/* ── app.store.pay ──────────────────────────────────────────────────── */

/* Deterministic, non-secret plan token binding a plan preview to the exact
 * purchase and funding address it previewed (FNV-1a, 16 hex). */
static void sbn_plan_token(char out[17], int64_t purchase_id, const char *from)
{
    uint64_t h = 1469598103934665603ULL;
    char seed[192];
    (void)snprintf(seed, sizeof(seed), "app.store.pay|%lld|%s",
                   (long long)purchase_id, from ? from : "");
    for (const char *p = seed; *p; p++) {
        h ^= (unsigned char)*p;
        h *= 1099511628211ULL;
    }
    (void)snprintf(out, 17, "%016llx", (unsigned long long)h);
}

void zcl_native_handle_store_pay(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *in = request->input;
    int64_t purchase_id = json_get_int_or(in, "purchase_id", 0);
    const char *from = json_get_str(json_get(in, "from_address"));

    if (purchase_id <= 0) {
        sbn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "INVALID_PURCHASE_ID", "normalize",
                 "purchase_id must be a positive integer", "purchase_id");
        return;
    }
    if (!from || !from[0]) {
        sbn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_FROM_ADDRESS", "normalize",
                 "from_address is required — it is the wallet address the "
                 "payment is funded from", "from_address");
        return;
    }

    char token[17];
    sbn_plan_token(token, purchase_id, from);

    if (!json_get_bool_or(in, "confirm", false)) {
        char commit[320];
        (void)snprintf(commit, sizeof(commit),
                       "{\"purchase_id\":%lld,\"from_address\":\"%s\","
                       "\"confirm\":true}", (long long)purchase_id, from);
        (void)json_push_kv_int(&reply->data, "purchase_id", purchase_id);
        (void)json_push_kv_str(&reply->data, "from_address", from);
        (void)json_push_kv_str(&reply->data, "stage", "plan");
        (void)json_push_kv_str(&reply->data, "action", "store-pay");
        (void)json_push_kv_bool(&reply->data, "committed", false);
        (void)json_push_kv_bool(&reply->data, "spends_funds", true);
        (void)json_push_kv_str(&reply->data, "plan_token", token);
        (void)json_push_kv_str(
            &reply->data, "confirm_hint",
            "re-run this same command with the commit_input below to pay");
        (void)json_push_kv_str(&reply->data, "commit_input", commit);
        reply->error.mutated = false;
        return;
    }

    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_int(&p, purchase_id);
    rpc_arg_builder_push_str(&p, from);
    char *params = rpc_arg_builder_to_json(&p);
    if (!params) {
        sbn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "ARG_BUILD_FAILED", "normalize",
                 "could not encode the storebuy_pay parameters",
                 "app.store.pay");
        return;
    }
    struct json_value doc;
    json_init(&doc);
    bool ok = sbn_call(reply, "storebuy_pay", params, &doc);
    free(params);
    if (!ok)
        return;
    sbn_merge(&reply->data, &doc);
    json_free(&doc);
    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    (void)json_push_kv_str(&reply->data, "plan_token", token);
    reply->error.mutated = true;
}

/* ── app.store.purchases ────────────────────────────────────────────── */

void zcl_native_handle_store_purchases(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    int64_t purchase_id = json_get_int_or(request->input, "purchase_id", 0);
    char *params = NULL;

    if (purchase_id > 0) {
        struct rpc_arg_builder p;
        rpc_arg_builder_init(&p);
        rpc_arg_builder_push_int(&p, purchase_id);
        params = rpc_arg_builder_to_json(&p);
        if (!params) {
            sbn_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                     "normalize", "could not encode the storebuy_status "
                     "parameters", "app.store.purchases");
            return;
        }
    }
    struct json_value doc;
    json_init(&doc);
    bool ok = sbn_call(reply, "storebuy_status", params, &doc);
    free(params);
    if (!ok)
        return;
    sbn_merge(&reply->data, &doc);
    json_free(&doc);
}

/* ── app.store.collect ──────────────────────────────────────────────── */

void zcl_native_handle_store_collect(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *in = request->input;
    int64_t purchase_id = json_get_int_or(in, "purchase_id", 0);
    const char *out_path = json_get_str(json_get(in, "output_path"));

    if (purchase_id <= 0) {
        sbn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "INVALID_PURCHASE_ID", "normalize",
                 "purchase_id must be a positive integer", "purchase_id");
        return;
    }

    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_int(&p, purchase_id);
    if (out_path && out_path[0])
        rpc_arg_builder_push_str(&p, out_path);
    char *params = rpc_arg_builder_to_json(&p);
    if (!params) {
        sbn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "ARG_BUILD_FAILED", "normalize",
                 "could not encode the storebuy_collect parameters",
                 "app.store.collect");
        return;
    }
    struct json_value doc;
    json_init(&doc);
    bool ok = sbn_call(reply, "storebuy_collect", params, &doc);
    free(params);
    if (!ok)
        return;
    sbn_merge(&reply->data, &doc);
    json_free(&doc);
    reply->error.mutated = true;
}

/* ── Hot-swappable leaves ──────────────────────────────────────────────────
 * Read-only STORE BUYER projections: the catalog and this buyer's ledger. Every mutating sibling in this file is
 * absent from the table; the loader refuses to re-point a leaf that is
 * missing from this file's row in config/hotswap_swappable.def. */
#if defined(ZCL_HOTSWAP_GEN) || defined(ZCL_HOTSWAP_MODULE_GEN)
#define ZCL_HOTSWAP_PROBE_LEAF "app.store.catalog"
#include "hotswap/hotswap_register.h"
ZCL_HOTSWAP_LEAVES_BEGIN(store_buyer)
ZCL_HOTSWAP_LEAF("app.store.catalog", zcl_native_handle_store_catalog)
ZCL_HOTSWAP_LEAF("app.store.purchases", zcl_native_handle_store_purchases)
ZCL_HOTSWAP_LEAVES_END(store_buyer)
#endif
