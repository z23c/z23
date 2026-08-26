/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Typed, path-free buyer payment commands for the P2P file market. */

#include "controllers/native_handler_body.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "base/hex.h"
#include "command/native_command.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "hotswap/hotswap_service.h"
#include "services/market_purchase_view_service.h"
#include "util/log_macros.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MPN_TAG "native.market.purchase"

/* Retrieve runs the whole buyer download inside one RPC: one blocking
 * embedded-Tor fetch per 60 KiB slice on the onion path (~10 s cold per
 * fetch, each bounded at 60 s), so the generic 10 s loopback deadline
 * would give up mid-download. Must stay aligned with the server-side
 * slot budget for zmarket_purchase_retrieve
 * (RPC_MARKET_DELIVERY_TIMEOUT_MS) — if the server is tighter, its
 * watchdog kills the socket first and the reply below never arrives. */
#define MPN_RETRIEVE_DEADLINE_MS 300000L

static void mpn_fail(struct zcl_command_reply *reply,
                     enum zcl_command_status status,
                     enum zcl_command_exit exit_code, const char *code,
                     const char *phase, const char *message,
                     const char *evidence, bool mutated)
{
    LOG_ERROR(MPN_TAG, "%s: %s", code, message);
    zcl_command_reply_fail(reply, status, exit_code, code, phase, mutated,
                           false, message, evidence ? evidence : "");
}

static void mpn_merge(struct json_value *dst, const struct json_value *src)
{
    if (!dst || !src || src->type != JSON_OBJ) return;
    for (size_t i = 0; i < src->num_children; i++) {
        const char *key = src->keys ? src->keys[i] : NULL;
        if (!key || !key[0] || strcmp(key, "ok") == 0 ||
            strcmp(key, "code") == 0 || strcmp(key, "message") == 0)
            continue;
        (void)json_push_kv(dst, key, &src->children[i]);
    }
}

static void mpn_error_class_to_command(
    enum market_purchase_error_class_v1 error_class,
    enum zcl_command_status *status, enum zcl_command_exit *exit_code)
{
    *status = ZCL_COMMAND_STATUS_FAILED;
    *exit_code = ZCL_COMMAND_EXIT_FAILED;
    switch (error_class) {
    case MARKET_PURCHASE_ERROR_INVALID:
        *exit_code = ZCL_COMMAND_EXIT_INVALID;
        break;
    case MARKET_PURCHASE_ERROR_DENIED:
        *status = ZCL_COMMAND_STATUS_BLOCKED;
        *exit_code = ZCL_COMMAND_EXIT_DENIED;
        break;
    case MARKET_PURCHASE_ERROR_TRANSIENT:
        *status = ZCL_COMMAND_STATUS_BLOCKED;
        *exit_code = ZCL_COMMAND_EXIT_TRANSIENT;
        break;
    case MARKET_PURCHASE_ERROR_BLOCKED:
        *status = ZCL_COMMAND_STATUS_BLOCKED;
        *exit_code = ZCL_COMMAND_EXIT_BLOCKED;
        break;
    case MARKET_PURCHASE_ERROR_FAILED:
    default:
        break;
    }
}

static bool mpn_call(struct zcl_command_reply *reply, const char *method,
                     const struct json_value *input, struct json_value *body,
                     long total_ms)
{
    struct rpc_arg_builder args;
    rpc_arg_builder_init(&args);
    rpc_arg_builder_push_value(&args, input);
    char *params = rpc_arg_builder_to_json(&args);
    if (!params) {
        mpn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "ARG_BUILD_FAILED", "normalize",
                 "could not encode the purchase request", method, false);
        return false;
    }
    zcl_native_bridge_ensure_rpc();
    /* total_ms > 0 overrides the generic 10 s loopback deadline for methods
     * whose server-side work legitimately exceeds it (see the retrieve
     * handler below); the server slot budget must be at least as generous
     * or the watchdog kills the socket first. */
    char *raw = total_ms > 0
        ? node_rpc_call_deadline(method, params, 2000, total_ms)
        : node_rpc_call(method, params);
    free(params);
    if (!raw) {
        mpn_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                 ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE", "dispatch",
                 "the node did not answer the purchase request", method,
                 false);
        return false;
    }
    bool parsed = json_read(body, raw, strlen(raw));
    if (!parsed || body->type != JSON_OBJ) {
        /* Name what the daemon actually sent (bounded): a watchdog-killed
         * or otherwise truncated reply is diagnosable from this line
         * alone, without a packet capture. */
        LOG_ERROR(MPN_TAG, "%s: unparseable node reply body: %.200s",
                  method, raw);
        free(raw);
        json_free(body);
        mpn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "BAD_RPC_BODY", "serialize",
                 "the node returned an invalid purchase document", method,
                 false);
        return false;
    }
    free(raw);
    /* A transport-level ({"error":{code,message}} from the loopback client)
     * or JSON-RPC-level ({code:int,message} from the server) failure is an
     * error envelope, not a purchase document — neither carries the
     * purchase "code" string, so without this branch they fall through to
     * the misleading PURCHASE_REFUSED default. Purchase refusals render
     * "code" as a STRING; the JSON-RPC error object renders it as an int,
     * which is what distinguishes the two shapes. */
    const struct json_value *envelope = json_get(body, "error");
    const char *env_message = envelope
        ? json_get_str(json_get(envelope, "message")) : NULL;
    const struct json_value *rpc_code = json_get(body, "code");
    if (!env_message && rpc_code && rpc_code->type == JSON_INT)
        env_message = json_get_str(json_get(body, "message"));
    if (env_message) {
        char message_copy[320];
        (void)snprintf(message_copy, sizeof(message_copy), "%s", env_message);
        json_free(body);
        mpn_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                 ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE", "dispatch",
                 message_copy, method, false);
        return false;
    }
    if (json_get_bool_or(body, "ok", false)) return true;

    const char *code = json_get_str(json_get(body, "code"));
    const char *message = json_get_str(json_get(body, "message"));
    struct zcl_hotswap_service_lease lease = {0};
    const struct market_purchase_view_service_v1 *service =
        zcl_hotswap_service_acquire(MARKET_PURCHASE_VIEW_SERVICE_ID, &lease);
    if (!service) service = market_purchase_view_service_builtin();
    struct market_purchase_error_result_v1 classified = {0};
    enum zcl_command_status status = ZCL_COMMAND_STATUS_FAILED;
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_FAILED;
    if (service->classify_error(code, &classified))
        mpn_error_class_to_command(classified.error_class, &status, &exit_code);
    zcl_hotswap_service_release(&lease);
    char code_copy[64], message_copy[320];
    (void)snprintf(code_copy, sizeof(code_copy), "%s",
                   code && code[0] ? code : "PURCHASE_REFUSED");
    (void)snprintf(message_copy, sizeof(message_copy), "%s",
                   message && message[0] ? message
                                         : "the purchase operation was refused");
    json_free(body);
    mpn_fail(reply, status, exit_code, code_copy, "execute", message_copy,
             method, false);
    return false;
}

static bool market_purchase_view_frozen_kat(const void *opaque, char *why,
                                            size_t why_sz)
{
    const struct market_purchase_view_service_v1 *service = opaque;
    struct market_purchase_error_result_v1 classified;
    struct market_purchase_guide_result_v1 guide;
    char commit[192];
    const char *plan =
        "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
    static const struct {
        const char *code;
        enum market_purchase_error_class_v1 error_class;
    } vectors[] = {
        {"MONEY_STATE_NOT_CURRENT", MARKET_PURCHASE_ERROR_TRANSIENT},
        {"IDEMPOTENCY_CONFLICT", MARKET_PURCHASE_ERROR_INVALID},
        {"CUSTODY_ALLOCATION_EXCEEDED", MARKET_PURCHASE_ERROR_DENIED},
        {"COMMIT_UNCERTAIN", MARKET_PURCHASE_ERROR_BLOCKED},
        {"MONEY_SNAPSHOT_CHANGED", MARKET_PURCHASE_ERROR_TRANSIENT},
        {"OFFER_CONTRACT_CHANGED", MARKET_PURCHASE_ERROR_BLOCKED},
        {"COMMIT_BUSY", MARKET_PURCHASE_ERROR_TRANSIENT},
        {"COMMIT_STATE_UNCERTAIN", MARKET_PURCHASE_ERROR_BLOCKED},
        {"DESTINATION_INVALID", MARKET_PURCHASE_ERROR_INVALID},
        {"DOWNLOAD_BINDING_CONFLICT", MARKET_PURCHASE_ERROR_BLOCKED},
        {"DESTINATION_CONFLICT", MARKET_PURCHASE_ERROR_BLOCKED},
        {"MANIFEST_VERIFICATION_FAILED", MARKET_PURCHASE_ERROR_FAILED},
        {"STAGING_VERIFICATION_FAILED", MARKET_PURCHASE_ERROR_FAILED},
        {"DELIVERY_NOT_READY", MARKET_PURCHASE_ERROR_TRANSIENT},
        {"ONION_DELIVERY_UNAVAILABLE", MARKET_PURCHASE_ERROR_DENIED},
    };
    if (!service || !service->classify_error ||
        !service->render_commit_input || !service->render_guide) {
        if (why && why_sz) (void)snprintf(why, why_sz,
            "frozen marketplace service shape vector failed");
        return false;
    }
    for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        if (!service->classify_error(vectors[i].code, &classified) ||
            !classified.known || classified.error_class != vectors[i].error_class) {
            if (why && why_sz) (void)snprintf(why, why_sz,
                "frozen marketplace error vector %zu failed", i);
            return false;
        }
    }
    if (!service->classify_error("UNKNOWN", &classified) || classified.known ||
        classified.error_class != MARKET_PURCHASE_ERROR_FAILED ||
        !service->render_commit_input("dev", plan, commit, sizeof(commit)) ||
        strcmp(commit,
            "{\"wallet_scope\":\"dev\",\"plan_id\":\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\",\"confirm\":true}") != 0 ||
        service->render_commit_input("other", plan, commit, sizeof(commit)) ||
        !service->render_guide(&guide) || guide.classified_error_count != 15 ||
        guide.effects_swappable || !guide.payment_authority_static ||
        strcmp(guide.flow, "plan->commit->status->retrieve") != 0) {
        if (why && why_sz) (void)snprintf(why, why_sz,
            "frozen marketplace error/commit/guide vector failed");
        return false;
    }
    return true;
}

static const struct zcl_hotswap_service_contract k_market_view_contract = {
    .service_id = MARKET_PURCHASE_VIEW_SERVICE_ID,
    .source_tu = "app/services/src/market_purchase_view_service.c",
    .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
    .vtable_size = sizeof(struct market_purchase_view_service_v1),
    .abi_fingerprint = MARKET_PURCHASE_VIEW_ABI_FINGERPRINT,
    .schema_fingerprint = MARKET_PURCHASE_VIEW_SCHEMA_FINGERPRINT,
    .wire_fingerprint = MARKET_PURCHASE_VIEW_WIRE_FINGERPRINT,
    .kat_fingerprint = MARKET_PURCHASE_VIEW_KAT_FINGERPRINT,
    .frozen_kat = market_purchase_view_frozen_kat,
};

const struct zcl_hotswap_service_contract *
zcl_native_market_purchase_view_service_contract(void)
{
    return &k_market_view_contract;
}

void zcl_native_handle_market_purchase_guide(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !request->input || !reply ||
        request->input->type != JSON_OBJ || request->input->num_children != 0) {
        if (reply) mpn_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_INVALID, "BAD_MARKET_PURCHASE_GUIDE_INPUT",
            "validate", "app market purchase guide accepts no input keys",
            "app.market.purchase.guide", false);
        return;
    }
    struct zcl_hotswap_service_lease lease = {0};
    const struct market_purchase_view_service_v1 *service =
        zcl_hotswap_service_acquire(MARKET_PURCHASE_VIEW_SERVICE_ID, &lease);
    if (!service) service = market_purchase_view_service_builtin();
    struct market_purchase_guide_result_v1 guide;
    if (!service->render_guide(&guide)) {
        zcl_hotswap_service_release(&lease);
        mpn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "MARKET_PURCHASE_VIEW_FAILED", "render",
            "the pure marketplace view service refused workflow rendering",
            "app.market.purchase.guide", false);
        return;
    }
    (void)json_push_kv_str(&reply->data, "service_id",
                           MARKET_PURCHASE_VIEW_SERVICE_ID);
    (void)json_push_kv_int(&reply->data, "service_generation",
                           zcl_hotswap_service_generation());
    (void)json_push_kv_str(&reply->data, "flow", guide.flow);
    (void)json_push_kv_int(&reply->data, "classified_error_count",
                           guide.classified_error_count);
    (void)json_push_kv_bool(&reply->data, "effects_swappable",
                            guide.effects_swappable);
    (void)json_push_kv_bool(&reply->data, "payment_authority_static",
                            guide.payment_authority_static);
    (void)json_push_kv_str(&reply->data, "live_surface", guide.live_surface);
    (void)json_push_kv_str(&reply->data, "static_boundary",
                           guide.static_boundary);
    (void)json_push_kv_str(&reply->data, "next_command", guide.next_command);
    zcl_hotswap_service_release(&lease);
}

void zcl_native_handle_market_purchase_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !request->input || !reply) return;
    const char *scope = json_get_str(json_get(request->input, "wallet_scope"));
    const char *offer = json_get_str(json_get(request->input, "offer_id"));
    const char *source = json_get_str(json_get(request->input,
                                                "source_address"));
    const char *key = json_get_str(json_get(request->input,
                                             "idempotency_key"));
    if (!scope || !offer || !source || !key ||
        !json_get(request->input, "chunk_start") ||
        !json_get(request->input, "chunks_paid")) {
        mpn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_INPUT", "normalize",
                 "wallet_scope, offer_id, source_address, chunk_start, "
                 "chunks_paid, and idempotency_key are required",
                 "app.market.purchase.plan", false);
        return;
    }
    struct json_value body;
    json_init(&body);
    if (!mpn_call(reply, "zmarket_purchase_plan", request->input, &body, 0))
        return;
    mpn_merge(&reply->data, &body);
    const char *plan = json_get_str(json_get(&body, "plan_id"));
    bool replay = json_get_bool_or(&body, "idempotent_replay", false);
    struct zcl_hotswap_service_lease lease = {0};
    const struct market_purchase_view_service_v1 *service =
        zcl_hotswap_service_acquire(MARKET_PURCHASE_VIEW_SERVICE_ID, &lease);
    if (!service) service = market_purchase_view_service_builtin();
    char commit[192] = {0};
    bool commit_rendered = service->render_commit_input(
        scope, plan ? plan : "", commit, sizeof(commit));
    zcl_hotswap_service_release(&lease);
    if (!commit_rendered) {
        json_free(&body);
        mpn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "COMMIT_HINT_FAILED", "render",
                 "the pure marketplace view service refused the commit hint",
                 "app.market.purchase.plan", reply->error.mutated);
        return;
    }
    (void)json_push_kv_str(&reply->data, "stage", "plan");
    (void)json_push_kv_bool(&reply->data, "committed", false);
    (void)json_push_kv_bool(&reply->data, "spends_funds", false);
    (void)json_push_kv_str(
        &reply->data, "confirm_hint",
        "pass commit_input to app market purchase commit to pay");
    (void)json_push_kv_str(&reply->data, "commit_input", commit);
    reply->error.mutated = !replay;
    json_free(&body);
}

void zcl_native_handle_market_purchase_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !request->input || !reply) return;
    const char *scope = json_get_str(json_get(request->input, "wallet_scope"));
    const char *plan = json_get_str(json_get(request->input, "plan_id"));
    if (!scope || !plan || !json_get_bool_or(request->input, "confirm", false)) {
        mpn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "CONFIRM_REQUIRED", "normalize",
                 "wallet_scope, plan_id, and confirm:true are required",
                 "app.market.purchase.commit", false);
        return;
    }
    struct json_value input = {0};
    json_set_object(&input);
    json_push_kv_str(&input, "wallet_scope", scope);
    json_push_kv_str(&input, "plan_id", plan);
    struct json_value body;
    json_init(&body);
    if (!mpn_call(reply, "zmarket_purchase_commit", &input, &body, 0)) {
        json_free(&input);
        return;
    }
    json_free(&input);
    mpn_merge(&reply->data, &body);
    bool replay = json_get_bool_or(&body, "idempotent_replay", false);
    bool queued = json_get_bool_or(&body,
                                    "payment_notification_queued", false);
    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    (void)json_push_kv_bool(&reply->data, "spends_funds", true);
    reply->error.mutated = !replay || queued;
    json_free(&body);
}

void zcl_native_handle_market_purchase_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !request->input || !reply) return;
    const char *plan = json_get_str(json_get(request->input, "plan_id"));
    if (!plan || !plan[0]) {
        mpn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_PLAN_ID", "normalize", "plan_id is required",
                 "app.market.purchase.status", false);
        return;
    }
    struct json_value input = {0};
    json_set_object(&input);
    json_push_kv_str(&input, "plan_id", plan);
    struct json_value body;
    json_init(&body);
    if (!mpn_call(reply, "zmarket_purchase_status", &input, &body, 0)) {
        json_free(&input);
        return;
    }
    json_free(&input);
    mpn_merge(&reply->data, &body);
    (void)json_push_kv_str(&reply->data, "stage", "status");
    reply->error.mutated = false;
    json_free(&body);
}

void zcl_native_handle_market_purchase_retrieve(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *plan = request && request->input
        ? json_get_str(json_get(request->input, "plan_id")) : NULL;
    const char *destination = request && request->input
        ? json_get_str(json_get(request->input, "destination_path")) : NULL;
    uint8_t parsed[32];
    if (!plan || !destination || !destination[0] ||
        !zcl_hex_decode(plan, parsed, 32)) {
        mpn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_INPUT", "normalize",
                 "plan_id and private destination_path are required",
                 "app.market.purchase.retrieve", false);
        return;
    }
    struct json_value body;
    json_init(&body);
    if (!mpn_call(reply, "zmarket_purchase_retrieve", request->input,
                  &body, MPN_RETRIEVE_DEADLINE_MS))
        return;
    mpn_merge(&reply->data, &body);
    (void)json_push_kv_str(&reply->data, "stage", "retrieved");
    reply->error.mutated = true;
    json_free(&body);
}

/* ── Hot-swappable leaves ──────────────────────────────────────────────────
 * Read-only PURCHASE projections: the buyer guide and one purchase's state. Every mutating sibling in this file is
 * absent from the table; the loader refuses to re-point a leaf that is
 * missing from this file's row in config/hotswap_swappable.def. */
#if defined(ZCL_HOTSWAP_GEN) || defined(ZCL_HOTSWAP_MODULE_GEN)
#define ZCL_HOTSWAP_PROBE_LEAF "app.market.purchase.guide"
#include "hotswap/hotswap_register.h"
ZCL_HOTSWAP_LEAVES_BEGIN(market_purchase)
ZCL_HOTSWAP_LEAF("app.market.purchase.guide", zcl_native_handle_market_purchase_guide)
ZCL_HOTSWAP_LEAF("app.market.purchase.status", zcl_native_handle_market_purchase_status)
ZCL_HOTSWAP_LEAVES_END(market_purchase)
#endif
