/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Owner-only typed adapters for per-node marketplace listing moderation.
 *
 * The active profile decides which locally-ingested offers this node
 * lists AND which ones it hands to another party. There are no
 * network-wide bans and no deletion authority — a hidden offer stays
 * stored, keeps its signed wire, and stays reachable from any node that
 * does host it — and protocol validity is never filtered: moderation
 * never reaches block or transaction acceptance. Each handler proxies one
 * zmarket_* RPC so the policy file and node.db stay single-writer in the
 * node process. */

#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "command/native_command.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "services/market_moderation_view_service.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MMN_TAG "native.market.moderation"

static bool market_moderation_view_frozen_kat(const void *opaque, char *why,
                                               size_t why_sz)
{
    const struct market_moderation_view_service_v1 *service = opaque;
    struct market_moderation_decision_result_v1 decision;
    struct market_moderation_profile_result_v1 profile;
    struct market_moderation_guide_result_v1 guide;
    int resolved = -1;
    static const bool visible[MARKET_MODERATION_PROFILE_COUNT]
                             [MARKET_REVIEW_STATE_COUNT] = {
        {false, true, false},
        {true, true, true},
    };
    if (!service || !service->resolve_profile || !service->decide ||
        !service->render_profile || !service->render_guide) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen moderation service shape vector failed");
        return false;
    }
    for (int p = 0; p < MARKET_MODERATION_PROFILE_COUNT; p++) {
        for (int s = 0; s < MARKET_REVIEW_STATE_COUNT; s++) {
            if (!service->decide(p, s, &decision) || !decision.valid ||
                decision.visible != visible[p][s] ||
                !decision.local_view_only || !decision.wire_unchanged) {
                if (why && why_sz) (void)snprintf(
                    why, why_sz,
                    "frozen moderation visibility vector %d/%d failed", p,
                    s);
                return false;
            }
        }
    }
    if (!service->decide(99, MARKET_REVIEW_REVIEWED_OK, &decision) ||
        decision.valid || !decision.local_view_only ||
        !decision.wire_unchanged ||
        !service->resolve_profile("default", MARKET_MODERATION_PROFILE_OPEN,
                                  &resolved) ||
        resolved != MARKET_MODERATION_PROFILE_OPEN ||
        !service->resolve_profile("general", MARKET_MODERATION_PROFILE_OPEN,
                                  &resolved) ||
        resolved != MARKET_MODERATION_PROFILE_DEFAULT ||
        !service->resolve_profile("open", MARKET_MODERATION_PROFILE_DEFAULT,
                                  &resolved) ||
        resolved != MARKET_MODERATION_PROFILE_OPEN ||
        service->resolve_profile("unknown", MARKET_MODERATION_PROFILE_DEFAULT,
                                 &resolved) ||
        !service->render_profile(MARKET_MODERATION_PROFILE_DEFAULT, &profile) ||
        !profile.valid || !profile.immutable ||
        strcmp(profile.profile,
               MARKET_MODERATION_PROFILE_GENERAL_AUDIENCE_V1) != 0 ||
        !service->render_profile(MARKET_MODERATION_PROFILE_OPEN, &profile) ||
        !profile.valid || strcmp(profile.hides, "nothing") != 0 ||
        !service->render_guide(&guide) || !guide.policy_authority_static ||
        !guide.persistence_static || !guide.network_authority_static ||
        !guide.wire_unchanged) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen moderation resolve/profile/guide vector failed");
        return false;
    }
    return true;
}

static const struct zcl_hotswap_service_contract k_market_moderation_contract = { /* hotswap-static-ok: leaf registration tables are immutable */    .service_id = MARKET_MODERATION_VIEW_SERVICE_ID,
    .source_tu = "contexts/market/services/src/market_moderation_view_service.c",
    .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
    .vtable_size = sizeof(struct market_moderation_view_service_v1),
    .abi_fingerprint = MARKET_MODERATION_VIEW_ABI_FINGERPRINT,
    .schema_fingerprint = MARKET_MODERATION_VIEW_SCHEMA_FINGERPRINT,
    .wire_fingerprint = MARKET_MODERATION_VIEW_WIRE_FINGERPRINT,
    .kat_fingerprint = MARKET_MODERATION_VIEW_KAT_FINGERPRINT,
    .frozen_kat = market_moderation_view_frozen_kat,
};

const struct zcl_hotswap_service_contract *
zcl_native_market_moderation_view_service_contract(void)
{
    return &k_market_moderation_contract;
}

static void mmn_fail(struct zcl_command_reply *reply,
                     enum zcl_command_status status,
                     enum zcl_command_exit exit_code, const char *code,
                     const char *phase, const char *message,
                     const char *evidence)
{
    LOG_ERROR(MMN_TAG, "%s: %s", code, message);
    zcl_command_reply_fail(reply, status, exit_code, code, phase, false,
                           false, message, evidence);
}

static const char *mmn_str(const struct json_value *in, const char *key)
{
    const struct json_value *v = in ? json_get(in, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

/* Call one zmarket_* moderation RPC with a positional string arg list and
 * parse the JSON body. NULL + a filled reply on transport/parse failure. */
static bool mmn_call(const char *method,
                     const char *const *args, size_t arg_count,
                     struct json_value *body,
                     struct zcl_command_reply *reply)
{
    struct rpc_arg_builder params;
    rpc_arg_builder_init(&params);
    for (size_t i = 0; i < arg_count; i++)
        rpc_arg_builder_push_str(&params, args[i]);
    char *params_json = rpc_arg_builder_to_json(&params);
    if (!params_json) {
        mmn_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                 ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED", "normalize",
                 "could not encode the moderation request", method);
        return false;
    }
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call(method, arg_count ? params_json : NULL);
    free(params_json);
    if (!raw) {
        mmn_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                 ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE", "dispatch",
                 "the node did not answer the moderation request", method);
        return false;
    }
    bool parsed = json_read(body, raw, strlen(raw));
    free(raw);
    if (!parsed) {
        json_free(body);
        mmn_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                 ZCL_COMMAND_EXIT_INTERNAL, "BAD_RPC_BODY", "serialize",
                 "the moderation reply was unparseable", method);
        return false;
    }
    if (body->type == JSON_STR) {
        /* Error-body convention: "CODE: message" or a bare message. */
        const char *reason = json_get_str(body);
        char code[64] = "MARKET_MODERATION_REFUSED";
        const char *colon = reason ? strchr(reason, ':') : NULL;
        if (colon && colon > reason && (size_t)(colon - reason) < 48) {
            size_t n = (size_t)(colon - reason);
            memcpy(code, reason, n);
            code[n] = '\0';
            reason = colon + 1;
            while (*reason == ' ') reason++;
        }
        char message[256];
        snprintf(message, sizeof(message), "%s",
                 reason && reason[0] ? reason
                                     : "the moderation request was refused");
        json_free(body);
        mmn_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                 ZCL_COMMAND_EXIT_FAILED, code, "execute", message, method);
        return false;
    }
    if (body->type != JSON_OBJ) {
        json_free(body);
        mmn_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                 ZCL_COMMAND_EXIT_INTERNAL, "BAD_RPC_BODY", "serialize",
                 "the moderation reply was not an object", method);
        return false;
    }
    return true;
}

static void mmn_copy_str(struct json_value *data,
                         const struct json_value *body, const char *key)
{
    const char *v = mmn_str(body, key);
    if (v)
        (void)json_push_kv_str(data, key, v);
}

static void mmn_copy_int(struct json_value *data,
                         const struct json_value *body, const char *key)
{
    const struct json_value *v = json_get(body, key);
    if (v && v->type == JSON_INT)
        (void)json_push_kv_int(data, key, json_get_int(v));
}

static void mmn_copy_bool(struct json_value *data,
                          const struct json_value *body, const char *key)
{
    const struct json_value *v = json_get(body, key);
    if (v && v->type == JSON_BOOL)
        (void)json_push_kv_bool(data, key, json_get_bool(v));
}

void zcl_native_handle_market_moderation_guide(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !request->input || !reply ||
        request->input->type != JSON_OBJ || request->input->num_children != 0) {
        if (reply) mmn_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_INVALID, "BAD_MARKET_MODERATION_GUIDE_INPUT",
            "validate", "app market moderation guide accepts no input keys",
            "app.market.moderation.guide");
        return;
    }
    struct zcl_hotswap_service_lease lease = {0};
    const struct market_moderation_view_service_v1 *service =
        zcl_hotswap_service_acquire(MARKET_MODERATION_VIEW_SERVICE_ID, &lease);
    if (!service) service = market_moderation_view_service_builtin();
    struct market_moderation_guide_result_v1 guide;
    if (!service->render_guide(&guide)) {
        zcl_hotswap_service_release(&lease);
        mmn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "MARKET_MODERATION_VIEW_FAILED", "render",
                 "the pure moderation view service refused guide rendering",
                 "app.market.moderation.guide");
        return;
    }
    (void)json_push_kv_str(&reply->data, "service_id",
                           MARKET_MODERATION_VIEW_SERVICE_ID);
    (void)json_push_kv_int(&reply->data, "service_generation",
                           zcl_hotswap_service_generation());
    (void)json_push_kv_bool(&reply->data, "policy_authority_static",
                            guide.policy_authority_static);
    (void)json_push_kv_bool(&reply->data, "persistence_static",
                            guide.persistence_static);
    (void)json_push_kv_bool(&reply->data, "network_authority_static",
                            guide.network_authority_static);
    (void)json_push_kv_bool(&reply->data, "wire_unchanged",
                            guide.wire_unchanged);
    (void)json_push_kv_str(&reply->data, "live_surface", guide.live_surface);
    (void)json_push_kv_str(&reply->data, "static_boundary",
                           guide.static_boundary);
    (void)json_push_kv_str(&reply->data, "next_command", guide.next_command);
    zcl_hotswap_service_release(&lease);
}

void zcl_native_handle_market_moderation_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct json_value body;
    if (!mmn_call("zmarket_moderation_status", NULL, 0, &body, reply))
        return;
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.market_moderation_status.v1");
    mmn_copy_str(&reply->data, &body, "active_profile");
    /* Both legs reach the typed surface as two separately-valued keys.
     * A reader must never have to derive the relay posture from the
     * serve rule, or from a key being absent. */
    mmn_copy_str(&reply->data, &body, "serve_rule");
    mmn_copy_str(&reply->data, &body, "relay_rule");
    mmn_copy_bool(&reply->data, &body, "relay_gated");
    mmn_copy_str(&reply->data, &body, "policy_file");
    mmn_copy_int(&reply->data, &body, "offers_cached");
    mmn_copy_bool(&reply->data, &body, "review_counts_live");
    mmn_copy_bool(&reply->data, &body, "view_filter_only");
    const struct json_value *counts = json_get(&body, "review_counts");
    if (counts && counts->type == JSON_OBJ) {
        struct json_value flat;
        json_init(&flat);
        json_set_object(&flat);
        static const char *const states[] = {
            "unreviewed", "reviewed_ok", "sensitive" };
        for (size_t i = 0; i < 3; i++) {
            const struct json_value *n = json_get(counts, states[i]);
            if (n && n->type == JSON_INT)
                (void)json_push_kv_int(&flat, states[i], json_get_int(n));
        }
        (void)json_push_kv(&reply->data, "review_counts", &flat);
        json_free(&flat);
    }
    const struct json_value *profiles = json_get(&body,
                                                 "available_profiles");
    if (profiles && profiles->type == JSON_ARR) {
        struct json_value copy;
        json_init(&copy);
        json_set_array(&copy);
        for (size_t i = 0; i < profiles->num_children; i++) {
            const struct json_value *p = &profiles->children[i];
            const char *name =
                p->type == JSON_STR ? json_get_str(p) : NULL;
            if (!name)
                continue;
            struct json_value item;
            json_init(&item);
            json_set_str(&item, name);
            (void)json_push_back(&copy, &item);
            json_free(&item);
        }
        (void)json_push_kv(&reply->data, "available_profiles", &copy);
        json_free(&copy);
    }
    json_free(&body);
}

void zcl_native_handle_market_moderation_profile_show(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *profile = mmn_str(request->input, "profile");
    if (!profile || !profile[0]) {
        mmn_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                 ZCL_COMMAND_EXIT_INVALID, "MISSING_INPUT", "normalize",
                 "profile is required",
                 "zmarket_moderation_profile_show");
        return;
    }
    const char *const args[] = { profile };
    struct json_value body;
    if (!mmn_call("zmarket_moderation_profile_show", args, 1, &body, reply))
        return;
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.market_moderation_profile.v1");
    mmn_copy_str(&reply->data, &body, "profile");
    mmn_copy_bool(&reply->data, &body, "immutable");
    mmn_copy_bool(&reply->data, &body, "active");
    mmn_copy_str(&reply->data, &body, "shows");
    mmn_copy_str(&reply->data, &body, "hides");
    mmn_copy_str(&reply->data, &body, "leg");
    mmn_copy_str(&reply->data, &body, "active_relay_rule");
    mmn_copy_str(&reply->data, &body, "policy_file");
    json_free(&body);
}

void zcl_native_handle_market_moderation_profile_set(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *profile = mmn_str(request->input, "profile");
    const char *mode = mmn_str(request->input, "mode");
    const char *plan_token = mmn_str(request->input, "plan_token");
    if (!profile || !profile[0] || !mode ||
        (strcmp(mode, "plan") != 0 && strcmp(mode, "commit") != 0) ||
        (strcmp(mode, "commit") == 0 && (!plan_token || !plan_token[0]))) {
        mmn_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                 ZCL_COMMAND_EXIT_INVALID, "MISSING_INPUT", "normalize",
                 "profile plus mode (plan|commit) are required; commit also "
                 "requires the plan_token minted by the plan step",
                 "zmarket_moderation_profile_set");
        return;
    }
    const char *const args[] = { profile, mode,
                                 plan_token ? plan_token : "" };
    struct json_value body;
    if (!mmn_call("zmarket_moderation_profile_set", args, 3, &body, reply))
        return;
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.market_moderation_profile_set.v1");
    mmn_copy_str(&reply->data, &body, "mode");
    mmn_copy_bool(&reply->data, &body, "committed");
    mmn_copy_str(&reply->data, &body, "plan_token");
    mmn_copy_str(&reply->data, &body, "profile");
    mmn_copy_str(&reply->data, &body, "previous_profile");
    /* Echo the leg this command did NOT touch, so the operator can see
     * that moving the serve profile left relay where it was. */
    mmn_copy_str(&reply->data, &body, "relay_rule");
    mmn_copy_bool(&reply->data, &body, "relay_rule_unchanged");
    mmn_copy_str(&reply->data, &body, "policy_file");
    const struct json_value *committed = json_get(&body, "committed");
    if (committed && committed->type == JSON_BOOL &&
        json_get_bool(committed))
        reply->error.mutated = true;
    json_free(&body);
}

/* The RELAY leg's typed setter: a command of its own, never a flag on
 * the profile setter, because the two legs have different defaults and
 * changing what this node HOSTS must not move what it FORWARDS. */
void zcl_native_handle_market_moderation_relay_set(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *relay_rule = mmn_str(request->input, "relay_rule");
    const char *mode = mmn_str(request->input, "mode");
    const char *plan_token = mmn_str(request->input, "plan_token");
    if (!relay_rule || !relay_rule[0] || !mode ||
        (strcmp(mode, "plan") != 0 && strcmp(mode, "commit") != 0) ||
        (strcmp(mode, "commit") == 0 && (!plan_token || !plan_token[0]))) {
        mmn_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                 ZCL_COMMAND_EXIT_INVALID, "MISSING_INPUT", "normalize",
                 "relay_rule plus mode (plan|commit) are required; commit "
                 "also requires the plan_token minted by the plan step",
                 "zmarket_moderation_relay_set");
        return;
    }
    const char *const args[] = { relay_rule, mode,
                                 plan_token ? plan_token : "" };
    struct json_value body;
    if (!mmn_call("zmarket_moderation_relay_set", args, 3, &body, reply))
        return;
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.market_moderation_relay_set.v1");
    mmn_copy_str(&reply->data, &body, "mode");
    mmn_copy_bool(&reply->data, &body, "committed");
    mmn_copy_str(&reply->data, &body, "plan_token");
    mmn_copy_str(&reply->data, &body, "relay_rule");
    mmn_copy_str(&reply->data, &body, "previous_relay_rule");
    mmn_copy_str(&reply->data, &body, "profile");
    mmn_copy_bool(&reply->data, &body, "profile_unchanged");
    mmn_copy_str(&reply->data, &body, "policy_file");
    const struct json_value *committed = json_get(&body, "committed");
    if (committed && committed->type == JSON_BOOL &&
        json_get_bool(committed))
        reply->error.mutated = true;
    json_free(&body);
}

void zcl_native_handle_market_moderation_review_set(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *offer_id = mmn_str(request->input, "offer_id");
    const char *review_state = mmn_str(request->input, "review_state");
    const char *mode = mmn_str(request->input, "mode");
    const char *plan_token = mmn_str(request->input, "plan_token");
    if (!offer_id || !offer_id[0] || !review_state || !review_state[0] ||
        !mode ||
        (strcmp(mode, "plan") != 0 && strcmp(mode, "commit") != 0) ||
        (strcmp(mode, "commit") == 0 && (!plan_token || !plan_token[0]))) {
        mmn_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                 ZCL_COMMAND_EXIT_INVALID, "MISSING_INPUT", "normalize",
                 "offer_id, review_state, and mode (plan|commit) are "
                 "required; commit also requires the plan_token minted by "
                 "the plan step",
                 "zmarket_review_set");
        return;
    }
    const char *const args[] = { offer_id, review_state, mode,
                                 plan_token ? plan_token : "" };
    struct json_value body;
    if (!mmn_call("zmarket_review_set", args, 4, &body, reply))
        return;
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.market_review_set.v1");
    mmn_copy_str(&reply->data, &body, "mode");
    mmn_copy_bool(&reply->data, &body, "committed");
    mmn_copy_str(&reply->data, &body, "plan_token");
    mmn_copy_str(&reply->data, &body, "status");
    mmn_copy_str(&reply->data, &body, "offer_id");
    mmn_copy_str(&reply->data, &body, "review_state");
    mmn_copy_str(&reply->data, &body, "previous_review_state");
    mmn_copy_bool(&reply->data, &body, "local_only");
    mmn_copy_bool(&reply->data, &body, "gossiped");
    /* Only the commit leg mutates; a plan reports what WOULD change and
     * must not claim otherwise through the mutation flag. */
    const struct json_value *committed = json_get(&body, "committed");
    if (committed && committed->type == JSON_BOOL &&
        json_get_bool(committed))
        reply->error.mutated = true;
    json_free(&body);
}

/* ── Hot-swappable leaves ──────────────────────────────────────────────────
 * Read-only MODERATION POSTURE: what this node serves and relays. Every mutating sibling in this file is
 * absent from the table; the loader refuses to re-point a leaf that is
 * missing from this file's row in config/hotswap_swappable.def. */
#if defined(ZCL_HOTSWAP_GEN) || defined(ZCL_HOTSWAP_MODULE_GEN)
#define ZCL_HOTSWAP_PROBE_LEAF "app.market.moderation.status"
#include "hotswap/hotswap_register.h"
ZCL_HOTSWAP_LEAVES_BEGIN(market_moderation)
ZCL_HOTSWAP_LEAF("app.market.moderation.profile.show", zcl_native_handle_market_moderation_profile_show)
ZCL_HOTSWAP_LEAF("app.market.moderation.guide", zcl_native_handle_market_moderation_guide)
ZCL_HOTSWAP_LEAF("app.market.moderation.status", zcl_native_handle_market_moderation_status)
ZCL_HOTSWAP_LEAVES_END(market_moderation)
#endif
