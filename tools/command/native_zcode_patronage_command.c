/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: native simulation-only ZC23 patronage offer, funding, settlement
 * and refund adapters. */
#include "command/native_command.h"
#include "command/native_zcode_patronage_priv.h"

#include "base/checked.h"
#include "base/hex.h"
#include "json/json.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_commons_projection.h"
#include "vcs/zcode_patronage_funding.h"
#include "vcs/zcode_patronage_projection.h"
#include "vcs/zcode_patronage_settlement.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *zpc_str(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool zpc_keys(const struct json_value *input,
                     const char *const *allowed, size_t count)
{
    if (!input || input->type != JSON_OBJ) return false;
    for (size_t i = 0; i < input->num_children; i++) {
        bool known = false;
        for (size_t j = 0; j < count; j++)
            known = known || strcmp(input->keys[i], allowed[j]) == 0;
        if (!known) return false;
    }
    return true;
}

static bool zpc_hex(const struct json_value *input, const char *key,
                    uint8_t *out, size_t out_len)
{
    const char *value = zpc_str(input, key);
    return value && strlen(value) == out_len * 2u &&
           zcl_hex_decode_lower(value, out, out_len);
}

static bool zpc_now(const struct json_value *input, int64_t *out)
{
    const struct json_value *value = input ? json_get(input, "now_unix")
                                           : NULL;
    if (!value || value->type != JSON_INT || json_get_int(value) <= 0)
        return false;
    *out = json_get_int(value);
    return true;
}

static void zpc_fail(struct zcl_command_reply *reply, const char *code,
                     const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, detail, "zcode.patronage");
}

static void zpc_root(struct json_value *data, const char *key,
                     const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(data, key, hex);
}

static const char *zpc_mode(uint8_t mode)
{
    switch (mode) {
    case VCS_ZCODE_PATRONAGE_EXACT_TASK_COMMISSION:
        return "exact_task_commission";
    case VCS_ZCODE_PATRONAGE_PACKAGE_CONTINUITY:
        return "package_continuity";
    case VCS_ZCODE_PATRONAGE_DIRECT_GIFT: return "direct_gift";
    default: return "invalid";
    }
}

static void zpc_render_intent(
    struct json_value *data,
    const struct vcs_zcode_patronage_intent_v1 *intent,
    const uint8_t root[32])
{
    (void)json_push_kv_str(data, "object", "patronage_intent");
    zpc_root(data, "patronage_intent_root", root);
    (void)json_push_kv_str(data, "mode", zpc_mode(intent->mode));
    (void)json_push_kv_int(data, "amount_atoms",
                           (int64_t)intent->amount_atoms);
    (void)json_push_kv_int(data, "created_unix", intent->created_unix);
    (void)json_push_kv_int(data, "expires_unix", intent->expires_unix);
    zpc_root(data, "target_root", intent->target_root);
    zpc_root(data, "patron_contributor_binding_root",
             intent->patron_contributor_binding_root);
    zpc_root(data, "intended_recipient_binding_root",
             intent->intended_recipient_binding_root);
    (void)json_push_kv_bool(data, "funded", false);
    (void)json_push_kv_bool(data, "simulation_only", true);
    (void)json_push_kv_bool(data, "no_authority", true);
    (void)json_push_kv_bool(data, "implies_ownership", false);
    (void)json_push_kv_bool(data, "creates_score", false);
    (void)json_push_kv_bool(data, "moves_live_funds", false);
}

static void zpc_render_funding(
    struct json_value *data,
    const struct vcs_zcode_patronage_funding_v1 *funding,
    const uint8_t root[32])
{
    (void)json_push_kv_str(data, "object", "patronage_funding");
    zpc_root(data, "patronage_funding_root", root);
    zpc_root(data, "patronage_intent_root",
             funding->patronage_intent_root);
    zpc_root(data, "simulation_plan_root", funding->simulation_plan_root);
    (void)json_push_kv_int(data, "amount_atoms",
                           (int64_t)funding->amount_atoms);
    (void)json_push_kv_int(data, "created_unix", funding->created_unix);
    (void)json_push_kv_str(data, "funding_status", "fully_simulated");
    (void)json_push_kv_bool(data, "funded", false);
    (void)json_push_kv_bool(data, "simulation_funded", true);
    (void)json_push_kv_bool(data, "has_transaction_bytes", false);
    (void)json_push_kv_bool(data, "moves_live_funds", false);
    (void)json_push_kv_bool(data, "creates_protocol_emission", false);
}

static bool zpc_context(
    const struct json_value *input,
    struct vcs_zcode_patronage_validation_context *context,
    uint8_t network[32])
{
    const char *workspace = zpc_str(input, "workspace");
    int64_t now = 0;
    if (!workspace ||
        !zcl_native_zcode_workspace_is_explicit_scratch(workspace) ||
        !zpc_hex(input, "expected_network_genesis_root",
                                network, 32) || !zpc_now(input, &now))
        return false;
    memset(context, 0, sizeof(*context));
    context->workspace = workspace;
    context->expected_network_genesis_root = network;
    context->now_unix = now;
    return true;
}

static bool zpc_intent_input(
    const struct json_value *input,
    struct vcs_zcode_patronage_intent_v1 *intent,
    uint8_t wire[VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES], uint8_t root[32],
    struct vcs_zcode_patronage_validation_context *context,
    uint8_t network[32],
    const char **reason)
{
    if (!zpc_context(input, context, network) ||
        !zpc_hex(input, "intent_hex", wire,
                 VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES)) {
        *reason = "workspace, exact intent_hex, network root and now required";
        return false;
    }
    enum vcs_zcode_patronage_error error =
        vcs_zcode_patronage_intent_parse(
            wire, VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES, intent);
    if (error == VCS_ZCODE_PATRONAGE_OK)
        error = vcs_zcode_patronage_intent_verify_cas(intent, context);
    if (error == VCS_ZCODE_PATRONAGE_OK)
        error = vcs_zcode_patronage_intent_root(intent, root);
    if (error != VCS_ZCODE_PATRONAGE_OK) {
        *reason = vcs_zcode_patronage_error_string(error);
        return false;
    }
    return true;
}

static void zpc_offer(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    bool persist)
{
    static const char *const keys[] = {
        "workspace", "intent_hex", "expected_network_genesis_root",
        "now_unix",
    };
    if (!request || !reply) return;
    if (!zpc_keys(request->input, keys, sizeof(keys) / sizeof(keys[0]))) {
        zpc_fail(reply, "BAD_PATRONAGE_OFFER", "closed input rejected");
        return;
    }
    uint8_t wire[VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES], root[32], network[32];
    struct vcs_zcode_patronage_intent_v1 intent;
    struct vcs_zcode_patronage_validation_context context;
    const char *reason = NULL;
    if (!zpc_intent_input(request->input, &intent, wire, root,
                          &context, network, &reason) ||
        (persist && (!vcs_object_store_init(context.workspace) ||
                     !vcs_object_put_addressed(context.workspace, root, wire,
                                               sizeof(wire))))) {
        zpc_fail(reply, "PATRONAGE_OFFER_REFUSED",
                 reason ? reason : "existing workspace CAS write refused");
        return;
    }
    zpc_render_intent(&reply->data, &intent, root);
    (void)json_push_kv_bool(&reply->data, "persisted", persist);
    (void)json_push_kv_str(&reply->data, "validation_authority",
                           "caller_pinned_simulation_context");
}

void zcl_native_handle_zcode_patronage_offer_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zpc_offer(request, reply, false);
}

void zcl_native_handle_zcode_patronage_offer_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zpc_offer(request, reply, true);
}

static bool zpc_funding_input(
    const struct json_value *input,
    struct vcs_zcode_patronage_funding_v1 *funding,
    uint8_t wire[VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES], uint8_t root[32],
    struct vcs_zcode_patronage_validation_context *context,
    uint8_t network[32],
    const char **reason)
{
    if (!zpc_context(input, context, network) ||
        !zpc_hex(input, "funding_hex", wire,
                 VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES)) {
        *reason = "workspace, exact funding_hex, network root and now required";
        return false;
    }
    enum vcs_zcode_patronage_funding_error error =
        vcs_zcode_patronage_funding_parse(
            wire, VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES, funding);
    if (error == VCS_ZCODE_PATRONAGE_FUNDING_OK)
        error = vcs_zcode_patronage_funding_verify_cas(funding, context);
    if (error == VCS_ZCODE_PATRONAGE_FUNDING_OK)
        error = vcs_zcode_patronage_funding_root(funding, root);
    if (error != VCS_ZCODE_PATRONAGE_FUNDING_OK) {
        *reason = vcs_zcode_patronage_funding_error_string(error);
        return false;
    }
    return true;
}

static void zpc_fund(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    bool persist)
{
    static const char *const keys[] = {
        "workspace", "funding_hex", "expected_network_genesis_root",
        "now_unix",
    };
    if (!request || !reply) return;
    if (!zpc_keys(request->input, keys, sizeof(keys) / sizeof(keys[0]))) {
        zpc_fail(reply, "BAD_PATRONAGE_FUNDING", "closed input rejected");
        return;
    }
    uint8_t wire[VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES], root[32], network[32];
    struct vcs_zcode_patronage_funding_v1 funding;
    struct vcs_zcode_patronage_validation_context context;
    const char *reason = NULL;
    if (!zpc_funding_input(request->input, &funding, wire, root,
                           &context, network, &reason) ||
        (persist && (!vcs_object_store_init(context.workspace) ||
                     !vcs_object_put_addressed(context.workspace, root, wire,
                                               sizeof(wire))))) {
        zpc_fail(reply, "PATRONAGE_FUNDING_REFUSED",
                 reason ? reason : "existing workspace CAS write refused");
        return;
    }
    zpc_render_funding(&reply->data, &funding, root);
    (void)json_push_kv_bool(&reply->data, "persisted", persist);
    (void)json_push_kv_str(&reply->data, "validation_authority",
                           "caller_pinned_simulation_context");
}

void zcl_native_handle_zcode_patronage_fund_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zpc_fund(request, reply, false);
}

void zcl_native_handle_zcode_patronage_fund_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zpc_fund(request, reply, true);
}

void zcl_native_handle_zcode_patronage_show(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static const char *const keys[] = {
        "workspace", "root", "expected_network_genesis_root", "now_unix",
    };
    if (!request || !reply) return;
    uint8_t root[32], network[32], derived[32], *wire = NULL;
    size_t wire_len = 0;
    struct vcs_zcode_patronage_validation_context context;
    if (!zpc_keys(request->input, keys, sizeof(keys) / sizeof(keys[0])) ||
        !zpc_hex(request->input, "root", root, 32) ||
        !zpc_context(request->input, &context, network) ||
        vcs_object_load_raw_bounded(context.workspace, root,
            VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES,
            &wire, &wire_len) != 0) {
        free(wire);
        zpc_fail(reply, "PATRONAGE_NOT_FOUND",
                 "exact root absent or closed show input malformed");
        return;
    }
    bool ok = false;
    if (wire_len == VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES) {
        struct vcs_zcode_patronage_intent_v1 intent;
        ok = vcs_zcode_patronage_intent_parse(wire, wire_len, &intent) ==
                VCS_ZCODE_PATRONAGE_OK &&
             vcs_zcode_patronage_intent_verify_cas(&intent, &context) ==
                VCS_ZCODE_PATRONAGE_OK &&
             vcs_zcode_patronage_intent_root(&intent, derived) ==
                VCS_ZCODE_PATRONAGE_OK && memcmp(root, derived, 32) == 0;
        if (ok) zpc_render_intent(&reply->data, &intent, root);
    } else if (wire_len == VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES) {
        struct vcs_zcode_patronage_funding_v1 funding;
        ok = vcs_zcode_patronage_funding_parse(wire, wire_len, &funding) ==
                VCS_ZCODE_PATRONAGE_FUNDING_OK &&
             vcs_zcode_patronage_funding_verify_cas(&funding, &context) ==
                VCS_ZCODE_PATRONAGE_FUNDING_OK &&
             vcs_zcode_patronage_funding_root(&funding, derived) ==
                VCS_ZCODE_PATRONAGE_FUNDING_OK &&
             memcmp(root, derived, 32) == 0;
        if (ok) zpc_render_funding(&reply->data, &funding, root);
    }
    free(wire);
    if (!ok) {
        zpc_fail(reply, "PATRONAGE_CORRUPT",
                 "stored offer or funding did not reverify");
        return;
    }
    (void)json_push_kv_str(&reply->data, "validation_authority",
                           "caller_pinned_simulation_context");
}

static const char *zpc_projection_kind(uint8_t kind)
{
    switch (kind) {
    case VCS_ZCODE_PATRONAGE_PROJECTION_OFFER: return "unfunded_offer";
    case VCS_ZCODE_PATRONAGE_PROJECTION_SIMULATED_FUNDING:
        return "simulated_funding";
    case VCS_ZCODE_PATRONAGE_PROJECTION_CONTINUITY_POLICY:
        return "continuity_policy";
    default: return "invalid";
    }
}

void zcl_native_handle_zcode_patronage_list(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static const char *const keys[] = {
        "workspace", "expected_network_genesis_root", "now_unix",
    };
    if (!request || !reply) return;
    uint8_t network[32], projection_root[32], failure_root[32];
    struct vcs_zcode_patronage_validation_context context;
    if (!zpc_keys(request->input, keys, sizeof(keys) / sizeof(keys[0])) ||
        !zpc_context(request->input, &context, network)) {
        zpc_fail(reply, "BAD_PATRONAGE_LIST", "closed list input rejected");
        return;
    }
    struct vcs_zcode_patronage_projection *projection =
        vcs_zcode_patronage_projection_build(&context);
    if (!projection || !vcs_zcode_patronage_projection_root(
                            projection, projection_root)) {
        vcs_zcode_patronage_projection_free(projection);
        zpc_fail(reply, "PATRONAGE_LIST_REFUSED",
                 "read-only canonical CAS rebuild failed");
        return;
    }
    struct json_value rows;
    json_init(&rows); json_set_array(&rows);
    size_t offers = 0, fundings = 0, policies = 0;
    size_t count = vcs_zcode_patronage_projection_count(projection);
    for (size_t i = 0; i < count; i++) {
        const struct vcs_zcode_patronage_projection_entry *entry =
            vcs_zcode_patronage_projection_at(projection, i);
        struct json_value row;
        json_init(&row); json_set_object(&row);
        zpc_root(&row, "root", entry->root);
        zpc_root(&row, "target_root", entry->target_root);
        (void)json_push_kv_str(&row, "kind",
                               zpc_projection_kind(entry->kind));
        char amount[21];
        (void)snprintf(amount, sizeof(amount), "%" PRIu64,
                       entry->amount_atoms);
        (void)json_push_kv_str(&row, "amount_atoms", amount);
        (void)json_push_kv_int(&row, "created_unix", entry->created_unix);
        (void)json_push_kv_int(&row, "expires_unix", entry->expires_unix);
        bool active = entry->expires_unix > 0 &&
                      context.now_unix < entry->expires_unix;
        (void)json_push_kv_bool(&row, "active", active);
        (void)json_push_kv_bool(&row, "funded", false);
        (void)json_push_back(&rows, &row); json_free(&row);
        offers += entry->kind == VCS_ZCODE_PATRONAGE_PROJECTION_OFFER;
        fundings += entry->kind ==
            VCS_ZCODE_PATRONAGE_PROJECTION_SIMULATED_FUNDING;
        policies += entry->kind ==
            VCS_ZCODE_PATRONAGE_PROJECTION_CONTINUITY_POLICY;
    }
    zpc_root(&reply->data, "projection_root", projection_root);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)count);
    (void)json_push_kv_int(&reply->data, "offer_count", (int64_t)offers);
    (void)json_push_kv_int(&reply->data, "simulated_funding_count",
                           (int64_t)fundings);
    (void)json_push_kv_int(&reply->data, "continuity_policy_count",
                           (int64_t)policies);
    (void)json_push_kv(&reply->data, "objects", &rows); json_free(&rows);
    const char *reason = NULL;
    bool failed = vcs_zcode_patronage_projection_first_failure(
        projection, failure_root, &reason);
    (void)json_push_kv_str(&reply->data, "verification_status",
        failed ? "partial" : count ? "historically_verified" : "unknown");
    if (failed) {
        zpc_root(&reply->data, "first_failure_root", failure_root);
        (void)json_push_kv_str(&reply->data, "first_failure", reason);
    }
    (void)json_push_kv_bool(&reply->data, "funded", false);
    (void)json_push_kv_bool(&reply->data, "moves_live_funds", false);
    (void)json_push_kv_bool(&reply->data, "persisted", false);
    (void)json_push_kv_bool(&reply->data, "creates_score", false);
    vcs_zcode_patronage_projection_free(projection);
}

/* ── simulated settlement / refund ────────────────────────────────────────
 *
 * The settlement verifier (contexts/commons/modules/vcs/src/zcode_patronage_settlement_verify.c)
 * refuses to run without an active-chain anchor authority, an immutable
 * ZC23 policy root and continuity-uniqueness facts — the contexts the
 * PLANNED rows were blocked on. This adapter binds all three from explicit
 * caller pins, the same caller_pinned_simulation_context authority the
 * offer/fund leaves declare, so the leaves execute end to end while every
 * live-money path stays fail-closed by wire shape (the settlement codec
 * rejects any wire without the simulation-only/no-live-funds/no-transaction
 * flags). */

static bool zpc_sim_anchor_is_active(void *opaque, uint64_t height,
                                     const uint8_t block_hash[32])
{
    const struct zpc_simulation_context *context = opaque;
    return context && block_hash &&
        ((height == context->opening_height &&
          memcmp(block_hash, context->opening_hash, 32) == 0) ||
         (height == context->maturity_height &&
          memcmp(block_hash, context->maturity_hash, 32) == 0));
}

/* The callback is consulted only for non-ACTIVE, non-REVOKE (rotated)
 * bindings. Proving a rotation current needs a rotation directory the
 * isolated simulation adapter does not hold, so it fails closed. */
static bool zpc_sim_binding_is_current(void *opaque,
                                       const uint8_t binding_root[32])
{
    (void)opaque;
    (void)binding_root;
    return false;
}

static bool zpc_sim_contribution_is_duplicate(
    void *opaque, const uint8_t candidate_root[32],
    const uint8_t attribution_root[32])
{
    const struct zpc_simulation_context *context = opaque;
    if (!context || !candidate_root || !attribution_root)
        return true; /* fail closed: an unprovable uniqueness is a duplicate */
    struct vcs_zcode_commons_projection *projection =
        vcs_zcode_commons_projection_build(context->patronage.workspace);
    if (!projection)
        return true;
    bool duplicate = false;
    size_t count = vcs_zcode_commons_projection_creation_count(projection);
    for (size_t i = 0; i < count && !duplicate; i++) {
        const struct vcs_zcode_commons_creation_entry *entry =
            vcs_zcode_commons_projection_creation_at(projection, i);
        duplicate = entry &&
            memcmp(entry->candidate_root, candidate_root, 32) == 0 &&
            memcmp(entry->root, attribution_root, 32) != 0;
    }
    vcs_zcode_commons_projection_free(projection);
    return duplicate;
}

/* The continuity event key (zcode_continuity_policy.c) binds exactly the
 * event class, the Score unit evidence root, the package, the release and
 * the toolchain capsule. Root addressing makes same-score-receipt-root imply
 * the same evidence root and same-task-root imply the same capsule, so
 * event-key equality is this five-field tuple over the attribution wire
 * alone — no evidence vertical has to be reloaded to detect a duplicate. */
static uint8_t zpc_sim_event_class(uint16_t category)
{
    switch (category) {
    case VCS_ZCODE_CREATION_BORN_RED_FIX:
    case VCS_ZCODE_CREATION_SECURITY_FIX: return 1;
    case VCS_ZCODE_CREATION_INDEPENDENT_REPRODUCTION: return 2;
    case VCS_ZCODE_CREATION_COMPATIBILITY: return 3;
    case VCS_ZCODE_CREATION_PRESERVATION: return 4;
    default: return 0;
    }
}

static bool zpc_sim_load_creation(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_creation_attribution_v1 *out)
{
    uint8_t *wire = NULL, derived[32];
    size_t wire_len = 0;
    bool ok = vcs_object_load_raw_bounded(
            workspace, root, VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES,
            &wire, &wire_len) == 0 &&
        vcs_zcode_creation_attribution_parse(wire, wire_len, out) ==
            VCS_ZCODE_CREATION_OK &&
        vcs_zcode_creation_attribution_root(out, derived) ==
            VCS_ZCODE_CREATION_OK && memcmp(derived, root, 32) == 0;
    free(wire);
    return ok;
}

static bool zpc_sim_same_event(
    const struct vcs_zcode_creation_attribution_v1 *left,
    const struct vcs_zcode_creation_attribution_v1 *right)
{
    return zpc_sim_event_class(left->category) != 0 &&
        zpc_sim_event_class(left->category) ==
            zpc_sim_event_class(right->category) &&
        memcmp(left->score_receipt_root, right->score_receipt_root, 32) ==
            0 &&
        memcmp(left->package_root, right->package_root, 32) == 0 &&
        memcmp(left->release_root, right->release_root, 32) == 0 &&
        memcmp(left->task_root, right->task_root, 32) == 0;
}

static bool zpc_sim_continuity_is_duplicate(
    void *opaque, const uint8_t event_key[32],
    const uint8_t attribution_root[32])
{
    const struct zpc_simulation_context *context = opaque;
    /* The key itself is not trusted: the identity is independently re-derived
     * from canonical bytes via the tuple equality above. */
    (void)event_key;
    if (!context || !attribution_root)
        return true; /* fail closed */
    struct vcs_zcode_creation_attribution_v1 queried;
    if (!zpc_sim_load_creation(context->patronage.workspace,
                               attribution_root, &queried))
        return true;
    struct vcs_zcode_commons_projection *projection =
        vcs_zcode_commons_projection_build(context->patronage.workspace);
    if (!projection)
        return true;
    bool duplicate = false;
    size_t count = vcs_zcode_commons_projection_creation_count(projection);
    for (size_t i = 0; i < count && !duplicate; i++) {
        const struct vcs_zcode_commons_creation_entry *entry =
            vcs_zcode_commons_projection_creation_at(projection, i);
        if (!entry || memcmp(entry->root, attribution_root, 32) == 0)
            continue;
        struct vcs_zcode_creation_attribution_v1 other;
        if (!zpc_sim_load_creation(context->patronage.workspace, entry->root,
                                   &other)) {
            duplicate = true; /* an unreadable sibling proves nothing */
            break;
        }
        duplicate = zpc_sim_same_event(&queried, &other);
    }
    vcs_zcode_commons_projection_free(projection);
    return duplicate;
}

/* Numeric context pins arrive as decimal strings: the registry's typed-CLI
 * validator types every key it does not name as a string, and these pins are
 * adapter-local. Strict digits-only with checked overflow. */
static bool zpc_u64_pin(const struct json_value *input, const char *key,
                        uint64_t *out)
{
    const char *text = zpc_str(input, key);
    if (!text || !text[0])
        return false;
    uint64_t value = 0;
    for (const char *p = text; *p; p++) {
        if (*p < '0' || *p > '9')
            return false;
        uint64_t next = 0;
        if (!zcl_u64_mul(value, UINT64_C(10), &next) ||
            !zcl_u64_add(next, (uint64_t)(*p - '0'), &next))
            return false;
        value = next;
    }
    *out = value;
    return true;
}

bool zpc_simulation_context_bind(
    const struct json_value *input, struct zpc_simulation_context *context,
    const char **reason)
{
    if (!context)
        return false;
    memset(context, 0, sizeof(*context));
    const char *workspace = zpc_str(input, "workspace");
    int64_t now = 0;
    uint64_t epoch = 0, award = 0, active_height = 0, active_mtp = 0;
    if (!workspace ||
        !zcl_native_zcode_workspace_is_explicit_scratch(workspace) ||
        !zpc_hex(input, "expected_network_genesis_root",
                 context->network_root, 32) ||
        !zpc_hex(input, "expected_zc23_policy_root",
                 context->policy_root, 32) ||
        !zpc_u64_pin(input, "expected_epoch", &epoch) ||
        !zpc_u64_pin(input, "expected_award_atoms", &award) ||
        !zpc_u64_pin(input, "active_height", &active_height) ||
        !zpc_u64_pin(input, "active_mtp", &active_mtp) ||
        !zpc_u64_pin(input, "anchor_opening_height",
                     &context->opening_height) ||
        !zpc_hex(input, "anchor_opening_hash", context->opening_hash, 32) ||
        !zpc_u64_pin(input, "anchor_maturity_height",
                     &context->maturity_height) ||
        !zpc_hex(input, "anchor_maturity_hash", context->maturity_hash, 32) ||
        !zpc_now(input, &now)) {
        if (reason)
            *reason = "workspace, network/immutable-policy roots, epoch/award,"
                      " active-chain height/MTP, both declared anchors and"
                      " now are required";
        return false;
    }
    static const uint8_t zero[32] = {0};
    if (award == 0 || active_height == 0 || active_mtp == 0 ||
        context->opening_height == 0 || context->maturity_height == 0 ||
        memcmp(context->network_root, zero, 32) == 0 ||
        memcmp(context->policy_root, zero, 32) == 0 ||
        memcmp(context->opening_hash, zero, 32) == 0 ||
        memcmp(context->maturity_hash, zero, 32) == 0) {
        if (reason)
            *reason = "zero or empty network, immutable-policy or anchor pin";
        return false;
    }
    if (context->opening_height > context->maturity_height ||
        context->maturity_height > active_height) {
        if (reason)
            *reason = "declared anchors are above the active-chain tip";
        return false;
    }
    if (strlen(workspace) >= sizeof(context->workspace)) {
        if (reason)
            *reason = "workspace path is above the bounded scratch length";
        return false;
    }
    memcpy(context->workspace, workspace, strlen(workspace) + 1);
    context->patronage.workspace = context->workspace;
    context->patronage.expected_network_genesis_root = context->network_root;
    context->patronage.now_unix = now;
    context->patronage.binding_is_current = zpc_sim_binding_is_current;
    context->patronage.callback_opaque = context;
    context->creation.workspace = context->workspace;
    context->creation.expected_network_genesis_root = context->network_root;
    context->creation.expected_zc23_policy_root = context->policy_root;
    context->creation.expected_epoch = epoch;
    context->creation.expected_award_atoms = award;
    context->creation.active_height = active_height;
    context->creation.active_mtp = (int64_t)active_mtp;
    context->creation.now_unix = now;
    context->creation.anchor_is_active = zpc_sim_anchor_is_active;
    context->creation.contribution_is_duplicate =
        zpc_sim_contribution_is_duplicate;
    context->creation.binding_is_current = zpc_sim_binding_is_current;
    context->creation.continuity_is_duplicate =
        zpc_sim_continuity_is_duplicate;
    context->creation.callback_opaque = context;
    context->settlement.patronage = &context->patronage;
    context->settlement.creation = &context->creation;
    context->settlement.active_height = active_height;
    context->settlement.active_mtp = (int64_t)active_mtp;
    context->settlement.now_unix = now;
    return true;
}

/* Refunds carry no proof chain (the codec forbids evidence roots on a
 * REFUNDED wire), so the refund context needs only the patronage facts and
 * the active-chain height/MTP authority the expiry schedule is checked
 * against. The immutable-policy/epoch/award pins stay settle-side. */
static bool zpc_refund_context_bind(
    const struct json_value *input, struct zpc_simulation_context *context,
    const char **reason)
{
    memset(context, 0, sizeof(*context));
    const char *workspace = zpc_str(input, "workspace");
    int64_t now = 0;
    uint64_t active_height = 0, active_mtp = 0;
    if (!workspace ||
        !zcl_native_zcode_workspace_is_explicit_scratch(workspace) ||
        !zpc_hex(input, "expected_network_genesis_root",
                 context->network_root, 32) ||
        !zpc_u64_pin(input, "active_height", &active_height) ||
        !zpc_u64_pin(input, "active_mtp", &active_mtp) ||
        !zpc_now(input, &now)) {
        if (reason)
            *reason = "workspace, network root, active-chain height/MTP pins"
                      " and now are required";
        return false;
    }
    static const uint8_t zero[32] = {0};
    if (active_height == 0 || active_mtp == 0 ||
        memcmp(context->network_root, zero, 32) == 0) {
        if (reason)
            *reason = "zero or empty network root or active-chain pin";
        return false;
    }
    if (strlen(workspace) >= sizeof(context->workspace)) {
        if (reason)
            *reason = "workspace path is above the bounded scratch length";
        return false;
    }
    memcpy(context->workspace, workspace, strlen(workspace) + 1);
    context->patronage.workspace = context->workspace;
    context->patronage.expected_network_genesis_root = context->network_root;
    context->patronage.now_unix = now;
    context->patronage.binding_is_current = zpc_sim_binding_is_current;
    context->patronage.callback_opaque = context;
    context->settlement.patronage = &context->patronage;
    context->settlement.creation = NULL;
    context->settlement.active_height = active_height;
    context->settlement.active_mtp = (int64_t)active_mtp;
    context->settlement.now_unix = now;
    return true;
}

static void zpc_render_settlement(
    struct json_value *data,
    const struct vcs_zcode_patronage_settlement_v1 *settlement,
    const uint8_t root[32])
{
    bool settling =
        settlement->action == VCS_ZCODE_PATRONAGE_SIMULATED_SETTLED;
    (void)json_push_kv_str(data, "object", "patronage_settlement");
    zpc_root(data, "patronage_settlement_root", root);
    (void)json_push_kv_str(data, "action",
        settling ? "simulated_settled" : "simulated_refunded");
    zpc_root(data, "patronage_intent_root",
             settlement->patronage_intent_root);
    zpc_root(data, "patronage_funding_root",
             settlement->patronage_funding_root);
    zpc_root(data, "creation_attribution_root",
             settlement->creation_attribution_root);
    zpc_root(data, "recipient_contributor_binding_root",
             settlement->recipient_contributor_binding_root);
    (void)json_push_kv_int(data, "amount_atoms",
                           (int64_t)settlement->amount_atoms);
    (void)json_push_kv_int(data, "created_unix", settlement->created_unix);
    (void)json_push_kv_int(data, "observed_height",
                           (int64_t)settlement->observed_height);
    (void)json_push_kv_int(data, "observed_mtp", settlement->observed_mtp);
    (void)json_push_kv_bool(data, "settled", false);
    (void)json_push_kv_bool(data, "refunded", false);
    (void)json_push_kv_bool(data, "simulated_settled", settling);
    (void)json_push_kv_bool(data, "simulated_refunded", !settling);
    (void)json_push_kv_bool(data, "simulation_only", true);
    (void)json_push_kv_bool(data, "no_authority", true);
    (void)json_push_kv_bool(data, "implies_custody", false);
    (void)json_push_kv_bool(data, "has_transaction_bytes", false);
    (void)json_push_kv_bool(data, "moves_live_funds", false);
    (void)json_push_kv_bool(data, "creates_protocol_emission", false);
}

/* Shared verify/persist/render. The context is bound by the caller: keeping
 * the bind functions out of this body keeps each leaf's typed input surface
 * exactly the keys its own context consumes (the call-graph input-key gate
 * attributes every callee's reads to the handler). */
static void zpc_settlement_run(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    bool persist, uint8_t expected_action, bool bound,
    const struct zpc_simulation_context *context, const char *reason)
{
    bool settling = expected_action == VCS_ZCODE_PATRONAGE_SIMULATED_SETTLED;
    const char *refused_code =
        settling ? "PATRONAGE_SETTLE_REFUSED" : "PATRONAGE_REFUND_REFUSED";
    uint8_t wire[VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES], root[32];
    if (!bound ||
        !zpc_hex(request->input, "settlement_hex", wire, sizeof(wire))) {
        zpc_fail(reply, refused_code,
                 reason ? reason : "exact settlement_hex wire required");
        return;
    }
    struct vcs_zcode_patronage_settlement_v1 settlement;
    enum vcs_zcode_patronage_settlement_error error =
        vcs_zcode_patronage_settlement_parse(wire, sizeof(wire), &settlement);
    if (error == VCS_ZCODE_PATRONAGE_SETTLEMENT_OK &&
        settlement.action != expected_action) {
        zpc_fail(reply, refused_code, "settlement-action-mismatch");
        return;
    }
    if (error == VCS_ZCODE_PATRONAGE_SETTLEMENT_OK)
        error = vcs_zcode_patronage_settlement_verify_cas(
            &settlement, &context->settlement);
    if (error == VCS_ZCODE_PATRONAGE_SETTLEMENT_OK)
        error = vcs_zcode_patronage_settlement_root(&settlement, root);
    if (error != VCS_ZCODE_PATRONAGE_SETTLEMENT_OK) {
        zpc_fail(reply, refused_code,
                 vcs_zcode_patronage_settlement_error_string(error));
        return;
    }
    if (persist &&
        (!vcs_object_store_init(context->patronage.workspace) ||
         !vcs_object_put_addressed(context->patronage.workspace, root, wire,
                                   sizeof(wire)))) {
        zpc_fail(reply, refused_code, "existing workspace CAS write refused");
        return;
    }
    zpc_render_settlement(&reply->data, &settlement, root);
    (void)json_push_kv_bool(&reply->data, "persisted", persist);
    (void)json_push_kv_str(&reply->data, "validation_authority",
                           "caller_pinned_simulation_context");
}

static void zpc_settle_handle(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    bool persist)
{
    static const char *const keys[] = {
        "workspace", "settlement_hex", "expected_network_genesis_root",
        "expected_zc23_policy_root", "expected_epoch", "expected_award_atoms",
        "active_height", "active_mtp", "anchor_opening_height",
        "anchor_opening_hash", "anchor_maturity_height",
        "anchor_maturity_hash", "now_unix",
    };
    if (!request || !reply)
        return;
    if (!zpc_keys(request->input, keys, sizeof(keys) / sizeof(keys[0]))) {
        zpc_fail(reply, "BAD_PATRONAGE_SETTLE", "closed input rejected");
        return;
    }
    struct zpc_simulation_context context;
    const char *reason = NULL;
    bool bound = zpc_simulation_context_bind(request->input, &context,
                                             &reason);
    zpc_settlement_run(request, reply, persist,
                       VCS_ZCODE_PATRONAGE_SIMULATED_SETTLED, bound, &context,
                       reason);
}

static void zpc_refund_handle(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    bool persist)
{
    static const char *const keys[] = {
        "workspace", "settlement_hex", "expected_network_genesis_root",
        "active_height", "active_mtp", "now_unix",
    };
    if (!request || !reply)
        return;
    if (!zpc_keys(request->input, keys, sizeof(keys) / sizeof(keys[0]))) {
        zpc_fail(reply, "BAD_PATRONAGE_REFUND", "closed input rejected");
        return;
    }
    struct zpc_simulation_context context;
    const char *reason = NULL;
    bool bound = zpc_refund_context_bind(request->input, &context, &reason);
    zpc_settlement_run(request, reply, persist,
                       VCS_ZCODE_PATRONAGE_SIMULATED_REFUNDED, bound,
                       &context, reason);
}

void zcl_native_handle_zcode_patronage_settle_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zpc_settle_handle(request, reply, false);
}

void zcl_native_handle_zcode_patronage_settle_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zpc_settle_handle(request, reply, true);
}

void zcl_native_handle_zcode_patronage_refund_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zpc_refund_handle(request, reply, false);
}

void zcl_native_handle_zcode_patronage_refund_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zpc_refund_handle(request, reply, true);
}

bool zcl_native_zcode_anchor_verify_commons(
    const struct json_value *input,
    struct zcl_native_zcode_anchor_report *report)
{
    if (!input || !report)
        return false;
    memset(report, 0, sizeof(*report));
    static const char *const context_keys[] = {
        "expected_network_genesis_root", "expected_zc23_policy_root",
        "expected_epoch", "expected_award_atoms", "active_height",
        "active_mtp", "anchor_opening_height", "anchor_opening_hash",
        "anchor_maturity_height", "anchor_maturity_hash", "now_unix",
    };
    size_t present = 0;
    const char *missing = NULL;
    for (size_t i = 0; i < sizeof(context_keys) / sizeof(context_keys[0]);
         i++) {
        if (json_get(input, context_keys[i]))
            present++;
        else if (!missing)
            missing = context_keys[i];
    }
    if (present == 0) {
        (void)snprintf(report->context_blocker,
                       sizeof(report->context_blocker), "%s",
                       "simulation_anchor_context_not_supplied");
        return true;
    }
    if (missing) {
        (void)snprintf(report->context_blocker,
                       sizeof(report->context_blocker),
                       "missing_simulation_context_pin:%s", missing);
        return true;
    }
    struct zpc_simulation_context context;
    const char *reason = NULL;
    if (!zpc_simulation_context_bind(input, &context, &reason)) {
        (void)snprintf(report->context_blocker,
                       sizeof(report->context_blocker), "%s",
                       reason ? reason : "simulation context refused");
        return true;
    }
    report->context_bound = true;
    struct vcs_zcode_commons_projection *projection =
        vcs_zcode_commons_projection_build(context.patronage.workspace);
    if (!projection) {
        (void)snprintf(report->first_failure, sizeof(report->first_failure),
                       "%s", "commons-projection-rebuild-failed");
        return true;
    }
    uint8_t failed_root[32];
    const char *failure = NULL;
    bool sound = !vcs_zcode_commons_projection_first_failure(
        projection, failed_root, &failure);
    if (!sound) {
        memcpy(report->first_failure_root, failed_root, 32);
        (void)snprintf(report->first_failure, sizeof(report->first_failure),
                       "%s",
                       failure ? failure : "commons-structural-failure");
    }
    size_t count = vcs_zcode_commons_projection_creation_count(projection);
    for (size_t i = 0; sound && i < count; i++) {
        const struct vcs_zcode_commons_creation_entry *entry =
            vcs_zcode_commons_projection_creation_at(projection, i);
        struct vcs_zcode_creation_attribution_v1 attribution;
        enum vcs_zcode_creation_error error =
            (entry && zpc_sim_load_creation(context.patronage.workspace,
                                            entry->root, &attribution))
                ? vcs_zcode_creation_attribution_verify_cas(
                      &attribution, &context.creation)
                : VCS_ZCODE_CREATION_CAS;
        if (error != VCS_ZCODE_CREATION_OK) {
            if (entry)
                memcpy(report->first_failure_root, entry->root, 32);
            (void)snprintf(report->first_failure,
                           sizeof(report->first_failure), "%s",
                           vcs_zcode_creation_error_string(error));
            sound = false;
        } else {
            report->attributions_checked++;
        }
    }
    report->verified = sound;
    vcs_zcode_commons_projection_free(projection);
    return true;
}
