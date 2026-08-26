/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native Tier-1 hot-swap command glue. The activatable machinery lives here
 * and in lib/hotswap:
 *
 *   - `dev.hotswap.probe`  — VERIFY-ONLY, in the CLI's own throwaway process:
 *     dlopen + ABI-validate + self_test of a module .so, NEVER commits. This is
 *     the default dev-loop surface — it proves a swap WOULD work.
 *   - `dev.hotswap.apply`  — forwards to the RESIDENT node's `dev_hotswap_native`
 *     RPC (a separate CLI process cannot re-point the running node's registry).
 *   - `dev_hotswap_native` — the resident RPC that actually performs the swap
 *     IN the running node, gated by hotswap_activation_authorized(): default is
 *     verify-only; a live swap needs BOTH `-hotswap-activate` AND
 *     `ZCL_HOTSWAP_ACTIVATE=1` and the exact dev datadir (canonical refused).
 *
 * The superseded module .so is dlclose'd only after the command-registry
 * override snapshots drain (registry_quiesced_cb -> epoch/refcount quiesce).
 *
 * The ENTIRE executable surface is `#ifdef ZCL_DEV_BUILD`; a release build links
 * only the no-op register_dev_native_hotswap_rpc() stub. */

#define _GNU_SOURCE
#include "command/native_dev_hotswap.h"
#include "command/native_command.h"

#include "base/hex.h"
#include "crypto/sha256.h"
#include "hotswap/hotswap.h"
#include "hotswap/hotswap_module.h"
#include "hotswap/hotswap_service.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "services/zcode_c23_corpus_service.h"
#include "services/dev_reflex_policy_service.h"
#include "services/zcode_c23_economics_service.h"
#include "services/market_purchase_view_service.h"
#include "services/market_moderation_view_service.h"
#include "services/zcode_package_view_service.h"
#include "services/zcode_moderation_view_service.h"
#include "services/zcode_passport_view_service.h"
#include "services/zcode_goal_context_calc_service.h"
#include "services/zcode_lane_view_service.h"
#include "services/zcode_workspace_view_service.h"
#include "services/shop_reputation_view_service.h"
#include "services/shop_status_view_service.h"
#include "services/shop_want_view_service.h"
#include "services/vault_intent_decision_service.h"
#include "controllers/rpc_client.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

#ifdef ZCL_DEV_BUILD

static bool probe_service_any(const char *so_path,
                              const char *resolved_datadir,
                              bool activate,
                              struct zcl_hotswap_service_report *report)
{
    const struct zcl_hotswap_service_contract *service_contracts[] = {
        zcl_native_dev_reflex_policy_service_contract(),
        zcl_native_zcode_corpus_service_contract(),
        zcl_native_zcode_economics_service_contract(),
        zcl_native_market_purchase_view_service_contract(),
        zcl_native_market_moderation_view_service_contract(),
        zcl_native_zcode_package_view_service_contract(),
        zcl_native_zcode_moderation_view_service_contract(),
        zcl_native_zcode_passport_view_service_contract(),
        zcode_goal_context_calc_service_contract(),
        zcode_lane_view_service_contract(),
        zcl_native_zcode_workspace_view_service_contract(),
        zcl_native_shop_reputation_view_service_contract(),
        zcl_native_shop_status_view_service_contract(),
        zcl_native_shop_want_view_service_contract(),
        zcl_native_vault_intent_decision_service_contract(),
    };
    return zcl_hotswap_service_activate_so_any(
        so_path, resolved_datadir, activate, service_contracts,
        sizeof(service_contracts) / sizeof(service_contracts[0]), report);
}

bool zcl_native_hotswap_service_probe_local(
    const char *so_path, struct zcl_hotswap_service_report *report)
{
    return probe_service_any(so_path, "", false, report);
}

/* The resident node's own datadir, captured at RPC registration (boot) time.
 * rpc_dev_hotswap_native runs INSIDE the node process, where the one-shot
 * RPC-client global (node_rpc_client_datadir) is never initialized — using it
 * here made the dev-datadir self-check fail closed in exactly the process the
 * RPC exists for. Registration already refuses any non-dev datadir, so this
 * stash is always the exact dev datadir (or empty before boot). */
static char g_resident_datadir[512];

#endif /* ZCL_DEV_BUILD — publish hooks continue below in every build that can
        * publish a candidate into a command registry */

/* ── Command-registry publish hooks — the ONE implementation ───────────────
 *
 * These three callbacks are "how a candidate is validated and published": the
 * all-or-nothing batch commit, probe-before-publish, and the retired-snapshot
 * quiesce poll that gates dlclose. They contain NO dynamic loading (no
 * dlopen/dlsym/dlclose) — they only touch the command registry — so they are
 * not part of the release-purity dl* containment and may compile wherever a
 * registry exists.
 *
 * They are widened past ZCL_DEV_BUILD to ZCL_TESTING for one reason: the
 * parallel test harness can load a freshly compiled module .so through the
 * REAL loader (lib/hotswap/src/hotswap_activate.c) instead of relinking the
 * whole test binary. If the harness re-implemented these hooks, a test would
 * pass through a validation path production never runs — the exact divergence
 * this facility exists to avoid. A release build (neither macro) still links
 * none of it. See docs/DEVELOPING.md "Module mode". */
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

/* The probe executes on the activating RPC worker. Keep its rendered command
 * data in host-owned thread-local memory long enough to include it in the
 * activation receipt; modules never own or retain this state. */
static _Thread_local char *g_probe_rendered;

static void probe_rendered_clear(void)
{
    free(g_probe_rendered);
    g_probe_rendered = NULL;
}

void zcl_native_hotswap_probe_rendered_clear(void)
{
    probe_rendered_clear();
}

#ifdef ZCL_DEV_BUILD
static void probe_rendered_append(struct json_value *out)
{
    if (!out || !g_probe_rendered)
        return;
    size_t rendered_len = strlen(g_probe_rendered);
    struct sha256_ctx hash_ctx;
    unsigned char digest[SHA256_OUTPUT_SIZE];
    char digest_hex[SHA256_OUTPUT_SIZE * 2 + 1];
    sha256_init(&hash_ctx);
    sha256_write(&hash_ctx, (const unsigned char *)g_probe_rendered,
                 rendered_len);
    sha256_finalize(&hash_ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), digest_hex);
    (void)json_push_kv_int(out, "probe_data_bytes", (int64_t)rendered_len);
    (void)json_push_kv_str(out, "probe_data_sha256", digest_hex);

    struct json_value data;
    json_init(&data);
    if (json_read(&data, g_probe_rendered, rendered_len)) {
        if (rendered_len <= 1536) {
            (void)json_push_kv(out, "probe_data", &data);
        } else {
            /* The probed leaf's own response budget can be much larger than
             * the dev activation command's. Preserve a content binding plus
             * the useful scalar behavior fields instead of overflowing the
             * outer receipt after a successful resident commit. */
            static const char *const summary_fields[] = {
                "schema", "height", "provable_tip", "peers", "sync_gap",
                "count", "total", "kind_count", "available",
            };
            struct json_value summary;
            json_init(&summary);
            json_set_object(&summary);
            for (size_t i = 0;
                 i < sizeof(summary_fields) / sizeof(summary_fields[0]); i++) {
                const struct json_value *value =
                    json_get(&data, summary_fields[i]);
                if (value)
                    (void)json_push_kv(&summary, summary_fields[i], value);
            }
            (void)json_push_kv(out, "probe_data", &summary);
            (void)json_push_kv_bool(out, "probe_data_truncated", true);
            json_free(&summary);
        }
    }
    json_free(&data);
}
#endif /* ZCL_DEV_BUILD — probe_rendered_append feeds the dev activation
        * receipt only; the hooks below do not use it */

/* Publish a module's ENTIRE leaf set into the live command registry as ONE
 * all-or-nothing batch. zcl_command_registry_replace_batch pre-validates every
 * path (READY + EFFECT_READ + non-alias + resolvable) BEFORE it clones or
 * publishes anything, so a partial admit publishes ZERO leaves. */
static bool registry_commit_batch_cb(void *ctx,
                                     const struct zcl_hotswap_leaf *leaves,
                                     size_t leaf_count, uint32_t *out_gen,
                                     char *why, size_t why_sz)
{
    (void)ctx;
    if (!leaves || leaf_count == 0) {
        if (why && why_sz)
            snprintf(why, why_sz, "module published no leaves");
        return false;
    }
    if (leaf_count > ZCL_COMMAND_HANDLER_OVERRIDE_MAX) {
        if (why && why_sz)
            snprintf(why, why_sz,
                     "module carries %zu leaves, registry batch ceiling is %u",
                     leaf_count, (unsigned)ZCL_COMMAND_HANDLER_OVERRIDE_MAX);
        return false;
    }
    struct zcl_command_handler_override ovr[ZCL_COMMAND_HANDLER_OVERRIDE_MAX];
    for (size_t i = 0; i < leaf_count; i++) {
        ovr[i].path = leaves[i].name;
        ovr[i].handler = leaves[i].fn;
    }
    if (!zcl_command_registry_replace_batch(0, ovr, leaf_count, why, why_sz))
        return false;
    if (out_gen)
        *out_gen = zcl_command_registry_active_generation();
    return true;
}

/* PROBE BEFORE PUBLISH — the last gate, and the one that replaces module
 * self-certification.
 *
 * The candidate's declared probe leaf is dispatched against the PUBLIC command
 * registry's contract for that leaf: the registry-resolved spec (which must
 * still be a READY, read-only, non-alias leaf), the registry's own input
 * validation of the resident-owned bounded canonical request, and the registry
 * reply envelope. The reply is checked against the case's frozen schema and
 * tighter byte budget. Any mismatch returns false and publishes NOTHING.
 *
 * This runs the candidate body, which for a native bridge leaf issues one
 * loopback RPC. In the resident node that is a self-call served by a sibling
 * RPC worker (RPC_HTTP_WORKERS=4) under the client's receive timeout — it
 * cannot wedge the activation path. */
static bool registry_probe_cb(void *ctx, const char *leaf,
                              zcl_hotswap_handler_fn fn, char *why,
                              size_t why_sz)
{
    (void)ctx;
#define PROBE_FAIL(...)                                                      \
    do {                                                                     \
        if (why && why_sz) snprintf(why, why_sz, __VA_ARGS__);               \
        return false;                                                        \
    } while (0)

    if (!leaf || !leaf[0] || !fn)
        PROBE_FAIL("probe leaf or candidate handler missing");

    const struct zcl_hotswap_probe_case *probe =
        hotswap_probe_case_for_operation(leaf);
    if (!probe)
        PROBE_FAIL("probe leaf '%s' has no resident-owned case", leaf);
    if (!probe->canonical_input_json || !probe->expected_schema ||
        probe->byte_budget == 0 || probe->byte_budget > ZCL_COMMAND_LIST_BUDGET)
        PROBE_FAIL("probe case '%s' has an invalid resident contract",
                   probe->case_id ? probe->case_id : "(unnamed)");

    const struct zcl_command_registry *reg = zcl_command_catalog();
    bool was_alias = false;
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(reg, leaf, &was_alias);
    if (!spec)
        PROBE_FAIL("probe leaf '%s' does not resolve in the public registry",
                   leaf);
    if (was_alias)
        PROBE_FAIL("probe leaf '%s' resolves only through an alias", leaf);
    if (spec->availability != ZCL_COMMAND_READY)
        PROBE_FAIL("probe leaf '%s' is not READY", leaf);
    if (spec->effect != ZCL_COMMAND_EFFECT_READ)
        PROBE_FAIL("probe leaf '%s' is not read-only", leaf);
    if (!spec->output_schema || !spec->output_schema[0])
        PROBE_FAIL("probe leaf '%s' declares no output schema", leaf);
    if (strcmp(spec->output_schema, probe->expected_schema) != 0)
        PROBE_FAIL("probe case '%s' expected schema '%s' but registry declares '%s'",
                   probe->case_id, probe->expected_schema,
                   spec->output_schema);
    if (spec->budget_bytes > 0 &&
        probe->byte_budget > (size_t)spec->budget_bytes)
        PROBE_FAIL("probe case '%s' budget %zu exceeds registry budget %zu",
                   probe->case_id, probe->byte_budget,
                   (size_t)spec->budget_bytes);

    struct json_value input;
    json_init(&input);
    if (!json_read(&input, probe->canonical_input_json,
                   strlen(probe->canonical_input_json)) ||
        input.type != JSON_OBJ) {
        json_free(&input);
        PROBE_FAIL("probe case '%s' canonical input is not a JSON object",
                   probe->case_id);
    }
    char vwhy[192] = {0};
    if (!zcl_command_registry_input_validate(spec, &input, vwhy,
                                             sizeof(vwhy))) {
        json_free(&input);
        PROBE_FAIL("bounded probe case '%s' rejected for '%s': %s",
                   probe->case_id, leaf,
                   vwhy[0] ? vwhy : "input validation failed");
    }

    size_t budget = probe->byte_budget;
    struct zcl_command_context context = {
        .registry = reg,
        .authority_ceiling = spec->authority,
        .dev_build = true,
    };
    struct zcl_command_request request = {
        .spec = spec,
        .context = &context,
        .input = &input,
        .budget_bytes = budget,
        .invoked_name = spec->path,
    };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, probe->expected_schema);
    fn(&request, &reply);

    bool ok = true;
    char detail[192] = {0};
    if (reply.status != ZCL_COMMAND_STATUS_PASSED &&
        reply.status != ZCL_COMMAND_STATUS_ACCEPTED) {
        ok = false;
        snprintf(detail, sizeof(detail), "status=%s code=%s message=%s",
                 zcl_command_status_name(reply.status),
                 reply.error.code[0] ? reply.error.code : "(none)",
                 reply.error.message[0] ? reply.error.message : "(none)");
    } else if (!reply.data_schema ||
               strcmp(reply.data_schema, spec->output_schema) != 0) {
        ok = false;
        snprintf(detail, sizeof(detail),
                 "reply data_schema '%s' != declared output schema '%s'",
                 reply.data_schema ? reply.data_schema : "(null)",
                 spec->output_schema);
    } else if (reply.data.type != JSON_OBJ) {
        ok = false;
        snprintf(detail, sizeof(detail),
                 "reply data is not a JSON object (type %d)",
                 (int)reply.data.type);
    } else {
        char *rendered = (char *)zcl_malloc(budget + 1, "hotswap.probe.render");
        if (!rendered) {
            ok = false;
            snprintf(detail, sizeof(detail), "probe render buffer unavailable");
        } else {
            size_t n = json_write(&reply.data, rendered, budget + 1);
            if (n == 0 || n > budget) {
                ok = false;
                snprintf(detail, sizeof(detail),
                         "reply data does not render inside the declared "
                         "%zu-byte budget", budget);
            }
            if (ok) {
                probe_rendered_clear();
                g_probe_rendered = rendered;
                rendered = NULL;
            }
            free(rendered);
        }
    }

    zcl_command_reply_free(&reply);
    json_free(&input);
    if (!ok)
        PROBE_FAIL("%s", detail);
    return true;
#undef PROBE_FAIL
}

/* Gate the dlclose of a superseded module .so on override-snapshot drain. */
static bool registry_quiesced_cb(void *ctx)
{
    (void)ctx;
    return zcl_command_registry_all_retired_quiesced();
}

void zcl_native_hotswap_publish_hooks(struct hotswap_publish_hooks *out,
                                      bool with_quiesce)
{
    if (!out)
        return;
    out->commit = registry_commit_batch_cb;
    out->probe = registry_probe_cb;
    out->quiesced = with_quiesce ? registry_quiesced_cb : NULL;
    out->ctx = NULL;
}

#endif /* ZCL_DEV_BUILD || ZCL_TESTING — end of the shared publish hooks */

#ifdef ZCL_DEV_BUILD

/* Render a hotswap_activate_report into an already-init'd reply. */
static void report_to_reply(struct zcl_command_reply *reply,
                            const struct hotswap_activate_report *report)
{
    json_free(&reply->data);
    json_init(&reply->data);
    json_set_object(&reply->data);
    json_push_kv_str(&reply->data, "schema", "zcl.hotswap_activate.v2");
    json_push_kv_bool(&reply->data, "ok", report->ok);
    json_push_kv_bool(&reply->data, "verify_only", report->verify_only);
    json_push_kv_bool(&reply->data, "activated", report->activated);
    json_push_kv_bool(&reply->data, "rolled_back", report->rolled_back);
    json_push_kv_bool(&reply->data, "probed", report->probed);
    json_push_kv_int(&reply->data, "generation", (int64_t)report->generation);
    json_push_kv_int(&reply->data, "leaf_count", (int64_t)report->leaf_count);
    json_push_kv_str(&reply->data, "source_tu", report->source_tu);
    json_push_kv_str(&reply->data, "leaves", report->leaves);
    json_push_kv_str(&reply->data, "probe_leaf", report->probe_leaf);
    json_push_kv_str(&reply->data, "handler", report->handler_name);
    json_push_kv_str(&reply->data, "artifact_sha256", report->artifact_sha256);
    json_push_kv_str(&reply->data, "stage", report->stage);
    if (report->error[0])
        json_push_kv_str(&reply->data, "error", report->error);
    probe_rendered_append(&reply->data);

    if (report->ok) {
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = ZCL_COMMAND_EXIT_OK;
    } else {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "HOTSWAP_REFUSED", report->stage[0] ? report->stage : "activate",
            false, false,
            report->error[0] ? report->error : "hot-swap refused",
            report->handler_name);
    }
}

static void service_report_to_reply(
    struct zcl_command_reply *reply,
    const struct zcl_hotswap_service_report *report)
{
    json_free(&reply->data);
    json_init(&reply->data);
    json_set_object(&reply->data);
    json_push_kv_str(&reply->data, "schema",
                     "zcl.hotswap_service_activate.v1");
    json_push_kv_bool(&reply->data, "ok", report->ok);
    json_push_kv_bool(&reply->data, "verify_only", report->verify_only);
    json_push_kv_bool(&reply->data, "activated", report->activated);
    json_push_kv_bool(&reply->data, "rolled_back", report->rolled_back);
    json_push_kv_bool(&reply->data, "probed", report->probed);
    json_push_kv_bool(&reply->data, "dev_restart", report->dev_restart);
    json_push_kv_int(&reply->data, "generation",
                     (int64_t)report->generation);
    json_push_kv_str(&reply->data, "service_id", report->service_id);
    json_push_kv_str(&reply->data, "stage", report->stage);
    if (report->error[0])
        json_push_kv_str(&reply->data, "error", report->error);
    if (report->ok) {
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = ZCL_COMMAND_EXIT_OK;
    } else {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            report->dev_restart ? "DEV_RESTART" : "HOTSWAP_REFUSED",
            report->stage[0] ? report->stage : "activate", false, false,
            report->error[0] ? report->error : "service hot-swap refused",
            report->service_id);
    }
}

/* After a service candidate has passed the frozen host-owned KAT and been
 * published, observe it through the service's ordinary static status handler. The
 * candidate cannot choose this operation or its input, and the handler keeps
 * ownership of parsing/rendering.  This makes the resident activation receipt
 * a direct edit-to-visible proof rather than only a generation assertion. */
static void service_resident_observation_append(struct json_value *out,
                                                const char *service_id)
{
    const char *operation = zcl_hotswap_service_probe_for_id(service_id);
    const struct zcl_hotswap_probe_case *probe =
        hotswap_probe_case_for_operation(operation);
    if (!probe || strcmp(probe->kind, "service") != 0) {
        (void)json_push_kv_str(out, "resident_observation_error",
                              "service has no resident-owned probe case");
        return;
    }
    struct json_value input;
    json_init(&input);
    if (!json_read(&input, probe->canonical_input_json,
                   strlen(probe->canonical_input_json)) ||
        input.type != JSON_OBJ) {
        json_free(&input);
        (void)json_push_kv_str(out, "resident_observation_error",
                              "service probe input is not canonical JSON");
        return;
    }
    struct zcl_command_request request = { .input = &input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, probe->expected_schema);
    if (strcmp(operation, "zcode.commons.economics.status") == 0) {
        zcl_native_handle_zcode_commons_economics_status(&request, &reply);
    } else if (strcmp(operation, "zcode.commons.corpus.show") == 0) {
        zcl_native_handle_zcode_commons_corpus_show(&request, &reply);
    } else if (strcmp(operation, "app.market.purchase.guide") == 0) {
        zcl_native_handle_market_purchase_guide(&request, &reply);
    } else if (strcmp(operation, "app.market.moderation.guide") == 0) {
        zcl_native_handle_market_moderation_guide(&request, &reply);
    } else if (strcmp(operation, "zcode.package.guide") == 0) {
        zcl_native_handle_zcode_package_guide(&request, &reply);
    } else if (strcmp(operation, "zcode.moderation.status") == 0) {
        zcl_native_handle_zcode_moderation_status(&request, &reply);
    } else if (strcmp(operation, "zcode.passport.status") == 0) {
        zcl_native_handle_zcode_passport_status(&request, &reply);
    } else if (strcmp(operation, "zcode.work.context") == 0) {
        zcl_native_handle_zcode_work_context(&request, &reply);
    } else if (strcmp(operation, "zcode.package.dev.promotion-guide") == 0) {
        zcl_native_handle_zcode_lane_guide(&request, &reply);
    } else if (strcmp(operation, "zcode.workspace.status") == 0) {
        zcl_native_handle_zcode_workspace_status(&request, &reply);
    } else if (strcmp(operation, "app.shop.reputation") == 0) {
        zcl_native_handle_shop_reputation(&request, &reply);
    } else if (strcmp(operation, "app.shop.status") == 0) {
        zcl_native_handle_shop_status(&request, &reply);
    } else if (strcmp(operation, "app.shop.want.list") == 0) {
        zcl_native_handle_shop_want_list(&request, &reply);
    } else {
        zcl_command_reply_fail(&reply, ZCL_COMMAND_STATUS_BLOCKED,
            ZCL_COMMAND_EXIT_BLOCKED, "UNKNOWN_SERVICE_PROBE", "probe",
            false, false, "service probe operation is not statically bound",
            operation);
    }
    char *rendered = NULL;
    size_t rendered_len = 0;
    if (reply.exit_code == ZCL_COMMAND_EXIT_OK && reply.data_schema &&
        strcmp(reply.data_schema, probe->expected_schema) == 0) {
        rendered = zcl_malloc(probe->byte_budget + 1,
                              "hotswap.service.probe.render");
        if (rendered)
            rendered_len = json_write(&reply.data, rendered,
                                      probe->byte_budget + 1);
    }
    if (rendered_len > 0 && rendered_len <= probe->byte_budget) {
        (void)json_push_kv(out, "resident_observation", &reply.data);
        (void)json_push_kv_str(out, "probe_case", probe->case_id);
    } else {
        (void)json_push_kv_str(out, "resident_observation_error",
                              "static service status handler refused observation");
    }
    free(rendered);
    zcl_command_reply_free(&reply);
    json_free(&input);
}

/* Resident RPC: perform the swap IN this (running node) process.
 * Positional params: [so_path, (activate_bool)]. activate defaults false
 * (verify-only). A true activate is still gated by hotswap_activation_authorized
 * inside hotswap_activate — no flag/env or a canonical datadir => typed refusal. */
static bool rpc_dev_hotswap_native(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "dev_hotswap_native \"/absolute/module.so\" ( activate )");
        return true;
    }
    if (!hotswap_datadir_is_dev(g_resident_datadir)) {
        json_rpc_error_full(result, RPC_FORBIDDEN_BY_SAFE_MODE,
            "native hot-swap available only in the running ~/.zclassic-c23-dev node",
            "dev_hotswap_native");
        return false;
    }
    if (!params || params->type != JSON_ARR || json_size(params) < 1 ||
        json_size(params) > 2) {
        json_rpc_error_full(result, RPC_INVALID_PARAMS,
            "expected [so_path, (activate)]", "dev_hotswap_native");
        return false;
    }
    const struct json_value *path_v = json_at(params, 0);
    const struct json_value *act_v = json_size(params) > 1 ? json_at(params, 1) : NULL;
    if (!path_v || path_v->type != JSON_STR) {
        json_rpc_error_full(result, RPC_INVALID_PARAMS,
            "so_path must be a string", "dev_hotswap_native");
        return false;
    }
    const char *so_path = json_get_str(path_v);
    if (!so_path || so_path[0] != '/') {
        json_rpc_error_full(result, RPC_INVALID_PARAMETER,
            "so_path must be absolute", "dev_hotswap_native");
        return false;
    }
    bool activate = act_v && act_v->type == JSON_BOOL && json_get_bool(act_v);

    /* Service islands carry a distinct descriptor. Try that symbol first;
     * an ordinary command module is unrecognized and falls through to the
     * existing v2 command path. A recognized-but-invalid service NEVER falls
     * through: contract/KAT drift must route to DEV_RESTART, not be
     * reinterpreted under another ABI. */
    struct zcl_hotswap_service_report service_report;
    bool service_ok = probe_service_any(
        so_path, g_resident_datadir, activate, &service_report);
    if (service_report.recognized) {
        json_set_object(result);
        json_push_kv_str(result, "schema", "zcl.hotswap_service_activate.v1");
        json_push_kv_bool(result, "ok", service_report.ok);
        json_push_kv_bool(result, "verify_only", service_report.verify_only);
        json_push_kv_bool(result, "activated", service_report.activated);
        json_push_kv_bool(result, "rolled_back", service_report.rolled_back);
        json_push_kv_bool(result, "probed", service_report.probed);
        json_push_kv_bool(result, "dev_restart", service_report.dev_restart);
        json_push_kv_int(result, "generation",
                         (int64_t)service_report.generation);
        json_push_kv_str(result, "service_id", service_report.service_id);
        json_push_kv_str(result, "stage", service_report.stage);
        if (service_report.error[0])
            json_push_kv_str(result, "error", service_report.error);
        if (service_ok && service_report.activated)
            service_resident_observation_append(
                result, service_report.service_id);
        return service_ok;
    }

    struct hotswap_publish_hooks hooks;
    zcl_native_hotswap_publish_hooks(&hooks, /*with_quiesce=*/true);
    struct hotswap_activate_report report;
    probe_rendered_clear();
    hotswap_activate(so_path, g_resident_datadir, activate, &hooks, &report);

    /* Return the full report either way; the CLI renders ok/verify_only/error. */
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.hotswap_activate.v2");
    json_push_kv_bool(result, "ok", report.ok);
    json_push_kv_bool(result, "verify_only", report.verify_only);
    json_push_kv_bool(result, "activated", report.activated);
    json_push_kv_bool(result, "rolled_back", report.rolled_back);
    json_push_kv_bool(result, "probed", report.probed);
    json_push_kv_int(result, "generation", (int64_t)report.generation);
    json_push_kv_int(result, "leaf_count", (int64_t)report.leaf_count);
    json_push_kv_str(result, "source_tu", report.source_tu);
    json_push_kv_str(result, "leaves", report.leaves);
    json_push_kv_str(result, "probe_leaf", report.probe_leaf);
    json_push_kv_str(result, "handler", report.handler_name);
    json_push_kv_str(result, "artifact_sha256", report.artifact_sha256);
    json_push_kv_str(result, "stage", report.stage);
    if (report.error[0])
        json_push_kv_str(result, "error", report.error);
    probe_rendered_append(result);
    probe_rendered_clear();
    return report.ok;
}

/* CLI `dev hotswap apply`: forward to the resident node's dev_hotswap_native so
 * the RUNNING node performs the gated swap. A separate CLI process cannot
 * re-point the resident registry itself. */
void zcl_native_handle_dev_hotswap_apply(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    /* Non-bridge handler: initialize the one-shot RPC client from the
     * CLI-resolved -datadir/-rpcport before node_rpc_call(). */
    zcl_native_bridge_ensure_rpc();
    const char *so_path = json_get_str(json_get(request->input, "so_path"));
    if (!so_path || so_path[0] != '/') {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_INVALID, "HOTSWAP_BAD_INPUT", "validate", false,
            false, "so_path (absolute) is required", "dev.hotswap.apply");
        return;
    }
    /* Build [so_path, true] safely via the JSON writer. */
    struct json_value arr, s, b;
    json_init(&arr);
    json_set_array(&arr);
    json_init(&s);
    json_set_str(&s, so_path);
    json_push_back(&arr, &s);
    json_free(&s);
    json_init(&b);
    json_set_bool(&b, true);
    json_push_back(&arr, &b);
    json_free(&b);
    char params[1024];
    size_t n = json_write(&arr, params, sizeof(params));
    json_free(&arr);
    if (n == 0 || n >= sizeof(params)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_INVALID, "HOTSWAP_BAD_INPUT", "serialize", false,
            false, "so_path too long", "dev.hotswap.apply");
        return;
    }

    char *resp = node_rpc_call("dev_hotswap_native", params);
    if (!resp) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_TRANSIENT, "HOTSWAP_NO_RESIDENT", "dispatch",
            true, false, "resident node did not respond", "dev.hotswap.apply");
        return;
    }
    struct json_value doc;
    json_init(&doc);
    bool parsed = json_read(&doc, resp, strlen(resp)) && doc.type == JSON_OBJ;
    if (parsed) {
        json_free(&reply->data);
        json_init(&reply->data);
        json_copy(&reply->data, &doc);
        bool ok = json_get_bool(json_get(&doc, "ok"));
        if (ok) {
            reply->status = ZCL_COMMAND_STATUS_PASSED;
            reply->exit_code = ZCL_COMMAND_EXIT_OK;
        } else {
            const char *err = json_get_str(json_get(&doc, "error"));
            const char *stage = json_get_str(json_get(&doc, "stage"));
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                ZCL_COMMAND_EXIT_BLOCKED, "HOTSWAP_REFUSED",
                stage && stage[0] ? stage : "activate", false, false,
                err && err[0] ? err : "resident refused the swap",
                "dev.hotswap.apply");
        }
    } else {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_INTERNAL, "HOTSWAP_BAD_RESPONSE", "serialize",
            false, false, "resident returned a non-object response",
            "dev.hotswap.apply");
    }
    json_free(&doc);
    free(resp);
}

/* CLI `dev hotswap probe`: VERIFY-ONLY in this throwaway CLI process. dlopen +
 * ABI + self_test, never commits — the safest way to prove a swap would work. */
void zcl_native_handle_dev_hotswap_probe(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    /* Non-bridge handler: initialize the one-shot RPC client so
     * node_rpc_client_datadir() below returns the CLI-resolved dev datadir. */
    zcl_native_bridge_ensure_rpc();
    const char *so_path = json_get_str(json_get(request->input, "so_path"));
    if (!so_path || so_path[0] != '/') {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_INVALID, "HOTSWAP_BAD_INPUT", "validate", false,
            false, "so_path (absolute) is required", "dev.hotswap.probe");
        return;
    }
    struct zcl_hotswap_service_report service_report;
    (void)probe_service_any(
        so_path, node_rpc_client_datadir(), false, &service_report);
    if (service_report.recognized) {
        service_report_to_reply(reply, &service_report);
        return;
    }
    struct hotswap_publish_hooks hooks;
    zcl_native_hotswap_publish_hooks(&hooks, /*with_quiesce=*/false);
    struct hotswap_activate_report report;
    probe_rendered_clear();
    hotswap_activate(so_path, node_rpc_client_datadir(),
                     /*request_activate=*/false, &hooks, &report);
    report_to_reply(reply, &report);
    probe_rendered_clear();
}

bool register_dev_native_hotswap_rpc(struct rpc_table *table,
                                     const char *datadir, int rpc_port)
{
    static const struct rpc_command cmd = {
        "dev", "dev_hotswap_native", rpc_dev_hotswap_native, true,
    };
    /* Only the exact dev lane gets the resident hot-swap RPC; every other lane
     * is a successful no-op. */
    if (!table || rpc_port <= 0 || rpc_port > 65535 ||
        !hotswap_datadir_is_dev(datadir))
        return true;
    (void)snprintf(g_resident_datadir, sizeof(g_resident_datadir), "%s",
                   datadir);
    /* Candidate bridge handlers execute inside this resident process and use
     * the ordinary native controller seam. Bind both the RPC client and the
     * bridge's lazy-init guard: initializing only node_rpc_client here let the
     * first handler overwrite it with the empty one-shot CLI defaults. */
    zcl_native_bridge_bind_rpc(datadir, rpc_port);
    /* The override commit (zcl_command_registry_replace_batch) requires an
     * active registry in THIS process. The node never dispatches native
     * leaves, so bind the catalog here: replace_batch validates the override
     * against it (READY + EFFECT_READ + canonical) and the slot/quiesce
     * bookkeeping becomes inspectable via dumpstate hotswap. */
    zcl_command_registry_set_active(zcl_command_catalog());
    rpc_table_must_append(table, &cmd);
    return true;
}

#else /* !ZCL_DEV_BUILD — release: no resident hot-swap RPC surface */

bool zcl_native_hotswap_service_probe_local(
    const char *so_path, struct zcl_hotswap_service_report *report)
{
    (void)so_path;
    if (report)
        memset(report, 0, sizeof(*report));
    return false;
}

bool register_dev_native_hotswap_rpc(struct rpc_table *table,
                                     const char *datadir, int rpc_port)
{
    (void)table;
    (void)datadir;
    (void)rpc_port;
    return true;
}

#endif /* ZCL_DEV_BUILD */
