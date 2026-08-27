/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: born-red contract for pure service-island publication. */

#include "test/test_helpers.h"

#include "base/hex.h"
#include "hotswap/hotswap_service.h"
#include "command/native_command.h"
#include "json/json.h"
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
#include "vcs/build_action.h"
#include "vcs/zcode_lane.h"

#include <stdatomic.h>
#include <string.h>

struct arithmetic_vtable {
    uint64_t (*sum)(uint64_t, uint64_t);
};

static uint64_t sum_builtin(uint64_t a, uint64_t b) { return a + b; }
static uint64_t sum_candidate(uint64_t a, uint64_t b) { return a + b + 7u; }

static const struct arithmetic_vtable k_builtin = {sum_builtin};
static const struct arithmetic_vtable k_candidate = {sum_candidate};

static bool frozen_kat(const void *vtable, char *why, size_t why_sz)
{
    const struct arithmetic_vtable *v = vtable;
    if (!v || !v->sum || v->sum(20, 22) != 49) {
        if (why && why_sz) snprintf(why, why_sz, "frozen vector 20+22 failed");
        return false;
    }
    return true;
}

static const struct zcl_hotswap_service_contract k_contract = {
    .service_id = "test.arithmetic.v1",
    .source_tu = "app/services/src/test_arithmetic.c",
    .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
    .vtable_size = sizeof(struct arithmetic_vtable),
    .abi_fingerprint = "abi-1",
    .schema_fingerprint = "schema-1",
    .wire_fingerprint = "wire-1",
    .kat_fingerprint = "kat-1",
    .frozen_kat = frozen_kat,
};

static struct zcl_hotswap_service_candidate candidate(void)
{
    return (struct zcl_hotswap_service_candidate) {
        .service_id = "test.arithmetic.v1",
        .source_tu = "app/services/src/test_arithmetic.c",
        .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
        .vtable_size = sizeof(struct arithmetic_vtable),
        .abi_fingerprint = "abi-1",
        .schema_fingerprint = "schema-1",
        .wire_fingerprint = "wire-1",
        .kat_fingerprint = "kat-1",
        .vtable = &k_candidate,
    };
}

static int t_publish_and_lease(void)
{
    int failures = 0;
    TEST("service publication is atomic, versioned, and reader-quiescent") {
        zcl_hotswap_service_reset();
        struct zcl_hotswap_service_candidate c = candidate();
        struct zcl_hotswap_service_report report = {0};
        ASSERT(zcl_hotswap_service_publish(&k_contract, &c, true, &report));
        ASSERT(report.activated);
        ASSERT(report.probed);
        ASSERT_EQ(report.generation, 1u);

        struct zcl_hotswap_service_lease lease = {0};
        const struct arithmetic_vtable *active =
            zcl_hotswap_service_acquire("test.arithmetic.v1", &lease);
        ASSERT(active != NULL);
        ASSERT_EQ(active->sum(1, 2), 10u);
        ASSERT(zcl_hotswap_service_publish(&k_contract, &c, true, &report));
        ASSERT_EQ(report.generation, 2u);
        ASSERT(!zcl_hotswap_service_all_retired_quiesced());

        c.vtable = &k_builtin;
        ASSERT(!zcl_hotswap_service_publish(&k_contract, &c, true, &report));
        ASSERT_EQ(strcmp(report.stage, "kat"), 0);
        ASSERT_EQ(zcl_hotswap_service_generation(), 2u);
        zcl_hotswap_service_release(&lease);
        ASSERT(zcl_hotswap_service_all_retired_quiesced());
        PASS();
    } _test_next:;
    return failures;
}

static int t_contract_drift_restarts(void)
{
    int failures = 0;
    TEST("ABI, schema, wire, or KAT drift routes to DEV_RESTART") {
        const char *fields[] = {"abi", "schema", "wire", "kat"};
        for (size_t i = 0; i < 4; i++) {
            struct zcl_hotswap_service_candidate c = candidate();
            if (i == 0) c.abi_fingerprint = "changed";
            if (i == 1) c.schema_fingerprint = "changed";
            if (i == 2) c.wire_fingerprint = "changed";
            if (i == 3) c.kat_fingerprint = "changed";
            struct zcl_hotswap_service_report report = {0};
            ASSERT(!zcl_hotswap_service_publish(&k_contract, &c, true,
                                                &report));
            ASSERT(report.dev_restart);
            ASSERT_EQ(strcmp(report.stage, fields[i]), 0);
            ASSERT(!report.activated);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int t_manifest_mapping(void)
{
    int failures = 0;
    TEST("service source and private header map to one resident-owned probe") {
        ASSERT_STR_EQ(zcl_hotswap_service_source_for_path(
                          "app/services/src/zcode_c23_corpus_service.c"),
                      "app/services/src/zcode_c23_corpus_service.c");
        ASSERT(zcl_hotswap_service_source_for_path(
                   "app/services/include/services/zcode_c23_corpus_service.h")
               == NULL);
        ASSERT_STR_EQ(zcl_hotswap_service_contract_source_for_path(
                          "app/services/include/services/zcode_c23_corpus_service.h"),
                      "app/services/src/zcode_c23_corpus_service.c");
        ASSERT(zcl_hotswap_service_contract_source_for_path(
                   "app/services/src/zcode_c23_corpus_service.c") == NULL);
        ASSERT_STR_EQ(zcl_hotswap_service_probe_for_source(
                          "app/services/src/zcode_c23_corpus_service.c"),
                      "zcode.commons.corpus.show");
        ASSERT_STR_EQ(zcl_hotswap_service_source_for_path(
                          "app/services/src/zcode_c23_economics_service.c"),
                      "app/services/src/zcode_c23_economics_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_contract_source_for_path(
                          "app/services/include/services/zcode_c23_economics_service.h"),
                      "app/services/src/zcode_c23_economics_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_source_for_path(
                          "app/services/src/zcode_c23_economics_internal.h"),
                      "app/services/src/zcode_c23_economics_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_probe_for_source(
                          "app/services/src/zcode_c23_economics_service.c"),
                      "zcode.commons.economics.status");
        ASSERT_STR_EQ(zcl_hotswap_service_source_for_path(
                          "app/services/src/market_purchase_view_service.c"),
                      "app/services/src/market_purchase_view_service.c");
        ASSERT(zcl_hotswap_service_source_for_path(
                   "app/services/include/services/market_purchase_view_service.h")
               == NULL);
        ASSERT_STR_EQ(zcl_hotswap_service_contract_source_for_path(
                          "app/services/include/services/market_purchase_view_service.h"),
                      "app/services/src/market_purchase_view_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_probe_for_source(
                          "app/services/src/market_purchase_view_service.c"),
                      "app.market.purchase.guide");
        ASSERT_STR_EQ(zcl_hotswap_service_source_for_path(
                          "app/services/src/market_moderation_view_service.c"),
                      "app/services/src/market_moderation_view_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_source_for_path(
                          "app/services/src/market_moderation_view_internal.h"),
                      "app/services/src/market_moderation_view_service.c");
        ASSERT(zcl_hotswap_service_source_for_path(
                   "app/services/include/services/market_moderation_view_service.h")
               == NULL);
        ASSERT_STR_EQ(zcl_hotswap_service_contract_source_for_path(
                          "app/services/include/services/market_moderation_view_service.h"),
                      "app/services/src/market_moderation_view_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_probe_for_source(
                          "app/services/src/market_moderation_view_service.c"),
                      "app.market.moderation.guide");
        ASSERT_STR_EQ(zcl_hotswap_service_source_for_path(
                          "app/services/src/zcode_package_view_service.c"),
                      "app/services/src/zcode_package_view_service.c");
        ASSERT(zcl_hotswap_service_source_for_path(
                   "app/services/include/services/zcode_package_view_service.h")
               == NULL);
        ASSERT_STR_EQ(zcl_hotswap_service_contract_source_for_path(
                          "app/services/include/services/zcode_package_view_service.h"),
                      "app/services/src/zcode_package_view_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_probe_for_source(
                          "app/services/src/zcode_package_view_service.c"),
                      "zcode.package.guide");
        ASSERT_STR_EQ(zcl_hotswap_service_source_for_path(
                          "app/services/src/zcode_moderation_view_service.c"),
                      "app/services/src/zcode_moderation_view_service.c");
        ASSERT(zcl_hotswap_service_source_for_path(
                   "app/services/include/services/zcode_moderation_view_service.h")
               == NULL);
        ASSERT_STR_EQ(zcl_hotswap_service_contract_source_for_path(
                          "app/services/include/services/zcode_moderation_view_service.h"),
                      "app/services/src/zcode_moderation_view_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_probe_for_source(
                          "app/services/src/zcode_moderation_view_service.c"),
                      "zcode.moderation.status");
        ASSERT_STR_EQ(zcl_hotswap_service_source_for_path(
                          "app/services/src/zcode_workspace_view_service.c"),
                      "app/services/src/zcode_workspace_view_service.c");
        ASSERT(zcl_hotswap_service_source_for_path(
                   "app/services/include/services/zcode_workspace_view_service.h")
               == NULL);
        ASSERT_STR_EQ(zcl_hotswap_service_contract_source_for_path(
                          "app/services/include/services/zcode_workspace_view_service.h"),
                      "app/services/src/zcode_workspace_view_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_probe_for_source(
                          "app/services/src/zcode_workspace_view_service.c"),
                      "zcode.workspace.status");
        ASSERT_STR_EQ(zcl_hotswap_service_source_for_path(
                          "app/services/src/zcode_passport_view_service.c"),
                      "app/services/src/zcode_passport_view_service.c");
        ASSERT(zcl_hotswap_service_source_for_path(
                   "app/services/include/services/zcode_passport_view_service.h")
               == NULL);
        ASSERT_STR_EQ(zcl_hotswap_service_contract_source_for_path(
                          "app/services/include/services/zcode_passport_view_service.h"),
                      "app/services/src/zcode_passport_view_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_probe_for_source(
                          "app/services/src/zcode_passport_view_service.c"),
                      "zcode.passport.status");
        ASSERT_STR_EQ(zcl_hotswap_service_source_for_path(
                          "app/services/src/zcode_goal_context_calc_service.c"),
                      "app/services/src/zcode_goal_context_calc_service.c");
        ASSERT(zcl_hotswap_service_source_for_path(
                   "app/services/include/services/zcode_goal_context_calc_service.h")
               == NULL);
        ASSERT_STR_EQ(zcl_hotswap_service_contract_source_for_path(
                          "app/services/include/services/zcode_goal_context_calc_service.h"),
                      "app/services/src/zcode_goal_context_calc_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_probe_for_source(
                          "app/services/src/zcode_goal_context_calc_service.c"),
                      "zcode.work.context");
        ASSERT_STR_EQ(zcl_hotswap_service_source_for_path(
                          "app/services/src/zcode_lane_view_service.c"),
                      "app/services/src/zcode_lane_view_service.c");
        ASSERT(zcl_hotswap_service_source_for_path(
                   "app/services/include/services/zcode_lane_view_service.h")
               == NULL);
        ASSERT_STR_EQ(zcl_hotswap_service_contract_source_for_path(
                          "app/services/include/services/zcode_lane_view_service.h"),
                      "app/services/src/zcode_lane_view_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_probe_for_source(
                          "app/services/src/zcode_lane_view_service.c"),
                      "zcode.package.dev.promotion-guide");
        ASSERT_STR_EQ(zcl_hotswap_service_source_for_path(
                          "app/services/src/shop_reputation_view_service.c"),
                      "app/services/src/shop_reputation_view_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_contract_source_for_path(
                          "app/services/include/services/shop_reputation_view_service.h"),
                      "app/services/src/shop_reputation_view_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_probe_for_source(
                          "app/services/src/shop_reputation_view_service.c"),
                      "app.shop.reputation");
        ASSERT_STR_EQ(zcl_hotswap_service_source_for_path(
                          "app/services/src/shop_status_view_service.c"),
                      "app/services/src/shop_status_view_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_probe_for_source(
                          "app/services/src/shop_status_view_service.c"),
                      "app.shop.status");
        ASSERT_STR_EQ(zcl_hotswap_service_source_for_path(
                          "app/services/src/shop_want_view_service.c"),
                      "app/services/src/shop_want_view_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_source_for_path(
                          "app/services/src/shop_want_view_internal.h"),
                      "app/services/src/shop_want_view_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_contract_source_for_path(
                          "app/services/include/services/shop_want_view_service.h"),
                      "app/services/src/shop_want_view_service.c");
        ASSERT_STR_EQ(zcl_hotswap_service_probe_for_source(
                          "app/services/src/shop_want_view_service.c"),
                      "app.shop.want.list");
        ASSERT_STR_EQ(zcl_hotswap_shadow_service_for_owner(
                          "tools/command/native_dev_command.c"),
                      "app/services/src/dev_reflex_policy_service.c");
        ASSERT(zcl_hotswap_shadow_path_is_static_owner(
                   "tools/command/native_dev_command.c"));
        ASSERT(!zcl_hotswap_shadow_path_is_static_owner(
                   "app/services/src/dev_reflex_policy_service.c"));
        ASSERT_STR_EQ(zcl_hotswap_shadow_service_for_owner(
                          "lib/vcs/src/zcode_workspace_manifest.c"),
                      "app/services/src/zcode_workspace_view_service.c");
        ASSERT(strstr(zcl_hotswap_shadow_members_for_service(
                          "app/services/src/zcode_workspace_view_service.c"),
                      "lib/vcs/src/zcode_workspace_manifest.c") != NULL);
        ASSERT(zcl_hotswap_service_source_for_path(
                   "lib/storage/src/storage.c") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static bool candidate_market_guide(
    struct market_purchase_guide_result_v1 *out)
{
    if (!market_purchase_view_service_builtin()->render_guide(out))
        return false;
    snprintf(out->next_command, sizeof(out->next_command), "%s",
             "candidate marketplace service generation is active");
    return true;
}

static int t_market_purchase_view(void)
{
    int failures = 0;
    TEST("marketplace calculations publish while payment authority stays static") {
        zcl_hotswap_service_reset();
        const struct market_purchase_view_service_v1 *builtin =
            market_purchase_view_service_builtin();
        struct market_purchase_error_result_v1 classified;
        char commit[192];
        ASSERT(builtin->classify_error("COMMIT_BUSY", &classified));
        ASSERT(classified.known);
        ASSERT_EQ(classified.error_class, MARKET_PURCHASE_ERROR_TRANSIENT);
        ASSERT(builtin->render_commit_input(
            "prod",
            "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
            commit, sizeof(commit)));
        ASSERT(strstr(commit, "\"wallet_scope\":\"prod\"") != NULL);
        ASSERT(strstr(commit,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
            != NULL);

        struct market_purchase_view_service_v1 candidate_service = *builtin;
        candidate_service.render_guide = candidate_market_guide;
        struct zcl_hotswap_service_candidate service_candidate = {
            .service_id = MARKET_PURCHASE_VIEW_SERVICE_ID,
            .source_tu = "app/services/src/market_purchase_view_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(candidate_service),
            .abi_fingerprint = MARKET_PURCHASE_VIEW_ABI_FINGERPRINT,
            .schema_fingerprint = MARKET_PURCHASE_VIEW_SCHEMA_FINGERPRINT,
            .wire_fingerprint = MARKET_PURCHASE_VIEW_WIRE_FINGERPRINT,
            .kat_fingerprint = MARKET_PURCHASE_VIEW_KAT_FINGERPRINT,
            .vtable = &candidate_service,
        };
        struct zcl_hotswap_service_report report = {0};
        ASSERT(zcl_hotswap_service_publish(
            zcl_native_market_purchase_view_service_contract(),
            &service_candidate, true, &report));
        ASSERT(report.probed);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.app_market_purchase_guide.v1");
        zcl_native_handle_market_purchase_guide(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "service_generation")),
                  1);
        ASSERT(!json_get_bool(json_get(&reply.data, "effects_swappable")));
        ASSERT(json_get_bool(json_get(&reply.data,
                                      "payment_authority_static")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "next_command")),
                      "candidate marketplace service generation is active");
        zcl_command_reply_free(&reply);
        json_free(&input);
        zcl_hotswap_service_reset();
        PASS();
    } _test_next:;
    return failures;
}

static bool candidate_moderation_guide(
    struct market_moderation_guide_result_v1 *out)
{
    if (!market_moderation_view_service_builtin()->render_guide(out))
        return false;
    snprintf(out->next_command, sizeof(out->next_command), "%s",
             "candidate moderation service generation is active");
    return true;
}

static int t_market_moderation_view(void)
{
    int failures = 0;
    TEST("market moderation visibility swaps while policy authority stays static") {
        zcl_hotswap_service_reset();
        const struct market_moderation_view_service_v1 *builtin =
            market_moderation_view_service_builtin();
        struct market_moderation_decision_result_v1 decision;
        ASSERT(builtin->decide(MARKET_MODERATION_PROFILE_DEFAULT,
                               MARKET_REVIEW_REVIEWED_OK, &decision));
        ASSERT(decision.valid);
        ASSERT(decision.visible);
        ASSERT(decision.local_view_only);
        ASSERT(decision.wire_unchanged);
        ASSERT(builtin->decide(MARKET_MODERATION_PROFILE_DEFAULT,
                               MARKET_REVIEW_SENSITIVE, &decision));
        ASSERT(decision.valid);
        ASSERT(!decision.visible);

        struct market_moderation_view_service_v1 candidate_service = *builtin;
        candidate_service.render_guide = candidate_moderation_guide;
        struct zcl_hotswap_service_candidate service_candidate = {
            .service_id = MARKET_MODERATION_VIEW_SERVICE_ID,
            .source_tu =
                "app/services/src/market_moderation_view_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(candidate_service),
            .abi_fingerprint = MARKET_MODERATION_VIEW_ABI_FINGERPRINT,
            .schema_fingerprint = MARKET_MODERATION_VIEW_SCHEMA_FINGERPRINT,
            .wire_fingerprint = MARKET_MODERATION_VIEW_WIRE_FINGERPRINT,
            .kat_fingerprint = MARKET_MODERATION_VIEW_KAT_FINGERPRINT,
            .vtable = &candidate_service,
        };
        struct zcl_hotswap_service_report report = {0};
        ASSERT(zcl_hotswap_service_publish(
            zcl_native_market_moderation_view_service_contract(),
            &service_candidate, true, &report));
        ASSERT(report.probed);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply,
                               "zcl.app_market_moderation_guide.v1");
        zcl_native_handle_market_moderation_guide(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "service_generation")),
                  1);
        ASSERT(json_get_bool(json_get(&reply.data, "policy_authority_static")));
        ASSERT(json_get_bool(json_get(&reply.data, "wire_unchanged")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "next_command")),
                      "candidate moderation service generation is active");
        zcl_command_reply_free(&reply);
        json_free(&input);
        zcl_hotswap_service_reset();
        PASS();
    } _test_next:;
    return failures;
}

static bool candidate_package_guide(
    struct zcode_package_guide_result_v1 *out)
{
    if (!zcode_package_view_service_builtin()->render_guide(out))
        return false;
    snprintf(out->next_command, sizeof(out->next_command), "%s",
             "candidate package service generation is active");
    return true;
}

static int t_zcode_package_view(void)
{
    int failures = 0;
    TEST("package presentation swaps while package authority stays static") {
        zcl_hotswap_service_reset();
        const struct zcode_package_view_service_v1 *builtin =
            zcode_package_view_service_builtin();
        struct vcs_package_index_entry entry = {0};
        snprintf(entry.release_id_hex, sizeof(entry.release_id_hex), "%064x",
                 1);
        snprintf(entry.package_root_hex, sizeof(entry.package_root_hex),
                 "%064x", 2);
        snprintf(entry.name, sizeof(entry.name), "%s", "alice/ring");
        struct zcode_package_view_entry_v1 rendered;
        ASSERT(builtin->render_entry(&entry, &rendered));
        ASSERT(rendered.valid);
        ASSERT_STR_EQ(rendered.name, "alice/ring");

        struct zcode_package_view_service_v1 candidate_service = *builtin;
        candidate_service.render_guide = candidate_package_guide;
        struct zcl_hotswap_service_candidate service_candidate = {
            .service_id = ZCODE_PACKAGE_VIEW_SERVICE_ID,
            .source_tu = "app/services/src/zcode_package_view_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(candidate_service),
            .abi_fingerprint = ZCODE_PACKAGE_VIEW_ABI_FINGERPRINT,
            .schema_fingerprint = ZCODE_PACKAGE_VIEW_SCHEMA_FINGERPRINT,
            .wire_fingerprint = ZCODE_PACKAGE_VIEW_WIRE_FINGERPRINT,
            .kat_fingerprint = ZCODE_PACKAGE_VIEW_KAT_FINGERPRINT,
            .vtable = &candidate_service,
        };
        struct zcl_hotswap_service_report report = {0};
        ASSERT(zcl_hotswap_service_publish(
            zcl_native_zcode_package_view_service_contract(),
            &service_candidate, true, &report));
        ASSERT(report.probed);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_package_guide.v1");
        zcl_native_handle_zcode_package_guide(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "service_generation")),
                  1);
        ASSERT(json_get_bool(json_get(&reply.data, "cas_authority_static")));
        ASSERT(json_get_bool(json_get(&reply.data, "index_reads_static")));
        ASSERT(json_get_bool(json_get(&reply.data, "publication_static")));
        ASSERT(json_get_bool(json_get(&reply.data, "execution_static")));
        ASSERT(!json_get_bool(json_get(&reply.data, "fetch_executes")));
        ASSERT(!json_get_bool(json_get(&reply.data, "remote_name_search")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "preflight")),
                      "zcode network status");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data,
                                            "hosting_requirement")),
                      "run the full node with -packagehost=1 -buildworker=1");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "join_flags")),
                      "-packagehost=1 -buildworker=1");
        ASSERT(!json_get_bool(json_get(&reply.data, "joined")));
        ASSERT(!json_get_bool(json_get(&reply.data, "package_hosting")));
        ASSERT(!json_get_bool(json_get(&reply.data, "build_worker")));
        ASSERT(json_get_bool(json_get(&reply.data,
                                      "source_identity_portable")));
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "other_build_targets_proven")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data,
                                            "current_build_target")),
                      VCS_BUILD_TARGET_V1);
        const struct json_value *author = json_get(&reply.data, "author");
        const struct json_value *consumer = json_get(&reply.data, "consumer");
        const struct json_value *reproducer = json_get(&reply.data,
                                                       "reproducer");
        ASSERT(author && author->type == JSON_ARR && author->num_children == 6);
        ASSERT(consumer && consumer->type == JSON_ARR &&
               consumer->num_children == 4);
        ASSERT(reproducer && reproducer->type == JSON_ARR &&
               reproducer->num_children == 3);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(author, 1), "status")),
                      "unsigned");
        /* The pointer gate is a named author journey step: publication of a
         * package pointer follows local admission plus the distinct rebuild
         * receipt, never bare CAS admission. */
        ASSERT_STR_EQ(json_get_str(json_get(json_at(author, 4), "status")),
                      "locally-reproduced");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(consumer, 1), "status")),
                      "inert-fetch-or-resume");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(consumer, 0),
                                            "command")),
                      "zcode network records");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(reproducer, 2),
                                            "subject")),
                      "an exact async action_id, not a package name");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "next_command")),
                      "candidate package service generation is active");
        zcl_command_reply_free(&reply);
        json_free(&input);
        zcl_hotswap_service_reset();
        PASS();
    } _test_next:;
    return failures;
}

static bool candidate_moderation_policy(
    const struct vcs_zcode_family_policy_v1 *policy,
    const char *policy_root_hex,
    struct zcode_moderation_policy_view_v1 *out)
{
    if (!zcode_moderation_view_service_builtin()->render_policy(
            policy, policy_root_hex, out))
        return false;
    snprintf(out->policy_summary, sizeof(out->policy_summary), "%s",
             "candidate moderation view generation is active");
    return true;
}

static bool candidate_moderation_service_status(
    const struct zcode_moderation_service_status_input_v1 *input,
    struct zcode_moderation_service_status_result_v1 *out)
{
    if (!zcode_moderation_view_service_builtin()->render_service_status(
            input, out))
        return false;
    snprintf(out->blocker, sizeof(out->blocker), "%s",
             "candidate moderation readiness generation is active");
    return true;
}

static bool candidate_moderation_admission_status(
    const struct zcode_moderation_admission_status_input_v1 *input,
    struct zcode_moderation_admission_status_result_v1 *out)
{
    if (!zcode_moderation_view_service_builtin()->render_admission_status(
            input, out))
        return false;
    if (!out->effective_default)
        snprintf(out->activation_blocker, sizeof(out->activation_blocker),
                 "%s", "candidate admission-readiness generation is active");
    return true;
}

static int t_zcode_moderation_view(void)
{
    int failures = 0;
    TEST("Family policy presentation swaps while enforcement stays static") {
        zcl_hotswap_service_reset();
        const struct zcode_moderation_view_service_v1 *builtin =
            zcode_moderation_view_service_builtin();
        struct vcs_zcode_family_policy_v1 policy;
        struct zcode_moderation_policy_view_v1 view;
        uint8_t root[32];
        char root_hex[65];
        vcs_zcode_family_policy_v1_default(&policy);
        ASSERT_EQ(vcs_zcode_family_policy_v1_root(&policy, root),
                  VCS_ZCODE_COMMONS_V2_OK);
        zcl_hex_encode(root, sizeof(root), root_hex);
        ASSERT(builtin->render_policy(&policy, root_hex, &view));
        ASSERT(view.valid);
        ASSERT_STR_EQ(view.policy_root, root_hex);
        struct zcode_moderation_service_status_input_v1 status_input = {0};
        struct zcode_moderation_service_status_result_v1 status_view;
        ASSERT(builtin->render_service_status(&status_input, &status_view));
        ASSERT_STR_EQ(status_view.bootstrap_label,
                      "unavailable:no_signed_service_roster");

        struct zcode_moderation_view_service_v1 candidate_service = *builtin;
        candidate_service.render_policy = candidate_moderation_policy;
        candidate_service.render_service_status =
            candidate_moderation_service_status;
        candidate_service.render_admission_status =
            candidate_moderation_admission_status;
        struct zcl_hotswap_service_candidate service_candidate = {
            .service_id = ZCODE_MODERATION_VIEW_SERVICE_ID,
            .source_tu = "app/services/src/zcode_moderation_view_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(candidate_service),
            .abi_fingerprint = ZCODE_MODERATION_VIEW_ABI_FINGERPRINT,
            .schema_fingerprint = ZCODE_MODERATION_VIEW_SCHEMA_FINGERPRINT,
            .wire_fingerprint = ZCODE_MODERATION_VIEW_WIRE_FINGERPRINT,
            .kat_fingerprint = ZCODE_MODERATION_VIEW_KAT_FINGERPRINT,
            .vtable = &candidate_service,
        };
        struct zcl_hotswap_service_report report = {0};
        ASSERT(zcl_hotswap_service_publish(
            zcl_native_zcode_moderation_view_service_contract(),
            &service_candidate, true, &report));
        ASSERT(report.probed);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_moderation_status.v1");
        zcl_native_handle_zcode_moderation_status(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&reply.data,
                                       "view_service_generation")), 1);
        ASSERT(!json_get_bool(json_get(&reply.data,
                                      "enforcement_complete")));
        ASSERT(!json_get_bool(json_get(&reply.data, "effective_default")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "policy_summary")),
                      "candidate moderation view generation is active");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data,
                                            "activation_blocker")),
                      "candidate admission-readiness generation is active");
        zcl_command_reply_free(&reply);

        zcl_command_reply_init(&reply,
                               "zcl.zcode_moderation_service_status.v1");
        zcl_native_handle_zcode_moderation_service_status(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "blocker")),
                      "candidate moderation readiness generation is active");
        zcl_command_reply_free(&reply);
        json_free(&input);
        zcl_hotswap_service_reset();
        PASS();
    } _test_next:;
    return failures;
}

static bool candidate_shop_reputation(
    const struct shop_reputation_view_input_v1 *input,
    struct shop_reputation_view_result_v1 *out)
{
    if (!shop_reputation_view_service_builtin()->render(input, out))
        return false;
    snprintf(out->doctrine, sizeof(out->doctrine), "%s",
             "candidate marketplace reputation generation is active");
    return true;
}

static bool candidate_workspace_status(
    struct zcode_workspace_view_result_v1 *out)
{
    if (!zcode_workspace_view_service_builtin()->render_status(out))
        return false;
    snprintf(out->capability, sizeof(out->capability), "%s",
             "candidate workspace view generation is active");
    return true;
}

static bool candidate_workspace_manifest(
    enum zcode_workspace_manifest_view_mode_v1 mode,
    struct zcode_workspace_view_result_v1 *out)
{
    if (!zcode_workspace_view_service_builtin()->render_manifest(mode, out))
        return false;
    if (mode == ZCODE_WORKSPACE_MANIFEST_VIEW_PLAN)
        snprintf(out->capability, sizeof(out->capability), "%s",
                 "candidate manifest presentation generation is active");
    return true;
}

static int t_zcode_workspace_view(void)
{
    int failures = 0;
    TEST("workspace views swap while signatures and root authority stay static") {
        zcl_hotswap_service_reset();
        ASSERT(zcode_workspace_view_service_builtin()->render_manifest);
        struct zcode_workspace_view_service_v1 candidate =
            *zcode_workspace_view_service_builtin();
        candidate.render_status = candidate_workspace_status;
        candidate.render_manifest = candidate_workspace_manifest;
        struct zcl_hotswap_service_candidate publication = {
            .service_id = ZCODE_WORKSPACE_VIEW_SERVICE_ID,
            .source_tu = "app/services/src/zcode_workspace_view_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(candidate),
            .abi_fingerprint = ZCODE_WORKSPACE_VIEW_ABI_FINGERPRINT,
            .schema_fingerprint = ZCODE_WORKSPACE_VIEW_SCHEMA_FINGERPRINT,
            .wire_fingerprint = ZCODE_WORKSPACE_VIEW_WIRE_FINGERPRINT,
            .kat_fingerprint = ZCODE_WORKSPACE_VIEW_KAT_FINGERPRINT,
            .vtable = &candidate,
        };
        struct zcl_hotswap_service_report report = {0};
        ASSERT(zcl_hotswap_service_publish(
            zcl_native_zcode_workspace_view_service_contract(), &publication,
            true, &report));
        ASSERT(report.probed);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_workspace_status.v1");
        zcl_native_handle_zcode_workspace_status(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&reply.data,
                                       "view_service_generation")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "capability")),
                      "candidate workspace view generation is active");
        ASSERT(json_get_bool(json_get(&reply.data,
                                      "signature_verification_static")));
        ASSERT(json_get_bool(json_get(&reply.data,
                                      "root_confirmation_static")));
        ASSERT(!json_get_bool(json_get(&reply.data, "effects_swappable")));
        struct zcl_hotswap_service_lease lease = {0};
        const struct zcode_workspace_view_service_v1 *active =
            zcl_hotswap_service_acquire(ZCODE_WORKSPACE_VIEW_SERVICE_ID,
                                        &lease);
        struct zcode_workspace_view_result_v1 manifest_view;
        ASSERT(active);
        ASSERT(active->render_manifest(ZCODE_WORKSPACE_MANIFEST_VIEW_PLAN,
                                       &manifest_view));
        ASSERT_STR_EQ(manifest_view.capability,
                      "candidate manifest presentation generation is active");
        zcl_hotswap_service_release(&lease);
        zcl_command_reply_free(&reply);
        json_free(&input);
        zcl_hotswap_service_reset();
        PASS();
    } _test_next:;
    return failures;
}

static bool candidate_passport_render(
    enum zcode_passport_view_mode_v1 mode,
    struct zcode_passport_view_result_v1 *out)
{
    if (!zcode_passport_view_service_builtin()->render(mode, out))
        return false;
    if (mode == ZCODE_PASSPORT_VIEW_STATUS)
        snprintf(out->capability, sizeof(out->capability), "%s",
                 "candidate Passport view generation is active");
    return true;
}

static int t_zcode_passport_view(void)
{
    int failures = 0;
    TEST("Passport views swap while signatures, roots and publication stay static") {
        zcl_hotswap_service_reset();
        struct zcode_passport_view_service_v1 candidate =
            *zcode_passport_view_service_builtin();
        candidate.render = candidate_passport_render;
        struct zcl_hotswap_service_candidate publication = {
            .service_id = ZCODE_PASSPORT_VIEW_SERVICE_ID,
            .source_tu = "app/services/src/zcode_passport_view_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(candidate),
            .abi_fingerprint = ZCODE_PASSPORT_VIEW_ABI_FINGERPRINT,
            .schema_fingerprint = ZCODE_PASSPORT_VIEW_SCHEMA_FINGERPRINT,
            .wire_fingerprint = ZCODE_PASSPORT_VIEW_WIRE_FINGERPRINT,
            .kat_fingerprint = ZCODE_PASSPORT_VIEW_KAT_FINGERPRINT,
            .vtable = &candidate,
        };
        struct zcl_hotswap_service_report report = {0};
        ASSERT(zcl_hotswap_service_publish(
            zcl_native_zcode_passport_view_service_contract(), &publication,
            true, &report));
        ASSERT(report.probed);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_passport_status.v1");
        zcl_native_handle_zcode_passport_status(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&reply.data,
                                       "view_service_generation")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "capability")),
                      "candidate Passport view generation is active");
        ASSERT(json_get_bool(json_get(&reply.data,
                                      "signature_verification_static")));
        ASSERT(json_get_bool(json_get(&reply.data, "canonical_root_static")));
        ASSERT(json_get_bool(json_get(&reply.data, "signing_payload_static")));
        ASSERT(!json_get_bool(json_get(&reply.data, "persistence_swappable")));
        ASSERT(!json_get_bool(json_get(&reply.data, "publication_swappable")));
        zcl_command_reply_free(&reply);
        json_free(&input);
        zcl_hotswap_service_reset();
        PASS();
    } _test_next:;
    return failures;
}

static bool candidate_goal_context_status(
    struct zcode_goal_context_view_v1 *out)
{
    if (!zcode_goal_context_calc_service_builtin()->render_status(out))
        return false;
    snprintf(out->capability, sizeof(out->capability), "%s",
             "candidate goal-context generation is active");
    return true;
}

static int t_zcode_goal_context_calc(void)
{
    int failures = 0;
    TEST("goal-context calculation swaps while index reads and task effects stay static") {
        zcl_hotswap_service_reset();
        struct zcode_goal_context_calc_service_v1 candidate =
            *zcode_goal_context_calc_service_builtin();
        candidate.render_status = candidate_goal_context_status;
        struct zcl_hotswap_service_candidate publication = {
            .service_id = ZCODE_GOAL_CONTEXT_CALC_SERVICE_ID,
            .source_tu = "app/services/src/zcode_goal_context_calc_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(candidate),
            .abi_fingerprint = ZCODE_GOAL_CONTEXT_CALC_ABI_FINGERPRINT,
            .schema_fingerprint = ZCODE_GOAL_CONTEXT_CALC_SCHEMA_FINGERPRINT,
            .wire_fingerprint = ZCODE_GOAL_CONTEXT_CALC_WIRE_FINGERPRINT,
            .kat_fingerprint = ZCODE_GOAL_CONTEXT_CALC_KAT_FINGERPRINT,
            .vtable = &candidate,
        };
        struct zcl_hotswap_service_report report = {0};
        ASSERT(zcl_hotswap_service_publish(
            zcode_goal_context_calc_service_contract(), &publication, true,
            &report));
        ASSERT(report.probed);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_work_context.v1");
        zcl_native_handle_zcode_work_context(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "service_generation")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "capability")),
                      "candidate goal-context generation is active");
        ASSERT(json_get_bool(json_get(&reply.data, "codeindex_reads_static")));
        ASSERT(json_get_bool(json_get(&reply.data, "clock_measurement_static")));
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "workspace_writes_swappable")));
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "task_creation_swappable")));
        zcl_command_reply_free(&reply);
        json_free(&input);
        zcl_hotswap_service_reset();
        PASS();
    } _test_next:;
    return failures;
}

static bool candidate_lane_render(
    uint8_t lane, struct zcode_lane_view_result_v1 *out)
{
    if (!zcode_lane_view_service_builtin()->render(lane, out)) return false;
    if (lane == ZCODE_LANE_VIEW_GUIDE)
        snprintf(out->capability, sizeof(out->capability), "%s",
                 "candidate lane view generation is active");
    return true;
}

static bool candidate_lane_wrong_name(
    uint8_t lane, struct zcode_lane_view_result_v1 *out)
{
    if (!zcode_lane_view_service_builtin()->render(lane, out)) return false;
    if (lane == VCS_ZCODE_LANE_FRONTIER)
        snprintf(out->lane_name, sizeof(out->lane_name), "%s", "PROVEN");
    return true;
}

static int t_zcode_lane_view(void)
{
    int failures = 0;
    TEST("lane views swap while CAS, signatures, proofs and promotions stay static") {
        zcl_hotswap_service_reset();
        struct zcode_lane_view_service_v1 candidate =
            *zcode_lane_view_service_builtin();
        candidate.render = candidate_lane_render;
        struct zcl_hotswap_service_candidate publication = {
            .service_id = ZCODE_LANE_VIEW_SERVICE_ID,
            .source_tu = "app/services/src/zcode_lane_view_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(candidate),
            .abi_fingerprint = ZCODE_LANE_VIEW_ABI_FINGERPRINT,
            .schema_fingerprint = ZCODE_LANE_VIEW_SCHEMA_FINGERPRINT,
            .wire_fingerprint = ZCODE_LANE_VIEW_WIRE_FINGERPRINT,
            .kat_fingerprint = ZCODE_LANE_VIEW_KAT_FINGERPRINT,
            .vtable = &candidate,
        };
        struct zcl_hotswap_service_report report = {0};
        ASSERT(zcl_hotswap_service_publish(
            zcode_lane_view_service_contract(), &publication, true, &report));
        ASSERT(report.probed);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_lane_guide.v1");
        zcl_native_handle_zcode_lane_guide(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&reply.data,
                                       "lane_view_service_generation")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "capability")),
                      "candidate lane view generation is active");
        ASSERT(json_get_bool(json_get(&reply.data, "cas_reads_static")));
        ASSERT(json_get_bool(json_get(&reply.data,
                                      "database_projection_static")));
        ASSERT(json_get_bool(json_get(&reply.data,
                                      "signature_verification_static")));
        ASSERT(json_get_bool(json_get(&reply.data, "proof_evaluation_static")));
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "promotion_writes_swappable")));
        zcl_command_reply_free(&reply);
        json_free(&input);
        zcl_hotswap_service_reset();

        candidate.render = candidate_lane_wrong_name;
        publication.vtable = &candidate;
        memset(&report, 0, sizeof(report));
        ASSERT(!zcl_hotswap_service_publish(
            zcode_lane_view_service_contract(), &publication, true, &report));
        ASSERT_STR_EQ(report.stage, "kat");
        ASSERT(!report.activated);
        PASS();
    } _test_next:;
    return failures;
}

static int t_shop_reputation_view(void)
{
    int failures = 0;
    TEST("marketplace reputation rendering swaps while evidence reads stay static") {
        zcl_hotswap_service_reset();
        struct shop_reputation_view_input_v1 input = {.releases = 1};
        struct shop_reputation_view_result_v1 result;
        ASSERT(shop_reputation_view_service_builtin()->render(&input,
                                                               &result));
        ASSERT_EQ(result.row_count, SHOP_REPUTATION_VIEW_ROW_COUNT);
        ASSERT_STR_EQ(result.rows[0].state, "recorded");
        ASSERT_STR_EQ(result.rows[7].state, "unavailable");

        struct shop_reputation_view_service_v1 candidate_service = {
            .render = candidate_shop_reputation,
        };
        struct zcl_hotswap_service_candidate service_candidate = {
            .service_id = SHOP_REPUTATION_VIEW_SERVICE_ID,
            .source_tu =
                "app/services/src/shop_reputation_view_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(candidate_service),
            .abi_fingerprint = SHOP_REPUTATION_VIEW_ABI_FINGERPRINT,
            .schema_fingerprint = SHOP_REPUTATION_VIEW_SCHEMA_FINGERPRINT,
            .wire_fingerprint = SHOP_REPUTATION_VIEW_WIRE_FINGERPRINT,
            .kat_fingerprint = SHOP_REPUTATION_VIEW_KAT_FINGERPRINT,
            .vtable = &candidate_service,
        };
        struct zcl_hotswap_service_report report = {0};
        ASSERT(zcl_hotswap_service_publish(
            zcl_native_shop_reputation_view_service_contract(),
            &service_candidate, true, &report));
        ASSERT(report.probed);

        struct zcl_hotswap_service_lease lease = {0};
        const struct shop_reputation_view_service_v1 *active =
            zcl_hotswap_service_acquire(SHOP_REPUTATION_VIEW_SERVICE_ID,
                                        &lease);
        ASSERT(active != NULL);
        ASSERT(active->render(&input, &result));
        ASSERT_STR_EQ(result.doctrine,
                      "candidate marketplace reputation generation is active");
        zcl_hotswap_service_release(&lease);
        zcl_hotswap_service_reset();
        PASS();
    } _test_next:;
    return failures;
}

static bool candidate_shop_status(const struct shop_status_view_input_v1 *input,
                                  struct shop_status_view_result_v1 *out)
{
    if (!shop_status_view_service_builtin()->render(input, out))
        return false;
    if (out->shop_live)
        snprintf(out->shop_url, sizeof(out->shop_url), "%s",
                 "http://live-generation.invalid/store");
    return true;
}

static int t_shop_status_view(void)
{
    int failures = 0;
    TEST("shop posture rendering swaps while probes and init effects stay static") {
        zcl_hotswap_service_reset();
        struct shop_status_view_input_v1 input = {
            .tor_real = true,
            .identity_present = true,
            .wallet = SHOP_STATUS_WALLET_ENCRYPTED,
            .node_db_present = true,
            .store_schema = true,
            .announced = true,
        };
        snprintf(input.address, sizeof(input.address), "%s", "fixture");
        struct shop_status_view_service_v1 candidate = {
            .render = candidate_shop_status,
        };
        struct zcl_hotswap_service_candidate publication = {
            .service_id = SHOP_STATUS_VIEW_SERVICE_ID,
            .source_tu = "app/services/src/shop_status_view_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(candidate),
            .abi_fingerprint = SHOP_STATUS_VIEW_ABI_FINGERPRINT,
            .schema_fingerprint = SHOP_STATUS_VIEW_SCHEMA_FINGERPRINT,
            .wire_fingerprint = SHOP_STATUS_VIEW_WIRE_FINGERPRINT,
            .kat_fingerprint = SHOP_STATUS_VIEW_KAT_FINGERPRINT,
            .vtable = &candidate,
        };
        struct zcl_hotswap_service_report report = {0};
        ASSERT(zcl_hotswap_service_publish(
            zcl_native_shop_status_view_service_contract(), &publication,
            true, &report));
        struct zcl_hotswap_service_lease lease = {0};
        const struct shop_status_view_service_v1 *active =
            zcl_hotswap_service_acquire(SHOP_STATUS_VIEW_SERVICE_ID, &lease);
        struct shop_status_view_result_v1 out;
        ASSERT(active && active->render(&input, &out));
        ASSERT(out.shop_live && out.gap_count == 0);
        ASSERT_STR_EQ(out.shop_url, "http://live-generation.invalid/store");
        zcl_hotswap_service_release(&lease);
        zcl_hotswap_service_reset();
        PASS();
    } _test_next:;
    return failures;
}

static bool candidate_shop_want(
    const struct shop_want_view_input_v1 *input,
    struct shop_want_view_result_v1 *out)
{
    if (!shop_want_view_service_builtin()->render(input, out))
        return false;
    if (input->amount_zatoshi == 777u)
        snprintf(out->next_action, sizeof(out->next_action), "%s",
                 "candidate buyer-want generation is active; this ad moves no value");
    return true;
}

static int t_shop_want_view(void)
{
    int failures = 0;
    TEST("buyer-want rendering swaps while signatures, storage, and value stay static") {
        zcl_hotswap_service_reset();
        struct shop_want_view_input_v1 input = {
            .amount_zatoshi = 777u,
            .criteria_len = 4u,
            .issued_unix = 100,
            .expires_unix = 200,
            .now_unix = 150,
            .review_state = 1,
            .full = true,
        };
        input.want_id[0] = 1;
        input.buyer_pubkey[0] = 2;
        memcpy(input.criteria, "test", 4);
        struct shop_want_view_service_v1 candidate =
            *shop_want_view_service_builtin();
        candidate.render = candidate_shop_want;
        struct zcl_hotswap_service_candidate publication = {
            .service_id = SHOP_WANT_VIEW_SERVICE_ID,
            .source_tu = "app/services/src/shop_want_view_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(candidate),
            .abi_fingerprint = SHOP_WANT_VIEW_ABI_FINGERPRINT,
            .schema_fingerprint = SHOP_WANT_VIEW_SCHEMA_FINGERPRINT,
            .wire_fingerprint = SHOP_WANT_VIEW_WIRE_FINGERPRINT,
            .kat_fingerprint = SHOP_WANT_VIEW_KAT_FINGERPRINT,
            .vtable = &candidate,
        };
        struct zcl_hotswap_service_report report = {0};
        ASSERT(zcl_hotswap_service_publish(
            zcl_native_shop_want_view_service_contract(), &publication,
            true, &report));
        ASSERT(report.probed);

        struct zcl_hotswap_service_lease lease = {0};
        const struct shop_want_view_service_v1 *active =
            zcl_hotswap_service_acquire(SHOP_WANT_VIEW_SERVICE_ID, &lease);
        struct shop_want_view_result_v1 out;
        ASSERT(active && active->render(&input, &out));
        ASSERT_STR_EQ(out.state, "open");
        ASSERT_STR_EQ(out.next_action,
                      "candidate buyer-want generation is active; this ad moves no value");
        zcl_hotswap_service_release(&lease);

        struct json_value request_input;
        json_init(&request_input);
        json_set_object(&request_input);
        ASSERT(json_push_kv_str(&request_input, "datadir",
                                "./test-tmp/shop-want-view-no-db"));
        ASSERT(json_push_kv_str(
            &request_input, "buyer_secret",
            "0101010101010101010101010101010101010101010101010101010101010101"));
        ASSERT(json_push_kv_int(&request_input, "amount_zatoshi", 777));
        ASSERT(json_push_kv_str(&request_input, "criteria", "test"));
        ASSERT(json_push_kv_int(&request_input, "now_unix", 100));
        ASSERT(json_push_kv_int(&request_input, "expires_unix", 200));
        struct zcl_command_request request = {.input = &request_input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.shop_want_post.v1");
        /* Test builds pin the want-post leaf's clock through now_unix;
         * the release fork refuses it outright (shw_now's compile-time
         * twin of shf_now). */
        zcl_native_handle_shop_want_post(&request, &reply);
        const struct json_value *want = json_get(&reply.data, "want");
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(want, "next_action")),
                      "candidate buyer-want generation is active; this ad moves no value");
        zcl_command_reply_free(&reply);
        json_free(&request_input);
        zcl_hotswap_service_reset();
        PASS();
    } _test_next:;
    return failures;
}

int test_hotswap_service_registry(void)
{
    int failures = t_publish_and_lease() + t_contract_drift_restarts() +
                   t_manifest_mapping() + t_market_purchase_view() +
                   t_market_moderation_view() + t_zcode_package_view();
    failures += t_zcode_moderation_view() + t_shop_reputation_view() +
                t_zcode_workspace_view() + t_zcode_passport_view() +
                t_zcode_goal_context_calc() + t_zcode_lane_view() +
                t_shop_status_view() +
                t_shop_want_view();
    zcl_hotswap_service_reset();
    printf("=== hotswap_service_registry: %d failures ===\n", failures);
    return failures;
}
