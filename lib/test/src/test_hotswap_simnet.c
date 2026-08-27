/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hermetic proof for transactional native command-registry hot-swap: the
 * kernel command-registry override layer (lib/kernel/src/command_registry.c)
 * atomically re-points a leaf handler across successive generations with
 * strict generation monotonicity, no restart, and no torn intermediate state
 * observable by dispatch. No sockets, services, files, or datadirs are used.
 */

#include "test/test_core.h"

#include "json/json.h"
#include "kernel/command_registry.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void hsim_leaf_h_base(const struct zcl_command_request *request,
                             struct zcl_command_reply *reply)
{
    (void)request;
    (void)json_push_kv_str(&reply->data, "gen", "BASE");
}

static void hsim_leaf_h_gen_a(const struct zcl_command_request *request,
                              struct zcl_command_reply *reply)
{
    (void)request;
    (void)json_push_kv_str(&reply->data, "gen", "A");
}

static void hsim_leaf_h_gen_b(const struct zcl_command_request *request,
                              struct zcl_command_reply *reply)
{
    (void)request;
    (void)json_push_kv_str(&reply->data, "gen", "B");
}

static const struct zcl_command_spec g_hsim_leaf_specs[] = {
    {
        .path = "sim.leaf.repoint",
        .summary = "hot-swap native-leaf re-point probe",
        .layer = ZCL_COMMAND_LAYER_CORE,
        .effect = ZCL_COMMAND_EFFECT_READ,
        .availability = ZCL_COMMAND_READY,
        .mode = ZCL_COMMAND_MODE_SYNC,
        .allowed_lanes = ZCL_COMMAND_LANE_LOCAL,
        .handler = hsim_leaf_h_base,
    },
};

static const struct zcl_command_registry g_hsim_leaf_registry = {
    .commands = g_hsim_leaf_specs,
    .count = sizeof(g_hsim_leaf_specs) / sizeof(g_hsim_leaf_specs[0]),
};

static enum zcl_command_exit hsim_leaf_dispatch(char *out, size_t out_size)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    (void)zcl_command_registry_execute_json(
        &g_hsim_leaf_registry, &g_hsim_leaf_specs[0], NULL, &input, false,
        "sim.leaf.repoint", "normal", 0, 0, NULL, out, out_size, &exit_code);
    json_free(&input);
    return exit_code;
}

static int test_hotswap_native_leaf_repoint(void)
{
    int failures = 0;
    TEST("native.leaves: replace_batch atomically re-points a leaf handler; "
         "generation is strictly monotonic") {
        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(&g_hsim_leaf_registry);
        char out[4096];
        char why[256];

        /* Baseline: catalog handler runs. */
        ASSERT_EQ((int)hsim_leaf_dispatch(out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"gen\":\"BASE\"") != NULL);

        /* Generation A publishes and dispatch observes it immediately. */
        struct zcl_command_handler_override ovr_a = {
            .path = "sim.leaf.repoint", .handler = hsim_leaf_h_gen_a,
        };
        why[0] = '\0';
        uint32_t gen_a = 0;
        ASSERT(zcl_command_registry_replace_batch(0, &ovr_a, 1, why,
                                                  sizeof(why), &gen_a));
        ASSERT(gen_a > 0);
        ASSERT_EQ((int)hsim_leaf_dispatch(out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"gen\":\"A\"") != NULL);

        /* Generation B atomically re-points the SAME leaf path — no
         * restart, no intermediate torn state observable by dispatch. */
        struct zcl_command_handler_override ovr_b = {
            .path = "sim.leaf.repoint", .handler = hsim_leaf_h_gen_b,
        };
        why[0] = '\0';
        uint32_t gen_b = 0;
        ASSERT(zcl_command_registry_replace_batch(0, &ovr_b, 1, why,
                                                  sizeof(why), &gen_b));
        ASSERT(gen_b > gen_a);
        ASSERT_EQ((int)hsim_leaf_dispatch(out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"gen\":\"B\"") != NULL);

        /* Generation monotonicity: a generation <= the active one is
         * rejected outright and publishes nothing. */
        why[0] = '\0';
        ASSERT(!zcl_command_registry_replace_batch(gen_b, &ovr_a, 1, why,
                                                    sizeof(why), NULL));
        ASSERT(strstr(why, "not newer") != NULL);
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)gen_b);
        ASSERT_EQ((int)hsim_leaf_dispatch(out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"gen\":\"B\"") != NULL);

        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_hotswap_simnet(void)
{
    printf("\n=== hot-swap native command-registry re-point ===\n");
    int failures = 0;
    failures += test_hotswap_native_leaf_repoint();
    printf("=== hotswap_simnet: %d failures ===\n", failures);
    return failures;
}
