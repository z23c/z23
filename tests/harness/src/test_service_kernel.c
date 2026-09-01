/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "config/boot.h"
#include "kernel/service_kernel.h"
#include <string.h>

struct service_kernel_test_ctx {
    int id;
    bool fail_init;
    bool fail_start;
    int init_count;
    int start_count;
    int stop_count;
    int *events;
    int *event_count;
};

static void record_event(struct service_kernel_test_ctx *ctx, int event)
{
    ctx->events[(*ctx->event_count)++] = event;
}

static bool test_service_init(struct zcl_service_kernel *kernel, void *raw)
{
    (void)kernel;
    struct service_kernel_test_ctx *ctx = raw;
    ctx->init_count++;
    record_event(ctx, ctx->id * 10 + 1);
    return !ctx->fail_init;
}

static bool test_service_start(void *raw)
{
    struct service_kernel_test_ctx *ctx = raw;
    ctx->start_count++;
    record_event(ctx, ctx->id * 10 + 2);
    return !ctx->fail_start;
}

static void test_service_stop(void *raw)
{
    struct service_kernel_test_ctx *ctx = raw;
    ctx->stop_count++;
    record_event(ctx, ctx->id * 10 + 3);
}

static bool test_service_status(void *raw, struct zcl_service_status *out)
{
    struct service_kernel_test_ctx *ctx = raw;
    if (ctx->fail_start) {
        out->reason = "configured failure";
        return true;
    }
    return true;
}

static struct zcl_service_spec test_spec(const char *name,
                                         struct service_kernel_test_ctx *ctx)
{
    struct zcl_service_spec spec = {
        .name = name,
        .init = test_service_init,
        .start = test_service_start,
        .stop = test_service_stop,
        .status = test_service_status,
        .ctx = ctx,
    };
    return spec;
}

static int test_service_kernel_lifecycle(void)
{
    int failures = 0;
    TEST("service kernel: register, start in order, stop in reverse") {
        struct zcl_service_kernel kernel;
        int events[8] = {0};
        int event_count = 0;
        struct service_kernel_test_ctx a = {
            .id = 1, .events = events, .event_count = &event_count
        };
        struct service_kernel_test_ctx b = {
            .id = 2, .events = events, .event_count = &event_count
        };

        zcl_service_kernel_init(&kernel);
        struct zcl_service_spec spec_a = test_spec("chain", &a);
        struct zcl_service_spec spec_b = test_spec("sync", &b);

        ASSERT(zcl_service_kernel_register(&kernel, &spec_a));
        ASSERT(zcl_service_kernel_register(&kernel, &spec_b));
        ASSERT_EQ((int)zcl_service_kernel_count(&kernel), 2);
        ASSERT(zcl_service_kernel_find(&kernel, "chain") != NULL);
        ASSERT(!zcl_service_kernel_register(&kernel, &spec_a));

        ASSERT(zcl_service_kernel_start_all(&kernel));
        ASSERT(kernel.started);
        ASSERT_EQ(a.init_count, 1);
        ASSERT_EQ(b.init_count, 1);
        ASSERT_EQ(a.start_count, 1);
        ASSERT_EQ(b.start_count, 1);
        ASSERT_EQ(event_count, 4);
        ASSERT_EQ(events[0], 11);
        ASSERT_EQ(events[1], 21);
        ASSERT_EQ(events[2], 12);
        ASSERT_EQ(events[3], 22);

        zcl_service_kernel_stop_all(&kernel);
        ASSERT(!kernel.started);
        ASSERT_EQ(a.stop_count, 1);
        ASSERT_EQ(b.stop_count, 1);
        ASSERT_EQ(event_count, 6);
        ASSERT_EQ(events[4], 23);
        ASSERT_EQ(events[5], 13);
        PASS();
    } _test_next:;
    return failures;
}

static int test_service_kernel_failure_unwinds(void)
{
    int failures = 0;
    TEST("service kernel: start failure unwinds already-started services") {
        struct zcl_service_kernel kernel;
        int events[8] = {0};
        int event_count = 0;
        struct service_kernel_test_ctx a = {
            .id = 1, .events = events, .event_count = &event_count
        };
        struct service_kernel_test_ctx b = {
            .id = 2, .fail_start = true,
            .events = events, .event_count = &event_count
        };

        zcl_service_kernel_init(&kernel);
        struct zcl_service_spec spec_a = test_spec("chain", &a);
        struct zcl_service_spec spec_b = test_spec("sync", &b);
        ASSERT(zcl_service_kernel_register(&kernel, &spec_a));
        ASSERT(zcl_service_kernel_register(&kernel, &spec_b));

        ASSERT(!zcl_service_kernel_start_all(&kernel));
        ASSERT(!kernel.started);
        ASSERT_EQ(a.stop_count, 1);
        ASSERT_EQ(b.stop_count, 0);

        const struct zcl_service_entry *failed =
            zcl_service_kernel_find(&kernel, "sync");
        ASSERT(failed != NULL);
        ASSERT_EQ((int)failed->state, (int)ZCL_SERVICE_FAILED);
        ASSERT(failed->failure_reason != NULL);

        struct zcl_service_status status;
        ASSERT(zcl_service_kernel_status(&kernel, "sync", &status));
        ASSERT_EQ((int)status.state, (int)ZCL_SERVICE_FAILED);
        ASSERT(status.reason != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_service_kernel_init_failure(void)
{
    int failures = 0;
    TEST("service kernel: init failure stops before later services start") {
        struct zcl_service_kernel kernel;
        int events[8] = {0};
        int event_count = 0;
        struct service_kernel_test_ctx a = {
            .id = 1, .fail_init = true,
            .events = events, .event_count = &event_count
        };
        struct service_kernel_test_ctx b = {
            .id = 2, .events = events, .event_count = &event_count
        };

        zcl_service_kernel_init(&kernel);
        struct zcl_service_spec spec_a = test_spec("chain", &a);
        struct zcl_service_spec spec_b = test_spec("sync", &b);
        ASSERT(zcl_service_kernel_register(&kernel, &spec_a));
        ASSERT(zcl_service_kernel_register(&kernel, &spec_b));

        ASSERT(!zcl_service_kernel_start_all(&kernel));
        ASSERT(!kernel.initialized);
        ASSERT(!kernel.started);
        ASSERT_EQ(a.init_count, 1);
        ASSERT_EQ(a.start_count, 0);
        ASSERT_EQ(b.init_count, 0);
        ASSERT_EQ(b.start_count, 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_service_kernel_optional_failures(void)
{
    int failures = 0;
    TEST("service kernel: optional service failures do not stop required services") {
        struct zcl_service_kernel kernel;
        int events[12] = {0};
        int event_count = 0;
        struct service_kernel_test_ctx a = {
            .id = 1, .events = events, .event_count = &event_count
        };
        struct service_kernel_test_ctx b = {
            .id = 2, .fail_start = true,
            .events = events, .event_count = &event_count
        };
        struct service_kernel_test_ctx c = {
            .id = 3, .events = events, .event_count = &event_count
        };

        zcl_service_kernel_init(&kernel);
        struct zcl_service_spec spec_a = test_spec("chain", &a);
        struct zcl_service_spec spec_b = test_spec("mempool_limits", &b);
        struct zcl_service_spec spec_c = test_spec("sync", &c);
        spec_b.flags = ZCL_SERVICE_OPTIONAL;

        ASSERT(zcl_service_kernel_register(&kernel, &spec_a));
        ASSERT(zcl_service_kernel_register(&kernel, &spec_b));
        ASSERT(zcl_service_kernel_register(&kernel, &spec_c));
        ASSERT(zcl_service_kernel_start_all(&kernel));
        ASSERT(kernel.started);
        ASSERT_EQ(a.start_count, 1);
        ASSERT_EQ(b.start_count, 1);
        ASSERT_EQ(c.start_count, 1);
        ASSERT_EQ(b.stop_count, 0);

        const struct zcl_service_entry *optional =
            zcl_service_kernel_find(&kernel, "mempool_limits");
        ASSERT(optional != NULL);
        ASSERT_EQ((int)optional->state, (int)ZCL_SERVICE_FAILED);

        zcl_service_kernel_stop_all(&kernel);
        ASSERT_EQ(c.stop_count, 1);
        ASSERT_EQ(a.stop_count, 1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_runtime_profile_parse(void)
{
    int failures = 0;
    TEST("runtime profile: parses service profile names and aliases") {
        enum zcl_runtime_profile profile = ZCL_RUNTIME_FULL;

        ASSERT(app_runtime_profile_parse("full", &profile));
        ASSERT_EQ((int)profile, (int)ZCL_RUNTIME_FULL);
        ASSERT(app_runtime_profile_parse("zclassic-only", &profile));
        ASSERT_EQ((int)profile, (int)ZCL_RUNTIME_ZCLASSIC_ONLY);
        ASSERT(app_runtime_profile_parse("zclassic", &profile));
        ASSERT_EQ((int)profile, (int)ZCL_RUNTIME_ZCLASSIC_ONLY);
        ASSERT(app_runtime_profile_parse("explorer", &profile));
        ASSERT_EQ((int)profile, (int)ZCL_RUNTIME_EXPLORER);
        ASSERT(app_runtime_profile_parse("onion-node", &profile));
        ASSERT_EQ((int)profile, (int)ZCL_RUNTIME_ONION_NODE);
        ASSERT(app_runtime_profile_parse("legacy-compat", &profile));
        ASSERT_EQ((int)profile, (int)ZCL_RUNTIME_LEGACY_COMPAT);
        ASSERT(!app_runtime_profile_parse("unknown", &profile));
        ASSERT(strcmp(app_runtime_profile_name(ZCL_RUNTIME_ZCLASSIC_ONLY),
                      "zclassic-only") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_runtime_profile_zclassic_only_capabilities(void)
{
    int failures = 0;
    TEST("runtime profile: zclassic-only is a lean sync node") {
        ASSERT(!app_runtime_profile_has_explorer(
            ZCL_RUNTIME_ZCLASSIC_ONLY));
        ASSERT(!app_runtime_profile_has_store(
            ZCL_RUNTIME_ZCLASSIC_ONLY));
        ASSERT(!app_runtime_profile_has_file_service(
            ZCL_RUNTIME_ZCLASSIC_ONLY));
        ASSERT(!app_runtime_profile_has_onion(
            ZCL_RUNTIME_ZCLASSIC_ONLY, false));
        ASSERT(app_runtime_profile_has_onion(
            ZCL_RUNTIME_ZCLASSIC_ONLY, true));
        PASS();
    } _test_next:;
    return failures;
}

static int test_runtime_profile_app_surface_capabilities(void)
{
    int failures = 0;
    TEST("runtime profile: app surfaces stay explicit") {
        ASSERT(app_runtime_profile_has_explorer(ZCL_RUNTIME_FULL));
        ASSERT(app_runtime_profile_has_store(ZCL_RUNTIME_FULL));
        ASSERT(app_runtime_profile_has_file_service(ZCL_RUNTIME_FULL));
        ASSERT(app_runtime_profile_has_explorer(ZCL_RUNTIME_EXPLORER));
        ASSERT(!app_runtime_profile_has_store(ZCL_RUNTIME_EXPLORER));
        ASSERT(!app_runtime_profile_has_file_service(
            ZCL_RUNTIME_EXPLORER));
        ASSERT(app_runtime_profile_has_explorer(ZCL_RUNTIME_ONION_NODE));
        ASSERT(app_runtime_profile_has_store(ZCL_RUNTIME_ONION_NODE));
        ASSERT(app_runtime_profile_has_file_service(
            ZCL_RUNTIME_ONION_NODE));
        ASSERT(app_runtime_profile_has_onion(
            ZCL_RUNTIME_ONION_NODE, false));
        ASSERT(app_runtime_profile_has_explorer(
            ZCL_RUNTIME_LEGACY_COMPAT));
        ASSERT(app_runtime_profile_has_store(ZCL_RUNTIME_LEGACY_COMPAT));
        ASSERT(app_runtime_profile_has_file_service(
            ZCL_RUNTIME_LEGACY_COMPAT));
        PASS();
    } _test_next:;
    return failures;
}

int test_service_kernel(void)
{
    int failures = 0;
    failures += test_service_kernel_lifecycle();
    failures += test_service_kernel_failure_unwinds();
    failures += test_service_kernel_init_failure();
    failures += test_service_kernel_optional_failures();
    failures += test_runtime_profile_parse();
    failures += test_runtime_profile_zclassic_only_capabilities();
    failures += test_runtime_profile_app_surface_capabilities();
    return failures;
}
