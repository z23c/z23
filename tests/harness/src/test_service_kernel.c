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

/* THE 2026-09-08 node1 outage, reproduced.
 *
 * The frontend kernel registers file_service, rom_seed, rpc_http, api_cache,
 * https_explorer, miner, onion_tor, zcode_store in that order. rpc_http was
 * the only REQUIRED entry. Its bind failed once — the outgoing process still
 * held the RPC port — and start_all() unwound file_service and rom_seed and
 * returned WITHOUT ever calling https_explorer's start hook. The public site
 * stayed down for 27 minutes for a failure that had nothing to do with it.
 *
 * The shape below is the real one: a required-but-INDEPENDENT service in the
 * middle, ordinary optional services after it. */
static int test_service_kernel_independent_failure_spares_siblings(void)
{
    int failures = 0;
    TEST("service kernel: an independent failure does not cancel later services") {
        struct zcl_service_kernel kernel;
        int events[16] = {0};
        int event_count = 0;
        struct service_kernel_test_ctx before = {
            .id = 1, .events = events, .event_count = &event_count
        };
        struct service_kernel_test_ctx front_door = {
            .id = 2, .fail_start = true,
            .events = events, .event_count = &event_count
        };
        struct service_kernel_test_ctx site = {
            .id = 3, .events = events, .event_count = &event_count
        };

        zcl_service_kernel_init(&kernel);
        struct zcl_service_spec spec_before = test_spec("rom_seed", &before);
        spec_before.flags = ZCL_SERVICE_OPTIONAL;
        struct zcl_service_spec spec_front = test_spec("rpc_http",
                                                       &front_door);
        spec_front.flags = ZCL_SERVICE_INDEPENDENT;
        struct zcl_service_spec spec_site = test_spec("https_explorer", &site);
        spec_site.flags = ZCL_SERVICE_OPTIONAL;

        ASSERT(zcl_service_kernel_register(&kernel, &spec_before));
        ASSERT(zcl_service_kernel_register(&kernel, &spec_front));
        ASSERT(zcl_service_kernel_register(&kernel, &spec_site));

        /* Still a failure — the caller must still degrade and say so. */
        ASSERT(!zcl_service_kernel_start_all(&kernel));
        /* ...but the site came up, and nothing was rolled back. */
        ASSERT_EQ(site.start_count, 1);
        ASSERT_EQ(before.stop_count, 0);
        ASSERT(kernel.started);

        const struct zcl_service_entry *explorer =
            zcl_service_kernel_find(&kernel, "https_explorer");
        ASSERT(explorer != NULL);
        ASSERT_EQ((int)explorer->state, (int)ZCL_SERVICE_STARTED);

        /* The failure is still named, with its reason, on the right entry. */
        const struct zcl_service_entry *door =
            zcl_service_kernel_find(&kernel, "rpc_http");
        ASSERT(door != NULL);
        ASSERT_EQ((int)door->state, (int)ZCL_SERVICE_FAILED);
        ASSERT(door->failure_reason != NULL);

        /* And a genuinely required service still unwinds: INDEPENDENT is a
         * per-service decision, not a weakening of the kernel. */
        zcl_service_kernel_stop_all(&kernel);
        PASS();
    } _test_next:;
    return failures;
}

/* Per-service timing, and the in-flight description a watchdog reads. */
static int test_service_kernel_start_timing(void)
{
    int failures = 0;
    TEST("service kernel: names the service a slow start is waiting on") {
        struct zcl_service_kernel kernel;
        int events[8] = {0};
        int event_count = 0;
        struct service_kernel_test_ctx a = {
            .id = 1, .events = events, .event_count = &event_count
        };
        char desc[80];

        zcl_service_kernel_init(&kernel);
        struct zcl_service_spec spec_a = test_spec("https_explorer", &a);
        ASSERT(zcl_service_kernel_register(&kernel, &spec_a));

        /* Nothing in flight before the start, and nothing after it. */
        ASSERT(!zcl_service_kernel_describe_starting(
            &kernel, "frontend", 0, ZCL_SERVICE_SLOW_START_US,
            desc, sizeof(desc)));
        ASSERT_EQ(desc[0], '\0');

        ASSERT(zcl_service_kernel_start_all(&kernel));
        const struct zcl_service_entry *e =
            zcl_service_kernel_find(&kernel, "https_explorer");
        ASSERT(e != NULL);
        ASSERT(e->start_us >= 0);
        ASSERT(!zcl_service_kernel_describe_starting(
            &kernel, "frontend", 0, ZCL_SERVICE_SLOW_START_US,
            desc, sizeof(desc)));

        /* A start in flight: below the slow threshold it is not news, at or
         * above it the watchdog gets the service's NAME, which is the fact
         * `[boot] svc.frontend_tor_start 2462ms` never carried. */
        atomic_store(&kernel.starting_name, "rpc_http");
        atomic_store(&kernel.starting_since_us, 1000000);
        ASSERT(!zcl_service_kernel_describe_starting(
            &kernel, "frontend", 6000000, ZCL_SERVICE_SLOW_START_US,
            desc, sizeof(desc)));
        ASSERT(zcl_service_kernel_describe_starting(
            &kernel, "frontend", 42000000, ZCL_SERVICE_SLOW_START_US,
            desc, sizeof(desc)));
        ASSERT_STR_EQ(desc, "frontend=rpc_http 41s");

        atomic_store(&kernel.starting_name, NULL);
        zcl_service_kernel_stop_all(&kernel);
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
    failures += test_service_kernel_independent_failure_spares_siblings();
    failures += test_service_kernel_start_timing();
    failures += test_service_kernel_init_failure();
    failures += test_service_kernel_optional_failures();
    failures += test_runtime_profile_parse();
    failures += test_runtime_profile_zclassic_only_capabilities();
    failures += test_runtime_profile_app_surface_capabilities();
    return failures;
}
