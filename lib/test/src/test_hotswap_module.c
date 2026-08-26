/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the REAL (activatable) Tier-1 hot-swap module ABI + the
 * command-registry epoch/refcount drain that makes dlclose-after-swap safe.
 *
 * The test binary compiles ONE translation unit — the loader,
 * lib/hotswap/src/hotswap_activate.c — with -DZCL_DEV_BUILD, so `make
 * t-hotswap` can run a real test group against a hot-swapped module through
 * the same loader the dev node runs. Every other TU stays release-shaped. The
 * refusals asserted below are therefore the REAL loader's prechecks (path
 * confinement, dev-datadir classification), not a release stub.
 *
 * The behaviours the dlopen path would exercise (ABI-version mismatch,
 * missing/incomplete fields, the swappable allowlist hard line, and a failing
 * module self_test) are all factored into the pure, always-compiled
 * hotswap_module_admit(), which is unit-tested here with fabricated modules —
 * no dlopen required. The live swap + epoch-quiesce drain is proven against
 * the real command-registry override layer with function-pointer handlers
 * (the same mechanism hotswap_activate's commit_cb publishes into). */

#include "test/test_core.h"

#include "hotswap/hotswap.h"
#include "hotswap/hotswap_module.h"
#include "kernel/command_registry.h"
#include "json/json.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── Fabricated-module fixtures for hotswap_module_admit ──────────────── */

static void mod_handler(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply)
{
    (void)request;
    (void)json_push_kv_str(&reply->data, "who", "module");
}

static bool selftest_true(char *err, size_t cap) { (void)err; (void)cap; return true; }
static bool selftest_false(char *err, size_t cap)
{
    if (err && cap) snprintf(err, cap, "synthetic self_test failure");
    return false;
}

/* The status controller row of config/hotswap_swappable.def, whose declared
 * probe leaf in config/hotswap_eligible.def is core.status. */
#define STATUS_TU "app/controllers/src/status_native_handlers.c"

static const struct zcl_hotswap_leaf k_status_leaves[] = {
    { "core.status", mod_handler },
};
static const struct zcl_hotswap_leaf k_status_leaves_nullfn[] = {
    { "core.status", NULL },
};
static const struct zcl_hotswap_leaf k_consensus_leaves[] = {
    { "core.consensus.pow.verify", mod_handler },
};

static int test_admit_ok(void)
{
    int failures = 0;
    TEST("hotswap_module_admit accepts a well-formed allowlisted module") {
        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V2,
            .source_tu = STATUS_TU,   /* on config/hotswap_swappable.def */
            .leaf_count = 1,
            .leaves = k_status_leaves,
            .self_test = selftest_true,
        };
        char stage[64], why[192];
        ASSERT(hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        PASS();
    } _test_next:;
    return failures;
}

static int test_admit_abi_mismatch(void)
{
    int failures = 0;
    TEST("ABI version mismatch is refused at stage=abi") {
        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V2 + 7u,
            .source_tu = STATUS_TU, .leaf_count = 1,
            .leaves = k_status_leaves, .self_test = selftest_true,
        };
        char stage[64] = {0}, why[192] = {0};
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "abi"), 0);
        ASSERT(strstr(why, "abi_version") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_admit_missing_fields(void)
{
    int failures = 0;
    TEST("missing fields (NULL leaf fn) refused at stage=fields") {
        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V2,
            .source_tu = STATUS_TU, .leaf_count = 1,
            .leaves = k_status_leaves_nullfn, .self_test = selftest_true,
        };
        char stage[64] = {0}, why[192] = {0};
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "fields"), 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_admit_allowlist(void)
{
    int failures = 0;
    TEST("a non-allowlisted source is refused at stage=allowlist (HARD LINE)") {
        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V2,
            /* A consensus/validation TU — must NEVER be swappable. */
            .source_tu = "lib/consensus/src/pow.c",
            .leaf_count = 1, .leaves = k_consensus_leaves,
            .self_test = selftest_true,
        };
        char stage[64] = {0}, why[192] = {0};
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "allowlist"), 0);
        ASSERT(strstr(why, "allowlist") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_admit_leaf_not_owned(void)
{
    int failures = 0;
    TEST("an allowlisted source claiming a leaf it does not own is refused") {
        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V2,
            .source_tu = STATUS_TU, .leaf_count = 1,
            .leaves = k_consensus_leaves, .self_test = selftest_true,
        };
        char stage[64] = {0}, why[192] = {0};
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "allowlist"), 0);
        ASSERT(strstr(why, "core.consensus.pow.verify") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_admit_selftest_fail(void)
{
    int failures = 0;
    TEST("a failing module self_test is refused at stage=self_test (rollback)") {
        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V2,
            .source_tu = STATUS_TU, .leaf_count = 1,
            .leaves = k_status_leaves, .self_test = selftest_false,
        };
        char stage[64] = {0}, why[192] = {0};
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "self_test"), 0);
        ASSERT(strstr(why, "synthetic") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_module_admit(void)
{
    int failures = 0;
    failures += test_admit_ok();
    failures += test_admit_abi_mismatch();
    failures += test_admit_missing_fields();
    failures += test_admit_allowlist();
    failures += test_admit_leaf_not_owned();
    failures += test_admit_selftest_fail();
    return failures;
}

static int test_swappable_allowlist(void)
{
    int failures = 0;
    TEST("hotswap_handler_is_swappable: allowlisted yes, everything else no") {
        ASSERT(hotswap_handler_is_swappable("core.status"));
        ASSERT(hotswap_handler_is_swappable("ops.metrics"));
        ASSERT(!hotswap_handler_is_swappable("core.consensus.pow.verify"));
        ASSERT(!hotswap_handler_is_swappable("app.jobs.reducer.advance"));
        ASSERT(!hotswap_handler_is_swappable(""));
        ASSERT(!hotswap_handler_is_swappable(NULL));
        PASS();
    } _test_next:;
    return failures;
}

/* ── Activation gate: -hotswap-activate flag + env + non-canonical datadir ── */

static int test_activation_gate(void)
{
    int failures = 0;
    TEST("activation is refused unless flag + env + exact dev datadir") {
        char tmpl[] = "/tmp/zcl_hs_gate_XXXXXX";
        char *home = mkdtemp(tmpl);
        ASSERT(home != NULL);
        char devdir[512], canondir[512];
        snprintf(devdir, sizeof(devdir), "%s/.zclassic-c23-dev", home);
        snprintf(canondir, sizeof(canondir), "%s/.zclassic-c23", home);
        ASSERT_EQ(mkdir(devdir, 0700), 0);
        ASSERT_EQ(mkdir(canondir, 0700), 0);

        char *saved_home = getenv("HOME");
        char saved_home_copy[512] = {0};
        if (saved_home) snprintf(saved_home_copy, sizeof(saved_home_copy), "%s", saved_home);
        setenv("HOME", home, 1);
        unsetenv("ZCL_HOTSWAP_ACTIVATE");
        hotswap_set_activate_flag(false);

        char why[256];

        /* No flag => refused. */
        why[0] = '\0';
        ASSERT(!hotswap_activation_authorized(devdir, why, sizeof(why)));
        ASSERT(strstr(why, "-hotswap-activate") != NULL);

        /* Flag but no env => refused. */
        hotswap_set_activate_flag(true);
        why[0] = '\0';
        ASSERT(!hotswap_activation_authorized(devdir, why, sizeof(why)));
        ASSERT(strstr(why, "ZCL_HOTSWAP_ACTIVATE") != NULL);

        /* Flag + env but canonical datadir => refused LOUDLY. */
        setenv("ZCL_HOTSWAP_ACTIVATE", "1", 1);
        why[0] = '\0';
        ASSERT(!hotswap_activation_authorized(canondir, why, sizeof(why)));
        ASSERT(strstr(why, "canonical") != NULL);

        /* Flag + env + non-dev arbitrary datadir => refused. */
        why[0] = '\0';
        ASSERT(!hotswap_activation_authorized("/tmp", why, sizeof(why)));

        /* Flag + env + exact dev datadir => AUTHORIZED. */
        why[0] = '\0';
        ASSERT(hotswap_activation_authorized(devdir, why, sizeof(why)));

        /* Restore global process state for sibling groups. */
        hotswap_set_activate_flag(false);
        unsetenv("ZCL_HOTSWAP_ACTIVATE");
        if (saved_home_copy[0]) setenv("HOME", saved_home_copy, 1);
        else unsetenv("HOME");
        rmdir(devdir);
        rmdir(canondir);
        rmdir(home);
        PASS();
    } _test_next:;
    return failures;
}

/* The loader TU (lib/hotswap/src/hotswap_activate.c) is compiled into the test
 * binaries with -DZCL_DEV_BUILD — and ONLY that TU — so `make t-hotswap` can
 * run a test group against a hot-swapped module through the SAME loader the
 * dev node runs, instead of relinking the whole harness for a one-file edit.
 * See the module-mode block in the Makefile beside TEST_FAST_OBJECT_CFLAGS.
 *
 * Every OTHER TU stays release-shaped, so the "this binary is not a dev build"
 * assertions elsewhere in the suite remain true.
 *
 * What must stay proven here is that the REAL loader still refuses before it
 * touches anything: a path outside the confinement set never reaches dlopen,
 * and a non-dev datadir is refused ahead of the authorization gate. */
static int test_loader_refuses_unconfined_input(void)
{
    int failures = 0;
    TEST("the real loader refuses an unconfined so_path at precheck") {
        struct hotswap_activate_report report;
        /* Absolute, .so-suffixed, but neither /tmp nor build/hotswap, and
         * nonexistent — refused before dlopen, with nothing published. */
        bool ok = hotswap_activate("/nonexistent/module.so", "/tmp", true,
                                   NULL, &report);
        ASSERT(!ok);
        ASSERT(!report.ok);
        ASSERT(!report.activated);
        ASSERT_EQ(strcmp(report.stage, "precheck"), 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_loader_refuses_non_dev_datadir(void)
{
    int failures = 0;
    TEST("the real loader refuses a datadir that is not the dev lane") {
        struct hotswap_activate_report report;
        bool ok = hotswap_activate("/tmp/whatever.so", "/tmp", true, NULL,
                                   &report);
        ASSERT(!ok);
        ASSERT(!report.ok);
        ASSERT(!report.activated);
        /* Either gate may speak first depending on whether the path exists;
         * both are precheck refusals and both publish zero leaves. */
        ASSERT_EQ(strcmp(report.stage, "precheck"), 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Live swap + epoch-quiesce drain (registry override layer) ─────────── */

static _Atomic int g_v1_calls = 0;
static _Atomic int g_v2_calls = 0;

static void h_v1(const struct zcl_command_request *request,
                 struct zcl_command_reply *reply)
{
    (void)request;
    atomic_fetch_add_explicit(&g_v1_calls, 1, memory_order_relaxed);
    (void)json_push_kv_str(&reply->data, "v", "v1");
}
static void h_v2(const struct zcl_command_request *request,
                 struct zcl_command_reply *reply)
{
    (void)request;
    atomic_fetch_add_explicit(&g_v2_calls, 1, memory_order_relaxed);
    (void)json_push_kv_str(&reply->data, "v", "v2");
}

static const struct zcl_command_spec g_mod_specs[] = {
    {
        .path = "hs.mod.read",
        .summary = "swappable read leaf",
        .layer = ZCL_COMMAND_LAYER_CORE,
        .effect = ZCL_COMMAND_EFFECT_READ,
        .availability = ZCL_COMMAND_READY,
        .mode = ZCL_COMMAND_MODE_SYNC,
        .allowed_lanes = ZCL_COMMAND_LANE_LOCAL,
        .handler = h_v1,
    },
};
static const struct zcl_command_registry g_mod_reg = {
    .commands = g_mod_specs,
    .count = sizeof(g_mod_specs) / sizeof(g_mod_specs[0]),
};

static enum zcl_command_exit mod_exec(char *out, size_t out_size)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    enum zcl_command_exit ec = ZCL_COMMAND_EXIT_INTERNAL;
    (void)zcl_command_registry_execute_json(&g_mod_reg, &g_mod_specs[0], NULL,
                                            &input, false, "hs.mod.read",
                                            "normal", 0, 0, NULL, out, out_size,
                                            &ec);
    json_free(&input);
    return ec;
}

static int test_live_swap_and_quiesce(void)
{
    int failures = 0;
    TEST("commit swaps the live handler; retired snapshot quiesces when idle") {
        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(&g_mod_reg);
        atomic_store(&g_v1_calls, 0);
        atomic_store(&g_v2_calls, 0);
        char out[4096];

        /* Baseline builtin handler. */
        ASSERT_EQ((int)mod_exec(out, sizeof(out)), (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"v\":\"v1\"") != NULL);

        /* Publish v1 override (generation 1). */
        struct zcl_command_handler_override o1 = { .path = "hs.mod.read", .handler = h_v1 };
        char why[256] = {0};
        ASSERT(zcl_command_registry_replace_batch(0, &o1, 1, why, sizeof(why)));

        /* No in-flight readers: every retired snapshot has drained. */
        ASSERT(zcl_command_registry_all_retired_quiesced());

        /* Swap to v2 (generation 2, retires the gen-1 snapshot). */
        struct zcl_command_handler_override o2 = { .path = "hs.mod.read", .handler = h_v2 };
        ASSERT(zcl_command_registry_replace_batch(0, &o2, 1, why, sizeof(why)));
        ASSERT_EQ((int)mod_exec(out, sizeof(out)), (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"v\":\"v2\"") != NULL);
        ASSERT(atomic_load(&g_v2_calls) >= 1);

        /* With readers idle the retired gen-1 snapshot has quiesced — a loader
         * would now be clear to dlclose the superseded .so. */
        ASSERT(zcl_command_registry_all_retired_quiesced());

        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Concurrent dispatch during swap: never garbage, quiesces after join ── */

#define MOD_HAMMER_ITERS 4000
#define MOD_HAMMER_READERS 6

static _Atomic bool g_mod_done = false;
static _Atomic int g_mod_torn = 0;

static void *mod_writer(void *arg)
{
    (void)arg;
    struct zcl_command_handler_override ovr = { .path = "hs.mod.read", .handler = h_v1 };
    for (uint32_t i = 1; i <= MOD_HAMMER_ITERS; i++) {
        ovr.handler = (i & 1u) ? h_v2 : h_v1;
        (void)zcl_command_registry_replace_batch(i, &ovr, 1, NULL, 0);
    }
    atomic_store_explicit(&g_mod_done, true, memory_order_release);
    return NULL;
}

static void *mod_reader(void *arg)
{
    (void)arg;
    char out[4096];
    while (!atomic_load_explicit(&g_mod_done, memory_order_acquire)) {
        if (mod_exec(out, sizeof(out)) != ZCL_COMMAND_EXIT_OK) {
            atomic_fetch_add_explicit(&g_mod_torn, 1, memory_order_relaxed);
            continue;
        }
        /* Every landed call must be exactly v1 or v2 — never torn/garbage. */
        bool marker = strstr(out, "\"v\":\"v1\"") != NULL ||
                      strstr(out, "\"v\":\"v2\"") != NULL;
        struct json_value parsed;
        json_init(&parsed);
        bool parses = json_read(&parsed, out, strlen(out));
        json_free(&parsed);
        if (!marker || !parses)
            atomic_fetch_add_explicit(&g_mod_torn, 1, memory_order_relaxed);
    }
    return NULL;
}

static int test_concurrent_swap_hammer(void)
{
    int failures = 0;
    TEST("N readers dispatch while a writer swaps: no garbage, drains after") {
        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(&g_mod_reg);
        atomic_store(&g_mod_done, false);
        atomic_store(&g_mod_torn, 0);

        pthread_t writer;
        pthread_t readers[MOD_HAMMER_READERS];
        ASSERT_EQ(pthread_create(&writer, NULL, mod_writer, NULL), 0);
        for (int i = 0; i < MOD_HAMMER_READERS; i++)
            ASSERT_EQ(pthread_create(&readers[i], NULL, mod_reader, NULL), 0);
        pthread_join(writer, NULL);
        for (int i = 0; i < MOD_HAMMER_READERS; i++)
            pthread_join(readers[i], NULL);

        ASSERT_EQ(atomic_load(&g_mod_torn), 0);
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)MOD_HAMMER_ITERS);
        /* All readers gone: every retired snapshot must have drained to zero,
         * so the epoch/refcount drain terminates (dlclose would be safe). */
        ASSERT(zcl_command_registry_all_retired_quiesced());

        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_hotswap_module(void);

int test_hotswap_module(void)
{
    int failures = 0;
    failures += test_module_admit();
    failures += test_swappable_allowlist();
    failures += test_activation_gate();
    failures += test_loader_refuses_unconfined_input();
    failures += test_loader_refuses_non_dev_datadir();
    failures += test_live_swap_and_quiesce();
    failures += test_concurrent_swap_hammer();
    zcl_command_registry_reset_overrides();
    zcl_command_registry_set_active(NULL);
    printf("=== hotswap_module: %d failures ===\n", failures);
    return failures;
}
