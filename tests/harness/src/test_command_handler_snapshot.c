/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the kernel hot-swap leaf-handler override snapshot layer
 * (engine/modules/kernel/src/command_registry.c). This is the KERNEL half of the
 * command-registry hot-swap target: an atomic, all-or-nothing {path,handler}
 * override snapshot with batch replacement one layer down.
 *
 * Coverage:
 *   - install + dispatch-through-override (execute_json runs the override)
 *   - fallback-when-absent (unswapped leaves keep the catalog handler)
 *   - batch atomicity (a failing path leaves NOTHING installed)
 *   - destructive/mutating and not-READY and alias leaves are rejected
 *   - generation monotonicity
 *   - a publish reports ITS OWN generation (no read-after-write race); a
 *     refusal neither advances it nor writes the out-parameter
 *   - two-thread hammer (writer replace_batch loop + reader dispatch loop)
 */

#include "test/test_core.h"

#include "kernel/command_registry.h"
#include "json/json.h"

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

/* ── Fixture handlers ────────────────────────────────────────────── */

static _Atomic int g_base_calls = 0;
static _Atomic int g_override_calls = 0;

static void h_base(const struct zcl_command_request *request,
                   struct zcl_command_reply *reply)
{
    (void)request;
    atomic_fetch_add_explicit(&g_base_calls, 1, memory_order_relaxed);
    (void)json_push_kv_str(&reply->data, "who", "base");
}

static void h_override(const struct zcl_command_request *request,
                       struct zcl_command_reply *reply)
{
    (void)request;
    atomic_fetch_add_explicit(&g_override_calls, 1, memory_order_relaxed);
    (void)json_push_kv_str(&reply->data, "who", "override");
}

/* A minimal, well-formed leaf registry. Two READ leaves (swap targets), one
 * MUTATE leaf and one PLANNED leaf (rejection targets). LANE_LOCAL so a NULL
 * context is allowed; no required capabilities. */
static const struct zcl_command_spec g_specs[] = {
    {
        .path = "core.probe.read",
        .summary = "read probe leaf",
        .aliases = "probe-read",
        .layer = ZCL_COMMAND_LAYER_CORE,
        .effect = ZCL_COMMAND_EFFECT_READ,
        .availability = ZCL_COMMAND_READY,
        .mode = ZCL_COMMAND_MODE_SYNC,
        .allowed_lanes = ZCL_COMMAND_LANE_LOCAL,
        .handler = h_base,
    },
    {
        .path = "core.probe.read2",
        .summary = "second read probe leaf",
        .layer = ZCL_COMMAND_LAYER_CORE,
        .effect = ZCL_COMMAND_EFFECT_READ,
        .availability = ZCL_COMMAND_READY,
        .mode = ZCL_COMMAND_MODE_SYNC,
        .allowed_lanes = ZCL_COMMAND_LANE_LOCAL,
        .handler = h_base,
    },
    {
        .path = "core.probe.write",
        .summary = "mutating probe leaf",
        .layer = ZCL_COMMAND_LAYER_CORE,
        .effect = ZCL_COMMAND_EFFECT_MUTATE,
        .availability = ZCL_COMMAND_READY,
        .mode = ZCL_COMMAND_MODE_SYNC,
        .allowed_lanes = ZCL_COMMAND_LANE_LOCAL,
        .handler = h_base,
    },
    {
        .path = "core.probe.planned",
        .summary = "planned probe leaf",
        .layer = ZCL_COMMAND_LAYER_CORE,
        .effect = ZCL_COMMAND_EFFECT_READ,
        .availability = ZCL_COMMAND_PLANNED,
        .mode = ZCL_COMMAND_MODE_SYNC,
        .allowed_lanes = ZCL_COMMAND_LANE_LOCAL,
        .availability_reason = "not implemented",
        .handler = NULL,
    },
    {
        /* Mirrors the ZCL_COMMAND_BRANCH() macro shape exactly
         * (engine/composition/src/command_catalog.c): availability=READY,
         * effect=READ, mode=BRANCH, handler=NULL. A branch would slip
         * past the READY+READ checks if the mode weren't checked too. */
        .path = "core.probe.branch",
        .summary = "branch probe node (no handler)",
        .layer = ZCL_COMMAND_LAYER_CORE,
        .effect = ZCL_COMMAND_EFFECT_READ,
        .availability = ZCL_COMMAND_READY,
        .mode = ZCL_COMMAND_MODE_BRANCH,
        .allowed_lanes = ZCL_COMMAND_LANE_LOCAL,
        .handler = NULL,
    },
};

static const struct zcl_command_registry g_reg = {
    .commands = g_specs,
    .count = sizeof(g_specs) / sizeof(g_specs[0]),
};

static const struct zcl_command_spec *find_spec(const char *path)
{
    for (size_t i = 0; i < g_reg.count; i++)
        if (strcmp(g_reg.commands[i].path, path) == 0)
            return &g_reg.commands[i];
    return NULL;
}

/* Dispatch a leaf through the registry; returns the exit code + raw envelope. */
static enum zcl_command_exit exec_path(const char *path, char *out,
                                       size_t out_size)
{
    const struct zcl_command_spec *spec = find_spec(path);
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    (void)zcl_command_registry_execute_json(&g_reg, spec, NULL, &input, false,
                                            path, "normal", 0, 0, NULL, out,
                                            out_size, &exit_code);
    json_free(&input);
    return exit_code;
}

static void reset_fixture(void)
{
    zcl_command_registry_reset_overrides();
    zcl_command_registry_set_active(&g_reg);
    atomic_store_explicit(&g_base_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&g_override_calls, 0, memory_order_relaxed);
}

/* ── Tests ───────────────────────────────────────────────────────── */

static int test_install_and_dispatch(void)
{
    int failures = 0;
    TEST("override install re-points the live dispatch handler") {
        reset_fixture();
        char out[4096];

        /* Baseline: catalog handler runs. */
        ASSERT_EQ((int)exec_path("core.probe.read", out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"who\":\"base\"") != NULL);
        ASSERT_EQ(atomic_load(&g_base_calls), 1);
        ASSERT_EQ(atomic_load(&g_override_calls), 0);

        /* Install the override and dispatch again. */
        struct zcl_command_handler_override ovr = {
            .path = "core.probe.read", .handler = h_override,
        };
        char why[256] = {0};
        ASSERT(zcl_command_registry_replace_batch(0, &ovr, 1, why,
                                                 sizeof(why), NULL));
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(), 1u);

        ASSERT_EQ((int)exec_path("core.probe.read", out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"who\":\"override\"") != NULL);
        ASSERT_EQ(atomic_load(&g_override_calls), 1);
        ASSERT_EQ(atomic_load(&g_base_calls), 1); /* base NOT re-entered */

        /* effective-handler accessor agrees. */
        ASSERT(zcl_command_registry_effective_handler(
                   find_spec("core.probe.read")) == h_override);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fallback_when_absent(void)
{
    int failures = 0;
    TEST("unswapped leaves keep the immutable catalog handler") {
        reset_fixture();
        char out[4096];

        /* Swap read but NOT read2. */
        struct zcl_command_handler_override ovr = {
            .path = "core.probe.read", .handler = h_override,
        };
        ASSERT(zcl_command_registry_replace_batch(0, &ovr, 1, NULL, 0, NULL));

        ASSERT_EQ((int)exec_path("core.probe.read2", out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"who\":\"base\"") != NULL);
        ASSERT_EQ(atomic_load(&g_base_calls), 1);

        ASSERT(zcl_command_registry_effective_handler(
                   find_spec("core.probe.read2")) == h_base);
        PASS();
    } _test_next:;
    return failures;
}

static int test_batch_atomicity(void)
{
    int failures = 0;
    TEST("a failing path leaves NOTHING from the batch installed") {
        reset_fixture();
        char out[4096];

        /* Batch: a valid read override + a nonexistent leaf. Must all-or-
         * nothing REJECT, installing neither. */
        struct zcl_command_handler_override batch[] = {
            { .path = "core.probe.read", .handler = h_override },
            { .path = "core.probe.does_not_exist", .handler = h_override },
        };
        char why[256] = {0};
        ASSERT(!zcl_command_registry_replace_batch(0, batch, 2, why,
                                                   sizeof(why), NULL));
        ASSERT(why[0] != '\0');
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(), 0u);

        /* The good half must NOT have leaked in. */
        ASSERT_EQ((int)exec_path("core.probe.read", out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"who\":\"base\"") != NULL);
        ASSERT_EQ(atomic_load(&g_override_calls), 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_reject_ineligible_leaves(void)
{
    int failures = 0;
    TEST("mutating / not-READY / alias / null leaves are rejected") {
        reset_fixture();
        char why[256];

        /* Mutating leaf. */
        struct zcl_command_handler_override mut = {
            .path = "core.probe.write", .handler = h_override,
        };
        why[0] = '\0';
        ASSERT(!zcl_command_registry_replace_batch(0, &mut, 1, why,
                                                   sizeof(why), NULL));
        ASSERT(strstr(why, "mutating") != NULL ||
               strstr(why, "destructive") != NULL);

        /* Not-READY (PLANNED) leaf. */
        struct zcl_command_handler_override planned = {
            .path = "core.probe.planned", .handler = h_override,
        };
        why[0] = '\0';
        ASSERT(!zcl_command_registry_replace_batch(0, &planned, 1, why,
                                                   sizeof(why), NULL));
        ASSERT(strstr(why, "READY") != NULL);

        /* Alias (not a canonical path). */
        struct zcl_command_handler_override alias = {
            .path = "probe-read", .handler = h_override,
        };
        why[0] = '\0';
        ASSERT(!zcl_command_registry_replace_batch(0, &alias, 1, why,
                                                   sizeof(why), NULL));

        /* NULL handler. */
        struct zcl_command_handler_override nullh = {
            .path = "core.probe.read", .handler = NULL,
        };
        why[0] = '\0';
        ASSERT(!zcl_command_registry_replace_batch(0, &nullh, 1, why,
                                                   sizeof(why), NULL));

        /* None of these mutated the active snapshot. */
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(), 0u);
        PASS();
    } _test_next:;
    return failures;
}

static int test_reject_branch_leaf(void)
{
    int failures = 0;
    TEST("a branch leaf (NULL handler, mode=BRANCH) is rejected, not swappable") {
        reset_fixture();
        char why[256];

        struct zcl_command_handler_override branch = {
            .path = "core.probe.branch", .handler = h_override,
        };
        why[0] = '\0';
        ASSERT(!zcl_command_registry_replace_batch(0, &branch, 1, why,
                                                   sizeof(why), NULL));
        ASSERT(strstr(why, "branch") != NULL);
        ASSERT(strstr(why, "core.probe.branch") != NULL);

        /* Nothing installed. */
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(), 0u);
        ASSERT(zcl_command_registry_effective_handler(
                   find_spec("core.probe.branch")) == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_generation_monotonicity(void)
{
    int failures = 0;
    TEST("generation must strictly increase") {
        reset_fixture();
        struct zcl_command_handler_override ovr = {
            .path = "core.probe.read", .handler = h_override,
        };
        char why[256] = {0};

        /* Auto-increment from 0 -> 1. */
        ASSERT(zcl_command_registry_replace_batch(0, &ovr, 1, why,
                                                 sizeof(why), NULL));
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(), 1u);

        /* Explicit stale generation (== active) is rejected. */
        why[0] = '\0';
        ASSERT(!zcl_command_registry_replace_batch(1, &ovr, 1, why,
                                                   sizeof(why), NULL));
        ASSERT(strstr(why, "not newer") != NULL);
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(), 1u);

        /* Explicit jump forward. */
        ASSERT(zcl_command_registry_replace_batch(5, &ovr, 1, NULL, 0, NULL));
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(), 5u);

        /* Auto-increment continues from the active generation. */
        ASSERT(zcl_command_registry_replace_batch(0, &ovr, 1, NULL, 0, NULL));
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(), 6u);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Two-thread hammer ───────────────────────────────────────────── */

#define HAMMER_ITERS 4000
#define HAMMER_READERS 4

static _Atomic bool g_hammer_done = false;
static _Atomic int g_hammer_torn = 0;

static void *hammer_writer(void *arg)
{
    (void)arg;
    struct zcl_command_handler_override ovr = {
        .path = "core.probe.read", .handler = h_override,
    };
    for (uint32_t i = 1; i <= HAMMER_ITERS; i++) {
        /* Strictly increasing generation => always succeeds; alternate the
         * handler so readers can observe either the base or the override. */
        ovr.handler = (i & 1u) ? h_override : h_base;
        (void)zcl_command_registry_replace_batch(i, &ovr, 1, NULL, 0, NULL);
    }
    atomic_store_explicit(&g_hammer_done, true, memory_order_release);
    return NULL;
}

static void *hammer_reader(void *arg)
{
    (void)arg;
    char out[4096];
    while (!atomic_load_explicit(&g_hammer_done, memory_order_acquire)) {
        enum zcl_command_exit ec = exec_path("core.probe.read", out,
                                             sizeof(out));
        if (ec != ZCL_COMMAND_EXIT_OK) {
            atomic_fetch_add_explicit(&g_hammer_torn, 1, memory_order_relaxed);
            continue;
        }
        /* The envelope must always parse (never a torn/freed table) and carry
         * exactly one of the two known handler markers. */
        struct json_value parsed;
        json_init(&parsed);
        bool ok = json_read(&parsed, out, strlen(out));
        json_free(&parsed);
        bool marker = strstr(out, "\"who\":\"base\"") != NULL ||
                      strstr(out, "\"who\":\"override\"") != NULL;
        if (!ok || !marker)
            atomic_fetch_add_explicit(&g_hammer_torn, 1, memory_order_relaxed);
    }
    return NULL;
}


/* The publish reports ITS OWN generation.
 *
 * Callers used to publish and then call zcl_command_registry_active_generation()
 * to learn "which generation did my batch produce". That read-after-write is a
 * race: a concurrent publisher can bump the active generation in between, and
 * the caller then attributes another publisher's snapshot to its own batch.
 * The out-parameter is written under the same write lock that assigns the
 * generation, so it can only ever be this call's own value.
 *
 * This pins three things: a successful publish reports a generation, that
 * generation is strictly greater than the generation active before the call
 * (monotonicity is load-bearing — it is the ordering authority for the whole
 * hot-swap subsystem), and a REFUSED publish neither advances the generation
 * nor writes the out-parameter. */
static int test_publish_reports_own_generation(void)
{
    int failures = 0;
    TEST("replace_batch reports the generation it published") {
        reset_fixture();
        struct zcl_command_handler_override ovr = {
            .path = "core.probe.read", .handler = h_override,
        };
        char why[256] = {0};

        /* First publish onto an empty override layer. */
        uint32_t before = zcl_command_registry_active_generation();
        ASSERT_EQ((unsigned)before, 0u);
        uint32_t reported = 0;
        ASSERT(zcl_command_registry_replace_batch(0, &ovr, 1, why,
                                                 sizeof(why), &reported));
        ASSERT(reported > before);
        ASSERT_EQ((unsigned)reported,
                  (unsigned)zcl_command_registry_active_generation());

        /* Every further publish reports a strictly greater generation, both
         * for auto-increment and for an explicit forward jump. */
        for (int i = 0; i < 4; i++) {
            uint32_t prev = reported;
            uint32_t next = 0;
            ASSERT(zcl_command_registry_replace_batch(0, &ovr, 1, why,
                                                     sizeof(why), &next));
            ASSERT(next > prev);
            reported = next;
        }
        uint32_t jumped = 0;
        ASSERT(zcl_command_registry_replace_batch(reported + 100u, &ovr, 1,
                                                 why, sizeof(why), &jumped));
        ASSERT_EQ((unsigned)jumped, (unsigned)(reported + 100u));
        ASSERT(jumped > reported);
        reported = jumped;

        /* REFUSED at the generation check (inside the write lock): the active
         * generation does not move and the out-parameter keeps its sentinel. */
        uint32_t untouched = 0xDEADBEEFu;
        why[0] = '\0';
        ASSERT(!zcl_command_registry_replace_batch(reported, &ovr, 1, why,
                                                  sizeof(why), &untouched));
        ASSERT(strstr(why, "not newer") != NULL);
        ASSERT_EQ((unsigned)untouched, 0xDEADBEEFu);
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)reported);

        /* REFUSED at batch validation (before the write lock is ever taken):
         * same contract — no advance, no write. */
        struct zcl_command_handler_override bad = {
            .path = "core.probe.nope", .handler = h_override,
        };
        untouched = 0xFEEDFACEu;
        why[0] = '\0';
        ASSERT(!zcl_command_registry_replace_batch(0, &bad, 1, why,
                                                  sizeof(why), &untouched));
        ASSERT_EQ((unsigned)untouched, 0xFEEDFACEu);
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)reported);

        /* A REFUSED mutating leaf behaves identically. */
        struct zcl_command_handler_override mut = {
            .path = "core.probe.write", .handler = h_override,
        };
        untouched = 0xA5A5A5A5u;
        why[0] = '\0';
        ASSERT(!zcl_command_registry_replace_batch(0, &mut, 1, why,
                                                  sizeof(why), &untouched));
        ASSERT_EQ((unsigned)untouched, 0xA5A5A5A5u);
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)reported);

        /* A caller that does not want the generation still publishes fine. */
        ASSERT(zcl_command_registry_replace_batch(0, &ovr, 1, NULL, 0, NULL));
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)(reported + 1u));
        PASS();
    } _test_next:;
    return failures;
}

static int test_concurrent_hammer(void)
{
    int failures = 0;
    TEST("writer replace_batch loop + reader dispatch loop: no torn read") {
        reset_fixture();
        atomic_store_explicit(&g_hammer_done, false, memory_order_relaxed);
        atomic_store_explicit(&g_hammer_torn, 0, memory_order_relaxed);

        pthread_t writer;
        pthread_t readers[HAMMER_READERS];
        ASSERT_EQ(pthread_create(&writer, NULL, hammer_writer, NULL), 0);
        for (int i = 0; i < HAMMER_READERS; i++)
            ASSERT_EQ(pthread_create(&readers[i], NULL, hammer_reader, NULL), 0);

        pthread_join(writer, NULL);
        for (int i = 0; i < HAMMER_READERS; i++)
            pthread_join(readers[i], NULL);

        ASSERT_EQ(atomic_load(&g_hammer_torn), 0);
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)HAMMER_ITERS);
        PASS();
    } _test_next:;
    return failures;
}

int test_command_handler_snapshot(void)
{
    int failures = 0;
    failures += test_install_and_dispatch();
    failures += test_fallback_when_absent();
    failures += test_batch_atomicity();
    failures += test_reject_ineligible_leaves();
    failures += test_reject_branch_leaf();
    failures += test_generation_monotonicity();
    failures += test_publish_reports_own_generation();
    failures += test_concurrent_hammer();
    /* Leave the override layer clean for any sibling group sharing the TU. */
    zcl_command_registry_reset_overrides();
    zcl_command_registry_set_active(NULL);
    printf("=== command_handler_snapshot: %d failures ===\n", failures);
    return failures;
}
