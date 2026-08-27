/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The trampoline thesis, asserted.
 *
 * config/hotswap_eligible.def documents the escape hatch that keeps a hot-swap
 * module from cloning process state: "The resident half (atomic provider slot,
 * boot-populated main_state, ...) lives in a sibling NON-eligible trampoline
 * TU." app/controllers/src/policy_native_handlers.c is the first low-level
 * decision surface built that way, and this group holds the split honest:
 *
 *   1. the swappable leaf is a PURE decision — it answers from its arguments
 *      and compiled-in constants with no node, no datadir, no RPC and no
 *      wall-clock, which is what makes it dispatchable as its own
 *      probe-before-publish case in-process;
 *   2. the mutable state it reports lives in the resident sibling and is
 *      observed, not copied — the property a generation .so would break;
 *   3. the manifests agree with each other: the swappable row, the island
 *      member (the frozen policy table itself), the declared probe leaf, and
 *      the resident-owned probe case;
 *   4. the loader's admit gauntlet REFUSES a module that misdeclares itself.
 *
 * Nothing here dlopens: hotswap_module_admit() compiles in EVERY build, so the
 * whole gauntlet is drivable with fabricated modules.
 */

#include "test/test_helpers.h"

#include "config/command_catalog.h"
#include "controllers/policy_native_handlers.h"
#include "controllers/policy_native_resident.h"
#include "hotswap/hotswap_module.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "vcs/package_policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define POLICY_TU "app/controllers/src/policy_native_handlers.c"
#define POLICY_RESIDENT_TU "app/controllers/src/policy_native_resident.c"
#define POLICY_LEAF "zcode.package.policy.limits"
#define POLICY_ISLAND "lib/vcs/src/package_policy.c"
#define POLICY_SCHEMA "zcl.zcode_package_policy_limits.v1"

/* Parse one body render into a JSON object. Returns false (having freed) on a
 * malformed body so a caller asserts the shape rather than crashing. */
static bool policy_body_json(const char *body, struct json_value *out)
{
    if (!body)
        return false;
    if (!json_read(out, body, strlen(body))) {
        json_free(out);
        return false;
    }
    if (out->type != JSON_OBJ) {
        json_free(out);
        return false;
    }
    return true;
}

/* Render the leaf with an argument object built from `json_text`. */
static char *policy_render(const char *json_text,
                           struct zcl_native_body_err *err)
{
    struct json_value args;
    json_init(&args);
    if (!json_read(&args, json_text, strlen(json_text))) {
        json_free(&args);
        return NULL;
    }
    char *body = zcl_native_policy_limits_body(&args, err);
    json_free(&args);
    return body;
}

/* ── 1. the leaf is a pure decision, computable with no node ─────────────── */

static int t_empty_input_renders_the_free_allowance(void)
{
    int failures = 0;
    TEST("policy leaf: an empty argument object renders the free allowance "
         "from compiled-in constants alone") {
        struct zcl_native_body_err err = { 0 };
        char *body = policy_render("{}", &err);
        ASSERT(body != NULL);
        ASSERT_EQ((int)err.status, (int)ZCL_NATIVE_BODY_OK);

        struct json_value doc;
        ASSERT(policy_body_json(body, &doc));
        free(body);

        /* No top-level "error" key: zcl_native_bridge_run treats one as a
         * failure, so a probe case could never pass if the pure path made
         * one. */
        ASSERT(json_get(&doc, "error") == NULL);
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "tier")), "new-user");
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "tier_source")), "derived");

        const struct vcs_policy_limits *free_row =
            vcs_policy_limits_for(VCS_POLICY_TIER_NEW_USER);
        ASSERT_EQ(json_get_int(json_get(&doc, "publish_per_week")),
                  (int64_t)free_row->publish_per_week);
        ASSERT_EQ(json_get_int(json_get(&doc, "weekly_download_bytes")),
                  (int64_t)free_row->weekly_download_bytes);
        /* The owner-directive invariant the module self-test also guards. */
        ASSERT(free_row->weekly_download_bytes > 0);
        ASSERT(free_row->publish_per_week > 0);
        json_free(&doc);
        PASS();
    } _test_next:;
    return failures;
}

static int t_facts_derive_the_tier(void)
{
    int failures = 0;
    TEST("policy leaf: earned score plus verified byte counters derive the "
         "seeder tier with no other input") {
        struct zcl_native_body_err err = { 0 };
        /* 600 earned score and 512 MiB served against 1 MiB taken clears
         * every seeder gate, so the derived tier must be the seeder row. */
        char *body = policy_render(
            "{\"earned_score\":600,\"uploaded_bytes\":536870912,"
            "\"downloaded_bytes\":1048576}", &err);
        ASSERT(body != NULL);
        struct json_value doc;
        ASSERT(policy_body_json(body, &doc));
        free(body);
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "tier")), "verified-seeder");
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "tier_source")), "derived");
        ASSERT_EQ(json_get_int(json_get(&doc, "ratio_milli")),
                  (int64_t)vcs_policy_ratio_milli(536870912u, 1048576u));
        json_free(&doc);
        PASS();
    } _test_next:;
    return failures;
}

static int t_declared_tier_overrides_the_facts(void)
{
    int failures = 0;
    TEST("policy leaf: an explicitly named tier overrides the derived one and "
         "says so") {
        struct zcl_native_body_err err = { 0 };
        char *body = policy_render(
            "{\"tier\":\"new-user\",\"earned_score\":600}", &err);
        ASSERT(body != NULL);
        struct json_value doc;
        ASSERT(policy_body_json(body, &doc));
        free(body);
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "tier")), "new-user");
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "tier_source")), "declared");
        json_free(&doc);
        PASS();
    } _test_next:;
    return failures;
}

static int t_unknown_tier_is_typed_invalid(void)
{
    int failures = 0;
    TEST("policy leaf: an unknown tier is a typed INVALID, never a silent "
         "fallback to the free row") {
        struct zcl_native_body_err err = { 0 };
        char *body = policy_render("{\"tier\":\"platinum\"}", &err);
        ASSERT(body == NULL);
        ASSERT_EQ((int)err.status, (int)ZCL_NATIVE_BODY_INVALID);
        ASSERT(strstr(err.message, "platinum") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2. the resident half is observed, never copied ──────────────────────── */

static int t_resident_state_is_singular(void)
{
    int failures = 0;
    TEST("trampoline: the leaf reports the RESIDENT counters, so a generation "
         "that cloned them would be visible") {
        zcl_native_policy_resident_mark_boot();
        ASSERT(zcl_native_policy_resident_booted());

        uint64_t before = zcl_native_policy_resident_dispatches();
        struct zcl_native_body_err err = { 0 };
        char *body = policy_render("{}", &err);
        ASSERT(body != NULL);
        struct json_value doc;
        ASSERT(policy_body_json(body, &doc));
        free(body);

        /* The flag is set by the resident process, never by the leaf. A
         * module .so holding its own zero-initialized copy answers false. */
        ASSERT(json_get_bool(json_get(&doc, "resident_booted")));
        ASSERT_EQ(json_get_int(json_get(&doc, "resident_dispatches")),
                  (int64_t)(before + 1u));
        json_free(&doc);

        /* And the resident counter advanced — the leaf wrote through to the
         * one copy rather than into a private static of its own. */
        ASSERT_EQ((int64_t)zcl_native_policy_resident_dispatches(),
                  (int64_t)(before + 1u));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. the manifests agree ──────────────────────────────────────────────── */

static int t_manifest_rows_resolve_to_one_owner(void)
{
    int failures = 0;
    TEST("manifests: the swappable row, the island member and the declared "
         "probe leaf all resolve to one owning TU") {
        ASSERT(hotswap_source_is_swappable(POLICY_TU));
        ASSERT(hotswap_handler_is_swappable(POLICY_LEAF));
        ASSERT_STR_EQ(hotswap_swappable_source_for_leaf(POLICY_LEAF),
                      POLICY_TU);
        ASSERT_STR_EQ(hotswap_module_probe_leaf(POLICY_TU), POLICY_LEAF);
        /* The frozen policy table travels INSIDE the module, so editing the
         * rule itself takes effect from a single-TU rebuild. A leaf body or
         * decision table outside the island would be imported from the
         * resident node at dlopen and the swap would silently do nothing. */
        ASSERT_STR_EQ(hotswap_island_owner_for_path(POLICY_ISLAND), POLICY_TU);
        const char *members = hotswap_island_members_for_source(POLICY_TU);
        ASSERT(members != NULL);
        ASSERT(strstr(members, POLICY_ISLAND) != NULL);
        /* The resident half is deliberately absent from every manifest. */
        ASSERT(!hotswap_source_is_swappable(POLICY_RESIDENT_TU));
        ASSERT(hotswap_island_owner_for_path(POLICY_RESIDENT_TU) == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int t_probe_case_is_hermetic(void)
{
    int failures = 0;
    TEST("probe case: the resident owns a HERMETIC case for this leaf — empty "
         "input, so no node and no datadir can be required") {
        const struct zcl_hotswap_probe_case *probe =
            hotswap_module_probe_case(POLICY_TU);
        ASSERT(probe != NULL);
        ASSERT_STR_EQ(probe->kind, "command");
        ASSERT_STR_EQ(probe->operation, POLICY_LEAF);
        ASSERT_STR_EQ(probe->canonical_input_json, "{}");
        ASSERT_STR_EQ(probe->expected_schema, POLICY_SCHEMA);
        ASSERT(probe->byte_budget > 0);
        /* Resolving by operation must find the same, single case. */
        ASSERT(hotswap_probe_case_for_operation(POLICY_LEAF) == probe);
        PASS();
    } _test_next:;
    return failures;
}

static int t_probe_case_matches_the_registry(void)
{
    int failures = 0;
    TEST("catalog: the probe case's contract matches what the registry "
         "declares, so the loader's schema and budget checks can succeed") {
        const struct zcl_hotswap_probe_case *probe =
            hotswap_probe_case_for_operation(POLICY_LEAF);
        ASSERT(probe != NULL);
        bool was_alias = true;
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), POLICY_LEAF,
                                      &was_alias);
        ASSERT(spec != NULL);
        ASSERT(!was_alias);
        ASSERT_EQ((int)spec->availability, (int)ZCL_COMMAND_READY);
        ASSERT_EQ((int)spec->effect, (int)ZCL_COMMAND_EFFECT_READ);
        ASSERT_STR_EQ(spec->output_schema, probe->expected_schema);
        ASSERT(spec->budget_bytes > 0);
        ASSERT(probe->byte_budget <= (size_t)spec->budget_bytes);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. the gauntlet still refuses ───────────────────────────────────────── */

static void policy_stub_handler(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    (void)request;
    (void)json_push_kv_str(&reply->data, "who", "policy_module_stub");
}

static bool policy_selftest_ok(char *err, size_t cap)
{
    (void)err;
    (void)cap;
    return true;
}

static bool policy_selftest_fail(char *err, size_t cap)
{
    if (err && cap)
        snprintf(err, cap, "free allowance violated");
    return false;
}

/* Build one fabricated module over `leaf` for `source_tu`. */
static struct zcl_hotswap_module policy_module(
    const char *source_tu, const struct zcl_hotswap_leaf *leaves,
    uint32_t abi, bool (*self_test)(char *, size_t))
{
    struct zcl_hotswap_module m = {
        .abi_version = abi,
        .source_tu = source_tu,
        .leaf_count = 1,
        .leaves = leaves,
        .self_test = self_test,
        /* The sealed-core sections a module built from THIS tree declares. */
        .core_sections = hotswap_core_sections_self(),
    };
    return m;
}

static int t_admit_accepts_the_honest_module(void)
{
    int failures = 0;
    TEST("admit: the honest module — right TU, its own leaf, current ABI — is "
         "admitted") {
        const struct zcl_hotswap_leaf leaves[] = {
            { POLICY_LEAF, policy_stub_handler },
        };
        struct zcl_hotswap_module m = policy_module(
            POLICY_TU, leaves, ZCL_HOTSWAP_MODULE_ABI_V3, policy_selftest_ok);
        char stage[64] = { 0 }, why[256] = { 0 };
        ASSERT(hotswap_module_admit(&m, stage, sizeof(stage), why,
                                    sizeof(why)));
        PASS();
    } _test_next:;
    return failures;
}

static int t_admit_refuses_a_foreign_leaf(void)
{
    int failures = 0;
    TEST("admit: a module claiming a leaf its own file does not own is "
         "refused at stage=allowlist") {
        const struct zcl_hotswap_leaf leaves[] = {
            { "core.status", policy_stub_handler },
        };
        struct zcl_hotswap_module m = policy_module(
            POLICY_TU, leaves, ZCL_HOTSWAP_MODULE_ABI_V3, policy_selftest_ok);
        char stage[64] = { 0 }, why[256] = { 0 };
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why,
                                     sizeof(why)));
        ASSERT_STR_EQ(stage, "allowlist");
        PASS();
    } _test_next:;
    return failures;
}

static int t_admit_refuses_the_resident_half(void)
{
    int failures = 0;
    TEST("admit: a module stamped with the RESIDENT sibling — the TU that owns "
         "the mutable state — is refused at stage=allowlist") {
        const struct zcl_hotswap_leaf leaves[] = {
            { POLICY_LEAF, policy_stub_handler },
        };
        struct zcl_hotswap_module m = policy_module(
            POLICY_RESIDENT_TU, leaves, ZCL_HOTSWAP_MODULE_ABI_V3,
            policy_selftest_ok);
        char stage[64] = { 0 }, why[256] = { 0 };
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why,
                                     sizeof(why)));
        ASSERT_STR_EQ(stage, "allowlist");
        PASS();
    } _test_next:;
    return failures;
}

static int t_admit_refuses_a_failing_self_test(void)
{
    int failures = 0;
    TEST("admit: a module whose own self-test fails is refused at "
         "stage=self_test, before any leaf is published") {
        const struct zcl_hotswap_leaf leaves[] = {
            { POLICY_LEAF, policy_stub_handler },
        };
        struct zcl_hotswap_module m = policy_module(
            POLICY_TU, leaves, ZCL_HOTSWAP_MODULE_ABI_V3, policy_selftest_fail);
        char stage[64] = { 0 }, why[256] = { 0 };
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why,
                                     sizeof(why)));
        ASSERT_STR_EQ(stage, "self_test");
        ASSERT(strstr(why, "free allowance") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int t_admit_refuses_the_old_abi(void)
{
    int failures = 0;
    TEST("admit: an ABI v1 module is refused at stage=abi before any field "
         "but abi_version is read") {
        const struct zcl_hotswap_leaf leaves[] = {
            { POLICY_LEAF, policy_stub_handler },
        };
        struct zcl_hotswap_module m = policy_module(
            POLICY_TU, leaves, ZCL_HOTSWAP_MODULE_ABI_V1, policy_selftest_ok);
        char stage[64] = { 0 }, why[256] = { 0 };
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why,
                                     sizeof(why)));
        ASSERT_STR_EQ(stage, "abi");
        PASS();
    } _test_next:;
    return failures;
}

int test_hotswap_policy_module(void)
{
    int failures = 0;
    failures += t_empty_input_renders_the_free_allowance();
    failures += t_facts_derive_the_tier();
    failures += t_declared_tier_overrides_the_facts();
    failures += t_unknown_tier_is_typed_invalid();
    failures += t_resident_state_is_singular();
    failures += t_manifest_rows_resolve_to_one_owner();
    failures += t_probe_case_is_hermetic();
    failures += t_probe_case_matches_the_registry();
    failures += t_admit_accepts_the_honest_module();
    failures += t_admit_refuses_a_foreign_leaf();
    failures += t_admit_refuses_the_resident_half();
    failures += t_admit_refuses_a_failing_self_test();
    failures += t_admit_refuses_the_old_abi();
    printf("=== hotswap_policy_module: %d failures ===\n", failures);
    return failures;
}
