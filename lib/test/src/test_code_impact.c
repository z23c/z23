/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * code.impact contract: the blast-radius leaf — the reverse-dependency
 * closure of one changed file (codeindex_impact_closure), the downstream
 * focused test groups via the SAME agent_impact_apply_shared_rules()
 * resolver code.tests/devloop_plan.c use, and the two quick depth-1 fan-out
 * numbers (direct_includes, direct_callers).
 *
 * Coverage:
 *   1. hub fixture   — a file with three direct callers plus one
 *                      second-level (transitive) caller: impacted_files ==
 *                      {itself, the three direct callers, the transitive
 *                      caller} sorted, count == 5, not truncated,
 *                      direct_callers == 3, direct_includes == 1 (its own
 *                      header, from the depfile), route/test_groups wired
 *                      through the shared resolver.
 *   2. leaf fixture  — a file nothing calls: impacted_files == {itself}
 *                      only, count == 1, truncated == false,
 *                      direct_callers == 0.
 *   3. missing path input — MISSING_PATH error body, never a bare failure.
 *   4. unknown file        — not found is never an error (mirrors
 *                      codeindex_impact_closure's own contract): closure of
 *                      a path absent from the index is itself only.
 *   5. budget           — the hub reply fits ZCL_COMMAND_LIST_BUDGET.
 *
 * All scratch work happens under ./test-tmp/ (project no-/tmp convention). */

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "command/native_command.h"
#include "kernel/command_registry.h"
#include "json/json.h"

#include <stddef.h>
#include <string.h>
#include <sys/stat.h>

#define CI_IMPACT_FIX "test-tmp/code_impact_fix"

static bool ci_impact_mk_write(const char *dir, const char *rel,
                               const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(full, 0755); *p = '/'; }
    }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    if (content && content[0]) fwrite(content, 1, strlen(content), f);
    fclose(f);
    return true;
}

/* ── fixture: ci_hub.c (3 direct callers + 1 transitive caller) plus
 * ci_leaf.c (nothing calls it) ── */
static bool write_ci_impact_fixture(void)
{
    bool ok = true;

    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX,
        "lib/net/include/net/ci_hub.h",
        "#ifndef NET_CI_HUB_H\n#define NET_CI_HUB_H\n"
        "int ci_hub_fn(int x);\n#endif\n");

    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX, "lib/net/src/ci_hub.c",
        "/* lib/net/src/ci_hub.c — impact fixture hub. */\n"
        "#include \"net/ci_hub.h\"\n"
        "int ci_hub_fn(int x)\n{\n    return x + 1;\n}\n");
    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX, "build/obj/ci_hub.d",
        "build/obj/ci_hub.o: lib/net/src/ci_hub.c "
        "lib/net/include/net/ci_hub.h\n");

    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX, "lib/net/src/ci_caller_a.c",
        "#include \"net/ci_hub.h\"\n"
        "int ci_call_a(void)\n{\n    return ci_hub_fn(1);\n}\n");
    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX, "lib/net/src/ci_caller_b.c",
        "#include \"net/ci_hub.h\"\n"
        "int ci_call_b(void)\n{\n    return ci_hub_fn(2);\n}\n");
    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX, "lib/net/src/ci_caller_c.c",
        "#include \"net/ci_hub.h\"\n"
        "int ci_call_c(void)\n{\n    return ci_hub_fn(3);\n}\n");

    /* Second-level caller: calls ci_call_a() (defined in ci_caller_a.c), not
     * ci_hub_fn directly — proves the closure recurses past depth 1. */
    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX,
        "lib/net/include/net/ci_caller_a.h",
        "#ifndef NET_CI_CALLER_A_H\n#define NET_CI_CALLER_A_H\n"
        "int ci_call_a(void);\n#endif\n");
    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX, "lib/net/src/ci_caller_d.c",
        "#include \"net/ci_caller_a.h\"\n"
        "int ci_call_d(void)\n{\n    return ci_call_a();\n}\n");

    /* A file nothing calls: closure(it) == itself only. */
    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX, "lib/net/src/ci_leaf.c",
        "/* lib/net/src/ci_leaf.c — impact fixture leaf (no callers). */\n"
        "int ci_leaf_fn(void)\n{\n    return 42;\n}\n");

    return ok;
}

static void ci_impact_call(const char *path, const char *source_root,
                           struct zcl_command_reply *reply)
{
    struct zcl_command_context ctx = { .source_root = source_root };
    struct json_value input;
    json_init(&input); json_set_object(&input);
    if (path) (void)json_push_kv_str(&input, "path", path);
    struct zcl_command_request request = {
        .input = &input, .context = source_root ? &ctx : NULL,
        .view = "normal", .invoked_name = "code.impact",
    };
    zcl_command_reply_init(reply, "zcl.code_impact.v1");
    zcl_native_handle_code_impact(&request, reply);
    json_free(&input);
}

/* ── 1: hub fixture — 3 direct callers + 1 transitive, sorted, capped ── */
static int test_code_impact_hub(void)
{
    int failures = 0;
    TEST("code_impact: hub file closure = {itself, 3 direct callers, 1 "
         "transitive caller}, sorted, untruncated, direct_callers == 3") {
        system("rm -rf " CI_IMPACT_FIX);
        ASSERT(write_ci_impact_fixture());

        struct zcl_command_reply reply;
        ci_impact_call("lib/net/src/ci_hub.c", CI_IMPACT_FIX, &reply);

        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "path")),
                     "lib/net/src/ci_hub.c");

        const struct json_value *arr = json_get(&reply.data, "impacted_files");
        ASSERT(arr && arr->type == JSON_ARR);
        ASSERT(json_get_int(json_get(&reply.data, "count")) == 5);
        ASSERT(arr->num_children == 5);
        ASSERT(!json_get_bool(json_get(&reply.data, "truncated")));

        /* deterministic, sorted, unique — every fixture file present once. */
        static const char *const want[] = {
            "lib/net/src/ci_caller_a.c", "lib/net/src/ci_caller_b.c",
            "lib/net/src/ci_caller_c.c", "lib/net/src/ci_caller_d.c",
            "lib/net/src/ci_hub.c",
        };
        bool sorted_and_complete = true;
        for (size_t i = 0; i < 5; i++) {
            if (strcmp(json_get_str(&arr->children[i]), want[i]) != 0) {
                sorted_and_complete = false;
                break;
            }
        }
        ASSERT(sorted_and_complete);

        /* direct fan-out: exactly the 3 call sites into ci_hub_fn itself
         * (ci_caller_d.c calls ci_call_a(), not ci_hub_fn, so it is NOT a
         * direct caller — only reachable via the full closure walk). */
        ASSERT(json_get_int(json_get(&reply.data, "direct_callers")) == 3);

        /* direct_includes: ci_hub.c's own depfile lists one in-tree header. */
        ASSERT(json_get_int(json_get(&reply.data, "direct_includes")) == 1);

        /* the shared-rule resolver ran (same one code.tests/code.room use);
         * these fixture paths match no real repo rule and are not a
         * consensus-risk prefix, so the deterministic fallback fires. */
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "route")),
                     "make_lint_gates");
        ASSERT(!json_get_bool(json_get(&reply.data, "consensus_risk")));
        const struct json_value *groups = json_get(&reply.data, "test_groups");
        ASSERT(groups && groups->type == JSON_ARR);

        const char *summary = json_get_str(json_get(&reply.data, "summary"));
        ASSERT(summary && summary[0]);

        /* the reply fits the leaf's declared list budget. */
        char buf[8192];
        size_t n = json_write(&reply.data, buf, sizeof(buf));
        ASSERT(n > 0 && n < sizeof(buf) && n <= ZCL_COMMAND_LIST_BUDGET);

        zcl_command_reply_free(&reply);
        system("rm -rf " CI_IMPACT_FIX);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2: leaf fixture — nothing calls it, closure is itself only ── */
static int test_code_impact_leaf(void)
{
    int failures = 0;
    TEST("code_impact: leaf file with no callers closes over itself only") {
        system("rm -rf " CI_IMPACT_FIX);
        ASSERT(write_ci_impact_fixture());

        struct zcl_command_reply reply;
        ci_impact_call("lib/net/src/ci_leaf.c", CI_IMPACT_FIX, &reply);

        ASSERT(json_get_int(json_get(&reply.data, "count")) == 1);
        ASSERT(!json_get_bool(json_get(&reply.data, "truncated")));
        const struct json_value *arr = json_get(&reply.data, "impacted_files");
        ASSERT(arr && arr->num_children == 1);
        ASSERT_STR_EQ(json_get_str(&arr->children[0]), "lib/net/src/ci_leaf.c");
        ASSERT(json_get_int(json_get(&reply.data, "direct_callers")) == 0);
        ASSERT(json_get_int(json_get(&reply.data, "direct_includes")) == 0);

        zcl_command_reply_free(&reply);
        system("rm -rf " CI_IMPACT_FIX);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3: missing path input — a typed error body, never a bare failure ── */
static int test_code_impact_missing_path(void)
{
    int failures = 0;
    TEST("code_impact: missing path input sets a typed MISSING_PATH error") {
        struct zcl_command_reply reply;
        ci_impact_call(NULL, NULL, &reply);

        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "MISSING_PATH");
        ASSERT(reply.error.message[0]);

        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4: unknown path — not found is never an error (closure of {itself}) ── */
static int test_code_impact_unknown_path(void)
{
    int failures = 0;
    TEST("code_impact: a path absent from the index is not an error — "
         "closure is itself only, mirroring codeindex_impact_closure") {
        system("rm -rf " CI_IMPACT_FIX);
        ASSERT(write_ci_impact_fixture());

        struct zcl_command_reply reply;
        ci_impact_call("lib/net/src/ci_does_not_exist.c", CI_IMPACT_FIX,
                       &reply);

        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        ASSERT(json_get_int(json_get(&reply.data, "count")) == 1);
        const struct json_value *arr = json_get(&reply.data, "impacted_files");
        ASSERT(arr && arr->num_children == 1);
        ASSERT_STR_EQ(json_get_str(&arr->children[0]),
                     "lib/net/src/ci_does_not_exist.c");

        zcl_command_reply_free(&reply);
        system("rm -rf " CI_IMPACT_FIX);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_guide(void)
{
    int failures = 0;
    TEST("code.guide names the inner loop and refuses extra input") {
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        struct zcl_command_request request;
        memset(&request, 0, sizeof(request));
        request.input = &input;
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.test.code_guide.v1");
        zcl_native_handle_code_guide(&request, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "start_command")),
                      "z23 code impact <file.c>") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "lint_command")),
                      "make lint-fast") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "push_command")),
                      "make pre-push-ci") == 0);
        ASSERT(strstr(json_get_str(json_get(&reply.data, "never")),
                      "test_zcl") != NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "path", "x.c"));
        memset(&request, 0, sizeof(request));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.code_guide.v1");
        zcl_native_handle_code_guide(&request, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "BAD_CODE_GUIDE_INPUT");
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

int test_code_impact(void)
{
    int failures = 0;
    failures += test_code_impact_hub();
    failures += test_code_impact_leaf();
    failures += test_code_impact_missing_path();
    failures += test_code_impact_unknown_path();
    failures += test_code_guide();
    return failures;
}
