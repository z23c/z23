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
 *   5. room route ownership — repeated code.room summaries retain the exact
 *                      structured route after command lookup uses the stack.
 *   6. command feature room — one exact command root joins catalog leaves,
 *                      handler definitions, proof routes, and mixed-file
 *                      coupling without a second feature manifest.
 *   7. generated context map — the real tree has ten contexts, every
 *                      production file is classified, violations are explicit,
 *                      and compiler-depfile coupling is measured.
 *   8. budget           — the hub reply fits ZCL_COMMAND_LIST_BUDGET.
 *
 * All scratch work happens under ./test-tmp/ (project no-/tmp convention). */

#include "test/test_core.h"

#include "base/safe_alloc.h"
#include "codeindex/codeindex.h"
#include "command/native_command.h"
#include "kernel/command_registry.h"
#include "json/json.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CI_IMPACT_FIX "test-tmp/code_impact_fix"
#define CI_CONTEXT_PAGE_EDGES 257

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
        "core/modules/net/include/net/ci_hub.h",
        "#ifndef NET_CI_HUB_H\n#define NET_CI_HUB_H\n"
        "int ci_hub_fn(int x);\n#endif\n");

    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX, "core/modules/net/src/ci_hub.c",
        "/* core/modules/net/src/ci_hub.c — impact fixture hub. */\n"
        "#include \"net/ci_hub.h\"\n"
        "int ci_hub_fn(int x)\n{\n    return x + 1;\n}\n");
    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX, "build/obj/ci_hub.d",
        "build/obj/ci_hub.o: core/modules/net/src/ci_hub.c "
        "core/modules/net/include/net/ci_hub.h\n");

    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX, "core/modules/net/src/ci_caller_a.c",
        "#include \"net/ci_hub.h\"\n"
        "int ci_call_a(void)\n{\n    return ci_hub_fn(1);\n}\n");
    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX, "core/modules/net/src/ci_caller_b.c",
        "#include \"net/ci_hub.h\"\n"
        "int ci_call_b(void)\n{\n    return ci_hub_fn(2);\n}\n");
    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX, "core/modules/net/src/ci_caller_c.c",
        "#include \"net/ci_hub.h\"\n"
        "int ci_call_c(void)\n{\n    return ci_hub_fn(3);\n}\n");

    /* Second-level caller: calls ci_call_a() (defined in ci_caller_a.c), not
     * ci_hub_fn directly — proves the closure recurses past depth 1. */
    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX,
        "core/modules/net/include/net/ci_caller_a.h",
        "#ifndef NET_CI_CALLER_A_H\n#define NET_CI_CALLER_A_H\n"
        "int ci_call_a(void);\n#endif\n");
    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX, "core/modules/net/src/ci_caller_d.c",
        "#include \"net/ci_caller_a.h\"\n"
        "int ci_call_d(void)\n{\n    return ci_call_a();\n}\n");

    /* A file nothing calls: closure(it) == itself only. */
    ok = ok && ci_impact_mk_write(CI_IMPACT_FIX, "core/modules/net/src/ci_leaf.c",
        "/* core/modules/net/src/ci_leaf.c — impact fixture leaf (no callers). */\n"
        "int ci_leaf_fn(void)\n{\n    return 42;\n}\n");

    return ok;
}

static bool write_shape_overflow_fixture(void)
{
    for (int i = 0; i <= 48; i++) {
        char path[128];
        int n = snprintf(path, sizeof(path),
                         "contexts/wallet/extra_shape_%02d/src/item.c", i);
        if (n <= 0 || (size_t)n >= sizeof(path) ||
            !ci_impact_mk_write(CI_IMPACT_FIX, path,
                                "int context_shape_item(void) { return 1; }\n"))
            return false;
    }
    return true;
}

static bool write_context_paging_fixture(void)
{
    static const size_t depfile_cap = 32768;
    char *depfile = zcl_calloc(depfile_cap, 1,
                               "code_impact.context_paging_depfile");
    if (!depfile) return false;
    int wrote = snprintf(depfile, depfile_cap,
                         "build/obj/context_page.o: "
                         "lib/vcs/src/context_page.c");
    if (wrote <= 0 || (size_t)wrote >= depfile_cap) {
        free(depfile);
        return false;
    }
    size_t used = (size_t)wrote;
    bool ok = true;
    for (int i = 0; i < CI_CONTEXT_PAGE_EDGES; i++) {
        wrote = snprintf(depfile + used, depfile_cap - used,
                         " lib/net/include/net/page_%03d.h", i);
        if (wrote <= 0 || (size_t)wrote >= depfile_cap - used) {
            ok = false;
            break;
        }
        used += (size_t)wrote;
    }
    if (ok && used + 2 <= depfile_cap) {
        depfile[used++] = '\n';
        depfile[used] = '\0';
        ok = ci_impact_mk_write(
                 CI_IMPACT_FIX, "lib/vcs/src/context_page.c",
                 "int context_page_fixture(void) { return 1; }\n") &&
             ci_impact_mk_write(CI_IMPACT_FIX,
                                "build/obj/context_page.d", depfile);
    } else {
        ok = false;
    }
    free(depfile);
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

static void ci_room_call(const char *path, const char *source_root,
                         struct zcl_command_reply *reply)
{
    struct zcl_command_context ctx = { .source_root = source_root };
    struct json_value input;
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "path", path);
    struct zcl_command_request request = {
        .input = &input, .context = &ctx,
        .view = "normal", .invoked_name = "code.room",
    };
    zcl_command_reply_init(reply, "zcl.code_room.v1");
    zcl_native_handle_code_room(&request, reply);
    json_free(&input);
}

static void ci_context_map_call(const char *source_root,
                                struct zcl_command_reply *reply)
{
    struct zcl_command_context ctx = { .source_root = source_root };
    struct json_value input;
    json_init(&input); json_set_object(&input);
    struct zcl_command_request request = {
        .input = &input, .context = &ctx,
        .view = "normal", .invoked_name = "code.context-map",
    };
    zcl_command_reply_init(reply, "zcl.code_context_map.v1");
    zcl_native_handle_code_context_map(&request, reply);
    json_free(&input);
}

static bool json_array_has_string(const struct json_value *array,
                                  const char *wanted);

/* ── 1: hub fixture — 3 direct callers + 1 transitive, sorted, capped ── */
static int test_code_impact_hub(void)
{
    int failures = 0;
    TEST("code_impact: hub file closure = {itself, 3 direct callers, 1 "
         "transitive caller}, sorted, untruncated, direct_callers == 3") {
        system("rm -rf " CI_IMPACT_FIX);
        ASSERT(write_ci_impact_fixture());

        struct zcl_command_reply reply;
        ci_impact_call("core/modules/net/src/ci_hub.c", CI_IMPACT_FIX, &reply);

        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "path")),
                     "core/modules/net/src/ci_hub.c");

        const struct json_value *arr = json_get(&reply.data, "impacted_files");
        ASSERT(arr && arr->type == JSON_ARR);
        ASSERT(json_get_int(json_get(&reply.data, "count")) == 5);
        ASSERT(arr->num_children == 5);
        ASSERT(!json_get_bool(json_get(&reply.data, "truncated")));

        /* deterministic, sorted, unique — every fixture file present once. */
        static const char *const want[] = {
            "core/modules/net/src/ci_caller_a.c", "core/modules/net/src/ci_caller_b.c",
            "core/modules/net/src/ci_caller_c.c", "core/modules/net/src/ci_caller_d.c",
            "core/modules/net/src/ci_hub.c",
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

        /* The shared-rule resolver ran (same one code.tests/code.room use).
         * This core fixture is conservatively routed through consensus parity. */
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "route")),
                     "consensus_parity");
        ASSERT(json_get_bool(json_get(&reply.data, "consensus_risk")));
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
        ci_impact_call("core/modules/net/src/ci_leaf.c", CI_IMPACT_FIX, &reply);

        ASSERT(json_get_int(json_get(&reply.data, "count")) == 1);
        ASSERT(!json_get_bool(json_get(&reply.data, "truncated")));
        const struct json_value *arr = json_get(&reply.data, "impacted_files");
        ASSERT(arr && arr->num_children == 1);
        ASSERT_STR_EQ(json_get_str(&arr->children[0]), "core/modules/net/src/ci_leaf.c");
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
        ci_impact_call("core/modules/net/src/ci_does_not_exist.c", CI_IMPACT_FIX,
                       &reply);

        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        ASSERT(json_get_int(json_get(&reply.data, "count")) == 1);
        const struct json_value *arr = json_get(&reply.data, "impacted_files");
        ASSERT(arr && arr->num_children == 1);
        ASSERT_STR_EQ(json_get_str(&arr->children[0]),
                     "core/modules/net/src/ci_does_not_exist.c");

        zcl_command_reply_free(&reply);
        system("rm -rf " CI_IMPACT_FIX);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_room_route_storage(void)
{
    int failures = 0;
    TEST("code_room: summary retains its caller-owned route after command lookup") {
        system("rm -rf " CI_IMPACT_FIX);
        ASSERT(write_ci_impact_fixture());

        for (int i = 0; i < 16; i++) {
            struct zcl_command_reply reply;
            ci_room_call("core/modules/net/src/ci_hub.c", CI_IMPACT_FIX, &reply);
            const char *route = json_get_str(json_get(&reply.data, "route"));
            const char *summary =
                json_get_str(json_get(&reply.data, "summary"));
            char expected[96];
            ASSERT(route && route[0] && summary);
            ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "context")),
                          "core");
            ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "shape")),
                          "modules");
            ASSERT_STR_EQ(json_get_str(json_get(&reply.data,
                                                 "context_basis")),
                          "path_authority+module_manifest");
            ASSERT(!json_get_bool(json_get(&reply.data, "context_orphan")));
            ASSERT(!json_get_bool(json_get(&reply.data, "context_overlap")));
            int n = snprintf(expected, sizeof(expected), "tests→`%s`", route);
            ASSERT(n > 0 && (size_t)n < sizeof(expected));
            ASSERT(strstr(summary, expected) != NULL);
            zcl_command_reply_free(&reply);
        }

        system("rm -rf " CI_IMPACT_FIX);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_context_map(void)
{
    int failures = 0;
    TEST("code_context_map: real production tree is fully classified and "
         "reports exact violations and observed coupling") {
        struct zcl_command_reply reply;
        ci_context_map_call(".", &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);

        const struct json_value *taxonomy =
            json_get(&reply.data, "taxonomy");
        ASSERT(taxonomy && taxonomy->type == JSON_ARR &&
               taxonomy->num_children == 10);
        ASSERT(json_array_has_string(taxonomy, "wallet"));
        ASSERT(json_array_has_string(taxonomy, "explorer"));
        ASSERT(json_array_has_string(taxonomy, "naming"));
        ASSERT(json_array_has_string(taxonomy, "messaging"));
        ASSERT(json_array_has_string(taxonomy, "market"));
        ASSERT(json_array_has_string(taxonomy, "commons"));
        ASSERT(json_array_has_string(taxonomy, "cognition"));
        ASSERT(json_array_has_string(taxonomy, "engine"));
        ASSERT(json_array_has_string(taxonomy, "core"));
        ASSERT(json_array_has_string(taxonomy, "platform"));

        int production =
            json_get_int(json_get(&reply.data, "production_files"));
        ASSERT(production > 0);
        ASSERT(json_get_int(json_get(&reply.data, "classified_files")) ==
               production);
        ASSERT(json_get_int(json_get(&reply.data, "orphan_count")) == 0);
        const struct json_value *contexts =
            json_get(&reply.data, "contexts");
        const struct json_value *shapes = json_get(&reply.data, "shapes");
        ASSERT(contexts && contexts->type == JSON_ARR);
        ASSERT(shapes && shapes->type == JSON_ARR);
        int context_sum = 0, shape_sum = 0;
        for (size_t i = 0; i < contexts->num_children; i++)
            context_sum += json_get_int(json_get(&contexts->children[i],
                                                 "file_count"));
        for (size_t i = 0; i < shapes->num_children; i++)
            shape_sum += json_get_int(json_get(&shapes->children[i],
                                               "file_count"));
        ASSERT(context_sum == production);
        ASSERT(shape_sum == production);
        ASSERT(json_get_int(json_get(&reply.data, "overlap_count")) == 0);
        ASSERT(json_get_bool(json_get(&reply.data, "coupling_available")));
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "coupling_input_truncated")));
        ASSERT(json_get_int(json_get(&reply.data,
                                     "coupling_pair_count")) > 0);
        ASSERT(json_get_int(json_get(&reply.data,
                                     "observed_include_edges")) > 0);
        ASSERT(json_get_int(json_get(&reply.data,
                                     "cross_context_include_edges")) > 0);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "coupling_scope")),
                      "observed compiler-depfile include edges");
        const char *map_sha3 =
            json_get_str(json_get(&reply.data, "map_sha3"));
        ASSERT(map_sha3 && strlen(map_sha3) == 64);

        char buf[ZCL_COMMAND_LIST_BUDGET + 1];
        size_t n = json_write(&reply.data, buf, sizeof(buf));
        ASSERT(n > 0 && n <= ZCL_COMMAND_LIST_BUDGET);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_context_map_complete_pages(void)
{
    int failures = 0;
    TEST("code_context_map: coupling crosses the 256-edge page boundary and "
         "proves an exact short-page end") {
        system("rm -rf " CI_IMPACT_FIX);
        ASSERT(write_context_paging_fixture());

        struct codeindex *index = codeindex_open(CI_IMPACT_FIX);
        ASSERT(index != NULL);
        static char page[256][256];
        int first = codeindex_includes_of_file_page(
            index, "lib/vcs/src/context_page.c", 0, page, 256);
        ASSERT(first == 256);
        ASSERT_STR_EQ(page[0], "lib/net/include/net/page_000.h");
        ASSERT_STR_EQ(page[255], "lib/net/include/net/page_255.h");
        int second = codeindex_includes_of_file_page(
            index, "lib/vcs/src/context_page.c", 256, page, 256);
        ASSERT(second == 1);
        ASSERT_STR_EQ(page[0], "lib/net/include/net/page_256.h");
        int end = codeindex_includes_of_file_page(
            index, "lib/vcs/src/context_page.c", 257, page, 256);
        ASSERT(end == 0);
        codeindex_close(index);

        struct zcl_command_reply reply;
        ci_context_map_call(CI_IMPACT_FIX, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        ASSERT(json_get_bool(json_get(&reply.data, "coupling_available")));
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "coupling_input_truncated")));
        ASSERT(json_get_int(json_get(&reply.data,
                                     "observed_include_edges")) ==
               CI_CONTEXT_PAGE_EDGES);
        ASSERT(json_get_int(json_get(&reply.data,
                                     "cross_context_include_edges")) ==
               CI_CONTEXT_PAGE_EDGES);
        const struct json_value *couplings =
            json_get(&reply.data, "top_couplings");
        ASSERT(couplings && couplings->type == JSON_ARR &&
               couplings->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(&couplings->children[0], "from")),
                      "commons");
        ASSERT_STR_EQ(json_get_str(json_get(&couplings->children[0], "to")),
                      "core");
        ASSERT(json_get_int(json_get(&couplings->children[0],
                                     "edge_count")) ==
               CI_CONTEXT_PAGE_EDGES);
        zcl_command_reply_free(&reply);
        system("rm -rf " CI_IMPACT_FIX);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_context_map_shape_overflow(void)
{
    int failures = 0;
    TEST("code_context_map: shape overflow fails typed instead of claiming completeness") {
        system("rm -rf " CI_IMPACT_FIX);
        ASSERT(write_shape_overflow_fixture());
        struct zcl_command_reply reply;
        ci_context_map_call(CI_IMPACT_FIX, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "SHAPE_TAXONOMY_OVERFLOW");
        ASSERT(reply.error.message[0]);
        zcl_command_reply_free(&reply);
        system("rm -rf " CI_IMPACT_FIX);
        PASS();
    } _test_next:;
    return failures;
}

static bool json_array_has_string(const struct json_value *array,
                                  const char *wanted)
{
    if (!array || array->type != JSON_ARR || !wanted) return false;
    for (size_t i = 0; i < array->num_children; i++) {
        const char *value = json_get_str(&array->children[i]);
        if (value && strcmp(value, wanted) == 0) return true;
    }
    return false;
}

static int test_code_room_command_feature(void)
{
    int failures = 0;
    TEST("code_room: command feature root joins exact handlers and proof surface") {
        system("rm -rf " CI_IMPACT_FIX);
        ASSERT(write_ci_impact_fixture());
        struct zcl_command_reply incomplete;
        ci_room_call("app.messaging", CI_IMPACT_FIX, &incomplete);
        ASSERT(json_get_int(json_get(&incomplete.data,
                                     "handler_unindexed")) > 0);
        ASSERT(!json_get_bool(json_get(
            &incomplete.data, "shared_handler_file_command_count_complete")));
        zcl_command_reply_free(&incomplete);
        system("rm -rf " CI_IMPACT_FIX);

        static const char *const roots[] = {
            "core.wallet", "app.names", "app.market", "app.messaging",
            "zcode.commons", "zcode.package.dev",
        };
        for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
            struct zcl_command_reply root_reply;
            ci_room_call(roots[i], ".", &root_reply);
            ASSERT(root_reply.status != ZCL_COMMAND_STATUS_FAILED);
            ASSERT(json_get_bool(json_get(&root_reply.data, "found")));
            ASSERT_STR_EQ(json_get_str(json_get(&root_reply.data, "room_kind")),
                          "command_feature");
            ASSERT(json_get_int(json_get(&root_reply.data, "command_count")) >
                   1);
            char root_buf[ZCL_COMMAND_LIST_BUDGET + 1];
            size_t root_n = json_write(&root_reply.data, root_buf,
                                       sizeof(root_buf));
            ASSERT(root_n > 0 && root_n <= ZCL_COMMAND_LIST_BUDGET);
            zcl_command_reply_free(&root_reply);
        }

        struct zcl_command_reply reply;
        ci_room_call("app.messaging", ".", &reply);

        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        ASSERT(json_get_bool(json_get(&reply.data, "found")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "room_kind")),
                      "command_feature");
        ASSERT(json_get_int(json_get(&reply.data, "command_count")) == 5);
        ASSERT(json_array_has_string(json_get(&reply.data, "commands"),
                                     "app.messaging.send"));
        ASSERT(json_array_has_string(json_get(&reply.data, "commands"),
                                     "app.messaging.send-named"));
        ASSERT(json_array_has_string(
            json_get(&reply.data, "handler_symbols"),
            "zcl_native_handle_message_send"));
        ASSERT(json_array_has_string(
            json_get(&reply.data, "implementation_files"),
            "engine/controllers/src/app_write_native_handlers.c"));
        ASSERT(json_array_has_string(
            json_get(&reply.data, "implementation_groups"),
            "engine/controllers"));
        ASSERT(json_get_bool(json_get(&reply.data,
                                      "implementation_complete")));
        ASSERT(json_get_int(json_get(
            &reply.data, "shared_handler_file_command_count")) > 0);
        ASSERT(json_get(&reply.data, "test_groups") != NULL);
        ASSERT(strstr(json_get_str(json_get(&reply.data, "implementation_scope")),
                      "UNKNOWN") != NULL);

        char buf[ZCL_COMMAND_LIST_BUDGET + 1];
        size_t n = json_write(&reply.data, buf, sizeof(buf));
        ASSERT(n > 0 && n <= ZCL_COMMAND_LIST_BUDGET);
        zcl_command_reply_free(&reply);
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
                      "git push origin HEAD:main") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data,
                                             "legacy_parity_command")),
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
    failures += test_code_room_route_storage();
    failures += test_code_room_command_feature();
    failures += test_code_context_map();
    failures += test_code_context_map_complete_pages();
    failures += test_code_context_map_shape_overflow();
    failures += test_code_guide();
    return failures;
}
