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
#include "controllers/agent_impact_rules.h"
#include "controllers/agent_impact_harness.h"
#include "platform/glob_match.h"
#include "command/native_command.h"
#include "kernel/command_registry.h"
#include "json/json.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <utime.h>

#define CI_IMPACT_FIX "test-tmp/code_impact_fix"
#define CI_CONTEXT_PAGE_EDGES 257
#define CI_CONTEXT_WARM_FIX "test-tmp/code_context_warm_fix"

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
                         "contexts/commons/modules/vcs/src/context_page.c");
    if (wrote <= 0 || (size_t)wrote >= depfile_cap) {
        free(depfile);
        return false;
    }
    size_t used = (size_t)wrote;
    bool ok = true;
    for (int i = 0; i < CI_CONTEXT_PAGE_EDGES; i++) {
        char header[96];
        int header_len = snprintf(header, sizeof(header),
                                  "core/modules/net/include/net/page_%03d.h", i);
        if (header_len <= 0 || (size_t)header_len >= sizeof(header) ||
            !ci_impact_mk_write(CI_IMPACT_FIX, header, "/* paging edge */\n")) {
            ok = false;
            break;
        }
        wrote = snprintf(depfile + used, depfile_cap - used,
                         " core/modules/net/include/net/page_%03d.h", i);
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
                 CI_IMPACT_FIX,
                 "contexts/commons/modules/vcs/src/context_page.c",
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
 TEST_DISCARD(system("rm -rf " CI_IMPACT_FIX));
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
 TEST_DISCARD(system("rm -rf " CI_IMPACT_FIX));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2: leaf fixture — nothing calls it, closure is itself only ── */
static int test_code_impact_leaf(void)
{
    int failures = 0;
    TEST("code_impact: leaf file with no callers closes over itself only") {
 TEST_DISCARD(system("rm -rf " CI_IMPACT_FIX));
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
 TEST_DISCARD(system("rm -rf " CI_IMPACT_FIX));
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
 TEST_DISCARD(system("rm -rf " CI_IMPACT_FIX));
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
 TEST_DISCARD(system("rm -rf " CI_IMPACT_FIX));
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_room_route_storage(void)
{
    int failures = 0;
    TEST("code_room: summary retains its caller-owned route after command lookup") {
 TEST_DISCARD(system("rm -rf " CI_IMPACT_FIX));
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

 TEST_DISCARD(system("rm -rf " CI_IMPACT_FIX));
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
 TEST_DISCARD(system("rm -rf " CI_IMPACT_FIX));
        ASSERT(write_context_paging_fixture());

        struct codeindex *index = codeindex_open(CI_IMPACT_FIX);
        ASSERT(index != NULL);
        static char page[256][256];
        int first = codeindex_includes_of_file_page(
            index, "contexts/commons/modules/vcs/src/context_page.c",
            0, page, 256);
        ASSERT(first == 256);
        ASSERT_STR_EQ(page[0], "core/modules/net/include/net/page_000.h");
        ASSERT_STR_EQ(page[255], "core/modules/net/include/net/page_255.h");
        int second = codeindex_includes_of_file_page(
            index, "contexts/commons/modules/vcs/src/context_page.c",
            256, page, 256);
        ASSERT(second == 1);
        ASSERT_STR_EQ(page[0], "core/modules/net/include/net/page_256.h");
        int end = codeindex_includes_of_file_page(
            index, "contexts/commons/modules/vcs/src/context_page.c",
            257, page, 256);
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
 TEST_DISCARD(system("rm -rf " CI_IMPACT_FIX));
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_context_map_shape_overflow(void)
{
    int failures = 0;
    TEST("code_context_map: shape overflow fails typed instead of claiming completeness") {
 TEST_DISCARD(system("rm -rf " CI_IMPACT_FIX));
        ASSERT(write_shape_overflow_fixture());
        struct zcl_command_reply reply;
        ci_context_map_call(CI_IMPACT_FIX, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "SHAPE_TAXONOMY_OVERFLOW");
        ASSERT(reply.error.message[0]);
        zcl_command_reply_free(&reply);
 TEST_DISCARD(system("rm -rf " CI_IMPACT_FIX));
        PASS();
    } _test_next:;
    return failures;
}

static int ci_context_count(const struct zcl_command_reply *reply,
                            const char *context)
{
    const struct json_value *rows = json_get(&reply->data, "contexts");
    if (!rows || rows->type != JSON_ARR) return -1;
    for (size_t i = 0; i < rows->num_children; i++) {
        const char *name =
            json_get_str(json_get(&rows->children[i], "context"));
        if (name && strcmp(name, context) == 0)
            return (int)json_get_int(json_get(&rows->children[i],
                                              "file_count"));
    }
    return -1;
}

/* The warm map is derived data. A second dispatch may reuse it only while
 * the index generation it was derived from is the one just opened: a
 * depfile-only edit (same sources, same file count) or a rename across
 * contexts (same file count) republishes the index, and the map must follow
 * that generation rather than the file count. */
static int test_code_context_map_warm_follows_generation(void)
{
    int failures = 0;
    TEST("code_context_map: a warm map follows a depfile-only edit and a "
         "same-count rename instead of serving the previous generation") {
 TEST_DISCARD(system("rm -rf " CI_CONTEXT_WARM_FIX));
        ASSERT(ci_impact_mk_write(CI_CONTEXT_WARM_FIX,
            "contexts/commons/modules/vcs/src/warm_a.c",
            "int warm_a(void) { return 1; }\n"));
        ASSERT(ci_impact_mk_write(CI_CONTEXT_WARM_FIX,
            "core/modules/net/include/net/warm_b.h",
            "int warm_b(void);\n"));
        ASSERT(ci_impact_mk_write(CI_CONTEXT_WARM_FIX, "build/obj/warm_a.d",
            "build/obj/warm_a.o: contexts/commons/modules/vcs/src/warm_a.c\n"));

        struct zcl_command_reply reply;
        ci_context_map_call(CI_CONTEXT_WARM_FIX, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        ASSERT(json_get_int(json_get(&reply.data,
                                     "cross_context_include_edges")) == 0);
        int files = (int)json_get_int(json_get(&reply.data,
                                               "indexed_files"));
        ASSERT(files > 0);
        zcl_command_reply_free(&reply);
        uint8_t source_before[32], dep_before[32];
        struct codeindex *index = codeindex_open(CI_CONTEXT_WARM_FIX);
        ASSERT(index != NULL);
        ASSERT(codeindex_source_root_sha3(index, source_before));
        ASSERT(codeindex_dep_root_sha3(index, dep_before));
        codeindex_close(index);

        /* Depfile-only: the compiler now reports the core header. */
        ASSERT(ci_impact_mk_write(CI_CONTEXT_WARM_FIX, "build/obj/warm_a.d",
            "build/obj/warm_a.o: contexts/commons/modules/vcs/src/warm_a.c "
            "core/modules/net/include/net/warm_b.h\n"));
        ci_context_map_call(CI_CONTEXT_WARM_FIX, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        ASSERT(json_get_int(json_get(&reply.data, "indexed_files")) == files);
        ASSERT(json_get_int(json_get(&reply.data,
                                     "cross_context_include_edges")) == 1);
        zcl_command_reply_free(&reply);
        uint8_t source_after[32], dep_after[32];
        index = codeindex_open(CI_CONTEXT_WARM_FIX);
        ASSERT(index != NULL);
        ASSERT(codeindex_source_root_sha3(index, source_after));
        ASSERT(codeindex_dep_root_sha3(index, dep_after));
        codeindex_close(index);
        ASSERT(memcmp(source_before, source_after, 32) == 0);
        ASSERT(memcmp(dep_before, dep_after, 32) != 0);

        /* Same-count rename across contexts: commons -> wallet. */
        ASSERT(ci_impact_mk_write(CI_CONTEXT_WARM_FIX,
            "contexts/wallet/modules/wallet/src/warm_a.c",
            "int warm_a(void) { return 1; }\n"));
        ASSERT(remove(CI_CONTEXT_WARM_FIX
                      "/contexts/commons/modules/vcs/src/warm_a.c") == 0);
        ASSERT(ci_impact_mk_write(CI_CONTEXT_WARM_FIX, "build/obj/warm_a.d",
            "build/obj/warm_a.o: contexts/wallet/modules/wallet/src/warm_a.c "
            "core/modules/net/include/net/warm_b.h\n"));
        ci_context_map_call(CI_CONTEXT_WARM_FIX, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        ASSERT(json_get_int(json_get(&reply.data, "indexed_files")) == files);
        ASSERT(ci_context_count(&reply, "wallet") == 1);
        ASSERT(ci_context_count(&reply, "commons") == 0);
        zcl_command_reply_free(&reply);

        /* Unchanged generation: the warm answer is the same answer. */
        ci_context_map_call(CI_CONTEXT_WARM_FIX, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        ASSERT(ci_context_count(&reply, "wallet") == 1);
        ASSERT(json_get_int(json_get(&reply.data,
                                     "cross_context_include_edges")) == 1);
        zcl_command_reply_free(&reply);
 TEST_DISCARD(system("rm -rf " CI_CONTEXT_WARM_FIX));
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
 TEST_DISCARD(system("rm -rf " CI_IMPACT_FIX));
        ASSERT(write_ci_impact_fixture());
        struct zcl_command_reply incomplete;
        ci_room_call("app.messaging", CI_IMPACT_FIX, &incomplete);
        ASSERT(json_get_int(json_get(&incomplete.data,
                                     "handler_unindexed")) > 0);
        ASSERT(!json_get_bool(json_get(
            &incomplete.data, "shared_handler_file_command_count_complete")));
        zcl_command_reply_free(&incomplete);
 TEST_DISCARD(system("rm -rf " CI_IMPACT_FIX));

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

static int test_code_route_completeness(void)
{
    int failures = 0;
    TEST("code.tests distinguishes capped groups from a complete small or empty route") {
        const char *paths[] = {"tools/command/native_devagent.c",
                              "tests/harness/src/test_zcode_policy.c",
                              "zz_no_impact_rule_fixture.c"};
        for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
            struct agent_impact_acc acc = {0};
            bool consensus = false;
            const char *route = zcl_native_code_route_for_path(paths[i], &acc, &consensus);
            struct json_value input;
            json_init(&input);
            json_set_object(&input);
            ASSERT(json_push_kv_str(&input, "path", paths[i]));
            struct zcl_command_request request = {0};
            request.input = &input;
            struct zcl_command_reply reply;
            zcl_command_reply_init(&reply, "zcl.code_tests.v1");
            zcl_native_handle_code_tests(&request, &reply);
            ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
            const struct json_value *count = json_get(&reply.data, "test_groups_retained_count");
            const struct json_value *lost = json_get(&reply.data, "test_groups_lost");
            const struct json_value *truncated = json_get(&reply.data, "test_groups_truncated");
            ASSERT(count && count->type == JSON_INT);
            ASSERT(lost && lost->type == JSON_BOOL);
            ASSERT(truncated && truncated->type == JSON_BOOL);
            ASSERT_EQ(json_get_int(count), (int64_t)acc.groups_len);
            ASSERT_EQ(json_get_bool(lost), acc.groups_lost);
            const struct json_value *groups = json_get(&reply.data, "test_groups");
            ASSERT_EQ(json_size(groups), acc.groups_len < 12 ? acc.groups_len : 12);
            ASSERT_EQ(json_get_bool(truncated), acc.groups_len > 12 || acc.groups_lost);
            ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "route")), route);
            ASSERT_EQ(json_get_bool(json_get(&reply.data, "consensus_risk")), consensus);
            for (size_t g = 0; g < json_size(groups); g++)
                ASSERT_STR_EQ(json_get_str(json_at(groups, g)), acc.groups[g]);
            ASSERT(json_write(&reply.data, NULL, 0) <= ZCL_COMMAND_RESULT_BUDGET);
            if (i == 0)
                ASSERT(acc.groups_len > 12);
            if (i == 2)
                ASSERT_EQ(acc.groups_len, 0u);
            zcl_command_reply_free(&reply);
            json_free(&input);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_route_consumer_bounds(void)
{
    int failures = 0;
    TEST("all five shared route consumers retain completeness metadata within reply bounds") {
        TEST_DISCARD(system("rm -rf " CI_IMPACT_FIX));
        ASSERT(write_ci_impact_fixture());
        const struct {
            void (*handle)(const struct zcl_command_request *, struct zcl_command_reply *);
            const char *key, *value;
        } cases[] = {
            {zcl_native_handle_code_tests, "path", "core/modules/net/src/ci_hub.c"},
            {zcl_native_handle_code_file, "path", "core/modules/net/src/ci_hub.c"},
            {zcl_native_handle_code_impact, "path", "core/modules/net/src/ci_hub.c"},
            {zcl_native_handle_code_room, "path", "core/modules/net/src/ci_hub.c"},
            {zcl_native_handle_code_capsule, "name", "ci_hub_fn"}
        };
        struct zcl_command_context context = {.source_root = CI_IMPACT_FIX};
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            struct json_value input;
            json_init(&input); json_set_object(&input);
            ASSERT(json_push_kv_str(&input, cases[i].key, cases[i].value));
            struct zcl_command_request request = {.input = &input, .context = &context, .view = "normal"};
            struct zcl_command_reply reply;
            zcl_command_reply_init(&reply, "zcl.test.route.v1");
            cases[i].handle(&request, &reply);
            ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
            const struct json_value *count = json_get(&reply.data, "test_groups_retained_count");
            const struct json_value *lost = json_get(&reply.data, "test_groups_lost");
            const struct json_value *truncated = json_get(&reply.data, "test_groups_truncated");
            ASSERT(count && count->type == JSON_INT);
            ASSERT(lost && lost->type == JSON_BOOL);
            ASSERT(truncated && truncated->type == JSON_BOOL);
            ASSERT(!json_get_bool(lost));
            ASSERT(!json_get_bool(truncated));
            ASSERT_EQ(json_get_int(count), (int64_t)json_size(json_get(&reply.data, "test_groups")));
            ASSERT(json_write(&reply.data, NULL, 0) <= ZCL_COMMAND_RESULT_BUDGET);
            zcl_command_reply_free(&reply);
            json_free(&input);
        }
        TEST_DISCARD(system("rm -rf " CI_IMPACT_FIX));
        PASS();
    } _test_next:;
    return failures;
}

static bool impact_has_group(const struct agent_impact_acc *acc, const char *group)
{
    for (size_t i = 0; i < acc->groups_len; i++)
        if (strcmp(acc->groups[i], group) == 0)
            return true;
    return false;
}

static int test_code_devagent_routes(void)
{
    int failures = 0;
    TEST("code routes prioritize devagent leaf proofs while retaining the complete shared-rule union") {
        static const struct { const char *file, *group, *extra; } cases[] = {
            {"native_devagent.c", "devagent_surface", "command_input_bounds"},
            {"native_devagent_situation.c", "devagent_situation", "command_input_bounds"},
            {"native_devagent_usage.c", "devagent_outcomes", ""},
            {"native_devagent_reviewscore.c", "devagent_reviewscore", ""},
            {"native_devagent_rules.c", "devagent_rules", "command_input_bounds"},
            {"native_devagent_start.c", "devagent_start", "command_input_bounds"},
            {"native_devagent_claim.c", "devagent_claim", "command_input_bounds"},
            {"native_devagent_done.c", "devagent_done", "command_input_bounds"},
            {"native_devagent_triage.c", "devagent_triage", "command_input_bounds"},
            {"native_devagent_ceiling.c", "devagent_ceiling", "command_input_bounds"},
            {"native_devagent_pace.c", "devagent_pace", "command_input_bounds"},
            {"native_devagent_ticketkey.c", "devagent_ticketkey", "command_input_bounds"}
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            char path[160];
            snprintf(path, sizeof(path), "tools/command/%s", cases[i].file);
            struct agent_impact_acc actual = {0}, shared = {0}, expected = {0};
            bool consensus = false;
            const char *route = zcl_native_code_route_for_path(path, &actual, &consensus);
            ASSERT(!consensus);
            ASSERT_STR_EQ(route, cases[i].group);
            agent_impact_add_group_list(&expected, "make_lint_gates command_registry_catalog native_api_contract command_handler_snapshot hotswap_module dev_platform");
            agent_impact_add_group(&expected, cases[i].group);
            agent_impact_add_group_list(&expected, cases[i].extra);
            ASSERT(agent_impact_apply_shared_rules(path, &shared));
            ASSERT_EQ(shared.groups_len, expected.groups_len);
            ASSERT(!shared.groups_lost);
            ASSERT(!actual.groups_lost);
            /* Name-reference routes may add groups; the authoritative shared
             * rule union is exact and every member must survive routing. */
            for (size_t g = 0; g < expected.groups_len; g++) {
                ASSERT(impact_has_group(&shared, expected.groups[g]));
                ASSERT(impact_has_group(&actual, expected.groups[g]));
            }
        }
        struct agent_impact_acc acc;
        bool consensus = false;
        ASSERT_STR_EQ(zcl_native_code_route_for_path("tests/harness/src/test_devagent_claim.c", &acc, &consensus), "devagent_claim");
        ASSERT_STR_EQ(zcl_native_code_route_for_path("tools/command/native_command.c", &acc, &consensus), "make_lint_gates");
        ASSERT_STR_EQ(zcl_native_code_route_for_path("core/modules/crypto/src/sha256.c", &acc, &consensus), "consensus_parity");
        ASSERT(consensus);
        PASS();
    } _test_next:;
    return failures;
}

/* Independent original predicate: every bounded slice goes directly through
 * the platform glob authority, with no caller prefix rejection. */
static bool ci_reference_pattern(const char *path, const char *patterns)
{
    if (!path || !path[0]) return false;
    for (const char *p = patterns; *p;) {
        const char *bar = strchr(p, '|');
        size_t len = bar ? (size_t)(bar - p) : strlen(p);
        char pattern[256];
        if (len && len < sizeof(pattern)) {
            memcpy(pattern, p, len);
            pattern[len] = 0;
            if (platform_glob_match(pattern, path, false)) return true;
        }
        if (!bar) break;
        p = bar + 1;
    }
    return false;
}

static bool ci_reference_rules(const char *path, struct agent_impact_acc *acc)
{
    bool matched = false;
#define AGENT_IMPACT_RULE(patterns, groups) \
    do { \
        if (ci_reference_pattern(path, (patterns))) { \
            if (!acc) return true; \
            agent_impact_add_group_list(acc, (groups)); \
            acc->shared_rule_hits++; \
            matched = true; \
        } \
    } while (0);
#include "controllers/agent_impact_rules.def"
#undef AGENT_IMPACT_RULE
    return matched;
}

static bool ci_rule_fold_parity(const char *path, bool fill)
{
    struct agent_impact_acc expected = {0}, actual = {0};
    if (fill) {
        char group[32];
        for (size_t i = 0; i < ZCL_AGENT_IMPACT_MAX_GROUPS; i++) {
            (void)snprintf(group, sizeof(group), "parity_%zu", i);
            agent_impact_add_group(&expected, group);
            agent_impact_add_group(&actual, group);
        }
    }
    bool a = ci_reference_rules(path, &expected);
    bool b = agent_impact_apply_shared_rules(path, &actual);
    if (a != b || ci_reference_rules(path, NULL) !=
        agent_impact_apply_shared_rules(path, NULL) ||
        actual.shared_rule_hits != expected.shared_rule_hits ||
        actual.groups_len != expected.groups_len ||
        actual.groups_lost != expected.groups_lost) return false;
    for (size_t i = 0; i < actual.groups_len; i++)
        if (strcmp(actual.groups[i], expected.groups[i])) return false;
    return true;
}

static int test_code_rule_prefix_parity(void)
{
    int failures = 0;
    TEST("code impact: literal prefix rejection preserves full reference fold") {
        const char *paths[] = {NULL, "", "t", "tools", "tools/", "Tools/command/native_devagent_claim.c",
            "zz_no_rule.c", "tools/command/native_devagent_claim.c",
            "tools/command/native_devagent_claim.c.extra", "tools/command/native_code_command.c",
            "tests/harness/src/test_devagent_claim.c", "tests/harness/src/test_zcode_policy.c",
            "engine/composition/src/boot_services.c", "engine/modules/chainlog/src/nested/fixture.c",
            "cognition/controllers/src/agent_impact_rules.c", "platform/modules/fdt/nested/file.c",
            "tests/fixtures/lab/rev_cases.json", "core/modules/validation/src/fixture.c",
            "docs/README.md", "tools/command/native_fleet_triggers_extra.c"};
        for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
            ASSERT(ci_rule_fold_parity(paths[i], false));
            ASSERT(ci_rule_fold_parity(paths[i], true));
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_impact_rule_predicate(void)
{
    int failures = 0;
    TEST("code_impact: owner predicate preserves all accumulated proof groups") {
        static const struct {
            const char *path;
            size_t hits;
            size_t group_count;
            const char *groups[4];
        } cases[] = {
            {"tests/fixtures/lab/rev_cases.json", 1, 4,
             {"lab", "lab_promote", "command_registry_catalog", "native_api_contract"}},
            {"platform/adapters/outbound/persistence/src/hodl_history_sqlite.c", 1, 2,
             {"hodl_history_port", "make_lint_gates"}},
            {"tests/harness/src/test_zcode_policy.c", 1, 1,
             {"zcode_policy"}},
            {"engine/modules/chainlog/src/chainlog.c", 2, 4,
             {"chainlog", "dev_platform", "make_lint_gates", "land_queue"}},
            {"engine/modules/chainlog/src/nested/fixture.c", 2, 4,
             {"chainlog", "dev_platform", "make_lint_gates", "land_queue"}},
            {"tests/harness/src/test_muse_session.c", 1, 4,
             {"devagent_muse_run", "muse_session", "devagent_worker", "make_lint_gates"}},
            {"tests/harness/src/test_mesh_terminal_hub.c", 1, 2,
             {"mesh_terminal_hub", "make_lint_gates"}},
            {"cognition/modules/session/src/mesh_terminal_hub_server.c", 1, 2,
             {"mesh_terminal_hub", "make_lint_gates"}},
            {"zz_no_impact_rule_fixture.c", 0, 0, {NULL}},
            {"tests/harness/src/test_zcode_policy.c.extra", 0, 0, {NULL}},
            {"tests/harness/src/test_ZCODE_policy.c", 0, 0, {NULL}},
            {"", 0, 0, {NULL}},
            {NULL, 0, 0, {NULL}},
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            struct agent_impact_acc acc = {0};
            bool matched = agent_impact_apply_shared_rules(cases[i].path, &acc);
            ASSERT(matched == (cases[i].hits > 0));
            ASSERT(agent_impact_apply_shared_rules(cases[i].path, NULL) == matched);
            ASSERT_EQ(acc.shared_rule_hits, cases[i].hits);
            ASSERT_EQ(acc.groups_len, cases[i].group_count);
            for (size_t g = 0; g < acc.groups_len; g++)
                ASSERT_STR_EQ(acc.groups[g], cases[i].groups[g]);
        }
        /* A cursor-model change must re-prove the condition that refuses
         * legacy state and names the explicit operator recovery. */
        struct agent_impact_acc oprindex = {0};
        ASSERT(agent_impact_apply_shared_rules(
            "engine/models/src/op_return_index.c", &oprindex));
        ASSERT(!oprindex.groups_lost);
        bool legacy_state_selected = false;
        for (size_t g = 0; g < oprindex.groups_len; g++)
            legacy_state_selected = legacy_state_selected ||
                strcmp(oprindex.groups[g], "op_return_index_legacy_state") == 0;
        ASSERT(legacy_state_selected);
        PASS();
    } _test_next:;
    return failures;
}

/* A depfile that is incomplete, stale, or missing a prerequisite must not
 * be answered as a complete narrow impact. An in-tree quoted include it omits
 * is an added edge instead. The clean control stays complete, and the three
 * compile-scope refusals still fire. */
#define CI_NARROW_FIX "test-tmp/code_impact_narrow"

static bool ci_narrow_dim(const char *root, const char *path,
                          char *dim, size_t cap, long long *count)
{
    struct zcl_command_reply reply;
    ci_impact_call(path, root, &reply);
    const char *got = json_get_str(json_get(&reply.data, "include_dimension"));
    snprintf(dim, cap, "%s", got ? got : "");
    *count = json_get_int(json_get(&reply.data, "include_dependent_count"));
    bool ok = reply.exit_code == ZCL_COMMAND_EXIT_OK;
    zcl_command_reply_free(&reply);
    return ok;
}

static bool ci_narrow_base(const char *dir, const char *src, const char *dep)
{
    return ci_impact_mk_write(dir, "core/modules/net/include/net/real.h",
                              "int ci_narrow_real(void);\n") &&
           ci_impact_mk_write(dir, "core/modules/net/src/narrow.c", src) &&
           ci_impact_mk_write(dir, "build/obj/narrow.d", dep);
}

static void ci_narrow_touch_rel(const char *dir, const char *rel, int delta)
{
    char dep[512], path[512];
    struct stat st;
    snprintf(dep, sizeof dep, "%s/build/obj/narrow.d", dir);
    snprintf(path, sizeof path, "%s/%s", dir, rel);
    if (stat(dep, &st) != 0)
        return;
    struct utimbuf times;
    times.actime = st.st_mtime + delta;
    times.modtime = st.st_mtime + delta;
    (void)utime(path, &times);
}

static int ci_narrow_one(const char *name, const char *src, const char *dep,
                         const char *query, bool expect_complete)
{
    int failures = 0;
    char dir[256];
    snprintf(dir, sizeof dir, CI_NARROW_FIX "/%s", name);
 TEST_DISCARD(system("rm -rf " CI_NARROW_FIX));
    bool ready = true;
    if (strcmp(name, "quoted") == 0)
        ready = ci_impact_mk_write(dir, "core/modules/net/include/net/extra.h",
                                   "int ci_narrow_extra(void);\n");
    ready = ready && ci_narrow_base(dir, src, dep);
    if (strcmp(name, "changed") == 0)
        ready = ready && ci_impact_mk_write(
            dir, "core/modules/net/include/net/extra.h",
            "int ci_narrow_extra(void);\n");
    if (strcmp(name, "stale") == 0)
        ci_narrow_touch_rel(dir, "core/modules/net/src/narrow.c", 5);
    if (strcmp(name, "stale-header") == 0)
        ci_narrow_touch_rel(dir, "core/modules/net/include/net/real.h", 5);
    char dim[64] = "";
    long long count = -1;
    bool ok = ready && ci_narrow_dim(dir, query, dim, sizeof dim, &count);
    printf("invariant=unsafe_narrow_include_dimension case=%s "
           "include_dimension=%s include_dependent_count=%lld ok=%d\n",
           name, dim, count, ok ? 1 : 0);
    TEST("code_impact: depfile evidence cannot yield an unsafe narrow impact") {
        ASSERT(ok);
        if (expect_complete)
            ASSERT(strcmp(dim, "complete") == 0 && count >= 1);
        else
            ASSERT(strcmp(dim, "complete") != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_impact_unsafe_narrow(void)
{
    static const char *const src_plain =
        "/* narrow */\n#include \"net/real.h\"\nint ci_narrow(void){return 1;}\n";
    static const char *const dep_clean =
        "build/obj/narrow.o: core/modules/net/src/narrow.c "
        "core/modules/net/include/net/real.h\n";
    static const char *const dep_missing =
        "build/obj/narrow.o: core/modules/net/src/narrow.c "
        "core/modules/net/include/net/real.h "
        "core/modules/net/include/net/missing.h\n";
    static const char *const dep_incomplete =
        "build/obj/narrow.o: core/modules/net/src/narrow.c "
        "core/modules/net/include/net/real.h";
    static const char *const src_changed =
        "/* narrow */\n#include \"net/real.h\"\n"
        "#include \"core/modules/net/include/net/extra.h\"\n"
        "int ci_narrow(void){return 1;}\n";
    static const char *const src_quoted =
        "/* narrow */\n#include \"net/real.h\"\n"
        "#include \"net/extra.h\"\n"
        "int ci_narrow(void){return 1;}\n";
    int failures = 0;
    failures += ci_narrow_one("clean", src_plain, dep_clean,
                              "core/modules/net/include/net/real.h", true);
    failures += ci_narrow_one("missing", src_plain, dep_missing,
                              "core/modules/net/include/net/missing.h", false);
    failures += ci_narrow_one("incomplete", src_plain, dep_incomplete,
                              "core/modules/net/include/net/real.h", false);
    failures += ci_narrow_one("stale", src_plain, dep_clean,
                              "core/modules/net/include/net/real.h", false);
    failures += ci_narrow_one("changed", src_changed, dep_clean,
                              "core/modules/net/include/net/extra.h", true);
    failures += ci_narrow_one("quoted", src_quoted, dep_clean,
                              "core/modules/net/include/net/real.h", true);
    failures += ci_narrow_one("stale-header", src_plain, dep_clean,
                              "core/modules/net/include/net/real.h", false);
 TEST_DISCARD(system("rm -rf " CI_NARROW_FIX));
    return failures;
}

/* A narrow-unsafe include graph names WHICH rule made it unsafe and on WHICH
 * file, so a closure-truncated refusal is diagnosed from evidence. The first
 * cause in the sorted scan is kept; a clean graph names none. */
/* A failed candidate that added a translation unit can leave its object and
 * depfile behind in a shared build epoch. `foreign` is such a depfile, written
 * beside the live one: its unit is absent from this tree, so it is not part
 * of this tree's include graph and must name no cause of its own. */
#define CI_FOREIGN_DEP "build/obj/a/tools/dev/verify_attest.d"

static int ci_unsafe_cause_run(const char *name, const char *dep,
                               const char *touch, const char *foreign,
                               const char *want)
{
    static const char *const src =
        "/* narrow */\n#include \"net/real.h\"\nint ci_narrow(void){return 1;}\n";
    int failures = 0;
    char dir[256];
    snprintf(dir, sizeof dir, CI_NARROW_FIX "/cause_%s", name);
 TEST_DISCARD(system("rm -rf " CI_NARROW_FIX));
    bool ready = ci_narrow_base(dir, src, dep);
    if (ready && foreign)
        ready = ci_impact_mk_write(dir, CI_FOREIGN_DEP, foreign);
    if (ready && touch)
        ci_narrow_touch_rel(dir, touch, 5);
    char cause[CODEINDEX_INCLUDE_UNSAFE_CAUSE_MAX] = "unset";
    bool unsafe = false;
    struct codeindex *index = ready ? codeindex_open(dir) : NULL;
    if (index) {
        unsafe = codeindex_include_unsafe_cause(index, cause, sizeof cause);
        codeindex_close(index);
    }
    printf("invariant=include_unsafe_cause case=%s unsafe=%d cause=\"%s\" "
           "ok=%d\n", name, unsafe ? 1 : 0, cause, index ? 1 : 0);
    TEST("code_impact: a narrow-unsafe include graph names its first rule and file") {
        ASSERT(index != NULL);
        ASSERT(unsafe == (want[0] != '\0'));
        ASSERT_STR_EQ(cause, want);
        PASS();
    } _test_next:;
    return failures;
}

static int ci_unsafe_cause_one(const char *name, const char *dep,
                               const char *touch, const char *want)
{
    return ci_unsafe_cause_run(name, dep, touch, NULL, want);
}

static int test_code_impact_unsafe_cause(void)
{
    static const char *const dep_clean =
        "build/obj/narrow.o: core/modules/net/src/narrow.c "
        "core/modules/net/include/net/real.h\n";
    static const char *const dep_missing =
        "build/obj/narrow.o: core/modules/net/src/narrow.c "
        "core/modules/net/include/net/real.h "
        "core/modules/net/include/net/missing.h\n";
    static const char *const dep_incomplete =
        "build/obj/narrow.o: core/modules/net/src/narrow.c "
        "core/modules/net/include/net/real.h";
    int failures = 0;
    failures += ci_unsafe_cause_one("clean", dep_clean, NULL, "");
    failures += ci_unsafe_cause_one(
        "missing", dep_missing, NULL,
        "prereq_not_regular build/obj/narrow.d -> "
        "core/modules/net/include/net/missing.h");
    failures += ci_unsafe_cause_one(
        "incomplete", dep_incomplete, NULL,
        "depfile_incomplete build/obj/narrow.d");
    failures += ci_unsafe_cause_one(
        "stale", dep_clean, "core/modules/net/src/narrow.c",
        "prereq_newer_than_depfile build/obj/narrow.d -> "
        "core/modules/net/src/narrow.c");
    /* The foreign unit and a header it listed are both absent. Neither is
     * this tree's evidence, so the clean graph stays clean ... */
    static const char *const dep_foreign =
        "build/obj/a/tools/dev/verify_attest.o: tools/dev/verify_attest.c "
        "core/modules/net/include/net/real.h tools/dev/verify_attest.h\n"
        "tools/dev/verify_attest.h:\n";
    failures += ci_unsafe_cause_run("foreign", dep_clean, NULL, dep_foreign,
                                    "");
    /* ... and a live unit's missing header still refuses, even when the
     * foreign depfile sorts first. */
    failures += ci_unsafe_cause_run(
        "foreign-missing", dep_missing, NULL, dep_foreign,
        "prereq_not_regular build/obj/narrow.d -> "
        "core/modules/net/include/net/missing.h");
 TEST_DISCARD(system("rm -rf " CI_NARROW_FIX));
    return failures;
}

/* HOT_FORK caches depfiles for deleted .resident unity wrappers. They are
 * not the ordinary compiler graph and must not poison a live unit's impact. */
static int test_code_impact_hotfork_cache_scope(void)
{
    int failures = 0;
    const char *dir = CI_NARROW_FIX "/hotfork_cache";
    static const char src[] =
        "#include \"net/real.h\"\nint ci_narrow(void){return 1;}\n";
    static const char dep[] =
        "build/obj/narrow.o: core/modules/net/src/narrow.c "
        "core/modules/net/include/net/real.h\n";
    static const char stale[] =
        "build/hotswap-fast/x.o: build/hotswap-fast/.resident-gone.c "
        "core/modules/net/include/net/real.h\n";
 TEST_DISCARD(system("rm -rf " CI_NARROW_FIX));
    bool ready = ci_narrow_base(dir, src, dep) &&
        ci_impact_mk_write(dir, "build/hotswap-fast/x.hotfork.d", stale) &&
        ci_impact_mk_write(dir, "build/hotswap-fast/y.c.d", stale);
    char dim[64] = "";
    long long count = -1;
    bool ok = ready && ci_narrow_dim(dir,
        "core/modules/net/include/net/real.h", dim, sizeof dim, &count);
    char sibling[64] = "";
    long long sibling_count = -1;
    bool sibling_ok = ok && ci_impact_mk_write(
        dir, "build/hotswap-fast-sibling/live.d", stale) &&
        ci_narrow_dim(dir, "core/modules/net/include/net/real.h",
                      sibling, sizeof sibling, &sibling_count);
    printf("invariant=hotfork_cache_scope include_dimension=%s "
           "dependent_count=%lld sibling=%s/%lld ok=%d\n", dim, count,
           sibling, sibling_count, sibling_ok ? 1 : 0);
    TEST("code_impact: stale HOT_FORK cache does not poison a live depfile") {
        ASSERT(sibling_ok);
        ASSERT(strcmp(dim, "complete") == 0 && count == 1);
        ASSERT(strcmp(sibling, "complete") != 0);
        PASS();
    } _test_next:;
 TEST_DISCARD(system("rm -rf " CI_NARROW_FIX));
    return failures;
}

/* An inactive quoted include is not listed by the compiler depfile. If its
 * input disappears, the new graph cannot prove that no unit read it. */
static int test_code_impact_deleted_unlisted_input_ext(const char *extension)
{
    int failures = 0;
    static const char dep[] =
        "build/obj/narrow.o: core/modules/net/src/narrow.c "
        "core/modules/net/include/net/real.h\n";
    char dir[256], header[128], src[256], full[512];
    int a = snprintf(dir, sizeof dir, CI_NARROW_FIX "/deleted_%s", extension);
    int b = snprintf(header, sizeof header,
                     "core/modules/net/include/net/optional.%s", extension);
    int c = snprintf(src, sizeof src,
                     "#include \"net/real.h\"\n#if 0\n"
                     "#include \"net/optional.%s\"\n#endif\n"
                     "int ci_narrow(void){return 1;}\n", extension);
    bool ready = a > 0 && (size_t)a < sizeof dir &&
                 b > 0 && (size_t)b < sizeof header &&
                 c > 0 && (size_t)c < sizeof src &&
                 ci_impact_mk_write(dir, header, "int ci_optional(void);\n") &&
                 ci_narrow_base(dir, src, dep);
    char before[64] = "", after[64] = "";
    long long before_count = -1, after_count = -1;
    bool ok = ready && ci_narrow_dim(dir, header, before, sizeof before,
                                     &before_count);
    int n = snprintf(full, sizeof full, "%s/%s", dir, header);
    ok = ok && n > 0 && (size_t)n < sizeof full && remove(full) == 0 &&
         ci_narrow_dim(dir, header, after, sizeof after, &after_count);
    printf("invariant=deleted_unlisted_header ext=%s before=%s/%lld "
           "after=%s/%lld ok=%d\n", extension, before,
           before_count, after, after_count, ok ? 1 : 0);
    TEST("code_impact: deleted unlisted input cannot claim complete zero readers") {
        ASSERT(ok);
        ASSERT(strcmp(before, "complete") == 0 && before_count == 1);
        ASSERT(strcmp(after, "complete") != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_impact_deleted_unlisted_input(void)
{
    int failures = 0;
 TEST_DISCARD(system("rm -rf " CI_NARROW_FIX));
    failures += test_code_impact_deleted_unlisted_input_ext("h");
    failures += test_code_impact_deleted_unlisted_input_ext("def");
    failures += test_code_impact_deleted_unlisted_input_ext("inc");
    failures += test_code_impact_deleted_unlisted_input_ext("txt");
 TEST_DISCARD(system("rm -rf " CI_NARROW_FIX));
    return failures;
}

static int test_code_impact_incremental_include(void)
{
    int failures = 0;
    const char *dir = CI_NARROW_FIX "/incremental";
    static const char *const dep =
        "build/obj/narrow.o: core/modules/net/src/narrow.c "
        "core/modules/net/include/net/real.h\n";
    static const char *const src0 =
        "/* narrow */\n#include \"net/real.h\"\nint ci_narrow(void){return 1;}\n";
    static const char *const src1 =
        "/* narrow */\n#include \"net/real.h\"\n#include \"net/extra.h\"\n"
        "int ci_narrow(void){return 2;}\n";
 TEST_DISCARD(system("rm -rf " CI_NARROW_FIX));
    bool ready = ci_impact_mk_write(dir, "core/modules/net/include/net/extra.h",
                                    "int ci_narrow_extra(void);\n") &&
                 ci_narrow_base(dir, src0, dep);
    char first[64] = "";
    char second[64] = "";
    long long count = -1;
    bool ok = ready && ci_narrow_dim(dir, "core/modules/net/include/net/real.h",
                                     first, sizeof first, &count);
    ok = ok && ci_impact_mk_write(dir, "core/modules/net/src/narrow.c", src1);
    ci_narrow_touch_rel(dir, "core/modules/net/src/narrow.c", -5);
    ci_narrow_touch_rel(dir, "core/modules/net/include/net/extra.h", -5);
    ok = ok && ci_narrow_dim(dir, "core/modules/net/include/net/real.h",
                             second, sizeof second, &count);
    char added[64] = "";
    long long added_count = -1;
    ok = ok && ci_narrow_dim(dir, "core/modules/net/include/net/extra.h",
                             added, sizeof added, &added_count);
    printf("invariant=unsafe_narrow_include_dimension case=incremental "
           "include_dimension=%s then %s added=%s/%lld ok=%d\n",
           first, second, added, added_count, ok ? 1 : 0);
    TEST("code_impact: a later include change is rebuilt into a complete narrow impact") {
        ASSERT(ok);
        ASSERT(strcmp(first, "complete") == 0);
        ASSERT(strcmp(second, "complete") == 0);
        ASSERT(strcmp(added, "complete") == 0 && added_count >= 1);
        PASS();
    } _test_next:;
 TEST_DISCARD(system("rm -rf " CI_NARROW_FIX));
    return failures;
}

static int test_code_impact_scope_refusals(void)
{
    int failures = 0;
    TEST("code_impact: conflict, incomplete closure, and missing receipt still refuse") {
        char buf[1024];
        size_t used = 0;
        FILE *pipe = popen("tools/agent_fast_ci.sh compile-scope-selftest", "r");
        ASSERT(pipe != NULL);
        buf[0] = '\0';
        while (pipe && used + 1 < sizeof buf) {
            size_t got = fread(buf + used, 1, sizeof buf - used - 1, pipe);
            if (got == 0)
                break;
            used += got;
        }
        buf[used] = '\0';
        printf("%s\n", buf);
        int closed = pipe ? pclose(pipe) : 1;
        ASSERT(closed == 0);
        ASSERT(strstr(buf, "proof_observation_conflict") != NULL);
        ASSERT(strstr(buf, "closure_incomplete") != NULL);
        ASSERT(strstr(buf, "missing_receipt") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* A quoted include the depfile omits — here one inside an inactive
 * preprocessor conditional — names an in-tree file this configuration never
 * read. It is kept as an extra include edge from the translation unit, so the
 * graph holds a superset of the true edges and stays trusted. What the added
 * file includes is reached the same way. Every depfile hazard still refuses a
 * complete answer with such an include present, and the incremental index
 * rebuilds once a source edit adds an edge its stored rows lack. */
#define CI_COND_FIX "test-tmp/code_impact_conditional"
#define CI_COND_UNIT "core/modules/net/src/narrow.c"
#define CI_COND_INC "core/modules/net/src/narrow_win.inc"
#define CI_COND_DEF "core/modules/net/include/net/win_only.def"
#define CI_COND_REAL "core/modules/net/include/net/real.h"

static const char *const ci_cond_src =
    "/* narrow */\n#include \"net/real.h\"\n#ifdef _WIN32\n"
    "#include \"narrow_win.inc\"\n#endif\nint ci_narrow(void){return 1;}\n";
static const char *const ci_cond_dep =
    "build/obj/narrow.o: " CI_COND_UNIT " " CI_COND_REAL "\n";

static bool ci_cond_fixture(const char *dir, const char *dep)
{
    return ci_impact_mk_write(dir, CI_COND_INC,
                              "#include \"narrow_win.inc\"\n"
                              "#include \"net/win_only.def\"\n"
                              "static int ci_narrow_win;\n") &&
           ci_impact_mk_write(dir, CI_COND_DEF, "WIN_ROW(1)\n") &&
           ci_narrow_base(dir, ci_cond_src, dep);
}

/* Query `path`; report its include dimension and whether `want` is one of
 * its listed include dependents. */
static bool ci_cond_query(const char *root, const char *path,
                          const char *want, char *dim, size_t cap, bool *has)
{
    struct zcl_command_reply reply;
    ci_impact_call(path, root, &reply);
    const char *got = json_get_str(json_get(&reply.data, "include_dimension"));
    snprintf(dim, cap, "%s", got ? got : "");
    const struct json_value *arr = json_get(&reply.data, "include_dependents");
    *has = false;
    for (size_t i = 0; arr && arr->type == JSON_ARR && i < arr->num_children;
         i++) {
        const char *item = json_get_str(&arr->children[i]);
        if (item && strcmp(item, want) == 0)
            *has = true;
    }
    bool ok = reply.exit_code == ZCL_COMMAND_EXIT_OK;
    zcl_command_reply_free(&reply);
    return ok;
}

static int test_code_impact_conditional_include_edge(void)
{
    int failures = 0;
    const char *dir = CI_COND_FIX "/edge";
 TEST_DISCARD(system("rm -rf " CI_COND_FIX));
    bool ready = ci_cond_fixture(dir, ci_cond_dep);
    char inc_dim[64] = "", def_dim[64] = "", real_dim[64] = "";
    bool inc_has = false, def_has = false, real_has = false;
    bool ok = ready &&
              ci_cond_query(dir, CI_COND_INC, CI_COND_UNIT, inc_dim,
                            sizeof inc_dim, &inc_has) &&
              ci_cond_query(dir, CI_COND_DEF, CI_COND_UNIT, def_dim,
                            sizeof def_dim, &def_has) &&
              ci_cond_query(dir, CI_COND_REAL, CI_COND_UNIT, real_dim,
                            sizeof real_dim, &real_has);
    printf("invariant=conditional_include_edge inc=%s/%d def=%s/%d "
           "real=%s/%d ok=%d\n", inc_dim, inc_has ? 1 : 0, def_dim,
           def_has ? 1 : 0, real_dim, real_has ? 1 : 0, ok ? 1 : 0);
    TEST("code_impact: a conditional include the depfile omits is an edge that reaches what it includes") {
        ASSERT(ok);
        ASSERT(strcmp(inc_dim, "complete") == 0);
        ASSERT(inc_has);
        ASSERT(strcmp(def_dim, "complete") == 0);
        ASSERT(def_has);
        ASSERT(strcmp(real_dim, "complete") == 0);
        ASSERT(real_has);
        PASS();
    } _test_next:;
 TEST_DISCARD(system("rm -rf " CI_COND_FIX));
    return failures;
}

static int ci_cond_hazard(const char *name, const char *dep,
                          const char *touch, int delta)
{
    int failures = 0;
    char dir[256];
    snprintf(dir, sizeof dir, CI_COND_FIX "/%s", name);
 TEST_DISCARD(system("rm -rf " CI_COND_FIX));
    bool ready = ci_cond_fixture(dir, dep);
    if (ready && touch)
        ci_narrow_touch_rel(dir, touch, delta);
    char dim[64] = "";
    bool has = false;
    bool ok = ready && ci_cond_query(dir, CI_COND_INC, CI_COND_UNIT, dim,
                                     sizeof dim, &has);
    printf("invariant=conditional_include_hazard case=%s "
           "include_dimension=%s ok=%d\n", name, dim, ok ? 1 : 0);
    TEST("code_impact: a conditional include edge never masks a depfile hazard") {
        ASSERT(ok);
        ASSERT(strcmp(dim, "complete") != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_impact_conditional_hazards(void)
{
    static const char *const dep_missing =
        "build/obj/narrow.o: " CI_COND_UNIT " " CI_COND_REAL " "
        "core/modules/net/include/net/missing.h\n";
    static const char *const dep_incomplete =
        "build/obj/narrow.o: " CI_COND_UNIT " " CI_COND_REAL;
    int failures = 0;
    failures += ci_cond_hazard("missing", dep_missing, NULL, 0);
    failures += ci_cond_hazard("incomplete", dep_incomplete, NULL, 0);
    failures += ci_cond_hazard("stale", ci_cond_dep, CI_COND_UNIT, 5);
    failures += ci_cond_hazard("stale-header", ci_cond_dep, CI_COND_REAL, 5);
 TEST_DISCARD(system("rm -rf " CI_COND_FIX));
    return failures;
}

/* A fixed-size text scan must not certify a complete include closure when a
 * quoted include sits beyond its first input buffer. */
static int ci_long_include_line_case(size_t padding, bool over_bound)
{
    const char *dir = CI_COND_FIX "/long-line";
    char src[8500];
    static const char prefix[] = "#if 0\n";
    memcpy(src, prefix, sizeof(prefix) - 1);
    /* Put the directive across the 1023-byte or 8191-byte bound. */
    memset(src + sizeof(prefix) - 1, ' ', padding);
    size_t offset = sizeof(prefix) - 1 + padding;
    int wrote = snprintf(src + offset, sizeof(src) - offset,
                         "#include \"narrow_win.inc\"\n#endif\n"
                         "#include \"net/real.h\"\n");
 TEST_DISCARD(system("rm -rf " CI_COND_FIX));
    bool ready = wrote > 0 && (size_t)wrote < sizeof(src) - offset &&
                 ci_cond_fixture(dir, ci_cond_dep) &&
                 ci_impact_mk_write(dir, CI_COND_UNIT, src) &&
                 ci_impact_mk_write(dir, "build/obj/narrow.d", ci_cond_dep);
    if (ready) ci_narrow_touch_rel(dir, CI_COND_UNIT, -5);
    char dim[64] = "";
    bool has = false;
    const char *query = over_bound ? CI_COND_REAL : CI_COND_INC;
    bool ok = ready && ci_cond_query(dir, query, CI_COND_UNIT, dim,
                                     sizeof dim, &has);
    printf("invariant=long_include_line padding=%zu include_dimension=%s "
           "dependent=%d ok=%d\n", padding, dim, has ? 1 : 0, ok ? 1 : 0);
    int failures = 0;
    TEST("code_impact: long source lines cannot silently lose include edges") {
        ASSERT(ok);
        if (over_bound)
            ASSERT(strcmp(dim, "closure-truncated") == 0);
        else
            ASSERT(strcmp(dim, "complete") == 0 && has);
        PASS();
    } _test_next:;
 TEST_DISCARD(system("rm -rf " CI_COND_FIX));
    return failures;
}

static int test_code_impact_long_include_line(void)
{
    int failures = ci_long_include_line_case(1018, false);
    failures += ci_long_include_line_case(8186, true);
    return failures;
}

/* The incremental index reuses the stored include rows. A body-only edit
 * keeps the added edge and the complete answer; an edit that adds an include
 * the stored rows lack is rebuilt from a fresh scan, which records it. */
static int test_code_impact_conditional_incremental(void)
{
    int failures = 0;
    const char *dir = CI_COND_FIX "/incremental";
    static const char *const src_body =
        "/* narrow */\n#include \"net/real.h\"\n#ifdef _WIN32\n"
        "#include \"narrow_win.inc\"\n#endif\nint ci_narrow(void){return 2;}\n";
    static const char *const src_more =
        "/* narrow */\n#include \"net/real.h\"\n#ifdef _WIN32\n"
        "#include \"narrow_win.inc\"\n#include \"net/extra.h\"\n#endif\n"
        "int ci_narrow(void){return 3;}\n";
 TEST_DISCARD(system("rm -rf " CI_COND_FIX));
    bool ready = ci_impact_mk_write(dir, "core/modules/net/include/net/extra.h",
                                    "int ci_narrow_extra(void);\n") &&
                 ci_cond_fixture(dir, ci_cond_dep);
    char first[64] = "", second[64] = "", third[64] = "";
    bool has_first = false, has_second = false, has_third = false;
    bool ok = ready && ci_cond_query(dir, CI_COND_INC, CI_COND_UNIT, first,
                                     sizeof first, &has_first);
    ok = ok && ci_impact_mk_write(dir, CI_COND_UNIT, src_body);
    ci_narrow_touch_rel(dir, CI_COND_UNIT, -5);
    ok = ok && ci_cond_query(dir, CI_COND_INC, CI_COND_UNIT, second,
                             sizeof second, &has_second);
    ok = ok && ci_impact_mk_write(dir, CI_COND_UNIT, src_more);
    ci_narrow_touch_rel(dir, CI_COND_UNIT, -5);
    ci_narrow_touch_rel(dir, "core/modules/net/include/net/extra.h", -5);
    ok = ok && ci_cond_query(dir, "core/modules/net/include/net/extra.h",
                             CI_COND_UNIT, third,
                             sizeof third, &has_third);
    printf("invariant=conditional_include_incremental "
           "include_dimension=%s then %s then %s ok=%d\n",
           first, second, third, ok ? 1 : 0);
    TEST("code_impact: an incremental index keeps a stored conditional edge and rebuilds for one it never stored") {
        ASSERT(ok);
        ASSERT(strcmp(first, "complete") == 0 && has_first);
        ASSERT(strcmp(second, "complete") == 0 && has_second);
        ASSERT(strcmp(third, "complete") == 0 && has_third);
        PASS();
    } _test_next:;
 TEST_DISCARD(system("rm -rf " CI_COND_FIX));
    return failures;
}

/* The compiler spells a prerequisite the way the source named it, so a
 * registry included as "../../engine/..." appears in the depfile with its
 * ".." segments. The edge names the file by its checkout path, and a
 * conditional include that climbs out of its directory is followed the same
 * way; a query by the checkout path lists the includer. */
#define CI_DOT_REG "engine/composition/dot_reg.def"
#define CI_DOT_WIN "core/modules/net/include/net/dot_win.h"

static int test_code_impact_dotdot_include_edge(void)
{
    int failures = 0;
    const char *dir = CI_COND_FIX "/dotdot";
    static const char *const src =
        "/* narrow */\n#include \"net/real.h\"\n"
        "#include \"../../../../" CI_DOT_REG "\"\n#ifdef _WIN32\n"
        "#include \"../include/net/dot_win.h\"\n#endif\n"
        "int ci_narrow(void){return 1;}\n";
    static const char *const dep =
        "build/obj/narrow.o: " CI_COND_UNIT " " CI_COND_REAL " "
        "core/modules/net/src/../../../../" CI_DOT_REG "\n";
 TEST_DISCARD(system("rm -rf " CI_COND_FIX));
    bool ready = ci_impact_mk_write(dir, CI_DOT_REG, "DOT_ROW(1)\n") &&
                 ci_impact_mk_write(dir, CI_DOT_WIN, "int ci_dot_win;\n") &&
                 ci_narrow_base(dir, src, dep);
    char reg_dim[64] = "", win_dim[64] = "";
    bool reg_has = false, win_has = false;
    bool ok = ready &&
              ci_cond_query(dir, CI_DOT_REG, CI_COND_UNIT, reg_dim,
                            sizeof reg_dim, &reg_has) &&
              ci_cond_query(dir, CI_DOT_WIN, CI_COND_UNIT, win_dim,
                            sizeof win_dim, &win_has);
    printf("invariant=dotdot_include_edge reg=%s/%d win=%s/%d ok=%d\n",
           reg_dim, reg_has ? 1 : 0, win_dim, win_has ? 1 : 0, ok ? 1 : 0);
    TEST("code_impact: a dot-dot include names its file by the checkout path") {
        ASSERT(ok);
        ASSERT(strcmp(reg_dim, "complete") == 0);
        ASSERT(reg_has);
        ASSERT(strcmp(win_dim, "complete") == 0);
        ASSERT(win_has);
        PASS();
    } _test_next:;
 TEST_DISCARD(system("rm -rf " CI_COND_FIX));
    return failures;
}

/* An index written before include edges carried an edge root is rebuilt on
 * the next update: the answer is complete and lists the conditional includer. */
static bool ci_cond_drop_edge_root(const char *dir)
{
    char path[512];
    sqlite3 *db = NULL;
    int n = snprintf(path, sizeof path, "%s/.codeindex/index.kv.spare", dir);
    if (n <= 0 || (size_t)n >= sizeof path)
        return false;
    (void)remove(path);
    path[n - 6] = '\0';
    bool ok = sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL) ==
                  SQLITE_OK &&
              sqlite3_exec(db, /* raw-sql-ok:test-fixture */
                           "DELETE FROM meta WHERE k='include_edge_root_sha3'",
                           NULL, NULL, NULL) == SQLITE_OK &&
              sqlite3_changes(db) == 1;
    if (db)
        sqlite3_close(db);
    return ok;
}

static int test_code_impact_rootless_index_rebuilds(void)
{
    int failures = 0;
    const char *dir = CI_COND_FIX "/rootless";
    static const char *const src_body =
        "/* narrow */\n#include \"net/real.h\"\n#ifdef _WIN32\n"
        "#include \"narrow_win.inc\"\n#endif\nint ci_narrow(void){return 2;}\n";
 TEST_DISCARD(system("rm -rf " CI_COND_FIX));
    bool ready = ci_cond_fixture(dir, ci_cond_dep);
    char first[64] = "", second[64] = "";
    bool has_first = false, has_second = false;
    bool ok = ready && ci_cond_query(dir, CI_COND_INC, CI_COND_UNIT, first,
                                     sizeof first, &has_first);
    bool dropped = ok && ci_cond_drop_edge_root(dir);
    ok = dropped && ci_impact_mk_write(dir, CI_COND_UNIT, src_body);
    ci_narrow_touch_rel(dir, CI_COND_UNIT, -5);
    ok = ok && ci_cond_query(dir, CI_COND_INC, CI_COND_UNIT, second,
                             sizeof second, &has_second);
    printf("invariant=rootless_index_rebuilds include_dimension=%s then %s "
           "dropped=%d ok=%d\n", first, second, dropped ? 1 : 0, ok ? 1 : 0);
    TEST("code_impact: an index without an include edge root is rebuilt, not refused") {
        ASSERT(ok);
        ASSERT(strcmp(first, "complete") == 0 && has_first);
        ASSERT(strcmp(second, "complete") == 0 && has_second);
        PASS();
    } _test_next:;
 TEST_DISCARD(system("rm -rf " CI_COND_FIX));
    return failures;
}

static int test_boot_services_rule_capacity(void)
{
    int failures = 0;
    TEST("code impact: boot services retains every mapped proof group") {
        struct agent_impact_acc acc = {0};
        ASSERT(agent_impact_apply_shared_rules("engine/composition/src/boot_services.c", &acc));
        ASSERT(!acc.groups_lost);
        ASSERT(acc.groups_len > 32);
        bool rom_fetch = false, installed_state = false;
        for (size_t i = 0; i < acc.groups_len; i++) {
            if (strcmp(acc.groups[i], "rom_fetch") == 0)
                rom_fetch = true;
            if (strcmp(acc.groups[i], "consensus_state_install_runtime") == 0)
                installed_state = true;
        }
        ASSERT(rom_fetch);
        ASSERT(installed_state);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_literal_candidate_scan(void)
{
    int failures = 0;
    TEST("code impact: literal candidate scan preserves overlap and boundaries") {
        ASSERT(agent_impact_string_literal_contains("\"aaab\"", "aab"));
        ASSERT(agent_impact_string_literal_contains("\"needle tail\"", "needle"));
        ASSERT(agent_impact_string_literal_contains("\"tail needle\"", "needle"));
        ASSERT(agent_impact_string_literal_contains("\"\x80z\"", "\x80z"));
        ASSERT(!agent_impact_string_literal_contains("\"abc\"", ""));
        ASSERT(!agent_impact_string_literal_contains("\"abc\"", "abcd"));
        ASSERT(!agent_impact_string_literal_contains("\"aaaa\"", "aaab"));
        ASSERT(agent_impact_string_literal_contains_whole_token(
            "\"domain_main.cpp main.cpp main.c\"", "main.c"));
        ASSERT(agent_impact_string_literal_contains_whole_token("\"main.c\"", "main.c"));
        ASSERT(!agent_impact_string_literal_contains_whole_token("\"main.cpp\"", "main.c"));
        ASSERT(!agent_impact_string_literal_contains_whole_token("\"main.c\"", ""));
        ASSERT(!agent_impact_string_literal_contains_whole_token("\"main.c\"", "main.cpp"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_literal_raw_rejection_contract(void)
{
    int failures = 0;
    TEST("code impact: raw rejection preserves the existing literal scanner") {
        const char escaped_quote[] = {'"', '\\', '"', 'n', 'e', 'e', 'd', 'l', 'e', '"', 0};
        const char escaped_slash[] = {'"', '\\', '\\', '"', 'n', 'e', 'e', 'd', 'l', 'e', 0};
        ASSERT(!agent_impact_string_literal_contains(NULL, "needle"));
        ASSERT(!agent_impact_string_literal_contains("\"needle\"", NULL));
        ASSERT(!agent_impact_string_literal_contains("needle; \"other\"", "needle"));
        ASSERT(agent_impact_string_literal_contains("/* \"needle\" */", "needle"));
        ASSERT(agent_impact_string_literal_contains(escaped_quote, "needle"));
        ASSERT(!agent_impact_string_literal_contains(escaped_slash, "needle"));
        ASSERT(!agent_impact_string_literal_contains("\"nee\" \"dle\"", "needle"));
        ASSERT(agent_impact_string_literal_contains("\"needle", "needle"));
        ASSERT(agent_impact_string_literal_contains("\"needle\\", "needle"));
        ASSERT(!agent_impact_string_literal_contains("\"other\"\0\"needle\"", "needle"));
        ASSERT(agent_impact_string_literal_contains_whole_token(
            "\"main.cpp domain_main.c /main.c\"", "main.c"));
        ASSERT(!agent_impact_string_literal_contains_whole_token(
            "main.c; \"main.cpp\"", "main.c"));
        PASS();
    } _test_next:;
    return failures;
}

int test_code_impact(void)
{
    int failures = 0;
    failures += test_code_literal_candidate_scan();
    failures += test_code_literal_raw_rejection_contract();
    failures += test_code_impact_rule_predicate();
    failures += test_code_rule_prefix_parity();
    failures += test_code_devagent_routes();
    failures += test_code_route_completeness();
    failures += test_code_route_consumer_bounds();
    failures += test_code_impact_unsafe_narrow();
    failures += test_code_impact_unsafe_cause();
    failures += test_code_impact_hotfork_cache_scope();
    failures += test_code_impact_deleted_unlisted_input();
    failures += test_code_impact_incremental_include();
    failures += test_code_impact_scope_refusals();
    failures += test_code_impact_hub();
    failures += test_code_impact_leaf();
    failures += test_code_impact_missing_path();
    failures += test_code_impact_unknown_path();
    failures += test_code_room_route_storage();
    failures += test_code_room_command_feature();
    failures += test_code_context_map();
    failures += test_code_context_map_complete_pages();
    failures += test_code_context_map_shape_overflow();
    failures += test_boot_services_rule_capacity();
    failures += test_code_context_map_warm_follows_generation();
    failures += test_code_guide();
    failures += test_code_impact_conditional_include_edge();
    failures += test_code_impact_conditional_hazards();
    failures += test_code_impact_long_include_line();
    failures += test_code_impact_conditional_incremental();
    failures += test_code_impact_dotdot_include_edge();
    failures += test_code_impact_rootless_index_rebuilds();
    return failures;
}
