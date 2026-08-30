/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * code.capsule contract (WF4 4B/4D): the composed symbol capsule —
 * identity (linkage-aware id, def/decl site, signature, group/shape), direct
 * callers/callees, in-tree includes, the dispatch-index commands[] join, and
 * the code.tests route — plus the budget-aware self-shrinking that fits it
 * within ZCL_COMMAND_RESULT_BUDGET.
 *
 * Coverage:
 *   1. golden capsule       — a stable real symbol (sovereignty_guard_allow):
 *                             identity/def/callers non-empty, callers
 *                             deterministically ordered (ref_file, ref_line).
 *   2. dispatch join        — capsule(zcl_native_handle_code_sym) reports a
 *                             non-empty commands[] containing "code.sym", via
 *                             config/command_handler_index.h joined against
 *                             the code index's symbol table for that file.
 *   3. budget-shrink        — a purpose-built high-fan-in fixture (mirrors
 *                             test_codeindex.c's CG_FIX pattern) forces the
 *                             droppable sections (includes -> callees ->
 *                             callers) to shrink; the reply still fits the
 *                             budget and `dropped_sections` names what was
 *                             cut, in the fixed documented order, while
 *                             identity/def/route are never dropped. */

#include "test/test_core.h"
#include "codeindex/codeindex.h"
#include "config/command_handler_index.h"
#include "command/native_command.h"
#include "kernel/command_registry.h"
#include "json/json.h"

#include <stddef.h>
#include <string.h>
#include <sys/stat.h>

/* ── budget-shrink fixture ──────────────────────────────────────────────
 * A dedicated on-disk fixture (mirrors test_codeindex.c's mk_write/CG_FIX
 * pattern) so this test is deterministic and independent of the real repo's
 * ever-changing call graph. `cap_hot` is called by 10 long-named functions
 * in 10 separate long-named files, itself calls 10 long-named external
 * callees, and its def file's depfile lists 10 long-named padding headers —
 * long enough that even after each list is capped at 10 entries, the
 * serialized JSON overflows the reply budget and the self-shrink loop must
 * fire. */
#define CAP_BUDGET_FIX "test-tmp/cap_budget_fix"

static bool cap_budget_mk_write(const char *dir, const char *rel,
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

static bool write_cap_budget_fixture(void)
{
    bool ok = true;

    /* cap_hot.c: the target symbol, calling 10 long-named external callees. */
    char hot[8192];
    size_t n = 0;
    n += (size_t)snprintf(hot + n, sizeof(hot) - n,
                          "/* lib/net/src/cap_hot.c — budget-shrink fixture. */\n"
                          "#include \"net/cap_hot.h\"\n\nvoid cap_hot(void)\n{\n");
    for (int i = 0; i < 10; i++)
        n += (size_t)snprintf(hot + n, sizeof(hot) - n,
            "    callee_target_function_with_a_long_name_for_padding_number_%02d(0);\n",
            i);
    n += (size_t)snprintf(hot + n, sizeof(hot) - n, "}\n");
    ok = ok && cap_budget_mk_write(CAP_BUDGET_FIX, "lib/net/src/cap_hot.c", hot);

    char hoth[8192];
    n = 0;
    n += (size_t)snprintf(hoth + n, sizeof(hoth) - n,
        "#ifndef NET_CAP_HOT_H\n#define NET_CAP_HOT_H\nvoid cap_hot(void);\n");
    for (int i = 0; i < 10; i++)
        n += (size_t)snprintf(hoth + n, sizeof(hoth) - n,
            "int callee_target_function_with_a_long_name_for_padding_number_%02d(int x);\n",
            i);
    n += (size_t)snprintf(hoth + n, sizeof(hoth) - n, "#endif\n");
    ok = ok && cap_budget_mk_write(CAP_BUDGET_FIX,
                                   "lib/net/include/net/cap_hot.h", hoth);

    /* 10 long-named padding headers, all included by cap_hot.c via depfile. */
    char depfile[4096];
    n = 0;
    n += (size_t)snprintf(depfile + n, sizeof(depfile) - n,
        "build/obj/cap_hot.o: lib/net/src/cap_hot.c "
        "lib/net/include/net/cap_hot.h");
    for (int i = 0; i < 10; i++) {
        char hdr_rel[256];
        snprintf(hdr_rel, sizeof(hdr_rel),
            "lib/net/include/net/padding_header_number_%02d_with_a_very_long_"
            "filename_for_the_budget_shrink_fixture_test.h", i);
        ok = ok && cap_budget_mk_write(CAP_BUDGET_FIX, hdr_rel, "#pragma once\n");
        n += (size_t)snprintf(depfile + n, sizeof(depfile) - n, " %s", hdr_rel);
    }
    n += (size_t)snprintf(depfile + n, sizeof(depfile) - n, "\n");
    ok = ok && cap_budget_mk_write(CAP_BUDGET_FIX, "build/obj/cap_hot.d", depfile);

    /* 10 caller files, each with a long-named function calling cap_hot(). */
    for (int i = 0; i < 10; i++) {
        char rel[256];
        snprintf(rel, sizeof(rel),
            "lib/net/src/caller_module_for_budget_shrink_fixture_number_%02d_"
            "with_padding.c", i);
        char c[1024];
        snprintf(c, sizeof(c),
            "#include \"net/cap_hot.h\"\n"
            "void caller_function_with_a_reasonably_long_name_number_%02d(void)\n"
            "{\n    cap_hot();\n}\n", i);
        ok = ok && cap_budget_mk_write(CAP_BUDGET_FIX, rel, c);
    }
    return ok;
}

/* ── 1: golden capsule — identity/def/callers, deterministic ordering ── */
static int test_code_capsule_golden_symbol(void)
{
    int failures = 0;
    TEST("code_capsule: golden capsule (sovereignty_guard_allow) — identity, "
         "def, deterministically ordered callers") {
        struct json_value input;
        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "name", "sovereignty_guard_allow");
        struct zcl_command_request request = {
            .input = &input, .view = "normal", .invoked_name = "code.capsule",
        };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.code_capsule.v1");
        zcl_native_handle_code_capsule(&request, &reply);

        ASSERT(json_get_bool(json_get(&reply.data, "found")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "name")),
                     "sovereignty_guard_allow");

        const char *id = json_get_str(json_get(&reply.data, "id"));
        ASSERT(id && id[0] && strncmp(id, "fn:", 3) == 0);

        const char *def_path = json_get_str(json_get(&reply.data, "def_path"));
        ASSERT(def_path && def_path[0]);
        ASSERT(json_get_int(json_get(&reply.data, "def_line")) > 0);

        const char *sig = json_get_str(json_get(&reply.data, "signature"));
        ASSERT(sig && sig[0]);

        const struct json_value *callers = json_get(&reply.data, "callers");
        ASSERT(callers && callers->type == JSON_ARR && callers->num_children > 0);
        ASSERT(json_get_int(json_get(&reply.data, "caller_count")) ==
              (int64_t)callers->num_children);

        /* deterministic ordering: (ref_file, ref_line) non-decreasing. */
        bool ordered = true;
        for (size_t i = 1; i < callers->num_children; i++) {
            const char *f0 = json_get_str(json_get(&callers->children[i - 1], "file"));
            const char *f1 = json_get_str(json_get(&callers->children[i], "file"));
            int cmp = strcmp(f0, f1);
            if (cmp > 0) { ordered = false; break; }
            if (cmp == 0) {
                int64_t l0 = json_get_int(json_get(&callers->children[i - 1], "line"));
                int64_t l1 = json_get_int(json_get(&callers->children[i], "line"));
                if (l0 >= l1) { ordered = false; break; }
            }
        }
        ASSERT(ordered);

        const char *route = json_get_str(json_get(&reply.data, "route"));
        ASSERT(route && route[0]);

        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2: dispatch join — commands[] for a symbol behind a native handler ── */
static int test_code_capsule_commands_join(void)
{
    int failures = 0;
    TEST("code_capsule: commands[] joins the dispatch index "
         "(zcl_native_handle_code_sym -> code.sym)") {
        struct json_value input;
        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "name", "zcl_native_handle_code_sym");
        struct zcl_command_request request = {
            .input = &input, .view = "normal", .invoked_name = "code.capsule",
        };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.code_capsule.v1");
        zcl_native_handle_code_capsule(&request, &reply);

        ASSERT(json_get_bool(json_get(&reply.data, "found")));
        const struct json_value *cmds = json_get(&reply.data, "commands");
        ASSERT(cmds && cmds->type == JSON_ARR && cmds->num_children == 1);
        ASSERT(json_get_int(json_get(&reply.data, "command_count")) ==
              (int64_t)cmds->num_children);

        bool has_sym = false;
        for (size_t i = 0; i < cmds->num_children; i++)
            if (strcmp(json_get_str(&cmds->children[i]), "code.sym") == 0)
                has_sym = true;
        ASSERT(has_sym);
        const struct json_value *evidence = json_get(&reply.data, "evidence");
        ASSERT_STR_EQ(json_get_str(json_get(evidence, "registry")),
                      "exact_def_handler_name");
        ASSERT_STR_EQ(json_get_str(json_get(evidence, "includes")),
                      "exact_compiler_depfile_edges");
        const struct json_value *unknowns = json_get(&reply.data, "unknowns");
        ASSERT(unknowns && unknowns->type == JSON_ARR &&
               unknowns->num_children > 0);

        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3: stable static identity — exact lookup and file-scoped graph ───── */
static int test_code_capsule_static_id_is_exact(void)
{
    int failures = 0;
    TEST("code_capsule: stable id selects one same-named static definition "
         "and scopes its call graph to that file") {
        const char *id =
            "fn:static:lib/storage/src/wallet_projection.c:ensure_schema";
        struct json_value input;
        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "name", id);
        struct zcl_command_request request = {
            .input = &input, .view = "normal", .invoked_name = "code.capsule",
        };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.code_capsule.v1");
        zcl_native_handle_code_capsule(&request, &reply);

        ASSERT(json_get_bool(json_get(&reply.data, "found")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "query")), id);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "id")), id);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "resolution")),
                      "exact_stable_id");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "def_path")),
                      "lib/storage/src/wallet_projection.c");

        const struct json_value *callers = json_get(&reply.data, "callers");
        ASSERT(callers && callers->type == JSON_ARR);
        for (size_t i = 0; i < callers->num_children; i++)
            ASSERT_STR_EQ(json_get_str(
                json_get(&callers->children[i], "file")),
                "lib/storage/src/wallet_projection.c");
        const struct json_value *callees = json_get(&reply.data, "callees");
        ASSERT(callees && callees->type == JSON_ARR);
        for (size_t i = 0; i < callees->num_children; i++)
            ASSERT_STR_EQ(json_get_str(
                json_get(&callees->children[i], "file")),
                "lib/storage/src/wallet_projection.c");

        const struct json_value *others =
            json_get(&reply.data, "other_defs");
        ASSERT(others && others->type == JSON_ARR &&
               others->num_children > 0);
        for (size_t i = 0; i < others->num_children; i++) {
            const char *other_id = json_get_str(
                json_get(&others->children[i], "id"));
            ASSERT(other_id && strncmp(other_id, "fn:static:", 10) == 0);
            ASSERT(strcmp(other_id, id) != 0);
        }

        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_change_plan_symbol(void)
{
    int failures = 0;
    TEST("code_change_plan: exact stable symbol yields bounded read/edit/test plan") {
        struct json_value input;
        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "name",
            "fn:static:lib/storage/src/wallet_projection.c:ensure_schema");
        struct zcl_command_request request = {
            .input = &input, .view = "normal",
            .invoked_name = "code.change-plan",
        };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.code_change_plan.v1");
        zcl_native_handle_code_change_plan(&request, &reply);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "resolution")),
                      "exact_stable_id");
        ASSERT(json_get_bool(json_get(&reply.data, "symbol_found")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "symbol_id")),
            "fn:static:lib/storage/src/wallet_projection.c:ensure_schema");
        const struct json_value *read = json_get(&reply.data, "read");
        ASSERT(read && read->type == JSON_ARR && read->num_children > 0);
        ASSERT_STR_EQ(json_get_str(json_get(&read->children[0], "path")),
                      "lib/storage/src/wallet_projection.c");
        const struct json_value *tests = json_get(&reply.data, "test_groups");
        ASSERT(tests && tests->type == JSON_ARR && tests->num_children > 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;

    return failures;
}

static int test_code_change_plan_patch(void)
{
    int failures = 0;
    TEST("code_change_plan: unified patch extracts exact bounded paths") {
        struct json_value input;
        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "patch",
            "diff --git a/lib/json/src/json.c b/lib/json/src/json.c\n"
            "--- a/lib/json/src/json.c\n+++ b/lib/json/src/json.c\n@@ -1 +1 @@\n");
        struct zcl_command_request request = {
            .input = &input, .view = "normal",
            .invoked_name = "code.change-plan",
        };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.code_change_plan.v1");
        zcl_native_handle_code_change_plan(&request, &reply);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "resolution")),
                      "exact_patch_paths");
        const struct json_value *edit = json_get(&reply.data, "edit");
        ASSERT(edit && edit->type == JSON_ARR && edit->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(&edit->children[0], "path")),
                      "lib/json/src/json.c");
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4: budget-shrink — a high-fan-in symbol still fits, reports drops ── */
static int test_code_capsule_budget_shrink(void)
{
    int failures = 0;
    TEST("code_capsule: high-fan-in fixture symbol still fits the budget "
         "and reports dropped_sections in the fixed order") {
        system("rm -rf " CAP_BUDGET_FIX);
        ASSERT(write_cap_budget_fixture());

        struct zcl_command_context ctx = { .source_root = CAP_BUDGET_FIX };
        struct json_value input;
        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "name", "cap_hot");
        struct zcl_command_request request = {
            .input = &input, .context = &ctx, .view = "normal",
            .invoked_name = "code.capsule",
        };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.code_capsule.v1");
        zcl_native_handle_code_capsule(&request, &reply);

        ASSERT(json_get_bool(json_get(&reply.data, "found")));

        /* identity/def/route are NEVER dropped, even under shrink. */
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "name")), "cap_hot");
        const char *id = json_get_str(json_get(&reply.data, "id"));
        ASSERT(id && id[0]);
        const char *def_path = json_get_str(json_get(&reply.data, "def_path"));
        ASSERT(def_path && def_path[0]);
        const char *route = json_get_str(json_get(&reply.data, "route"));
        ASSERT(route && route[0]);

        const struct json_value *dropped =
            json_get(&reply.data, "dropped_sections");
        ASSERT(dropped && dropped->type == JSON_ARR && dropped->num_children > 0);
        /* fixed documented order: includes is always the first casualty. */
        ASSERT_STR_EQ(json_get_str(&dropped->children[0]), "includes");

        /* the reply itself still fits the kernel's per-leaf result budget. */
        char buf[8192];
        size_t n = json_write(&reply.data, buf, sizeof(buf));
        ASSERT(n > 0 && n < sizeof(buf) && n <= ZCL_COMMAND_RESULT_BUDGET);

        const char *summary = json_get_str(json_get(&reply.data, "summary"));
        ASSERT(summary && strstr(summary, "shrunk to fit budget") != NULL);

        zcl_command_reply_free(&reply);
        json_free(&input);
        system("rm -rf " CAP_BUDGET_FIX);
        PASS();
    } _test_next:;
    return failures;
}

int test_code_capsule(void)
{
    int failures = 0;
    failures += test_code_capsule_golden_symbol();
    failures += test_code_capsule_commands_join();
    failures += test_code_capsule_static_id_is_exact();
    failures += test_code_change_plan_symbol();
    failures += test_code_change_plan_patch();
    failures += test_code_capsule_budget_shrink();
    return failures;
}
