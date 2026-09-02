/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * code_firsthour — the M3 "first-hour questions" contract: the three agent
 * leaves that tell a fresh agent where to focus in seconds.
 *
 * Coverage:
 *   1. owner — a contexts/<feature>/ file reports its context and shape; a
 *      core/ path reports sealed=true; a modules/ path reports its nearest
 *      owning module directory; an unindexed, absent path is UNOWNED without
 *      an error status; a missing path input is a MISSING_PATH error body.
 *   2. cost  — route/test_groups match `code tests` for the same path; with
 *      no timing artifact every group is measured=false; with a synthetic
 *      last-run.json the measured path reports real numbers.
 *   3. recent — a git fixture with three commits returns exactly the later
 *      commits newest-first for `since <first>`; a bogus ref fails closed
 *      with GIT_LOG_FAILED.
 *
 * All scratch work happens under ./test-tmp/ (project no-/tmp convention). */

#include "test/test_core.h"

#include "command/native_command.h"
#include "kernel/command_registry.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define FH_FIX "test-tmp/ci_firsthour"

/* Write content to <dir>/<rel>, creating parent dirs. */
static bool fh_mk_write(const char *dir, const char *rel, const char *content)
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

static bool write_fh_fixture(void)
{
    return fh_mk_write(FH_FIX, "contexts/messaging/src/firsthour_msg.c",
        "/* contexts/messaging/src/firsthour_msg.c — first-hour fixture. */\n"
        "int firsthour_msg(void)\n{\n    return 1;\n}\n") &&
        fh_mk_write(FH_FIX, "core/consensus/src/firsthour_sealed.c",
        "/* core/consensus/src/firsthour_sealed.c — sealed-room fixture. */\n"
        "int firsthour_sealed(void)\n{\n    return 2;\n}\n") &&
        fh_mk_write(FH_FIX,
        "cognition/modules/codeindex/src/firsthour_probe.c",
        "/* cognition/modules/codeindex/src/firsthour_probe.c — module "
        "fixture. */\n"
        "int firsthour_probe(void)\n{\n    return 3;\n}\n") &&
        fh_mk_write(FH_FIX, "docs/examples/firsthour_documented.c",
        "/* docs/examples/firsthour_documented.c — documented fixture. */\n"
        "int firsthour_documented(void)\n{\n    return 4;\n}\n");
}

static void fh_call(void (*handler)(const struct zcl_command_request *,
                                    struct zcl_command_reply *),
                    const char *schema, const char *invoked,
                    const char *path, const char *since,
                    struct zcl_command_reply *reply)
{
    struct zcl_command_context ctx = { .source_root = FH_FIX };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    if (path) (void)json_push_kv_str(&input, "path", path);
    if (since) (void)json_push_kv_str(&input, "since", since);
    struct zcl_command_request request = {
        .input = &input, .context = &ctx,
        .view = "normal", .invoked_name = invoked,
    };
    zcl_command_reply_init(reply, schema);
    handler(&request, reply);
    json_free(&input);
}

/* ── 1: code owner ── */
static int test_fh_owner_contexts(void)
{
    int failures = 0;
    TEST("code_firsthour: owner classifies a contexts/ room file") {
        struct zcl_command_reply reply;
        fh_call(zcl_native_handle_code_owner, "zcl.code_owner.v1",
                "code.owner", "contexts/messaging/src/firsthour_msg.c",
                NULL, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        ASSERT(json_get_bool(json_get(&reply.data, "exists")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "verdict")), "OWNED");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "authority")),
                      "contexts");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "context")),
                      "messaging");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "shape")), "src");
        ASSERT(!json_get_bool(json_get(&reply.data, "sealed")));
        ASSERT(json_get_str(json_get(&reply.data, "summary")) != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fh_owner_sealed(void)
{
    int failures = 0;
    TEST("code_firsthour: owner flags a core/ path as consensus-sealed") {
        struct zcl_command_reply reply;
        fh_call(zcl_native_handle_code_owner, "zcl.code_owner.v1",
                "code.owner", "core/consensus/src/firsthour_sealed.c",
                NULL, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "verdict")), "OWNED");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "authority")), "core");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "context")), "core");
        ASSERT(json_get_bool(json_get(&reply.data, "sealed")));
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fh_owner_module(void)
{
    int failures = 0;
    TEST("code_firsthour: owner names the nearest owning module directory") {
        struct zcl_command_reply reply;
        fh_call(zcl_native_handle_code_owner, "zcl.code_owner.v1",
                "code.owner",
                "cognition/modules/codeindex/src/firsthour_probe.c",
                NULL, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "verdict")), "OWNED");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "module")),
                      "cognition/modules/codeindex");
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fh_owner_unowned(void)
{
    int failures = 0;
    TEST("code_firsthour: an unindexed absent path is UNOWNED, not an error") {
        struct zcl_command_reply reply;
        fh_call(zcl_native_handle_code_owner, "zcl.code_owner.v1",
                "code.owner", "vendorish/nothing_here.c", NULL, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        ASSERT(!json_get_bool(json_get(&reply.data, "exists")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "verdict")),
                      "UNOWNED");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "group")), "");
        ASSERT(strstr(json_get_str(json_get(&reply.data, "summary")),
                      "UNOWNED") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fh_owner_missing_path(void)
{
    int failures = 0;
    TEST("code_firsthour: owner refuses a missing path with an error body") {
        struct zcl_command_reply reply;
        fh_call(zcl_native_handle_code_owner, "zcl.code_owner.v1",
                "code.owner", NULL, NULL, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "MISSING_PATH");
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2: code cost ── */
static int test_fh_cost_unmeasured(void)
{
    int failures = 0;
    TEST("code_firsthour: cost route matches code tests, unmeasured without "
         "an artifact") {
        struct zcl_command_reply cost;
        fh_call(zcl_native_handle_code_cost, "zcl.code_cost.v1", "code.cost",
                "cognition/modules/codeindex/src/firsthour_probe.c",
                NULL, &cost);
        ASSERT(cost.status != ZCL_COMMAND_STATUS_FAILED);

        struct zcl_command_reply tests;
        fh_call(zcl_native_handle_code_tests, "zcl.code_tests.v1",
                "code.tests",
                "cognition/modules/codeindex/src/firsthour_probe.c",
                NULL, &tests);
        ASSERT(tests.status != ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(json_get_str(json_get(&cost.data, "route")),
                      json_get_str(json_get(&tests.data, "route")));
        const struct json_value *cost_groups =
            json_get(&cost.data, "test_groups");
        const struct json_value *tests_groups =
            json_get(&tests.data, "test_groups");
        ASSERT(cost_groups && tests_groups &&
               cost_groups->num_children == tests_groups->num_children);
        ASSERT(json_get_int(json_get(&cost.data, "total_groups")) ==
               (int64_t)cost_groups->num_children);
        ASSERT(json_get_int(json_get(&cost.data, "measured_groups")) == 0);
        ASSERT(json_get_int(json_get(&cost.data, "total_ms")) == 0);
        const struct json_value *rows = json_get(&cost.data, "groups");
        ASSERT(rows && rows->type == JSON_ARR &&
               rows->num_children == cost_groups->num_children);
        for (size_t i = 0; i < rows->num_children; i++)
            ASSERT(!json_get_bool(json_get(json_at(rows, i), "measured")));
        ASSERT(strstr(json_get_str(json_get(&cost.data, "summary")),
                      "not measured") != NULL);
        zcl_command_reply_free(&cost);
        zcl_command_reply_free(&tests);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fh_cost_measured(void)
{
    int failures = 0;
    TEST("code_firsthour: cost reads the suite timing artifact when present") {
        ASSERT(fh_mk_write(FH_FIX, ".cache/test-timing/last-run.json",
            "{\n"
            "  \"schema\":\"zcl.test_timing.v1\",\n"
            "  \"groups\":[\n"
            "    {\"name\":\"test_codeindex\",\"ms\":68000,\"rc\":0,"
            "\"signaled\":false,\"cached\":true}\n"
            "  ]\n}\n"));
        struct zcl_command_reply cost;
        fh_call(zcl_native_handle_code_cost, "zcl.code_cost.v1", "code.cost",
                "cognition/modules/codeindex/src/firsthour_probe.c",
                NULL, &cost);
        ASSERT(cost.status != ZCL_COMMAND_STATUS_FAILED);
        ASSERT(json_get_int(json_get(&cost.data, "measured_groups")) == 1);
        ASSERT(json_get_int(json_get(&cost.data, "total_ms")) == 68000);
        const struct json_value *rows = json_get(&cost.data, "groups");
        ASSERT(rows && rows->type == JSON_ARR && rows->num_children >= 1);
        const struct json_value *measured_row = NULL;
        size_t measured_rows = 0;
        for (size_t i = 0; i < rows->num_children; i++) {
            const struct json_value *row = json_at(rows, i);
            if (json_get_bool(json_get(row, "measured"))) {
                measured_rows++;
                measured_row = row;
            }
        }
        ASSERT(measured_rows == 1 && measured_row);
        ASSERT_STR_EQ(json_get_str(json_get(measured_row, "name")),
                      "codeindex");
        ASSERT(json_get_int(json_get(measured_row, "ms")) == 68000);
        ASSERT(json_get_bool(json_get(measured_row, "cached")));
        ASSERT(json_get_int(json_get(measured_row, "rc")) == 0);
        zcl_command_reply_free(&cost);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3: code recent ── */
static bool fh_git(const char *args)
{
    char cmd[4096];
    int n = snprintf(cmd, sizeof(cmd), "git -C %s %s", FH_FIX, args);
    if (n <= 0 || (size_t)n >= sizeof(cmd)) return false;
    return system(cmd) == 0;
}

static bool write_fh_git_fixture(void)
{
    return fh_git("init -q -b main") &&
        fh_git("add contexts docs core cognition") &&
        fh_git("-c user.name='First Hour' -c user.email=firsthour@fixture "
               "commit -qm 'one: seed the fixture'") &&
        fh_mk_write(FH_FIX, "contexts/messaging/src/firsthour_msg.c",
        "/* contexts/messaging/src/firsthour_msg.c — second pass. */\n"
        "int firsthour_msg(void)\n{\n    return 11;\n}\n") &&
        fh_git("add contexts/messaging/src/firsthour_msg.c") &&
        fh_git("-c user.name='First Hour' -c user.email=firsthour@fixture "
               "commit -qm 'two: retune the messaging fixture'") &&
        fh_mk_write(FH_FIX, "contexts/messaging/src/firsthour_msg.c",
        "/* contexts/messaging/src/firsthour_msg.c — third pass. */\n"
        "int firsthour_msg(void)\n{\n    return 111;\n}\n") &&
        fh_git("add contexts/messaging/src/firsthour_msg.c") &&
        fh_git("-c user.name='First Hour' -c user.email=firsthour@fixture "
               "commit -qm 'three: retune the messaging fixture again'");
}

static int test_fh_recent_history(void)
{
    int failures = 0;
    TEST("code_firsthour: recent lists the commits since a ref, newest "
         "first") {
        ASSERT(write_fh_git_fixture());
        struct zcl_command_reply reply;
        fh_call(zcl_native_handle_code_recent, "zcl.code_recent.v1",
                "code.recent", "contexts/messaging/src/firsthour_msg.c",
                "HEAD~2", &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        ASSERT(json_get_int(json_get(&reply.data, "count")) == 2);
        ASSERT(json_get_int(json_get(&reply.data, "total")) == 2);
        ASSERT(!json_get_bool(json_get(&reply.data, "truncated")));
        const struct json_value *commits = json_get(&reply.data, "commits");
        ASSERT(commits && commits->type == JSON_ARR &&
               commits->num_children == 2);
        const struct json_value *newest = json_at(commits, 0);
        const struct json_value *oldest = json_at(commits, 1);
        ASSERT_STR_EQ(json_get_str(json_get(newest, "summary")),
                      "three: retune the messaging fixture again");
        ASSERT_STR_EQ(json_get_str(json_get(oldest, "summary")),
                      "two: retune the messaging fixture");
        ASSERT(strlen(json_get_str(json_get(newest, "commit"))) == 40);
        ASSERT(strlen(json_get_str(json_get(newest, "date"))) == 10);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fh_recent_bogus_since(void)
{
    int failures = 0;
    TEST("code_firsthour: recent fails closed on a bogus since ref") {
        struct zcl_command_reply reply;
        fh_call(zcl_native_handle_code_recent, "zcl.code_recent.v1",
                "code.recent", "contexts/messaging/src/firsthour_msg.c",
                "no-such-ref-anywhere", &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "GIT_LOG_FAILED");
        ASSERT(strstr(reply.error.message, "git log") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fh_recent_missing_inputs(void)
{
    int failures = 0;
    TEST("code_firsthour: recent requires path and since") {
        struct zcl_command_reply reply;
        fh_call(zcl_native_handle_code_recent, "zcl.code_recent.v1",
                "code.recent", NULL, NULL, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "MISSING_PATH");
        zcl_command_reply_free(&reply);
        fh_call(zcl_native_handle_code_recent, "zcl.code_recent.v1",
                "code.recent", "contexts/messaging/src/firsthour_msg.c",
                NULL, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "MISSING_SINCE");
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

int test_code_firsthour(void)
{
    int failures = 0;
    (void)system("rm -rf " FH_FIX);
    if (!write_fh_fixture()) {
        printf("  code_firsthour: fixture write... FAIL\n");
        return 1;
    }
    failures += test_fh_owner_contexts();
    failures += test_fh_owner_sealed();
    failures += test_fh_owner_module();
    failures += test_fh_owner_unowned();
    failures += test_fh_owner_missing_path();
    failures += test_fh_cost_unmeasured();
    failures += test_fh_cost_measured();
    failures += test_fh_recent_history();
    failures += test_fh_recent_bogus_since();
    failures += test_fh_recent_missing_inputs();
    return failures;
}
