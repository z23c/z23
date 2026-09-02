/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Prove `code focus` ranking, tie-break, reasons, --list, and
 * UNKNOWN_SPECIALIST from a fixture index with two specialists. */

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_focus.h"
#include "command/native_command.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define FOCUS_FIX "test-tmp/code_focus_fix"

static bool focus_mk_write(const char *dir, const char *rel,
                           const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(full, 0755);
            *p = '/';
        }
    }
    FILE *f = fopen(full, "wb");
    if (!f)
        return false;
    if (content && content[0])
        fwrite(content, 1, strlen(content), f);
    fclose(f);
    return true;
}

static bool write_focus_fixture(void)
{
    bool ok = true;
    ok = ok && focus_mk_write(FOCUS_FIX, "core/modules/net/src/a.c",
        "/* purpose: focus fixture file a (failed group). */\n"
        "int focus_a(void) { return 1; }\n");
    ok = ok && focus_mk_write(FOCUS_FIX, "core/modules/net/src/b.c",
        "/* purpose: focus fixture file b (failed group, later path). */\n"
        "int focus_b(void) { return 2; }\n");
    ok = ok && focus_mk_write(FOCUS_FIX, "core/modules/net/src/c.c",
        "/* purpose: focus fixture file c (unrouted). */\n"
        "int focus_c(void) { return 3; }\n");
    ok = ok && focus_mk_write(FOCUS_FIX, "contexts/wallet/src/w.c",
        "/* purpose: focus fixture wallet file (other specialist). */\n"
        "int focus_w(void) { return 4; }\n");
    return ok;
}

static size_t focus_test_route(const char *path,
                               char (*out)[SPECIALIST_GROUP_MAX],
                               size_t cap, void *user)
{
    (void)user;
    if (!path || cap == 0)
        return 0;
    if (strstr(path, "/a.c") || strstr(path, "/b.c")) {
        (void)snprintf(out[0], SPECIALIST_GROUP_MAX, "%s", "net");
        return 1;
    }
    return 0;
}

static void focus_call_list(struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_bool(&input, "list", true);
    struct zcl_command_request request = {
        .input = &input, .view = "normal", .invoked_name = "code.focus",
    };
    zcl_command_reply_init(reply, "zcl.code_focus.v1");
    zcl_native_handle_code_focus(&request, reply);
    json_free(&input);
}

static void focus_call_name(const char *name, const char *source_root,
                            struct zcl_command_reply *reply)
{
    struct zcl_command_context ctx = { .source_root = source_root };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    if (name)
        (void)json_push_kv_str(&input, "specialist", name);
    struct zcl_command_request request = {
        .input = &input,
        .context = source_root ? &ctx : NULL,
        .view = "normal",
        .invoked_name = "code.focus",
    };
    zcl_command_reply_init(reply, "zcl.code_focus.v1");
    zcl_native_handle_code_focus(&request, reply);
    json_free(&input);
}

static int test_focus_list(void)
{
    int failures = 0;
    TEST("code_focus: --list names the seeded specialists in catalog order") {
        struct zcl_command_reply reply;
        focus_call_list(&reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        char buf[ZCL_COMMAND_RESULT_BUDGET + 1];
        size_t n = json_write(&reply.data, buf, sizeof(buf));
        ASSERT(n > 0 && n < sizeof(buf));
        ASSERT(strstr(buf, "\"scope\":\"list\"") != NULL);
        ASSERT(strstr(buf, "\"name\":\"consensus\"") != NULL);
        ASSERT(strstr(buf, "\"name\":\"net\"") != NULL);
        ASSERT(strstr(buf, "\"name\":\"storage\"") != NULL);
        ASSERT(strstr(buf, "\"name\":\"wallet\"") != NULL);
        ASSERT(strstr(buf, "\"name\":\"explorer\"") != NULL);
        ASSERT(strstr(buf, "\"name\":\"codeindex\"") != NULL);
        ASSERT(strstr(buf, "\"name\":\"lint\"") != NULL);
        ASSERT(strstr(buf, "\"name\":\"docs\"") != NULL);
        ASSERT(strstr(buf, "\"name\":\"platform\"") != NULL);
        ASSERT(strstr(buf, "\"name\":\"packages\"") != NULL);
        const char *first = strstr(buf, "\"name\":\"consensus\"");
        const char *second = strstr(buf, "\"name\":\"net\"");
        ASSERT(first && second && first < second);
        struct zcl_command_reply again;
        focus_call_list(&again);
        char buf2[ZCL_COMMAND_RESULT_BUDGET + 1];
        size_t n2 = json_write(&again.data, buf2, sizeof(buf2));
        ASSERT(n == n2 && memcmp(buf, buf2, n) == 0);
        zcl_command_reply_free(&reply);
        zcl_command_reply_free(&again);
        PASS();
    } _test_next:;
    return failures;
}

static int test_focus_unknown(void)
{
    int failures = 0;
    TEST("code_focus: unknown specialist is UNKNOWN_SPECIALIST") {
        struct zcl_command_reply reply;
        focus_call_name("no-such-specialist", NULL, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_INVALID);
        ASSERT(strcmp(reply.error.code, "UNKNOWN_SPECIALIST") == 0);
        ASSERT(strstr(reply.error.message, "code focus --list") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_focus_missing_run(void)
{
    int failures = 0;
    TEST("code_focus: missing last-run.json is no run recorded, not clean") {
        system("rm -rf " FOCUS_FIX);
        ASSERT(write_focus_fixture());
        struct specialist_focus_evidence ev;
        specialist_focus_evidence_clear(&ev);
        ASSERT(specialist_focus_load_failed_groups(FOCUS_FIX, &ev));
        ASSERT(ev.tests_run == SPECIALIST_FOCUS_ARTIFACT_MISSING);
        ASSERT(ev.failed_count == 0);

        struct zcl_command_reply reply;
        focus_call_name("net", FOCUS_FIX, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        char buf[ZCL_COMMAND_RESULT_BUDGET + 1];
        size_t n = json_write(&reply.data, buf, sizeof(buf));
        ASSERT(n > 0 && n < sizeof(buf));
        ASSERT(strstr(buf, "no run recorded") != NULL);
        ASSERT(strstr(buf, "\"status\":\"no run recorded\"") != NULL);
        ASSERT(strstr(buf, "\"source\":\".cache/test-timing/last-run.json\"")
               != NULL);
        zcl_command_reply_free(&reply);
        system("rm -rf " FOCUS_FIX);
        PASS();
    } _test_next:;
    return failures;
}

static int test_focus_lint_gates(void)
{
    int failures = 0;
    TEST("code_focus: failed owned lint gate scores territory with a cited reason") {
        system("rm -rf " FOCUS_FIX);
        ASSERT(write_focus_fixture());
        ASSERT(focus_mk_write(FOCUS_FIX, ".cache/lint-timing/last-run.json",
            "{\"schema\":\"zcl.lint_timing.v1\",\"gates\":["
            "{\"name\":\"check-malloc\",\"ms\":43,\"rc\":0},"
            "{\"name\":\"check-raw-sqlite\",\"ms\":5467,\"rc\":2}]}"));

        struct specialist_focus_evidence ev;
        specialist_focus_evidence_clear(&ev);
        ASSERT(ev.gates_run == SPECIALIST_FOCUS_ARTIFACT_MISSING);
        ASSERT(specialist_focus_load_failed_gates(FOCUS_FIX, &ev));
        ASSERT(ev.gates_run == SPECIALIST_FOCUS_ARTIFACT_RECORDED);
        ASSERT(ev.failed_gate_count == 1);
        ASSERT(strcmp(ev.failed_gates[0], "check-raw-sqlite") == 0);

        struct codeindex *ci = codeindex_open_source_view(FOCUS_FIX);
        ASSERT(ci != NULL);
        static const struct specialist spec = {
            "alpha", "core/modules/net", "check-raw-sqlite", "net", "p2p"
        };
        struct specialist_focus_hit hits[8];
        bool truncated = false;
        int n = specialist_focus_rank(ci, &spec, &ev, focus_test_route,
                                      NULL, hits, 8, &truncated);
        ASSERT(n == 3);
        ASSERT(!truncated);
        /* unrouted stacks on the lane-level gate weight, then path order */
        ASSERT(strcmp(hits[0].path, "core/modules/net/src/c.c") == 0);
        ASSERT(strcmp(hits[1].path, "core/modules/net/src/a.c") == 0);
        ASSERT(strcmp(hits[2].path, "core/modules/net/src/b.c") == 0);
        ASSERT(hits[0].score > hits[1].score);
        ASSERT(hits[1].score == hits[2].score);
        for (int i = 0; i < n; i++) {
            ASSERT(strstr(hits[i].reason,
                          "failed-gate:check-raw-sqlite "
                          "(.cache/lint-timing/last-run.json)") != NULL);
        }
        codeindex_close(ci);

        /* Reply honesty with no test artifact but a recorded lint run: the
         * storage lane owns check-raw-sqlite, so its gates block reports the
         * failure while tests still say no run recorded. */
        struct zcl_command_reply reply;
        focus_call_name("storage", FOCUS_FIX, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        char buf[ZCL_COMMAND_RESULT_BUDGET + 1];
        size_t bn = json_write(&reply.data, buf, sizeof(buf));
        ASSERT(bn > 0 && bn < sizeof(buf));
        ASSERT(strstr(buf, "\"tests\":{\"source\":"
                       "\".cache/test-timing/last-run.json\","
                       "\"status\":\"no run recorded\"}") != NULL);
        ASSERT(strstr(buf, "\"gates\":{\"source\":"
                       "\".cache/lint-timing/last-run.json\","
                       "\"status\":\"recorded\",\"failed_count\":1,"
                       "\"failed\":[\"check-raw-sqlite\"]}") != NULL);
        const char *sum = json_get_str(json_get(&reply.data, "summary"));
        ASSERT(sum && strstr(sum, "tests: no run recorded") != NULL);
        ASSERT(strstr(sum, "gates: no run recorded") == NULL);
        zcl_command_reply_free(&reply);

        /* A corrupt lint artifact fails closed, never a clean score. */
        ASSERT(focus_mk_write(FOCUS_FIX, ".cache/lint-timing/last-run.json",
                              "{oops"));
        struct specialist_focus_evidence bad;
        specialist_focus_evidence_clear(&bad);
        ASSERT(!specialist_focus_load_failed_gates(FOCUS_FIX, &bad));
        system("rm -rf " FOCUS_FIX);
        PASS();
    } _test_next:;
    return failures;
}

static size_t focus_flood_route(const char *path,
                                char (*out)[SPECIALIST_GROUP_MAX],
                                size_t cap, void *user)
{
    (void)user;
    if (!path || cap == 0)
        return 0;
    if (strstr(path, "/zz_failed.c")) {
        (void)snprintf(out[0], SPECIALIST_GROUP_MAX, "%s", "net");
        return 1;
    }
    return 0;
}

static int test_focus_work_cap(void)
{
    int failures = 0;
    TEST("code_focus: late failed-group file survives a full work set") {
        system("rm -rf " FOCUS_FIX);
        char rel[512];
        bool ok = true;
        /* WORK_CAP + 1 in-territory candidates: the unrouted fillers fill
         * any index-order cap first, and the failed-group file sorts last
         * (the codeindex pages files ORDER BY path ASC). */
        for (int i = 0; i < SPECIALIST_FOCUS_WORK_CAP && ok; i++) {
            snprintf(rel, sizeof rel, "core/modules/net/src/g%03d.c", i);
            ok = focus_mk_write(FOCUS_FIX, rel,
                "/* purpose: focus fixture unrouted filler. */\nint g(void);\n");
        }
        ok = ok && focus_mk_write(FOCUS_FIX, "core/modules/net/src/zz_failed.c",
            "/* purpose: focus fixture failed-group file sorting last. */\n"
            "int zz(void);\n");
        ASSERT(ok);

        struct codeindex *ci = codeindex_open_source_view(FOCUS_FIX);
        ASSERT(ci != NULL);
        static const struct specialist spec = {
            "alpha", "core/modules/net", "check-malloc", "net", "p2p"
        };
        struct specialist_focus_evidence ev;
        specialist_focus_evidence_clear(&ev);
        (void)snprintf(ev.failed[0], sizeof ev.failed[0], "%s", "net");
        ev.failed_count = 1;

        struct specialist_focus_hit hits[8];
        bool truncated = false;
        int n = specialist_focus_rank(ci, &spec, &ev, focus_flood_route,
                                      NULL, hits, 8, &truncated);
        ASSERT(n == 8);
        ASSERT(truncated);
        ASSERT(strcmp(hits[0].path, "core/modules/net/src/zz_failed.c") == 0);
        ASSERT(hits[0].score > hits[1].score);
        ASSERT(strstr(hits[0].reason,
                      "failed-group:net (.cache/test-timing/last-run.json)")
               != NULL);
        for (int i = 1; i < n; i++)
            ASSERT(strstr(hits[i].reason, "unrouted:agent_impact_rules")
                   != NULL);
        ASSERT(strcmp(hits[1].path, "core/modules/net/src/g000.c") == 0);
        ASSERT(strcmp(hits[2].path, "core/modules/net/src/g001.c") == 0);
        codeindex_close(ci);
        system("rm -rf " FOCUS_FIX);
        PASS();
    } _test_next:;
    return failures;
}

static int test_focus_rank(void)
{
    int failures = 0;
    TEST("code_focus: fixture ranking order, tie-break, and reason sources") {
        system("rm -rf " FOCUS_FIX);
        ASSERT(write_focus_fixture());
        struct codeindex *ci = codeindex_open_source_view(FOCUS_FIX);
        ASSERT(ci != NULL);

        static const struct specialist specs[2] = {
            { "alpha", "core/modules/net", "check-malloc", "net", "p2p" },
            { "beta", "contexts/wallet", "check-wallet-raw-prepare-log",
              "wallet", "wallet" },
        };
        struct specialist_focus_evidence ev;
        specialist_focus_evidence_clear(&ev);
        (void)snprintf(ev.failed[0], sizeof ev.failed[0], "%s", "net");
        ev.failed_count = 1;

        struct specialist_focus_hit hits[8];
        bool truncated = false;
        int n = specialist_focus_rank(ci, &specs[0], &ev, focus_test_route,
                                      NULL, hits, 8, &truncated);
        ASSERT(n >= 3);
        ASSERT(!truncated);
        ASSERT(strcmp(hits[0].path, "core/modules/net/src/a.c") == 0);
        ASSERT(strcmp(hits[1].path, "core/modules/net/src/b.c") == 0);
        ASSERT(hits[0].score == hits[1].score);
        ASSERT(hits[0].score > hits[2].score);
        ASSERT(strstr(hits[0].reason,
                      "failed-group:net (.cache/test-timing/last-run.json)")
               != NULL);
        ASSERT(strstr(hits[1].reason,
                      "failed-group:net (.cache/test-timing/last-run.json)")
               != NULL);
        int unrouted_at = -1;
        for (int i = 0; i < n; i++) {
            if (strcmp(hits[i].path, "core/modules/net/src/c.c") == 0)
                unrouted_at = i;
            ASSERT(strstr(hits[i].path, "contexts/wallet") == NULL);
        }
        ASSERT(unrouted_at >= 0);
        ASSERT(strstr(hits[unrouted_at].reason, "unrouted:agent_impact_rules")
               != NULL);

        struct specialist_focus_hit beta[8];
        int nb = specialist_focus_rank(ci, &specs[1], &ev, focus_test_route,
                                       NULL, beta, 8, &truncated);
        ASSERT(nb >= 1);
        ASSERT(strcmp(beta[0].path, "contexts/wallet/src/w.c") == 0);
        ASSERT(strstr(beta[0].reason, "unrouted:agent_impact_rules") != NULL);

        char first[sizeof hits[0].reason];
        memcpy(first, hits[0].reason, sizeof first);
        n = specialist_focus_rank(ci, &specs[0], &ev, focus_test_route,
                                  NULL, hits, 8, &truncated);
        ASSERT(n >= 3);
        ASSERT(strcmp(hits[0].reason, first) == 0);

        codeindex_close(ci);
        system("rm -rf " FOCUS_FIX);
        PASS();
    } _test_next:;
    return failures;
}

int test_code_focus(void)
{
    int failures = 0;
    failures += test_focus_list();
    failures += test_focus_unknown();
    failures += test_focus_missing_run();
    failures += test_focus_lint_gates();
    failures += test_focus_work_cap();
    failures += test_focus_rank();
    return failures;
}
