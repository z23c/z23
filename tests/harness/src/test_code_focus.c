/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Prove `code focus` ranking, tie-break, reasons, --list, and
 * UNKNOWN_SPECIALIST from a fixture index with two specialists. */

#include "test/test_core.h"

#include "base/safe_alloc.h"
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
 TEST_DISCARD(system("rm -rf " FOCUS_FIX));
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
 TEST_DISCARD(system("rm -rf " FOCUS_FIX));
        PASS();
    } _test_next:;
    return failures;
}

static int test_focus_malformed_run(void)
{
    int failures = 0;
    TEST("code_focus: malformed timing rows refuse instead of becoming valid evidence") {
        static const char *const bad[] = {
            "{}",
            "{\"groups\":null}",
            "{\"groups\":[1]}",
            "{\"groups\":[{\"rc\":1}]}",
            "{\"groups\":[{\"name\":\"\",\"rc\":1}]}",
            "{\"groups\":[{\"name\":7,\"rc\":1}]}",
            "{\"groups\":[{\"name\":\"net\"}]}",
            "{\"groups\":[{\"name\":\"net\",\"rc\":\"1\"}]}",
            "{\"groups\":[{\"name\":\"net\",\"rc\":0.5}]}",
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            ASSERT(focus_mk_write(FOCUS_FIX, ".cache/test-timing/last-run.json", bad[i]));
            struct specialist_focus_evidence ev;
            specialist_focus_evidence_clear(&ev);
            ASSERT(!specialist_focus_load_failed_groups(FOCUS_FIX, &ev));
            ASSERT(ev.tests_run == SPECIALIST_FOCUS_ARTIFACT_RECORDED);
        }
        ASSERT(focus_mk_write(FOCUS_FIX, ".cache/test-timing/last-run.json",
            "{\"groups\":[{\"name\":\"test_fleet_parity\",\"rc\":1},"
            "{\"name\":\"\",\"rc\":0}]}"));
        struct specialist_focus_evidence ev;
        specialist_focus_evidence_clear(&ev);
        ASSERT(!specialist_focus_load_failed_groups(FOCUS_FIX, &ev));
        ASSERT(ev.tests_run == SPECIALIST_FOCUS_ARTIFACT_RECORDED);
        ASSERT(ev.failed_count == 1);
        ASSERT_STR_EQ(ev.failed[0], "test_fleet_parity");

        ASSERT(focus_mk_write(FOCUS_FIX, ".cache/lint-timing/last-run.json",
                              "{\"gates\":[{\"name\":\"check-malloc\"}]}"));
        specialist_focus_evidence_clear(&ev);
        ASSERT(!specialist_focus_load_failed_gates(FOCUS_FIX, &ev));
        ASSERT(ev.gates_run == SPECIALIST_FOCUS_ARTIFACT_RECORDED);

        ASSERT(focus_mk_write(FOCUS_FIX, ".cache/test-timing/last-run.json",
            "{\"groups\":[{\"name\":\"net\",\"rc\":0},"
            "{\"name\":\"test_fleet_parity\",\"rc\":1}]}"));
        specialist_focus_evidence_clear(&ev);
        ASSERT(specialist_focus_load_failed_groups(FOCUS_FIX, &ev));
        ASSERT(ev.tests_run == SPECIALIST_FOCUS_ARTIFACT_RECORDED);
        ASSERT(ev.failed_count == 1);
        ASSERT_STR_EQ(ev.failed[0], "test_fleet_parity");
        PASS();
    } _test_next:;
    test_rm_rf_recursive(FOCUS_FIX);
    return failures;
}

static bool focus_write_boundary(bool gates, size_t cap, int extra)
{
    char raw[4096];
    int n = snprintf(raw, sizeof(raw), "{\"%s\":[", gates ? "gates" : "groups");
    if (n < 0 || (size_t)n >= sizeof(raw))
        return false;
    size_t used = (size_t)n;
    size_t rows = cap + (extra != 0);
    for (size_t i = 0; i < rows; i++) {
        size_t id = extra == 2 && i == cap ? 0 : i;
        n = snprintf(raw + used, sizeof(raw) - used,
                     "%s{\"name\":\"failure_%zu\",\"rc\":1}", i ? "," : "", id);
        if (n < 0 || (size_t)n >= sizeof(raw) - used)
            return false;
        used += (size_t)n;
    }
    n = snprintf(raw + used, sizeof(raw) - used, "]}");
    if (n < 0 || (size_t)n >= sizeof(raw) - used)
        return false;
    return focus_mk_write(FOCUS_FIX, gates ? ".cache/lint-timing/last-run.json"
                                          : ".cache/test-timing/last-run.json", raw);
}

static int focus_test_failure_capacity(bool gates)
{
    int failures = 0;
    TEST(gates ? "code_focus: 32 gates fit, duplicates fit, gate 33 refuses"
               : "code_focus: 64 groups fit, duplicates fit, group 65 refuses") {
        size_t cap = gates ? SPECIALIST_FOCUS_GATE_CAP : SPECIALIST_FOCUS_FAILED_CAP;
        bool (*load)(const char *, struct specialist_focus_evidence *) = gates
            ? specialist_focus_load_failed_gates : specialist_focus_load_failed_groups;
        ASSERT(focus_write_boundary(gates, cap, 0));
        struct specialist_focus_evidence ev, full;
        specialist_focus_evidence_clear(&ev);
        ASSERT(load(FOCUS_FIX, &ev));
        ASSERT((gates ? ev.gates_run : ev.tests_run) == SPECIALIST_FOCUS_ARTIFACT_RECORDED);
        ASSERT((gates ? ev.failed_gate_count : ev.failed_count) == cap);
        for (size_t i = 0; i < cap; i++) {
            char name[SPECIALIST_GROUP_MAX];
            int n = snprintf(name, sizeof(name), "failure_%zu", i);
            ASSERT(n > 0 && (size_t)n < sizeof(name));
            ASSERT(strcmp(gates ? ev.failed_gates[i] : ev.failed[i], name) == 0);
        }
        memcpy(&full, &ev, sizeof(full));
        ASSERT(focus_write_boundary(gates, cap, 2));
        specialist_focus_evidence_clear(&ev);
        ASSERT(load(FOCUS_FIX, &ev));
        ASSERT(memcmp(&ev, &full, sizeof(ev)) == 0);
        ASSERT(focus_write_boundary(gates, cap, 1));
        specialist_focus_evidence_clear(&ev);
        ASSERT(!load(FOCUS_FIX, &ev));
        /* Present artifact remains RECORDED; the bounded prefix and every
         * unrelated evidence field survive refusal without an extra name. */
        ASSERT(memcmp(&ev, &full, sizeof(ev)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_focus_lint_gates(void)
{
    int failures = 0;
    TEST("code_focus: failed owned lint gate scores territory with a cited reason") {
 TEST_DISCARD(system("rm -rf " FOCUS_FIX));
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

        /* No test artifact but a recorded lint run: the storage lane owns
         * check-raw-sqlite, so its gates block reports the failure while
         * tests still say no run recorded. */
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
 TEST_DISCARD(system("rm -rf " FOCUS_FIX));
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
 TEST_DISCARD(system("rm -rf " FOCUS_FIX));
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
 TEST_DISCARD(system("rm -rf " FOCUS_FIX));
        PASS();
    } _test_next:;
    return failures;
}

static int test_focus_recorded_run(void)
{
    int failures = 0;
    TEST("code_focus: a real mini last-run.json records failures it names") {
 TEST_DISCARD(system("rm -rf " FOCUS_FIX));
        ASSERT(write_focus_fixture());
        /* Byte-shape of tests/harness/src/test_parallel.c output, trimmed
         * to the rows the loader reads. test_net failed; download passed;
         * the specialist routes a.c/b.c to the `net` group. */
        ASSERT(focus_mk_write(FOCUS_FIX, ".cache/test-timing/last-run.json",
            "{\"schema\":\"zcl.test_timing.v1\","
            "\"generated_at_utc\":\"2026-09-02T00:00:00Z\","
            "\"wall_ms\":17,\"failed_count\":1,\"groups\":["
            "{\"name\":\"test_net\",\"ms\":12,\"rc\":1,\"signaled\":false,"
            "\"cached\":false},"
            "{\"name\":\"download\",\"ms\":5,\"rc\":0,\"signaled\":false,"
            "\"cached\":false}]}"));

        struct specialist_focus_evidence ev;
        specialist_focus_evidence_clear(&ev);
        ASSERT(specialist_focus_load_failed_groups(FOCUS_FIX, &ev));
        ASSERT(ev.tests_run == SPECIALIST_FOCUS_ARTIFACT_RECORDED);
        ASSERT(ev.failed_count == 1);
        ASSERT(strcmp(ev.failed[0], "test_net") == 0);

        struct codeindex *ci = codeindex_open_source_view(FOCUS_FIX);
        ASSERT(ci != NULL);
        static const struct specialist spec = {
            "alpha", "core/modules/net", "check-malloc", "net", "p2p"
        };
        struct specialist_focus_hit hits[8];
        bool truncated = false;
        int n = specialist_focus_rank(ci, &spec, &ev, focus_test_route,
                                      NULL, hits, 8, &truncated);
        ASSERT(n == 3);
        ASSERT(!truncated);
        ASSERT(strcmp(hits[0].path, "core/modules/net/src/a.c") == 0);
        ASSERT(strcmp(hits[1].path, "core/modules/net/src/b.c") == 0);
        ASSERT(hits[0].score == hits[1].score);
        ASSERT(hits[0].score > hits[2].score);
        ASSERT(strstr(hits[0].reason,
                      "failed-group:test_net "
                      "(.cache/test-timing/last-run.json)") != NULL);
        ASSERT(strstr(hits[2].reason, "unrouted:agent_impact_rules") != NULL);
        codeindex_close(ci);

        /* End to end with a recorded test run and no lint run: each source
         * reports its own truth — recorded with the failed count, and no
         * run recorded — in the same reply. */
        struct zcl_command_reply reply;
        focus_call_name("net", FOCUS_FIX, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        char buf[ZCL_COMMAND_RESULT_BUDGET + 1];
        size_t bn = json_write(&reply.data, buf, sizeof(buf));
        ASSERT(bn > 0 && bn < sizeof(buf));
        ASSERT(strstr(buf, "\"tests\":{\"source\":"
                       "\".cache/test-timing/last-run.json\","
                       "\"status\":\"recorded\",\"failed_count\":1}")
               != NULL);
        ASSERT(strstr(buf, "\"status\":\"no run recorded\"}") != NULL);
        const char *sum = json_get_str(json_get(&reply.data, "summary"));
        ASSERT(sum && strstr(sum, "gates: no run recorded") != NULL);
        ASSERT(strstr(sum, "tests: no run recorded") == NULL);
        zcl_command_reply_free(&reply);
 TEST_DISCARD(system("rm -rf " FOCUS_FIX));
        PASS();
    } _test_next:;
    return failures;
}

static int test_focus_rank(void)
{
    int failures = 0;
    TEST("code_focus: fixture ranking order, tie-break, and reason sources") {
 TEST_DISCARD(system("rm -rf " FOCUS_FIX));
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
 TEST_DISCARD(system("rm -rf " FOCUS_FIX));
        PASS();
    } _test_next:;
    return failures;
}

static bool focus_write_capped_notes(const char *tail)
{
    if (!focus_mk_write(FOCUS_FIX, "docs/agent/LESSONS.md", ""))
        return false;
    FILE *f = fopen(FOCUS_FIX "/docs/agent/LESSONS.md", "wb");
    if (!f)
        return false;
    char spaces[4096];
    memset(spaces, ' ', sizeof spaces);
    bool ok = true;
    for (size_t i = 0; i < 64 && ok; i++)
        ok = fwrite(spaces, 1, sizeof spaces, f) == sizeof spaces;
    size_t n = strlen(tail);
    if (ok)
        ok = fwrite(tail, 1, n, f) == n;
    if (fclose(f) != 0)
        ok = false;
    return ok;
}

static int test_focus_notes_read_cap(void)
{
    int failures = 0;
    TEST("code_focus: notes beyond the read cap refuse without changing evidence") {
 TEST_DISCARD(system("rm -rf " FOCUS_FIX));
        ASSERT(focus_write_capped_notes("`contexts/net/src/tail.c`\n"));
        struct specialist_focus_evidence ev;
        specialist_focus_evidence_clear(&ev);
        ASSERT(!specialist_focus_load_notes(FOCUS_FIX, &ev));
        ASSERT(ev.notes_count == 0);
        ASSERT(ev.notes[0].path[0] == '\0');
        ASSERT(ev.notes[0].source[0] == '\0');
        ASSERT(focus_mk_write(FOCUS_FIX, "docs/agent/LESSONS.md",
                              "`contexts/net/src/small.c`\n"));
        ASSERT(specialist_focus_load_notes(FOCUS_FIX, &ev));
        ASSERT(ev.notes_count == 1);
        ASSERT(strcmp(ev.notes[0].path, "contexts/net/src/small.c") == 0);
        ASSERT(strcmp(ev.notes[0].source, "docs/agent/LESSONS.md") == 0);
        ASSERT(focus_write_capped_notes("`contexts/net/src/tail.c`\n"));
        ASSERT(!specialist_focus_load_notes(FOCUS_FIX, &ev));
        ASSERT(ev.notes_count == 1);
        ASSERT(strcmp(ev.notes[0].path, "contexts/net/src/small.c") == 0);
        ASSERT(strcmp(ev.notes[0].source, "docs/agent/LESSONS.md") == 0);
        ASSERT(focus_write_capped_notes(""));
        specialist_focus_evidence_clear(&ev);
        ASSERT(specialist_focus_load_notes(FOCUS_FIX, &ev));
        ASSERT(ev.notes_count == 0);
 TEST_DISCARD(system("rm -rf " FOCUS_FIX));
        PASS();
    } _test_next:;
    return failures;
}

static int test_focus_selected_root(void)
{
    int failures = 0;
    TEST("code_focus: failed referrer is routed from the selected root") {
        test_rm_rf_recursive(FOCUS_FIX);
        ASSERT(focus_mk_write(FOCUS_FIX, "tools/command/native_code_focus_" "beacon1109.c",
                              "int focus_beacon1109(void) { return 0; }\n"));
        ASSERT(focus_mk_write(FOCUS_FIX, "tests/harness/src/test_fleet_parity.c",
                              "const char *s = \"native_code_focus_" "beacon1109\";\n"));
        ASSERT(focus_mk_write(FOCUS_FIX, ".cache/test-timing/last-run.json",
            "{\"schema\":\"zcl.test_timing.v1\",\"failed_count\":1,\"groups\":[{\"name\":\"test_fleet_parity\",\"ms\":17,\"rc\":1}]}"));
        struct zcl_command_reply reply;
        focus_call_name("codeindex", FOCUS_FIX, &reply);
        const struct json_value *files = json_get(&reply.data, "files");
        ASSERT(files && json_size(files) == 1);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(files, 0), "path")),
                      "tools/command/native_code_focus_" "beacon1109.c");
        ASSERT_EQ(json_get_int(json_get(json_at(files, 0), "score")), 100000);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    test_rm_rf_recursive(FOCUS_FIX);
    return failures;
}

static int test_focus_primary_only(void)
{
    int failures = 0;
    TEST("code_focus: no failed groups avoids unnecessary secondary scan") {
        test_rm_rf_recursive(FOCUS_FIX);
        ASSERT(focus_mk_write(FOCUS_FIX, "tools/command/native_code_focus_" "primary1109.c",
                              "int focus_primary1109(void) { return 0; }\n"));
        ASSERT(focus_mk_write(FOCUS_FIX, "tests/harness/src/test_fleet_parity.c",
                              "const char *s = \"native_code_focus_" "primary1109\";\n"));
        ASSERT(focus_mk_write(FOCUS_FIX, ".cache/test-timing/last-run.json",
                              "{\"groups\":[]}"));
        struct zcl_command_reply reply;
        zcl_alloc_fault_fail_next("agent_impact_names");
        focus_call_name("codeindex", FOCUS_FIX, &reply);
        bool armed = zcl_alloc_fault_armed_label() != NULL;
        zcl_alloc_fault_clear();
        ASSERT(armed);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_size(json_get(&reply.data, "files")), 0);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    zcl_alloc_fault_clear();
    test_rm_rf_recursive(FOCUS_FIX);
    return failures;
}

static bool focus_pad_timing(FILE *f)
{
    long pos = ftell(f);
    if (pos < 0) return false;
    while (pos++ <= 4L * 1024 * 1024)
        if (fputc(' ', f) == EOF) return false;
    return true;
}

/* Emit the timing writer's row fields, with the only failure past 256 KiB. */
static bool focus_write_full_timing(bool corrupt, bool oversized, long *size)
{
    if (!focus_mk_write(FOCUS_FIX, ".cache/test-timing/last-run.json", "")) return false;
    FILE *f = fopen(FOCUS_FIX "/.cache/test-timing/last-run.json", "wb");
    if (!f) return false;
    bool ok = fputs("{\"schema\":\"zcl.test_timing.v1\",\"groups\":[\n", f) >= 0;
    for (unsigned i = 0; i < 1800 && ok; i++) {
        ok = fprintf(f, "%s{\"name\":\"%s%04u\",\"ms\":123,\"timing_valid\":true,"
            "\"rc\":%d,\"signaled\":false,\"cached\":false,\"measured\":true,"
            "\"key_valid\":true,\"input_key\":\"0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef\",\"proof_contract\":0,"
            "\"skip_markers\":0,\"env_unobserved\":0,\"load_flaky\":0}",
            i ? ",\n" : "", i == 1799 ? "test_late_failure_" : "test_suite_group_",
            i, i == 1799 ? 1 : 0) > 0;
    }
    if (ok) ok = fputs(corrupt ? ",{\"name\":]" : "]}", f) >= 0;
    if (ok && oversized) ok = focus_pad_timing(f);
    *size = ftell(f);
    if (*size < 0) ok = false;
    if (fclose(f) != 0) ok = false;
    return ok;
}

static int test_focus_full_timing(void)
{
    int failures = 0;
    TEST("code_focus: full-suite timing retains the late failure and bounds reads") {
        long size = 0;
        struct specialist_focus_evidence ev;
        test_rm_rf_recursive(FOCUS_FIX);
        ASSERT(focus_write_full_timing(false, false, &size));
        ASSERT(size > 256L * 1024 && size < 4L * 1024 * 1024);
        specialist_focus_evidence_clear(&ev);
        ASSERT(specialist_focus_load_failed_groups(FOCUS_FIX, &ev));
        ASSERT_EQ(ev.tests_run, SPECIALIST_FOCUS_ARTIFACT_RECORDED);
        ASSERT_EQ(ev.failed_count, 1);
        ASSERT_STR_EQ(ev.failed[0], "test_late_failure_1799");
        ASSERT(focus_write_full_timing(true, false, &size));
        ASSERT(size > 256L * 1024 && size < 4L * 1024 * 1024);
        specialist_focus_evidence_clear(&ev);
        ASSERT(!specialist_focus_load_failed_groups(FOCUS_FIX, &ev));
        ASSERT(focus_write_full_timing(false, true, &size));
        ASSERT(size > 4L * 1024 * 1024);
        specialist_focus_evidence_clear(&ev);
        ASSERT(!specialist_focus_load_failed_groups(FOCUS_FIX, &ev));
        PASS();
    } _test_next:;
    test_rm_rf_recursive(FOCUS_FIX);
    return failures;
}

int test_code_focus(void)
{
    int failures = 0;
    failures += test_focus_list();
    failures += test_focus_unknown();
    failures += test_focus_missing_run();
    failures += test_focus_malformed_run();
    failures += test_focus_full_timing();
    failures += focus_test_failure_capacity(false);
    failures += focus_test_failure_capacity(true);
    failures += test_focus_recorded_run();
    failures += test_focus_lint_gates();
    failures += test_focus_work_cap();
    failures += test_focus_rank();
    failures += test_focus_selected_root();
    failures += test_focus_primary_only();
    failures += test_focus_notes_read_cap();
    return failures;
}
