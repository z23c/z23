/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: status says when main itself may be red. A
 * fixture outcomes ledger of failed and landed rows is read back through
 * `dev land status`; the advisory list and the per-row hint are derived at
 * read time and change nothing. Part of the test_dev_land group; shared
 * fixtures live in test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"

#include "command/native_dev_land_main_red.h"

/* Ledger row builders: seq doubles as the tip, so every row has its own. */
static void dlr_failed(char *out, size_t cap, long long seq,
                       const char *worktree, const char *dimension,
                       const char *detail)
{
    (void)snprintf(out, cap,
        "{\"seq\":%lld,\"tip\":\"%040llx\",\"worktree\":\"%s\","
        "\"state\":\"failed\",\"attempt\":1,\"dimension\":\"%s\","
        "\"detail\":\"%s\"}\n",
        seq, seq, worktree, dimension, detail);
}

static void dlr_landed(char *out, size_t cap, long long seq,
                       const char *worktree)
{
    (void)snprintf(out, cap,
        "{\"seq\":%lld,\"tip\":\"%040llx\",\"worktree\":\"%s\","
        "\"state\":\"landed\",\"attempt\":1}\n",
        seq, seq, worktree);
}

/* Seed the ledger from `text`, run status, and leave the call open. */
static bool dlr_status(struct dlx_call *c, const char *tag, const char *text)
{
    char land[1024], path[1200];
    dlx_isolate(tag);
    dlx_begin(c, "step");
    bool ready = dlx_run(c) && dlx_ok(c);
    dlx_end(c);
    dlx_landdir(land, sizeof(land));
    int n = snprintf(path, sizeof(path), "%s/outcomes.jsonl", land);
    if (!ready || n <= 0 || (size_t)n >= sizeof(path) || !dlx_write(path, text))
        return false;
    dlx_begin(c, "status");
    return dlx_run(c) && dlx_ok(c);
}

static const struct json_value *dlr_hint_of(const struct dlx_call *c,
                                            long long seq)
{
    const struct json_value *rows = dlx_arr(c, "outcomes");
    for (size_t i = 0; rows && i < rows->num_children; i++)
        if (json_get_int(json_get(&rows->children[i], "seq")) == seq)
            return json_get(&rows->children[i], "main_red_hint");
    return NULL;
}

#define DLR_TEST_FAIL "test test_mcp_serve: FAIL at tests/x.c:1599 (cond)"

static int dlr_case_0(void)
{
    int failures = 0;
    char a[1024], b[1024], text[4096];
    bool opened = false;
    struct dlx_call c;

    TEST("land: the same test group failing for two candidates marks main red") {
        dlr_failed(a, sizeof(a), 1, "/w/one", "test", DLR_TEST_FAIL);
        dlr_failed(b, sizeof(b), 2, "/w/two", "test", DLR_TEST_FAIL);
        (void)snprintf(text, sizeof(text), "%s%s", a, b);
        ASSERT(dlr_status(&c, "main_red_two", text));
        opened = true;
        const struct json_value *red = dlx_arr(&c, "main_red");
        ASSERT(red && red->num_children == 1);
        const struct json_value *s = &red->children[0];
        ASSERT_STR_EQ(json_get_str(json_get(s, "group")), "test_mcp_serve");
        ASSERT_STR_EQ(json_get_str(json_get(s, "dimension")), "test");
        ASSERT_EQ(json_get_int(json_get(s, "first_seq")), 1);
        const struct json_value *rows = json_get(s, "rows");
        ASSERT(rows && rows->num_children == 2);
        ASSERT_EQ(json_get_int(&rows->children[0]), 1);
        ASSERT_EQ(json_get_int(&rows->children[1]), 2);
        ASSERT_STR_EQ(json_get_str(json_get(s, "hint")),
            "main may be red for test_mcp_serve: rows 1, 2 failed it; check main before resubmitting");
        /* The author of the later row reads the same hint on their own row. */
        const struct json_value *h = dlr_hint_of(&c, 2);
        ASSERT(h && strstr(json_get_str(h), "check main before resubmitting"));
        PASS();
    } _test_next:;
    if (opened) dlx_end(&c);
    opened = false;
    dlx_restore();

    return failures;
}

static int dlr_case_1(void)
{
    int failures = 0;
    char a[1024], b[1024], text[4096];
    bool opened = false;
    struct dlx_call c;

    TEST("land: one candidate failing its own test twice does not mark main red") {
        dlr_failed(a, sizeof(a), 1, "/w/one", "test", DLR_TEST_FAIL);
        dlr_failed(b, sizeof(b), 2, "/w/one", "test", DLR_TEST_FAIL);
        (void)snprintf(text, sizeof(text), "%s%s", a, b);
        ASSERT(dlr_status(&c, "main_red_same", text));
        opened = true;
        const struct json_value *red = dlx_arr(&c, "main_red");
        ASSERT(red && red->num_children == 0);
        ASSERT(dlr_hint_of(&c, 2) == NULL);
        PASS();
    } _test_next:;
    if (opened) dlx_end(&c);
    opened = false;
    dlx_restore();

    return failures;
}

static int dlr_case_2(void)
{
    int failures = 0;
    char a[1024], b[1024], l[512], text[4096];
    bool opened = false;
    struct dlx_call c;

    TEST("land: a landing after the failures clears it, a landing before does not") {
        char other[1024];
        dlr_failed(a, sizeof(a), 2, "/w/one", "test", DLR_TEST_FAIL);
        dlr_failed(b, sizeof(b), 3, "/w/two", "test", DLR_TEST_FAIL);
        dlr_landed(l, sizeof(l), 1, "/w/r");
        (void)snprintf(text, sizeof(text), "%s%s%s", l, a, b);
        ASSERT(dlr_status(&c, "main_red_before", text)); /* landed first */
        opened = true;
        const struct json_value *red = dlx_arr(&c, "main_red");
        ASSERT(red && red->num_children == 1);
        dlx_end(&c);
        opened = false;
        dlx_restore();
        /* Same two failures, then a landing, then a different failure. */
        dlr_landed(l, sizeof(l), 4, "/w/r");
        dlr_failed(other, sizeof(other), 5, "/w/three", "test",
                   "test test_other: FAIL at tests/y.c:7 (x)");
        dlr_failed(a, sizeof(a), 1, "/w/one", "test", DLR_TEST_FAIL);
        dlr_failed(b, sizeof(b), 2, "/w/two", "test", DLR_TEST_FAIL);
        (void)snprintf(text, sizeof(text), "%s%s%s%s", a, b, l, other);
        ASSERT(dlr_status(&c, "main_red_after", text));
        opened = true;
        red = dlx_arr(&c, "main_red");
        ASSERT(red && red->num_children == 0);
        ASSERT(dlr_hint_of(&c, 2) == NULL);
        PASS();
    } _test_next:;
    if (opened) dlx_end(&c);
    opened = false;
    dlx_restore();

    return failures;
}

static int dlr_case_3(void)
{
    int failures = 0;
    char a[1024], b[1024], d[1024], text[4096];
    bool opened = false;
    struct dlx_call c;

    TEST("land: the lint dimension is judged the same way, and a compile error is no group") {
        dlr_failed(a, sizeof(a), 1, "/w/one", "lint",
                   "FAIL check-doc-counts: docs/README.md: 3 != 4");
        dlr_failed(b, sizeof(b), 2, "/w/two", "lint",
                   "lint FAIL check-doc-counts: docs/README.md: 5 != 6");
        dlr_failed(d, sizeof(d), 3, "/w/three", "lint",
                   "zcc cc -std=c23 -O2 broke");
        (void)snprintf(text, sizeof(text), "%s%s%s", a, b, d);
        ASSERT(dlr_status(&c, "main_red_lint", text));
        opened = true;
        const struct json_value *red = dlx_arr(&c, "main_red");
        ASSERT(red && red->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(&red->children[0], "group")),
                      "check-doc-counts");
        ASSERT_STR_EQ(json_get_str(json_get(&red->children[0], "dimension")), "lint");
        ASSERT(dlr_hint_of(&c, 3) == NULL);
        PASS();
    } _test_next:;
    if (opened) dlx_end(&c);
    dlx_restore();

    return failures;
}

static int dlr_case_4(void)
{
    int failures = 0;

    TEST("land: the group names are read from test and lint details only") {
        char g[DLMR_GROUP_MAX];
        ASSERT(dlmr_group_of("test", "test test_rpc: exit code=1 [x]", g, sizeof(g)));
        ASSERT_STR_EQ(g, "test_rpc");
        ASSERT(dlmr_group_of("lint", "lint FAIL check-a-b: x", g, sizeof(g)));
        ASSERT_STR_EQ(g, "check-a-b");
        ASSERT(!dlmr_group_of("lint", "ok\nFAIL check-late: x", g, sizeof(g)));
        ASSERT(!dlmr_group_of("push", "test test_rpc: FAIL", g, sizeof(g)));
        ASSERT(!dlmr_group_of("test", "proof_failed", g, sizeof(g)));
        PASS();
    } _test_next:;
    return failures;
}

static int dlr_case_5(void)
{
    int failures = 0;
    char a[1024], b[1024], fill[256], text[16384];
    bool opened = false;
    struct dlx_call c;

    TEST("land: failures at different places, or far apart, do not mark main red") {
        /* The same group failing at two different assertions is two bugs. */
        dlr_failed(a, sizeof(a), 1, "/w/one", "test", DLR_TEST_FAIL);
        dlr_failed(b, sizeof(b), 2, "/w/two", "test",
                   "test test_mcp_serve: FAIL at tests/x.c:77 (other)");
        (void)snprintf(text, sizeof(text), "%s%s", a, b);
        ASSERT(dlr_status(&c, "main_red_site", text));
        opened = true;
        const struct json_value *red = dlx_arr(&c, "main_red");
        ASSERT(red && red->num_children == 0);
        dlx_end(&c);
        opened = false;
        dlx_restore();
        /* The same failure with DLMR_GAP + 1 unrelated rows between. */
        (void)snprintf(text, sizeof(text), "%s", a);
        for (long long s = 2; s < 2 + DLMR_GAP + 1; s++) {
            dlr_failed(fill, sizeof(fill), s, "/w/f", "push", "PUSH_DECLINED");
            ASSERT(strlen(text) + strlen(fill) < sizeof(text));
            (void)strcat(text, fill);
        }
        dlr_failed(b, sizeof(b), 100, "/w/two", "test", DLR_TEST_FAIL);
        ASSERT(strlen(text) + strlen(b) < sizeof(text));
        (void)strcat(text, b);
        ASSERT(dlr_status(&c, "main_red_gap", text));
        opened = true;
        red = dlx_arr(&c, "main_red");
        ASSERT(red && red->num_children == 0);
        PASS();
    } _test_next:;
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

#define DLR_CX "FAIL check-cyclomatic-complexity: [check-cyclomatic-complexity] " \
    "FAIL 1 complexity violation(s) at cap 15 (mode: RATCHET) "

static void dlr_cx(char *out, size_t cap, long long seq, const char *worktree,
                   const char *site)
{
    char detail[512];
    (void)snprintf(detail, sizeof(detail), DLR_CX "%s: f M=16 exceeds cap 15", site);
    dlr_failed(out, cap, seq, worktree, "lint", detail);
}

static int dlr_case_6(void)
{
    int failures = 0;
    char a[1024], b[1024], d[1024], text[4096];
    bool opened = false;
    struct dlx_call c;

    TEST("land: one lint gate failing at three different sites is three changes, not a red main") {
        dlr_cx(a, sizeof(a), 1, "/w/one", "tools/command/one.c:388");
        dlr_cx(b, sizeof(b), 2, "/w/two", "cognition/two.c:153");
        dlr_cx(d, sizeof(d), 3, "/w/three", "tests/harness/src/three.c:3266");
        (void)snprintf(text, sizeof(text), "%s%s%s", a, b, d);
        ASSERT(dlr_status(&c, "main_red_lint_sites", text));
        opened = true;
        const struct json_value *red = dlx_arr(&c, "main_red");
        ASSERT(red && red->num_children == 0);
        ASSERT(dlr_hint_of(&c, 3) == NULL);
        PASS();
    } _test_next:;
    if (opened) dlx_end(&c);
    opened = false;
    dlx_restore();
    return failures;
}

static int dlr_case_6b(void)
{
    int failures = 0;
    char a[1024], b[1024], d[1024], text[4096];
    bool opened = false;
    struct dlx_call c;

    TEST("land: two candidates failing one lint gate at the same site is flagged, and a bare gate name is not a key") {
        dlr_cx(a, sizeof(a), 1, "/w/one", "tools/command/one.c:388");
        dlr_cx(b, sizeof(b), 2, "/w/two", "tools/command/one.c:391");
        (void)snprintf(text, sizeof(text), "%s%s", a, b);
        ASSERT(dlr_status(&c, "main_red_lint_same", text));
        opened = true;
        const struct json_value *red = dlx_arr(&c, "main_red");
        ASSERT(red && red->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(&red->children[0], "group")),
                      "check-cyclomatic-complexity");
        ASSERT(dlr_hint_of(&c, 2) != NULL);
        dlx_end(&c);
        opened = false;
        dlx_restore();
        /* Timing-only rows name no site: three authors, no key. */
        dlr_failed(a, sizeof(a), 1, "/w/one", "lint",
                   "FAIL check-flag-registry      744 ms (rc=1)");
        dlr_failed(b, sizeof(b), 2, "/w/two", "lint",
                   "FAIL check-flag-registry      812 ms (rc=1)");
        dlr_failed(d, sizeof(d), 3, "/w/three", "lint",
                   "FAIL check-flag-registry      790 ms (rc=1) [child_proof_failed_exit_2]");
        (void)snprintf(text, sizeof(text), "%s%s%s", a, b, d);
        ASSERT(dlr_status(&c, "main_red_lint_bare", text));
        opened = true;
        red = dlx_arr(&c, "main_red");
        ASSERT(red && red->num_children == 0);
        PASS();
    } _test_next:;
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

static const struct json_value *dlr_was_of(const struct dlx_call *c,
                                           long long seq)
{
    const struct json_value *rows = dlx_arr(c, "outcomes");
    for (size_t i = 0; rows && i < rows->num_children; i++)
        if (json_get_int(json_get(&rows->children[i], "seq")) == seq)
            return json_get(&rows->children[i], "main_red_was_suspect");
    return NULL;
}

static int dlr_case_7(void)
{
    int failures = 0;
    char a[1024], b[1024], l[512], fill[256], text[16384];
    bool opened = false;
    struct dlx_call c;

    TEST("land: after the clearing landing the failed rows keep a bounded was-suspect marking") {
        dlr_failed(a, sizeof(a), 1, "/w/one", "test", DLR_TEST_FAIL);
        dlr_failed(b, sizeof(b), 2, "/w/two", "test", DLR_TEST_FAIL);
        dlr_landed(l, sizeof(l), 3, "/w/r");
        (void)snprintf(text, sizeof(text), "%s%s%s", a, b, l);
        ASSERT(dlr_status(&c, "main_red_was", text));
        opened = true;
        const struct json_value *red = dlx_arr(&c, "main_red");
        ASSERT(red && red->num_children == 0);
        ASSERT(dlr_hint_of(&c, 2) == NULL);
        const struct json_value *w = dlr_was_of(&c, 2);
        ASSERT(w != NULL);
        ASSERT_STR_EQ(json_get_str(w),
            "main may have been red for test_mcp_serve: rows 1, 2 failed it; "
            "a landing followed, check whether it repaired main before resubmitting");
        ASSERT(dlr_was_of(&c, 3) == NULL);
        dlx_end(&c);
        opened = false;
        dlx_restore();
        /* DLMR_AFTER outcome rows after the landing, the marking is gone. */
        (void)snprintf(text, sizeof(text), "%s%s%s", a, b, l);
        for (long long s = 4; s < 4 + DLMR_AFTER + 1; s++) {
            dlr_failed(fill, sizeof(fill), s, "/w/f", "push", "PUSH_DECLINED");
            ASSERT(strlen(text) + strlen(fill) < sizeof(text));
            (void)strcat(text, fill);
        }
        ASSERT(dlr_status(&c, "main_red_was_old", text));
        opened = true;
        ASSERT(dlr_was_of(&c, 2) == NULL);
        PASS();
    } _test_next:;
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

static int dlr_case_8(void)
{
    int failures = 0;
    char a[1024], b[1024], other[1024], text[4096];
    bool opened = false;
    struct dlx_call c;

    TEST("land: a different row that reuses a suspect row's seq gets no hint") {
        dlr_failed(a, sizeof(a), 1, "/w/one", "test", DLR_TEST_FAIL);
        dlr_failed(b, sizeof(b), 2, "/w/two", "test", DLR_TEST_FAIL);
        /* Early ledger history reuses seq values: same seq 2, another tip. */
        (void)snprintf(other, sizeof(other),
            "{\"seq\":2,\"tip\":\"%040llx\",\"worktree\":\"/w/old\","
            "\"state\":\"failed\",\"attempt\":1,\"dimension\":\"push\","
            "\"detail\":\"PUSH_DECLINED\"}\n", 99ULL);
        (void)snprintf(text, sizeof(text), "%s%s%s", a, b, other);
        ASSERT(dlr_status(&c, "main_red_seq_reuse", text));
        opened = true;
        const struct json_value *red = dlx_arr(&c, "main_red");
        ASSERT(red && red->num_children == 1);
        const struct json_value *rows = dlx_arr(&c, "outcomes");
        size_t hinted = 0, seq2 = 0;
        for (size_t i = 0; rows && i < rows->num_children; i++) {
            if (json_get_int(json_get(&rows->children[i], "seq")) != 2)
                continue;
            seq2++;
            if (json_get(&rows->children[i], "main_red_hint"))
                hinted++;
        }
        ASSERT_EQ(seq2, 2);
        ASSERT_EQ(hinted, 1);
        PASS();
    } _test_next:;
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

int test_dev_land_main_red_advisory(void)
{
    return dlr_case_0() + dlr_case_1() + dlr_case_2() + dlr_case_3() +
           dlr_case_4() + dlr_case_5() + dlr_case_6() + dlr_case_6b() + dlr_case_7() +
           dlr_case_8();
}
