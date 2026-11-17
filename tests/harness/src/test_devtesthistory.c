/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance bar for the persistent per-group failure-history feed:
 *   writer — tests/harness/src/group_history.c (one JSONL line per
 *            EXECUTED group, appended by the parallel runner beside
 *            last-run.json)
 *   reader — tools/command/native_dev_test_history.c (dev.test.history)
 *
 * Both halves are tested against local fixtures built here, never the
 * checkout the test runs in. The reader is called through its bound
 * handler (as the CLI does after input validation) and its input keys are
 * validated through the real registry.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "devloop.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "test/group_history.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#define DTH_PATH "dev.test.history"
#define DTH_LEDGER_NAME "group-history.jsonl"
#define DTH_TREE_A "1111111111111111111111111111111111111111"
#define DTH_TREE_B "2222222222222222222222222222222222222222"
#define DTH_TREE_C "76ffcc4885843f63df1f69fc8c531911ba5f1181"

/* ── fixture helpers ─────────────────────────────────────────────── */

static bool dth_write_text(const char *path, const char *text)
{
    FILE *fp = fopen(path, "w");
    if (!fp)
        return false;
    bool ok = fputs(text, fp) != EOF;
    return fclose(fp) == 0 && ok;
}

static bool dth_read_text(const char *path, char *buf, size_t cap)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
        return false;
    size_t n = fread(buf, 1, cap - 1, fp);
    bool ok = !ferror(fp);
    fclose(fp);
    buf[n] = '\0';
    return ok;
}

static bool dth_mkdir(const char *path)
{
    return mkdir(path, 0755) == 0 || errno == EEXIST;
}

/* ── reader call harness (mirrors the devagent outcomes test) ─────── */

struct dth_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dth_begin(struct dth_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), DTH_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.dev_test_history.v1");
}

static void dth_end(struct dth_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool dth_run(struct dth_call *c)
{
    char why[192];
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_dev_test_history(&c->request, &c->reply);
    return true;
}

static bool dth_ok(const struct dth_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *dth_str(const struct dth_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static int64_t dth_int(const struct dth_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -12345;
}

static bool dth_bool(const struct dth_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_BOOL ? json_get_bool(v) : false;
}

static const struct json_value *dth_groups(const struct dth_call *c)
{
    const struct json_value *v = json_get(&c->reply.data, "groups");
    return v && v->type == JSON_ARR ? v : NULL;
}

static const char *dth_entry_str(const struct json_value *e, const char *key)
{
    const struct json_value *v = json_get(e, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static int64_t dth_entry_int(const struct json_value *e, const char *key)
{
    const struct json_value *v = json_get(e, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -12345;
}

static bool dth_group_in(const char groups[][ZCL_DEVLOOP_GROUP_MAX],
                         size_t n, const char *want)
{
    for (size_t i = 0; i < n; i++) {
        if (strcmp(groups[i], want) == 0)
            return true;
    }
    return false;
}

/* The ledger every aggregation case reads: five well-formed rows across
 * three groups (two failing at different rates) plus one malformed line. */
static const char dth_ledger_rows[] =
    "{\"ts\":\"2026-11-15T08:00:00Z\",\"group\":\"alpha\",\"rc\":1,"
    "\"verdict\":\"FAIL\",\"wall_ms\":100,\"load_flaky\":0,"
    "\"tree\":\"" DTH_TREE_A "\"}\n"
    "{\"ts\":\"2026-11-16T09:00:00Z\",\"group\":\"alpha\",\"rc\":0,"
    "\"verdict\":\"PASS\",\"wall_ms\":90,\"load_flaky\":1,"
    "\"tree\":\"" DTH_TREE_A "\"}\n"
    "{\"ts\":\"2026-11-14T10:00:00Z\",\"group\":\"beta\",\"rc\":2,"
    "\"verdict\":\"FAIL\",\"wall_ms\":80,\"load_flaky\":0,"
    "\"tree\":\"" DTH_TREE_B "\"}\n"
    "{\"ts\":\"2026-11-17T11:00:00Z\",\"group\":\"beta\",\"rc\":-9,"
    "\"verdict\":\"FAIL\",\"wall_ms\":null,\"load_flaky\":0,"
    "\"tree\":\"" DTH_TREE_B "\"}\n"
    "{\"ts\":\"2026-11-17T12:00:00Z\",\"group\":\"gamma\",\"rc\":0,"
    "\"verdict\":\"PASS\",\"wall_ms\":70,\"load_flaky\":0,"
    "\"tree\":\"" DTH_TREE_C "\"}\n"
    "not one json object\n";

/* Two rows the append cases write: a measured pass and a signaled crash. */
static const struct zcl_group_history_row dth_rows[2] = {
    { .group = "alpha", .rc = 0, .pass = true, .timing_valid = true,
      .wall_ms = 1234, .load_flaky = 0 },
    { .group = "beta_two", .rc = -9, .pass = false,
      .timing_valid = false, .wall_ms = 0, .load_flaky = 1 },
};

/* ── writer: one line per executed group ──────────────────────────── */

static int dth_case_line_pass(void)
{
    int failures = 0;
    char buf[512];
    TEST_CASE("history: a measured pass renders one exact ledger line") {
        size_t n = zcl_group_history_line(buf, sizeof(buf), &dth_rows[0],
                                          "2026-11-17T18:00:00Z",
                                          DTH_TREE_C);
        ASSERT_STR_EQ(buf,
            "{\"ts\":\"2026-11-17T18:00:00Z\",\"group\":\"alpha\",\"rc\":0,"
            "\"verdict\":\"PASS\",\"wall_ms\":1234,\"load_flaky\":0,"
            "\"tree\":\"" DTH_TREE_C "\"}");
        ASSERT_EQ((int64_t)n, (int64_t)strlen(buf));
    } TEST_END;
    return failures;
}

static int dth_case_line_crash(void)
{
    int failures = 0;
    char buf[512];
    TEST_CASE("history: a signaled group renders null wall, FAIL, empty tree") {
        size_t n = zcl_group_history_line(buf, sizeof(buf), &dth_rows[1],
                                          "2026-11-17T18:00:01Z", "");
        ASSERT_STR_EQ(buf,
            "{\"ts\":\"2026-11-17T18:00:01Z\",\"group\":\"beta_two\","
            "\"rc\":-9,\"verdict\":\"FAIL\",\"wall_ms\":null,"
            "\"load_flaky\":1,\"tree\":\"\"}");
        ASSERT_EQ((int64_t)n, (int64_t)strlen(buf));
    } TEST_END;
    return failures;
}

static int dth_case_line_short_buffer(void)
{
    int failures = 0;
    TEST_CASE("history: a short buffer is refused, never truncated") {
        char tiny[32];
        ASSERT_EQ((int64_t)zcl_group_history_line(tiny, sizeof(tiny),
                                                  &dth_rows[0],
                                                  "2026-11-17T18:00:00Z",
                                                  DTH_TREE_C),
                  (int64_t)0);
        ASSERT_STR_EQ(tiny, "");
    } TEST_END;
    return failures;
}

static int dth_case_append_two(const char *root)
{
    int failures = 0;
    char path[1024], text[2048];
    (void)snprintf(path, sizeof(path), "%s/%s", root, DTH_LEDGER_NAME);
    TEST_CASE("history: append writes both lines in order, newline-terminated") {
        ASSERT_EQ(zcl_group_history_append(path, "2026-11-17T18:00:00Z",
                                           DTH_TREE_C, dth_rows, 2), 2);
        ASSERT(dth_read_text(path, text, sizeof(text)));
        ASSERT_STR_EQ(text,
            "{\"ts\":\"2026-11-17T18:00:00Z\",\"group\":\"alpha\",\"rc\":0,"
            "\"verdict\":\"PASS\",\"wall_ms\":1234,\"load_flaky\":0,"
            "\"tree\":\"" DTH_TREE_C "\"}\n"
            "{\"ts\":\"2026-11-17T18:00:00Z\",\"group\":\"beta_two\","
            "\"rc\":-9,\"verdict\":\"FAIL\",\"wall_ms\":null,"
            "\"load_flaky\":1,\"tree\":\"" DTH_TREE_C "\"}\n");
    } TEST_END;
    return failures;
}

static int dth_case_append_again(const char *root)
{
    int failures = 0;
    char path[1024], text[2048];
    (void)snprintf(path, sizeof(path), "%s/%s", root, DTH_LEDGER_NAME);
    TEST_CASE("history: a second append keeps the earlier lines (persistence)") {
        ASSERT_EQ(zcl_group_history_append(path, "2026-11-17T19:00:00Z",
                                           DTH_TREE_A, dth_rows, 1), 1);
        ASSERT(dth_read_text(path, text, sizeof(text)));
        ASSERT(text[strlen(text) - 1] == '\n');
        ASSERT(strstr(text, "\"group\":\"beta_two\"") != NULL);
        ASSERT(strstr(text, "\"ts\":\"2026-11-17T19:00:00Z\"") != NULL);
    } TEST_END;
    return failures;
}

static int dth_case_append_zero(const char *root)
{
    int failures = 0;
    TEST_CASE("history: zero rows append nothing and create no file") {
        char empty[1024];
        struct stat st;
        (void)snprintf(empty, sizeof(empty), "%s/empty.jsonl", root);
        ASSERT_EQ(zcl_group_history_append(empty, "2026-11-17T20:00:00Z",
                                           DTH_TREE_A, NULL, 0), 0);
        ASSERT(stat(empty, &st) != 0 && errno == ENOENT);
    } TEST_END;
    return failures;
}

static int dth_case_append_unwritable(const char *root)
{
    int failures = 0;
    TEST_CASE("history: an unwritable path is reported, never silent") {
        char bad[1024];
        (void)snprintf(bad, sizeof(bad), "%s/no-such-dir/x.jsonl", root);
        errno = 0;
        ASSERT_EQ(zcl_group_history_append(bad, "2026-11-17T20:00:00Z",
                                           DTH_TREE_A, dth_rows, 1), -1);
        ASSERT(errno != 0);
    } TEST_END;
    return failures;
}

/* ── writer: worktree HEAD resolution ─────────────────────────────── */

static int dth_case_tree_detached(const char *root)
{
    int failures = 0;
    char path[1280], out[ZCL_GROUP_HISTORY_TREE_LEN];
    TEST_CASE("history: a detached HEAD resolves to its 40-hex commit") {
        (void)snprintf(path, sizeof(path), "%s/t1", root);
        ASSERT(dth_mkdir(path));
        (void)snprintf(path, sizeof(path), "%s/t1/.git", root);
        ASSERT(dth_mkdir(path));
        (void)snprintf(path, sizeof(path), "%s/t1/.git/HEAD", root);
        ASSERT(dth_write_text(path, DTH_TREE_C "\n"));
        (void)snprintf(path, sizeof(path), "%s/t1", root);
        zcl_group_history_tree(path, out, sizeof(out));
        ASSERT_STR_EQ(out, DTH_TREE_C);
    } TEST_END;
    return failures;
}

static int dth_case_tree_symref(const char *root)
{
    int failures = 0;
    char path[1280], out[ZCL_GROUP_HISTORY_TREE_LEN];
    TEST_CASE("history: a symref HEAD resolves through the loose ref") {
        (void)snprintf(path, sizeof(path), "%s/t2", root);
        ASSERT(dth_mkdir(path));
        (void)snprintf(path, sizeof(path), "%s/t2/.git", root);
        ASSERT(dth_mkdir(path));
        (void)snprintf(path, sizeof(path), "%s/t2/.git/HEAD", root);
        ASSERT(dth_write_text(path, "ref: refs/heads/lane\n"));
        (void)snprintf(path, sizeof(path), "%s/t2/.git/refs", root);
        ASSERT(dth_mkdir(path));
        (void)snprintf(path, sizeof(path), "%s/t2/.git/refs/heads", root);
        ASSERT(dth_mkdir(path));
        (void)snprintf(path, sizeof(path), "%s/t2/.git/refs/heads/lane", root);
        ASSERT(dth_write_text(path, DTH_TREE_A "\n"));
        (void)snprintf(path, sizeof(path), "%s/t2", root);
        zcl_group_history_tree(path, out, sizeof(out));
        ASSERT_STR_EQ(out, DTH_TREE_A);
    } TEST_END;
    return failures;
}

static int dth_case_tree_worktree(const char *root)
{
    int failures = 0;
    char gitdir[1024], common[1024], path[1536];
    char out[ZCL_GROUP_HISTORY_TREE_LEN];
    TEST_CASE("history: a linked worktree resolves refs from the common dir") {
        (void)snprintf(path, sizeof(path), "%s/t3", root);
        ASSERT(dth_mkdir(path));
        (void)snprintf(gitdir, sizeof(gitdir), "%s/t3/wt-git", root);
        (void)snprintf(common, sizeof(common), "%s/t3/wt-common", root);
        ASSERT(dth_mkdir(gitdir) && dth_mkdir(common));
        (void)snprintf(path, sizeof(path), "%s/t3/.git", root);
        {
            char dotgit[1792];
            ASSERT(snprintf(dotgit, sizeof(dotgit), "gitdir: %s\n", gitdir) <
                   (int)sizeof(dotgit));
            ASSERT(dth_write_text(path, dotgit));
        }
        (void)snprintf(path, sizeof(path), "%s/HEAD", gitdir);
        ASSERT(dth_write_text(path, "ref: refs/heads/packed\n"));
        (void)snprintf(path, sizeof(path), "%s/commondir", gitdir);
        ASSERT(dth_write_text(path, common));
        (void)snprintf(path, sizeof(path), "%s/packed-refs", common);
        ASSERT(dth_write_text(path,
            "# pack-refs with: peeled fully-peeled sorted\n"
            DTH_TREE_B " refs/heads/packed\n"
            DTH_TREE_A " refs/heads/other\n"));
        (void)snprintf(path, sizeof(path), "%s/t3", root);
        zcl_group_history_tree(path, out, sizeof(out));
        ASSERT_STR_EQ(out, DTH_TREE_B);
    } TEST_END;
    return failures;
}

static int dth_case_tree_broken(const char *root)
{
    int failures = 0;
    char gitdir[1024], path[1280], out[ZCL_GROUP_HISTORY_TREE_LEN];
    TEST_CASE("history: an unresolvable HEAD reports empty, never a guess") {
        (void)snprintf(path, sizeof(path), "%s/t4", root);
        ASSERT(dth_mkdir(path));
        (void)snprintf(gitdir, sizeof(gitdir), "%s/t4/broken-git", root);
        ASSERT(dth_mkdir(gitdir));
        (void)snprintf(path, sizeof(path), "%s/t4/.git", root);
        ASSERT(dth_write_text(path, gitdir));
        (void)snprintf(path, sizeof(path), "%s/HEAD", gitdir);
        ASSERT(dth_write_text(path, "garbage\n"));
        (void)snprintf(path, sizeof(path), "%s/t4", root);
        zcl_group_history_tree(path, out, sizeof(out));
        ASSERT_STR_EQ(out, "");
    } TEST_END;
    return failures;
}

/* ── reader: dev.test.history ─────────────────────────────────────── */

static int dth_case_registered(void)
{
    int failures = 0;
    TEST_CASE("history: the leaf is registered and accepts ledger, since, limit") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DTH_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->handler != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "ledger") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "since") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "limit") != NULL);
    } TEST_END;
    return failures;
}

static int dth_case_aggregate(const char *ledger)
{
    int failures = 0;
    struct dth_call c;
    TEST_CASE("history: aggregates failures-first with the newest failure named") {
        dth_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        ASSERT(dth_run(&c) && dth_ok(&c));
        ASSERT_STR_EQ(dth_str(&c, "leaf"), DTH_PATH);
        ASSERT_STR_EQ(dth_str(&c, "ledger"), ledger);
        ASSERT(dth_bool(&c, "exists"));
        ASSERT_EQ(dth_int(&c, "rows"), 5);
        ASSERT_EQ(dth_int(&c, "malformed"), 1);
        ASSERT_EQ(dth_int(&c, "failing_groups"), 2);
        ASSERT(!dth_bool(&c, "truncated"));
        const struct json_value *g = dth_groups(&c);
        ASSERT(g != NULL && g->num_children == 2);
        ASSERT_STR_EQ(dth_entry_str(&g->children[0], "group"), "beta");
        ASSERT_EQ(dth_entry_int(&g->children[0], "attempts"), 2);
        ASSERT_EQ(dth_entry_int(&g->children[0], "fail"), 2);
        ASSERT_EQ(dth_entry_int(&g->children[0], "flaky"), 0);
        ASSERT_STR_EQ(dth_entry_str(&g->children[0], "last_fail_ts"),
                      "2026-11-17T11:00:00Z");
        ASSERT_EQ(dth_entry_int(&g->children[0], "last_fail_rc"), -9);
        ASSERT_STR_EQ(dth_entry_str(&g->children[0], "last_fail_tree"),
                      DTH_TREE_B);
        ASSERT_STR_EQ(dth_entry_str(&g->children[1], "group"), "alpha");
        ASSERT_EQ(dth_entry_int(&g->children[1], "attempts"), 2);
        ASSERT_EQ(dth_entry_int(&g->children[1], "fail"), 1);
        ASSERT_EQ(dth_entry_int(&g->children[1], "flaky"), 1);
        ASSERT_STR_EQ(dth_entry_str(&g->children[1], "last_fail_ts"),
                      "2026-11-15T08:00:00Z");
        ASSERT_EQ(dth_entry_int(&g->children[1], "last_fail_rc"), 1);
        dth_end(&c);
    } TEST_END;
    return failures;
}

static int dth_case_missing(const char *root)
{
    int failures = 0;
    struct dth_call c;
    TEST_CASE("history: a missing ledger is a true zero, never a guess") {
        char absent[1024];
        (void)snprintf(absent, sizeof(absent), "%s/definitely-absent.jsonl",
                       root);
        dth_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", absent);
        ASSERT(dth_run(&c) && dth_ok(&c));
        ASSERT_STR_EQ(dth_str(&c, "ledger"), absent);
        ASSERT(!dth_bool(&c, "exists"));
        ASSERT_EQ(dth_int(&c, "rows"), 0);
        ASSERT_EQ(dth_int(&c, "malformed"), 0);
        ASSERT_EQ(dth_int(&c, "failing_groups"), 0);
        ASSERT(!dth_bool(&c, "truncated"));
        const struct json_value *g = dth_groups(&c);
        ASSERT(g != NULL && g->num_children == 0);
        dth_end(&c);
    } TEST_END;
    return failures;
}

static int dth_case_since(const char *ledger)
{
    int failures = 0;
    struct dth_call c;
    TEST_CASE("history: since drops old rows from the table, not the counts") {
        dth_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_str(&c.input, "since", "2026-11-16T00:00:00Z");
        ASSERT(dth_run(&c) && dth_ok(&c));
        ASSERT_EQ(dth_int(&c, "rows"), 5);
        ASSERT_EQ(dth_int(&c, "malformed"), 1);
        ASSERT_EQ(dth_int(&c, "failing_groups"), 1);
        const struct json_value *g = dth_groups(&c);
        ASSERT(g != NULL && g->num_children == 1);
        ASSERT_STR_EQ(dth_entry_str(&g->children[0], "group"), "beta");
        ASSERT_EQ(dth_entry_int(&g->children[0], "attempts"), 1);
        ASSERT_EQ(dth_entry_int(&g->children[0], "fail"), 1);
        dth_end(&c);
    } TEST_END;
    return failures;
}

static int dth_case_limit(const char *ledger)
{
    int failures = 0;
    struct dth_call c;
    TEST_CASE("history: limit bounds the reply and reports the cut") {
        dth_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_int(&c.input, "limit", 1);
        ASSERT(dth_run(&c) && dth_ok(&c));
        const struct json_value *g = dth_groups(&c);
        ASSERT(g != NULL && g->num_children == 1);
        ASSERT_STR_EQ(dth_entry_str(&g->children[0], "group"), "beta");
        ASSERT_EQ(dth_int(&c, "failing_groups"), 2);
        ASSERT(dth_bool(&c, "truncated"));
        dth_end(&c);
    } TEST_END;
    return failures;
}

static int dth_case_bad_since(const char *ledger)
{
    int failures = 0;
    struct dth_call c;
    TEST_CASE("history: a misshapen since is refused, never a silent unfilter") {
        dth_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_str(&c.input, "since", "2026-11-16");
        ASSERT(dth_run(&c) && !dth_ok(&c));
        ASSERT_STR_EQ(dth_str(&c, "leaf"), DTH_PATH);
        dth_end(&c);
    } TEST_END;
    return failures;
}

static int dth_case_bad_limit(const char *ledger)
{
    int failures = 0;
    struct dth_call c;
    TEST_CASE("history: an out-of-range limit is refused, never a silent clamp") {
        /* 0 is refused by the registry's shared integer rule before the
         * handler; 100000 passes that rule (1..1000000) and is refused by
         * the leaf's own 1..200 bound. Neither may yield a passed reply. */
        dth_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_int(&c.input, "limit", 0);
        ASSERT(!(dth_run(&c) && dth_ok(&c)));
        dth_end(&c);
        dth_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_int(&c.input, "limit", 100000);
        ASSERT(dth_run(&c) && !dth_ok(&c));
        dth_end(&c);
    } TEST_END;
    return failures;
}

static int dth_case_default_path(void)
{
    int failures = 0;
    struct dth_call c;
    TEST_CASE("history: no ledger key reads the runner's conventional path") {
        dth_begin(&c);
        ASSERT(dth_run(&c) && dth_ok(&c));
        ASSERT_STR_EQ(dth_str(&c, "ledger"),
                      ".cache/test-timing/group-history.jsonl");
        /* Whatever that file holds here, the counts are honest integers
         * and the reply stays bounded; a missing file is the true-zero
         * case proven above. */
        ASSERT(dth_int(&c, "rows") >= 0);
        ASSERT(dth_int(&c, "failing_groups") >= 0);
        dth_end(&c);
    } TEST_END;
    return failures;
}

/* ── impact routing: the feed's files select this group ───────────── */

static int dth_case_impact(void)
{
    int failures = 0;
    TEST_CASE("history: each feed path selects the devtesthistory regression") {
        /* Production paths select the shared rule's bare group name; the
         * audited test translation unit is its own semantic-leaf path
         * floor, which the plan reports under the full group id. */
        static const struct { const char *path, *group; } cases[] = {
            {"tests/harness/src/group_history.c", "devtesthistory"},
            {"tests/harness/include/test/group_history.h", "devtesthistory"},
            {"tools/command/native_dev_test_history.c", "devtesthistory"},
            {"tests/harness/src/test_devtesthistory.c", "test_devtesthistory"},
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            const char *files[] = {cases[i].path};
            struct zcl_devloop_plan plan;
            ASSERT(zcl_devloop_plan_files(files, 1, &plan));
            ASSERT(dth_group_in(plan.path_groups, plan.path_groups_len,
                                cases[i].group));
        }
    } TEST_END;
    return failures;
}

int test_devtesthistory(void);
int test_devtesthistory(void)
{
    int failures = 0;
    char root[512], ledger[1024];

    failures += dth_case_line_pass();
    failures += dth_case_line_crash();
    failures += dth_case_line_short_buffer();

    test_make_tmpdir(root, sizeof(root), "devtesthistory", "fixtures");
    failures += dth_case_append_two(root);
    failures += dth_case_append_again(root);
    failures += dth_case_append_zero(root);
    failures += dth_case_append_unwritable(root);
    (void)snprintf(ledger, sizeof(ledger), "%s/%s", root, DTH_LEDGER_NAME);
    if (!dth_write_text(ledger, dth_ledger_rows)) {
        printf("test_devtesthistory: fixture ledger write failed: %s\n",
               strerror(errno));
        failures++;
    }
    failures += dth_case_tree_detached(root);
    failures += dth_case_tree_symref(root);
    failures += dth_case_tree_worktree(root);
    failures += dth_case_tree_broken(root);
    failures += dth_case_registered();
    failures += dth_case_aggregate(ledger);
    failures += dth_case_missing(root);
    failures += dth_case_since(ledger);
    failures += dth_case_limit(ledger);
    failures += dth_case_bad_since(ledger);
    failures += dth_case_bad_limit(ledger);
    failures += dth_case_default_path();
    failures += dth_case_impact();

    if (failures == 0) printf("test_devtesthistory: all passed\n");
    else printf("test_devtesthistory: %d FAILED\n", failures);
    return failures;
}
