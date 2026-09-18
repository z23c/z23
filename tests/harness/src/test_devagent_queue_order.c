/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ACCEPTANCE for dev.agent.queue's READY order and backpressure.
 *
 * The queue is the one work ledger a resident worker claims from. These
 * cases pin the thin seam that turns it from FIFO into "highest-value READY
 * work first" without a second scheduler:
 *   - claim takes the lowest (priority, seq) queued row;
 *   - a row naming `depends_on` stays blocked until an outcome row completes
 *     that name under the closed predicate: an unknown, unfinished or
 *     failed dependency never unlocks it;
 *   - rows written before the fields existed read as P3, no dependency;
 *   - malformed priority/depends_on are refused at post and store nothing;
 *   - post refuses QUEUE_FULL once the queued bound is reached.
 * Isolated XDG_STATE_HOME; the handler is called in-process after the real
 * registry validates the input keys. No model, network or spawn.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DQO_PATH "dev.agent.queue"

static char g_dqo_state[1024];
static char g_dqo_saved_xdg[4096];
static bool g_dqo_had_xdg;

static void dqo_isolate(const char *tag)
{
    char base[512];
    test_make_tmpdir(base, sizeof(base), "devagent_queue_order", tag);
    (void)snprintf(g_dqo_state, sizeof(g_dqo_state), "%s/state", base);
    g_dqo_had_xdg = getenv("XDG_STATE_HOME") != NULL;
    if (g_dqo_had_xdg)
        (void)snprintf(g_dqo_saved_xdg, sizeof(g_dqo_saved_xdg), "%s",
                       getenv("XDG_STATE_HOME"));
    setenv("XDG_STATE_HOME", g_dqo_state, 1);
}

static void dqo_restore(void)
{
    if (g_dqo_had_xdg)
        setenv("XDG_STATE_HOME", g_dqo_saved_xdg, 1);
    else
        unsetenv("XDG_STATE_HOME");
}

struct dqo_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dqo_begin(struct dqo_call *c, const char *action)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), DQO_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c->input, "action", action);
}

/* Validate through the REAL registry, then call the handler. */
static bool dqo_run(struct dqo_call *c)
{
    char why[256];
    if (!c->request.spec ||
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_dev_agent_queue(&c->request, &c->reply);
    return true;
}

static void dqo_end(struct dqo_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* Post one leaf row; priority < 0 and after == NULL leave them unset.
 * Returns the reply's error code ("" on success) in code. */
static bool dqo_post(const char *name, int priority, const char *after,
                     char *code, size_t cap)
{
    struct dqo_call c;
    bool ran;
    dqo_begin(&c, "post");
    (void)json_push_kv_str(&c.input, "kind", "leaf");
    (void)json_push_kv_str(&c.input, "name", name);
    if (priority >= 0)
        (void)json_push_kv_int(&c.input, "priority", priority);
    if (after)
        (void)json_push_kv_str(&c.input, "depends_on", after);
    ran = dqo_run(&c);
    (void)snprintf(code, cap, "%s",
                   c.reply.status == ZCL_COMMAND_STATUS_PASSED
                       ? "" : c.reply.error.code);
    dqo_end(&c);
    return ran;
}

static bool dqo_post_ok(const char *name, int priority, const char *after)
{
    char code[64];
    return dqo_post(name, priority, after, code, sizeof(code)) && !code[0];
}

/* Claim once; the claimed name, or "" when the queue had nothing READY. */
static void dqo_claim(char *name, size_t cap)
{
    struct dqo_call c;
    const struct json_value *v;
    name[0] = '\0';
    dqo_begin(&c, "claim");
    (void)json_push_kv_str(&c.input, "worker", "w1");
    (void)json_push_kv_str(&c.input, "session", "s1");
    if (dqo_run(&c) && c.reply.status == ZCL_COMMAND_STATUS_PASSED) {
        v = json_get(&c.reply.data, "name");
        if (v && v->type == JSON_STR && json_get_str(v))
            (void)snprintf(name, cap, "%s", json_get_str(v));
    }
    dqo_end(&c);
}

static bool dqo_claim_is(const char *want)
{
    char got[96];
    dqo_claim(got, sizeof(got));
    if (strcmp(got, want) != 0) {
        printf("[claimed '%s', wanted '%s'] ", got, want);
        return false;
    }
    return true;
}

/* Append one raw line to a queue-dir file (outcomes.jsonl, queue.jsonl). */
static bool dqo_append(const char *file, const char *line)
{
    char dir[1200], path[1300];
    FILE *f;
    bool ok;
    (void)snprintf(dir, sizeof(dir), "%s/z23/dev/queue", g_dqo_state);
    (void)snprintf(path, sizeof(path), "%s/%s", dir, file);
    f = fopen(path, "ab");
    if (!f)
        return false;
    ok = fputs(line, f) >= 0;
    return fclose(f) == 0 && ok;
}

static int dqo_case_priority(void)
{
    int failures = 0;
    TEST("queue order: lowest priority first, seq breaks ties") {
        dqo_isolate("prio");
        ASSERT(dqo_post_ok("p3-first", -1, NULL));
        ASSERT(dqo_post_ok("p1-early", 1, NULL));
        ASSERT(dqo_post_ok("p0-late", 0, NULL));
        ASSERT(dqo_post_ok("p1-late", 1, NULL));
        ASSERT(dqo_claim_is("p0-late"));
        ASSERT(dqo_claim_is("p1-early"));
        ASSERT(dqo_claim_is("p1-late"));
        ASSERT(dqo_claim_is("p3-first"));
        ASSERT(dqo_claim_is(""));
        PASS();
    }
_test_next:;
    dqo_restore();
    return failures;
}

static int dqo_case_after(void)
{
    int failures = 0;
    TEST("queue order: a dependency unlocks only on its closed pass") {
        dqo_isolate("after");
        ASSERT(dqo_post_ok("child", 0, "parent"));
        ASSERT(dqo_post_ok("orphan", 0, "never-posted"));
        /* Blocked P0 rows never outrank READY work, and are not claimable
         * while their dependency is unfinished. */
        ASSERT(dqo_post_ok("parent", 3, NULL));
        ASSERT(dqo_claim_is("parent"));
        ASSERT(dqo_claim_is(""));
        /* A FAILED outcome of the dependency does not unlock. */
        ASSERT(dqo_append("outcomes.jsonl",
            "{\"ts\":\"2026-09-18T00:00:00Z\",\"name\":\"parent\","
            "\"attempt\":1,\"verdict\":\"failed\",\"rc\":1}\n"));
        ASSERT(dqo_claim_is(""));
        ASSERT(dqo_append("outcomes.jsonl",
            "{\"ts\":\"2026-09-18T00:01:00Z\",\"name\":\"parent\","
            "\"attempt\":2,\"verdict\":\"pass\",\"rc\":0}\n"));
        ASSERT(dqo_claim_is("child"));
        /* An unknown dependency stays unknown: it never unlocks. */
        ASSERT(dqo_claim_is(""));
        PASS();
    }
_test_next:;
    dqo_restore();
    return failures;
}

static int dqo_case_legacy_and_refusals(void)
{
    int failures = 0;
    TEST("queue order: pre-field rows are P3; bad order input is refused") {
        char code[64];
        dqo_isolate("legacy");
        /* Creates the queue dir, then a row with neither field. */
        ASSERT(dqo_post_ok("modern-p2", 2, NULL));
        ASSERT(dqo_append("queue.jsonl",
            "{\"seq\":9,\"ts\":\"2026-09-18T00:00:00Z\",\"kind\":\"leaf\","
            "\"name\":\"legacy\",\"group\":\"\",\"path\":\"\",\"brief\":\"\","
            "\"model\":\"\",\"attempt\":1,\"state\":\"queued\","
            "\"worktree\":\"\",\"pid_or_unit\":\"\",\"started\":0}\n"));
        ASSERT(dqo_post(("bad-prio"), 4, NULL, code, sizeof(code)));
        ASSERT_STR_EQ(code, "BAD_INPUT");
        ASSERT(dqo_post("self-dep", 1, "self-dep", code, sizeof(code)));
        ASSERT_STR_EQ(code, "BAD_INPUT");
        ASSERT(dqo_post("bad-dep", 1, "..", code, sizeof(code)));
        ASSERT_STR_EQ(code, "BAD_INPUT");
        ASSERT(dqo_claim_is("modern-p2"));
        ASSERT(dqo_claim_is("legacy"));
        ASSERT(dqo_claim_is(""));
        PASS();
    }
_test_next:;
    dqo_restore();
    return failures;
}

static int dqo_case_backpressure(void)
{
    int failures = 0;
    TEST("queue order: post refuses QUEUE_FULL at the queued bound") {
        char name[32], code[64];
        int i;
        dqo_isolate("full");
        for (i = 0; i < 64; i++) {
            (void)snprintf(name, sizeof(name), "fill-%d", i);
            ASSERT(dqo_post_ok(name, 3, NULL));
        }
        ASSERT(dqo_post("one-too-many", 0, NULL, code, sizeof(code)));
        ASSERT_STR_EQ(code, "QUEUE_FULL");
        /* Draining one row makes room again. */
        ASSERT(dqo_claim_is("fill-0"));
        ASSERT(dqo_post_ok("one-too-many", 0, NULL));
        PASS();
    }
_test_next:;
    dqo_restore();
    return failures;
}

/* Post one file unit with a write scope; the reply's error code or "". */
static bool dqo_post_file(const char *name, const char *path,
                          const char *brief, char *code, size_t cap)
{
    struct dqo_call c;
    bool ran;
    dqo_begin(&c, "post");
    (void)json_push_kv_str(&c.input, "kind", "file");
    (void)json_push_kv_str(&c.input, "name", name);
    (void)json_push_kv_str(&c.input, "group", "hex_codec");
    (void)json_push_kv_str(&c.input, "path", path);
    (void)json_push_kv_str(&c.input, "brief", brief);
    ran = dqo_run(&c);
    (void)snprintf(code, cap, "%s",
                   c.reply.status == ZCL_COMMAND_STATUS_PASSED
                       ? "" : c.reply.error.code);
    dqo_end(&c);
    return ran;
}

static int dqo_case_scope_list(void)
{
    int failures = 0;
    TEST("queue order: a file unit's scope may name a fix and its test") {
        char brief[1300], code[64];
        FILE *f;
        dqo_isolate("scope");
        ASSERT(dqo_post_ok("seed", 3, NULL));
        (void)snprintf(brief, sizeof(brief), "%s/z23/dev/queue/brief.txt",
                       g_dqo_state);
        f = fopen(brief, "wb");
        ASSERT(f != NULL);
        ASSERT(fputs("fix and test\n", f) >= 0);
        ASSERT(fclose(f) == 0);
        ASSERT(dqo_post_file("two-roots", "src/a.c,tests/t_a.c", brief, code,
                             sizeof(code)));
        ASSERT_STR_EQ(code, "");
        ASSERT(dqo_post_file("five", "a,b,c,d,e", brief, code, sizeof(code)));
        ASSERT_STR_EQ(code, "BAD_INPUT");
        ASSERT(dqo_post_file("escape", "src/,../x", brief, code,
                             sizeof(code)));
        ASSERT_STR_EQ(code, "BAD_INPUT");
        ASSERT(dqo_post_file("empty", "src/,", brief, code, sizeof(code)));
        ASSERT_STR_EQ(code, "BAD_INPUT");
        PASS();
    }
_test_next:;
    dqo_restore();
    return failures;
}

int test_devagent_queue_order(void);
int test_devagent_queue_order(void)
{
    int failures = 0;
#if defined(_WIN32)
    TEST("queue order: POSIX state rig only") {
        PASS();
    }
    return failures;
#endif
    failures += dqo_case_priority();
    failures += dqo_case_after();
    failures += dqo_case_legacy_and_refusals();
    failures += dqo_case_backpressure();
    failures += dqo_case_scope_list();
    return failures;
}
