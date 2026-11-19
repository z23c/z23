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
 *   - exact queued reprioritization is atomic, idempotent and state-guarded;
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
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

#define DQO_PATH "dev.agent.queue"
#define DQO_PRIORITY_PATH "dev.fleet.queue-reprioritize"
#define DQO_CANCEL_PATH "dev.fleet.queue-cancel"

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
static bool dqo_run_handler(struct dqo_call *c,
    void (*handler)(const struct zcl_command_request *, struct zcl_command_reply *))
{
    char why[256];
    if (!c->request.spec ||
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    handler(&c->request, &c->reply);
    return true;
}

static bool dqo_run(struct dqo_call *c)
{
    return dqo_run_handler(c, zcl_native_handle_dev_agent_queue);
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

struct dqo_priority_reply {
    char code[64];
    char leaf[40];
    long long seq;
    long long attempt;
    long long previous;
    long long priority;
    bool changed;
};

static bool dqo_priority_call(const char *name, long long seq,
    long long attempt, int priority, struct dqo_priority_reply *out)
{
    struct dqo_call c;
    memset(out, 0, sizeof(*out));
    out->seq = out->attempt = out->previous = out->priority = -1;
    json_init(&c.input);
    json_set_object(&c.input);
    memset(&c.request, 0, sizeof(c.request));
    c.request.input = &c.input;
    c.request.spec = zcl_command_registry_find(zcl_command_catalog(),
        DQO_PRIORITY_PATH, NULL);
    zcl_command_reply_init(&c.reply, "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c.input, "name", name);
    (void)json_push_kv_int(&c.input, "seq", seq);
    (void)json_push_kv_int(&c.input, "attempt", attempt);
    (void)json_push_kv_int(&c.input, "priority", priority);
    bool ran = dqo_run_handler(&c, zcl_native_handle_dev_agent_queue_reprioritize);
    (void)snprintf(out->code, sizeof(out->code), "%s",
        c.reply.status == ZCL_COMMAND_STATUS_PASSED ? "" : c.reply.error.code);
    (void)snprintf(out->leaf, sizeof(out->leaf), "%s",
        json_get_str(json_get(&c.reply.data, "leaf")));
    const struct json_value *v;
    if ((v = json_get(&c.reply.data, "seq")) && v->type == JSON_INT)
        out->seq = json_get_int(v);
    if ((v = json_get(&c.reply.data, "attempt")) && v->type == JSON_INT)
        out->attempt = json_get_int(v);
    if ((v = json_get(&c.reply.data, "previous_priority")) && v->type == JSON_INT)
        out->previous = json_get_int(v);
    if ((v = json_get(&c.reply.data, "priority")) && v->type == JSON_INT)
        out->priority = json_get_int(v);
    out->changed = json_get_bool(json_get(&c.reply.data, "changed"));
    dqo_end(&c);
    return ran;
}

struct dqo_cancel_reply {
    char code[64];
    char leaf[40];
    long long seq;
    long long attempt;
    long long cancelled;
    long long terminated;
};

static void dqo_cancel_begin(struct dqo_call *c, const char *name)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec = zcl_command_registry_find(zcl_command_catalog(),
        DQO_CANCEL_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c->input, "name", name);
}

static bool dqo_cancel_finish(struct dqo_call *c, bool ran,
    struct dqo_cancel_reply *out)
{
    const struct json_value *v;
    memset(out, 0, sizeof(*out));
    out->seq = out->attempt = out->cancelled = out->terminated = -1;
    (void)snprintf(out->code, sizeof(out->code), "%s",
        c->reply.status == ZCL_COMMAND_STATUS_PASSED ? "" : c->reply.error.code);
    const char *leaf = json_get_str(json_get(&c->reply.data, "leaf"));
    (void)snprintf(out->leaf, sizeof(out->leaf), "%s", leaf ? leaf : "");
    if ((v = json_get(&c->reply.data, "seq")) && v->type == JSON_INT)
        out->seq = json_get_int(v);
    if ((v = json_get(&c->reply.data, "attempt")) && v->type == JSON_INT)
        out->attempt = json_get_int(v);
    if ((v = json_get(&c->reply.data, "cancelled")) && v->type == JSON_INT)
        out->cancelled = json_get_int(v);
    if ((v = json_get(&c->reply.data, "terminated")) && v->type == JSON_INT)
        out->terminated = json_get_int(v);
    dqo_end(c);
    return ran;
}

static bool dqo_cancel_exact(const char *name, long long seq,
    long long attempt, bool terminate, struct dqo_cancel_reply *out)
{
    struct dqo_call c;
    dqo_cancel_begin(&c, name);
    (void)json_push_kv_int(&c.input, "seq", seq);
    (void)json_push_kv_int(&c.input, "attempt", attempt);
    if (terminate)
        (void)json_push_kv_bool(&c.input, "terminate", true);
    return dqo_cancel_finish(&c,
        dqo_run_handler(&c, zcl_native_handle_dev_agent_queue_cancel_exact), out);
}

static bool dqo_cancel_unpaired(const char *name, bool seq_only,
    struct dqo_cancel_reply *out)
{
    struct dqo_call c;
    dqo_cancel_begin(&c, name);
    if (seq_only)
        (void)json_push_kv_int(&c.input, "seq", 2);
    else
        (void)json_push_kv_int(&c.input, "attempt", 1);
    return dqo_cancel_finish(&c,
        dqo_run_handler(&c, zcl_native_handle_dev_agent_queue_cancel_exact), out);
}

static bool dqo_cancel_wrong_type(const char *name,
    struct dqo_cancel_reply *out)
{
    struct dqo_call c;
    dqo_cancel_begin(&c, name);
    (void)json_push_kv_str(&c.input, "seq", "2");
    (void)json_push_kv_str(&c.input, "attempt", "1");
    return dqo_cancel_finish(&c,
        dqo_run_handler(&c, zcl_native_handle_dev_agent_queue_cancel_exact), out);
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

static bool dqo_queue_row(long long seq, const char *name, int priority)
{
    char line[1024];
    (void)snprintf(line, sizeof(line),
        "{\"seq\":%lld,\"ts\":\"2026-09-18T00:00:00Z\",\"kind\":\"leaf\","
        "\"name\":\"%s\",\"group\":\"\",\"path\":\"\",\"brief\":\"\","
        "\"model\":\"\",\"attempt\":1,\"priority\":%d,\"state\":\"queued\","
        "\"worktree\":\"\",\"pid_or_unit\":\"\",\"started\":0}\n",
        seq, name, priority);
    return dqo_append("queue.jsonl", line);
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

static int dqo_case_reprioritize(void)
{
    int failures = 0;
    TEST("queue order: exact queued identity reprioritizes atomically") {
        struct dqo_priority_reply r;
        char tmp[1300];
        dqo_isolate("reprioritize");
        ASSERT(dqo_post_ok("promoted", 3, NULL));
        ASSERT(dqo_post_ok("other", 1, NULL));
        ASSERT(dqo_priority_call("promoted", 1, 1, 0, &r));
        ASSERT_STR_EQ(r.code, "");
        ASSERT_STR_EQ(r.leaf, DQO_PRIORITY_PATH);
        ASSERT(r.changed && r.seq == 1 && r.attempt == 1 &&
            r.previous == 3 && r.priority == 0);
        (void)snprintf(tmp, sizeof(tmp), "%s/z23/dev/queue/queue.jsonl.tmp",
            g_dqo_state);
#if !defined(_WIN32)
        ASSERT(mkdir(tmp, 0700) == 0);
#endif
        ASSERT(dqo_priority_call("promoted", 1, 1, 0, &r));
        ASSERT_STR_EQ(r.code, "");
        ASSERT(!r.changed && r.seq == 1 && r.attempt == 1 &&
            r.previous == 0 && r.priority == 0);
#if !defined(_WIN32)
        ASSERT(rmdir(tmp) == 0);
        ASSERT(mkdir(tmp, 0700) == 0);
#endif
        ASSERT(dqo_priority_call("promoted", 1, 1, 3, &r));
        ASSERT_STR_EQ(r.code, "QUEUE_WRITE_FAILED");
        ASSERT_STR_EQ(r.leaf, DQO_PRIORITY_PATH);
#if !defined(_WIN32)
        ASSERT(rmdir(tmp) == 0);
#endif
        ASSERT(dqo_claim_is("promoted"));
        ASSERT(dqo_priority_call("promoted", 1, 1, 0, &r));
        ASSERT_STR_EQ(r.code, "PRIORITY_RUNNING");
        ASSERT(dqo_priority_call("other", 1, 1, 1, &r));
        ASSERT_STR_EQ(r.code, "PRIORITY_IDENTITY_MISMATCH");
        ASSERT(dqo_priority_call("other", 2, 2, 1, &r));
        ASSERT_STR_EQ(r.code, "PRIORITY_IDENTITY_MISMATCH");
        ASSERT(dqo_priority_call("other", 2, 1, 4, &r));
        ASSERT_STR_EQ(r.code, "BAD_INPUT");
        ASSERT(dqo_priority_call("other", 2, 1, 0, &r));
        ASSERT_STR_EQ(r.code, "");
        ASSERT(r.changed && r.seq == 2 && r.attempt == 1 &&
            r.previous == 1 && r.priority == 0);
        ASSERT(dqo_claim_is("other"));
        ASSERT(dqo_post_ok("waiting", 3, "owner"));
        ASSERT(dqo_claim_is(""));
        ASSERT(dqo_priority_call("waiting", 3, 1, 3, &r));
        ASSERT_STR_EQ(r.code, "PRIORITY_NOT_QUEUED");
        ASSERT(dqo_priority_call("waiting", 3, 1, 0, &r));
        ASSERT_STR_EQ(r.code, "PRIORITY_NOT_QUEUED");
        ASSERT(dqo_post_ok("duplicate", 2, NULL));
        ASSERT(dqo_queue_row(4, "duplicate", 2));
        ASSERT(dqo_priority_call("duplicate", 4, 1, 0, &r));
        ASSERT_STR_EQ(r.code, "QUEUE_READ_FAILED");
        ASSERT_STR_EQ(r.leaf, DQO_PRIORITY_PATH);
        PASS();
    }
_test_next:;
    dqo_restore();
    return failures;
}

static int dqo_case_cancel_exact(void)
{
    int failures = 0;
    TEST("queue order: exact cancel cannot remove a stale or running task") {
        struct dqo_cancel_reply r;
        char tmp[1300];
        dqo_isolate("cancel-exact");
        ASSERT(dqo_post_ok("victim", 3, NULL));
        ASSERT(dqo_post_ok("other", 1, NULL));
        (void)snprintf(tmp, sizeof(tmp), "%s/z23/dev/queue/queue.jsonl.tmp",
            g_dqo_state);
#if !defined(_WIN32)
        ASSERT(mkdir(tmp, 0700) == 0);
#endif
        ASSERT(dqo_cancel_exact("victim", 1, 1, false, &r));
        ASSERT_STR_EQ(r.code, "QUEUE_WRITE_FAILED");
        ASSERT(r.cancelled == -1 && r.terminated == -1);
#if !defined(_WIN32)
        ASSERT(rmdir(tmp) == 0);
#endif
        ASSERT(dqo_cancel_exact("victim", 1, 1, false, &r));
        ASSERT_STR_EQ(r.code, "");
        ASSERT_STR_EQ(r.leaf, DQO_CANCEL_PATH);
        ASSERT(r.seq == 1 && r.attempt == 1 && r.cancelled == 1 &&
            r.terminated == 0);
        ASSERT(dqo_cancel_exact("victim", 1, 1, false, &r));
        ASSERT_STR_EQ(r.code, "CANCEL_NOT_FOUND");
        ASSERT(!dqo_cancel_exact("other", 2, 0, false, &r));
        ASSERT(dqo_cancel_unpaired("other", true, &r));
        ASSERT_STR_EQ(r.code, "BAD_INPUT");
        ASSERT(dqo_cancel_unpaired("other", false, &r));
        ASSERT_STR_EQ(r.code, "BAD_INPUT");
        ASSERT(!dqo_cancel_wrong_type("other", &r));
        ASSERT(dqo_claim_is("other"));
        ASSERT(!dqo_cancel_exact("other", 2, 1, true, &r));
        ASSERT(dqo_cancel_exact("other", 2, 1, false, &r));
        ASSERT_STR_EQ(r.code, "CANCEL_RUNNING");
        ASSERT(r.cancelled == -1 && r.terminated == -1);
        ASSERT(dqo_cancel_exact("other", 2, 2, false, &r));
        ASSERT_STR_EQ(r.code, "CANCEL_NOT_FOUND");
        ASSERT(dqo_post_ok("waiting", 3, "owner"));
        ASSERT(dqo_claim_is(""));
        ASSERT(dqo_cancel_exact("waiting", 3, 1, false, &r));
        ASSERT_STR_EQ(r.code, "CANCEL_NOT_QUEUED");
        ASSERT(dqo_queue_row(4, "renewed", 2));
        ASSERT(dqo_queue_row(5, "renewed", 2));
        ASSERT(dqo_cancel_exact("renewed", 4, 1, false, &r));
        ASSERT_STR_EQ(r.code, "");
        ASSERT(r.cancelled == 1 && r.terminated == 0);
        ASSERT(dqo_claim_is("renewed"));
        ASSERT(dqo_cancel_exact("renewed", 5, 1, false, &r));
        ASSERT_STR_EQ(r.code, "CANCEL_RUNNING");
        ASSERT(dqo_queue_row(6, "duplicate-cancel", 2));
        ASSERT(dqo_queue_row(6, "duplicate-cancel", 2));
        ASSERT(dqo_cancel_exact("duplicate-cancel", 6, 1, false, &r));
        ASSERT_STR_EQ(r.code, "QUEUE_READ_FAILED");
        ASSERT(r.cancelled == -1 && r.terminated == -1);
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
    failures += dqo_case_reprioritize();
    failures += dqo_case_cancel_exact();
    failures += dqo_case_after();
    failures += dqo_case_legacy_and_refusals();
    failures += dqo_case_backpressure();
    failures += dqo_case_scope_list();
    return failures;
}
