/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ACCEPTANCE for dev.agent.queue's one-run-per-name guard.
 *
 * A name is one run directory (engine/<name>/a<attempt>), so two live rows
 * for one name are two executions racing on the same work. These cases pin
 * that the queue never lets that happen:
 *   - post refuses a name that is still queued or running, by name, and
 *     leaves the original row (its seq, its attempt) untouched;
 *   - claim never hands out a second running row for a name already
 *     running, even from a ledger that already carries a duplicate;
 *   - a restarted worker claiming again gets nothing new, and a reap that
 *     sees the same result twice records it once and claims nothing;
 *   - explicit cancel still drops the queued row, and a name whose run is
 *     terminal can be posted again (resume re-posts the same name).
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

#define DQG_PATH "dev.agent.queue"

static char g_dqg_state[1024];
static char g_dqg_saved_xdg[4096];
static bool g_dqg_had_xdg;

static void dqg_isolate(const char *tag)
{
    char base[512];
    test_make_tmpdir(base, sizeof(base), "devagent_queue_guard", tag);
    (void)snprintf(g_dqg_state, sizeof(g_dqg_state), "%s/state", base);
    g_dqg_had_xdg = getenv("XDG_STATE_HOME") != NULL;
    if (g_dqg_had_xdg)
        (void)snprintf(g_dqg_saved_xdg, sizeof(g_dqg_saved_xdg), "%s",
                       getenv("XDG_STATE_HOME"));
    setenv("XDG_STATE_HOME", g_dqg_state, 1);
}

static void dqg_restore(void)
{
    if (g_dqg_had_xdg)
        setenv("XDG_STATE_HOME", g_dqg_saved_xdg, 1);
    else
        unsetenv("XDG_STATE_HOME");
}

struct dqg_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dqg_begin(struct dqg_call *c, const char *action)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), DQG_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c->input, "action", action);
}

/* Validate through the REAL registry, then call the handler. */
static bool dqg_run(struct dqg_call *c)
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

static void dqg_end(struct dqg_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static void dqg_code(const struct dqg_call *c, char *code, size_t cap)
{
    (void)snprintf(code, cap, "%s",
                   c->reply.status == ZCL_COMMAND_STATUS_PASSED
                       ? "" : c->reply.error.code);
}

/* Post one leaf row; after == NULL leaves depends_on unset. The reply's
 * error code ("" on success) lands in code, the new seq in seq. */
static bool dqg_post(const char *name, const char *after, char *code,
                     size_t cap, long long *seq)
{
    struct dqg_call c;
    const struct json_value *v;
    bool ran;
    dqg_begin(&c, "post");
    (void)json_push_kv_str(&c.input, "kind", "leaf");
    (void)json_push_kv_str(&c.input, "name", name);
    if (after)
        (void)json_push_kv_str(&c.input, "depends_on", after);
    ran = dqg_run(&c);
    dqg_code(&c, code, cap);
    v = json_get(&c.reply.data, "seq");
    if (seq)
        *seq = (v && v->type == JSON_INT) ? json_get_int(v) : -1;
    dqg_end(&c);
    return ran;
}

static bool dqg_post_ok(const char *name, const char *after)
{
    char code[64];
    return dqg_post(name, after, code, sizeof(code), NULL) && !code[0];
}

/* Claim once as worker w1; the claimed name and seq, or "" / -1 when the
 * queue handed out nothing. */
static void dqg_claim(const char *session, char *name, size_t cap,
                      long long *seq)
{
    struct dqg_call c;
    const struct json_value *v;
    name[0] = '\0';
    *seq = -1;
    dqg_begin(&c, "claim");
    (void)json_push_kv_str(&c.input, "worker", "w1");
    (void)json_push_kv_str(&c.input, "session", session);
    if (dqg_run(&c) && c.reply.status == ZCL_COMMAND_STATUS_PASSED) {
        v = json_get(&c.reply.data, "name");
        if (v && v->type == JSON_STR && json_get_str(v))
            (void)snprintf(name, cap, "%s", json_get_str(v));
        v = json_get(&c.reply.data, "seq");
        if (v && v->type == JSON_INT)
            *seq = json_get_int(v);
    }
    dqg_end(&c);
}

static bool dqg_claim_is(const char *want)
{
    char got[96];
    long long seq;
    dqg_claim("s1", got, sizeof(got), &seq);
    if (strcmp(got, want) != 0) {
        printf("[claimed '%s', wanted '%s'] ", got, want);
        return false;
    }
    return true;
}

/* Count the rows of one status section ("queued" or "running") that
 * carry name; -1 when status itself failed. */
static long long dqg_count(const char *section, const char *name)
{
    struct dqg_call c;
    const struct json_value *arr;
    long long n = -1;
    dqg_begin(&c, "status");
    (void)json_push_kv_bool(&c.input, "json", true);
    if (dqg_run(&c) && c.reply.status == ZCL_COMMAND_STATUS_PASSED) {
        arr = json_get(&c.reply.data, section);
        n = 0;
        for (size_t i = 0; arr && i < json_size(arr); i++) {
            const struct json_value *nm = json_get(json_at(arr, i), "name");
            if (nm && nm->type == JSON_STR &&
                strcmp(json_get_str(nm), name) == 0)
                n++;
        }
    }
    dqg_end(&c);
    return n;
}

/* Append one raw line to a queue-dir file (outcomes.jsonl, queue.jsonl). */
static bool dqg_append(const char *file, const char *line)
{
    char path[1300];
    FILE *f;
    bool ok;
    (void)snprintf(path, sizeof(path), "%s/z23/dev/queue/%s", g_dqg_state,
                   file);
    f = fopen(path, "ab");
    if (!f)
        return false;
    ok = fputs(line, f) >= 0;
    return fclose(f) == 0 && ok;
}

/* Write the run's receipt so reap records its outcome. */
static bool dqg_receipt(const char *name, const char *verdict)
{
    char path[1400];
    FILE *f;
    bool ok;
    (void)snprintf(path, sizeof(path), "%s/z23/dev/engine/%s/a1/receipt.json",
                   g_dqg_state, name);
    f = fopen(path, "wb");
    if (!f)
        return false;
    ok = fprintf(f, "{\"verdict\":\"%s\",\"rc\":0}\n", verdict) > 0;
    return fclose(f) == 0 && ok;
}

/* Reap once; the number of outcomes it recorded, -1 on refusal. */
static long long dqg_reap(void)
{
    struct dqg_call c;
    const struct json_value *arr;
    long long n = -1;
    dqg_begin(&c, "reap");
    if (dqg_run(&c) && c.reply.status == ZCL_COMMAND_STATUS_PASSED) {
        arr = json_get(&c.reply.data, "outcomes");
        n = arr ? (long long)json_size(arr) : 0;
    }
    dqg_end(&c);
    return n;
}

static int dqg_case_post_queued(void)
{
    int failures = 0;
    TEST("queue guard: a second post of a queued name is refused by name") {
        char code[64];
        long long first = -1, again = -1;
        dqg_isolate("postq");
        ASSERT(dqg_post("twin", NULL, code, sizeof(code), &first));
        ASSERT_STR_EQ(code, "");
        ASSERT(first >= 1);
        ASSERT(dqg_post("twin", NULL, code, sizeof(code), &again));
        ASSERT_STR_EQ(code, "NAME_IN_FLIGHT");
        ASSERT_EQ(dqg_count("queued", "twin"), 1);
        /* The original enqueue identity survives: it is the row claimed. */
        {
            char got[96];
            long long seq;
            dqg_claim("s1", got, sizeof(got), &seq);
            ASSERT_STR_EQ(got, "twin");
            ASSERT_EQ(seq, first);
        }
        PASS();
    }
_test_next:;
    dqg_restore();
    return failures;
}

static int dqg_case_post_running(void)
{
    int failures = 0;
    TEST("queue guard: a post of a running name is refused, no 2nd run") {
        char code[64];
        dqg_isolate("postr");
        ASSERT(dqg_post_ok("solo", NULL));
        ASSERT(dqg_claim_is("solo"));
        ASSERT(dqg_post("solo", NULL, code, sizeof(code), NULL));
        ASSERT_STR_EQ(code, "NAME_IN_FLIGHT");
        ASSERT(dqg_claim_is(""));
        ASSERT_EQ(dqg_count("running", "solo"), 1);
        ASSERT_EQ(dqg_count("queued", "solo"), 0);
        PASS();
    }
_test_next:;
    dqg_restore();
    return failures;
}

/* A ledger written before the guard can already hold two queued rows for
 * one name: claim runs the first and never the second while it runs. A
 * restarted worker (a new session) claiming again gets nothing new. */
static int dqg_case_legacy_duplicate(void)
{
    int failures = 0;
    TEST("queue guard: claim never runs a name twice, even from old rows") {
        char got[96];
        long long seq = -1;
        dqg_isolate("legacy");
        ASSERT(dqg_post_ok("seed", NULL));
        ASSERT(dqg_append("queue.jsonl",
            "{\"seq\":7,\"ts\":\"2026-09-18T00:00:00Z\",\"kind\":\"leaf\","
            "\"name\":\"seed\",\"attempt\":1,\"state\":\"queued\"}\n"));
        dqg_claim("s1", got, sizeof(got), &seq);
        ASSERT_STR_EQ(got, "seed");
        ASSERT_EQ(seq, 1);
        dqg_claim("s2-restart", got, sizeof(got), &seq);
        ASSERT_STR_EQ(got, "");
        ASSERT_EQ(dqg_count("running", "seed"), 1);
        PASS();
    }
_test_next:;
    dqg_restore();
    return failures;
}

/* Cancel still drops the queued row; a terminal run may be posted again;
 * reaping the same result twice records it once and claims nothing. */
static int dqg_case_cancel_and_terminal(void)
{
    int failures = 0;
    TEST("queue guard: cancel and terminal results reopen the name once") {
        dqg_isolate("reopen");
        ASSERT(dqg_post_ok("again", NULL));
        {
            struct dqg_call c;
            char code[64];
            dqg_begin(&c, "cancel");
            (void)json_push_kv_str(&c.input, "name", "again");
            ASSERT(dqg_run(&c));
            dqg_code(&c, code, sizeof(code));
            dqg_end(&c);
            ASSERT_STR_EQ(code, "");
        }
        ASSERT(dqg_post_ok("again", NULL));
        ASSERT(dqg_claim_is("again"));
        ASSERT(dqg_receipt("again", "fail"));
        ASSERT_EQ(dqg_reap(), 1);
        ASSERT_EQ(dqg_reap(), 0);
        ASSERT(dqg_claim_is(""));
        ASSERT(dqg_post_ok("again", NULL));
        ASSERT_EQ(dqg_count("queued", "again"), 1);
        PASS();
    }
_test_next:;
    dqg_restore();
    return failures;
}

int test_devagent_queue_guard(void);
int test_devagent_queue_guard(void)
{
    int failures = 0;
#if defined(_WIN32)
    TEST("queue guard: POSIX state rig only") {
        PASS();
    }
    return failures;
#endif
    failures += dqg_case_post_queued();
    failures += dqg_case_post_running();
    failures += dqg_case_legacy_duplicate();
    failures += dqg_case_cancel_and_terminal();
    return failures;
}
