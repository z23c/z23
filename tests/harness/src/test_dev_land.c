/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.land (tools/command/native_dev_land.c).
 *
 * THE PROPERTY THIS GROUP EXISTS FOR: nothing waits. Every case below runs
 * against an isolated XDG_STATE_HOME and a real git rig — a bare "origin"
 * plus a clone — so it proves the queue's behavior rather than the state of
 * this machine. The exact proof is the ONE thing replaced, by
 * ZCL_LAND_PROOF_STUB: a case that ran a real 15-minute proof would be a
 * test of the proof, not of the queue. Every rebase, push, row, and lock
 * exercised here is the production path.
 *
 * The handler is called DIRECTLY, which is exactly what the CLI does after
 * input validation — and the input is additionally validated through the
 * real registry first, so a key the .def never declared is caught here
 * rather than passing in-process and failing from a shell.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(_WIN32)
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define DLX_PATH "dev.land"

/* ── isolated state root ───────────────────────────────────────────────── */

static char g_dlx_state[1024];
static char g_dlx_saved_xdg[4096];
static bool g_dlx_had_xdg;

static void dlx_isolate(const char *tag)
{
    char base[512];
    test_make_tmpdir(base, sizeof(base), "dev_land", tag);
    (void)snprintf(g_dlx_state, sizeof(g_dlx_state), "%s/state", base);
    g_dlx_had_xdg = getenv("XDG_STATE_HOME") != NULL;
    if (g_dlx_had_xdg)
        (void)snprintf(g_dlx_saved_xdg, sizeof(g_dlx_saved_xdg), "%s",
                       getenv("XDG_STATE_HOME"));
    setenv("XDG_STATE_HOME", g_dlx_state, 1);
    unsetenv("ZCL_LAND_PROOF_STUB");
    unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
}

static void dlx_restore(void)
{
    if (g_dlx_had_xdg)
        setenv("XDG_STATE_HOME", g_dlx_saved_xdg, 1);
    else
        unsetenv("XDG_STATE_HOME");
    unsetenv("ZCL_LAND_PROOF_STUB");
    unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
}

static void dlx_landdir(char *out, size_t cap)
{
    (void)snprintf(out, cap, "%s/z23/dev/land", g_dlx_state);
}

/* ── one in-process invocation ─────────────────────────────────────────── */

struct dlx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dlx_begin(struct dlx_call *c, const char *action)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), DLX_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.land.v1");
    if (action)
        (void)json_push_kv_str(&c->input, "action", action);
}

static bool dlx_run(struct dlx_call *c)
{
    char why[256];
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_dev_land(&c->request, &c->reply);
    return true;
}

static void dlx_end(struct dlx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool dlx_ok(const struct dlx_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *dlx_str(const struct dlx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static int64_t dlx_int(const struct dlx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static const struct json_value *dlx_arr(const struct dlx_call *c,
                                        const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_ARR ? v : NULL;
}

#if !defined(_WIN32)

/* ── a real git rig: a bare origin and a clone ─────────────────────────── */

static int dlx_git(const char *dir, const char *const *args)
{
    const char *argv[24];
    size_t n = 0;
    char sink[4096];
    argv[n++] = "git";
    if (dir) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i]; i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    return zcl_spawn_capture(argv, sink, sizeof(sink), 60000);
}

static int dlx_git_out(const char *dir, const char *const *args, char *out,
                       size_t cap)
{
    const char *argv[24];
    size_t n = 0;
    int rc;
    argv[n++] = "git";
    if (dir) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i]; i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    rc = zcl_spawn_capture(argv, out, cap, 60000);
    for (size_t i = strlen(out); i > 0; i--) {
        if (out[i - 1] == '\n' || out[i - 1] == '\r')
            out[i - 1] = '\0';
        else
            break;
    }
    return rc;
}

static bool dlx_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    size_t len;
    bool wrote;
    if (!f)
        return false;
    len = strlen(text);
    wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

struct dlx_rig {
    char bare[600];
    char clone[600];
    char tip[64];
};

/* A commit in the clone whose parent is origin/main, pushed nowhere. */
static bool dlx_commit(const char *dir, const char *name, const char *body,
                       char out[64])
{
    char path[1200];
    const char *add[] = { "add", "-A", NULL };
    const char *commit[] = { "-c", "user.name=land",
                             "-c", "user.email=land@z23.invalid",
                             "commit", "--quiet", "--no-verify",
                             "--no-gpg-sign", "-m", name, NULL };
    const char *head[] = { "rev-parse", "HEAD", NULL };
    (void)snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (!dlx_write(path, body))
        return false;
    if (dlx_git(dir, add) != 0)
        return false;
    if (dlx_git(dir, commit) != 0)
        return false;
    return dlx_git_out(dir, head, out, 64) == 0 && strlen(out) == 40;
}

/* NOTE: tag must differ from every other fixture tag in the same TEST —
 * test_make_tmpdir wipes and recreates its path. */
static bool dlx_rig_make(struct dlx_rig *rig, const char *tag)
{
    char base[512];
    const char *init_bare[] = { "init", "--quiet", "--bare",
                                "--initial-branch=main", rig->bare, NULL };
    const char *clone[] = { "clone", "--quiet", rig->bare, rig->clone,
                            NULL };
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
    char seed[64];
    test_make_tmpdir(base, sizeof(base), "dev_land", tag);
    (void)snprintf(rig->bare, sizeof(rig->bare), "%s/origin.git", base);
    (void)snprintf(rig->clone, sizeof(rig->clone), "%s/clone", base);
    if (dlx_git(NULL, init_bare) != 0)
        return false;
    if (dlx_git(NULL, clone) != 0)
        return false;
    /* A checkout marker set, so the leaf's checkout-root walk and its own
     * worktree bookkeeping behave the way they do in a real tree. */
    if (!dlx_commit(rig->clone, "seed.txt", "seed\n", seed))
        return false;
    if (dlx_git(rig->clone, push) != 0)
        return false;
    if (dlx_git(rig->clone, fetch) != 0)
        return false;
    if (!dlx_commit(rig->clone, "change.txt", "one\n", rig->tip))
        return false;
    return true;
}

static bool dlx_file_exists(const char *path)
{
    struct stat st;
    return path && path[0] && stat(path, &st) == 0;
}

static void dlx_submit(struct dlx_call *c, const struct dlx_rig *rig,
                       const char *tip)
{
    dlx_begin(c, "submit");
    (void)json_push_kv_str(&c->input, "tip", tip);
    (void)json_push_kv_str(&c->input, "worktree", rig->clone);
}

/* origin/main as the bare repo itself reports it. */
static bool dlx_origin_main(const struct dlx_rig *rig, char out[64])
{
    const char *args[] = { "rev-parse", "main", NULL };
    return dlx_git_out(rig->bare, args, out, 64) == 0 && strlen(out) == 40;
}

#endif /* !defined(_WIN32) */

int test_dev_land(void);
int test_dev_land(void)
{
    int failures = 0;

    TEST("land: the leaf is registered with its verb and row keys") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DLX_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "action") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "tip") != NULL);
        ASSERT(spec->input_keys &&
               strstr(spec->input_keys, "worktree") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "note") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "seq") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "json") != NULL);
        ASSERT(spec->positional_keys &&
               strstr(spec->positional_keys, "action") != NULL);
        PASS();
    }

    TEST("land: an unknown action and a missing one are refused") {
        struct dlx_call c;
        dlx_isolate("route");
        dlx_begin(&c, "launch");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, NULL);
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        dlx_restore();
        PASS();
    }

#if !defined(_WIN32)

    TEST("land: submit refuses an unsigned tip and an unknown one") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("refuse");
        ASSERT(dlx_rig_make(&rig, "refuse_rig"));
        /* The fixture commits are --no-gpg-sign, so this IS the unsigned
         * case, and the bypass is not set. */
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        /* A commit id nobody can resolve. */
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, "0123456789abcdef0123456789abcdef01234567");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        /* Not a commit id at all. */
        dlx_submit(&c, &rig, "main");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        /* Nothing was stored by any of the three. */
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(dlx_arr(&c, "queued") != NULL);
        ASSERT_EQ((long long)dlx_arr(&c, "queued")->num_children, 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }

    TEST("land: submit queues the tip and status lists it, without waiting") {
        struct dlx_rig rig;
        struct dlx_call c;
        const struct json_value *rows;
        char full[64];
        time_t t0, t1;
        dlx_isolate("queue");
        ASSERT(dlx_rig_make(&rig, "queue_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        (void)snprintf(full, sizeof(full), "%s", rig.tip);
        t0 = time(NULL);
        dlx_submit(&c, &rig, full);
        (void)json_push_kv_str(&c.input, "note", "the first landing");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 1);
        ASSERT(strcmp(dlx_str(&c, "state"), "queued") == 0);
        ASSERT(strcmp(dlx_str(&c, "tip"), full) == 0);
        dlx_end(&c);
        t1 = time(NULL);
        /* Submit is a file append. It cannot have proved anything. */
        ASSERT((long long)(t1 - t0) < 20);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        rows = dlx_arr(&c, "queued");
        ASSERT(rows != NULL);
        ASSERT_EQ((long long)rows->num_children, 1);
        ASSERT(json_get_str(json_get(&rows->children[0], "tip")) &&
               strcmp(json_get_str(json_get(&rows->children[0], "tip")),
                      full) == 0);
        /* Nothing is in flight before a step runs. */
        ASSERT(json_get(&c.reply.data, "in_flight") == NULL);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }

    TEST("land: a step over an empty queue is a no-op that returns at once") {
        struct dlx_call c;
        time_t t0, t1;
        dlx_isolate("empty");
        t0 = time(NULL);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "empty") == 0);
        dlx_end(&c);
        t1 = time(NULL);
        ASSERT((long long)(t1 - t0) < 10);
        dlx_restore();
        PASS();
    }

    TEST("land: the step that asks for a proof returns before it finishes") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], logpath[1400];
        dlx_isolate("start");
        ASSERT(dlx_rig_make(&rig, "start_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        /* Asked for, not answered: the request is in flight and the verb
         * came back. A step that waited would still be inside the proof. */
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        ASSERT(strcmp(dlx_str(&c, "phase"), "prove") == 0);
        dlx_end(&c);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(json_get(&c.reply.data, "in_flight") != NULL);
        ASSERT_EQ((long long)dlx_arr(&c, "queued")->num_children, 0);
        dlx_end(&c);
        /* A second step while the proof is still pending changes nothing
         * and still returns. */
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "proving") == 0);
        dlx_end(&c);
        /* The private landing worktree was created once and reused. */
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(logpath, sizeof(logpath), "%s/wt/.git", landdir);
        ASSERT(dlx_file_exists(logpath));
        dlx_restore();
        PASS();
    }

    TEST("land: a passing proof fast-forwards the real origin and lands") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], local[64];
        const struct json_value *outcomes;
        dlx_isolate("land");
        ASSERT(dlx_rig_make(&rig, "land_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        /* The proof answers between steps, exactly as the real one does. */
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        (void)snprintf(local, sizeof(local), "%s", dlx_str(&c, "tip_pushed"));
        ASSERT(strlen(local) == 40);
        dlx_end(&c);
        /* The bare origin moved, and to exactly the commit that was proved. */
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, before) != 0);
        ASSERT(strcmp(after, local) == 0);
        /* The outcome is durable and the queue is empty again. */
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_EQ((long long)dlx_arr(&c, "queued")->num_children, 0);
        ASSERT(json_get(&c.reply.data, "in_flight") == NULL);
        outcomes = dlx_arr(&c, "outcomes");
        ASSERT(outcomes != NULL);
        ASSERT_EQ((long long)outcomes->num_children, 1);
        ASSERT(json_get_str(json_get(&outcomes->children[0], "state")) &&
               strcmp(json_get_str(json_get(&outcomes->children[0],
                                            "state")), "landed") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }

    TEST("land: a failing proof records the dimension and a log path") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], logpath[4200];
        const struct json_value *outcomes;
        dlx_isolate("fail");
        ASSERT(dlx_rig_make(&rig, "fail_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "fail", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "lint") == 0);
        (void)snprintf(logpath, sizeof(logpath), "%s", dlx_str(&c,
                                                               "log_path"));
        ASSERT(logpath[0] != '\0');
        ASSERT(dlx_file_exists(logpath));
        dlx_end(&c);
        /* A red proof pushes nothing. */
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, before) == 0);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        outcomes = dlx_arr(&c, "outcomes");
        ASSERT(outcomes != NULL);
        ASSERT_EQ((long long)outcomes->num_children, 1);
        ASSERT(json_get_str(json_get(&outcomes->children[0], "state")) &&
               strcmp(json_get_str(json_get(&outcomes->children[0],
                                            "state")), "failed") == 0);
        ASSERT(json_get_str(json_get(&outcomes->children[0], "log_path")) &&
               json_get_str(json_get(&outcomes->children[0],
                                     "log_path"))[0] != '\0');
        dlx_end(&c);
        dlx_restore();
        PASS();
    }

    TEST("land: a base that moved while proving re-rebases, never lands") {
        struct dlx_rig rig;
        struct dlx_call c;
        char stranger[64], main_now[64];
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
        const char *branch[] = { "checkout", "--quiet", "-B", "side",
                                 "origin/main", NULL };
        const char *back[] = { "checkout", "--quiet", "-B", "main", NULL };
        char side[600];
        dlx_isolate("moved");
        ASSERT(dlx_rig_make(&rig, "moved_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        /* A STRANGER lands on main while this request is proving. */
        (void)snprintf(side, sizeof(side), "%s", rig.clone);
        ASSERT(dlx_git(side, branch) == 0);
        ASSERT(dlx_commit(side, "stranger.txt", "elsewhere\n", stranger));
        ASSERT(dlx_git(side, push) == 0);
        ASSERT(dlx_git(side, back) == 0);
        ASSERT(dlx_git(side, fetch) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        /* The receipt is about a base nobody is on. It rebases instead. */
        ASSERT(strcmp(dlx_str(&c, "state"), "rebased") == 0);
        ASSERT_EQ(dlx_int(&c, "attempt"), 2);
        dlx_end(&c);
        /* main is still the stranger's commit: nothing was landed on a
         * stale receipt. */
        ASSERT(dlx_origin_main(&rig, main_now));
        ASSERT(strcmp(main_now, stranger) == 0);
        dlx_restore();
        PASS();
    }

    TEST("land: cancel drops one request by sequence number") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("cancel");
        ASSERT(dlx_rig_make(&rig, "cancel_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        /* A sequence number nobody submitted is refused, not invented. */
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 99);
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "cancelled") == 0);
        dlx_end(&c);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_EQ((long long)dlx_arr(&c, "queued")->num_children, 0);
        dlx_end(&c);
        /* A cancelled request is a step's no-op, not a landing. */
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "empty") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }

    TEST("land: two submitters at once never interleave a row") {
        struct dlx_rig rig;
        char landdir[1200], qf[1400], line[8192];
        pid_t a, b;
        int sa = 0, sb = 0, nlines = 0;
        FILE *f;
        dlx_isolate("fork");
        ASSERT(dlx_rig_make(&rig, "fork_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        a = fork();
        ASSERT(a >= 0);
        if (a == 0) {
            struct dlx_call c;
            dlx_submit(&c, &rig, rig.tip);
            (void)dlx_run(&c);
            _exit(dlx_ok(&c) ? 0 : 1);
        }
        b = fork();
        ASSERT(b >= 0);
        if (b == 0) {
            struct dlx_call c;
            dlx_submit(&c, &rig, rig.tip);
            (void)json_push_kv_str(&c.input, "note", "second");
            (void)dlx_run(&c);
            _exit(dlx_ok(&c) ? 0 : 1);
        }
        while (waitpid(a, &sa, 0) < 0)
            ;
        while (waitpid(b, &sb, 0) < 0)
            ;
        ASSERT(WIFEXITED(sa) && WEXITSTATUS(sa) == 0);
        ASSERT(WIFEXITED(sb) && WEXITSTATUS(sb) == 0);
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(qf, sizeof(qf), "%s/queue.jsonl", landdir);
        f = fopen(qf, "r");
        ASSERT(f != NULL);
        if (f) {
            while (fgets(line, sizeof(line), f)) {
                struct json_value v;
                size_t len = strlen(line);
                while (len > 0 &&
                       (line[len - 1] == '\n' || line[len - 1] == '\r'))
                    line[--len] = '\0';
                if (len == 0)
                    continue;
                nlines++;
                json_init(&v);
                ASSERT(json_read(&v, line, len) && v.type == JSON_OBJ);
                json_free(&v);
            }
            (void)fclose(f);
        }
        ASSERT_EQ((long long)nlines, 2);
        dlx_restore();
        PASS();
    }

#endif /* !defined(_WIN32) */

_test_next:;
    dlx_restore();
    if (failures == 0)
        printf("test_dev_land: all passed\n");
    else
        printf("test_dev_land: %d FAILED\n", failures);
    return failures;
}
