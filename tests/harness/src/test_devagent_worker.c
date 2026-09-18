/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.agent.worker (tools/command/native_devagent_worker.c)
 * plus the queue claim arm it consumes.
 *
 * Written against an isolated XDG_STATE_HOME, never the operator's real
 * state dir. It drives zcl_devagent_worker_drive DIRECTLY with tiny TEST
 * executor fixtures (no model, no network): the production seam
 * (zcl_devagent_worker_no_executor) is proven to run nothing, and the
 * lifecycle half — post, claim, execute, gate, receipt, reap, result —
 * is proven end to end. Restart, cancel, and crash cases pin the
 * never-duplicate and never-upgrade rules:
 *
 *   post -> worker claim -> fixture execution -> gate -> result/reap ->
 *     completed; restart before/after claim; cancel queued; crash
 *     incomplete; same task never submits twice; a model "completed" is
 *     never upgraded to PASS.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_devagent.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/confined_process.h"
#include "platform/process_lifecycle.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

/* ── isolated state root (this group owns its own rig) ─────────────────── */

static char g_wtx_state[1024];
static char g_wtx_saved_xdg[4096];
static bool g_wtx_had_xdg;
static char g_fx_count[1024];
static char g_fx_task[1024];

static void wtx_isolate(const char *tag)
{
    char base[512];
    test_make_tmpdir(base, sizeof(base), "devagent_worker", tag);
    (void)snprintf(g_wtx_state, sizeof(g_wtx_state), "%s/state", base);
    (void)snprintf(g_fx_count, sizeof(g_fx_count), "%s/fx.count", base);
    (void)snprintf(g_fx_task, sizeof(g_fx_task), "%s/fx.task", base);
    (void)remove(g_fx_count);
    (void)remove(g_fx_task);
    g_wtx_had_xdg = getenv("XDG_STATE_HOME") != NULL;
    if (g_wtx_had_xdg)
        (void)snprintf(g_wtx_saved_xdg, sizeof(g_wtx_saved_xdg), "%s",
                       getenv("XDG_STATE_HOME"));
    setenv("XDG_STATE_HOME", g_wtx_state, 1);
}

static void wtx_restore(void)
{
    if (g_wtx_had_xdg)
        setenv("XDG_STATE_HOME", g_wtx_saved_xdg, 1);
    else
        unsetenv("XDG_STATE_HOME");
}

/* ── one in-process queue invocation ───────────────────────────────────── */

struct wtx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void wtx_begin(struct wtx_call *c, const char *path,
                      const char *schema)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    c->request.view = "normal";
    zcl_command_reply_init(&c->reply, schema);
}

static void wtx_end(struct wtx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool wtx_ok(const struct wtx_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static void wtx_queue_post(const char *name)
{
    struct wtx_call c;
    wtx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c.input, "action", "post");
    (void)json_push_kv_str(&c.input, "kind", "leaf");
    (void)json_push_kv_str(&c.input, "name", name);
    zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
    (void)wtx_ok(&c);
    wtx_end(&c);
}

static bool wtx_queue_verb(const char *action, const char *extra_key,
                           const char *extra_val)
{
    struct wtx_call c;
    bool ok;
    wtx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c.input, "action", action);
    if (extra_key)
        (void)json_push_kv_str(&c.input, extra_key, extra_val);
    if (strcmp(action, "status") == 0)
        (void)json_push_kv_bool(&c.input, "json", true);
    if ((strcmp(action, "claim") == 0) && !extra_key) {
        (void)json_push_kv_str(&c.input, "worker", "wtx");
        (void)json_push_kv_str(&c.input, "session", "s1");
    }
    zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
    ok = wtx_ok(&c);
    wtx_end(&c);
    return ok;
}

/* Find {verdict, rc} for name in the status outcomes array. */
static bool wtx_outcome(const char *name, char *verdict, size_t vcap,
                        long long *rc)
{
    struct wtx_call c;
    const struct json_value *arr;
    size_t n, i;
    bool found = false;
    wtx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c.input, "action", "status");
    (void)json_push_kv_bool(&c.input, "json", true);
    zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
    if (wtx_ok(&c)) {
        arr = json_get(&c.reply.data, "outcomes");
        if (arr && arr->type == JSON_ARR) {
            n = json_size(arr);
            for (i = 0; i < n && !found; i++) {
                const struct json_value *r = json_at(arr, i);
                const struct json_value *v;
                const char *nm;
                if (!r || r->type != JSON_OBJ)
                    continue;
                v = json_get(r, "name");
                nm = (v && v->type == JSON_STR) ? json_get_str(v) : "";
                if (strcmp(nm, name) != 0)
                    continue;
                v = json_get(r, "verdict");
                (void)snprintf(verdict, vcap, "%s",
                               (v && v->type == JSON_STR) ? json_get_str(v) :
                                                           "");
                v = json_get(r, "rc");
                *rc = (v && v->type == JSON_INT) ?
                      (long long)json_get_int(v) : -1;
                found = true;
            }
        }
    }
    wtx_end(&c);
    return found;
}

/* True when a result mail row under ref carries needle in its body. */
static bool wtx_mail_has(const char *ref, const char *needle)
{
    struct wtx_call c;
    const struct json_value *arr;
    size_t n, i;
    bool found = false;
    wtx_begin(&c, "dev.agent.mail", "zcl.agent_mail.v1");
    (void)json_push_kv_str(&c.input, "action", "pull");
    zcl_native_handle_dev_agent_mail(&c.request, &c.reply);
    if (wtx_ok(&c)) {
        arr = json_get(&c.reply.data, "rows");
        if (arr && arr->type == JSON_ARR) {
            n = json_size(arr);
            for (i = 0; i < n && !found; i++) {
                const struct json_value *r = json_at(arr, i);
                const struct json_value *v;
                const char *rr, *body;
                if (!r || r->type != JSON_OBJ)
                    continue;
                v = json_get(r, "ref");
                rr = (v && v->type == JSON_STR) ? json_get_str(v) : "";
                v = json_get(r, "body");
                body = (v && v->type == JSON_STR) ? json_get_str(v) : "";
                if (strcmp(rr, ref) == 0 && strstr(body, needle))
                    found = true;
            }
        }
    }
    wtx_end(&c);
    return found;
}

/* Copy the body of the result mail row under ref. False when no row
 * under that ref exists at all. */
static bool wtx_mail_body(const char *ref, char *out, size_t cap)
{
    struct wtx_call c;
    const struct json_value *arr;
    size_t n, i;
    bool found = false;
    out[0] = '\0';
    wtx_begin(&c, "dev.agent.mail", "zcl.agent_mail.v1");
    (void)json_push_kv_str(&c.input, "action", "pull");
    zcl_native_handle_dev_agent_mail(&c.request, &c.reply);
    if (wtx_ok(&c)) {
        arr = json_get(&c.reply.data, "rows");
        if (arr && arr->type == JSON_ARR) {
            n = json_size(arr);
            for (i = 0; i < n && !found; i++) {
                const struct json_value *r = json_at(arr, i);
                const struct json_value *v;
                const char *rr;
                if (!r || r->type != JSON_OBJ)
                    continue;
                v = json_get(r, "ref");
                rr = (v && v->type == JSON_STR) ? json_get_str(v) : "";
                if (strcmp(rr, ref) != 0)
                    continue;
                v = json_get(r, "body");
                (void)snprintf(out, cap, "%s",
                               (v && v->type == JSON_STR) ? json_get_str(v)
                                                          : "");
                found = true;
            }
        }
    }
    wtx_end(&c);
    return found;
}

/* True when the run's own outcome row (run.out) carries needle. */
static bool wtx_runout_has(const char *name, long long attempt,
                           const char *needle)
{
    char path[4096], text[8192];
    FILE *f;
    size_t n;
    (void)snprintf(path, sizeof(path),
                   "%s/z23/dev/engine/%s/a%lld/run.out", g_wtx_state, name,
                   attempt);
    f = fopen(path, "rb");
    if (!f)
        return false;
    n = fread(text, 1, sizeof(text) - 1, f);
    (void)fclose(f);
    text[n] = '\0';
    return strstr(text, needle) != NULL;
}

#if !defined(_WIN32)
/* True when the run left a receipt.json behind. */
static bool wtx_receipt_exists(const char *name, long long attempt)
{
    char path[4096];
    struct stat st;
    (void)snprintf(path, sizeof(path),
                   "%s/z23/dev/engine/%s/a%lld/receipt.json", g_wtx_state,
                   name, attempt);
    return stat(path, &st) == 0;
}

/* Post one doc unit whose brief is `bytes` of filler ending in `tail`,
 * written under the state root where post admits briefs. */
static bool wtx_post_brief(const char *name, size_t bytes, const char *tail)
{
    struct wtx_call c;
    char path[4096];
    FILE *f;
    size_t k;
    bool ok;
    if (!wtx_queue_verb("status", NULL, NULL))
        return false;
    (void)snprintf(path, sizeof(path), "%s/z23/dev/%s.brief", g_wtx_state,
                   name);
    f = fopen(path, "wb");
    if (!f)
        return false;
    for (k = 0; k < bytes; k++)
        (void)fputc((k % 64) == 63 ? '\n' : 'b', f);
    (void)fputs(tail, f);
    (void)fclose(f);
    wtx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c.input, "action", "post");
    (void)json_push_kv_str(&c.input, "kind", "doc");
    (void)json_push_kv_str(&c.input, "name", name);
    (void)json_push_kv_str(&c.input, "path", "docs/brief-target.md");
    (void)json_push_kv_str(&c.input, "brief", path);
    zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
    ok = wtx_ok(&c);
    wtx_end(&c);
    return ok;
}

/* True when the task the fixture saw carries needle. */
static bool wtx_task_has(const char *needle)
{
    char text[16384];
    FILE *f = fopen(g_fx_task, "rb");
    size_t n;
    if (!f)
        return false;
    n = fread(text, 1, sizeof(text) - 1, f);
    (void)fclose(f);
    text[n] = '\0';
    return strstr(text, needle) != NULL;
}
#endif

/* ── TEST executor fixtures ──────────────────────────────────────────────
 * Modes: 0 guided outcome, 1 abort in child (crash), 2 sleep past the
 * wall cap (timeout), 3 hand-written receipt carrying g_fx_cand_raw as
 * the candidate byte for byte. The guided outcome writes a real
 * candidate file so the gate has something to judge. */

static int g_fx_mode;
static char g_fx_terminal[32];
static long long g_fx_rc;
static bool g_fx_candidate;
static char g_fx_cand_raw[512];

/* The executor runs in a forked child, so the run count crosses the
 * fork through an append-only file, never through process memory. */
static void wtx_count_bump(void)
{
    FILE *f;
    if (!g_fx_count[0])
        return;
    f = fopen(g_fx_count, "ab");
    if (f) {
        (void)fwrite("x", 1, 1, f);
        (void)fclose(f);
    }
}

static long long wtx_count_read(void)
{
    FILE *f;
    long long n = 0;
    int ch;
    f = fopen(g_fx_count, "rb");
    if (!f)
        return 0;
    while ((ch = fgetc(f)) != EOF) {
        if (ch == 'x')
            n++;
    }
    (void)fclose(f);
    return n;
}

/* The task the executor was handed, byte for byte, for the brief cases. */
static void wtx_task_record(const struct wkr_job *job)
{
    FILE *f;
    if (!g_fx_task[0])
        return;
    f = fopen(g_fx_task, "wb");
    if (f) {
        (void)fwrite(job->task, 1, strlen(job->task), f);
        (void)fclose(f);
    }
}

static bool wtx_fixture(const struct wkr_job *job, struct wkr_result *res)
{
    wtx_count_bump();
    wtx_task_record(job);
    if (g_fx_mode == 1) {
        struct rlimit core;
        /* A real crash: die by signal like a segfaulting adapter would.
         * Reset the harness's own fatal-signal watcher first (inherited
         * across the fork) and bar core files, so only the worker's
         * waitpid observes the death. */
        core.rlim_cur = 0;
        core.rlim_max = 0;
        (void)setrlimit(RLIMIT_CORE, &core);
        (void)signal(SIGABRT, SIG_DFL);
        (void)fflush(NULL);
        abort();
        _exit(134);
    }
    if (g_fx_mode == 2) {
        unsigned k;
        for (k = 0; k < 60; k++)
            (void)sleep(1);
    }
    if (g_fx_mode == 3) {
        /* The normal child path JSON-escapes the candidate, so a raw
         * newline could never reach the worker through it. Write the
         * receipt by hand and exit: the candidate arrives as exactly the
         * bytes a hostile or broken executor emitted. */
        char path[4096 + 64], line[2048];
        FILE *f;
        int w = snprintf(line, sizeof(line),
                         "{\"terminal\":\"pass\",\"rc\":0,\"candidate\":"
                         "\"%s\",\"evidence\":\"fixture receipt\","
                         "\"tokens_used\":42,\"wall_ms\":7}\n",
                         g_fx_cand_raw);
        if (w <= 0 || (size_t)w >= sizeof(line))
            _exit(126);
        if (snprintf(path, sizeof(path), "%s/executor_result.json",
                     job->rundir) >= (int)sizeof(path))
            _exit(126);
        f = fopen(path, "wb");
        if (!f)
            _exit(126);
        (void)fwrite(line, 1, strlen(line), f);
        (void)fclose(f);
        (void)fflush(NULL);
        _exit(0);
    }
    memset(res, 0, sizeof(*res));
    (void)snprintf(res->terminal, sizeof(res->terminal), "%s",
                   g_fx_terminal);
    res->rc = g_fx_rc;
    if (g_fx_candidate) {
        char path[4096 + 32];
        FILE *f;
        if (snprintf(path, sizeof(path), "%s/cand.diff", job->rundir) >=
            (int)sizeof(path))
            return true;
        f = fopen(path, "wb");
        if (f) {
            (void)fwrite("diff --breath\n", 1, 14, f);
            (void)fclose(f);
            (void)snprintf(res->candidate, sizeof(res->candidate), "%s",
                           "cand.diff");
        }
    }
    (void)snprintf(res->evidence, sizeof(res->evidence), "%s",
                   "fixture saw the task");
    res->tokens_used = 42;
    res->wall_ms = 7;
    return true;
}

static void wtx_opts(struct wkr_drive_opts *o, const char *worker,
                     const char *session)
{
    memset(o, 0, sizeof(*o));
    (void)snprintf(o->worker, sizeof(o->worker), "%s", worker);
    (void)snprintf(o->session, sizeof(o->session), "%s", session);
    o->deadline_s = 30;
    o->idle_start_s = 1;
    o->idle_limit_s = 3;
    o->max_jobs = 1;
    o->time_cap_s = 30;
    o->cpu_s = 30;
    o->mem_mb = 512;
    o->token_cap = 32000;
}

/* ── idle wake rig ───────────────────────────────────────────────────────
 * A forked poster queues one row after `delay_ms`, the way the receiver
 * does from its own process, while this process drives the worker. The
 * measured latency is the drive return time minus the post time, on the
 * system-wide monotonic clock. */

#if !defined(_WIN32)
static pid_t wtx_post_later(const char *name, int delay_ms)
{
    pid_t pid = fork();
    if (pid == 0) {
        platform_sleep_ms(delay_ms);
        wtx_queue_post(name);
        _exit(0);
    }
    return pid;
}

/* One fixture job posted `delay_ms` after the drive starts. Returns jobs
 * run; *after_post_ms gets the drive's return time since the post. */
static long long wtx_drive_late_post(struct wkr_drive_opts *o,
                                     const char *name, int delay_ms,
                                     long long *after_post_ms)
{
    long long t0, jobs;
    int st = 0;
    pid_t pid;
    /* The worker lock lives in the queue dir: let the queue create it. */
    if (!wtx_queue_verb("status", NULL, NULL))
        return -1;
    t0 = (long long)platform_time_monotonic_ms();
    pid = wtx_post_later(name, delay_ms);
    if (pid < 0)
        return -1;
    jobs = zcl_devagent_worker_drive(o, wtx_fixture);
    *after_post_ms =
        (long long)platform_time_monotonic_ms() - (t0 + delay_ms);
    (void)waitpid(pid, &st, 0);
    return jobs;
}
#endif

/* ── result-mail safety rig ──────────────────────────────────────────────
 * The result row under the ref is the ONLY thing the originating client
 * sees, so malformed executor evidence must never cancel it. Each case
 * drives one job whose receipt names `cand` verbatim and copies back the
 * body the client would read. */

#define WTX_ELIDED "unsafe-elided"

static bool wtx_hostile_run(const char *tag, const char *name,
                            const char *cand, char *body, size_t cap)
{
    struct wkr_drive_opts o;
    wtx_isolate(tag);
    wtx_queue_post(name);
    (void)remove(g_fx_count);
    g_fx_mode = 3;
    (void)snprintf(g_fx_cand_raw, sizeof(g_fx_cand_raw), "%s", cand);
    wtx_opts(&o, "wtx", "s-hostile");
    if (zcl_devagent_worker_drive(&o, wtx_fixture) != 1)
        return false;
    return wtx_mail_body(name, body, cap);
}

/* Every hostile candidate ends the same way: the row is posted, the
 * candidate is the marker, the substitution is announced, and the
 * hostile bytes are nowhere in the body. */
static bool wtx_elided_ok(const char *body, const char *name,
                          const char *leak)
{
    char refline[128];
    (void)snprintf(refline, sizeof(refline), "ref=%s\n", name);
    return strstr(body, refline) != NULL &&
           strstr(body, "candidate=" WTX_ELIDED "\n") != NULL &&
           strstr(body, "elided=" WTX_ELIDED "\n") != NULL &&
           strstr(body, leak) == NULL;
}

static void wtx_flip_submitted(const char *name, long long attempt,
                               bool to_true)
{
    char path[4096], text[2048], out[2048];
    const char *hit;
    const char *from = to_true ? "\"submitted\":false" : "\"submitted\":true";
    const char *to = to_true ? "\"submitted\":true" : "\"submitted\":false";
    FILE *f;
    size_t n;
    (void)snprintf(path, sizeof(path), "%s/z23/dev/engine/%s/a%lld/claim.json",
                   g_wtx_state, name, attempt);
    f = fopen(path, "rb");
    if (!f)
        return;
    n = fread(text, 1, sizeof(text) - 1, f);
    (void)fclose(f);
    text[n] = '\0';
    hit = strstr(text, from);
    if (!hit)
        return;
    {
        size_t pre = (size_t)(hit - text);
        size_t rest = strlen(hit + strlen(from));
        memcpy(out, text, pre);
        memcpy(out + pre, to, strlen(to));
        memcpy(out + pre + strlen(to), hit + strlen(from), rest + 1);
    }
    f = fopen(path, "wb");
    if (f) {
        (void)fwrite(out, 1, strlen(out), f);
        (void)fclose(f);
    }
}

/* ── confinement backend: platform-neutral half ──────────────────────────
 * The caps, the outcome mapping, the result record/parse/gate, the job
 * hand-off, the write-root and environment choices are the same code on
 * every host; these cases pin them on Linux. The Windows-only half (the
 * restricted job itself) is proven natively by the devagent_worker_confine
 * Windows acceptance program. */

static bool wtx_fx_failed(const struct wkr_job *job, struct wkr_result *res)
{
    (void)job;
    memset(res, 0, sizeof(*res));
    (void)snprintf(res->terminal, sizeof(res->terminal), "%s", "failed");
    res->rc = 3;
    (void)snprintf(res->evidence, sizeof(res->evidence), "%s",
                   "fixture failed on purpose");
    res->tokens_used = 5;
    return true;
}

static bool wtx_mkfile(const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    (void)fclose(f);
    return true;
}

/* A temp dir that looks like a worktree: a directory holding ".git". */
static bool wtx_worktree(const char *tag, char *out, size_t cap, bool git)
{
    char marker[1200];
    test_make_tmpdir(out, cap, "devagent_worker_ws", tag);
    if (!git)
        return true;
    (void)snprintf(marker, sizeof(marker), "%s/.git", out);
    return wtx_mkfile(marker);
}

static bool wtx_env_has(const char **env, const char *needle)
{
    for (size_t i = 0; env[i]; i++)
        if (strstr(env[i], needle))
            return true;
    return false;
}

static bool wtx_outcome_is(int status, bool signaled, bool term, long long rc,
                           const char *terminal)
{
    struct wkr_spawn_out out;
    struct wkr_outcome o;
    memset(&out, 0, sizeof(out));
    out.status = status;
    out.signaled = signaled;
    zcl_devagent_worker_outcome(&out, term, &o);
    if (!terminal)
        return o.gate;
    return !o.gate && o.rc == rc && strcmp(o.terminal, terminal) == 0;
}

#if !defined(_WIN32)
/* The confinement cases, in their own function so the suite entry stays
 * under the complexity cap. Returns the failure count. */
static int wtx_confine_cases(void)
{
    int failures = 0;
    TEST("confine: caps derive the POSIX rlimits and the Windows job caps")
    {
        struct wkr_drive_opts o;
        struct wkr_caps caps;
        wtx_opts(&o, "wtx", "s-caps");
        ASSERT(zcl_devagent_worker_caps(&o, &caps));
        ASSERT_EQ(caps.memory_bytes, 512ull * 1024ull * 1024ull);
        ASSERT_EQ(caps.cpu_s, 30);
        ASSERT_EQ(caps.wall_s, 30);
        ASSERT_EQ(caps.active_processes, WKR_ACTIVE_PROCESS_CAP);
        /* An uncapped field keeps POSIX's "not capped" meaning and makes
         * the set incomplete, which a Windows launch refuses. */
        o.mem_mb = 0;
        ASSERT(!zcl_devagent_worker_caps(&o, &caps));
        ASSERT_EQ(caps.memory_bytes, 0ull);
        ASSERT_EQ(caps.cpu_s, 30);
        o.mem_mb = 512;
        o.cpu_s = 0;
        ASSERT(!zcl_devagent_worker_caps(&o, &caps));
        ASSERT(!zcl_devagent_worker_caps(NULL, &caps));
        PASS();
    }

    TEST("confine: one outcome mapping for both backends")
    {
        ASSERT(wtx_outcome_is(-1, false, false, 127, "launch-failed"));
        ASSERT(wtx_outcome_is(-1, true, true, 127, "launch-failed"));
        ASSERT(wtx_outcome_is(0, false, false, 124, "timeout"));
        ASSERT(wtx_outcome_is(1, true, false, 130, "crashed"));
        ASSERT(wtx_outcome_is(1, false, true, 130, "crashed"));
        ASSERT(wtx_outcome_is(1, false, false, 0, NULL));
        /* An exception or fast-fail exit is the Windows death by signal;
         * an ordinary nonzero exit (the executor's rc) is not. */
        ASSERT(platform_confined_exit_is_crash(0xC0000005u));
        ASSERT(platform_confined_exit_is_crash(0xC0000409u));
        ASSERT(platform_confined_exit_is_crash(0xC00000FDu));
        ASSERT(!platform_confined_exit_is_crash(0u));
        ASSERT(!platform_confined_exit_is_crash(3u));
        ASSERT(!platform_confined_exit_is_crash(125u));
        ASSERT(!platform_confined_exit_is_crash(1816u));
        PASS();
    }

    TEST("confine: a failing executor exit maps to the failed verdict")
    {
        struct wkr_job *job = calloc(1, sizeof(*job));
        struct wkr_result res;
        struct wkr_spawn_out out;
        struct wkr_outcome oc;
        char verdict[32];
        int code;
        ASSERT(job != NULL);
        test_make_tmpdir(job->rundir, sizeof(job->rundir),
                         "devagent_worker", "cfail");
        job->token_cap = 32000;
        code = zcl_devagent_worker_child_record(job, wtx_fx_failed);
        ASSERT_EQ(code, 3);
        /* The parent saw an ordinary exit: the result file is gated. */
        memset(&out, 0, sizeof(out));
        out.status = 1;
        zcl_devagent_worker_outcome(&out, false, &oc);
        ASSERT(oc.gate);
        ASSERT(zcl_devagent_worker_parse_result(job->rundir, &res));
        ASSERT_STR_EQ(res.terminal, "failed");
        ASSERT_EQ(res.rc, 3);
        ASSERT_EQ(zcl_devagent_worker_gate(job, &res, verdict,
                                           sizeof(verdict)), 1);
        ASSERT_STR_EQ(verdict, "failed");
        ASSERT_EQ(zcl_devagent_worker_child_record(job, NULL), 125);
        free(job);
        PASS();
    }

    TEST("confine: unarmed backend refuses and runs nothing")
    {
        struct wkr_drive_opts o;
        struct wkr_job *job = calloc(1, sizeof(*job));
        struct wkr_spawn_out out;
        struct wkr_outcome oc;
        struct platform_process proc;
        struct platform_confined_spec spec;
        struct platform_confined_report rep;
        char path[4200];
        ASSERT(job != NULL);
        ASSERT_EQ((int)platform_confined_probe(),
                  (int)PLATFORM_CONFINE_MISSING_OS);
        ASSERT_STR_EQ(platform_confine_missing_name(
                          PLATFORM_CONFINE_MISSING_OS), "os");
        ASSERT_STR_EQ(platform_confine_missing_name(
                          PLATFORM_CONFINE_MISSING_LOW_INTEGRITY),
                      "low-integrity");
        memset(&spec, 0, sizeof(spec));
        platform_process_init(&proc);
        ASSERT_EQ((int)platform_confined_start(&proc, &spec),
                  (int)PLATFORM_CONFINE_MISSING_OS);
        ASSERT(proc.native == UINTPTR_MAX);
        ASSERT(!platform_confined_report(&proc, &rep));
        ASSERT(!platform_confined_release_roots(NULL, 0));
        ASSERT_EQ((int)platform_confined_self_check(1u << 30),
                  (int)PLATFORM_CONFINE_MISSING_OS);
        test_make_tmpdir(job->rundir, sizeof(job->rundir),
                         "devagent_worker", "unarmed");
        wtx_opts(&o, "wtx", "s-unarmed");
        out = zcl_devagent_worker_spawn_confined(&o, job, NULL);
        ASSERT_EQ(out.status, -1);
        zcl_devagent_worker_outcome(&out, false, &oc);
        ASSERT_EQ(oc.rc, 127);
        ASSERT_STR_EQ(oc.note, "executor-launch-failed");
        /* The re-entry refuses on a host with no confined backend and
         * leaves no result behind. */
        ASSERT_EQ(zcl_devagent_worker_child_main(job->rundir, wtx_fixture),
                  2);
        (void)snprintf(path, sizeof(path), "%s/executor_result.json",
                       job->rundir);
        ASSERT(!zcl_devagent_worker_file_exists(path));
        free(job);
        PASS();
    }

    TEST("confine: the job crosses the process boundary intact")
    {
        struct wkr_job *a = calloc(1, sizeof(*a));
        struct wkr_job *b = calloc(1, sizeof(*b));
        unsigned long long mem = 0;
        char missing[1100];
        ASSERT(a != NULL && b != NULL);
        test_make_tmpdir(a->rundir, sizeof(a->rundir), "devagent_worker",
                         "jobfile");
        (void)snprintf(a->name, sizeof(a->name), "%s", "wtx-job");
        (void)snprintf(a->kind, sizeof(a->kind), "%s", "leaf");
        (void)snprintf(a->model, sizeof(a->model), "%s", "m-1");
        (void)snprintf(a->task, sizeof(a->task), "%s",
                       "name=wtx-job\nquote=\"q\" back=\\ tab=\t\n\nprose");
        a->attempt = 2;
        a->seq = 7;
        a->token_cap = 32000;
        a->time_cap_s = 30;
        ASSERT(zcl_devagent_worker_job_store(a, 512ull << 20));
        ASSERT(zcl_devagent_worker_job_load(a->rundir, b, &mem));
        ASSERT_EQ(mem, 512ull << 20);
        ASSERT_STR_EQ(b->rundir, a->rundir);
        ASSERT_STR_EQ(b->name, a->name);
        ASSERT_STR_EQ(b->kind, a->kind);
        ASSERT_STR_EQ(b->model, a->model);
        ASSERT_STR_EQ(b->task, a->task);
        ASSERT_EQ(b->attempt, 2);
        ASSERT_EQ(b->seq, 7);
        ASSERT_EQ(b->token_cap, 32000);
        ASSERT_EQ(b->time_cap_s, 30);
        /* No memory cap, no job: the child would have nothing to verify. */
        ASSERT(!zcl_devagent_worker_job_store(a, 0));
        (void)snprintf(missing, sizeof(missing), "%s/absent", a->rundir);
        ASSERT(!zcl_devagent_worker_job_load(missing, b, &mem));
        free(a);
        free(b);
        PASS();
    }

    TEST("confine: only a named worktree becomes a write root")
    {
        char ws[1024], bare[1024], task[3000], out[4096];
        ASSERT(wtx_worktree("git", ws, sizeof(ws), true));
        ASSERT(wtx_worktree("bare", bare, sizeof(bare), false));
        (void)snprintf(task, sizeof(task),
                       "name=n\nkind=doc\nmuse-workspace: %s  \n"
                       "muse-scope: src/\n\nprose", ws);
        ASSERT(zcl_devagent_worker_task_workspace(task, out, sizeof(out)));
        ASSERT_STR_EQ(out, ws);
        /* Not a checkout, a filesystem root, relative, climbing, after the
         * header block, or absent: never a write root. */
        (void)snprintf(task, sizeof(task), "muse-workspace: %s\n", bare);
        ASSERT(!zcl_devagent_worker_task_workspace(task, out, sizeof(out)));
        ASSERT_STR_EQ(out, "");
        ASSERT(!zcl_devagent_worker_task_workspace("muse-workspace: /\n",
                                                   out, sizeof(out)));
        ASSERT(!zcl_devagent_worker_task_workspace(
            "muse-workspace: C:\\\n", out, sizeof(out)));
        ASSERT(!zcl_devagent_worker_task_workspace(
            "muse-workspace: rel/dir\n", out, sizeof(out)));
        (void)snprintf(task, sizeof(task), "muse-workspace: %s/../x\n", ws);
        ASSERT(!zcl_devagent_worker_task_workspace(task, out, sizeof(out)));
        (void)snprintf(task, sizeof(task), "name=n\n\nmuse-workspace: %s\n",
                       ws);
        ASSERT(!zcl_devagent_worker_task_workspace(task, out, sizeof(out)));
        ASSERT(!zcl_devagent_worker_task_workspace("name=n\n", out,
                                                   sizeof(out)));
        ASSERT(!zcl_devagent_worker_task_workspace(NULL, out, sizeof(out)));
        PASS();
    }

    TEST("confine: the child environment is explicit and carries no secret")
    {
        static char store[WKR_ENV_MAX][WKR_ENV_ENTRY_MAX];
        const char *env[WKR_ENV_MAX + 1];
        static char saved_path[8192];
        const char *old_path = getenv("PATH");
        bool had_path = old_path != NULL;
        int n;
        if (had_path)
            (void)snprintf(saved_path, sizeof(saved_path), "%s", old_path);
        setenv("ANTHROPIC_API_KEY", "wtx-secret-anthropic", 1);
        setenv("GITHUB_TOKEN", "wtx-secret-github", 1);
        setenv("PATH", "/usr/bin:/bin", 1);
        n = zcl_devagent_worker_child_env("/run/dir", store, env,
                                          WKR_ENV_MAX);
        unsetenv("ANTHROPIC_API_KEY");
        unsetenv("GITHUB_TOKEN");
        if (had_path)
            setenv("PATH", saved_path, 1);
        else
            unsetenv("PATH");
        ASSERT(n >= 3);
        ASSERT(env[n] == NULL);
        ASSERT(wtx_env_has(env, "PATH=/usr/bin:/bin"));
        ASSERT(wtx_env_has(env, "TEMP=/run/dir"));
        ASSERT(wtx_env_has(env, "TMP=/run/dir"));
        ASSERT(!wtx_env_has(env, "wtx-secret"));
        ASSERT(!wtx_env_has(env, "ANTHROPIC"));
        ASSERT(!wtx_env_has(env, "TOKEN"));
        /* Too little room is an overflow, never a truncated environment. */
        ASSERT_EQ(zcl_devagent_worker_child_env("/run/dir", store, env, 1),
                  -1);
        PASS();
    }
_test_next:;
    return failures;
}
#endif

int test_devagent_worker(void);
int test_devagent_worker(void)
{
    int failures = 0;

#if !defined(_WIN32)
    TEST("lifecycle: post claim fixture gate receipt reap completed")
    {
        struct wkr_drive_opts o;
        char verdict[64];
        long long rc = -1, jobs;
        /* The registry admits the new leaf's keys, ints included, so a
         * shell spelling reaches the handler. */
        struct wtx_call v;
        char why[256];
        wtx_isolate("lifecycle");
        wtx_begin(&v, "dev.agent.worker", "zcl.agent_worker.v1");
        (void)json_push_kv_str(&v.input, "action", "run");
        (void)json_push_kv_str(&v.input, "worker", "wtx");
        (void)json_push_kv_int(&v.input, "max_jobs", 1);
        (void)json_push_kv_int(&v.input, "time_cap_s", 30);
        ASSERT(v.request.spec != NULL);
        ASSERT(zcl_command_registry_input_validate(v.request.spec, &v.input,
                                                   why, sizeof(why)));
        wtx_end(&v);
        wtx_queue_post("wtx-life");
        (void)remove(g_fx_count);
        g_fx_mode = 0;
        (void)snprintf(g_fx_terminal, sizeof(g_fx_terminal), "%s", "pass");
        g_fx_rc = 0;
        g_fx_candidate = true;
        wtx_opts(&o, "wtx", "s-life");
        jobs = zcl_devagent_worker_drive(&o, wtx_fixture);
        ASSERT_EQ(jobs, 1);
        ASSERT_EQ(wtx_count_read(), 1);
        ASSERT(wtx_queue_verb("reap", NULL, NULL));
        ASSERT(wtx_outcome("wtx-life", verdict, sizeof(verdict), &rc));
        ASSERT_STR_EQ(verdict, "pass");
        ASSERT_EQ(rc, 0);
        ASSERT(zcl_devagent_closed_pass(verdict, rc));
        ASSERT(wtx_mail_has("wtx-life", "gate=pass"));
        ASSERT(wtx_mail_has("wtx-life", "candidate=cand.diff"));
        ASSERT(wtx_mail_has("wtx-life", "tokens=42"));
        wtx_restore();
        PASS();
    }

    TEST("completed work is never resubmitted")
    {
        struct wkr_drive_opts o;
        struct wtx_call c;
        wtx_isolate("noresubmit");
        wtx_queue_post("wtx-done");
        (void)remove(g_fx_count);
        g_fx_mode = 0;
        (void)snprintf(g_fx_terminal, sizeof(g_fx_terminal), "%s", "pass");
        g_fx_rc = 0;
        g_fx_candidate = true;
        wtx_opts(&o, "wtx", "s-first");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, wtx_fixture), 1);
        ASSERT(wtx_queue_verb("reap", NULL, NULL));
        /* A restarted worker with a new session finds CLAIM_COMPLETED,
         * never a fresh submission. */
        (void)remove(g_fx_count);
        wtx_opts(&o, "wtx", "s-second");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, wtx_fixture), 0);
        ASSERT_EQ(wtx_count_read(), 0);
        /* Re-post the same name: the finished ref stays finished. */
        wtx_queue_post("wtx-done");
        wtx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
        (void)json_push_kv_str(&c.input, "action", "claim");
        (void)json_push_kv_str(&c.input, "worker", "wtx");
        (void)json_push_kv_str(&c.input, "session", "s-third");
        zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
        ASSERT(!wtx_ok(&c));
        wtx_end(&c);
        wtx_restore();
        PASS();
    }

    TEST("restart after claim adopts the un-submitted orphan once")
    {
        struct wkr_drive_opts o;
        char verdict[64];
        long long rc = -1;
        wtx_isolate("adopt");
        wtx_queue_post("wtx-orphan");
        ASSERT(wtx_queue_verb("claim", NULL, NULL));
        /* New process, new session, same queue: the orphan never
         * submitted, so it runs exactly once. */
        (void)remove(g_fx_count);
        g_fx_mode = 0;
        (void)snprintf(g_fx_terminal, sizeof(g_fx_terminal), "%s", "PASS");
        g_fx_rc = 0;
        g_fx_candidate = true;
        wtx_opts(&o, "wtx", "s-restart");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, wtx_fixture), 1);
        ASSERT_EQ(wtx_count_read(), 1);
        ASSERT(wtx_queue_verb("reap", NULL, NULL));
        ASSERT(wtx_outcome("wtx-orphan", verdict, sizeof(verdict), &rc));
        ASSERT_STR_EQ(verdict, "PASS");
        ASSERT(zcl_devagent_closed_pass(verdict, rc));
        wtx_restore();
        PASS();
    }

    TEST("restart after submit crash-records and never resubmits")
    {
        struct wkr_drive_opts o;
        char verdict[64];
        long long rc = -1;
        wtx_isolate("lostsubmit");
        wtx_queue_post("wtx-lost");
        ASSERT(wtx_queue_verb("claim", NULL, NULL));
        /* The first drive submitted, then died before any receipt. */
        wtx_flip_submitted("wtx-lost", 1, true);
        (void)remove(g_fx_count);
        g_fx_mode = 0;
        (void)snprintf(g_fx_terminal, sizeof(g_fx_terminal), "%s", "pass");
        g_fx_rc = 0;
        g_fx_candidate = true;
        wtx_opts(&o, "wtx", "s-aftercrash");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, wtx_fixture), 1);
        ASSERT_EQ(wtx_count_read(), 0);
        ASSERT(wtx_queue_verb("reap", NULL, NULL));
        ASSERT(wtx_outcome("wtx-lost", verdict, sizeof(verdict), &rc));
        ASSERT_STR_EQ(verdict, "no-receipt");
        ASSERT(!zcl_devagent_closed_pass(verdict, rc));
        /* The row is settled; a further drive finds nothing to redo. */
        (void)remove(g_fx_count);
        wtx_opts(&o, "wtx", "s-later");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, wtx_fixture), 0);
        ASSERT_EQ(wtx_count_read(), 0);
        wtx_restore();
        PASS();
    }

    TEST("queued cancel prevents claim")
    {
        struct wkr_drive_opts o;
        wtx_isolate("cancelq");
        wtx_queue_post("wtx-cancelled");
        ASSERT(wtx_queue_verb("cancel", "name", "wtx-cancelled"));
        (void)remove(g_fx_count);
        g_fx_mode = 0;
        (void)snprintf(g_fx_terminal, sizeof(g_fx_terminal), "%s", "pass");
        g_fx_rc = 0;
        g_fx_candidate = true;
        wtx_opts(&o, "wtx", "s-cancel");
        o.idle_limit_s = 2;
        ASSERT_EQ(zcl_devagent_worker_drive(&o, wtx_fixture), 0);
        ASSERT_EQ(wtx_count_read(), 0);
        wtx_restore();
        PASS();
    }

    TEST("idle worker wakes on a queued row, not on its backoff")
    {
        struct wkr_drive_opts o;
        long long after_post_ms = -1;
        wtx_isolate("wake");
        (void)remove(g_fx_count);
        g_fx_mode = 0;
        (void)snprintf(g_fx_terminal, sizeof(g_fx_terminal), "%s", "pass");
        g_fx_rc = 0;
        g_fx_candidate = true;
        wtx_opts(&o, "wtx", "s-wake");
        /* A 30 s backoff: only the queue watch can claim inside 3 s. */
        o.idle_start_s = 30;
        o.idle_limit_s = 60;
        o.deadline_s = 60;
        ASSERT_EQ(wtx_drive_late_post(&o, "wtx-wake", 1500, &after_post_ms),
                  1);
        ASSERT_EQ(wtx_count_read(), 1);
        (void)printf("    devagent_worker wake latency: %lld ms after post\n",
                     after_post_ms);
        ASSERT(after_post_ms >= 0);
        ASSERT(after_post_ms < 3000);
        wtx_restore();
        PASS();
    }

    TEST("a wake right after a failed claim waits out the one-second floor")
    {
        struct wkr_drive_opts o;
        long long after_post_ms = -1;
        wtx_isolate("floor");
        (void)remove(g_fx_count);
        g_fx_mode = 0;
        (void)snprintf(g_fx_terminal, sizeof(g_fx_terminal), "%s", "pass");
        g_fx_rc = 0;
        g_fx_candidate = true;
        wtx_opts(&o, "wtx", "s-floor");
        o.idle_start_s = 30;
        o.idle_limit_s = 60;
        o.deadline_s = 60;
        /* Posted 0.2 s after the empty claim: the next claim still waits
         * until 1 s after it, then happens at once. */
        ASSERT_EQ(wtx_drive_late_post(&o, "wtx-floor", 200, &after_post_ms),
                  1);
        ASSERT_EQ(wtx_count_read(), 1);
        (void)printf("    devagent_worker floor wake: %lld ms after post\n",
                     after_post_ms);
        ASSERT(after_post_ms >= 700);
        ASSERT(after_post_ms < 2500);
        wtx_restore();
        PASS();
    }

    TEST("without a queue watch the backoff still bounds the idle wait")
    {
        struct wkr_drive_opts o;
        long long after_post_ms = -1;
        wtx_isolate("nowatch");
        (void)remove(g_fx_count);
        g_fx_mode = 0;
        (void)snprintf(g_fx_terminal, sizeof(g_fx_terminal), "%s", "pass");
        g_fx_rc = 0;
        g_fx_candidate = true;
        wtx_opts(&o, "wtx", "s-nowatch");
        o.timed_idle_only = true;
        o.idle_start_s = 2;
        o.idle_limit_s = 4;
        /* Posted at 0.3 s: the timed path must not see it before its 2 s
         * backoff expires, and must claim it right after. */
        ASSERT_EQ(wtx_drive_late_post(&o, "wtx-nowatch", 300, &after_post_ms),
                  1);
        ASSERT_EQ(wtx_count_read(), 1);
        (void)printf("    devagent_worker timed fallback: %lld ms after post\n",
                     after_post_ms);
        ASSERT(after_post_ms >= 1500);
        ASSERT(after_post_ms < 3500);
        wtx_restore();
        PASS();
    }

    TEST("executor crash stays incomplete")
    {
        struct wkr_drive_opts o;
        char verdict[64];
        long long rc = -1;
        wtx_isolate("crash");
        wtx_queue_post("wtx-crash");
        (void)remove(g_fx_count);
        g_fx_mode = 1;
        wtx_opts(&o, "wtx", "s-crash");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, wtx_fixture), 1);
        ASSERT_EQ(wtx_count_read(), 1);
        ASSERT(wtx_queue_verb("reap", NULL, NULL));
        ASSERT(wtx_outcome("wtx-crash", verdict, sizeof(verdict), &rc));
        ASSERT_STR_EQ(verdict, "no-receipt");
        ASSERT(!zcl_devagent_closed_pass(verdict, rc));
        ASSERT(wtx_mail_has("wtx-crash", "terminal=crashed"));
        wtx_restore();
        PASS();
    }

    TEST("model completed is never upgraded to pass")
    {
        struct wkr_drive_opts o;
        char verdict[64];
        long long rc = -1;
        wtx_isolate("noupgrade");
        wtx_queue_post("wtx-completed");
        (void)remove(g_fx_count);
        g_fx_mode = 0;
        (void)snprintf(g_fx_terminal, sizeof(g_fx_terminal), "%s",
                       "completed");
        g_fx_rc = 0;
        g_fx_candidate = true;
        wtx_opts(&o, "wtx", "s-completed");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, wtx_fixture), 1);
        ASSERT(wtx_queue_verb("reap", NULL, NULL));
        ASSERT(wtx_outcome("wtx-completed", verdict, sizeof(verdict), &rc));
        ASSERT_STR_EQ(verdict, "gate-refused");
        ASSERT(!zcl_devagent_closed_pass(verdict, rc));
        wtx_restore();
        PASS();
    }

    TEST("wall cap kills a hung executor, incomplete")
    {
        struct wkr_drive_opts o;
        char verdict[64];
        long long rc = -1;
        wtx_isolate("timeout");
        wtx_queue_post("wtx-hung");
        (void)remove(g_fx_count);
        g_fx_mode = 2;
        wtx_opts(&o, "wtx", "s-hung");
        o.time_cap_s = 2;
        ASSERT_EQ(zcl_devagent_worker_drive(&o, wtx_fixture), 1);
        ASSERT(wtx_queue_verb("reap", NULL, NULL));
        ASSERT(wtx_outcome("wtx-hung", verdict, sizeof(verdict), &rc));
        ASSERT_STR_EQ(verdict, "no-receipt");
        ASSERT(!zcl_devagent_closed_pass(verdict, rc));
        wtx_restore();
        PASS();
    }

    TEST("no executor wired means no run, row untouched")
    {
        struct wkr_drive_opts o;
        struct wtx_call c;
        const struct json_value *arr;
        bool still_running = false;
        size_t n, i;
        wtx_isolate("noseam");
        wtx_queue_post("wtx-seam");
        wtx_opts(&o, "wtx", "s-seam");
        ASSERT_EQ(zcl_devagent_worker_drive(
                      &o, zcl_devagent_worker_no_executor),
                  0);
        /* The claim was adopted but refused at the seam: still running,
         * no receipt, ready for C's adapter. */
        wtx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
        (void)json_push_kv_str(&c.input, "action", "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
        ASSERT(wtx_ok(&c));
        arr = json_get(&c.reply.data, "running");
        if (arr && arr->type == JSON_ARR) {
            n = json_size(arr);
            for (i = 0; i < n; i++) {
                const struct json_value *r = json_at(arr, i);
                const struct json_value *v;
                if (!r || r->type != JSON_OBJ)
                    continue;
                v = json_get(r, "name");
                if (v && v->type == JSON_STR && json_get_str(v) &&
                    strcmp(json_get_str(v), "wtx-seam") == 0)
                    still_running = true;
            }
        }
        wtx_end(&c);
        ASSERT(still_running);
        /* Claim input refuses a bad worker spelling. */
        wtx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
        (void)json_push_kv_str(&c.input, "action", "claim");
        (void)json_push_kv_str(&c.input, "worker", "bad worker!");
        (void)json_push_kv_str(&c.input, "session", "s1");
        zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
        ASSERT(!wtx_ok(&c));
        wtx_end(&c);
        wtx_restore();
        PASS();
    }
    TEST("result mail survives an absolute-path candidate")
    {
        char body[4096];
        ASSERT(wtx_hostile_run("mabs", "wtx-abs", "/etc/passwd", body,
                               sizeof(body)));
        ASSERT(wtx_elided_ok(body, "wtx-abs", "/etc/passwd"));
        /* The gate verdict and the rc still reach the client. */
        ASSERT(strstr(body, "gate=gate-refused\n") != NULL);
        ASSERT(strstr(body, "rc=1\n") != NULL);
        wtx_restore();
        PASS();
    }

    TEST("result mail survives a climbing candidate")
    {
        char body[4096];
        ASSERT(wtx_hostile_run("mclimb", "wtx-climb", "cand/../../out.diff",
                               body, sizeof(body)));
        ASSERT(wtx_elided_ok(body, "wtx-climb", ".."));
        wtx_restore();
        PASS();
    }

    TEST("result mail survives a home-prefixed candidate")
    {
        char body[4096];
        ASSERT(wtx_hostile_run("mhome", "wtx-home", "~/keys.diff", body,
                               sizeof(body)));
        ASSERT(wtx_elided_ok(body, "wtx-home", "~/"));
        wtx_restore();
        PASS();
    }

    TEST("result mail survives a drive-prefixed candidate")
    {
        char body[4096];
        ASSERT(wtx_hostile_run("mdrive", "wtx-drive", "C:/work/cand.diff",
                               body, sizeof(body)));
        ASSERT(wtx_elided_ok(body, "wtx-drive", "C:/"));
        wtx_restore();
        PASS();
    }

    TEST("result mail survives a newline candidate, no forged line")
    {
        char body[4096];
        /* A body-structure attack, not a path: the mail leaf admits this
         * one, so only the safe-shape check keeps the forged key=value
         * line out of the row other code parses. */
        ASSERT(wtx_hostile_run("mline", "wtx-line", "cand\ninjected=1", body,
                               sizeof(body)));
        ASSERT(wtx_elided_ok(body, "wtx-line", "injected=1"));
        wtx_restore();
        PASS();
    }

    TEST("result mail survives a carriage-return candidate")
    {
        char body[4096];
        /* A bare CR is the other half of the line terminator, and a
         * reader that splits on CR as well as LF sees the same forged
         * key=value line an LF would have made. The allowlist excludes
         * it by construction, which is an argument; this is the
         * evidence, and it is what keeps the exclusion from being
         * deleted by someone who only sees the LF case. */
        ASSERT(wtx_hostile_run("mcr", "wtx-cr", "cand\rinjected=1", body,
                               sizeof(body)));
        ASSERT(wtx_elided_ok(body, "wtx-cr", "injected=1"));
        /* The gate verdict and the rc still reach the client. */
        ASSERT(strstr(body, "gate=gate-refused\n") != NULL);
        ASSERT(strstr(body, "rc=1\n") != NULL);
        wtx_restore();
        PASS();
    }

    TEST("result mail survives a CRLF candidate")
    {
        char body[4096];
        /* CR and LF together, the terminator every line-oriented reader
         * agrees on. Proven separately from either byte alone: a check
         * that rejected only the first character of a pair would still
         * pass both single-byte cases. */
        ASSERT(wtx_hostile_run("mcrlf", "wtx-crlf", "cand\r\ninjected=1",
                               body, sizeof(body)));
        ASSERT(wtx_elided_ok(body, "wtx-crlf", "injected=1"));
        ASSERT(strstr(body, "gate=gate-refused\n") != NULL);
        ASSERT(strstr(body, "rc=1\n") != NULL);
        wtx_restore();
        PASS();
    }

    TEST("an oversized candidate cannot cancel the row")
    {
        char body[4096], huge[256];
        size_t k;
        /* Over the grammar's bound, clean charset: a field too wide for
         * the row is elided like any other unsafe one, so it can neither
         * overflow the body nor take the row down with it. */
        for (k = 0; k + 1 < sizeof(huge); k++)
            huge[k] = 'a';
        huge[sizeof(huge) - 1] = '\0';
        ASSERT(wtx_hostile_run("mbig", "wtx-big", huge, body,
                               sizeof(body)));
        ASSERT(strstr(body, "ref=wtx-big\n") != NULL);
        ASSERT(strstr(body, "candidate=" WTX_ELIDED "\n") != NULL);
        ASSERT(strstr(body, "elided=" WTX_ELIDED "\n") != NULL);
        ASSERT(strstr(body, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == NULL);
        /* The verdict and the rc the client came for are still there. */
        ASSERT(strstr(body, "gate=gate-refused\n") != NULL);
        ASSERT(strstr(body, "rc=1\n") != NULL);
        wtx_restore();
        PASS();
    }

    TEST("a well-formed row keeps the byte-exact format")
    {
        struct wkr_drive_opts o;
        char body[4096];
        const char *expect =
            "ref=wtx-exact\nworker=wtx\nsession=s-exact\nmodel=\n"
            "attempt=1\nterminal=pass\ncandidate=cand.diff\ngate=pass\n"
            "rc=0\ntokens=42\nwall_ms=";
        const char *tail;
        size_t k = 0;
        wtx_isolate("mexact");
        wtx_queue_post("wtx-exact");
        (void)remove(g_fx_count);
        g_fx_mode = 0;
        (void)snprintf(g_fx_terminal, sizeof(g_fx_terminal), "%s", "pass");
        g_fx_rc = 0;
        g_fx_candidate = true;
        wtx_opts(&o, "wtx", "s-exact");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, wtx_fixture), 1);
        ASSERT(wtx_mail_body("wtx-exact", body, sizeof(body)));
        /* Other code parses these lines: the safe path adds nothing and
         * moves nothing. Only wall_ms is a measured number. */
        ASSERT(strncmp(body, expect, strlen(expect)) == 0);
        tail = body + strlen(expect);
        while (tail[k] >= '0' && tail[k] <= '9')
            k++;
        ASSERT(k > 0);
        ASSERT_STR_EQ(tail + k, "\n");
        wtx_restore();
        PASS();
    }

    TEST("a refused result post is recorded, never silent")
    {
        char body[4096];
        /* A candidate the safe shape admits but the mail leaf refuses on
         * its own admission rule. The row is lost; the loss is not. */
        ASSERT(!wtx_hostile_run("mrefused", "wtx-refused", "privkey", body,
                                sizeof(body)));
        ASSERT(!wtx_mail_has("wtx-refused", "ref=wtx-refused"));
        ASSERT(wtx_runout_has("wtx-refused", 1, "result-mail-refused="));
        ASSERT(wtx_runout_has("wtx-refused", 1, "MAIL_REFUSED_KEY"));
        /* The outcome row keeps its rc and its evidence. */
        ASSERT(wtx_runout_has("wtx-refused", 1, "rc=1\n"));
        ASSERT(wtx_runout_has("wtx-refused", 1, "fixture receipt"));
        wtx_restore();
        PASS();
    }

    TEST("a brief that fits reaches the executor whole")
    {
        struct wkr_drive_opts o;
        wtx_isolate("briefok");
        ASSERT(wtx_post_brief("wtx-brief-ok", 2000, "BRIEF-TAIL-OK\n"));
        (void)remove(g_fx_count);
        g_fx_mode = 0;
        (void)snprintf(g_fx_terminal, sizeof(g_fx_terminal), "%s", "pass");
        g_fx_rc = 0;
        g_fx_candidate = true;
        wtx_opts(&o, "wtx", "s-briefok");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, wtx_fixture), 1);
        ASSERT_EQ(wtx_count_read(), 1);
        ASSERT(wtx_task_has("name=wtx-brief-ok\n"));
        ASSERT(wtx_task_has("BRIEF-TAIL-OK\n"));
        wtx_restore();
        PASS();
    }

    TEST("a brief that does not fit refuses by name, never runs truncated")
    {
        struct wkr_drive_opts o;
        char verdict[64];
        long long rc = -1;
        wtx_isolate("briefbig");
        /* Inside the 32 KiB read cap, over the 8 KiB task: before the fix
         * the executor ran the head and the tail was silently dropped. */
        ASSERT(wtx_post_brief("wtx-brief-big", 12000, "BRIEF-TAIL-BIG\n"));
        (void)remove(g_fx_count);
        g_fx_mode = 0;
        (void)snprintf(g_fx_terminal, sizeof(g_fx_terminal), "%s", "pass");
        g_fx_rc = 0;
        g_fx_candidate = true;
        wtx_opts(&o, "wtx", "s-briefbig");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, wtx_fixture), 1);
        ASSERT_EQ(wtx_count_read(), 0);
        ASSERT(wtx_runout_has("wtx-brief-big", 1, "brief-too-large"));
        ASSERT(!wtx_receipt_exists("wtx-brief-big", 1));
        ASSERT(wtx_mail_has("wtx-brief-big", "terminal=brief-too-large"));
        ASSERT(!wtx_mail_has("wtx-brief-big", "gate=pass"));
        ASSERT(wtx_queue_verb("reap", NULL, NULL));
        ASSERT(wtx_outcome("wtx-brief-big", verdict, sizeof(verdict), &rc));
        ASSERT_STR_EQ(verdict, "no-receipt");
        ASSERT(!zcl_devagent_closed_pass(verdict, rc));
        wtx_restore();
        PASS();
    }

    TEST("a brief over the read cap refuses by name too")
    {
        struct wkr_drive_opts o;
        wtx_isolate("briefhuge");
        ASSERT(wtx_post_brief("wtx-brief-huge", 40000, "BRIEF-TAIL-HUGE\n"));
        (void)remove(g_fx_count);
        g_fx_mode = 0;
        (void)snprintf(g_fx_terminal, sizeof(g_fx_terminal), "%s", "pass");
        g_fx_rc = 0;
        g_fx_candidate = true;
        wtx_opts(&o, "wtx", "s-briefhuge");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, wtx_fixture), 1);
        ASSERT_EQ(wtx_count_read(), 0);
        ASSERT(wtx_runout_has("wtx-brief-huge", 1, "brief-too-large"));
        ASSERT(!wtx_mail_has("wtx-brief-huge", "gate=pass"));
        wtx_restore();
        PASS();
    }

    failures += wtx_confine_cases();
#endif /* !defined(_WIN32) */

_test_next:;
    wtx_restore();
    if (failures == 0)
        printf("test_devagent_worker: all passed\n");
    else
        printf("test_devagent_worker: %d FAILED\n", failures);
    return failures;
}
