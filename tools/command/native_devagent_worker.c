/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.worker — the resident DEV-ONLY loop that consumes
 *          dev.agent.queue continuously. post/next/reap/status/cancel stay
 *          the only scheduler; this leaf is the caller the queue contract
 *          leaves to the operator: claim ONE job, run the wired executor,
 *          judge it through the required gate, record receipt plus run.out
 *          for the existing reap, and post a result mail row under the SAME
 *          ref. Then repeat until the deadline, the idle limit, or the job
 *          cap.
 *
 * ── CONTRACT ─────────────────────────────────────────────────────────────
 *
 * STANDALONE, DEV-ONLY. This leaf never touches consensus, wallet,
 * deployment, or the canonical node: only the owner-private state root
 * (queue, engine run dirs, mail outbox) plus one worker.lock beside the
 * queue. No yolo, no API fallback, no wallet, no deploy, no push
 * authority anywhere in this file. The model is never polled: the loop
 * waits on local queue files. While idle it blocks on a directory watch of
 * the queue with the doubling backoff as the timeout, so a queued row is
 * claimed within about a second, never faster than one claim attempt per
 * second. Without a watch it sleeps the backoff exactly as before.
 *
 * ONE ACTIVE JOB PER WORKER. worker.lock (flock on POSIX, the platform's
 * owner-private lock file on Windows; non-blocking, held for the whole
 * drive) refuses a second concurrent drive on the same queue. On POSIX the
 * executor runs in a forked child under RLIMIT_CPU/RLIMIT_AS; on Windows
 * it runs in a restricted low-integrity child inside a kill-on-close Job
 * Object carrying the same caps (native_devagent_worker_run.c). Either
 * way a wall-clock watchdog kills it; the parent never blocks past the
 * job cap, and no Windows run happens unless that backend arms.
 *
 * CLAIM BEFORE SUBMISSION. dev.agent.queue claim persists claim.json
 * (submitted:false) before this leaf ever sees the job; the leaf flips it
 * to submitted:true immediately before forking the executor. A restart
 * adopts orphans by that flag: submitted:false with no receipt is safe to
 * run exactly once; submitted:true (or an unreadable claim) with no
 * receipt is crash-recorded and NEVER resubmitted. Finished names are
 * refused by claim itself (CLAIM_COMPLETED).
 *
 * COMPLETION. A model terminal of "completed" is not PASS. The leaf
 * writes receipt verdict "pass" only when the executor's own word is
 * pass/PASS with rc 0 AND the candidate artifact exists AND evidence is
 * present AND tokens fit the cap; everything else keeps its own word
 * (failed, gate-refused, timeout, crashed, no-receipt, limit-exceeded)
 * and stays incomplete under the shared closed predicate. crash and no
 * receipt follow the existing policy: reap records them incomplete, no
 * requeue is invented here. Queued cancel prevents claim (the row is
 * gone); a running row refuses cancel and stays the worker's own
 * shutdown business (SIGTERM finishes nothing new: no new claims, the
 * in-flight job is crash-recorded).
 *
 * WHOLE BRIEFS. A claimed row's brief reaches the executor whole or not
 * at all: one that does not fit the task is refused by name
 * (brief-too-large) before any submission, never cut to its head.
 *
 * EXECUTOR SEAM. wkr_executor_fn is the whole production seam. The leaf
 * wires zcl_devagent_worker_no_executor (always refuses) until operator
 * relay supplies C's muse_session; the drive, gate, limits, receipts,
 * mail, and restart rules do not change when it drops in. Tests wire
 * fixtures through zcl_devagent_worker_drive directly.
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/native_command.h"
#include "command/native_devagent.h"

#include "base/safe_alloc.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/confined_process.h"
#include "platform/directory_watcher.h"
#include "platform/process_lock.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#if !defined(_WIN32)
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/wait.h>
#endif

#define WKR_LEAF "dev.agent.worker"
#define WKR_CLAIM_FILE "claim.json"
#define WKR_RECEIPT_FILE "receipt.json"
#define WKR_RUNOUT_FILE "run.out"
#define WKR_LOCK_FILE "worker.lock"
#define WKR_FILE_CAP (64u * 1024u)
#define WKR_TASK_BRIEF_CAP (32u * 1024u)
/* Named refusals for a claimed row that must never reach the executor.
 * The rc is the one reap records; it never collides with 99-101 below. */
#define WKR_REFUSE_BRIEF_SIZE "brief-too-large"
#define WKR_REFUSE_BRIEF_READ "brief-unreadable"
#define WKR_RC_REFUSED 102
#define WKR_SLICE_NS (25u * 1000u * 1000u)

/* SIGTERM asks for shutdown between jobs; the wait slices also honor it
 * so an in-flight job is crash-recorded instead of orphaned. */
static volatile sig_atomic_t g_wkr_term = 0;

static void wkr_on_term(int sig)
{
    (void)sig;
    g_wkr_term = 1;
}

static void wkr_fail(struct zcl_command_reply *reply, const char *code,
                     const char *phase, const char *msg, const char *evidence)
{
    (void)json_push_kv_str(&reply->data, "leaf", WKR_LEAF);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, phase, false,
                           false, msg, evidence);
    reply->error.human_action_required = true;
}

/* ── sibling sub-dispatch (same in-process shape the CLI takes) ────────── */

struct wkr_sub {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
    /* The sibling handler was INVOKED. It never means the sibling
     * accepted: acceptance is reply.status, which wkr_sub_ok reads. */
    bool ran;
    bool valid;
};

static void wkr_sub_begin(struct wkr_sub *s, const char *schema,
                          const char *sib_path)
{
    json_init(&s->input);
    json_set_object(&s->input);
    memset(&s->request, 0, sizeof(s->request));
    s->request.input = &s->input;
    s->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), sib_path, NULL);
    s->request.view = "normal";
    zcl_command_reply_init(&s->reply, schema);
    s->ran = false;
    s->valid = s->request.spec != NULL;
}

static void wkr_sub_end(struct wkr_sub *s)
{
    zcl_command_reply_free(&s->reply);
    json_free(&s->input);
    s->ran = false;
}

static bool wkr_sub_input(struct wkr_sub *s, const char *text)
{
    struct json_value tmp;
    if (!s || !text)
        return false;
    json_init(&tmp);
    if (!json_read(&tmp, text, strlen(text))) {
        json_free(&tmp);
        return false;
    }
    json_free(&s->input);
    s->input = tmp;
    s->request.input = &s->input;
    return true;
}

static bool wkr_sub_ok(const struct wkr_sub *s)
{
    return s && s->ran && s->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *wkr_sub_str(const struct wkr_sub *s, const char *key)
{
    const struct json_value *v;
    if (!s || !key)
        return "";
    v = json_get(&s->reply.data, key);
    return (v && v->type == JSON_STR) ? json_get_str(v) : "";
}

static long long wkr_sub_int(const struct wkr_sub *s, const char *key,
                             long long dflt)
{
    const struct json_value *v;
    if (!s || !key)
        return dflt;
    v = json_get(&s->reply.data, key);
    if (!v || v->type != JSON_INT)
        return dflt;
    return (long long)json_get_int(v);
}

/* ── state dirs and bounded files ──────────────────────────────────────── */

static bool wkr_state_dir(char *out, size_t cap, const char *leaf)
{
    char root[4096];
    if (!out || cap == 0 || !leaf)
        return false;
    if (!platform_state_root(root, sizeof(root)))
        return false;
    if (snprintf(out, cap, "%s/%s", root, leaf) >= (int)cap)
        return false;
    return true;
}

/* ── reap: settle whatever finished since the last pass ────────────────── */

static void wkr_reap(void)
{
    struct wkr_sub sub;
    wkr_sub_begin(&sub, "zcl.agent_queue.v1", "dev.agent.queue");
    if (!sub.valid) {
        wkr_sub_end(&sub);
        return;
    }
    if (!wkr_sub_input(&sub, "{\"action\":\"reap\"}")) {
        wkr_sub_end(&sub);
        return;
    }
    zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
    sub.ran = true;
    wkr_sub_end(&sub);
}

/* ── claim: take the oldest unfinished row ──────────────────────────────
 * Returns 1 with job filled, 0 when the queue is empty, -1 when claim
 * refuses (completed name, bad input, or a ledger failure). */

static void wkr_fill_job_from_claim(const struct wkr_sub *sub,
                                    const struct wkr_drive_opts *opts,
                                    struct wkr_job *job)
{
    const char *s;
    memset(job, 0, sizeof(*job));
    s = wkr_sub_str(sub, "rundir");
    (void)snprintf(job->rundir, sizeof(job->rundir), "%s", s);
    s = wkr_sub_str(sub, "name");
    (void)snprintf(job->name, sizeof(job->name), "%s", s);
    s = wkr_sub_str(sub, "kind");
    (void)snprintf(job->kind, sizeof(job->kind), "%s", s);
    job->attempt = wkr_sub_int(sub, "attempt", 1);
    job->seq = wkr_sub_int(sub, "seq", 0);
    s = wkr_sub_str(sub, "model");
    if (!s[0])
        s = opts->model;
    (void)snprintf(job->model, sizeof(job->model), "%s", s ? s : "");
    job->token_cap = opts->token_cap;
    job->time_cap_s = opts->time_cap_s;
}

/* The brief a claimed row names, whole, into head. NULL when it loaded;
 * "" when there is no brief file (the degrade case); otherwise the named
 * refusal. A brief is never cut: its head alone is a different job. */
static const char *wkr_brief_load(const char *brief, char *head, size_t cap)
{
    struct stat st;
    if (stat(brief, &st) != 0)
        return "";
    if (st.st_size < 0 || (unsigned long long)st.st_size >= cap)
        return WKR_REFUSE_BRIEF_SIZE;
    if (!zcl_devagent_worker_read_file(brief, head, cap))
        return WKR_REFUSE_BRIEF_READ;
    return NULL;
}

/* Executor-ready text: identity lines plus the WHOLE brief file for
 * doc/file kinds. A missing brief degrades to identity lines only — the
 * executor decides whether that suffices, the gate still judges. A brief
 * that exists but does not fit the task whole empties the task and
 * returns the named refusal: running its head would execute a different
 * job than the one posted, and the gate and receipt would bless it. */
static const char *wkr_compose_task(const struct wkr_sub *sub,
                                    struct wkr_job *job)
{
    const char *brief = wkr_sub_str(sub, "brief");
    const char *why;
    char head[WKR_TASK_BRIEF_CAP];
    size_t used, n;
    int w = snprintf(job->task, sizeof(job->task),
                     "name=%s\nkind=%s\nattempt=%lld\nmodel=%s\n",
                     job->name, job->kind, job->attempt, job->model);
    if (w <= 0 || (size_t)w >= sizeof(job->task)) {
        job->task[0] = '\0';
        return NULL;
    }
    if (!brief[0])
        return NULL;
    why = wkr_brief_load(brief, head, sizeof(head));
    if (why && !why[0])
        return NULL;
    used = strlen(job->task);
    n = why ? 0 : strlen(head);
    if (!why && n >= sizeof(job->task) - used)
        why = WKR_REFUSE_BRIEF_SIZE;
    if (why) {
        job->task[0] = '\0';
        return why;
    }
    memcpy(job->task + used, head, n + 1);
    return NULL;
}

/* Returns 1 with job filled (and *refusal set when the claimed row must
 * be refused rather than run), 0 when the queue is empty, -1 on refusal
 * of the claim itself. */
static int wkr_claim_job(const struct wkr_drive_opts *opts,
                         struct wkr_job *job, const char **refusal)
{
    struct wkr_sub sub;
    char input[512];
    const char *state;
    int rc = -1;
    if (!opts || !job || !refusal)
        return -1;
    *refusal = NULL;
    if (snprintf(input, sizeof(input),
                 "{\"action\":\"claim\",\"worker\":\"%.48s\","
                 "\"session\":\"%.48s\",\"model\":\"%.128s\"}",
                 opts->worker, opts->session, opts->model) >=
        (int)sizeof(input))
        return -1;
    wkr_sub_begin(&sub, "zcl.agent_queue.v1", "dev.agent.queue");
    if (!sub.valid) {
        wkr_sub_end(&sub);
        return -1;
    }
    if (!wkr_sub_input(&sub, input)) {
        wkr_sub_end(&sub);
        return -1;
    }
    zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
    sub.ran = true;
    if (!wkr_sub_ok(&sub)) {
        wkr_sub_end(&sub);
        return -1;
    }
    state = wkr_sub_str(&sub, "state");
    if (strcmp(state, "empty") == 0)
        rc = 0;
    else if (strcmp(state, "running") == 0) {
        wkr_fill_job_from_claim(&sub, opts, job);
        *refusal = wkr_compose_task(&sub, job);
        rc = (job->rundir[0] && job->name[0]) ? 1 : -1;
    }
    wkr_sub_end(&sub);
    return rc;
}

/* ── claim.json: the submitted flag ──────────────────────────────────────
 * -1 unreadable/unparseable (fail closed: never submit), 0 submitted:false
 * (safe to run exactly once), 1 submitted:true (never resubmit). */

static int wkr_claim_submitted(const char *rundir)
{
    char path[4096 + 32], text[2048];
    const char *p;
    if (!rundir)
        return -1;
    if (snprintf(path, sizeof(path), "%s/%s", rundir, WKR_CLAIM_FILE) >=
        (int)sizeof(path))
        return -1;
    if (!zcl_devagent_worker_read_file(path, text, sizeof(text)))
        return -1;
    p = strstr(text, "\"submitted\":");
    if (!p)
        return -1;
    p += strlen("\"submitted\":");
    if (strncmp(p, "true", 4) == 0)
        return 1;
    if (strncmp(p, "false", 5) == 0)
        return 0;
    return -1;
}

/* Flip submitted:false to submitted:true, atomically, immediately before
 * the executor fork. False when the flag is absent (nothing to flip —
 * the caller treats that as un-runnable, never as un-submitted). */
static bool wkr_set_submitted(const char *rundir)
{
    char path[4096 + 32], text[2048];
    const char *hit;
    if (!rundir)
        return false;
    if (snprintf(path, sizeof(path), "%s/%s", rundir, WKR_CLAIM_FILE) >=
        (int)sizeof(path))
        return false;
    if (!zcl_devagent_worker_read_file(path, text, sizeof(text)))
        return false;
    hit = strstr(text, "\"submitted\":false");
    if (!hit)
        return false;
    {
        char out[2048];
        size_t pre = (size_t)(hit - text);
        size_t rest = strlen(hit + strlen("\"submitted\":false"));
        const char *mid = "\"submitted\":true";
        if (pre + strlen(mid) + rest >= sizeof(out))
            return false;
        memcpy(out, text, pre);
        memcpy(out + pre, mid, strlen(mid));
        memcpy(out + pre + strlen(mid), hit + strlen("\"submitted\":false"),
               rest + 1);
        return zcl_devagent_worker_write_atomic(path, out, strlen(out));
    }
}

/* ── adopt: resume an orphaned running row ───────────────────────────────
 * A running worker row with no receipt and no run.out belongs to a dead
 * drive (this drive holds worker.lock, so no other drive can own it).
 * submitted:false runs exactly once; anything else crash-records without
 * ever submitting. Returns 1 with job filled, 0 when no orphan waits. */

static bool wkr_row_is_orphan(const char *rundir)
{
    char path[4096 + 32];
    if (!rundir)
        return false;
    if (snprintf(path, sizeof(path), "%s/%s", rundir, WKR_RECEIPT_FILE) >=
        (int)sizeof(path))
        return false;
    if (zcl_devagent_worker_file_exists(path))
        return false;
    if (snprintf(path, sizeof(path), "%s/%s", rundir, WKR_RUNOUT_FILE) >=
        (int)sizeof(path))
        return false;
    return !zcl_devagent_worker_file_exists(path);
}

static long long wkr_row_attempt(const struct json_value *v)
{
    if (!v || v->type != JSON_INT)
        return 0;
    return (long long)json_get_int(v);
}

/* A worker-owned running row with a usable name and attempt. */
static bool wkr_row_mine(const struct json_value *r, const char **name,
                         long long *attempt)
{
    const struct json_value *v;
    const char *owner;
    if (!r || r->type != JSON_OBJ || !name || !attempt)
        return false;
    v = json_get(r, "pid_or_unit");
    owner = (v && v->type == JSON_STR) ? json_get_str(v) : "";
    if (strncmp(owner, "worker:", 7) != 0)
        return false;
    v = json_get(r, "name");
    *name = (v && v->type == JSON_STR) ? json_get_str(v) : "";
    *attempt = wkr_row_attempt(json_get(r, "attempt"));
    return (*name)[0] != '\0' && *attempt >= 1;
}

static void wkr_adopt_fill(const struct json_value *r, const char *rundir,
                           const char *name, long long attempt,
                           const struct wkr_drive_opts *opts,
                           struct wkr_job *job, int *submitted)
{
    const struct json_value *v = json_get(r, "kind");
    memset(job, 0, sizeof(*job));
    (void)snprintf(job->rundir, sizeof(job->rundir), "%s", rundir);
    (void)snprintf(job->name, sizeof(job->name), "%s", name);
    job->attempt = attempt;
    (void)snprintf(job->kind, sizeof(job->kind), "%s",
                   (v && v->type == JSON_STR) ? json_get_str(v) : "leaf");
    (void)snprintf(job->model, sizeof(job->model), "%s", opts->model);
    job->token_cap = opts->token_cap;
    job->time_cap_s = opts->time_cap_s;
    *submitted = wkr_claim_submitted(rundir);
}

/* One running row examined for adoption: a worker-owned orphan fills
 * the job. Returns 1 adopted, 0 not an orphan. */
static int wkr_adopt_row(const struct json_value *r, const char *enginedir,
                         const struct wkr_drive_opts *opts,
                         struct wkr_job *job, int *submitted)
{
    const char *name = NULL;
    long long attempt = 0;
    char rundir[4096];
    if (!enginedir || !opts || !job || !submitted)
        return 0;
    if (!wkr_row_mine(r, &name, &attempt))
        return 0;
    if (snprintf(rundir, sizeof(rundir), "%s/%s/a%lld", enginedir, name,
                 attempt) >= (int)sizeof(rundir))
        return 0;
    if (!wkr_row_is_orphan(rundir))
        return 0;
    wkr_adopt_fill(r, rundir, name, attempt, opts, job, submitted);
    return 1;
}

static int wkr_adopt_job(const struct wkr_drive_opts *opts,
                         struct wkr_job *job, int *submitted)
{
    struct wkr_sub sub;
    const struct json_value *arr;
    char enginedir[4096];
    size_t n, i;
    int rc = 0;
    if (!opts || !job || !submitted)
        return -1;
    if (!wkr_state_dir(enginedir, sizeof(enginedir), "engine"))
        return -1;
    wkr_sub_begin(&sub, "zcl.agent_queue.v1", "dev.agent.queue");
    if (!sub.valid) {
        wkr_sub_end(&sub);
        return -1;
    }
    if (!wkr_sub_input(&sub, "{\"action\":\"status\",\"json\":true}")) {
        wkr_sub_end(&sub);
        return -1;
    }
    zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
    sub.ran = true;
    if (!wkr_sub_ok(&sub)) {
        wkr_sub_end(&sub);
        return -1;
    }
    arr = json_get(&sub.reply.data, "running");
    if (arr && arr->type == JSON_ARR) {
        n = json_size(arr);
        for (i = 0; i < n && rc == 0; i++)
            rc = wkr_adopt_row(json_at(arr, i), enginedir, opts, job,
                               submitted);
    }
    wkr_sub_end(&sub);
    return rc;
}

/* ── spawn: run the executor bounded ─────────────────────────────────────
 * POSIX: the child takes RLIMIT_CPU/RLIMIT_AS from the shared caps, runs
 * the wired executor, writes executor_result.json, and exits; the parent
 * watches the wall clock in slices and kills past the cap. Windows: the
 * confined backend in native_devagent_worker_run.c does the same under a
 * restricted low-integrity token and a capped kill-on-close job. Both fill
 * the same wkr_spawn_out, which zcl_devagent_worker_outcome maps: 1 ran
 * (result file or not — the caller parses), 0 timed out (killed), -1
 * launch/wait failure. A crashed child is a ran-without-result: no
 * receipt, reap records it incomplete. SIGTERM in flight kills the child
 * and crash-records. */

#if defined(_WIN32)
/* The executor that runs is the one this image's child entry wires (the
 * production entry passes the Muse executor, as the leaf does). */
static struct wkr_spawn_out wkr_spawn(const struct wkr_drive_opts *opts,
                                      const struct wkr_job *job,
                                      wkr_executor_fn exec)
{
    (void)exec;
    return zcl_devagent_worker_spawn_confined(opts, job, &g_wkr_term);
}
#else

/* Child side only: confine, run, record, exit. Never returns. */
static void wkr_child_run(const struct wkr_drive_opts *opts,
                          const struct wkr_job *job, wkr_executor_fn exec)
{
    struct wkr_caps caps;
    struct rlimit rl;
    (void)zcl_devagent_worker_caps(opts, &caps);
    if (caps.cpu_s > 0) {
        rl.rlim_cur = rl.rlim_max = (rlim_t)caps.cpu_s;
        (void)setrlimit(RLIMIT_CPU, &rl);
    }
    if (caps.memory_bytes > 0) {
        rl.rlim_cur = rl.rlim_max = (rlim_t)caps.memory_bytes;
        (void)setrlimit(RLIMIT_AS, &rl);
    }
    _exit(zcl_devagent_worker_child_record(job, exec));
}

/* Parent wait in slices: wall cap, SIGTERM, crash, and exit capture.
 * Seconds through the unclassified platform seam, never a raw syscall. */
static struct wkr_spawn_out wkr_wait_child(pid_t pid, long long cap_s,
                                           long long t0_s)
{
    struct wkr_spawn_out out;
    memset(&out, 0, sizeof(out));
    out.status = -1;
    for (;;) {
        int st = 0;
        pid_t got;
        struct timespec slice;
        long long now_s = platform_time_wall_unix();
        if (g_wkr_term) {
            (void)kill(pid, SIGKILL);
            (void)waitpid(pid, &st, 0);
            out.signaled = true;
            break;
        }
        if (cap_s > 0 && now_s - t0_s >= cap_s) {
            (void)kill(pid, SIGKILL);
            (void)waitpid(pid, &st, 0);
            out.status = 0;
            break;
        }
        got = waitpid(pid, &st, WNOHANG);
        if (got == pid) {
            out.status = 1;
            out.signaled = WIFSIGNALED(st) ? true : false;
            break;
        }
        if (got < 0 && errno != EINTR)
            break;
        slice.tv_sec = 0;
        slice.tv_nsec = WKR_SLICE_NS;
        (void)nanosleep(&slice, NULL);
    }
    out.wall_ms = (platform_time_wall_unix() - t0_s) * 1000LL;
    return out;
}

static struct wkr_spawn_out wkr_spawn(const struct wkr_drive_opts *opts,
                                      const struct wkr_job *job,
                                      wkr_executor_fn exec)
{
    struct wkr_spawn_out out;
    pid_t pid;
    long long t0_s;
    memset(&out, 0, sizeof(out));
    out.status = -1;
    if (!opts || !job || !exec)
        return out;
    t0_s = platform_time_wall_unix();
    pid = fork();
    if (pid < 0)
        return out;
    if (pid == 0)
        wkr_child_run(opts, job, exec);
    out = wkr_wait_child(pid, opts->time_cap_s, t0_s);
    return out;
}
#endif

/* ── finish: run.out always, receipt only on a gated outcome ─────────────
 * run.out carries rc=N for the existing reap scan; receipt.json carries
 * the verdict reap judges. Crash/timeout/no-result write run.out alone,
 * so reap records them incomplete without inventing a verdict. */

static void wkr_write_runout(const struct wkr_job *job, long long rc,
                             const char *note)
{
    char path[4096 + 32], text[4096];
    int w;
    if (!job || !note)
        return;
    if (snprintf(path, sizeof(path), "%s/%s", job->rundir,
                 WKR_RUNOUT_FILE) >= (int)sizeof(path))
        return;
    w = snprintf(text, sizeof(text), "rc=%lld\n%s\n", rc, note);
    if (w <= 0 || (size_t)w >= sizeof(text))
        return;
    (void)zcl_devagent_worker_write_atomic(path, text, (size_t)w);
}

static void wkr_write_receipt(const struct wkr_drive_opts *opts,
                              const struct wkr_job *job, const char *verdict,
                              const struct wkr_result *res)
{
    char path[4096 + 32], text[4096];
    char e_cand[512];
    int w;
    if (!opts || !job || !verdict || !res)
        return;
    if (snprintf(path, sizeof(path), "%s/%s", job->rundir,
                 WKR_RECEIPT_FILE) >= (int)sizeof(path))
        return;
    if (!zcl_devagent_worker_json_escape(res->candidate, e_cand, sizeof(e_cand)))
        return;
    w = snprintf(text, sizeof(text),
                 "{\"verdict\":\"%s\",\"worker\":\"%.48s\","
                 "\"session\":\"%.48s\",\"model\":\"%.128s\","
                 "\"candidate\":\"%s\",\"tokens\":%lld,\"wall_ms\":%lld,"
                 "\"ts\":%lld}\n",
                 verdict, opts->worker, opts->session, job->model, e_cand,
                 res->tokens_used, res->wall_ms,
                 (long long)platform_time_wall_unix());
    if (w <= 0 || (size_t)w >= sizeof(text))
        return;
    (void)zcl_devagent_worker_write_atomic(path, text, (size_t)w);
}

/* ── result mail: the row the originating client sees ────────────────────
 * Result mail under the SAME ref: flat scanner-safe key=value lines, which
 * other code parses. The mail leaf refuses EVERY absolute path in a body —
 * it consults no checkout root and no process cwd — and refuses any
 * path-shaped token carrying a ".." segment. So nothing path-shaped may
 * reach the body, whatever directory it names.
 *
 * What is GUARANTEED after a call:
 *   - the row is emitted. No evidence field can cancel it, because
 *     malformed evidence is exactly when the client needs the row;
 *   - a value that fails the safe shape is replaced by WKR_MAIL_ELIDED and
 *     the substitution is announced on its own line, so an elided field is
 *     never read as an absent one;
 *   - every field is individually bounded; a body that still would not fit
 *     posts the reduced row rather than nothing;
 *   - the leaf's reply is inspected, and a refused post is RECORDED in the
 *     run's own outcome row (run.out) beside the rc, where the operator
 *     and the next attempt's brief already read.
 * What is still best-effort: DELIVERY of the row itself. The leaf may
 * refuse on its own admission rules (a key marker, an IP), and this
 * function neither retries nor reposts. The outcome row remains the
 * authority for the verdict; what changed is that a lost result row is now
 * visible there instead of silent. */

#define WKR_MAIL_ELIDED "unsafe-elided"
#define WKR_MAIL_ELIDED_LINE "elided=" WKR_MAIL_ELIDED "\n"

/* One interpolated value may be carried verbatim when it is empty (an
 * absent field stays absent) or matches zcl_devagent_name_ok — the
 * grammar the queue already admits names under. That grammar rejects
 * every shape the mail leaf refuses: a leading '/' (any '/' at all), a
 * ".." segment, a '~/' prefix, a "C:\" or "C:/" drive prefix, CR/LF, and
 * anything outside its bounded printable alphabet. It is deliberately
 * narrower than the leaf's refusal set: a value that passes here gives
 * the leaf no path-shaped reason to refuse the body. */
static bool wkr_field_safe(const char *v)
{
    if (!v || !v[0])
        return true;
    return zcl_devagent_name_ok(v);
}

/* The value, or the marker in its place. Never returns NULL. */
static const char *wkr_field_carry(const char *v, bool *elided)
{
    if (wkr_field_safe(v))
        return v ? v : "";
    if (elided)
        *elided = true;
    return WKR_MAIL_ELIDED;
}

/* The safe, bounded pieces of one result row. */
struct wkr_mail_row {
    const char *ref;
    const char *worker;
    const char *session;
    const char *model;
    const char *terminal;
    const char *candidate;
    const char *gate;
    bool elided;
};

static void wkr_row_safe(struct wkr_mail_row *row,
                         const struct wkr_drive_opts *opts,
                         const struct wkr_job *job, const char *terminal,
                         const char *candidate, const char *verdict)
{
    memset(row, 0, sizeof(*row));
    row->ref = wkr_field_carry(job->name, &row->elided);
    row->worker = wkr_field_carry(opts->worker, &row->elided);
    row->session = wkr_field_carry(opts->session, &row->elided);
    row->model = wkr_field_carry(job->model, &row->elided);
    row->terminal = wkr_field_carry(terminal, &row->elided);
    row->candidate = wkr_field_carry(candidate, &row->elided);
    row->gate = wkr_field_carry(verdict, &row->elided);
}

/* Post one composed body under ref. True when the mail leaf ACCEPTED it;
 * on anything else code is filled with the refusal the outcome row will
 * carry. The code is COPIED: the reply it comes from does not outlive
 * this call. */
static bool wkr_mail_post(const char *body, const char *ref,
                          const char *worker, char *code, size_t cap)
{
    struct wkr_sub sub;
    char ebody[8192], eref[192], input[9216];
    bool posted;
    (void)snprintf(code, cap, "%s", "encode-failed");
    if (!zcl_devagent_worker_json_escape(body, ebody, sizeof(ebody)) ||
        !zcl_devagent_worker_json_escape(ref, eref, sizeof(eref)))
        return false;
    if (snprintf(input, sizeof(input),
                 "{\"action\":\"post\",\"to\":\"*\",\"kind\":\"result\","
                 "\"body\":\"%s\",\"ref\":\"%s\",\"from\":\"%.48s\"}",
                 ebody, eref, worker) >= (int)sizeof(input))
        return false;
    wkr_sub_begin(&sub, "zcl.agent_mail.v1", "dev.agent.mail");
    if (!sub.valid) {
        (void)snprintf(code, cap, "%s", "mail-leaf-absent");
        wkr_sub_end(&sub);
        return false;
    }
    if (!wkr_sub_input(&sub, input)) {
        (void)snprintf(code, cap, "%s", "post-input-unreadable");
        wkr_sub_end(&sub);
        return false;
    }
    zcl_native_handle_dev_agent_mail(&sub.request, &sub.reply);
    /* ran means the sibling handler was invoked, never that it accepted:
     * acceptance is the reply's own status, which wkr_sub_ok reads. */
    sub.ran = true;
    posted = wkr_sub_ok(&sub);
    if (!posted)
        (void)snprintf(code, cap, "%s",
                       sub.reply.error.code[0] ? sub.reply.error.code
                                               : "mail-refused");
    wkr_sub_end(&sub);
    return posted;
}

/* The row that always fits: the ref the client waits on, the verdict, the
 * rc, and the marker saying the rest was dropped to get it out. Bounding
 * every field to the shared name grammar makes the full row always fit, so
 * this is a fail-safe, not a routine path: it is what keeps a body that
 * somehow will not compose from cancelling the result. */
static bool wkr_mail_reduced(const char *ref, const char *gate, long long rc,
                             const char *postref, const char *worker,
                             char *code, size_t cap)
{
    char body[512];
    int w = snprintf(body, sizeof(body),
                     "ref=%.64s\ngate=%.64s\nrc=%lld\nreduced=1\n", ref,
                     gate, rc);
    if (w <= 0 || (size_t)w >= sizeof(body)) {
        (void)snprintf(code, cap, "%s", "reduced-compose-failed");
        return false;
    }
    return wkr_mail_post(body, postref, worker, code, cap);
}

/* Record a lost result row where the operator and the next attempt's
 * brief already read: the run's own outcome row, rc unchanged, the
 * evidence note kept and the refusal appended to it. */
static void wkr_mail_note_refusal(const struct wkr_job *job, long long rc,
                                  const char *note, const char *code)
{
    char full[3400];
    (void)snprintf(full, sizeof(full), "%.3000s result-mail-refused=%.64s",
                   note ? note : "", code ? code : "mail-refused");
    wkr_write_runout(job, rc, full);
}

static void wkr_mail_result(const struct wkr_drive_opts *opts,
                            const struct wkr_job *job, const char *terminal,
                            const char *candidate, const char *verdict,
                            long long rc, long long tokens, long long wall_ms,
                            const char *note)
{
    struct wkr_mail_row row;
    char body[2048], code[80];
    bool posted;
    int w;
    if (!opts || !job || !terminal || !verdict)
        return;
    if (!candidate)
        candidate = "";
    (void)snprintf(code, sizeof(code), "%s", "mail-refused");
    wkr_row_safe(&row, opts, job, terminal, candidate, verdict);
    w = snprintf(body, sizeof(body),
                 "ref=%.64s\nworker=%.64s\nsession=%.64s\nmodel=%.64s\n"
                 "attempt=%lld\nterminal=%.64s\ncandidate=%.64s\n"
                 "gate=%.64s\nrc=%lld\ntokens=%lld\nwall_ms=%lld\n%s",
                 row.ref, row.worker, row.session, row.model, job->attempt,
                 row.terminal, row.candidate, row.gate, rc, tokens, wall_ms,
                 row.elided ? WKR_MAIL_ELIDED_LINE : "");
    if (w <= 0 || (size_t)w >= sizeof(body))
        posted = wkr_mail_reduced(row.ref, row.gate, rc, job->name,
                                  opts->worker, code, sizeof(code));
    else
        posted = wkr_mail_post(body, job->name, opts->worker, code,
                               sizeof(code));
    if (!posted)
        wkr_mail_note_refusal(job, rc, note, code);
}

/* ── run one job ─────────────────────────────────────────────────────────
 * fresh: flip submitted pre-fork, spawn, gate, finish, mail. adopted
 * with submitted!=false: crash-record without ever submitting. Returns
 * 1 processed, 0 when there was no executor to run. */

static long long wkr_run_fresh(const struct wkr_drive_opts *opts,
                               const struct wkr_job *job,
                               wkr_executor_fn exec)
{
    struct wkr_spawn_out out;
    struct wkr_outcome oc;
    struct wkr_result res;
    char verdict[32];
    long long rc;
    if (!wkr_set_submitted(job->rundir)) {
        wkr_write_runout(job, 101, "claim-identity-unwritable");
        wkr_mail_result(opts, job, "claim-identity-unwritable", "",
                        "no-receipt", 101, 0, 0,
                        "claim-identity-unwritable");
        return 1;
    }
    out = wkr_spawn(opts, job, exec);
    zcl_devagent_worker_outcome(&out, g_wkr_term != 0, &oc);
    if (oc.gate && !zcl_devagent_worker_parse_result(job->rundir, &res)) {
        oc.gate = false;
        oc.rc = 100;
        oc.terminal = "no-result";
        oc.note = "executor-no-result";
    }
    if (!oc.gate) {
        wkr_write_runout(job, oc.rc, oc.note);
        wkr_mail_result(opts, job, oc.terminal, "", "no-receipt", oc.rc, 0,
                        out.wall_ms, oc.note);
        return 1;
    }
    res.wall_ms = out.wall_ms;
    rc = zcl_devagent_worker_gate(job, &res, verdict, sizeof(verdict));
    wkr_write_runout(job, rc, res.evidence);
    wkr_write_receipt(opts, job, verdict, &res);
    wkr_mail_result(opts, job, res.terminal, res.candidate, verdict, rc,
                    res.tokens_used, res.wall_ms, res.evidence);
    return 1;
}

static long long wkr_run_job(const struct wkr_drive_opts *opts,
                             const struct wkr_job *job,
                             wkr_executor_fn exec, bool adopted,
                             int submitted)
{
    if (!opts || !job || !exec)
        return 0;
    if (adopted && submitted != 0) {
        /* A previous drive submitted (or the claim is unreadable): the
         * model may already have run, so never submit again. Record
         * the loss; reap marks it incomplete. */
        wkr_write_runout(job, 99, "worker-lost-after-submit");
        wkr_mail_result(opts, job, "worker-lost-after-submit", "",
                        "no-receipt", 99, 0, 0,
                        "worker-lost-after-submit");
        return 1;
    }
    /* Fresh claims arrive submitted:false; adoptions with submitted==0
     * are proven un-submitted. The production stub refuses here so no
     * job runs without C's adapter wired. */
    if (exec == zcl_devagent_worker_no_executor)
        return 0;
    return wkr_run_fresh(opts, job, exec);
}

/* A claimed row that must never reach the executor: the refusal is named
 * in run.out, where reap records it as an incomplete outcome, and in the
 * result row the client reads. Nothing was submitted. */
static long long wkr_refuse_job(const struct wkr_drive_opts *opts,
                                const struct wkr_job *job, const char *why)
{
    wkr_write_runout(job, WKR_RC_REFUSED, why);
    wkr_mail_result(opts, job, why, "", "no-receipt", WKR_RC_REFUSED, 0, 0,
                    why);
    return 1;
}

bool zcl_devagent_worker_no_executor(const struct wkr_job *job,
                                     struct wkr_result *res)
{
    (void)job;
    (void)res;
    return false;
}

/* ── idle: wake on the queue, the backoff is only the ceiling ──────────────
 * The drive arms one directory watch on the queue dir for its lifetime.
 * The queue.jsonl identity taken after reap and before the claim is the
 * baseline: a watch event wakes the worker only when the ledger differs
 * from it, so the worker's own lock-file and reap writes never wake it and
 * a row posted after the claim looked is never missed. A real wake still
 * waits out WKR_CLAIM_FLOOR_MS since the failed claim. A watch that cannot
 * be armed, or that errors, falls back to sleeping the backoff. */

#define WKR_CLAIM_FLOOR_MS 1000
#define WKR_IDLE_SLICE_MS 100

struct wkr_qsig {
    long long size;
    long long mtime;
    long long ino;
    bool present;
};

struct wkr_idle {
    struct platform_directory_watcher watcher;
    bool watching;
    char queuedir[4096];
    struct wkr_qsig base;
};

static void wkr_qsig_take(const char *queuedir, struct wkr_qsig *sig)
{
    char path[4096 + 32];
    struct stat st;
    memset(sig, 0, sizeof(*sig));
    if (snprintf(path, sizeof(path), "%s/queue.jsonl", queuedir) >=
        (int)sizeof(path))
        return;
    if (stat(path, &st) != 0)
        return;
    sig->present = true;
    sig->size = (long long)st.st_size;
    sig->mtime = (long long)st.st_mtime;
    sig->ino = (long long)st.st_ino;
}

static bool wkr_qsig_moved(const struct wkr_idle *idle)
{
    struct wkr_qsig now;
    wkr_qsig_take(idle->queuedir, &now);
    return now.present != idle->base.present ||
           now.size != idle->base.size || now.mtime != idle->base.mtime ||
           now.ino != idle->base.ino;
}

static bool wkr_stop_asked(void *opaque)
{
    (void)opaque;
    return g_wkr_term != 0;
}

/* Milliseconds from now until `until_ms` on the monotonic clock, >= 0. */
static long long wkr_ms_left(long long until_ms)
{
    long long left = until_ms - (long long)platform_time_monotonic_ms();
    return left > 0 ? left : 0;
}

/* Sleep until `until_ms` on the monotonic clock, in term-aware slices. */
static void wkr_idle_sleep_until(long long until_ms)
{
    long long left = wkr_ms_left(until_ms);
    while (!g_wkr_term && left > 0) {
        platform_sleep_ms(
            (int)(left < WKR_IDLE_SLICE_MS ? left : WKR_IDLE_SLICE_MS));
        left = wkr_ms_left(until_ms);
    }
}

static void wkr_idle_open(struct wkr_idle *idle, const char *queuedir,
                          bool timed_only)
{
    platform_directory_watcher_init(&idle->watcher);
    (void)snprintf(idle->queuedir, sizeof(idle->queuedir), "%s", queuedir);
    memset(&idle->base, 0, sizeof(idle->base));
    idle->watching = !timed_only && platform_directory_watcher_open(
                                        &idle->watcher, idle->queuedir);
}

static void wkr_idle_close(struct wkr_idle *idle)
{
    if (idle->watching)
        platform_directory_watcher_close(&idle->watcher);
    idle->watching = false;
}

/* Block for at most wait_ms. True when the queue ledger changed and a
 * claim is worth trying (the claim floor already honoured); false on
 * timeout or shutdown. */
static bool wkr_idle_wait(struct wkr_idle *idle, long long wait_ms)
{
    long long t0 = (long long)platform_time_monotonic_ms();
    long long left = wait_ms;
    while (!g_wkr_term && left > 0) {
        enum platform_directory_watch_result r;
        if (!idle->watching) {
            wkr_idle_sleep_until(t0 + wait_ms);
            return false;
        }
        r = platform_directory_watcher_wait(&idle->watcher, (uint32_t)left,
                                            wkr_stop_asked, NULL);
        if (r == PLATFORM_DIRECTORY_WATCH_ERROR)
            wkr_idle_close(idle);
        else if (r != PLATFORM_DIRECTORY_WATCH_CHANGED &&
                 r != PLATFORM_DIRECTORY_WATCH_OVERFLOW)
            return false;
        else if (wkr_qsig_moved(idle)) {
            wkr_idle_sleep_until(t0 + WKR_CLAIM_FLOOR_MS);
            return !g_wkr_term;
        }
        left = wkr_ms_left(t0 + wait_ms);
    }
    return false;
}

/* Bounded idle. A timeout doubles the backoff up to the idle limit; a
 * wake keeps it, so an unclaimable change never shortens later waits.
 * True when the idle streak hit the limit and the drive should stop. */
static bool wkr_drive_idle(const struct wkr_drive_opts *opts,
                           struct wkr_idle *idle, long long *idle_ms,
                           long long *wait_s)
{
    long long t0;
    bool woke;
    if (!opts || !idle || !idle_ms || !wait_s)
        return true;
    t0 = (long long)platform_time_monotonic_ms();
    woke = wkr_idle_wait(idle, *wait_s * 1000);
    *idle_ms += (long long)platform_time_monotonic_ms() - t0;
    if (*idle_ms >= opts->idle_limit_s * 1000)
        return true;
    if (!woke)
        *wait_s *= 2;
    if (*wait_s > opts->idle_limit_s)
        *wait_s = opts->idle_limit_s;
    if (*wait_s < 1)
        *wait_s = 1;
    return false;
}

/* One drive step: at most one adoption or claim and its run. Returns
 * jobs processed (0 when the queue is empty). The loop reaps first. */
static long long wkr_drive_step(const struct wkr_drive_opts *opts,
                                wkr_executor_fn exec)
{
    struct wkr_job job;
    const char *refusal = NULL;
    int submitted = 0;
    int got;
    if (!opts || !exec)
        return 0;
    got = wkr_adopt_job(opts, &job, &submitted);
    if (got < 0)
        got = 0;
    if (got == 1)
        return wkr_run_job(opts, &job, exec, true, submitted);
    if (wkr_claim_job(opts, &job, &refusal) != 1)
        return 0;
    if (refusal)
        return wkr_refuse_job(opts, &job, refusal);
    return wkr_run_job(opts, &job, exec, false, 0);
}

/* ── drive ─────────────────────────────────────────────────────────────── */

/* worker.lock: one drive per queue, held for the whole drive. POSIX takes
 * a non-blocking flock; Windows takes the platform's retained,
 * owner-private, non-blocking lock file. Both release on process death. */
struct wkr_lock {
    int fd;
#if defined(_WIN32)
    struct platform_process_lock plock;
#endif
};

static bool wkr_lock_take(struct wkr_lock *lk, const char *path)
{
    lk->fd = -1;
#if defined(_WIN32)
    platform_process_lock_init(&lk->plock);
    return platform_process_lock_try_acquire(&lk->plock, path, true);
#else
    lk->fd = open(path, O_CREAT | O_RDWR, 0600);
    if (lk->fd < 0)
        return false;
    if (flock(lk->fd, LOCK_EX | LOCK_NB) != 0) {
        (void)close(lk->fd);
        lk->fd = -1;
        return false;
    }
    return true;
#endif
}

static void wkr_lock_drop(struct wkr_lock *lk)
{
#if defined(_WIN32)
    platform_process_lock_release(&lk->plock);
#else
    (void)flock(lk->fd, LOCK_UN);
    (void)close(lk->fd);
    lk->fd = -1;
#endif
}

long long zcl_devagent_worker_drive(const struct wkr_drive_opts *opts,
                                    wkr_executor_fn exec)
{
    char queuedir[4096], lockpath[4096 + 32];
    void (*old_term)(int) = SIG_DFL;
    struct wkr_lock lock;
    struct wkr_idle idle;
    long long t0_s;
    long long jobs = 0, idle_ms = 0, wait_s;
    if (!opts || !exec)
        return -1;
    if (!wkr_state_dir(queuedir, sizeof(queuedir), "queue"))
        return -1;
    if (snprintf(lockpath, sizeof(lockpath), "%s/%s", queuedir,
                 WKR_LOCK_FILE) >= (int)sizeof(lockpath))
        return -1;
    if (!wkr_lock_take(&lock, lockpath))
        return -1;
    old_term = signal(SIGTERM, wkr_on_term);
    wkr_idle_open(&idle, queuedir, opts->timed_idle_only);
    t0_s = platform_time_wall_unix();
    wait_s = opts->idle_start_s > 0 ? opts->idle_start_s : 1;
    while (!g_wkr_term) {
        long long done;
        if (platform_time_wall_unix() - t0_s >= opts->deadline_s)
            break;
        if (opts->max_jobs > 0 && jobs >= opts->max_jobs)
            break;
        wkr_reap();
        wkr_qsig_take(queuedir, &idle.base);
        /* A refused seam processes nothing: idle instead of re-adopting
         * the same orphan in a tight loop. */
        done = wkr_drive_step(opts, exec);
        jobs += done;
        if (done > 0) {
            idle_ms = 0;
            wait_s = opts->idle_start_s > 0 ? opts->idle_start_s : 1;
            continue;
        }
        if (wkr_drive_idle(opts, &idle, &idle_ms, &wait_s))
            break;
    }
    wkr_idle_close(&idle);
    (void)signal(SIGTERM, old_term);
    wkr_lock_drop(&lock);
    return jobs;
}

/* ── leaf ──────────────────────────────────────────────────────────────── */

static long long wkr_leaf_int(const struct zcl_command_request *req,
                              const char *key, long long dflt, long long lo,
                              long long hi)
{
    const struct json_value *v;
    long long n;
    if (!req || !req->input || !key)
        return dflt;
    v = json_get(req->input, key);
    if (!v || v->type != JSON_INT)
        return dflt;
    n = (long long)json_get_int(v);
    if (n < lo)
        return lo;
    if (n > hi)
        return hi;
    return n;
}

static const char *wkr_leaf_str(const struct zcl_command_request *req,
                                const char *key)
{
    const struct json_value *v;
    if (!req || !req->input || !key)
        return "";
    v = json_get(req->input, key);
    return (v && v->type == JSON_STR) ? json_get_str(v) : "";
}

/* Parse the run input into opts. NULL on success, else the refusal
 * message (the evidence names the offending input). */
static const char *wkr_leaf_opts(const struct zcl_command_request *request,
                                 struct wkr_drive_opts *opts,
                                 const char **evidence)
{
    const char *worker, *session;
    char sess_default[56];
    *evidence = "request.input was missing";
    if (!request || !request->input)
        return "dev.agent.worker run needs a worker identity";
    *evidence = "input.action missing or unknown";
    if (strcmp(wkr_leaf_str(request, "action"), "run") != 0)
        return "action is exactly run";
    worker = wkr_leaf_str(request, "worker");
    *evidence = "input.worker missing or too long";
    if (!worker[0] || strlen(worker) > 48)
        return "worker names the resident worker, 1-48 characters";
    memset(opts, 0, sizeof(*opts));
    session = wkr_leaf_str(request, "session");
    if (!session[0]) {
        (void)snprintf(sess_default, sizeof(sess_default), "s%lld-%ld",
                       (long long)platform_time_wall_unix(),
                       (long)getpid());
        session = sess_default;
    }
    *evidence = "input.session too long";
    if (strlen(session) > (sizeof(opts->session) - 1))
        return "session names this worker run, at most 55 characters";
    (void)snprintf(opts->worker, sizeof(opts->worker), "%s", worker);
    (void)snprintf(opts->session, sizeof(opts->session), "%s", session);
    (void)snprintf(opts->model, sizeof(opts->model), "%s",
                   wkr_leaf_str(request, "model"));
    opts->deadline_s = wkr_leaf_int(request, "deadline_s", 300, 1, 3600);
    opts->idle_start_s = wkr_leaf_int(request, "idle_start_s", 1, 1, 30);
    opts->idle_limit_s = wkr_leaf_int(request, "idle_limit_s", 60, 1, 600);
    opts->max_jobs = wkr_leaf_int(request, "max_jobs", 0, 0, 1000);
    opts->time_cap_s = wkr_leaf_int(request, "time_cap_s", 600, 1, 3600);
    opts->cpu_s = wkr_leaf_int(request, "cpu_s", 600, 1, 3600);
    opts->mem_mb = wkr_leaf_int(request, "mem_mb", 1024, 64, 8192);
    opts->token_cap = wkr_leaf_int(request, "token_cap", 32000, 1, 1000000);
    return NULL;
}

/* The run's confinement backend, or false with the refusal filled. POSIX
 * forks under rlimits and is always available; Windows runs only when its
 * confinement backend arms on this host, and otherwise names the missing
 * capability — it never runs an executor unconfined. */
static bool wkr_backend_armed(struct zcl_command_reply *reply)
{
#if defined(_WIN32)
    enum platform_confine_missing m = platform_confined_probe();
    char evidence[96];
    if (m == PLATFORM_CONFINE_ARMED)
        return true;
    (void)snprintf(evidence, sizeof(evidence), "missing=%s",
                   platform_confine_missing_name(m));
    wkr_fail(reply, "WORKER_CONFINEMENT_UNAVAILABLE", "run",
             "dev.agent.worker on Windows runs only inside its confinement "
             "backend, which cannot arm on this host",
             evidence);
    return false;
#else
    (void)reply;
    return true;
#endif
}

void zcl_native_handle_dev_agent_worker(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct wkr_drive_opts opts;
    const char *refusal, *evidence = "";
    long long jobs;
    if (!reply)
        return;
    refusal = wkr_leaf_opts(request, &opts, &evidence);
    if (refusal) {
        wkr_fail(reply, "BAD_INPUT", "run", refusal, evidence);
        return;
    }
    if (!wkr_backend_armed(reply))
        return;
    jobs = zcl_devagent_worker_drive(&opts,
                                     zcl_devagent_worker_muse_executor);
    if (jobs < 0) {
        wkr_fail(reply, "WORKER_BUSY", "run",
                 "another worker holds this queue, or the state root refuses",
                 "worker.lock exclusive");
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", WKR_LEAF);
    (void)json_push_kv_str(&reply->data, "state", "done");
    (void)json_push_kv_int(&reply->data, "jobs", jobs);
    (void)json_push_kv_str(&reply->data, "worker", opts.worker);
    (void)json_push_kv_str(&reply->data, "session", opts.session);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}
