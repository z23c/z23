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
 * executor runs in a forked child under RLIMIT_CPU/RLIMIT_DATA; on Windows
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
 * present AND tokens fit the cap AND — for file kinds — the row's own
 * test group passes right now through the shared run seam; everything
 * else keeps its own word (failed, gate-refused, timeout, crashed,
 * cancelled, no-receipt, limit-exceeded) and stays incomplete under the
 * shared closed predicate. Crash and no receipt follow the existing
 * policy: reap records them incomplete, no requeue is invented here.
 * Queued cancel prevents claim (the row is gone); a running row refuses
 * cancel and stays the worker's own shutdown business (SIGTERM finishes
 * nothing new: no new claims, and the in-flight job gets an explicit
 * cancelled receipt — a named non-PASS rather than an ambiguity, while a
 * genuine crash still leaves none). A gated run whose receipt cannot be
 * written fails as receipt-unwritable and never mails a pass.
 *
 * PROVENANCE. Every result record carries the executor's provider, the
 * turns it took, the command it ran, the source it touched and the diff
 * it produced, from the child's record through receipt.json to the flat
 * result mail row. receipt.json keeps those bytes exactly; the mail copy
 * is bound by the shared name grammar and announces anything it cannot
 * carry as elided, so a path-shaped value never costs the client its row.
 *
 * WHOLE BRIEFS. A claimed row's brief reaches the executor whole or not
 * at all: one that does not fit the task is refused by name
 * (brief-too-large) before any submission, never cut to its head.
 *
 * PRE-SPEND GUARDS. After claim and before the submitted flip and the
 * executor fork, the worker re-verifies the sender authority the
 * receiver's per-ref .evidence record names (binding plus expiry against
 * the live grant store, peer grant for board-carried rows) and
 * re-observes the brief's workspace (HEAD moved or dirty refuses).
 * Either refuses through the existing refusal vocabulary below; missing
 * evidence fails closed. The grant store is only ever read.
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
#include "command/native_fleet.h"
#include "fleet_enrol.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/confined_process.h"
#include "platform/directory_compat.h"
#include "platform/directory_watcher.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/rng.h"
#include "platform/process_lock.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#include "platform/windows_path.h"
#include "sha3/sha3.h"
#include "util/log_macros.h"

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
#include <sys/wait.h>
#endif

#define WKR_LEAF "dev.agent.worker"
#define WKR_CLAIM_FILE "claim.json"
#define WKR_RECEIPT_FILE "receipt.json"
#define WKR_RUNOUT_FILE "run.out"
#define WKR_LOCK_FILE "worker.lock"
#define WKR_FILE_CAP (64u * 1024u)
/* External group run: the job's own wall cap when it has one, else ten
 * minutes, and never more than an hour whatever the row asked for. */
#define WKR_GROUP_MS_DFLT 600000LL
#define WKR_GROUP_MS_MAX 3600000LL
#define WKR_TASK_BRIEF_CAP (32u * 1024u)
/* Named refusals for a claimed row that must never reach the executor.
 * The rc is the one reap records; it never collides with 99-101 below. */
#define WKR_REFUSE_BRIEF_SIZE "brief-too-large"
#define WKR_REFUSE_BRIEF_READ "brief-unreadable"
#define WKR_REFUSE_BRIEF_PATH "brief-outside-roots"
/* Pre-spend refusals: dead or unreadable sender authority, or a workspace
 * that moved or dirtied between admission and execution. They ride the
 * SAME refusal path as the brief refusals above (run.out rc 102 plus a
 * no-receipt result row for reap to record) — no new queue state, no new
 * outcome vocabulary. Nothing was submitted and nothing forked. */
#define WKR_REFUSE_AUTHORITY "authority-ungranted"
#define WKR_REFUSE_AUTHORITY_READ "authority-unreadable"
#define WKR_REFUSE_WS_DIRTY "workspace-dirty"
#define WKR_REFUSE_WS_MOVED "workspace-moved"
/* The grant scope the worker re-verifies: the same "send" scope the
 * receiver admitted under, never a second permission system. */
#define WKR_SEND_SCOPE "send"
#define WKR_RC_REFUSED 102
/* A gated run whose receipt could not be written fails with this rc. */
#define WKR_RECEIPT_UNWRITABLE "receipt-unwritable"
#define WKR_RC_NO_RECEIPT 103
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
    s = wkr_sub_str(sub, "group");
    (void)snprintf(job->group, sizeof(job->group), "%s", s);
    job->attempt = wkr_sub_int(sub, "attempt", 1);
    job->seq = wkr_sub_int(sub, "seq", 0);
    s = wkr_sub_str(sub, "model");
    if (!s[0])
        s = opts->model;
    (void)snprintf(job->model, sizeof(job->model), "%s", s ? s : "");
    job->token_cap = opts->token_cap;
    job->time_cap_s = opts->time_cap_s;
}

#if defined(_WIN32)
static bool wkr_brief_missing_parent(const wchar_t *wide)
{
    wchar_t full[32768];
    DWORD n = GetFullPathNameW(wide, 32768, full, NULL);
    if (!n || n >= 32768) return false;
    for (;;) {
        DWORD attrs = GetFileAttributesW(full);
        if (attrs != INVALID_FILE_ATTRIBUTES)
            return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
        DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND &&
            error != ERROR_PATH_NOT_FOUND)
            return false;
        wchar_t *slash = wcsrchr(full, L'\\');
        if (!slash || slash == full) return false;
        if (slash[-1] == L':') {
            slash[1] = L'\0';
            attrs = GetFileAttributesW(full);
            return attrs != INVALID_FILE_ATTRIBUTES &&
                   (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
        }
        *slash = L'\0';
    }
}
#endif

static bool wkr_brief_resolve(const char *brief, char out[PATH_MAX])
{
    out[0] = '\0';
#if defined(_WIN32)
    wchar_t wide[32768];
    struct platform_positioned_file file;
    if (!platform_windows_wide_path(brief, wide)) {
        errno = EINVAL;
        return false;
    }
    HANDLE handle = CreateFileW(wide, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        errno = (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) &&
            wkr_brief_missing_parent(wide)
            ? ENOENT : EIO;
        return false;
    }
    platform_positioned_file_init(&file);
    file.native = (uintptr_t)handle;
    bool ok = platform_positioned_file_path(&file, out, PATH_MAX);
    platform_positioned_file_close(&file);
    if (!ok) {
        out[0] = '\0';
        errno = EIO;
    }
    return ok;
#else
    return realpath(brief, out) != NULL;
#endif
}

static bool wkr_brief_under(const char *path, const char *root)
{
    size_t n = strlen(root);
    return n && strncmp(path, root, n) == 0 && (path[n] == '/' || path[n] == '\0'
#if defined(_WIN32)
           || path[n] == '\\'
#endif
        );
}
static bool wkr_brief_allowed(const char *path)
{
    char root[PATH_MAX], canonical[PATH_MAX];
    if (zcl_devagent_checkout_root(".", root, sizeof(root)) &&
        platform_directory_canonical_real(root, canonical, sizeof(canonical)) &&
        wkr_brief_under(path, canonical))
        return true;
    return platform_state_root_existing(root, sizeof(root)) &&
           platform_directory_canonical_real(root, canonical, sizeof(canonical)) &&
           wkr_brief_under(path, canonical);
}

/* The brief a claimed row names, whole, into head. NULL when it loaded;
 * "" when there is no brief file (the degrade case); otherwise the named
 * refusal. A brief is never cut: its head alone is a different job. */
static const char *wkr_brief_load(const char *brief, char *head, size_t cap)
{
#if defined(_WIN32)
    struct _stat64 st;
    wchar_t wide[32768];
#else
    struct stat st;
#endif
    char resolved[PATH_MAX];
    if (cap > 0) head[0] = '\0';
    if (!wkr_brief_resolve(brief, resolved))
        return errno == ENOENT ? "" : WKR_REFUSE_BRIEF_READ;
    if (!wkr_brief_allowed(resolved))
        return WKR_REFUSE_BRIEF_PATH;
    brief = resolved;
#if defined(_WIN32)
    if (!platform_windows_wide_path(brief, wide))
        return WKR_REFUSE_BRIEF_READ;
    if (_wstat64(wide, &st) != 0)
#else
    if (stat(brief, &st) != 0)
#endif
        return errno == ENOENT ? "" : WKR_REFUSE_BRIEF_READ;
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

#ifdef ZCL_TESTING
const char *zcl_devagent_worker_test_compose_task(const char *brief,
                                                struct wkr_job *job)
{
    struct wkr_sub sub = {0};
    json_set_object(&sub.reply.data);
    if (!json_push_kv_str(&sub.reply.data, "brief", brief)) {
        json_free(&sub.reply.data);
        job->task[0] = '\0';
        return WKR_REFUSE_BRIEF_READ;
    }
    const char *why = wkr_compose_task(&sub, job);
    json_free(&sub.reply.data);
    return why;
}
#endif

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
    return (*name)[0] != 0 && *attempt >= 1 &&
           wkr_row_attempt(json_get(r, "seq")) >= 1;
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
    job->seq = wkr_row_attempt(json_get(r, "seq"));
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
 * POSIX: the child takes RLIMIT_CPU/RLIMIT_DATA from the shared caps, runs
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
    (void)zcl_devagent_worker_caps(opts, &caps);
    zcl_devagent_worker_confine(&caps);
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
            /* The child ran and was reaped here, so this is status 1 (a
             * wait that was observed), not the -1 of a wait that never
             * happened. Leaving it -1 reported an operator shutdown as a
             * launch failure and hid the cancel from the outcome mapping. */
            (void)kill(pid, SIGKILL);
            (void)waitpid(pid, &st, 0);
            out.status = 1;
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
    const char *refusal = zcl_devagent_worker_memory_ceiling_refusal();
    if (refusal) {
        /* Typed refusal: never run an executor with no heap ceiling. */
        LOG_ERROR("devagent_worker", "launch refused: %s", refusal);
        return out;
    }
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

/* The receipt reap judges. False when it could not be composed or
 * written: the caller then fails the run, because a pass that left no
 * receipt must never be reported as one. */
static bool wkr_format_receipt(const struct wkr_drive_opts *opts,
                              const struct wkr_job *job, const char *verdict,
                              const struct wkr_result *res, const char *mail_digest,
                              char *text, size_t cap)
{

    char e_cand[sizeof(res->candidate) * WKR_JSON_ESCAPE_WORST];
    char e_name[sizeof(job->name) * WKR_JSON_ESCAPE_WORST];
    char e_kind[sizeof(job->kind) * WKR_JSON_ESCAPE_WORST];
    struct wkr_prov_esc e;
    int w;
    if (!opts || !job || !verdict || !res || !text || !cap)
        return false;
    /* The receipt keeps the provenance bytes exactly as the executor gave
     * them; only the mail copy is bound by the name grammar. */
    if (!zcl_devagent_worker_json_escape(job->name, e_name, sizeof(e_name)) ||
        !zcl_devagent_worker_json_escape(job->kind, e_kind, sizeof(e_kind)) ||
        !zcl_devagent_worker_json_escape(res->candidate, e_cand, sizeof(e_cand)) ||
        !zcl_devagent_worker_prov_escape(res, &e))
        return false;
    char binding[100] = {0};
    if (mail_digest) {
        if (strlen(mail_digest) != 64) return false;
        (void)snprintf(binding, sizeof(binding), ",\"mail_envelope_sha3\":\"%s\"", mail_digest);
    }
    w = snprintf(text, cap,
                 "{\"name\":\"%s\",\"attempt\":%lld,\"seq\":%lld,"
                 "\"kind\":\"%s\",\"verdict\":\"%s\",\"worker\":\"%.48s\","
                 "\"session\":\"%.48s\",\"model\":\"%.128s\","
                 "\"candidate\":\"%s\",\"tokens\":%lld,\"wall_ms\":%lld,"
                 "\"provider\":\"%s\",\"turns\":%lld,\"command\":\"%s\","
                 "\"source\":\"%s\",\"diff\":\"%s\",\"ts\":%lld%s}\n",
                 e_name, job->attempt, job->seq, e_kind,
                 verdict, opts->worker, opts->session, job->model, e_cand,
                 res->tokens_used, res->wall_ms, e.provider, res->turns,
                 e.command, e.source, e.diff,
                 (long long)platform_time_wall_unix(), binding);
    return w > 0 && (size_t)w < cap;
}

static bool wkr_write_receipt(const struct wkr_drive_opts *opts,
                              const struct wkr_job *job, const char *verdict,
                              const struct wkr_result *res)
{
    char path[4096 + 32], text[8192];
    if (!job || snprintf(path, sizeof(path), "%s/%s", job->rundir,
                         WKR_RECEIPT_FILE) >= (int)sizeof(path) ||
        !wkr_format_receipt(opts, job, verdict, res, NULL, text, sizeof(text)))
        return false;
    return zcl_devagent_worker_write_atomic(path, text, strlen(text));
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

/* The safe, bounded pieces of one result row. The provenance fields ride
 * the SAME grammar as everything else: a repo-relative source or command
 * is path-shaped, so it usually arrives as the elided marker here while
 * receipt.json keeps its exact bytes. That is deliberate — the client's
 * row must never be the thing a path cancels. */
struct wkr_mail_row {
    const char *ref;
    const char *worker;
    const char *session;
    const char *model;
    const char *terminal;
    const char *candidate;
    const char *gate;
    const char *provider;
    const char *command;
    const char *source;
    const char *diff;
    long long turns;
    bool elided;
};

static void wkr_row_prov(struct wkr_mail_row *row,
                         const struct wkr_result *res)
{
    row->provider = wkr_field_carry(res ? res->provider : "", &row->elided);
    row->command = wkr_field_carry(res ? res->command : "", &row->elided);
    row->source = wkr_field_carry(res ? res->source : "", &row->elided);
    row->diff = wkr_field_carry(res ? res->diff : "", &row->elided);
    row->turns = res ? res->turns : 0;
}

static void wkr_row_safe(struct wkr_mail_row *row,
                         const struct wkr_drive_opts *opts,
                         const struct wkr_job *job, const char *terminal,
                         const char *candidate, const char *verdict,
                         const struct wkr_result *res)
{
    memset(row, 0, sizeof(*row));
    row->ref = wkr_field_carry(job->name, &row->elided);
    row->worker = wkr_field_carry(opts->worker, &row->elided);
    row->session = wkr_field_carry(opts->session, &row->elided);
    row->model = wkr_field_carry(job->model, &row->elided);
    row->terminal = wkr_field_carry(terminal, &row->elided);
    row->candidate = wkr_field_carry(candidate, &row->elided);
    row->gate = wkr_field_carry(verdict, &row->elided);
    wkr_row_prov(row, res);
}

/* Post one composed body under ref. True when the mail leaf ACCEPTED it;
 * on anything else code is filled with the refusal the outcome row will
 * carry. The code is COPIED: the reply it comes from does not outlive
 * this call. */
static bool wkr_mail_post(const char *body, const char *ref,
                          const char *worker, const struct wkr_job *key,
                          char *code, size_t cap)
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
    if (key)
        zcl_devagent_mail_worker_post(&sub.request, &sub.reply, key->name,
                                      key->attempt, key->seq);
    else
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

/* Compose once so a retry publishes exactly the original safe body. */
static bool wkr_mail_body(const struct wkr_drive_opts *opts,
                          const struct wkr_job *job, const char *terminal,
                          const char *candidate, const char *verdict,
                          long long rc, long long tokens, long long wall_ms,
                          const struct wkr_result *res, char *body, size_t cap)
{
    struct wkr_mail_row row;
    if (!opts || !job || !terminal || !verdict || !body || !cap) return false;
    wkr_row_safe(&row, opts, job, terminal, candidate ? candidate : "", verdict, res);
    int w = snprintf(body, cap,
                 "ref=%.64s\nworker=%.64s\nsession=%.64s\nmodel=%.64s\n"
                 "attempt=%lld\nprovider=%.64s\nturns=%lld\ncommand=%.64s\n"
                 "source=%.64s\ndiff=%.64s\nterminal=%.64s\ncandidate=%.64s\n"
                 "gate=%.64s\nrc=%lld\ntokens=%lld\nwall_ms=%lld\n%s",
                 row.ref, row.worker, row.session, row.model, job->attempt,
                 row.provider, row.turns, row.command, row.source, row.diff,
                 row.terminal, row.candidate, row.gate, rc, tokens, wall_ms,
                 row.elided ? WKR_MAIL_ELIDED_LINE : "");
    if (w > 0 && (size_t)w < cap) return true;
    w = snprintf(body, cap, "ref=%.64s\ngate=%.64s\nrc=%lld\nreduced=1\n",
                 row.ref, row.gate, rc);
    return w > 0 && (size_t)w < cap;
}

static void wkr_mail_result(const struct wkr_drive_opts *opts,
                            const struct wkr_job *job, const char *terminal,
                            const char *candidate, const char *verdict,
                            long long rc, long long tokens, long long wall_ms,
                            const char *note, const struct wkr_result *res)
{
    char body[2048], code[80] = "encode-failed";
    if (!opts || !job || !terminal || !verdict) return;
    if (!wkr_mail_body(opts, job, terminal, candidate, verdict, rc, tokens,
                       wall_ms, res, body, sizeof(body)) ||
        !wkr_mail_post(body, job->name, opts->worker, NULL, code, sizeof(code)))
        wkr_mail_note_refusal(job, rc, note, code);
}

#ifdef ZCL_TESTING
bool (*zcl_devagent_worker_test_hold_pending)(void) = NULL;
#endif

#define WKR_PENDING_FILE "worker-result.pending"
#define WKR_PENDING_CAP (32u * 1024u)

struct wkr_pending {
    struct wkr_job job;
    char worker[49], body[2048], receipt_sha3[65], note[3400];
    long long rc;
};

static void wkr_digest(const char *text, size_t size, char hex[65])
{
    struct sha3_256_ctx ctx;
    unsigned char sum[32];
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)text, size);
    sha3_256_finalize(&ctx, sum);
    zcl_hex_encode(sum, sizeof(sum), hex);
}

/* Each field is length-prefixed, and the domain includes its NUL. */
static void wkr_envelope_field(struct sha3_256_ctx *ctx, const char *value)
{
    char length[32];
    size_t n = strlen(value);
    int w = snprintf(length, sizeof(length), "%zu:", n);
    if (w > 0 && (size_t)w < sizeof(length))
        sha3_256_write(ctx, (const unsigned char *)length, (size_t)w);
    sha3_256_write(ctx, (const unsigned char *)value, n);
}

static void wkr_envelope_digest(const struct wkr_pending *p, char hex[65])
{
    static const char domain[] = "z23.devagent.worker.result-envelope.v1";
    struct sha3_256_ctx ctx;
    unsigned char sum[32];
    char attempt[32], seq[32];
    (void)snprintf(attempt, sizeof(attempt), "%lld", p->job.attempt);
    (void)snprintf(seq, sizeof(seq), "%lld", p->job.seq);
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)domain, sizeof(domain));
    wkr_envelope_field(&ctx, p->worker);
    wkr_envelope_field(&ctx, p->job.name);
    wkr_envelope_field(&ctx, attempt);
    wkr_envelope_field(&ctx, seq);
    wkr_envelope_field(&ctx, p->body);
    sha3_256_finalize(&ctx, sum);
    zcl_hex_encode(sum, sizeof(sum), hex);
}

static bool wkr_receipt_envelope_matches(const char *receipt, const struct wkr_pending *p)
{
    struct json_value v;
    char expected[65];
    json_init(&v);
    wkr_envelope_digest(p, expected);
    bool ok = json_read(&v, receipt, strlen(receipt)) && v.type == JSON_OBJ;
    size_t count = 0;
    for (size_t i = 0; ok && i < v.num_children; i++)
        if (v.keys[i] && strcmp(v.keys[i], "mail_envelope_sha3") == 0) count++;
    const struct json_value *value = ok ? json_get(&v, "mail_envelope_sha3") : NULL;
    ok = count == 1 && value && value->type == JSON_STR && json_get_str(value) &&
         strcmp(json_get_str(value), expected) == 0;
    json_free(&v);
    return ok;
}

/* Publish a private file only after its bytes and containing directory sync. */
static bool wkr_private_publish(const char *path, const char *leaf, const char *text, size_t size)
{
    char resolved[4096], parent[4096], tmp[96];
    struct platform_private_staging staging;
    uint64_t nonce;
    bool ok = false;
    platform_private_staging_init(&staging);
    if (rng_fill((uint8_t *)&nonce, sizeof(nonce)) &&
        platform_private_destination_resolve(path, resolved, sizeof(resolved),
                                             parent, sizeof(parent))) {
        (void)snprintf(tmp, sizeof(tmp), ".worker-%016llx.tmp", (unsigned long long)nonce);
        if (leaf && platform_private_staging_create(&staging, parent, tmp))
            ok = platform_private_file_write_at(&staging.file, text, size, 0) &&
                 platform_private_staging_replace(&staging, leaf);
    }
    if (!ok) (void)platform_private_staging_retire(&staging);
    platform_private_staging_close(&staging);
    return ok;
}

static bool wkr_gated_runout(const struct wkr_job *job, long long rc, const char *note)
{
    char path[4096 + 32], text[4096];
    int n = snprintf(text, sizeof(text), "rc=%lld\n%s\n", rc, note);
    return n > 0 && (size_t)n < sizeof(text) &&
           snprintf(path, sizeof(path), "%s/%s", job->rundir, WKR_RUNOUT_FILE) < (int)sizeof(path) &&
           wkr_private_publish(path, WKR_RUNOUT_FILE, text, (size_t)n);
}

static bool wkr_gated_mail_refusal(const struct wkr_pending *p, const char *code)
{
    char note[3400];
    (void)snprintf(note, sizeof(note), "%.3000s result-mail-refused=%.64s", p->note, code);
    return wkr_gated_runout(&p->job, p->rc, note);
}

static bool wkr_private_read(const char *path, char *out, size_t cap)
{
    struct platform_private_file f;
    uint64_t size = 0;
    platform_private_file_init(&f);
    bool ok = platform_private_file_open_observation(path, &f) &&
              platform_private_file_validate_owner_private(&f) &&
              platform_private_file_size(&f, &size) && size > 0 && size < cap &&
              platform_private_file_read_at(&f, out, (size_t)size, 0);
    platform_private_file_close(&f);
    if (ok && memchr(out, 0, (size_t)size)) ok = false;
    if (ok) out[size] = 0;
    return ok;
}

static bool wkr_pending_path(char *out, size_t cap)
{
    char dir[4096];
    return wkr_state_dir(dir, sizeof(dir), "queue") &&
           snprintf(out, cap, "%s/%s", dir, WKR_PENDING_FILE) < (int)cap;
}

static bool wkr_pending_save(const struct wkr_pending *p)
{
    char path[4096 + 32], text[WKR_PENDING_CAP];
    struct json_value v;
    json_init(&v);
    json_set_object(&v);
    bool ok = json_push_kv_str(&v, "name", p->job.name) &&
              json_push_kv_int(&v, "attempt", p->job.attempt) &&
              json_push_kv_int(&v, "seq", p->job.seq) &&
              json_push_kv_int(&v, "rc", p->rc) &&
              json_push_kv_str(&v, "worker", p->worker) &&
              json_push_kv_str(&v, "body", p->body) &&
              json_push_kv_str(&v, "note", p->note) &&
              json_push_kv_str(&v, "receipt_sha3", p->receipt_sha3);
    size_t n = ok ? json_write(&v, text, sizeof(text)) : 0;
    json_free(&v);
    return n > 0 && n < sizeof(text) && wkr_pending_path(path, sizeof(path)) &&
           wkr_private_publish(path, WKR_PENDING_FILE, text, n);
}

static bool wkr_pending_string(const struct json_value *v, const char *key,
                               char *out, size_t cap)
{
    const struct json_value *x = json_get(v, key);
    const char *str = x && x->type == JSON_STR ? json_get_str(x) : NULL;
    if (!str || strlen(str) >= cap) return false;
    (void)snprintf(out, cap, "%s", str);
    return true;
}

static bool wkr_pending_int(const struct json_value *v, const char *key, long long *out)
{
    const struct json_value *x = json_get(v, key);
    if (!x || x->type != JSON_INT) return false;
    *out = (long long)json_get_int(x);
    return true;
}

static bool wkr_pending_fields(const struct json_value *v, struct wkr_pending *p)
{
    return wkr_pending_string(v, "name", p->job.name, sizeof(p->job.name)) &&
           wkr_pending_string(v, "worker", p->worker, sizeof(p->worker)) &&
           wkr_pending_string(v, "body", p->body, sizeof(p->body)) &&
           wkr_pending_string(v, "note", p->note, sizeof(p->note)) &&
           wkr_pending_string(v, "receipt_sha3", p->receipt_sha3, sizeof(p->receipt_sha3)) &&
           wkr_pending_int(v, "attempt", &p->job.attempt) &&
           wkr_pending_int(v, "seq", &p->job.seq) && wkr_pending_int(v, "rc", &p->rc);
}

static bool wkr_pending_identity(struct wkr_pending *p)
{
    char engine[4096];
    unsigned char digest[32];
    return zcl_devagent_name_ok(p->job.name) && zcl_devagent_name_ok(p->worker) &&
           p->job.attempt > 0 && p->job.seq > 0 && p->body[0] &&
           strlen(p->receipt_sha3) == 64 &&
           zcl_hex_decode_lower(p->receipt_sha3, digest, sizeof(digest)) &&
           wkr_state_dir(engine, sizeof(engine), "engine") &&
           snprintf(p->job.rundir, sizeof(p->job.rundir), "%s/%s/a%lld",
                    engine, p->job.name, p->job.attempt) < (int)sizeof(p->job.rundir);
}

static bool wkr_pending_load(const char *path, struct wkr_pending *p)
{
    char text[WKR_PENDING_CAP];
    struct json_value v;
    memset(p, 0, sizeof(*p));
    json_init(&v);
    bool ok = wkr_private_read(path, text, sizeof(text)) &&
              json_read(&v, text, strlen(text)) && v.type == JSON_OBJ &&
              wkr_pending_fields(&v, p) && wkr_pending_identity(p);
    json_free(&v);
    return ok;
}

static bool wkr_pending_remove(const char *path)
{
    struct platform_private_file file;
    struct platform_private_file_identity id;
    char resolved[4096], parent[4096];
    platform_private_file_init(&file);
    bool ok = platform_private_destination_resolve(path, resolved, sizeof(resolved),
                                                    parent, sizeof(parent)) &&
              platform_private_file_open_locked(resolved, &file) &&
              platform_private_file_validate_owner_private(&file) &&
              platform_private_file_identity(&file, &id) &&
              platform_private_file_retire_if_identity(&file, resolved, &id);
    platform_private_file_close(&file);
    return ok && platform_private_parent_flush(parent);
}

static int wkr_pending_missing(const char *path, struct wkr_pending *p)
{
    char body[512], code[80] = "encode-failed";
    int n = snprintf(body, sizeof(body),
                     "ref=%.64s\nterminal=receipt-unwritable\ngate=no-receipt\nrc=%d\n",
                     p->job.name, WKR_RC_NO_RECEIPT);
    wkr_write_runout(&p->job, WKR_RC_NO_RECEIPT, WKR_RECEIPT_UNWRITABLE);
    if (n <= 0 || (size_t)n >= sizeof(body) ||
        !wkr_mail_post(body, p->job.name, p->worker, &p->job, code, sizeof(code))) {
        wkr_mail_note_refusal(&p->job, WKR_RC_NO_RECEIPT, WKR_RECEIPT_UNWRITABLE, code);
        if (strncmp(code, "MAIL_REFUSED_", 13) != 0) return -1;
    }
    return wkr_pending_remove(path) ? 0 : -1;
}

static bool wkr_pending_receipt_matches(const char *receipt, const struct wkr_pending *p)
{
    char resolved[4096], parent[4096], text[8192], digest[65];
    if (!platform_private_destination_resolve(receipt, resolved, sizeof(resolved),
                                             parent, sizeof(parent)) ||
        !platform_private_parent_flush(parent) ||
        !wkr_private_read(resolved, text, sizeof(text))) return false;
    wkr_digest(text, strlen(text), digest);
    return strcmp(digest, p->receipt_sha3) == 0 && wkr_receipt_envelope_matches(text, p);
}

static bool wkr_pending_runout_matches(const struct wkr_pending *p)
{
    char path[4096 + 32], text[4096], prefix[48];
    int n = snprintf(prefix, sizeof(prefix), "rc=%lld\n", p->rc);
    return n > 0 && (size_t)n < sizeof(prefix) &&
           snprintf(path, sizeof(path), "%s/%s", p->job.rundir, WKR_RUNOUT_FILE) < (int)sizeof(path) &&
           wkr_private_read(path, text, sizeof(text)) && strncmp(text, prefix, (size_t)n) == 0;
}

static int wkr_pending_deliver(const char *path, struct wkr_pending *p)
{
    char code[80] = "encode-failed";
    if (!wkr_mail_post(p->body, p->job.name, p->worker, &p->job, code, sizeof(code))) {
        if (!wkr_gated_mail_refusal(p, code)) return -1;
        if (strncmp(code, "MAIL_REFUSED_", 13) != 0) return -1;
    }
#ifdef ZCL_TESTING
    if (zcl_devagent_worker_test_hold_pending && zcl_devagent_worker_test_hold_pending())
        return -1;
#endif
    return wkr_pending_remove(path) ? 0 : -1;
}

/* 0 is settled or absent; -1 retains the pending intent and stops this drive. */
static int wkr_pending_reconcile(void)
{
    char path[4096 + 32], receipt[4096 + 32];
    struct wkr_pending p;
    if (!wkr_pending_path(path, sizeof(path))) return -1;
    if (platform_private_path_absent(path)) return 0;
    if (!wkr_pending_load(path, &p) ||
        snprintf(receipt, sizeof(receipt), "%s/%s", p.job.rundir,
                 WKR_RECEIPT_FILE) >= (int)sizeof(receipt)) return -1;
    if (platform_private_path_absent(receipt)) return wkr_pending_missing(path, &p);
    if (!wkr_pending_receipt_matches(receipt, &p) || !wkr_pending_runout_matches(&p)) return -1;
    return wkr_pending_deliver(path, &p);
}

/* ── run one job ─────────────────────────────────────────────────────────
 * fresh: flip submitted pre-fork, spawn, gate, finish, mail. adopted
 * with submitted!=false: crash-record without ever submitting. Returns
 * 1 processed, 0 when there was no executor to run. */

/* The ungated end of a run. A cancelled outcome is the one that still
 * earns a receipt: the operator asked for the stop, so reap reads an
 * explicit non-PASS word instead of guessing at a missing file. Crash,
 * timeout and no-result keep writing none. */
static void wkr_finish_ungated(const struct wkr_drive_opts *opts,
                               const struct wkr_job *job,
                               const struct wkr_outcome *oc,
                               long long wall_ms)
{
    struct wkr_result res;
    memset(&res, 0, sizeof(res));
    wkr_write_runout(job, oc->rc, oc->note);
    if (!oc->cancelled) {
        wkr_mail_result(opts, job, oc->terminal, "", "no-receipt", oc->rc, 0,
                        wall_ms, oc->note, NULL);
        return;
    }
    (void)snprintf(res.terminal, sizeof(res.terminal), "%s", oc->terminal);
    res.rc = oc->rc;
    res.wall_ms = wall_ms;
    (void)snprintf(res.provider, sizeof(res.provider), "%s", "worker");
    if (!wkr_write_receipt(opts, job, oc->terminal, &res)) {
        wkr_write_runout(job, WKR_RC_NO_RECEIPT, WKR_RECEIPT_UNWRITABLE);
        wkr_mail_result(opts, job, WKR_RECEIPT_UNWRITABLE, "", "no-receipt",
                        WKR_RC_NO_RECEIPT, 0, wall_ms,
                        WKR_RECEIPT_UNWRITABLE, NULL);
        return;
    }
    wkr_mail_result(opts, job, oc->terminal, "", oc->terminal, oc->rc, 0,
                    wall_ms, oc->note, &res);
}

/* The wired external judge: run the job's own test group right now through
 * the shared runner. A real pass is the runner exiting clean, a whole
 * transcript, at least one group actually RUN, and none failed — a gated
 * or cached zero is not a pass. The note records what was observed either
 * way, so a refusal is readable in the outcome row. */
static bool wkr_group_ran_clean(const struct zcl_devagent_verdict *v, int rc,
                                bool truncated)
{
    return rc == 0 && v->present && !truncated && v->groups_ran > 0 &&
           v->groups_failed == 0;
}

static bool wkr_group_gate(const struct wkr_job *job, char *note,
                           size_t notecap)
{
    char root[4096], selector[160];
    struct zcl_devagent_verdict v;
    bool truncated = false;
    long long ms;
    int rc;
    memset(&v, 0, sizeof(v));
    if (!zcl_devagent_checkout_root(NULL, root, sizeof(root)) ||
        snprintf(selector, sizeof(selector), "--exact=%s", job->group) >=
            (int)sizeof(selector))
        return false;
    ms = job->time_cap_s > 0 ? job->time_cap_s * 1000LL : WKR_GROUP_MS_DFLT;
    if (ms > WKR_GROUP_MS_MAX)
        ms = WKR_GROUP_MS_MAX;
    rc = zcl_devagent_run_group(root, selector, (int)ms, &v, &truncated);
    if (note && notecap > 0)
        (void)snprintf(note, notecap,
                       "gate group=%s ran=%lld failed=%lld exit=%d",
                       job->group, v.groups_ran, v.groups_failed, rc);
    return wkr_group_ran_clean(&v, rc, truncated);
}

/* The run's own outcome row: the executor's evidence, then the gate's
 * one-line observation, so a group refusal is readable beside the rc. */
static void wkr_run_note(const struct wkr_result *res, const char *gateline,
                         char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    if (!gateline || !gateline[0]) {
        (void)snprintf(out, cap, "%s", res ? res->evidence : "");
        return;
    }
    (void)snprintf(out, cap, "%.3000s %s", res ? res->evidence : "", gateline);
}

/* ── pre-spend guards: authority, then workspace ─────────────────────────
 * A claimed row spends nothing until both hold, checked AFTER claim and
 * BEFORE the submitted flip and the executor fork:
 *
 * 1. AUTHORITY. The receiver's per-ref .evidence record
 *    (<state>/receive/brief/<name>.evidence) names the sender label, the
 *    binding stamp, and the grant expiry seen at install. All three are
 *    re-read against the LIVE grant store here: the binding must still be
 *    the live credential for the label with the "send" scope, and the
 *    expiry must still read. A board-carried row instead names the
 *    verified signer and is re-checked against the live peer grant. A
 *    revoke or expiry landing between admission and execution therefore
 *    refuses here. Missing, unreadable, or mis-shaped evidence fails
 *    closed: it refuses, it never admits.
 * 2. WORKSPACE. The brief's resolved workspace (the muse-workspace line
 *    the receiver wrote) is re-observed with the existing
 *    zcl_devagent_workspace_observe: a HEAD that moved, or tracked paths
 *    that dirtied, since the evidence record refuses. A brief naming no
 *    workspace has nothing recorded and nothing re-verified; a same-box
 *    absolute path (evidence head "none") re-checks existence and
 *    resolvability, the properties its admission verified.
 *
 * Both refuse through wkr_refuse_job below — the queue's existing
 * terminal/refusal vocabulary (run.out rc 102 plus the no-receipt result
 * row reap already records). No new queue state is invented, submitted is
 * never flipped, the executor never forks, and the grant store is only
 * ever read, never minted or renewed. */

struct wkr_evidence {
    char sender[64];
    char binding[ZCL_FLEET_STEER_BINDING_HEX + 1];
    bool peer;
    long long expiry;
    char signer[65];
    char head[41];
    bool has_head;
};

/* One `key=value` line out of the evidence record. False when the key is
 * absent, the value is empty or overflows, or a stray CR rides the line. */
static bool wkr_ev_line(const char *text, const char *key, char *out,
                        size_t cap)
{
    size_t klen = strlen(key);
    const char *p = text;
    if (!text || !key || !out || cap == 0)
        return false;
    for (;;) {
        const char *eol;
        size_t vlen;
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            p += klen + 1;
            eol = strchr(p, '\n');
            vlen = eol ? (size_t)(eol - p) : strlen(p);
            if (vlen == 0 || vlen >= cap)
                return false;
            memcpy(out, p, vlen);
            out[vlen] = '\0';
            return strchr(out, '\r') == NULL;
        }
        p = strchr(p, '\n');
        if (!p)
            return false;
        p++;
    }
}

static bool wkr_ev_binding_line(const char *text, char *out, size_t cap)
{
    static const char key[] = "sender_binding=";
    const char *p = text;
    if (!p) return false;
    for (;;) {
        if (strncmp(p, key, sizeof(key) - 1) == 0) {
            if (p[sizeof(key) - 1] == '\n' || p[sizeof(key) - 1] == '\0') {
                if (cap == 0) return false;
                out[0] = '\0';
                return true;
            }
            return wkr_ev_line(text, "sender_binding", out, cap);
        }
        p = strchr(p, '\n');
        if (!p) return false;
        p++;
    }
}

static bool wkr_ev_token(const char *s, size_t max)
{
    size_t i, n;
    if (!s || s[0] == '\0' || (n = strlen(s)) > max)
        return false;
    for (i = 0; i < n; i++) {
        char c = s[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')
            continue;
        return false;
    }
    return true;
}

static bool wkr_ev_hex(const char *s, size_t want)
{
    size_t i;
    if (!s || strlen(s) != want)
        return false;
    for (i = 0; i < want; i++) {
        char c = s[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
            continue;
        return false;
    }
    return true;
}

/* The evidence file one job's name addresses. False when the name cannot
 * name a file safely or the path will not fit — both fail closed. */
static bool wkr_evidence_path(const struct wkr_job *job, char *path,
                              size_t cap)
{
    char dir[4096];
    if (!job || !job->name[0] || !zcl_devagent_name_ok(job->name))
        return false;
    if (!wkr_state_dir(dir, sizeof(dir), "receive"))
        return false;
    return snprintf(path, cap, "%s/brief/%s.evidence", dir, job->name) <
           (int)cap;
}

/* The sender lines: who the row spends as and the stamp that tied the
 * row to the granting credential. */
static bool wkr_evidence_sender(const char *text, struct wkr_evidence *ev)
{
    if (!wkr_ev_line(text, "sender", ev->sender, sizeof(ev->sender)))
        return false;
    if (!wkr_ev_token(ev->sender, sizeof(ev->sender) - 1))
        return false;
    if (ev->peer) {
        if (!wkr_ev_binding_line(text, ev->binding, sizeof(ev->binding)))
            return false;
    } else if (!wkr_ev_line(text, "sender_binding", ev->binding,
                            sizeof(ev->binding))) {
        return false;
    }
    return (ev->peer && !ev->binding[0]) ||
           wkr_ev_hex(ev->binding, ZCL_FLEET_STEER_BINDING_HEX);
}

/* The expiry line: an integer install-time expiry for a local grant, or
 * the `peer` literal plus the verified signer for a board-carried row. */
static bool wkr_evidence_expiry(const char *text, struct wkr_evidence *ev)
{
    char expiry[32];
    char *end = NULL;
    if (!wkr_ev_line(text, "grant_expiry", expiry, sizeof(expiry)))
        return false;
    if (strcmp(expiry, "peer") == 0) {
        ev->peer = true;
        if (!wkr_ev_line(text, "board_signer", ev->signer,
                         sizeof(ev->signer)))
            return false;
        return wkr_ev_token(ev->signer, sizeof(ev->signer));
    }
    ev->expiry = strtoll(expiry, &end, 10);
    return end != NULL && *end == '\0';
}

/* The workspace_head line is optional: absent or "none" means the
 * admission recorded no HEAD (a same-box absolute path). A present but
 * mis-shaped HEAD fails closed like every other line. */
static bool wkr_evidence_head(const char *text, struct wkr_evidence *ev)
{
    char head[64];
    if (!wkr_ev_line(text, "workspace_head", head, sizeof(head)))
        return true;
    if (strcmp(head, "none") == 0)
        return true;
    if (!wkr_ev_hex(head, 40))
        return false;
    (void)snprintf(ev->head, sizeof(ev->head), "%s", head);
    ev->has_head = true;
    return true;
}

/* The authority lines of one job's evidence record. False when the file
 * is missing or unreadable, when the row name cannot name a file safely,
 * or when any required line is absent or mis-shaped — every one of those
 * fails closed at the caller. */
static bool wkr_evidence_read(const struct wkr_job *job,
                              struct wkr_evidence *ev)
{
    char path[4096 + 160], text[2048];
    memset(ev, 0, sizeof(*ev));
    if (!wkr_evidence_path(job, path, sizeof(path)))
        return false;
    if (!zcl_devagent_worker_read_file(path, text, sizeof(text)))
        return false;
    return wkr_evidence_expiry(text, ev) && wkr_evidence_sender(text, ev) &&
           wkr_evidence_head(text, ev);
}

/* The sender authority, re-verified against the live store. NULL passes;
 * otherwise the named refusal. */
static const char *wkr_guard_authority(const struct wkr_evidence *ev)
{
    long long exp = 0;
    const char *why;
    if (ev->peer) {
        char peer[FLEET_ENROL_NAME_MAX + 1];
        if (!zcl_devagent_boardmail_peer_name(ev->signer, peer, sizeof(peer)))
            return WKR_REFUSE_AUTHORITY;
        why = zcl_fleet_steer_grant_peer_live(ev->sender, peer,
                                              WKR_SEND_SCOPE);
        return why ? WKR_REFUSE_AUTHORITY : NULL;
    }
    why = zcl_fleet_steer_grant_binding_live(ev->sender, ev->binding,
                                             WKR_SEND_SCOPE);
    if (why)
        return WKR_REFUSE_AUTHORITY;
    if (!zcl_fleet_steer_grant_expiry(ev->sender, WKR_SEND_SCOPE, &exp))
        return WKR_REFUSE_AUTHORITY;
    return NULL;
}

/* The brief's workspace, re-observed. NULL passes; otherwise the named
 * refusal. No workspace line in the brief means the admission recorded
 * none, so there is nothing to re-verify. */
static const char *wkr_guard_workspace(const struct wkr_job *job,
                                       const struct wkr_evidence *ev)
{
    char ws[1024];
    struct rcv_workspace w;
    if (!zcl_devagent_worker_task_workspace(job->task, ws, sizeof(ws)))
        return NULL;
    memset(&w, 0, sizeof(w));
    if (!zcl_devagent_workspace_observe(ws, true, &w))
        return WKR_REFUSE_WS_MOVED;
    if (!w.directory || !w.resolved)
        return WKR_REFUSE_WS_MOVED;
    if (!ev->has_head)
        return NULL;
    if (!w.checkout || w.head[0] == '\0' || strcmp(w.head, ev->head) != 0)
        return WKR_REFUSE_WS_MOVED;
    if (w.dirty != 0)
        return WKR_REFUSE_WS_DIRTY;
    return NULL;
}

/* Both pre-spend guards in spend order. NULL spends; otherwise the named
 * refusal the caller records without submitting or forking. */
static const char *wkr_prespend_guard(const struct wkr_job *job)
{
    struct wkr_evidence ev;
    const char *refusal;
    if (!job)
        return WKR_REFUSE_AUTHORITY_READ;
    if (!wkr_evidence_read(job, &ev))
        return WKR_REFUSE_AUTHORITY_READ;
    refusal = wkr_guard_authority(&ev);
    if (refusal)
        return refusal;
    return wkr_guard_workspace(job, &ev);
}

static long long wkr_refuse_job(const struct wkr_drive_opts *opts,
                                const struct wkr_job *job, const char *why);

static bool wkr_gated_destination(const struct wkr_job *job)
{
    char engine[4096], expected[4096], receipt[4096 + 32];
    return zcl_devagent_name_ok(job->name) && job->attempt > 0 && job->seq > 0 &&
           wkr_state_dir(engine, sizeof(engine), "engine") &&
           snprintf(expected, sizeof(expected), "%s/%s/a%lld", engine, job->name, job->attempt) < (int)sizeof(expected) &&
           strcmp(expected, job->rundir) == 0 &&
           snprintf(receipt, sizeof(receipt), "%s/%s", expected, WKR_RECEIPT_FILE) < (int)sizeof(receipt) &&
           platform_private_path_absent(receipt);
}

static void wkr_gated_no_receipt(const struct wkr_drive_opts *opts,
                                 const struct wkr_job *job, const struct wkr_result *res)
{
    wkr_write_runout(job, WKR_RC_NO_RECEIPT, WKR_RECEIPT_UNWRITABLE);
    wkr_mail_result(opts, job, WKR_RECEIPT_UNWRITABLE, res->candidate, "no-receipt",
                    WKR_RC_NO_RECEIPT, res->tokens_used, res->wall_ms, WKR_RECEIPT_UNWRITABLE, res);
}

static void wkr_gated_pending_failed(const struct wkr_drive_opts *opts,
                                     const struct wkr_job *job, const struct wkr_result *res)
{
    char pending_path[4096 + 32], body[2048], code[80] = "encode-failed";
    if (!wkr_pending_path(pending_path, sizeof(pending_path)) ||
        !platform_private_path_absent(pending_path))
        return; /* A rename may have succeeded; replay the installed intent. */
    wkr_write_runout(job, WKR_RC_NO_RECEIPT, WKR_RECEIPT_UNWRITABLE);
    if (!wkr_mail_body(opts, job, WKR_RECEIPT_UNWRITABLE, res->candidate,
                       "no-receipt", WKR_RC_NO_RECEIPT, res->tokens_used,
                       res->wall_ms, res, body, sizeof(body)) ||
        !wkr_mail_post(body, job->name, opts->worker, job, code, sizeof(code)))
        wkr_mail_note_refusal(job, WKR_RC_NO_RECEIPT, WKR_RECEIPT_UNWRITABLE, code);
}

static long long wkr_finish_gated(const struct wkr_drive_opts *opts,
                                  const struct wkr_job *job, struct wkr_result *res)
{
    char verdict[32], gateline[256], note[3400];
    long long rc;

    rc = zcl_devagent_worker_gate(job, res, verdict, sizeof(verdict),
                                  gateline, sizeof(gateline),
                                  wkr_group_gate);
    wkr_run_note(res, gateline, note, sizeof(note));
    if (!wkr_gated_destination(job)) {
        wkr_gated_no_receipt(opts, job, res);
        return 1;
    }
    struct wkr_pending pending = {0};
    char receipt[8192], path[4096 + 32];
    pending.job = *job;
    pending.rc = rc;
    (void)snprintf(pending.worker, sizeof(pending.worker), "%s", opts->worker);
    (void)snprintf(pending.note, sizeof(pending.note), "%s", note);
    char envelope[65];
    bool ready = zcl_devagent_name_ok(job->name) && job->attempt > 0 && job->seq > 0 &&
        wkr_mail_body(opts, job, res->terminal, res->candidate, verdict, rc,
                      res->tokens_used, res->wall_ms, res, pending.body, sizeof(pending.body));
    if (ready) {
        wkr_envelope_digest(&pending, envelope);
        ready = wkr_format_receipt(opts, job, verdict, res, envelope, receipt, sizeof(receipt));
    }
    if (ready) wkr_digest(receipt, strlen(receipt), pending.receipt_sha3);
    if (!ready || !wkr_gated_runout(job, rc, note)) {
        wkr_gated_no_receipt(opts, job, res);
        return 1;
    }
    if (!wkr_pending_save(&pending)) {
        wkr_gated_pending_failed(opts, job, res);
        return 1;
    }
    if (snprintf(path, sizeof(path), "%s/%s", job->rundir, WKR_RECEIPT_FILE) >= (int)sizeof(path) ||
        !wkr_private_publish(path, WKR_RECEIPT_FILE, receipt, strlen(receipt))) {
        /* A failed directory barrier can follow a successful rename. Keep the
         * pending intent and let a later drive inspect the real receipt. */
        return 1;
    }
    (void)wkr_pending_reconcile();
    return 1;
}

static long long wkr_run_fresh(const struct wkr_drive_opts *opts,
                               const struct wkr_job *job,
                               wkr_executor_fn exec)
{
    struct wkr_spawn_out out;
    struct wkr_outcome oc;
    struct wkr_result res;
    const char *guard;
    /* Authority and workspace BEFORE the submitted flip and the fork: a
     * refusal here spends nothing and submits nothing. */
    guard = wkr_prespend_guard(job);
    if (guard)
        return wkr_refuse_job(opts, job, guard);
    if (!wkr_set_submitted(job->rundir)) {
        wkr_write_runout(job, 101, "claim-identity-unwritable");
        wkr_mail_result(opts, job, "claim-identity-unwritable", "",
                        "no-receipt", 101, 0, 0,
                        "claim-identity-unwritable", NULL);
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
        wkr_finish_ungated(opts, job, &oc, out.wall_ms);
        return 1;
    }
    res.wall_ms = out.wall_ms;
    return wkr_finish_gated(opts, job, &res);

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
                        "worker-lost-after-submit", NULL);
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
                    why, NULL);
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

/* Identity of the mail directory's *.jsonl streams. Cursor and read
 * files are not streams, and a read of a stream does not change this. */
struct wkr_mail_sig {
    int nfiles;
    uint64_t size;
    int64_t mtime;
    uint64_t ident;
};

struct wkr_idle {
    struct platform_directory_watcher watcher;
    struct platform_directory_watcher mail;
    bool watching;
    bool mail_watching;
    bool mail_woke;
    char queuedir[4096];
    char maildir[4096];
    struct wkr_qsig base;
    struct wkr_mail_sig mail_sig;
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

static bool wkr_jsonl_name(const char *name)
{
    size_t n;
    if (!name)
        return false;
    n = strlen(name);
    return n > 6 && strcmp(name + n - 6, ".jsonl") == 0;
}

/* False when the directory cannot be listed. A failed listing is not a
 * mail change: treating it as one would wake every slice. */
static bool wkr_mail_sig_take(const char *maildir, struct wkr_mail_sig *sig)
{
    struct platform_directory_list files = {0};
    size_t i;
    memset(sig, 0, sizeof(*sig));
    if (!maildir ||
        !platform_directory_list_regular_sorted(maildir, &files)) {
        platform_directory_list_free(&files);
        return false;
    }
    for (i = 0; i < files.count; i++) {
        const struct platform_directory_entry *e = &files.entries[i];
        if (!e->snapshot_valid || !wkr_jsonl_name(e->name))
            continue;
        sig->nfiles++;
        sig->size += e->size;
        sig->mtime += e->modified_seconds;
        sig->ident ^= e->file_low;
    }
    platform_directory_list_free(&files);
    return true;
}

static bool wkr_mail_sig_same(const struct wkr_mail_sig *a,
                              const struct wkr_mail_sig *b)
{
    return a->nfiles == b->nfiles && a->size == b->size &&
           a->mtime == b->mtime && a->ident == b->ident;
}

static void wkr_mail_resnap(struct wkr_idle *idle)
{
    struct wkr_mail_sig now;
    if (!idle->mail_watching)
        return;
    if (wkr_mail_sig_take(idle->maildir, &now))
        idle->mail_sig = now;
}

/* Sampled from the queue wait. A mail-directory event wakes the inbox
 * check only when a *.jsonl stream actually changed. */
static bool wkr_wake_stop(void *opaque)
{
    struct wkr_idle *idle = opaque;
    enum platform_directory_watch_result r;
    struct wkr_mail_sig now;
    if (g_wkr_term != 0)
        return true;
    if (!idle || !idle->mail_watching)
        return false;
    r = platform_directory_watcher_wait(&idle->mail, 0, NULL, NULL);
    if (r == PLATFORM_DIRECTORY_WATCH_ERROR) {
        platform_directory_watcher_close(&idle->mail);
        idle->mail_watching = false;
        return false;
    }
    if (r != PLATFORM_DIRECTORY_WATCH_CHANGED &&
        r != PLATFORM_DIRECTORY_WATCH_OVERFLOW)
        return false;
    if (!wkr_mail_sig_take(idle->maildir, &now) ||
        wkr_mail_sig_same(&idle->mail_sig, &now))
        return false;
    idle->mail_woke = true;
    return true;
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

static void wkr_mail_watch_open(struct wkr_idle *idle, bool timed_only)
{
    platform_directory_watcher_init(&idle->mail);
    idle->mail_watching = false;
    idle->mail_woke = false;
    idle->maildir[0] = '\0';
    memset(&idle->mail_sig, 0, sizeof(idle->mail_sig));
    if (timed_only || !wkr_state_dir(idle->maildir, sizeof(idle->maildir),
                                     "mail"))
        return;
    if (!platform_private_directory_ensure(idle->maildir)) {
        idle->maildir[0] = '\0';
        return;
    }
    idle->mail_watching =
        platform_directory_watcher_open(&idle->mail, idle->maildir);
    if (idle->mail_watching)
        wkr_mail_resnap(idle);
    else
        idle->maildir[0] = '\0';
}

static void wkr_idle_open(struct wkr_idle *idle, const char *queuedir,
                          bool timed_only)
{
    platform_directory_watcher_init(&idle->watcher);
    (void)snprintf(idle->queuedir, sizeof(idle->queuedir), "%s", queuedir);
    memset(&idle->base, 0, sizeof(idle->base));
    idle->watching = !timed_only && platform_directory_watcher_open(
                                        &idle->watcher, idle->queuedir);
    wkr_mail_watch_open(idle, timed_only);
}

static void wkr_idle_close(struct wkr_idle *idle)
{
    if (idle->watching)
        platform_directory_watcher_close(&idle->watcher);
    if (idle->mail_watching)
        platform_directory_watcher_close(&idle->mail);
    idle->watching = false;
    idle->mail_watching = false;
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
                                            wkr_wake_stop, idle);
        if (g_wkr_term != 0)
            return false;
        if (r == PLATFORM_DIRECTORY_WATCH_STOPPED && idle->mail_woke) {
            idle->mail_woke = false;
            return true;
        }
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

static bool wkr_lock_open(struct wkr_lock *lk, char *path, size_t cap,
                          const char *queuedir)
{
    if (!platform_private_directory_ensure(queuedir))
        return false;
    if (snprintf(path, cap, "%s/%s", queuedir, WKR_LOCK_FILE) >= (int)cap)
        return false;
    return wkr_lock_take(lk, path);
}

#ifdef ZCL_TESTING
void (*zcl_devagent_worker_test_after_empty_claim)(void) = NULL;
void (*zcl_devagent_worker_test_after_inbox)(void) = NULL;
void (*zcl_devagent_worker_test_after_first_note)(void) = NULL;
void (*zcl_devagent_worker_test_before_step)(void) = NULL;
static bool g_wkr_first_note;
#endif

/* Once per check, after the first note is stored and before the check
 * returns. Shipped builds have nothing to call. */
static void wkr_after_first_note(void)
{
#ifdef ZCL_TESTING
    if (g_wkr_first_note)
        return;
    g_wkr_first_note = true;
    if (zcl_devagent_worker_test_after_first_note)
        zcl_devagent_worker_test_after_first_note();
#endif
}

static const char *wkr_json_str(const struct json_value *row, const char *key)
{
    const struct json_value *v = row ? json_get(row, key) : NULL;
    const char *s;
    if (!v || v->type != JSON_STR)
        return "";
    s = json_get_str(v);
    return s ? s : "";
}

static bool wkr_reply_path(const char *worker, const char *ref, char *path,
                           size_t cap)
{
    char dir[4096];
    int n;
    if (!wkr_state_dir(dir, sizeof(dir), "mail"))
        return false;
    n = snprintf(path, cap, "%s/reply.%s.%s", dir, worker, ref);
    return n > 0 && (size_t)n < cap;
}

static bool wkr_marker_held(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return errno != ENOENT;
    (void)fclose(f);
    return true;
}

static void wkr_marker_store(const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return;
    if (fclose(f) == 0) {
#if !defined(_WIN32)
        (void)chmod(path, 0600);
#endif
    }
}

/* Kind note, never result: a result would look like execution. */
static bool wkr_post_note(const char *worker, const char *ref, const char *to)
{
    struct wkr_sub sub;
    char body[96], ebody[256], eref[192], eto[160], input[768];
    int n;
    bool posted = false;
    n = snprintf(body, sizeof(body), "disposition=DEFERRED\nref=%s\n", ref);
    if (n <= 0 || (size_t)n >= sizeof(body))
        return false;
    if (!zcl_devagent_worker_json_escape(body, ebody, sizeof(ebody)) ||
        !zcl_devagent_worker_json_escape(ref, eref, sizeof(eref)) ||
        !zcl_devagent_worker_json_escape(to, eto, sizeof(eto)))
        return false;
    n = snprintf(input, sizeof(input),
                 "{\"action\":\"post\",\"to\":\"%s\",\"kind\":\"note\","
                 "\"body\":\"%s\",\"ref\":\"%s\",\"from\":\"%.48s\"}",
                 eto, ebody, eref, worker);
    if (n <= 0 || (size_t)n >= sizeof(input))
        return false;
    wkr_sub_begin(&sub, "zcl.agent_mail.v1", "dev.agent.mail");
    if (sub.valid && wkr_sub_input(&sub, input)) {
        zcl_native_handle_dev_agent_mail(&sub.request, &sub.reply);
        sub.ran = true;
        posted = wkr_sub_ok(&sub);
    }
    wkr_sub_end(&sub);
    return posted;
}

static bool wkr_inbox_notes(const struct wkr_sub *sub, const char *worker)
{
    const struct json_value *rows = json_get(&sub->reply.data, "rows");
    size_t n, i;
    if (!rows || rows->type != JSON_ARR)
        return false;
    n = json_size(rows);
    for (i = 0; i < n; i++) {
        const struct json_value *row = json_at(rows, i);
        const char *kind = wkr_json_str(row, "kind");
        const char *to = wkr_json_str(row, "to");
        const char *ref = wkr_json_str(row, "ref");
        const char *from = wkr_json_str(row, "from");
        char path[4200];
        const char *dest;
        if (strcmp(kind, "directive") != 0 || strcmp(to, worker) != 0)
            continue;
        if (!zcl_devagent_name_ok(ref))
            continue;
        if (!wkr_reply_path(worker, ref, path, sizeof(path)) ||
            wkr_marker_held(path))
            continue;
        dest = (zcl_devagent_name_ok(from) && strcmp(from, worker) != 0)
                   ? from : "*";
        if (!wkr_post_note(worker, ref, dest))
            return false;
        wkr_marker_store(path);
        wkr_after_first_note();
    }
    return true;
}

static void wkr_drop_cursor(const char *worker)
{
    char dir[4096], path[4200];
    int n;
    if (!wkr_state_dir(dir, sizeof(dir), "mail"))
        return;
    n = snprintf(path, sizeof(path), "%s/cursor.%s", dir, worker);
    if (n > 0 && (size_t)n < sizeof(path))
        (void)remove(path);
}

static bool wkr_inbox_open(const char *worker, struct wkr_sub *sub,
                           char *token, size_t cap, long long *count,
                           bool *stale)
{
    char input[192];
    const char *next;
    const char *code;
    int n;
    *count = 0;
    *stale = false;
    token[0] = '\0';
    if (!zcl_devagent_name_ok(worker))
        return false;
    n = snprintf(input, sizeof(input),
                 "{\"action\":\"pull\",\"to\":\"%s\",\"agent\":\"%s\"}",
                 worker, worker);
    if (n <= 0 || (size_t)n >= sizeof(input))
        return false;
    wkr_sub_begin(sub, "zcl.agent_mail.v1", "dev.agent.mail");
    if (!sub->valid || !wkr_sub_input(sub, input)) {
        wkr_sub_end(sub);
        return false;
    }
    zcl_native_handle_dev_agent_mail(&sub->request, &sub->reply);
    sub->ran = true;
    if (!wkr_sub_ok(sub)) {
        code = sub->reply.error.code;
        *stale = code[0] && strcmp(code, "MAIL_CURSOR_STALE") == 0;
        wkr_sub_end(sub);
        return false;
    }
    *count = wkr_sub_int(sub, "count", 0);
    next = wkr_sub_str(sub, "next_since");
    if (!next || !strchr(next, '|') || strlen(next) >= cap) {
        wkr_sub_end(sub);
        return false;
    }
    (void)snprintf(token, cap, "%s", next);
    return true;
}

static void wkr_inbox_ack(const char *worker, const char *token)
{
    struct wkr_sub sub;
    char input[4600];
    int n;
    if (!token || !strchr(token, '|'))
        return;
    n = snprintf(input, sizeof(input),
                 "{\"action\":\"ack\",\"agent\":\"%s\",\"cursor\":\"%s\"}",
                 worker, token);
    if (n <= 0 || (size_t)n >= sizeof(input))
        return;
    wkr_sub_begin(&sub, "zcl.agent_mail.v1", "dev.agent.mail");
    if (sub.valid && wkr_sub_input(&sub, input)) {
        zcl_native_handle_dev_agent_mail(&sub.request, &sub.reply);
        sub.ran = true;
    }
    wkr_sub_end(&sub);
}

/* One pull. 1 = a page of this worker's mail was acked, and a row
 * appended while that page was noted is still unread. 0 = stop. -1 =
 * the stored cursor is stale. An empty pull writes nothing: the
 * worker's own note is addressed to the sender, so it is not a reason
 * to pull again. */
static int wkr_inbox_page(const char *worker, char *prev, size_t cap)
{
    struct wkr_sub sub;
    char token[4096];
    long long count = 0;
    bool stale = false;
    if (!wkr_inbox_open(worker, &sub, token, sizeof(token), &count, &stale))
        return stale ? -1 : 0;
    if (count <= 0 || (prev[0] != '\0' && strcmp(token, prev) == 0)) {
        wkr_sub_end(&sub);
        return 0;
    }
    (void)snprintf(prev, cap, "%s", token);
    (void)zcl_devagent_mail_record_read(worker, token);
    if (!wkr_inbox_notes(&sub, worker)) {
        wkr_sub_end(&sub);
        return 0;
    }
    wkr_inbox_ack(worker, token);
    wkr_sub_end(&sub);
    return 1;
}

/* Startup, each idle return, and each finished job. Keep pulling while
 * each pull acks a new resume token. Stop when the pull is empty, the
 * pull fails, or the token does not advance, so a backlog past sixty-four
 * pages is deferred before the drive idles and a stuck cursor cannot
 * spin. A stale cursor is dropped once; markers keep the replay from
 * posting twice. */
static void wkr_inbox_checkpoint(const struct wkr_drive_opts *opts)
{
    char prev[4096];
    bool retried = false;
    if (!opts)
        return;
#ifdef ZCL_TESTING
    g_wkr_first_note = false;
#endif
    prev[0] = '\0';
    for (;;) {
        int rc = wkr_inbox_page(opts->worker, prev, sizeof(prev));
        if (rc < 0 && !retried) {
            retried = true;
            prev[0] = '\0';
            wkr_drop_cursor(opts->worker);
            continue;
        }
        if (rc <= 0)
            return;
    }
}

/* True when this drive has used its deadline or its job cap. */
static bool wkr_drive_spent(const struct wkr_drive_opts *opts,
                            long long t0_s, long long jobs)
{
    if (platform_time_wall_unix() - t0_s >= opts->deadline_s)
        return true;
    return opts->max_jobs > 0 && jobs >= opts->max_jobs;
}

/* True when the idle streak says the drive should stop. The inbox check
 * runs on the mail wake and on the ordinary end of the wait. */
static bool wkr_after_idle(const struct wkr_drive_opts *opts,
                           struct wkr_idle *idle, long long *idle_ms,
                           long long *wait_s)
{
    bool stop = wkr_drive_idle(opts, idle, idle_ms, wait_s);
    wkr_inbox_checkpoint(opts);
    wkr_mail_resnap(idle);
#ifdef ZCL_TESTING
    if (zcl_devagent_worker_test_after_inbox)
        zcl_devagent_worker_test_after_inbox();
#endif
    return stop;
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
    if (!wkr_state_dir(queuedir, sizeof(queuedir), "queue") ||
        !wkr_lock_open(&lock, lockpath, sizeof(lockpath), queuedir))
        return -1;
    old_term = signal(SIGTERM, wkr_on_term);
    /* A previous drive in this process may have observed a termination
     * request; each drive starts unrequested. A SIGTERM that arrived
     * before the install above kept the old disposition, so clearing
     * here cannot swallow one this handler recorded. */
    g_wkr_term = 0;
    wkr_idle_open(&idle, queuedir, opts->timed_idle_only);
    t0_s = platform_time_wall_unix();
    wait_s = opts->idle_start_s > 0 ? opts->idle_start_s : 1;
    wkr_inbox_checkpoint(opts);
    wkr_mail_resnap(&idle);
    while (!g_wkr_term) {
        long long done;
        if (wkr_pending_reconcile() < 0) break;
        if (wkr_drive_spent(opts, t0_s, jobs))
            break;
        wkr_reap();
        wkr_qsig_take(queuedir, &idle.base);
#ifdef ZCL_TESTING
        if (zcl_devagent_worker_test_before_step)
            zcl_devagent_worker_test_before_step();
#endif
        /* A refused seam processes nothing: idle instead of re-adopting
         * the same orphan in a tight loop. */
        done = wkr_drive_step(opts, exec);
        jobs += done;
        if (done > 0) {
            wkr_inbox_checkpoint(opts);
            wkr_mail_resnap(&idle);
            idle_ms = 0;
            wait_s = opts->idle_start_s > 0 ? opts->idle_start_s : 1;
            continue;
        }
#ifdef ZCL_TESTING
        if (zcl_devagent_worker_test_after_empty_claim)
            zcl_devagent_worker_test_after_empty_claim();
#endif
        if (wkr_after_idle(opts, &idle, &idle_ms, &wait_s))
            break;
    }
    wkr_reap();
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

/* The queue's selector alphabet, checked before copying option text. */
static bool wkr_selector_ok(const char *s)
{
    return strlen(s) <= 128 && strspn(s,
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-:+") == strlen(s);
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
    if (strlen(worker) > 48 || !zcl_devagent_name_ok(worker))
        return "worker is 1-48 of [A-Za-z0-9_.-], excluding . and ..";
    memset(opts, 0, sizeof(*opts));
    session = wkr_leaf_str(request, "session");
    if (!session[0]) {
        (void)snprintf(sess_default, sizeof(sess_default), "s%lld-%ld",
                       (long long)platform_time_wall_unix(),
                       (long)getpid());
        session = sess_default;
    }
    *evidence = "input.session too long";
    if (strlen(session) > 48 || !zcl_devagent_name_ok(session))
        return "session is 1-48 of [A-Za-z0-9_.-], excluding . and ..";
    const char *selector = wkr_leaf_str(request, "model");
    *evidence = "input.model invalid alphabet or length";
    if (!wkr_selector_ok(selector))
        return "execution selector must fit the queue's 128-byte alphabet";
    (void)snprintf(opts->worker, sizeof(opts->worker), "%s", worker);
    (void)snprintf(opts->session, sizeof(opts->session), "%s", session);
    (void)snprintf(opts->model, sizeof(opts->model), "%s",
                   selector);
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

#ifdef ZCL_TESTING
bool zcl_devagent_worker_test_options(const struct zcl_command_request *request);
bool zcl_devagent_worker_test_options(const struct zcl_command_request *request)
{
    struct wkr_drive_opts opts;
    const char *evidence;
    return wkr_leaf_opts(request, &opts, &evidence) == NULL;
}
#endif

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
    /* status is read-only and answers before any run validation, so asking
     * about a resident never needs a worker identity, a model, or a cap.
     * `run` below is reached only for action=run and is unchanged. */
    if (request && request->input &&
        strcmp(wkr_leaf_str(request, "action"), "status") == 0) {
        zcl_native_devagent_worker_status(request, reply);
        return;
    }
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
