/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.agent.worker action=status — ask the resident what it is, without
 * touching anything.
 *
 * ── WHY IT EXISTS ──────────────────────────────────────────────────────────
 * The leaf accepted exactly one action, `run`, so there was no way to ask
 * whether a worker was resident, what it held, or what it was working on. The
 * unit file for zcl-agent-worker@ documents
 * `z23-dev dev agent worker status --worker=<id>` in its install block; that
 * command refused with "action is exactly run". An operator, or a remote
 * driver reading the fleet brief, had to infer liveness from the journal.
 *
 * ── STRICTLY READ-ONLY, AND THAT IS THE CONTRACT ───────────────────────────
 * This path claims nothing, reaps nothing, and writes nothing. Concretely:
 *
 *   - every open is O_RDONLY with NO O_CREAT, so probing a resident that has
 *     never run does not bring its lock file into existence. This is the one
 *     place the difference matters: the drive loop and the queue's own pool
 *     probe both open the lock with O_CREAT, which is correct for a writer and
 *     would be a mutation here.
 *   - no mkdir, no rename, no marker, no mail, no model, no service call.
 *     The root is resolved with platform_state_root_existing(), NOT
 *     platform_state_root(): the latter creates the z23/dev directories when
 *     they are absent, which a status call on a box that has never run a
 *     resident would otherwise do. This was caught by the "creates nothing"
 *     proof, not by reading the call.
 *   - the queue ledger is read WITHOUT taking queue.lock. That is safe because
 *     a row is one O_APPEND write of one line (see native_devagent_queue.c),
 *     so a reader sees whole lines; and it is necessary because taking the
 *     lock would both create the lock file and briefly contend with a live
 *     drive. A status call must never delay the worker it is describing.
 *   - it does not sleep, back off, or wait, so it cannot wake an idle drive:
 *     the worker's idle wait is a directory watch armed on the queue dir, and
 *     nothing here modifies that directory.
 *
 * ── WHAT IT WILL NOT SAY ───────────────────────────────────────────────────
 * `resident` is decided by a non-blocking flock probe of the existing
 * worker.lock, and a held lock is LIVENESS, never work: it says a drive owns
 * the queue, not that a job is running. The active job is reported only from
 * evidence that already exists — a running row in the ledger plus the run
 * directory's own claim.json — and is null when nothing proves one. Every
 * degraded or unknown case carries exactly one token from the closed
 * vocabulary below, so a caller branches on a name rather than on a missing
 * field.
 */

#include "command/native_command.h"

#include "command/native_devagent.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/clock.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(_WIN32)
#define O_CLOEXEC O_NOINHERIT
#else
#include <sys/file.h>
#endif

#define WKS_LEAF "dev.agent.worker"

/* One line of the ledger, and one claim record, both bounded. The ledger is
 * read a line at a time so a long queue never sizes a buffer. */
#define WKS_LINE_CAP 8192u
#define WKS_CLAIM_CAP 8192u

/* The closed reason vocabulary. Exactly one is reported, first applicable,
 * and "" means nothing was degraded. A caller matches these; it never parses
 * prose. */
#define WKS_OK ""
#define WKS_NO_STATE_ROOT "state-root-unavailable"
#define WKS_LOCK_ABSENT "worker-lock-absent"
#define WKS_LOCK_UNREADABLE "worker-lock-unreadable"
#define WKS_QUEUE_ABSENT "queue-ledger-absent"
#define WKS_QUEUE_UNREADABLE "queue-ledger-unreadable"
#define WKS_CLAIM_UNREADABLE "claim-unreadable"

struct wks_view {
    const char *resident; /* "held" | "free" | "unknown" */
    const char *reason;   /* one closed token, or "" */
    bool queue_known;
    long long queued;
    long long running;
    char job_name[128];
    long long job_attempt;
    char job_worker[64];
    char job_session[80];
    bool job_submitted;
    bool job_known;
};

/* ── resident: probe the EXISTING lock, never create one ───────────────── */

/* "held" when some drive owns worker.lock, "free" when it could be taken,
 * "unknown" when the probe itself could not be made. Sets `reason` only for
 * the cases a caller must distinguish. */
static void wks_resident(const char *queuedir, struct wks_view *v)
{
    char path[4096 + 32];
    int fd;

    v->resident = "unknown";
    if (snprintf(path, sizeof(path), "%s/worker.lock", queuedir) >=
        (int)sizeof(path)) {
        v->reason = WKS_LOCK_UNREADABLE;
        return;
    }
    /* No O_CREAT: a resident that has never run leaves no lock file, and
     * asking about it must not create one. Absence is a fact, reported as
     * free with the token naming how it was derived. */
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            v->resident = "free";
            v->reason = WKS_LOCK_ABSENT;
        } else {
            v->reason = WKS_LOCK_UNREADABLE;
        }
        return;
    }
#if !defined(_WIN32)
    /* Non-blocking, and released immediately. flock(2) permits LOCK_EX on a
     * read-only descriptor, so the probe needs no write access. */
    if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
        (void)flock(fd, LOCK_UN);
        v->resident = "free";
    } else if (errno == EWOULDBLOCK || errno == EAGAIN) {
        v->resident = "held";
    } else {
        v->reason = WKS_LOCK_UNREADABLE;
    }
#else
    v->resident = "unknown";
    v->reason = WKS_LOCK_UNREADABLE;
#endif
    (void)close(fd);
}

/* ── queue: count rows from the existing ledger, lockless ───────────────── */

/* The value of one flat "key":"value" or "key":N field in a ledger line.
 * Bounded, and it copies nothing when the key is absent. */
static bool wks_field(const char *line, const char *key, char *out, size_t cap)
{
    char pat[64];
    const char *at, *p;
    size_t n = 0;

    if (snprintf(pat, sizeof(pat), "\"%s\":", key) >= (int)sizeof(pat))
        return false;
    at = strstr(line, pat);
    if (!at)
        return false;
    p = at + strlen(pat);
    if (*p == '"')
        p++;
    while (*p && *p != '"' && *p != ',' && *p != '}' && n + 1 < cap)
        out[n++] = *p++;
    out[n] = '\0';
    return n > 0;
}

/* Count queued and running rows, and remember the newest running row's name
 * and attempt. Last row for a name wins, matching the ledger's own rule. */
static void wks_scan_line(const char *line, struct wks_view *v)
{
    char state[32], name[128], attempt[24];

    if (!wks_field(line, "state", state, sizeof(state)))
        return;
    if (strcmp(state, "queued") == 0) {
        v->queued++;
        return;
    }
    if (strcmp(state, "running") != 0)
        return;
    v->running++;
    if (!wks_field(line, "name", name, sizeof(name)))
        return;
    (void)snprintf(v->job_name, sizeof(v->job_name), "%s", name);
    v->job_attempt = wks_field(line, "attempt", attempt, sizeof(attempt))
                         ? (long long)strtoll(attempt, NULL, 10)
                         : 1;
}

static void wks_queue(const char *queuedir, struct wks_view *v)
{
    char path[4096 + 32];
    char line[WKS_LINE_CAP];
    FILE *f;
    struct stat st;

    if (snprintf(path, sizeof(path), "%s/queue.jsonl", queuedir) >=
        (int)sizeof(path)) {
        if (!v->reason[0])
            v->reason = WKS_QUEUE_UNREADABLE;
        return;
    }
    if (stat(path, &st) != 0) {
        /* No ledger is a measured emptiness on a box that has queued
         * nothing, distinct from one that cannot be read. */
        v->queue_known = true;
        if (!v->reason[0])
            v->reason = WKS_QUEUE_ABSENT;
        return;
    }
    f = fopen(path, "rb");
    if (!f) {
        if (!v->reason[0])
            v->reason = WKS_QUEUE_UNREADABLE;
        return;
    }
    while (fgets(line, sizeof(line), f))
        wks_scan_line(line, v);
    (void)fclose(f);
    v->queue_known = true;
}

/* ── the active job, only from evidence that already exists ─────────────── */

static const char *wks_claim_string(const struct json_value *claim,
                                   const char *key, size_t cap)
{
    const struct json_value *field = json_get(claim, key);
    if (!field || field->type != JSON_STR)
        return NULL;
    const char *s = json_get_str(field);
    return s[0] && strlen(s) < cap ? s : NULL;
}

static bool wks_claim(const char *buf, size_t n, struct wks_view *v)
{
    struct json_value claim;
    json_init(&claim);
    bool ok = json_read(&claim, buf, n) && claim.type == JSON_OBJ;
    const struct json_value *name = json_get(&claim, "name");
    const struct json_value *attempt = json_get(&claim, "attempt");
    const char *worker = wks_claim_string(&claim, "worker", sizeof(v->job_worker));
    const char *session = wks_claim_string(&claim, "session", sizeof(v->job_session));
    const struct json_value *submitted = json_get(&claim, "submitted");
    ok = ok && name && name->type == JSON_STR &&
         strcmp(json_get_str(name), v->job_name) == 0 &&
         attempt && attempt->type == JSON_INT &&
         json_get_int(attempt) == v->job_attempt &&
         worker && session &&
         submitted && submitted->type == JSON_BOOL;
    if (ok) {
        (void)snprintf(v->job_worker, sizeof(v->job_worker), "%s", worker);
        (void)snprintf(v->job_session, sizeof(v->job_session), "%s", session);
        v->job_submitted = json_get_bool(submitted);
    }
    json_free(&claim);
    return ok;
}

/* Read the run directory's own claim.json for the running row. Nothing is
 * created; an unreadable claim leaves the job unproven rather than guessed. */
static void wks_job(const struct wks_view *ro, struct wks_view *v)
{
    char root[4096], path[4096 + 256];
    char buf[WKS_CLAIM_CAP];
    FILE *f;
    size_t n;

    if (!ro->job_name[0])
        return;
    if (!platform_state_root_existing(root, sizeof(root)))
        return;
    if (snprintf(path, sizeof(path), "%s/engine/%s/a%lld/claim.json", root,
                 ro->job_name, ro->job_attempt) >= (int)sizeof(path))
        return;
    f = fopen(path, "rb");
    if (!f) {
        v->reason = v->reason[0] ? v->reason : WKS_CLAIM_UNREADABLE;
        return;
    }
    n = fread(buf, 1, sizeof(buf) - 1u, f);
    bool complete = !ferror(f) && feof(f);
    (void)fclose(f);
    buf[n] = '\0';
    v->job_known = complete && wks_claim(buf, n, v);
    if (!v->job_known && !v->reason[0])
        v->reason = WKS_CLAIM_UNREADABLE;
}

/* ── reply ─────────────────────────────────────────────────────────────── */

/* The optional `worker` input, echoed so a caller can bind the answer to the
 * identity it asked about. worker.lock is one per box, not one per identity,
 * so this names the question and never narrows the probe. */
static const char *wks_worker_name(const struct zcl_command_request *request)
{
    const struct json_value *v =
        request && request->input ? json_get(request->input, "worker") : NULL;
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    return s ? s : "";
}

static bool wks_emit_job(struct json_value *out, const struct wks_view *v)
{
    struct json_value job;
    bool ok;

    if (!v->job_name[0]) {
        struct json_value nv;
        json_init(&nv);
        json_set_null(&nv);
        ok = json_push_kv(out, "job", &nv);
        json_free(&nv);
        return ok;
    }
    json_init(&job);
    json_set_object(&job);
    ok = json_push_kv_str(&job, "name", v->job_name) &&
         json_push_kv_int(&job, "attempt", v->job_attempt) &&
         json_push_kv_bool(&job, "claim_read", v->job_known) &&
         json_push_kv_str(&job, "worker", v->job_worker) &&
         json_push_kv_str(&job, "session", v->job_session) &&
         json_push_kv_bool(&job, "submitted", v->job_submitted) &&
         json_push_kv(out, "job", &job);
    json_free(&job);
    return ok;
}

static bool wks_emit_count(struct json_value *out, const char *key,
                           long long value, bool known)
{
    struct json_value nv;
    bool ok;

    if (known)
        return json_push_kv_int(out, key, value);
    json_init(&nv);
    json_set_null(&nv);
    ok = json_push_kv(out, key, &nv);
    json_free(&nv);
    return ok;
}

void zcl_native_devagent_worker_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct wks_view v;
    char queuedir[4096];
    const char *worker;
    int64_t t0 = platform_time_monotonic_us();

    memset(&v, 0, sizeof(v));
    v.reason = WKS_OK;
    v.resident = "unknown";
    v.job_attempt = 1;
    worker = wks_worker_name(request);

    if (!platform_state_root_existing(queuedir, sizeof(queuedir)) ||
        snprintf(queuedir + strlen(queuedir),
                 sizeof(queuedir) - strlen(queuedir), "/queue") < 0) {
        v.reason = WKS_NO_STATE_ROOT;
    } else {
        wks_resident(queuedir, &v);
        wks_queue(queuedir, &v);
        {
            struct wks_view ro = v;
            wks_job(&ro, &v);
        }
    }
    json_set_object(&reply->data);
    if (!json_push_kv_str(&reply->data, "leaf", WKS_LEAF) ||
        !json_push_kv_str(&reply->data, "action", "status") ||
        !json_push_kv_str(&reply->data, "worker", worker) ||
        !json_push_kv_str(&reply->data, "resident", v.resident) ||
        !wks_emit_count(&reply->data, "queued", v.queued, v.queue_known) ||
        !wks_emit_count(&reply->data, "running", v.running, v.queue_known) ||
        !wks_emit_job(&reply->data, &v) ||
        !json_push_kv_str(&reply->data, "reason", v.reason) ||
        /* Stated in the reply, because a caller that will poll this needs to
         * know it costs nothing and moves nothing. */
        !json_push_kv_bool(&reply->data, "read_only", true) ||
        !json_push_kv_int(&reply->data, "latency_us",
                          (long long)(platform_time_monotonic_us() - t0))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "INTERNAL",
                               "status", false, false,
                               "the status reply could not be composed",
                               WKS_LEAF);
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}
