/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.queue — post, dispatch, reap, and inspect async
 *          flash-unit runs as one durable, non-blocking queue, so unit
 *          dispatch is a typed API instead of shell scripts.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. The interim fleet dispatch is four shell scripts that pop lines,
 * flock pool entries, compose task files, and launch the harness through
 * bash -c. Shell cannot be typed, validated, or discovered; this leaf keeps
 * the behavior (post/next/reap/status) and drops the shell.
 *
 * INPUT (zcl.agent_queue_input.v1)
 *   action   string, required: post | next | claim | reap | status | cancel.
 *            Also the first positional, so `z23 dev agent queue post ...`
 *            works.
 *   worker   claim only, required 1-48 [A-Za-z0-9_.-]: the resident worker.
 *   session  claim only, required 1-48 [A-Za-z0-9_.-]: this worker run.
 *   kind     post only: leaf | doc | file | fix-gate.
 *   name     post and cancel: [A-Za-z0-9_.-]{1,64}, never "." or ".." (a
 *            name is one path segment under engine/). Cancel drops queued
 *            rows with the name and refuses running names; terminal
 *            outcomes are never rewritten.
 *   group    post only, required for kind=file: a test group name.
 *   path     post only, required for kind=doc|file: a repo-relative path
 *            (never absolute, never containing ..).
 *   brief    post only, required for kind=doc|file: an existing file inside
 *            the repo or the state dir; stored as its absolute path.
 *   model    post only, optional model id, default picks flash until
 *            attempt 3, then the stronger model.
 *   attempt  post only, optional integer >= 1, default 1.
 *   priority post only, optional integer 0..3 (P0 correctness/custody,
 *            P1 node, P2 apps, P3 infrastructure), default 3.
 *   depends_on post only, optional name: this row is READY only once
 *            the CURRENT attempt of that name (the newest one any live row
 *            or outcome carries) ends in a closed pass. An unknown,
 *            unfinished, retrying or failed dependency never unlocks it,
 *            and a late PASS for an older attempt never does either.
 *            The three names owner, trust, and proof are not queue rows.
 *            They name an external party. claim parks every queued row
 *            that depends on one of them as state WAITING_EXTERNAL, writes
 *            queue/wait/<name>.json, and claims the next runnable row in
 *            the same call. WAITING_EXTERNAL is a worker-task wait. It is
 *            not a fleet.steer delivery state, it does not occupy the
 *            worker, and cancel drops it the way it drops a queued row.
 *   json     status only, optional bool: with true the reply carries the
 *            structured shape only; otherwise screen carries the human
 *            rendering too.
 *   cwd      optional string: checkout root override for path checks.
 *
 * READY ORDER. claim and next take the READY queued row with the lowest
 * (priority, seq): its depends_on dependency passed on its current attempt,
 * no other row with its name already running, and (claim only) the row's
 * own name not already completed. status reports the same gates per queued
 * row (ready, blocker) and never runs or cancels a held row. Nothing else
 * reorders work.
 *
 * ONE LIVE ROW PER NAME. A name is one run directory, so post refuses
 * NAME_IN_FLIGHT while a row with that name is queued or running, and the
 * existing row keeps its seq and attempt. Cancel or a terminal outcome
 * frees the name; resume re-posts it then.
 *
 * BACKPRESSURE. post refuses QUEUE_FULL while DVQ_QUEUED_MAX rows are
 * already queued, so an intake burst can never grow the ledger unbounded.
 *
 * STATE. <platform_state_root>/queue (0700): queue.jsonl (one JSON object
 * per line, O_APPEND single write, 0600), queue.lock (the short scheduler
 * flock), pool.txt (operator-listed warm worktree directories, one per
 * line), outcomes.jsonl, and .reap_stamp. Runs live in
 * <platform_state_root>/engine/<name>/a<attempt>/. No verb blocks on a
 * model, a build, or another process; a long-lived loop is the caller's
 * business.
 *
 * LAUNCH. next runs the harness detached with the interim shell's argv
 * (systemd-run with a unit-local flock when available, else double-fork
 * plus setsid with the worktree lock fd inherited). The harness's stdout
 * lands in the run's run.out in both branches (a truncated unit stream
 * under systemd, the spawn log otherwise). The dev binary the harness
 * gates through arrives as ZCL_Z23_BIN: an operator override wins,
 * otherwise the primed build/bin/z23-dev inside the running worktree;
 * unset means inherit. The harness binary itself is ZCL_ENGINE_UNIT_BIN
 * or zclassic23-engine-unit on PATH.
 *
 * OUTPUT (zcl.agent_queue.v1) on ok=true: leaf is always "dev.agent.queue",
 * plus per action: post {seq, name, state:"queued"}; next {seq, name,
 * worktree, pid_or_unit, state:"running"} or {state:"no_free_worktree"} or
 * {state:"empty"}; claim {seq, name, attempt, rundir, worker, session,
 * state:"running"} or {state:"empty"}; reap {state:"reaped",
 * outcomes:[...], requeued, reclaimed}; status {queued (each with ready
 * and blocker: null, or {ref, state, attempt, verdict} naming what holds
 * it), queued_total, queued_ready, running (each with owner_liveness
 * running|dead|unknown bound to PID and kernel birth), outcomes,
 * pool} plus screen unless json=true; cancel {state:"cancelled", name,
 * cancelled:N} or CANCEL_RUNNING/CANCEL_NOT_FOUND. claim refuses
 * CLAIM_COMPLETED when the closed predicate already finished the name.
 * reap's reclaimed counts running rows returned to queued because their
 * claimant died before the run's first artifact (see orphan reclaim).
 *
 * PROCESS RULE. Spawn only through zcl_spawn_detached() from util/spawn.h.
 * popen(), system() and a shell command string are forbidden and gated.
 *
 * Implement this file only; the test
 * tests/harness/src/test_devagent_queue.c is the acceptance bar and must
 * not be edited.
 */

/* realpath() is declared by glibc only through the fortify inline unless a
 * feature-test macro asks for it; without this the file compiles today by
 * accident of -O2 and is a hard C23 error at -O0 or on another libc. Must
 * precede the first #include, which is where <features.h> is read. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/native_command.h"
#include "command/native_devagent.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/os_proc.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#include "util/spawn.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <direct.h>
#include <io.h>
#else
#include <sys/file.h>
#endif

/* mingw's <fcntl.h> has no O_CLOEXEC: descriptors on Windows are not
 * inherited unless the handle is explicitly marked inheritable, so the
 * flag is a no-op there rather than a missing guarantee. */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define DVQ_LEAF "dev.agent.queue"

/* Bounded budgets: every file this leaf reads or writes is capped, so a
 * hostile state dir cannot grow the process without bound. */
#define DVQ_LINE_CAP 8192
#define DVQ_POOL_CAP (64u * 1024u)
#define DVQ_FILE_CAP (1024u * 1024u)
#define DVQ_TASK_CAP (128u * 1024u)
#define DVQ_SNIPPET_CAP (32u * 1024u)
#define DVQ_HARNESS_NAME "zclassic23-engine-unit"
#define DVQ_QUEUED_MAX 64
#define DVQ_PRIORITY_DEFAULT 3

/* ── failure ───────────────────────────────────────────────────────────── */

static void dvq_fail(struct zcl_command_reply *reply, const char *code,
                     const char *phase, const char *msg, const char *evidence)
{
    (void)json_push_kv_str(&reply->data, "leaf", DVQ_LEAF);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, phase, false,
                           false, msg, evidence);
    reply->error.human_action_required = true;
}

/* ── input accessors ───────────────────────────────────────────────────── */

static const char *dvq_str(const struct zcl_command_request *req,
                           const char *key)
{
    const struct json_value *v;
    if (!req || !req->input)
        return NULL;
    v = json_get(req->input, key);
    if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
        return json_get_str(v);
    return NULL;
}

static bool dvq_attempt(const struct zcl_command_request *req,
                        long long *out)
{
    const struct json_value *v;
    if (!req || !req->input || !out)
        return false;
    v = json_get(req->input, "attempt");
    if (!v)
        return false;
    if (v->type == JSON_INT && json_get_int(v) >= 1) {
        *out = json_get_int(v);
        return true;
    }
    return false;
}

/* ── validators ────────────────────────────────────────────────────────── */

/* A name is exactly one path segment under engine/<name>/: it must match
 * [A-Za-z0-9_.-]{1,64} and, like every segment dvq_path_ok accepts, it must
 * never be "." or ".." — a name of ".." would resolve the run directory one
 * level above the intended engine/ subtree. Dots inside a name stay legal.
 *
 * The grammar itself lives in zcl_devagent_name_ok so that whatever names
 * queue work — a directive ref included — is judged by this exact rule and
 * cannot accept work this queue would refuse. */
static bool dvq_name_ok(const char *s)
{
    return zcl_devagent_name_ok(s);
}

static bool dvq_kind_ok(const char *s)
{
    return s && (strcmp(s, "leaf") == 0 || strcmp(s, "doc") == 0 ||
                 strcmp(s, "file") == 0 || strcmp(s, "fix-gate") == 0);
}

static bool dvq_group_ok(const char *s)
{
    size_t n;
    if (!s || !s[0])
        return false;
    n = strlen(s);
    if (n > 64)
        return false;
    for (const char *p = s; *p; p++) {
        bool ok = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                  (*p >= '0' && *p <= '9') || *p == '_' || *p == '-';
        if (!ok)
            return false;
    }
    return true;
}

static bool dvq_model_ok(const char *s)
{
    size_t n;
    if (!s || !s[0])
        return false;
    n = strlen(s);
    if (n > 128)
        return false;
    for (const char *p = s; *p; p++) {
        bool ok = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                  (*p >= '0' && *p <= '9') || *p == '_' || *p == '.' ||
                  *p == '-' || *p == ':' || *p == '+';
        if (!ok)
            return false;
    }
    return true;
}

/* A unit relpath is anchored at the worktree root: relative, no drive or
 * root prefix, no parent escape, no empty segments. */
static bool dvq_path_ok(const char *s)
{
    size_t n;
    if (!s || !s[0])
        return false;
    n = strlen(s);
    if (n > 256 || s[0] == '/' || s[0] == '\\' || s[0] == '~')
        return false;
    if (s[1] == ':' && ((s[0] >= 'a' && s[0] <= 'z') ||
                        (s[0] >= 'A' && s[0] <= 'Z')))
        return false;
    for (const char *p = s; *p;) {
        const char *seg = p;
        while (*p && *p != '/' && *p != '\\')
            p++;
        if ((size_t)(p - seg) == 0 || ((size_t)(p - seg) == 1 && seg[0] == '.') ||
            ((size_t)(p - seg) == 2 && seg[0] == '.' && seg[1] == '.'))
            return false;
        for (const char *q = seg; q < p; q++) {
            bool ok = (*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z') ||
                      (*q >= '0' && *q <= '9') || *q == '_' || *q == '.' ||
                      *q == '-' || *q == '+';
            if (!ok)
                return false;
        }
        if (*p)
            p++;
    }
    return true;
}

/* ── state dirs ────────────────────────────────────────────────────────── */

struct dvq_dirs {
    char root[4096];
    char queue[4096];
    char engine[4096];
};

static bool dvq_mkdir_one(const char *path)
{
    struct stat st;
#if defined(_WIN32)
    if (_mkdir(path) == 0)
        return true;
#else
    if (mkdir(path, 0700) == 0)
        return true;
#endif
    if (errno != EEXIST)
        return false;
    return stat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFDIR;
}

static bool dvq_dirs_resolve(struct dvq_dirs *d, bool create)
{
    int n;
    if (!d || !(create ? platform_state_root(d->root, sizeof(d->root))
                       : platform_state_root_existing(d->root, sizeof(d->root))))
        return false;
    n = snprintf(d->queue, sizeof(d->queue), "%s/queue", d->root);
    if (n <= 0 || (size_t)n >= sizeof(d->queue))
        return false;
    n = snprintf(d->engine, sizeof(d->engine), "%s/engine", d->root);
    if (n <= 0 || (size_t)n >= sizeof(d->engine))
        return false;
    return !create || (dvq_mkdir_one(d->queue) && dvq_mkdir_one(d->engine));
}

/* ── time ──────────────────────────────────────────────────────────────── */

static void dvq_now_iso(char out[64])
{
    time_t now = platform_time_wall_time_t();
    struct tm tm_utc;
    memset(&tm_utc, 0, sizeof(tm_utc));
#if defined(_WIN32)
    (void)gmtime_s(&tm_utc, &now);
#else
    (void)gmtime_r(&now, &tm_utc);
#endif
    (void)strftime(out, 64, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

/* ── JSON string escaping (rows are machine-written, never trusted) ────── */

static bool dvq_escape(const char *in, char *out, size_t cap)
{
    size_t used = 0;
    if (!in || !out || cap == 0)
        return false;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        const char *rep = NULL;
        char tmp[8];
        switch (*p) {
        case '"': rep = "\\\""; break;
        case '\\': rep = "\\\\"; break;
        case '\n': rep = "\\n"; break;
        case '\r': rep = "\\r"; break;
        case '\t': rep = "\\t"; break;
        default: break;
        }
        if (rep) {
            if (used + 2 >= cap)
                return false;
            out[used++] = rep[0];
            out[used++] = rep[1];
        } else if (*p < 0x20) {
            int w = snprintf(tmp, sizeof(tmp), "\\u%04x", *p);
            if (w != 6 || used + 6 >= cap)
                return false;
            memcpy(out + used, tmp, 6);
            used += 6;
        } else {
            if (used + 1 >= cap)
                return false;
            out[used++] = (char)*p;
        }
    }
    if (used >= cap)
        return false;
    out[used] = '\0';
    return true;
}

/* ── minimal per-line field extraction (reap/status skip malformed rows) ─ */

static bool dvq_line_int(const char *line, const char *key, long long *out)
{
    char pat[64];
    const char *p;
    char *end;
    long long n;
    (void)snprintf(pat, sizeof(pat), "\"%s\":", key);
    p = strstr(line, pat);
    if (!p)
        return false;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t')
        p++;
    errno = 0;
    n = strtoll(p, &end, 10);
    if (errno != 0 || end == p)
        return false;
    *out = n;
    return true;
}

static bool dvq_line_str(const char *line, const char *key, char *out,
                         size_t cap)
{
    char pat[64];
    const char *p;
    size_t used = 0;
    (void)snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    p = strstr(line, pat);
    if (!p || !out || cap == 0)
        return false;
    p += strlen(pat);
    while (*p && *p != '"') {
        if (used + 2 > cap)
            return false;
        if (*p == '\\' && p[1]) {
            if (p[1] == 'u' && isxdigit((unsigned char)p[2]) &&
                isxdigit((unsigned char)p[3]) &&
                isxdigit((unsigned char)p[4]) &&
                isxdigit((unsigned char)p[5])) {
                out[used++] = '?';
                p += 6;
            } else {
                out[used++] = p[1];
                p += 2;
            }
        } else {
            out[used++] = *p++;
        }
    }
    if (*p != '"')
        return false;
    out[used] = '\0';
    return true;
}

/* ── bounded file IO ───────────────────────────────────────────────────── */

static bool dvq_read_file(const char *path, char *out, size_t cap,
                          size_t *len_out)
{
    FILE *f;
    size_t n;
    if (!path || !out || cap == 0)
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    n = fread(out, 1, cap - 1, f);
    if (ferror(f)) {
        (void)fclose(f);
        return false;
    }
    /* A file that does not fit the budget is refused, never truncated. */
    if (!feof(f)) {
        (void)fclose(f);
        return false;
    }
    out[n] = '\0';
    (void)fclose(f);
    if (len_out)
        *len_out = n;
    return true;
}

/* One write() per row: with O_APPEND each row lands atomically, so two
 * concurrent posters never interleave bytes. */
static bool dvq_append_row(const char *path, const char *line, size_t len)
{
    int fd;
    ssize_t w;
    if (!path || !line || len == 0)
        return false;
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    w = write(fd, line, len);
    (void)close(fd);
    return w == (ssize_t)len;
}

static bool dvq_write_file(const char *path, const char *text, size_t len)
{
    FILE *f;
    if (!path || !text)
        return false;
    f = fopen(path, "wb");
    if (!f)
        return false;
    if (len > 0 && fwrite(text, 1, len, f) != len) {
        (void)fclose(f);
        return false;
    }
    return fclose(f) == 0;
}

/* ── queue rows ────────────────────────────────────────────────────────── */

struct dvq_row {
    long long seq;
    char ts[64];
    char kind[16];
    char name[80];
    char group[80];
    char path[512];
    char brief[4096];
    char model[160];
    long long attempt;
    char state[24]; /* WAITING_EXTERNAL is 17 characters */
    char worktree[4096];
    char pid_or_unit[128];
    long long started;
    long long priority; /* 0..3, P0 first */
    char depends_on[80]; /* dependency name, "" for none */
    long long owner_pid;   /* process that marked the row running, 0 unknown */
    long long owner_start; /* its kernel start token, 0 unknown */
};

/* The READY-order fields. Rows written before they existed carry neither:
 * they read as P3 with no dependency, exactly the order they had. */
static void dvq_parse_order(const char *line, struct dvq_row *r)
{
    if (!dvq_line_int(line, "priority", &r->priority) || r->priority < 0 ||
        r->priority > 3)
        r->priority = DVQ_PRIORITY_DEFAULT;
    (void)dvq_line_str(line, "depends_on", r->depends_on,
                       sizeof(r->depends_on));
}

/* The running row's claimant. Rows written before it existed carry
 * neither field and read as unknown, which reap never reclaims. */
static void dvq_parse_owner(const char *line, struct dvq_row *r)
{
    (void)dvq_line_int(line, "owner_pid", &r->owner_pid);
    (void)dvq_line_int(line, "owner_start", &r->owner_start);
}

/* Stamp the process marking the row running, so reap can tell a live
 * claimant from one that died before the run's first artifact. */
static void dvq_stamp_owner(struct dvq_row *r)
{
    uint64_t token = 0;
    uint64_t pid = os_proc_current_pid();
    r->owner_pid = pid <= (uint64_t)LLONG_MAX ? (long long)pid : 0;
    r->owner_start = os_proc_pid_start_token(pid, &token) &&
                             token <= (uint64_t)LLONG_MAX
                         ? (long long)token
                         : 0;
}

static void dvq_clear_owner(struct dvq_row *r)
{
    r->owner_pid = 0;
    r->owner_start = 0;
}

/* A running row is not proof that its claimant still exists. Bind the PID
 * to the kernel birth token so reuse cannot turn an orphan into a live job. */
static const char *dvq_owner_liveness(const struct dvq_row *r)
{
    uint64_t token = 0;
    enum os_proc_liveness live;
    if (r->owner_pid <= 0 || r->owner_start <= 0)
        return "unknown";
    live = os_proc_pid_liveness((uint64_t)r->owner_pid);
    if (live == OS_PROC_LIVENESS_DEAD)
        return "dead";
    if (live != OS_PROC_LIVENESS_RUNNING ||
        !os_proc_pid_start_token((uint64_t)r->owner_pid, &token))
        return "unknown";
    return token == (uint64_t)r->owner_start ? "running" : "dead";
}

static bool dvq_parse_row(const char *line, struct dvq_row *r)
{
    if (!line || !line[0] || !r)
        return false;
    memset(r, 0, sizeof(*r));
    if (!dvq_line_int(line, "seq", &r->seq) || r->seq < 1)
        return false;
    (void)dvq_line_str(line, "ts", r->ts, sizeof(r->ts));
    if (!dvq_line_str(line, "kind", r->kind, sizeof(r->kind)) ||
        !dvq_kind_ok(r->kind))
        return false;
    if (!dvq_line_str(line, "name", r->name, sizeof(r->name)) ||
        !dvq_name_ok(r->name))
        return false;
    (void)dvq_line_str(line, "group", r->group, sizeof(r->group));
    (void)dvq_line_str(line, "path", r->path, sizeof(r->path));
    (void)dvq_line_str(line, "brief", r->brief, sizeof(r->brief));
    (void)dvq_line_str(line, "model", r->model, sizeof(r->model));
    if (!dvq_line_int(line, "attempt", &r->attempt) || r->attempt < 1)
        return false;
    if (!dvq_line_str(line, "state", r->state, sizeof(r->state)))
        return false;
    (void)dvq_line_str(line, "worktree", r->worktree, sizeof(r->worktree));
    (void)dvq_line_str(line, "pid_or_unit", r->pid_or_unit,
                       sizeof(r->pid_or_unit));
    (void)dvq_line_int(line, "started", &r->started);
    dvq_parse_order(line, r);
    dvq_parse_owner(line, r);
    return true;
}

static bool dvq_encode_row(const struct dvq_row *r, char *out, size_t cap,
                           size_t *len_out)
{
    char esc_kind[32], esc_name[160], esc_group[160], esc_path[1024];
    char esc_brief[8192], esc_model[320], esc_ts[128], esc_state[32];
    char esc_wt[8192], esc_unit[256], esc_dep[512];
    int w;
    if (!r || !out || cap == 0)
        return false;
    if (!dvq_escape(r->kind, esc_kind, sizeof(esc_kind)) ||
        !dvq_escape(r->name, esc_name, sizeof(esc_name)) ||
        !dvq_escape(r->group, esc_group, sizeof(esc_group)) ||
        !dvq_escape(r->path, esc_path, sizeof(esc_path)) ||
        !dvq_escape(r->brief, esc_brief, sizeof(esc_brief)) ||
        !dvq_escape(r->model, esc_model, sizeof(esc_model)) ||
        !dvq_escape(r->ts, esc_ts, sizeof(esc_ts)) ||
        !dvq_escape(r->state, esc_state, sizeof(esc_state)) ||
        !dvq_escape(r->worktree, esc_wt, sizeof(esc_wt)) ||
        !dvq_escape(r->pid_or_unit, esc_unit, sizeof(esc_unit)))
        return false;
    /* At most 79 bytes, 6x worst-case escaping: always fits esc_dep. */
    (void)dvq_escape(r->depends_on, esc_dep, sizeof(esc_dep));
    w = snprintf(out, cap,
                 "{\"seq\":%lld,\"ts\":\"%s\",\"kind\":\"%s\",\"name\":\"%s\","
                 "\"group\":\"%s\",\"path\":\"%s\",\"brief\":\"%s\","
                 "\"model\":\"%s\",\"attempt\":%lld,\"state\":\"%s\","
                 "\"worktree\":\"%s\",\"pid_or_unit\":\"%s\","
                 "\"started\":%lld,\"priority\":%lld,\"depends_on\":\"%s\","
                 "\"owner_pid\":%lld,\"owner_start\":%lld}\n",
                 r->seq, esc_ts, esc_kind, esc_name, esc_group, esc_path,
                 esc_brief, esc_model, r->attempt, esc_state, esc_wt,
                 esc_unit, r->started, r->priority, esc_dep, r->owner_pid,
                 r->owner_start);
    if (w <= 0 || (size_t)w >= cap)
        return false;
    if (len_out)
        *len_out = (size_t)w;
    return true;
}

/* Load every parseable row. Malformed lines are skipped, never fatal: the
 * queue survives a foreign write the way pull survives one. A missing file
 * is an empty queue (true, no rows); an unreadable one is false. */
static bool dvq_load_rows(const char *qpath, struct dvq_row **rows_out,
                          size_t *n_out)
{
    char *text;
    struct dvq_row *rows = NULL;
    size_t n = 0, cap = 0;
    char *save = NULL, *line;
    int read_errno = 0;
    if (!qpath || !rows_out || !n_out)
        return false;
    *rows_out = NULL;
    *n_out = 0;
    text = (char *)zcl_malloc(DVQ_FILE_CAP, "devagent.queue.file");
    if (!text)
        return false;
    if (!dvq_read_file(qpath, text, DVQ_FILE_CAP, NULL)) {
        read_errno = errno;
        free(text);
        return read_errno == ENOENT;
    }
    for (line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        struct dvq_row r;
        struct dvq_row *grow;
        if (!dvq_parse_row(line, &r))
            continue;
        if (n == cap) {
            size_t ncap = cap == 0 ? 16 : cap * 2;
            if (ncap > 65536)
                break;
            grow = (struct dvq_row *)zcl_realloc(
                rows, ncap * sizeof(*rows), "devagent.queue.rows");
            if (!grow)
                break;
            rows = grow;
            cap = ncap;
        }
        rows[n++] = r;
    }
    free(text);
    *rows_out = rows;
    *n_out = n;
    return true;
}

/* ── the short scheduler flock ─────────────────────────────────────────── */

static int dvq_lock(const char *queuedir)
{
    char path[4096 + 32];
    int fd;
    if (!queuedir ||
        snprintf(path, sizeof(path), "%s/queue.lock", queuedir) >=
            (int)sizeof(path))
        return -1;
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
#if !defined(_WIN32)
    if (flock(fd, LOCK_EX) != 0) {
        (void)close(fd);
        return -1;
    }
#endif
    return fd;
}

static void dvq_unlock(int fd)
{
    if (fd < 0)
        return;
#if !defined(_WIN32)
    (void)flock(fd, LOCK_UN);
#endif
    (void)close(fd);
}

/* ── brief containment ─────────────────────────────────────────────────── */

static bool dvq_abs_path(const char *in, char *out, size_t cap)
{
    if (!in || !out || cap == 0)
        return false;
#if defined(_WIN32)
    if (!_fullpath(out, in, cap))
        return false;
#else
    if (!realpath(in, out))
        return false;
#endif
    return out[0] != '\0';
}

static bool dvq_under(const char *path, const char *dir)
{
    size_t n;
    if (!path || !dir || !dir[0])
        return false;
    n = strlen(dir);
    if (strncmp(path, dir, n) != 0)
        return false;
    return path[n] == '/' || path[n] == '\\' || path[n] == '\0';
}

/* A file unit's path is its write scope: one to four repo-relative
 * prefixes joined by ',', each held to dvq_path_ok. */
static bool dvq_scope_path_ok(const char *s)
{
    char one[260];
    size_t count = 0;
    const char *at = s;
    if (!s || !s[0] || strlen(s) >= 512)
        return false;
    for (;;) {
        const char *end = strchr(at, ',');
        size_t n = end ? (size_t)(end - at) : strlen(at);
        if (++count > 4 || n == 0 || n >= sizeof(one))
            return false;
        memcpy(one, at, n);
        one[n] = '\0';
        if (!dvq_path_ok(one))
            return false;
        if (!end)
            return true;
        at = end + 1;
    }
}

/* Resolve a post-time brief file to its absolute path, refusing anything
 * outside the checkout and the state root. */
static bool dvq_resolve_brief(const struct zcl_command_request *req,
                              const char *brief, const char *statert,
                              char *out, size_t cap)
{
    char abs[4096];
    char root[4096];
    const char *cwd;
    if (!brief || !statert || !out || cap == 0)
        return false;
    if (!dvq_abs_path(brief, abs, sizeof(abs)))
        return false;
    cwd = dvq_str(req, "cwd");
    root[0] = '\0';
    (void)zcl_devagent_checkout_root(cwd && cwd[0] ? cwd : ".", root,
                                     sizeof(root));
    if ((root[0] && dvq_under(abs, root)) || dvq_under(abs, statert)) {
        if (strlen(abs) >= cap)
            return false;
        memcpy(out, abs, strlen(abs) + 1);
        return true;
    }
    return false;
}

/* ── post ──────────────────────────────────────────────────────────────── */

/* The optional READY-order inputs. Absent keeps the P3/no-dependency
 * default; a present value of the wrong shape is refused, never coerced. */
static bool dvq_post_order(const struct zcl_command_request *req,
                           const char *name, struct dvq_row *r,
                           const char **why)
{
    const struct json_value *v = json_get(req->input, "priority");
    const char *dep = dvq_str(req, "depends_on");
    r->priority = DVQ_PRIORITY_DEFAULT;
    if (v) {
        if (v->type != JSON_INT || json_get_int(v) < 0 ||
            json_get_int(v) > 3) {
            *why = "input.priority is not an integer 0..3";
            return false;
        }
        r->priority = json_get_int(v);
    }
    if (dep && dep[0]) {
        if (!dvq_name_ok(dep) || strcmp(dep, name) == 0) {
            *why = "input.depends_on is not another queue name";
            return false;
        }
        (void)snprintf(r->depends_on, sizeof(r->depends_on), "%s", dep);
    }
    return true;
}

/* attempt, model and the READY-order inputs: each wrong shape refuses with
 * its own message, and nothing is stored. */
static bool dvq_post_scalars(const struct zcl_command_request *req,
                             const char *name, const char *model,
                             long long *attempt, struct dvq_row *r,
                             const char **msg, const char **why)
{
    if (json_get(req->input, "attempt") && !dvq_attempt(req, attempt)) {
        *msg = "attempt is an integer attempt number, 1 or more";
        *why = "input.attempt has the wrong shape";
        return false;
    }
    if (model && !dvq_model_ok(model)) {
        *msg = "model is at most 128 model-id characters";
        *why = "input.model misspelled";
        return false;
    }
    *msg = "priority is 0..3 and depends_on names another queue row";
    return dvq_post_order(req, name, r, why);
}

static size_t dvq_count_queued(const struct dvq_row *rows, size_t n)
{
    size_t queued = 0;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(rows[i].state, "queued") == 0)
            queued++;
    }
    return queued;
}

/* The live row (queued or running) carrying name, or -1. A name is one
 * run directory, so at most one live row may carry it. */
static long dvq_live_row(const struct dvq_row *rows, size_t n,
                         const char *name, const char *state)
{
    for (size_t i = 0; i < n; i++) {
        if (strcmp(rows[i].name, name) != 0)
            continue;
        if (state ? strcmp(rows[i].state, state) == 0
                  : (strcmp(rows[i].state, "queued") == 0 ||
                     strcmp(rows[i].state, "running") == 0 ||
                     strcmp(rows[i].state, "WAITING_EXTERNAL") == 0))
            return (long)i;
    }
    return -1;
}

/* post admission under the lock: one live row per name, then the queued
 * bound. On refusal code/msg/evidence name why; the ledger is untouched,
 * so the live row keeps its seq and attempt. */
static bool dvq_post_admit(const struct dvq_row *rows, size_t n,
                           const char *name, const char **code,
                           const char **msg, char *evidence, size_t cap)
{
    long at = dvq_live_row(rows, n, name, NULL);
    if (at >= 0) {
        *code = "NAME_IN_FLIGHT";
        *msg = "that name is already queued or running; cancel it or wait "
               "for its outcome before posting it again";
        (void)snprintf(evidence, cap, "seq %lld is %s", rows[at].seq,
                       rows[at].state);
        return false;
    }
    if (dvq_count_queued(rows, n) >= DVQ_QUEUED_MAX) {
        *code = "QUEUE_FULL";
        *msg = "the queue already holds its bound of queued rows; retry "
               "after the worker drains it";
        (void)snprintf(evidence, cap, "%d queued", DVQ_QUEUED_MAX);
        return false;
    }
    return true;
}

static void dvq_post(const struct zcl_command_request *req,
                     struct zcl_command_reply *reply)
{
    struct dvq_dirs d;
    struct dvq_row r;
    struct dvq_row *rows = NULL;
    size_t nrows = 0;
    char qpath[4096 + 32];
    char line[DVQ_LINE_CAP];
    char brief_abs[4096];
    char ts[64];
    const char *kind, *name, *group, *path, *brief, *model;
    long long attempt = 1;
    size_t len = 0;
    int lock = -1;
    long long seq = 1;
    if (!req || !req->input) {
        dvq_fail(reply, "BAD_INPUT", "post",
                 "dev.agent.queue post needs kind and name",
                 "request.input was missing");
        return;
    }
    kind = dvq_str(req, "kind");
    name = dvq_str(req, "name");
    if (!kind || !dvq_kind_ok(kind)) {
        dvq_fail(reply, "BAD_INPUT", "post",
                 "kind is one of leaf|doc|file|fix-gate",
                 "input.kind missing or unknown");
        return;
    }
    if (!name || !dvq_name_ok(name)) {
        dvq_fail(reply, "BAD_INPUT", "post",
                 "name matches [A-Za-z0-9_.-]{1,64} and is never . or ..",
                 "input.name missing, misspelled, or escaping");
        return;
    }
    if (!dvq_dirs_resolve(&d, true)) {
        dvq_fail(reply, "STATE_DIR_FAILED", "post",
                 "cannot resolve the owner-private state root",
                 "platform_state_root");
        return;
    }
    group = dvq_str(req, "group");
    path = dvq_str(req, "path");
    brief = dvq_str(req, "brief");
    model = dvq_str(req, "model");
    memset(&r, 0, sizeof(r));
    {
        const char *msg = NULL, *why = NULL;
        if (!dvq_post_scalars(req, name, model, &attempt, &r, &msg, &why)) {
            dvq_fail(reply, "BAD_INPUT", "post", msg, why);
            return;
        }
    }
    if (strcmp(kind, "file") == 0 && (!group || !dvq_group_ok(group))) {
        dvq_fail(reply, "BAD_INPUT", "post",
                 "a file unit needs the test group that judges it",
                 "input.group missing or misspelled");
        return;
    }
    if (group && group[0] && !dvq_group_ok(group)) {
        dvq_fail(reply, "BAD_INPUT", "post",
                 "group is a test group name ([A-Za-z0-9_-], under 64)",
                 "input.group misspelled");
        return;
    }
    if (strcmp(kind, "doc") == 0 || strcmp(kind, "file") == 0) {
        if (!path || !dvq_scope_path_ok(path)) {
            dvq_fail(reply, "BAD_INPUT", "post",
                     "a doc/file unit needs a repo-relative path",
                     "input.path missing, absolute, or escaping");
            return;
        }
        if (!brief || !dvq_resolve_brief(req, brief, d.root, brief_abs,
                                         sizeof(brief_abs))) {
            dvq_fail(reply, "BAD_INPUT", "post",
                     "brief is an existing file inside the repo or state dir",
                     "input.brief missing or outside both roots");
            return;
        }
        if (strlen(brief_abs) >= sizeof(r.brief)) {
            dvq_fail(reply, "BAD_INPUT", "post",
                     "brief path is too long to record",
                     "input.brief over the row budget");
            return;
        }
        (void)snprintf(r.path, sizeof(r.path), "%s", path);
        (void)snprintf(r.brief, sizeof(r.brief), "%s", brief_abs);
    }
    if (group && group[0])
        (void)snprintf(r.group, sizeof(r.group), "%s", group);
    if (model && model[0])
        (void)snprintf(r.model, sizeof(r.model), "%s", model);
    (void)snprintf(r.kind, sizeof(r.kind), "%s", kind);
    (void)snprintf(r.name, sizeof(r.name), "%s", name);
    r.attempt = attempt;
    (void)snprintf(r.state, sizeof(r.state), "queued");
    dvq_now_iso(ts);
    (void)snprintf(r.ts, sizeof(r.ts), "%s", ts);
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d.queue) >=
        (int)sizeof(qpath)) {
        dvq_fail(reply, "QUEUE_WRITE_FAILED", "post",
                 "the queue path does not fit its buffer",
                 "platform_state_root too long");
        return;
    }
    /* The lock covers seq assignment plus the append, so a next rewriting
     * the file cannot drop this row; the critical section is local file
     * IO only, never a run. */
    lock = dvq_lock(d.queue);
    if (lock < 0) {
        dvq_fail(reply, "QUEUE_WRITE_FAILED", "post",
                 "cannot take the queue lock", qpath);
        return;
    }
    if (dvq_load_rows(qpath, &rows, &nrows)) {
        for (size_t i = 0; i < nrows; i++) {
            if (rows[i].seq >= seq)
                seq = rows[i].seq + 1;
        }
    }
    {
        const char *code = NULL, *msg = NULL;
        char evidence[128];
        if (!dvq_post_admit(rows, nrows, name, &code, &msg, evidence,
                            sizeof(evidence))) {
            free(rows);
            dvq_unlock(lock);
            dvq_fail(reply, code, "post", msg, evidence);
            return;
        }
    }
    free(rows);
    rows = NULL;
    r.seq = seq;
    if (!dvq_encode_row(&r, line, sizeof(line), &len) ||
        !dvq_append_row(qpath, line, len)) {
        dvq_unlock(lock);
        dvq_fail(reply, "QUEUE_WRITE_FAILED", "post",
                 "cannot append the queue row", qpath);
        return;
    }
    dvq_unlock(lock);
    (void)json_push_kv_str(&reply->data, "leaf", DVQ_LEAF);
    (void)json_push_kv_int(&reply->data, "seq", seq);
    (void)json_push_kv_str(&reply->data, "name", name);
    (void)json_push_kv_str(&reply->data, "state", "queued");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* ── next: the scheduler step ──────────────────────────────────────────── */

static void dvq_trim(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
                     s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = '\0';
}

/* Resolve the harness binary: an explicit env override wins, otherwise the
 * standard name is searched on PATH exactly the way execvp would find it.
 * The fake in the acceptance test arrives through PATH. */
static bool dvq_find_harness(char *out, size_t cap)
{
    const char *env = getenv("ZCL_ENGINE_UNIT_BIN");
    const char *path;
    char *save = NULL, *dir;
    char dirs[8192];
    if (env && env[0]) {
        if (strlen(env) >= cap)
            return false;
        memcpy(out, env, strlen(env) + 1);
        return true;
    }
    if (strchr(DVQ_HARNESS_NAME, '/')) {
        if (strlen(DVQ_HARNESS_NAME) >= cap)
            return false;
        memcpy(out, DVQ_HARNESS_NAME, sizeof(DVQ_HARNESS_NAME));
        return true;
    }
    path = getenv("PATH");
    if (!path || !path[0])
        return false;
    if (strlen(path) >= sizeof(dirs))
        return false;
    memcpy(dirs, path, strlen(path) + 1);
    for (dir = strtok_r(dirs, ":", &save); dir;
         dir = strtok_r(NULL, ":", &save)) {
        char cand[4096];
        FILE *probe;
        if (!dir[0] || snprintf(cand, sizeof(cand), "%s/%s", dir,
                                DVQ_HARNESS_NAME) >= (int)sizeof(cand))
            continue;
        probe = fopen(cand, "rb");
        if (!probe)
            continue;
        (void)fclose(probe);
        if (strlen(cand) >= cap)
            return false;
        memcpy(out, cand, strlen(cand) + 1);
        return true;
    }
    return false;
}

static bool dvq_have_systemd(void)
{
    const char *force = getenv("ZCL_QUEUE_DIRECT");
    const char *path;
    char dirs[8192];
    char *save = NULL, *dir;
    if (force && force[0] && strcmp(force, "0") != 0)
        return false;
    path = getenv("PATH");
    if (!path || !path[0])
        return false;
    if (strlen(path) >= sizeof(dirs))
        return false;
    memcpy(dirs, path, strlen(path) + 1);
    for (dir = strtok_r(dirs, ":", &save); dir;
         dir = strtok_r(NULL, ":", &save)) {
        char cand[4096];
        FILE *probe;
        if (!dir[0] || snprintf(cand, sizeof(cand), "%s/systemd-run",
                                dir) >= (int)sizeof(cand))
            continue;
        probe = fopen(cand, "rb");
        if (!probe)
            continue;
        (void)fclose(probe);
        return true;
    }
    return false;
}

/* Warm means <wt>/.eu-warm exists; free means the NB worktree lock holds.
 * On success the lock fd stays open for the caller: the detached child
 * inherits it, so the lock dies with the run, never with this process. */
static bool dvq_try_worktree(const char *wt, int *fd_out)
{
    char warm[4096 + 16], lockp[4096 + 16];
    FILE *probe;
    int fd;
    if (!wt || !wt[0] || !fd_out)
        return false;
    *fd_out = -1;
    if (snprintf(warm, sizeof(warm), "%s/.eu-warm", wt) >= (int)sizeof(warm))
        return false;
    probe = fopen(warm, "rb");
    if (!probe)
        return false;
    (void)fclose(probe);
    if (snprintf(lockp, sizeof(lockp), "%s/.eu-lock", wt) >=
        (int)sizeof(lockp))
        return false;
    fd = open(lockp, O_RDWR | O_CREAT, 0600);
    if (fd < 0)
        return false;
#if !defined(_WIN32)
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        (void)close(fd);
        return false;
    }
#else
    (void)close(fd);
    return false;
#endif
    *fd_out = fd;
    return true;
}

static void dvq_close_wt(int fd)
{
    if (fd >= 0)
        (void)close(fd);
}

/* Whole-file rewrite under the scheduler lock: temp file plus rename, so a
 * concurrent reader never sees a half-written queue. */
static bool dvq_rewrite_rows(const char *queuedir, const char *qpath,
                             const struct dvq_row *rows, size_t n)
{
    char tmp[4096 + 32];
    FILE *f;
    char line[DVQ_LINE_CAP];
    size_t len = 0;
    if (!queuedir || !qpath || (!rows && n > 0))
        return false;
    if (snprintf(tmp, sizeof(tmp), "%s/queue.jsonl.tmp", queuedir) >=
        (int)sizeof(tmp))
        return false;
    f = fopen(tmp, "wb");
    if (!f)
        return false;
    for (size_t i = 0; i < n; i++) {
        if (!dvq_encode_row(&rows[i], line, sizeof(line), &len) ||
            (len > 0 && fwrite(line, 1, len, f) != len)) {
            (void)fclose(f);
            return false;
        }
    }
    if (fclose(f) != 0)
        return false;
    return rename(tmp, qpath) == 0;
}

static bool dvq_snippet(const char *path, char *out, size_t cap)
{
    size_t n = 0;
    if (!path || !out || cap == 0)
        return false;
    out[0] = '\0';
    if (!dvq_read_file(path, out, cap < DVQ_SNIPPET_CAP ? cap : DVQ_SNIPPET_CAP,
                       &n))
        return false;
    out[n] = '\0';
    return true;
}

/* Append one bounded source file to the task, skipping it when absent: the
 * pool worktrees in tests are fixtures without real sources. */
static bool dvq_task_cat(char *task, size_t cap, size_t *used,
                         const char *title, const char *path)
{
    char *snippet;
    int w;
    size_t room;
    if (!task || !used || !title || !path)
        return false;
    snippet = (char *)zcl_malloc(DVQ_SNIPPET_CAP, "devagent.queue.snippet");
    if (!snippet)
        return false;
    if (!dvq_snippet(path, snippet, DVQ_SNIPPET_CAP)) {
        free(snippet);
        return true;
    }
    room = cap > *used ? cap - *used : 0;
    w = snprintf(task + *used, room, "\n=== %s: %s ===\n%s", title, path,
                 snippet);
    free(snippet);
    if (w <= 0 || (size_t)w >= room)
        return false;
    *used += (size_t)w;
    return true;
}

/* Compose the task file the harness will execute, mirroring the interim
 * dispatch scripts: the contract stub plus pinned test for leaf-shaped
 * units, the brief for doc/file units, and the previous gate tail on a
 * retry. Missing sources are skipped, never fatal. */
static bool dvq_task_prev(char *task, size_t cap, size_t *used,
                          const char *prevdir);

static bool dvq_compose_task(const struct dvq_row *r, const char *wt,
                             const char *st, const char *enginedir,
                             char *task, size_t cap, size_t *used_out)
{
    size_t used = 0;
    int w;
    bool doc;
    if (!r || !wt || !st || !enginedir || !task || cap == 0 || !used_out)
        return false;
    (void)st;
    doc = strcmp(r->kind, "doc") == 0;
    if (doc)
        w = snprintf(task, cap, "kind: doc-claim\n\nONE FILE. Emit exactly "
                                "one envelope: the COMPLETE contents of %s. "
                                "No other file.\n",
                     r->path);
    else if (strcmp(r->kind, "file") == 0)
        w = snprintf(task, cap, "kind: fix-gate\n\nONE FILE. Emit exactly "
                                "one envelope: the COMPLETE new contents of "
                                "%s. Do not emit any other file.\n",
                     r->path);
    else
        w = snprintf(task, cap, "kind: fix-gate\n\nONE FILE. Emit exactly "
                                "one envelope: the COMPLETE new contents of "
                                "tools/command/native_devagent_%s.c. Do not "
                                "emit any other file. The test "
                                "tests/harness/src/test_devagent_%s.c is "
                                "the acceptance bar and is read-only.\n",
                     r->name, r->name);
    if (w <= 0 || (size_t)w >= cap)
        return false;
    used = (size_t)w;
    if (strcmp(r->kind, "leaf") == 0 || strcmp(r->kind, "fix-gate") == 0) {
        char cur[4096 + 64], tst[4096 + 64], prev[4096 + 64];
        (void)snprintf(cur, sizeof(cur),
                       "%s/tools/command/native_devagent_%s.c", wt, r->name);
        (void)snprintf(tst, sizeof(tst),
                       "%s/tests/harness/src/test_devagent_%s.c", wt,
                       r->name);
        if (!dvq_task_cat(task, cap, &used, "CURRENT", cur))
            return false;
        if (!dvq_task_cat(task, cap, &used, "ACCEPTANCE TEST (read-only)",
                          tst))
            return false;
        if (r->attempt > 1) {
            (void)snprintf(prev, sizeof(prev), "%s/%s/a%lld", enginedir,
                           r->name, r->attempt - 1);
            if (!dvq_task_prev(task, cap, &used, prev))
                return false;
        }
    } else {
        char line[512];
        if (r->group[0]) {
            (void)snprintf(line, sizeof(line), "group: %s\n", r->group);
            if (used + strlen(line) >= cap)
                return false;
            memcpy(task + used, line, strlen(line) + 1);
            used += strlen(line);
        }
        if (!dvq_task_cat(task, cap, &used, "BRIEF", r->brief))
            return false;
    }
    *used_out = used;
    return true;
}

/* Previous-attempt gate tail, the way the interim shell greps it: lines
 * naming an error, failure, or verdict, newest last, at most 30. */
static bool dvq_task_prev(char *task, size_t cap, size_t *used,
                          const char *prevdir)
{
    static const char *const needles[] = {
        "error", "fail", "assert", "warning", "undefined", "suite verdict",
    };
    char runout[4096 + 16], gates[4096 + 16];
    char *text;
    const char *src = NULL;
    char *kept[30];
    size_t nkept = 0;
    int w;
    size_t room;
    if (!task || !used || !prevdir)
        return false;
    (void)snprintf(runout, sizeof(runout), "%s/run.out", prevdir);
    (void)snprintf(gates, sizeof(gates), "%s/gates.log", prevdir);
    text = (char *)zcl_malloc(DVQ_SNIPPET_CAP, "devagent.queue.snippet");
    if (!text)
        return false;
    if (dvq_read_file(gates, text, DVQ_SNIPPET_CAP, NULL))
        src = text;
    else if (dvq_read_file(runout, text, DVQ_SNIPPET_CAP, NULL))
        src = text;
    if (src) {
        char *save = NULL, *line;
        char *copy = text;
        for (line = strtok_r(copy, "\n", &save); line;
             line = strtok_r(NULL, "\n", &save)) {
            char lower[512];
            size_t k;
            bool hit = false;
            for (k = 0; k < sizeof(lower) - 1 && line[k]; k++)
                lower[k] = (char)tolower((unsigned char)line[k]);
            lower[k] = '\0';
            for (size_t i = 0;
                 i < sizeof(needles) / sizeof(needles[0]); i++) {
                if (strstr(lower, needles[i])) {
                    hit = true;
                    break;
                }
            }
            if (!hit)
                continue;
            if (nkept == sizeof(kept) / sizeof(kept[0])) {
                for (size_t i = 1; i < nkept; i++)
                    kept[i - 1] = kept[i];
                nkept--;
            }
            kept[nkept++] = line;
        }
        room = cap > *used ? cap - *used : 0;
        w = snprintf(task + *used, room,
                     "\n=== PREVIOUS ATTEMPT: GATE OUTPUT "
                     "(fix exactly these) ===\n");
        if (w > 0 && (size_t)w < room) {
            *used += (size_t)w;
            for (size_t i = 0; i < nkept; i++) {
                room = cap > *used ? cap - *used : 0;
                w = snprintf(task + *used, room, "%s\n", kept[i]);
                if (w <= 0 || (size_t)w >= room)
                    break;
                *used += (size_t)w;
            }
        }
    }
    free(text);
    return true;
}

/* Pool census for the no_free_worktree detail: entries listed, entries
 * warm. All local stats, never a launch. */
/* One count that may not exist. `why` non-NULL means the measurement was
 * never taken, and the key is pushed as null rather than as the zero the
 * out-param still holds. */
static bool dvq_push_count(struct json_value *obj, const char *key,
                           long long value, const char *why)
{
    struct json_value nv;
    bool ok;
    if (!why)
        return json_push_kv_int(obj, key, value);
    json_init(&nv);
    json_set_null(&nv);
    ok = json_push_kv(obj, key, &nv);
    json_free(&nv);
    return ok;
}

/* ── the pool is measured, or it is UNMEASURED: never a zero ──────────────
 *
 * pool.txt is the operator's list of warm worktree directories. A host that
 * has never been given one has an UNMEASURED pool, which is a different fact
 * from a pool measured to be empty, and reporting 0 for it is how a caller
 * concludes "no capacity" about a number nobody ever took.
 *
 * These reasons say which it is. NULL means the file was read and the counts
 * below it are real. fleet.steer.brief used to re-derive this by stat()ing
 * pool.txt itself, because this leaf's zero could not be trusted; it now
 * reads the answer from here, so the decision lives once, in the leaf that
 * owns the queue's state. */
#define DVQ_POOL_ABSENT \
    "no pool.txt on this host: the worktree pool is not listed here, so its " \
    "size is unknown, which is not the same as empty"
#define DVQ_POOL_UNREADABLE \
    "pool.txt exists but could not be read within its 64 KiB bound"
#define DVQ_POOL_NOMEM "the pool buffer could not be allocated"

/* NULL when `poolpath` was read into `text` (caller frees it), else the
 * reason it could not be, with `text` already freed and set to NULL. */
static const char *dvq_pool_text(const char *poolpath, char **text)
{
    struct stat st;
    *text = (char *)zcl_malloc(DVQ_POOL_CAP, "devagent.queue.pool");
    if (!*text)
        return DVQ_POOL_NOMEM;
    if (!poolpath || stat(poolpath, &st) != 0 || !S_ISREG(st.st_mode)) {
        free(*text);
        *text = NULL;
        return DVQ_POOL_ABSENT;
    }
    if (!dvq_read_file(poolpath, *text, DVQ_POOL_CAP, NULL)) {
        free(*text);
        *text = NULL;
        return DVQ_POOL_UNREADABLE;
    }
    return NULL;
}

/* ── the five states a worktree pool can be in ─────────────────────────────
 *
 * "no free worktree" is not one fact, it is five, and an operator who cannot
 * tell them apart cannot act on any of them:
 *
 *   inventory missing      nobody listed a pool here            UNMEASURED
 *   inventory empty        the list was read and holds nothing  measured 0
 *   entry missing          listed, but the directory is gone    stale list
 *   entry not warm         directory present, no .eu-warm       not prepared
 *   entry claimed          warm, but its lock is held now       in use
 *
 * Every count below is reported, and `blocked` names the ONE reason dispatch
 * is impossible, from a closed vocabulary, so "idle" can never stand in for
 * "cannot dispatch". warm == free + claimed always holds, which is what lets
 * a caller check the census against itself. */
struct dvq_pool_census {
    long long total;    /* non-blank lines in pool.txt */
    long long warm;     /* of those, carrying .eu-warm */
    long long free;     /* of the warm, lock acquirable right now */
    long long claimed;  /* of the warm, unavailable right now */
    long long missing;  /* listed, but no such directory */
    long long not_warm; /* directory present, no .eu-warm marker */
    const char *reason;  /* why unmeasured; NULL when the counts are real */
    const char *blocked; /* why dispatch is impossible; "" when it is not */
};

/* Dispatch is impossible for exactly one reason at a time; this is it. */
#define DVQ_BLOCK_UNMEASURED "pool-unmeasured"
#define DVQ_BLOCK_EMPTY "pool-empty"
#define DVQ_BLOCK_NO_WARM "pool-no-warm-entry"
#define DVQ_BLOCK_ALL_CLAIMED "pool-all-claimed"

/* Classify ONE listed entry into the census. Split out so the loop stays
 * flat and each state is decided in one place. */
static void dvq_pool_entry(const char *dir, struct dvq_pool_census *c)
{
    char probe[4096 + 16], lockp[4096 + 16];
    struct stat st;
    FILE *f;
    int fd;
    c->total++;
    if (snprintf(probe, sizeof(probe), "%s/.eu-warm", dir) >=
            (int)sizeof(probe) ||
        snprintf(lockp, sizeof(lockp), "%s/.eu-lock", dir) >=
            (int)sizeof(lockp)) {
        c->missing++; /* a path this box cannot even name is not usable */
        return;
    }
    /* A listed directory that is gone is a STALE LIST, not an unprepared
     * worktree: the operator's inventory names something that no longer
     * exists, and saying "not warm" about it would hide that. */
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        c->missing++;
        return;
    }
    f = fopen(probe, "rb");
    if (!f) {
        c->not_warm++;
        return;
    }
    (void)fclose(f);
    c->warm++;
    fd = open(lockp, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        c->reason = "pool-lock-unreadable";
        return;
    }
#if !defined(_WIN32)
    if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
        (void)flock(fd, LOCK_UN);
        c->free++;
    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        c->claimed++;
    } else {
        c->reason = "pool-lock-unreadable";
    }
#else
    c->free++;
#endif
    (void)close(fd);
}

/* The one blocked reason, decided after the counts are in. */
static const char *dvq_pool_blocked(const struct dvq_pool_census *c)
{
    if (c->reason)
        return DVQ_BLOCK_UNMEASURED;
    if (c->total == 0)
        return DVQ_BLOCK_EMPTY;
    if (c->warm == 0)
        return DVQ_BLOCK_NO_WARM;
    if (c->free == 0)
        return DVQ_BLOCK_ALL_CLAIMED;
    return "";
}

/* Read pool.txt once and classify every entry. Never fabricates a zero: an
 * unreadable inventory sets reason and leaves every count at 0 with
 * known:false carrying that distinction to the caller. */
static void dvq_pool_take(const char *poolpath, struct dvq_pool_census *c)
{
    char *text;
    char *save = NULL, *line;
    memset(c, 0, sizeof(*c));
    c->reason = dvq_pool_text(poolpath, &text);
    if (c->reason) {
        c->blocked = dvq_pool_blocked(c);
        return;
    }
    for (line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        dvq_trim(line);
        if (line[0])
            dvq_pool_entry(line, c);
    }
    free(text);
    c->blocked = dvq_pool_blocked(c);
}

/* Resolve the dev binary the harness gates through, the way the interim
 * dispatch scripts always set ZCL_Z23_BIN: an operator override wins,
 * otherwise the primed binary inside the worktree that will run the unit.
 * Unset means inherit and let the harness fall back on its own rules. */
static bool dvq_z23_bin(const char *wt, char *out, size_t cap)
{
    const char *env = getenv("ZCL_Z23_BIN");
    char cand[4096 + 32];
    if (env && env[0]) {
        if (strlen(env) >= cap)
            return false;
        memcpy(out, env, strlen(env) + 1);
        return true;
    }
    if (!wt || !wt[0])
        return false;
    if (snprintf(cand, sizeof(cand), "%s/build/bin/z23-dev", wt) >=
        (int)sizeof(cand))
        return false;
#if defined(_WIN32)
    {
        FILE *probe = fopen(cand, "rb");
        if (!probe)
            return false;
        (void)fclose(probe);
    }
#else
    if (access(cand, X_OK) != 0)
        return false;
#endif
    if (strlen(cand) >= cap)
        return false;
    memcpy(out, cand, strlen(cand) + 1);
    return true;
}

/* Sanitize a queue name into a systemd unit fragment. */
static void dvq_unit_frag(const char *in, char *out, size_t cap)
{
    size_t used = 0;
    if (!in || !out || cap == 0)
        return;
    for (const char *p = in; *p && used + 1 < cap; p++) {
        bool ok = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                  (*p >= '0' && *p <= '9') || *p == '_' || *p == '-';
        out[used++] = ok ? *p : '_';
    }
    out[used] = '\0';
}

/* Roll a failed launch back to queued: the row was marked running before
 * the spawn, and a row for a run that never started must not read busy. */
static void dvq_unmark(const char *queuedir, const char *qpath, long long seq)
{
    struct dvq_row *rows = NULL;
    size_t n = 0;
    int lock;
    if (!queuedir || !qpath)
        return;
    lock = dvq_lock(queuedir);
    if (lock < 0)
        return;
    if (dvq_load_rows(qpath, &rows, &n)) {
        for (size_t i = 0; i < n; i++) {
            if (rows[i].seq == seq &&
                strcmp(rows[i].state, "running") == 0) {
                (void)snprintf(rows[i].state, sizeof(rows[i].state),
                               "queued");
                rows[i].worktree[0] = '\0';
                rows[i].pid_or_unit[0] = '\0';
                rows[i].started = 0;
                dvq_clear_owner(&rows[i]);
            }
        }
        (void)dvq_rewrite_rows(queuedir, qpath, rows, n);
    }
    free(rows);
    dvq_unlock(lock);
}

/* ── model-worker claim ──────────────────────────────────────────────────
 * next dispatches to the flash-unit harness (worktree pool, detached
 * spawn). A resident model worker is the other dispatch arm on the same
 * ledger: claim takes the oldest queued row, marks it running WITHOUT a
 * worktree or a spawn, and persists claim.json in the run dir BEFORE
 * returning, so no model submission can precede the persisted claim. A
 * name the closed predicate already completed is refused with
 * CLAIM_COMPLETED: a restarted worker inspects outcomes first and never
 * duplicates finished work. Queued cancel still prevents claim (the row
 * is gone); running rows stay their worker's business. */

/* One outcome line completes name when it names it with a pass verdict
 * and a clean exit. Malformed lines never complete. */
static bool dvq_outcome_line_completed(const char *line, const char *name)
{
    char lname[80];
    char verdict[128];
    long long rc = -1;
    if (!line || !name)
        return false;
    if (!dvq_line_str(line, "name", lname, sizeof(lname)))
        return false;
    if (strcmp(lname, name) != 0)
        return false;
    if (!dvq_line_str(line, "verdict", verdict, sizeof(verdict)))
        return false;
    if (!dvq_line_int(line, "rc", &rc))
        return false;
    return zcl_devagent_closed_pass(verdict, rc);
}

/* True when any outcome row completes name. A missing outcomes file
 * completes nothing. */
static bool dvq_name_completed(const char *opath, const char *name)
{
    char *text;
    char *save = NULL, *line;
    bool done = false;
    if (!opath || !name)
        return false;
    text = (char *)zcl_malloc(DVQ_FILE_CAP, "devagent.queue.claim");
    if (!text)
        return false;
    if (!dvq_read_file(opath, text, DVQ_FILE_CAP, NULL)) {
        free(text);
        return false;
    }
    for (line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        if (dvq_outcome_line_completed(line, name)) {
            done = true;
            break;
        }
    }
    free(text);
    return done;
}

/* ── the current dependency attempt ──────────────────────────────────────
 * A prerequisite may own several attempts: a failed run, a retry queued
 * behind it, a late result for an older attempt. Only the CURRENT attempt
 * decides, derived from the ledger and outcomes alone: the highest attempt
 * any live row or outcome row carries, where a live row at or above the
 * newest outcome means that attempt is still pending. The dependency is
 * met only when the newest outcome is a closed pass and no newer attempt
 * is live, so an older or out-of-order PASS never unlocks a dependent. */
struct dvq_dep {
    const char *state; /* passed | terminal | queued | running | absent */
    long long attempt; /* 0 when absent */
    char verdict[128]; /* the current attempt's verdict, "" when none */
};

/* The newest outcome for name: its highest attempt, and the last line at
 * that attempt. attempt stays 0 when no outcome names it. */
static void dvq_dep_outcome(const char *opath, const char *name,
                            long long *attempt, char *verdict, size_t cap,
                            long long *rc)
{
    char *text = (char *)zcl_malloc(DVQ_FILE_CAP, "devagent.queue.dep");
    char *save = NULL, *line;
    if (!text)
        return;
    if (!dvq_read_file(opath, text, DVQ_FILE_CAP, NULL))
        text[0] = '\0';
    for (line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char lname[80];
        long long at = 0, lrc = -1;
        if (!dvq_line_str(line, "name", lname, sizeof(lname)) ||
            strcmp(lname, name) != 0 ||
            !dvq_line_int(line, "attempt", &at) || at < *attempt)
            continue;
        *attempt = at;
        verdict[0] = '\0';
        (void)dvq_line_str(line, "verdict", verdict, cap);
        *rc = dvq_line_int(line, "rc", &lrc) ? lrc : -1;
    }
    free(text);
}

/* The live row (queued or running) with the highest attempt for name. */
static long dvq_live_newest(const struct dvq_row *rows, size_t n,
                            const char *name)
{
    long best = -1;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(rows[i].name, name) != 0 ||
            (strcmp(rows[i].state, "queued") != 0 &&
             strcmp(rows[i].state, "running") != 0))
            continue;
        if (best < 0 || rows[i].attempt > rows[best].attempt)
            best = (long)i;
    }
    return best;
}

static void dvq_dep_eval(const struct dvq_row *rows, size_t n,
                         const char *opath, const char *dep,
                         struct dvq_dep *out)
{
    long long rc = -1;
    long live = dvq_live_newest(rows, n, dep);
    out->attempt = 0;
    out->verdict[0] = '\0';
    dvq_dep_outcome(opath, dep, &out->attempt, out->verdict,
                    sizeof(out->verdict), &rc);
    if (live >= 0 && rows[live].attempt >= out->attempt) {
        out->state = strcmp(rows[live].state, "running") == 0 ? "running"
                                                              : "queued";
        out->attempt = rows[live].attempt;
        out->verdict[0] = '\0';
        return;
    }
    if (out->attempt == 0) {
        out->state = "absent";
        return;
    }
    out->state = zcl_devagent_closed_pass(out->verdict, rc) ? "passed"
                                                            : "terminal";
}

/* The gates a queued row must clear to be READY, shared by the picker and
 * status so the two can never disagree: its dependency's current attempt
 * passed, and no row with its own name is already running (a ledger
 * written before post refused duplicates can still carry one). On false,
 * *ref names what holds it and dep says in what state. */
static bool dvq_row_gate(const struct dvq_row *rows, size_t n, size_t i,
                         const char *opath, struct dvq_dep *dep,
                         const char **ref)
{
    const struct dvq_row *r = &rows[i];
    long run;
    *ref = NULL;
    if (r->depends_on[0]) {
        dvq_dep_eval(rows, n, opath, r->depends_on, dep);
        if (strcmp(dep->state, "passed") != 0) {
            *ref = r->depends_on;
            return false;
        }
    }
    run = dvq_live_row(rows, n, r->name, "running");
    if (run < 0)
        return true;
    dep->state = "running";
    dep->attempt = rows[run].attempt;
    dep->verdict[0] = '\0';
    *ref = r->name;
    return false;
}

/* THE READY PICK, shared by claim and next: the queued row with the
 * lowest (priority, seq) that clears dvq_row_gate. With
 * skip_done, a row whose own name already completed is passed over and
 * named in done_name. Returns the row index, or -1 when nothing is READY. */
static long dvq_pick_ready(const struct dvq_row *rows, size_t n,
                           const char *opath, bool skip_done,
                           char *done_name)
{
    long best = -1;
    struct dvq_dep dep;
    const char *ref;
    for (size_t i = 0; i < n; i++) {
        const struct dvq_row *r = &rows[i];
        if (strcmp(r->state, "queued") != 0)
            continue;
        if (best >= 0 && (r->priority > rows[best].priority ||
                          (r->priority == rows[best].priority &&
                           r->seq > rows[best].seq)))
            continue;
        if (skip_done && dvq_name_completed(opath, r->name)) {
            (void)snprintf(done_name, 80, "%s", r->name);
            continue;
        }
        /* Dependency met on its current attempt, and a name already
         * running is never handed out twice. */
        if (!dvq_row_gate(rows, n, i, opath, &dep, &ref))
            continue;
        best = (long)i;
    }
    return best;
}

/* rundir ends "/<name>/a<attempt>": create the name dir, then the run. */
static bool dvq_claim_mkdir(const char *rundir)
{
    char namedir[4096 + 80];
    char *slash;
    if (!rundir)
        return false;
    if (snprintf(namedir, sizeof(namedir), "%s", rundir) >=
        (int)sizeof(namedir))
        return false;
    slash = strrchr(namedir, '/');
    if (!slash)
        return false;
    *slash = '\0';
    return dvq_mkdir_one(namedir) && dvq_mkdir_one(rundir);
}

/* All four claim.json strings escaped for the row. */
static bool dvq_claim_escape(const char *worker, const char *session,
                             const char *model, const char *name,
                             char *eworker, char *esession, char *emodel,
                             char *ename)
{
    if (!dvq_escape(worker, eworker, 128) ||
        !dvq_escape(session, esession, 128) ||
        !dvq_escape(name, ename, 160))
        return false;
    if (model && model[0])
        return dvq_escape(model, emodel, 320);
    emodel[0] = '\0';
    return true;
}

/* Claim identity persisted before any model submission may happen: the
 * run dir plus claim.json naming the exact row, worker, and session with
 * submitted:false. False when the disk refuses. */
static bool dvq_claim_write(const char *rundir, const struct dvq_row *pick,
                            const char *worker, const char *session,
                            const char *model, const char *ts)
{
    char cpath[4096 + 96], line[2048];
    char eworker[128], esession[128], emodel[320], ename[160];
    int w;
    if (!rundir || !pick || !worker || !session || !ts)
        return false;
    if (!dvq_claim_mkdir(rundir))
        return false;
    if (!dvq_claim_escape(worker, session, model, pick->name, eworker,
                          esession, emodel, ename))
        return false;
    if (snprintf(cpath, sizeof(cpath), "%s/claim.json", rundir) >=
        (int)sizeof(cpath))
        return false;
    w = snprintf(line, sizeof(line),
                 "{\"name\":\"%s\",\"attempt\":%lld,\"seq\":%lld,"
                 "\"worker\":\"%s\",\"session\":\"%s\",\"model\":\"%s\","
                 "\"ts\":\"%s\",\"submitted\":false}\n",
                 ename, pick->attempt, pick->seq, eworker, esession,
                 emodel, ts);
    if (w <= 0 || (size_t)w >= sizeof(line))
        return false;
    return dvq_write_file(cpath, line, (size_t)w);
}

/* One short claimant name: 1-48 of [A-Za-z0-9_.-], never . or .. . */
static bool dvq_claim_name(const char *value, const char *which,
                           const char *missing_evidence,
                           struct zcl_command_reply *reply)
{
    char msg[96];
    if (!value || strlen(value) == 0 || strlen(value) > 48 ||
        !dvq_name_ok(value)) {
        (void)snprintf(msg, sizeof(msg),
                       "%s is 1-48 of [A-Za-z0-9_.-]", which);
        dvq_fail(reply, "BAD_INPUT", "claim", msg, missing_evidence);
        return false;
    }
    return true;
}

/* Claim inputs: the resident worker and this run, both short names so
 * pid_or_unit ("worker:<worker>/<session>") stays inside 128 bytes. */
static bool dvq_claim_args(const struct zcl_command_request *req,
                           struct zcl_command_reply *reply,
                           const char **worker, const char **session,
                           const char **model)
{
    if (!req || !req->input || !worker || !session || !model) {
        dvq_fail(reply, "BAD_INPUT", "claim",
                 "dev.agent.queue claim needs worker and session",
                 "request.input was missing");
        return false;
    }
    *worker = dvq_str(req, "worker");
    *session = dvq_str(req, "session");
    if (!dvq_claim_name(*worker, "worker",
                        "input.worker missing, misspelled, or too long",
                        reply))
        return false;
    if (!dvq_claim_name(*session, "session",
                        "input.session missing, misspelled, or too long",
                        reply))
        return false;
    *model = dvq_str(req, "model");
    if (*model && (*model)[0] && !dvq_model_ok(*model)) {
        dvq_fail(reply, "BAD_INPUT", "claim",
                 "model is at most 128 model-id characters",
                 "input.model misspelled");
        return false;
    }
    if (!*model)
        *model = "";
    return true;
}

/* owner, trust, and proof are parties outside this queue. A row that
 * names one is not runnable work and must not become the active job. */
static bool dvq_external_dependency(const char *dep)
{
    return dep && (strcmp(dep, "owner") == 0 || strcmp(dep, "trust") == 0 ||
                   strcmp(dep, "proof") == 0);
}

/* Durable dependency packet beside the ledger. The row's own state is
 * WAITING_EXTERNAL; this file is the packet a later beat can name. */
static bool dvq_park_external(const char *queuedir, struct dvq_row *r)
{
    char dir[4096 + 8];
    char path[4096 + 96];
    char body[256];
    int n;
    if (!queuedir || !r || !dvq_external_dependency(r->depends_on))
        return false;
    if (snprintf(dir, sizeof(dir), "%s/wait", queuedir) >= (int)sizeof(dir))
        return false;
    if (!dvq_mkdir_one(dir))
        return false;
    if (snprintf(path, sizeof(path), "%s/%s.json", dir, r->name) >=
        (int)sizeof(path))
        return false;
    n = snprintf(body, sizeof(body),
                 "{\"name\":\"%s\",\"wait\":\"%s\",\"state\":\"WAITING_EXTERNAL\","
                 "\"seq\":%lld}\n",
                 r->name, r->depends_on, r->seq);
    if (n <= 0 || (size_t)n >= sizeof(body))
        return false;
    if (!dvq_write_file(path, body, (size_t)n))
        return false;
    (void)snprintf(r->state, sizeof(r->state), "WAITING_EXTERNAL");
    r->pid_or_unit[0] = '\0';
    dvq_clear_owner(r);
    return true;
}

/* Park every queued external wait before the ready pick. Returns the
 * number parked, or -1 when a packet could not be written. */
static int dvq_park_waiting(const char *queuedir, struct dvq_row *rows,
                            size_t n)
{
    int parked = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        if (strcmp(rows[i].state, "queued") != 0)
            continue;
        if (!dvq_external_dependency(rows[i].depends_on))
            continue;
        if (!dvq_park_external(queuedir, &rows[i]))
            return -1;
        parked++;
    }
    return parked;
}

/* Oldest unfinished row, skipping names the closed predicate already
 * completed. An owner/trust/proof wait is parked as WAITING_EXTERNAL
 * first, so the pick is a different runnable row. Marks that pick
 * running under the lock. Returns 1 with the pick, 0 with done_name
 * when only finished work waits, -1 refused. */
static int dvq_claim_take(const struct dvq_dirs *d, const char *qpath,
                          const char *opath, const char *worker,
                          const char *session, struct dvq_row *pick,
                          char *done_name,
                          struct zcl_command_reply *reply)
{
    struct dvq_row *rows = NULL;
    size_t nrows = 0;
    bool have_pick = false;
    int lock = -1;
    int rc = -1;
    lock = dvq_lock(d->queue);
    if (lock < 0) {
        dvq_fail(reply, "QUEUE_READ_FAILED", "claim",
                 "cannot take the queue lock", qpath);
        return -1;
    }
    if (!dvq_load_rows(qpath, &rows, &nrows)) {
        dvq_unlock(lock);
        dvq_fail(reply, "QUEUE_READ_FAILED", "claim",
                 "cannot read the queue file", qpath);
        return -1;
    }
    {
        int parked = dvq_park_waiting(d->queue, rows, nrows);
        if (parked < 0) {
            free(rows);
            dvq_unlock(lock);
            dvq_fail(reply, "QUEUE_WRITE_FAILED", "claim",
                     "cannot persist an external wait", qpath);
            return -1;
        }
        if (parked > 0 && !dvq_rewrite_rows(d->queue, qpath, rows, nrows)) {
            free(rows);
            dvq_unlock(lock);
            dvq_fail(reply, "QUEUE_WRITE_FAILED", "claim",
                     "cannot record WAITING_EXTERNAL", qpath);
            return -1;
        }
    }
    {
        long at = dvq_pick_ready(rows, nrows, opath, true, done_name);
        if (at >= 0) {
            *pick = rows[at];
            have_pick = true;
        }
    }
    if (!have_pick) {
        free(rows);
        dvq_unlock(lock);
        if (done_name[0]) {
            dvq_fail(reply, "CLAIM_COMPLETED", "claim",
                     "that name already completed under the closed predicate",
                     done_name);
            return -1;
        }
        (void)json_push_kv_str(&reply->data, "leaf", DVQ_LEAF);
        (void)json_push_kv_str(&reply->data, "state", "empty");
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = 0;
        return 0;
    }
    pick->worktree[0] = '\0';
    (void)snprintf(pick->pid_or_unit, sizeof(pick->pid_or_unit),
                   "worker:%s/%s", worker, session);
    pick->started = (long long)platform_time_wall_unix();
    dvq_stamp_owner(pick);
    (void)snprintf(pick->state, sizeof(pick->state), "running");
    for (size_t i = 0; i < nrows; i++) {
        if (rows[i].seq == pick->seq) {
            rows[i] = *pick;
            break;
        }
    }
    rc = dvq_rewrite_rows(d->queue, qpath, rows, nrows) ? 1 : -1;
    free(rows);
    dvq_unlock(lock);
    if (rc < 0) {
        dvq_fail(reply, "QUEUE_WRITE_FAILED", "claim",
                 "cannot mark the row running", qpath);
        return -1;
    }
    return 1;
}

static void dvq_claim(const struct zcl_command_request *req,
                      struct zcl_command_reply *reply)
{
    struct dvq_dirs d;
    struct dvq_row pick;
    char qpath[4096 + 32], opath[4096 + 32], rundir[4096 + 128];
    char done_name[80];
    char ts[64];
    const char *worker, *session, *model;
    int taken;
    done_name[0] = '\0';
    if (!dvq_claim_args(req, reply, &worker, &session, &model))
        return;
    if (!dvq_dirs_resolve(&d, true)) {
        dvq_fail(reply, "STATE_DIR_FAILED", "claim",
                 "cannot resolve the owner-private state root",
                 "platform_state_root");
        return;
    }
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d.queue) >=
        (int)sizeof(qpath) ||
        snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", d.queue) >=
        (int)sizeof(opath)) {
        dvq_fail(reply, "QUEUE_READ_FAILED", "claim",
                 "the queue paths do not fit their buffers",
                 "platform_state_root too long");
        return;
    }
    /* Finished work is never duplicated: outcomes first, before the pick. */
    taken = dvq_claim_take(&d, qpath, opath, worker, session, &pick,
                           done_name, reply);
    if (taken != 1)
        return;
    /* The row is durable now; everything below can fail back to queued. */
    if (snprintf(rundir, sizeof(rundir), "%s/%s/a%lld", d.engine,
                 pick.name, pick.attempt) >= (int)sizeof(rundir)) {
        dvq_unmark(d.queue, qpath, pick.seq);
        dvq_fail(reply, "DISPATCH_FAILED", "claim",
                 "the run path does not fit its buffer",
                 "platform_state_root too long");
        return;
    }
    dvq_now_iso(ts);
    if (!dvq_claim_write(rundir, &pick, worker, session, model, ts)) {
        dvq_unmark(d.queue, qpath, pick.seq);
        dvq_fail(reply, "STATE_DIR_FAILED", "claim",
                 "cannot persist the claim identity", rundir);
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", DVQ_LEAF);
    (void)json_push_kv_str(&reply->data, "state", "running");
    (void)json_push_kv_str(&reply->data, "name", pick.name);
    (void)json_push_kv_int(&reply->data, "seq", pick.seq);
    (void)json_push_kv_int(&reply->data, "attempt", pick.attempt);
    (void)json_push_kv_str(&reply->data, "kind", pick.kind);
    (void)json_push_kv_str(&reply->data, "brief", pick.brief);
    (void)json_push_kv_str(&reply->data, "group", pick.group);
    (void)json_push_kv_str(&reply->data, "path", pick.path);
    (void)json_push_kv_str(&reply->data, "model", pick.model);
    (void)json_push_kv_str(&reply->data, "rundir", rundir);
    (void)json_push_kv_str(&reply->data, "worker", worker);
    (void)json_push_kv_str(&reply->data, "session", session);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* Bounded cancel: drop queued (unclaimed) rows naming name, so a later
 * next never launches them. Running rows belong to their worker —
 * stopping one is the worker's own responsibility, never this action's.
 * Terminal outcomes are history and are never rewritten. Grant revoke
 * reaches here through the steer adapter, which cancels each queued row
 * its grant sent; direct cancel still refuses running rows. Lock,
 * temp+rename rewrite, typed refuses; no new state system appears. */
static void dvq_cancel_filter(struct dvq_row *rows, size_t nrows,
                              const char *name, struct dvq_row *kept,
                              size_t *nkept, size_t *dropped, bool *live)
{
    size_t i;
    *nkept = 0;
    *dropped = 0;
    *live = false;
    for (i = 0; i < nrows; i++) {
        if (strcmp(rows[i].name, name) == 0) {
            if (strcmp(rows[i].state, "queued") == 0 ||
                strcmp(rows[i].state, "WAITING_EXTERNAL") == 0) {
                (*dropped)++;
                continue;
            }
            *live = true;
        }
        kept[(*nkept)++] = rows[i];
    }
}

static void dvq_cancel(const struct zcl_command_request *req,
                       struct zcl_command_reply *reply)
{
    struct dvq_dirs d;
    struct dvq_row *rows = NULL, *kept = NULL;
    size_t nrows = 0, nkept = 0, dropped = 0;
    bool live = false;
    char qpath[4096];
    const char *name;
    int lock = -1;
    if (!req || !req->input) {
        dvq_fail(reply, "BAD_INPUT", "cancel",
                 "dev.agent.queue cancel needs a name",
                 "request.input was missing");
        return;
    }
    name = dvq_str(req, "name");
    if (!name || !dvq_name_ok(name)) {
        dvq_fail(reply, "BAD_INPUT", "cancel",
                 "name matches [A-Za-z0-9_.-]{1,64} and is never . or ..",
                 "input.name missing, misspelled, or escaping");
        return;
    }
    if (!dvq_dirs_resolve(&d, true)) {
        dvq_fail(reply, "STATE_DIR_FAILED", "cancel",
                 "cannot resolve the owner-private state root",
                 "platform_state_root");
        return;
    }
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d.queue) >=
        (int)sizeof(qpath)) {
        dvq_fail(reply, "QUEUE_READ_FAILED", "cancel",
                 "the queue path does not fit its buffer",
                 "platform_state_root too long");
        return;
    }
    lock = dvq_lock(d.queue);
    if (lock < 0) {
        dvq_fail(reply, "QUEUE_READ_FAILED", "cancel",
                 "cannot take the queue lock", qpath);
        return;
    }
    if (!dvq_load_rows(qpath, &rows, &nrows)) {
        dvq_unlock(lock);
        dvq_fail(reply, "QUEUE_READ_FAILED", "cancel",
                 "cannot read the queue file", qpath);
        return;
    }
    if (nrows > 0) {
        kept = zcl_malloc(nrows * sizeof(*kept), "devagent.queue.cancel");
        if (!kept) {
            free(rows);
            dvq_unlock(lock);
            dvq_fail(reply, "QUEUE_WRITE_FAILED", "cancel",
                     "cannot stage the kept rows", qpath);
            return;
        }
    }
    dvq_cancel_filter(rows, nrows, name, kept, &nkept, &dropped, &live);
    if (dropped > 0 &&
        !dvq_rewrite_rows(d.queue, qpath, kept, nkept)) {
        free(rows);
        free(kept);
        dvq_unlock(lock);
        dvq_fail(reply, "QUEUE_WRITE_FAILED", "cancel",
                 "cannot rewrite the queue file", qpath);
        return;
    }
    free(rows);
    free(kept);
    dvq_unlock(lock);
    if (dropped > 0) {
        (void)json_push_kv_str(&reply->data, "leaf", DVQ_LEAF);
        (void)json_push_kv_str(&reply->data, "state", "cancelled");
        (void)json_push_kv_str(&reply->data, "name", name);
        (void)json_push_kv_int(&reply->data, "cancelled",
                               (long long)dropped);
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = 0;
        return;
    }
    if (live) {
        dvq_fail(reply, "CANCEL_RUNNING", "cancel",
                 "a running row with that name belongs to its worker",
                 "only queued rows cancel");
        return;
    }
    dvq_fail(reply, "CANCEL_NOT_FOUND", "cancel",
             "no queued row carries that name", "nothing to stop");
}

/* The `pool` object of a status reply. Every count is null — never 0 — when
 * the pool was not measured, so a consumer reading only the numbers cannot
 * mistake "nobody listed a pool here" for "the pool is empty". `blocked`
 * names the ONE reason dispatch is impossible, so no caller infers it from a
 * set of zeroes and "idle" can never stand in for "cannot dispatch". Split
 * out of dvq_status for the complexity gate; it owns the shape alone. */
static bool dvq_status_pool(struct json_value *pool,
                            const struct dvq_pool_census *c)
{
    const char *why = c->reason;
    return json_push_kv_bool(pool, "known", why == NULL) &&
           dvq_push_count(pool, "total", c->total, why) &&
           dvq_push_count(pool, "warm", c->warm, why) &&
           dvq_push_count(pool, "free", c->free, why) &&
           dvq_push_count(pool, "claimed", c->claimed, why) &&
           dvq_push_count(pool, "missing", c->missing, why) &&
           dvq_push_count(pool, "not_warm", c->not_warm, why) &&
           json_push_kv_str(pool, "reason", why ? why : "") &&
           json_push_kv_str(pool, "blocked", c->blocked);
}

/* The same census as one human line. An unmeasured pool says so instead of
 * printing zeroes that would read as an empty one. */
static void dvq_pool_line(char *out, size_t cap,
                          const struct dvq_pool_census *c)
{
    if (c->reason) {
        (void)snprintf(out, cap, "pool UNMEASURED: %s", c->blocked);
        return;
    }
    (void)snprintf(out, cap,
                   "pool %lld free / %lld claimed / %lld warm / %lld total "
                   "(%lld missing, %lld not warm)%s%s",
                   c->free, c->claimed, c->warm, c->total, c->missing,
                   c->not_warm, c->blocked[0] ? " BLOCKED: " : "",
                   c->blocked);
}

/* The whole `no_free_worktree` answer, including WHICH of the five census
 * states blocked it. Split out of dvq_next so that walker stays under the
 * complexity gate: this is pure emission and owns every pool field, so the
 * shape can never drift between here and `status`. */
static void dvq_emit_no_worktree(struct zcl_command_reply *reply,
                                 const char *poolpath)
{
    struct dvq_pool_census census;
    const char *why;
    dvq_pool_take(poolpath, &census);
    why = census.reason;
    (void)json_push_kv_str(&reply->data, "leaf", DVQ_LEAF);
    (void)json_push_kv_str(&reply->data, "state", "no_free_worktree");
    /* The five states the census separates all used to arrive here as one
     * word; `pool_blocked` names the one that applies, and the counts say
     * how the inventory got that way. */
    (void)json_push_kv_bool(&reply->data, "pool_known", why == NULL);
    (void)dvq_push_count(&reply->data, "pool_total", census.total, why);
    (void)dvq_push_count(&reply->data, "pool_warm", census.warm, why);
    (void)dvq_push_count(&reply->data, "pool_free", census.free, why);
    (void)dvq_push_count(&reply->data, "pool_claimed", census.claimed, why);
    (void)dvq_push_count(&reply->data, "pool_missing", census.missing, why);
    (void)dvq_push_count(&reply->data, "pool_not_warm", census.not_warm, why);
    (void)json_push_kv_str(&reply->data, "pool_reason", why ? why : "");
    (void)json_push_kv_str(&reply->data, "pool_blocked", census.blocked);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static void dvq_next(const struct zcl_command_request *req,
                     struct zcl_command_reply *reply)
{
    struct dvq_dirs d;
    struct dvq_row *rows = NULL;
    struct dvq_row pick;
    size_t nrows = 0;
    bool have_pick = false;
    char qpath[4096 + 32], poolpath[4096 + 32];
    char wt[4096], st[4096 + 64], taskpath[4096 + 64];
    char runout[4096 + 64], lockpath[4096 + 16];
    char harness[4096], model[160], group[96], unit[160], unitarg[192];
    char wdirarg[4096 + 32];
    char zbind[4096 + 64], zbenv[4096 + 64], zsetenv[4096 + 64];
    char outarg[4096 + 64], errarg[4096 + 64];
    char *task = NULL;
    size_t task_used = 0;
    const char *tmo = "1200", *gtmo = "2400";
    const char *hargv[26];
    const char *sargv[56];
    bool have_zbin;
    int lock = -1, wtfd = -1;
    struct zcl_result zr;
    bool doc;
    (void)req;
#if defined(_WIN32)
    dvq_fail(reply, "NEXT_WINDOWS_UNAVAILABLE", "select",
             "dev.agent.queue next needs POSIX worktree locks",
             "run next on a POSIX host");
    return;
#endif
    if (!dvq_dirs_resolve(&d, true)) {
        dvq_fail(reply, "STATE_DIR_FAILED", "select",
                 "cannot resolve the owner-private state root",
                 "platform_state_root");
        return;
    }
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d.queue) >=
            (int)sizeof(qpath) ||
        snprintf(poolpath, sizeof(poolpath), "%s/pool.txt", d.queue) >=
            (int)sizeof(poolpath)) {
        dvq_fail(reply, "QUEUE_READ_FAILED", "select",
                 "the queue paths do not fit their buffers",
                 "platform_state_root too long");
        return;
    }
    lock = dvq_lock(d.queue);
    if (lock < 0) {
        dvq_fail(reply, "QUEUE_READ_FAILED", "select",
                 "cannot take the queue lock", qpath);
        return;
    }
    if (!dvq_load_rows(qpath, &rows, &nrows)) {
        dvq_unlock(lock);
        dvq_fail(reply, "QUEUE_READ_FAILED", "select",
                 "cannot read the queue file", qpath);
        return;
    }
    {
        char opath[4096 + 32], unused[80] = {0};
        long at = -1;
        if (snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", d.queue) <
            (int)sizeof(opath))
            at = dvq_pick_ready(rows, nrows, opath, false, unused);
        if (at >= 0) {
            pick = rows[at];
            have_pick = true;
        }
    }
    if (!have_pick) {
        free(rows);
        dvq_unlock(lock);
        (void)json_push_kv_str(&reply->data, "leaf", DVQ_LEAF);
        (void)json_push_kv_str(&reply->data, "state", "empty");
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = 0;
        return;
    }
    /* READY row held under the lock; now find it a free warm
     * worktree. Every probe below is a non-blocking local file op. */
    wt[0] = '\0';
    {
        char *text = (char *)zcl_malloc(DVQ_POOL_CAP, "devagent.queue.pool");
        char *save = NULL, *line;
        if (!text) {
            free(rows);
            dvq_close_wt(wtfd);
            dvq_unlock(lock);
            dvq_fail(reply, "QUEUE_READ_FAILED", "select",
                     "cannot allocate the pool buffer", poolpath);
            return;
        }
        if (dvq_read_file(poolpath, text, DVQ_POOL_CAP, NULL)) {
            for (line = strtok_r(text, "\n", &save); line;
                 line = strtok_r(NULL, "\n", &save)) {
                int fd = -1;
                dvq_trim(line);
                if (!line[0] || wt[0])
                    continue;
                if (strlen(line) >= sizeof(wt))
                    continue;
                if (dvq_try_worktree(line, &fd)) {
                    memcpy(wt, line, strlen(line) + 1);
                    wtfd = fd;
                }
            }
        }
        free(text);
    }
    if (!wt[0]) {
        free(rows);
        dvq_unlock(lock);
        dvq_emit_no_worktree(reply, poolpath);
        return;
    }
    /* Mark running before releasing the lock; the worktree fd stays open
     * across the spawn so the child inherits the lock. */
    if (pick.model[0])
        (void)snprintf(model, sizeof(model), "%s", pick.model);
    else
        (void)snprintf(model, sizeof(model), "%s",
                       pick.attempt >= 3 ? "glm-5.3" : "glm-5.3-flash");
    doc = strcmp(pick.kind, "doc") == 0;
    if (!doc && strcmp(pick.kind, "file") != 0) {
        tmo = "1200";
        gtmo = "2400";
    } else {
        tmo = "900";
        gtmo = NULL;
    }
    (void)snprintf(pick.worktree, sizeof(pick.worktree), "%s", wt);
    pick.started = (long long)platform_time_wall_unix();
    dvq_stamp_owner(&pick);
    if (dvq_have_systemd()) {
        char frag[96];
        dvq_unit_frag(pick.name, frag, sizeof(frag));
        (void)snprintf(unit, sizeof(unit), "eu-%s-a%lld-s%lld", frag,
                       pick.attempt, pick.seq);
        (void)snprintf(pick.pid_or_unit, sizeof(pick.pid_or_unit), "%s",
                       unit);
    } else {
        (void)snprintf(pick.pid_or_unit, sizeof(pick.pid_or_unit),
                       "direct");
    }
    (void)snprintf(pick.state, sizeof(pick.state), "running");
    for (size_t i = 0; i < nrows; i++) {
        if (rows[i].seq == pick.seq) {
            rows[i] = pick;
            break;
        }
    }
    if (!dvq_rewrite_rows(d.queue, qpath, rows, nrows)) {
        free(rows);
        dvq_close_wt(wtfd);
        dvq_unlock(lock);
        dvq_fail(reply, "QUEUE_WRITE_FAILED", "dispatch",
                 "cannot mark the row running", qpath);
        return;
    }
    free(rows);
    rows = NULL;
    dvq_unlock(lock);
    /* The row is durable now; everything below can fail back to queued. */
    if (snprintf(st, sizeof(st), "%s/%s/a%lld", d.engine, pick.name,
                 pick.attempt) >= (int)sizeof(st) ||
        snprintf(taskpath, sizeof(taskpath), "%s/task.txt", st) >=
            (int)sizeof(taskpath) ||
        snprintf(runout, sizeof(runout), "%s/run.out", st) >=
            (int)sizeof(runout) ||
        snprintf(lockpath, sizeof(lockpath), "%s/.eu-lock", wt) >=
            (int)sizeof(lockpath)) {
        dvq_close_wt(wtfd);
        dvq_unmark(d.queue, qpath, pick.seq);
        dvq_fail(reply, "DISPATCH_FAILED", "dispatch",
                 "the run paths do not fit their buffers",
                 "platform_state_root too long");
        return;
    }
    {
        char namedir[4096 + 80];
        (void)snprintf(namedir, sizeof(namedir), "%s/%s", d.engine,
                       pick.name);
        if (!dvq_mkdir_one(namedir) || !dvq_mkdir_one(st)) {
            dvq_close_wt(wtfd);
            dvq_unmark(d.queue, qpath, pick.seq);
            dvq_fail(reply, "STATE_DIR_FAILED", "dispatch",
                     "cannot create the run state dir", st);
            return;
        }
    }
    task = (char *)zcl_malloc(DVQ_TASK_CAP, "devagent.queue.task");
    if (!task) {
        dvq_close_wt(wtfd);
        dvq_unmark(d.queue, qpath, pick.seq);
        dvq_fail(reply, "DISPATCH_FAILED", "dispatch",
                 "cannot allocate the task buffer", "malloc failed");
        return;
    }
    if (!dvq_compose_task(&pick, wt, st, d.engine, task, DVQ_TASK_CAP,
                          &task_used) ||
        !dvq_write_file(taskpath, task, task_used)) {
        free(task);
        dvq_close_wt(wtfd);
        dvq_unmark(d.queue, qpath, pick.seq);
        dvq_fail(reply, "DISPATCH_FAILED", "dispatch",
                 "cannot compose the task file", taskpath);
        return;
    }
    free(task);
    if (!dvq_find_harness(harness, sizeof(harness))) {
        dvq_close_wt(wtfd);
        dvq_unmark(d.queue, qpath, pick.seq);
        dvq_fail(reply, "DISPATCH_NO_HARNESS", "dispatch",
                 "zclassic23-engine-unit is not on PATH and "
                 "ZCL_ENGINE_UNIT_BIN is unset",
                 "install the harness or set ZCL_ENGINE_UNIT_BIN");
        return;
    }
    {
        int n = 0;
        hargv[n++] = harness;
        hargv[n++] = "--engine";
        hargv[n++] = "glm";
        hargv[n++] = "--model";
        hargv[n++] = model;
        hargv[n++] = "--task";
        hargv[n++] = taskpath;
        if (doc) {
            hargv[n++] = "--no-group";
        } else {
            if (pick.group[0])
                (void)snprintf(group, sizeof(group), "%s", pick.group);
            else
                (void)snprintf(group, sizeof(group), "devagent_%s",
                               pick.name);
            hargv[n++] = "--group";
            hargv[n++] = group;
        }
        hargv[n++] = "--territory";
        hargv[n++] = "engine/modules/engine";
        hargv[n++] = "--worktree";
        hargv[n++] = wt;
        hargv[n++] = "--state-dir";
        hargv[n++] = st;
        hargv[n++] = "--timeout";
        hargv[n++] = tmo;
        if (gtmo) {
            hargv[n++] = "--gate-timeout";
            hargv[n++] = gtmo;
        }
        hargv[n++] = "--turns";
        hargv[n++] = "3";
        hargv[n++] = "--yes-dispatch";
        hargv[n++] = NULL;
        have_zbin = dvq_z23_bin(wt, zbind, sizeof(zbind));
        if (have_zbin) {
            if (snprintf(zbenv, sizeof(zbenv), "ZCL_Z23_BIN=%s", zbind) >=
                (int)sizeof(zbenv))
                have_zbin = false;
        }
        if (dvq_have_systemd()) {
            int m = 0;
            (void)snprintf(unitarg, sizeof(unitarg), "--unit=%s", unit);
            (void)snprintf(wdirarg, sizeof(wdirarg),
                           "--working-directory=%s", wt);
            (void)snprintf(outarg, sizeof(outarg),
                           "StandardOutput=truncate:%s", runout);
            (void)snprintf(errarg, sizeof(errarg),
                           "StandardError=truncate:%s", runout);
            sargv[m++] = "systemd-run";
            sargv[m++] = "--user";
            sargv[m++] = "--quiet";
            sargv[m++] = "--collect";
            sargv[m++] = "-p";
            sargv[m++] = "CPUQuota=600%";
            sargv[m++] = "-p";
            sargv[m++] = "Nice=12";
            sargv[m++] = "-p";
            sargv[m++] = outarg;
            sargv[m++] = "-p";
            sargv[m++] = errarg;
            sargv[m++] = unitarg;
            sargv[m++] = wdirarg;
            if (have_zbin) {
                (void)snprintf(zsetenv, sizeof(zsetenv), "--setenv=%s",
                               zbenv);
                sargv[m++] = zsetenv;
            }
            sargv[m++] = "flock";
            sargv[m++] = "-n";
            sargv[m++] = lockpath;
            for (int i = 0; hargv[i] && m < (int)(sizeof(sargv) /
                                                 sizeof(sargv[0])) - 1;
                 i++)
                sargv[m++] = hargv[i];
            sargv[m] = NULL;
            /* The unit takes its own flock; ours guarded it until launch. */
            dvq_close_wt(wtfd);
            wtfd = -1;
            zr = zcl_spawn_detached(sargv, runout);
        } else if (have_zbin) {
            /* No shell anywhere: env(1) carries the one variable and
             * execs the harness with the same argv. */
            int m = 0;
            sargv[m++] = "env";
            sargv[m++] = zbenv;
            for (int i = 0; hargv[i] && m < (int)(sizeof(sargv) /
                                                 sizeof(sargv[0])) - 1;
                 i++)
                sargv[m++] = hargv[i];
            sargv[m] = NULL;
            zr = zcl_spawn_detached(sargv, runout);
            /* The child inherited the worktree lock; ours can close. */
            dvq_close_wt(wtfd);
            wtfd = -1;
        } else {
            zr = zcl_spawn_detached(hargv, runout);
            /* The child inherited the worktree lock; ours can close. */
            dvq_close_wt(wtfd);
            wtfd = -1;
        }
    }
    if (!zr.ok) {
        dvq_unmark(d.queue, qpath, pick.seq);
        dvq_fail(reply, "DISPATCH_FAILED", "dispatch",
                 "the detached launch failed before handoff",
                 zr.message[0] ? zr.message : harness);
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", DVQ_LEAF);
    (void)json_push_kv_int(&reply->data, "seq", pick.seq);
    (void)json_push_kv_str(&reply->data, "name", pick.name);
    (void)json_push_kv_str(&reply->data, "worktree", wt);
    (void)json_push_kv_str(&reply->data, "pid_or_unit", pick.pid_or_unit);
    (void)json_push_kv_str(&reply->data, "state", "running");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* ── reap ──────────────────────────────────────────────────────────────── */

/* The run's numeric result: a trailing ^rc=N line (the interim shell's own
 * mark) or the harness's own trailing ^exit N line; -1 when neither fired. */
static long long dvq_runout_rc(const char *text)
{
    long long rc = -1, n;
    char *save = NULL, *line;
    char *copy;
    size_t len;
    if (!text)
        return -1;
    len = strlen(text) + 1;
    copy = (char *)zcl_malloc(len, "devagent.queue.runout");
    if (!copy)
        return -1;
    memcpy(copy, text, len);
    for (line = strtok_r(copy, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char *end = NULL;
        if (strncmp(line, "rc=", 3) == 0)
            n = strtoll(line + 3, &end, 10);
        else if (strncmp(line, "exit ", 5) == 0)
            n = strtoll(line + 5, &end, 10);
        else
            continue;
        if (end && end != line + 3 && n >= 0)
            rc = n;
    }
    free(copy);
    return rc;
}

static bool dvq_rate_limited(const char *text)
{
    static const char *const marks[] = {
        "circuit", "rate_limited", "response_refused", "refusing an empty",
    };
    size_t i;
    if (!text)
        return false;
    for (i = 0; i < sizeof(marks) / sizeof(marks[0]); i++) {
        if (strstr(text, marks[i]))
            return true;
    }
    return false;
}

/* USAGE CONTRACT. Every outcome (reap reply, outcomes.jsonl row, status)
 * carries tokens_used and wall_ms copied from the run's receipt.json
 * ("tokens" or "tokens_used", and "wall_ms"). A run with no receipt, or a
 * receipt that does not state the field, reports JSON null (-1 in the
 * jsonl row) — never 0: a run with no receipt did not cost nothing, it
 * cost an amount nobody recorded. Each running status row names its
 * claimant as `worker` from the run's claim.json, or null when nothing
 * claimed it through claim. */
struct dvq_usage {
    long long tokens;
    long long wall_ms;
};

static void dvq_usage_unknown(struct dvq_usage *u)
{
    u->tokens = -1;
    u->wall_ms = -1;
}

static void dvq_usage_from_text(const char *text, struct dvq_usage *u)
{
    long long v = -1;
    dvq_usage_unknown(u);
    if (!text)
        return;
    if ((dvq_line_int(text, "tokens", &v) ||
         dvq_line_int(text, "tokens_used", &v)) &&
        v >= 0)
        u->tokens = v;
    v = -1;
    if (dvq_line_int(text, "wall_ms", &v) && v >= 0)
        u->wall_ms = v;
}

static bool dvq_receipt_verdict(const char *path, char *out, size_t cap,
                                struct dvq_usage *usage)
{
    char text[DVQ_LINE_CAP];
    if (usage)
        dvq_usage_unknown(usage);
    if (!path || !out || cap == 0)
        return false;
    if (!dvq_read_file(path, text, sizeof(text), NULL))
        return false;
    if (usage)
        dvq_usage_from_text(text, usage);
    return dvq_line_str(text, "verdict", out, cap);
}

/* A usage field into an outcome item: the number when stated, JSON null
 * when unknown. */
static bool dvq_push_usage_field(struct json_value *item, const char *key,
                                 long long v)
{
    struct json_value nv;
    bool ok;
    if (v >= 0)
        return json_push_kv_int(item, key, v);
    json_init(&nv);
    json_set_null(&nv);
    ok = json_push_kv(item, key, &nv);
    json_free(&nv);
    return ok;
}

static bool dvq_push_outcome(struct json_value *arr, const char *name,
                             long long attempt, const char *verdict,
                             long long rc, const char *ts,
                             const struct dvq_usage *usage)
{
    struct json_value item;
    struct dvq_usage none;
    bool ok;
    if (!usage) {
        dvq_usage_unknown(&none);
        usage = &none;
    }
    json_init(&item);
    json_set_object(&item);
    ok = json_push_kv_str(&item, "name", name) &&
         json_push_kv_int(&item, "attempt", attempt) &&
         json_push_kv_str(&item, "verdict", verdict) &&
         json_push_kv_int(&item, "rc", rc) &&
         json_push_kv_str(&item, "ts", ts ? ts : "") &&
         dvq_push_usage_field(&item, "tokens_used", usage->tokens) &&
         dvq_push_usage_field(&item, "wall_ms", usage->wall_ms) &&
         json_push_back(arr, &item);
    json_free(&item);
    return ok;
}

/* ── orphan reclaim ──────────────────────────────────────────────────────
 * A claimant that dies between "mark running" and the run's first
 * artifact leaves a running row reap would skip forever (no receipt, no
 * rc line) and cancel refuses. Reap returns such a row to queued, and
 * only when BOTH hold: the run dir carries no artifact at all (so nothing
 * was ever submitted or launched), and the stamped claimant is provably
 * gone — the pid is dead, or a live pid carries a different kernel start
 * token (the pid was reused). An unknown claimant (a row from before the
 * stamp) and an undecidable liveness both count as alive. */

static const char *const dvq_run_artifacts[] = {
    "claim.json", "task.txt", "run.out", "receipt.json",
};

static bool dvq_run_artifact_free(const char *engine, const struct dvq_row *r)
{
    char path[4096 + 160];
    struct stat st;
    size_t i;
    for (i = 0; i < sizeof(dvq_run_artifacts) / sizeof(dvq_run_artifacts[0]);
         i++) {
        if (snprintf(path, sizeof(path), "%s/%s/a%lld/%s", engine, r->name,
                     r->attempt, dvq_run_artifacts[i]) >= (int)sizeof(path))
            return false;
        if (stat(path, &st) == 0 || errno != ENOENT)
            return false;
    }
    return true;
}

static bool dvq_owner_gone(const struct dvq_row *r)
{
    uint64_t token = 0;
    enum os_proc_liveness live;
    if (r->owner_pid <= 0)
        return false;
    live = os_proc_pid_liveness((uint64_t)r->owner_pid);
    if (live == OS_PROC_LIVENESS_DEAD)
        return true;
    if (live != OS_PROC_LIVENESS_RUNNING || r->owner_start <= 0)
        return false;
    if (!os_proc_pid_start_token((uint64_t)r->owner_pid, &token))
        return false;
    return token != (uint64_t)r->owner_start;
}

/* Requeue every orphan in rows (under the caller's queue lock). */
static long long dvq_reclaim_orphans(const char *engine, struct dvq_row *rows,
                                     size_t nrows)
{
    long long reclaimed = 0;
    size_t i;
    for (i = 0; i < nrows; i++) {
        struct dvq_row *r = &rows[i];
        if (strcmp(r->state, "running") != 0 || !dvq_owner_gone(r) ||
            !dvq_run_artifact_free(engine, r))
            continue;
        (void)snprintf(r->state, sizeof(r->state), "queued");
        r->worktree[0] = '\0';
        r->pid_or_unit[0] = '\0';
        r->started = 0;
        dvq_clear_owner(r);
        reclaimed++;
    }
    return reclaimed;
}

static void dvq_reap(const struct zcl_command_request *req,
                     struct zcl_command_reply *reply)
{
    struct dvq_dirs d;
    struct dvq_row *rows = NULL;
    size_t nrows = 0, caprows = 0;
    char qpath[4096 + 32], opath[4096 + 32], stampp[4096 + 32];
    char line[DVQ_LINE_CAP];
    struct json_value outcomes;
    long long requeued = 0;
    long long reclaimed = 0;
    long long maxseq = 0;
    time_t stamp = 0;
    struct stat st;
    int lock = -1;
    size_t len = 0;
    (void)req;
    if (!dvq_dirs_resolve(&d, true)) {
        dvq_fail(reply, "STATE_DIR_FAILED", "reap",
                 "cannot resolve the owner-private state root",
                 "platform_state_root");
        return;
    }
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d.queue) >=
            (int)sizeof(qpath) ||
        snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", d.queue) >=
            (int)sizeof(opath) ||
        snprintf(stampp, sizeof(stampp), "%s/.reap_stamp", d.queue) >=
            (int)sizeof(stampp)) {
        dvq_fail(reply, "QUEUE_READ_FAILED", "reap",
                 "the queue paths do not fit their buffers",
                 "platform_state_root too long");
        return;
    }
    if (stat(stampp, &st) == 0)
        stamp = st.st_mtime;
    lock = dvq_lock(d.queue);
    if (lock < 0) {
        dvq_fail(reply, "QUEUE_READ_FAILED", "reap",
                 "cannot take the queue lock", qpath);
        return;
    }
    if (!dvq_load_rows(qpath, &rows, &nrows)) {
        dvq_unlock(lock);
        dvq_fail(reply, "QUEUE_READ_FAILED", "reap",
                 "cannot read the queue file", qpath);
        return;
    }
    caprows = nrows;
    reclaimed = dvq_reclaim_orphans(d.engine, rows, nrows);
    for (size_t i = 0; i < nrows; i++) {
        if (rows[i].seq > maxseq)
            maxseq = rows[i].seq;
    }
    json_init(&outcomes);
    json_set_array(&outcomes);
    for (size_t i = 0; i < nrows; i++) {
        struct dvq_row *r = &rows[i];
        char dir[4096 + 128], receipt[4096 + 160], runout[4096 + 160];
        char seen[4096 + 160];
        char verdict[128], ots[64], oline[DVQ_LINE_CAP];
        char *runtext = NULL;
        size_t runlen = 0;
        FILE *probe;
        long long rc = -1;
        bool have_receipt = false;
        struct dvq_usage usage;
        dvq_usage_unknown(&usage);
        if (strcmp(r->state, "running") != 0)
            continue;
        if (snprintf(dir, sizeof(dir), "%s/%s/a%lld", d.engine, r->name,
                     r->attempt) >= (int)sizeof(dir) ||
            snprintf(receipt, sizeof(receipt), "%s/receipt.json", dir) >=
                (int)sizeof(receipt) ||
            snprintf(runout, sizeof(runout), "%s/run.out", dir) >=
                (int)sizeof(runout) ||
            snprintf(seen, sizeof(seen), "%s/.seen", dir) >=
                (int)sizeof(seen))
            continue;
        probe = fopen(seen, "rb");
        if (probe) {
            (void)fclose(probe);
            continue;
        }
        /* >=, not >: a receipt written in the same second as the stamp
         * is still new. Already-recorded receipts are excluded by the
         * .seen check above, so widening the comparison cannot
         * double-record. */
        if (stat(receipt, &st) == 0 && (stamp == 0 || st.st_mtime >= stamp))
            have_receipt = true;
        runtext = (char *)zcl_malloc(DVQ_FILE_CAP, "devagent.queue.runout");
        if (!runtext)
            continue;
        if (dvq_read_file(runout, runtext, DVQ_FILE_CAP, &runlen))
            rc = dvq_runout_rc(runtext);
        else
            runlen = 0;
        if (!have_receipt && rc < 0) {
            free(runtext);
            continue;
        }
        if (have_receipt) {
            if (!dvq_receipt_verdict(receipt, verdict, sizeof(verdict),
                                     &usage))
                (void)snprintf(verdict, sizeof(verdict), "unknown");
        } else {
            (void)snprintf(verdict, sizeof(verdict), "no-receipt");
        }
        dvq_now_iso(ots);
        if (!dvq_push_outcome(&outcomes, r->name, r->attempt, verdict, rc,
                              ots, &usage)) {
            free(runtext);
            json_free(&outcomes);
            free(rows);
            dvq_unlock(lock);
            dvq_fail(reply, "QUEUE_WRITE_FAILED", "reap",
                     "cannot encode the outcome reply", opath);
            return;
        }
        {
            char esc_verdict[256];
            int w;
            if (!dvq_escape(verdict, esc_verdict, sizeof(esc_verdict))) {
                free(runtext);
                json_free(&outcomes);
                free(rows);
                dvq_unlock(lock);
                dvq_fail(reply, "QUEUE_WRITE_FAILED", "reap",
                         "cannot encode the outcome row", opath);
                return;
            }
            w = snprintf(oline, sizeof(oline),
                         "{\"ts\":\"%s\",\"name\":\"%s\",\"attempt\":"
                         "%lld,\"verdict\":\"%s\",\"rc\":%lld,"
                         "\"tokens_used\":%lld,\"wall_ms\":%lld}\n",
                         ots, r->name, r->attempt, esc_verdict, rc,
                         usage.tokens, usage.wall_ms);
            if (w <= 0 || (size_t)w >= sizeof(oline) ||
                !dvq_append_row(opath, oline, (size_t)w)) {
                free(runtext);
                json_free(&outcomes);
                free(rows);
                dvq_unlock(lock);
                dvq_fail(reply, "QUEUE_WRITE_FAILED", "reap",
                         "cannot append the outcome row", opath);
                return;
            }
        }
        /* Mark seen before any requeue, so a retry never double-records. */
        {
            char now[32];
            (void)snprintf(now, sizeof(now), "%lld",
                           (long long)platform_time_wall_unix());
            (void)dvq_write_file(seen, now, strlen(now));
        }
        if (runlen > 0 && dvq_rate_limited(runtext) &&
            r->attempt < 3) {
            /* Copy the row BEFORE any realloc: r points into rows and
             * would dangle across the grow below. */
            struct dvq_row back = *r;
            long long back_attempt = back.attempt + 1;
            char nts[64];
            struct dvq_row *grow;
            if (nrows == caprows) {
                size_t ncap = caprows == 0 ? 16 : caprows * 2;
                if (ncap > 65536) {
                    free(runtext);
                    continue;
                }
                grow = (struct dvq_row *)zcl_realloc(
                    rows, ncap * sizeof(*rows), "devagent.queue.rows");
                if (!grow) {
                    free(runtext);
                    continue;
                }
                rows = grow;
                caprows = ncap;
            }
            dvq_now_iso(nts);
            back.seq = ++maxseq;
            back.attempt = back_attempt;
            back.state[0] = '\0';
            (void)snprintf(back.state, sizeof(back.state), "queued");
            back.worktree[0] = '\0';
            back.pid_or_unit[0] = '\0';
            back.started = 0;
            dvq_clear_owner(&back);
            (void)snprintf(back.ts, sizeof(back.ts), "%s", nts);
            if (dvq_encode_row(&back, line, sizeof(line), &len)) {
                rows[nrows++] = back;
                requeued++;
            } else {
                maxseq--;
            }
        }
        free(runtext);
    }
    /* Drop every running row the scan just marked seen; the requeued rows
     * appended above survive because they are queued, not seen. */
    {
        size_t kept = 0;
        for (size_t i = 0; i < nrows; i++) {
            bool drop = false;
            if (strcmp(rows[i].state, "running") == 0) {
                char dir[4096 + 128], seen[4096 + 160];
                FILE *probe;
                if (snprintf(dir, sizeof(dir), "%s/%s/a%lld", d.engine,
                             rows[i].name,
                             rows[i].attempt) < (int)sizeof(dir) &&
                    snprintf(seen, sizeof(seen), "%s/.seen", dir) <
                        (int)sizeof(seen)) {
                    probe = fopen(seen, "rb");
                    if (probe) {
                        (void)fclose(probe);
                        drop = true;
                    }
                }
            }
            if (!drop)
                rows[kept++] = rows[i];
        }
        nrows = kept;
        if (!dvq_rewrite_rows(d.queue, qpath, rows, nrows)) {
            json_free(&outcomes);
            free(rows);
            dvq_unlock(lock);
            dvq_fail(reply, "QUEUE_WRITE_FAILED", "reap",
                     "cannot rewrite the queue file", qpath);
            return;
        }
    }
    {
        char now[32];
        (void)snprintf(now, sizeof(now), "%lld", (long long)platform_time_wall_unix());
        (void)dvq_write_file(stampp, now, strlen(now));
    }
    free(rows);
    dvq_unlock(lock);
    (void)json_push_kv_str(&reply->data, "leaf", DVQ_LEAF);
    (void)json_push_kv_str(&reply->data, "state", "reaped");
    (void)json_push_kv(&reply->data, "outcomes", &outcomes);
    json_free(&outcomes);
    (void)json_push_kv_int(&reply->data, "requeued", requeued);
    (void)json_push_kv_int(&reply->data, "reclaimed", reclaimed);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* ── status ────────────────────────────────────────────────────────────── */

/* A string, or JSON null when empty: an absent value is never "". */
static void dvq_str_or_null(struct json_value *v, const char *s)
{
    json_init(v);
    if (s && s[0])
        json_set_str(v, s);
    else
        json_set_null(v);
}

/* What holds a queued row back, or JSON null when it is READY: the ref,
 * that ref's state (terminal, queued, running, absent), its current
 * attempt, and the verdict that attempt ended with (null while pending). */
static void dvq_blocker_json(struct json_value *out, const char *ref,
                             const struct dvq_dep *dep)
{
    struct json_value verdict, attempt;
    json_init(out);
    if (!ref) {
        json_set_null(out);
        return;
    }
    json_set_object(out);
    dvq_str_or_null(&verdict, dep->verdict);
    json_init(&attempt);
    if (dep->attempt > 0)
        json_set_int(&attempt, dep->attempt);
    else
        json_set_null(&attempt);
    (void)(json_push_kv_str(out, "ref", ref) &&
           json_push_kv_str(out, "state", dep->state) &&
           json_push_kv(out, "attempt", &attempt) &&
           json_push_kv(out, "verdict", &verdict));
    json_free(&verdict);
    json_free(&attempt);
}

/* One queued row with its READY verdict from the picker's own gates; a
 * READY row counts into *nready. */
static bool dvq_push_queued(struct json_value *arr, const struct dvq_row *rows,
                            size_t n, size_t i, const char *opath,
                            long long *nready)
{
    const struct dvq_row *r = &rows[i];
    struct json_value item, blocker;
    struct dvq_dep dep;
    const char *ref = NULL;
    bool ready = dvq_row_gate(rows, n, i, opath, &dep, &ref);
    bool ok;
    *nready += ready ? 1 : 0;
    dvq_blocker_json(&blocker, ref, &dep);
    json_init(&item);
    json_set_object(&item);
    ok = json_push_kv_int(&item, "seq", r->seq) &&
         json_push_kv_str(&item, "name", r->name) &&
         json_push_kv_str(&item, "kind", r->kind) &&
         json_push_kv_int(&item, "attempt", r->attempt) &&
         json_push_kv_str(&item, "ts", r->ts) &&
         json_push_kv_int(&item, "priority", r->priority) &&
         json_push_kv_str(&item, "depends_on", r->depends_on) &&
         json_push_kv_bool(&item, "ready", ready) &&
         json_push_kv(&item, "blocker", &blocker) &&
         json_push_back(arr, &item);
    json_free(&item);
    json_free(&blocker);
    return ok;
}

/* The human line for one queued row: READY rows plain, held rows say
 * which ref holds them — blocked by a terminal or absent ref, waiting on
 * a pending one. Returns snprintf's count. */
static int dvq_screen_queued(char *out, size_t cap, const struct dvq_row *rows,
                             size_t n, size_t i, const char *opath)
{
    const struct dvq_row *r = &rows[i];
    struct dvq_dep dep;
    const char *ref = NULL;
    bool pending;
    if (dvq_row_gate(rows, n, i, opath, &dep, &ref))
        return snprintf(out, cap, "  #%lld queued  %-12s a%-3lld\n", r->seq,
                        r->name, r->attempt);
    if (dep.attempt <= 0)
        return snprintf(out, cap,
                        "  #%lld queued  %-12s a%-3lld blocked by %s "
                        "(absent)\n", r->seq, r->name, r->attempt, ref);
    pending = strcmp(dep.state, "terminal") != 0;
    return snprintf(out, cap, "  #%lld queued  %-12s a%-3lld %s %s a%lld %s\n",
                    r->seq, r->name, r->attempt,
                    pending ? "waiting on" : "blocked by", ref, dep.attempt,
                    pending ? dep.state : dep.verdict);
}

/* The claimant a resident worker persisted in the run's claim.json, so a
 * running row names who claimed it. Empty when the row was launched by
 * `next` (no claim file) or the file does not read: the caller reports
 * that as JSON null, never as a guessed name. */
static void dvq_claim_worker(const char *engine, const struct dvq_row *r,
                             char *out, size_t cap)
{
    char path[4096 + 256], text[DVQ_LINE_CAP];
    out[0] = '\0';
    if (!engine || snprintf(path, sizeof(path), "%s/%s/a%lld/claim.json",
                            engine, r->name,
                            r->attempt) >= (int)sizeof(path))
        return;
    if (!dvq_read_file(path, text, sizeof(text), NULL) ||
        !dvq_line_str(text, "worker", out, cap))
        out[0] = '\0';
}

static bool dvq_push_running(struct json_value *arr, const struct dvq_row *r,
                             long long now, const char *engine)
{
    struct json_value item, nv;
    char worker[64];
    long long age = now - r->started;
    bool ok;
    if (age < 0)
        age = 0;
    dvq_claim_worker(engine, r, worker, sizeof(worker));
    json_init(&nv);
    if (worker[0])
        json_set_str(&nv, worker);
    else
        json_set_null(&nv);
    json_init(&item);
    json_set_object(&item);
    ok = json_push_kv_int(&item, "seq", r->seq) &&
         json_push_kv_str(&item, "name", r->name) &&
         json_push_kv_str(&item, "kind", r->kind) &&
         json_push_kv_int(&item, "attempt", r->attempt) &&
         json_push_kv_str(&item, "worktree", r->worktree) &&
         json_push_kv_str(&item, "pid_or_unit", r->pid_or_unit) &&
         json_push_kv_int(&item, "age_s", age) &&
         json_push_kv_str(&item, "owner_liveness", dvq_owner_liveness(r)) &&
         json_push_kv(&item, "worker", &nv) &&
         json_push_back(arr, &item);
    json_free(&item);
    json_free(&nv);
    return ok;
}

/* A warm entry whose NB lock holds right now counts as free. The probe
 * never holds the lock past this call. */
static void dvq_status(const struct zcl_command_request *req,
                       struct zcl_command_reply *reply)
{
    struct dvq_dirs d;
    struct dvq_row *rows = NULL;
    size_t nrows = 0;
    char qpath[4096 + 32], opath[4096 + 32], poolpath[4096 + 32];
    struct json_value queued, running, outcomes, pool;
    long long queued_ready = 0;
    struct dvq_pool_census census;
    long long now = (long long)platform_time_wall_unix();
    bool want_json = false;
    const struct json_value *jv;
    char screen[16384];
    size_t used = 0;
    int w;
    if (req && req->input) {
        jv = json_get(req->input, "json");
        want_json = jv && json_get_bool(jv);
    }
    if (!dvq_dirs_resolve(&d, false)) {
        dvq_fail(reply, "STATE_DIR_FAILED", "status",
                 "cannot resolve the owner-private state root",
                 "platform_state_root");
        return;
    }
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d.queue) >=
            (int)sizeof(qpath) ||
        snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", d.queue) >=
            (int)sizeof(opath) ||
        snprintf(poolpath, sizeof(poolpath), "%s/pool.txt", d.queue) >=
            (int)sizeof(poolpath)) {
        dvq_fail(reply, "QUEUE_READ_FAILED", "status",
                 "the queue paths do not fit their buffers",
                 "platform_state_root too long");
        return;
    }
    if (!dvq_load_rows(qpath, &rows, &nrows)) {
        dvq_fail(reply, "QUEUE_READ_FAILED", "status",
                 "cannot read the queue file", qpath);
        return;
    }
    json_init(&queued);
    json_set_array(&queued);
    json_init(&running);
    json_set_array(&running);
    json_init(&outcomes);
    json_set_array(&outcomes);
    json_init(&pool);
    json_set_object(&pool);
    for (size_t i = 0; i < nrows; i++) {
        if (strcmp(rows[i].state, "queued") == 0) {
            if (!dvq_push_queued(&queued, rows, nrows, i, opath,
                                 &queued_ready))
                goto fail;
        } else if (strcmp(rows[i].state, "running") == 0) {
            if (!dvq_push_running(&running, &rows[i], now, d.engine))
                goto fail;
        }
    }
    /* Last 10 outcome rows, oldest first. */
    {
        char *text = (char *)zcl_malloc(DVQ_FILE_CAP, "devagent.queue.outcomes");
        if (!text)
            goto fail;
        if (dvq_read_file(opath, text, DVQ_FILE_CAP, NULL)) {
            struct {
                char name[80];
                long long attempt;
                char verdict[128];
                long long rc;
                char ts[64];
                struct dvq_usage usage;
            } last[10];
            size_t kept = 0;
            char *save = NULL, *line;
            for (line = strtok_r(text, "\n", &save); line;
                 line = strtok_r(NULL, "\n", &save)) {
                char name[80], verdict[128], ts[64];
                long long attempt = 0, rc = -1;
                if (!dvq_line_str(line, "name", name, sizeof(name)) ||
                    !dvq_line_int(line, "attempt", &attempt))
                    continue;
                (void)dvq_line_str(line, "verdict", verdict,
                                   sizeof(verdict));
                (void)dvq_line_int(line, "rc", &rc);
                (void)dvq_line_str(line, "ts", ts, sizeof(ts));
                if (kept == sizeof(last) / sizeof(last[0])) {
                    for (size_t k = 1; k < kept; k++)
                        last[k - 1] = last[k];
                    kept--;
                }
                (void)snprintf(last[kept].name, sizeof(last[kept].name),
                               "%s", name);
                last[kept].attempt = attempt;
                (void)snprintf(last[kept].verdict,
                               sizeof(last[kept].verdict), "%s", verdict);
                last[kept].rc = rc;
                (void)snprintf(last[kept].ts, sizeof(last[kept].ts), "%s",
                               ts);
                dvq_usage_from_text(line, &last[kept].usage);
                kept++;
            }
            for (size_t k = 0; k < kept; k++) {
                if (!dvq_push_outcome(&outcomes, last[k].name,
                                      last[k].attempt, last[k].verdict,
                                      last[k].rc, last[k].ts,
                                      &last[k].usage))
                    break;
            }
        }
        free(text);
    }
    dvq_pool_take(poolpath, &census);
    /* known FIRST, then every count, which are null — never 0 — when the pool
     * was not measured, so a consumer reading only the numbers cannot mistake
     * "nobody listed a pool here" for "the pool is empty". `blocked` names the
     * ONE reason dispatch is impossible, so no caller has to infer it from a
     * set of zeroes, and "idle" can never stand in for "cannot dispatch". */
    if (!dvq_status_pool(&pool, &census))
        goto fail;
    if (!want_json) {
        char poolline[220];
        dvq_pool_line(poolline, sizeof(poolline), &census);
        w = snprintf(screen, sizeof(screen),
                     "queue: %llu queued (%lld ready), %llu running (%s)\n",
                     (unsigned long long)queued.num_children, queued_ready,
                     (unsigned long long)running.num_children, poolline);
        if (w <= 0 || (size_t)w >= sizeof(screen))
            goto fail;
        used = (size_t)w;
        for (size_t i = 0; i < nrows; i++) {
            const char *tag = NULL;
            if (strcmp(rows[i].state, "queued") == 0)
                tag = "queued ";
            else if (strcmp(rows[i].state, "running") == 0)
                tag = "running";
            else if (strcmp(rows[i].state, "WAITING_EXTERNAL") == 0)
                tag = "waiting";
            else
                continue;
            if (i >= 40) {
                w = snprintf(screen + used, sizeof(screen) - used,
                             "  ... and %llu more\n",
                             (unsigned long long)(nrows - i));
                if (w > 0 && (size_t)w < sizeof(screen) - used)
                    used += (size_t)w;
                break;
            }
            if (strcmp(tag, "running") == 0) {
                long long age = now - rows[i].started;
                if (age < 0)
                    age = 0;
                w = snprintf(screen + used, sizeof(screen) - used,
                             "  #%lld %-7s %-12s a%-3lld %s age %llds\n",
                             rows[i].seq, tag, rows[i].name,
                             rows[i].attempt, rows[i].worktree, age);
            } else if (strcmp(tag, "waiting") == 0) {
                w = snprintf(screen + used, sizeof(screen) - used,
                             "  #%lld WAITING_EXTERNAL %-12s a%-3lld %s\n",
                             rows[i].seq, rows[i].name, rows[i].attempt,
                             rows[i].depends_on);
            } else {
                w = dvq_screen_queued(screen + used, sizeof(screen) - used,
                                      rows, nrows, i, opath);
            }
            if (w <= 0 || (size_t)w >= sizeof(screen) - used)
                break;
            used += (size_t)w;
        }
    }
    free(rows);
    (void)json_push_kv_str(&reply->data, "leaf", DVQ_LEAF);
    (void)json_push_kv(&reply->data, "queued", &queued);
    (void)json_push_kv_int(&reply->data, "queued_total",
                           (long long)queued.num_children);
    (void)json_push_kv_int(&reply->data, "queued_ready", queued_ready);
    (void)json_push_kv(&reply->data, "running", &running);
    (void)json_push_kv(&reply->data, "outcomes", &outcomes);
    (void)json_push_kv(&reply->data, "pool", &pool);
    json_free(&queued);
    json_free(&running);
    json_free(&outcomes);
    json_free(&pool);
    if (!want_json)
        (void)json_push_kv_str(&reply->data, "screen", screen);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
    return;
fail:
    json_free(&queued);
    json_free(&running);
    json_free(&outcomes);
    json_free(&pool);
    free(rows);
    dvq_fail(reply, "QUEUE_READ_FAILED", "status",
             "cannot encode the status reply", qpath);
}

/* ── dispatcher ────────────────────────────────────────────────────────── */

/* The backpressure bound a preflight reports queue_full against: post
 * refuses QUEUE_FULL while this many rows are already queued. One
 * accessor rather than a second copy of the constant, so the report and
 * the refusal cannot drift apart. */
int zcl_devagent_queue_queued_max(void)
{
    return DVQ_QUEUED_MAX;
}

void zcl_native_handle_dev_agent_queue(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *action;
    if (!reply)
        return;
    if (!request || !request->input) {
        dvq_fail(reply, "BAD_INPUT", "route",
                 "dev.agent.queue needs an action: post|next|reap|status|cancel",
                 "request.input was missing");
        return;
    }
    action = dvq_str(request, "action");
    if (!action) {
        dvq_fail(reply, "BAD_INPUT", "route",
                 "dev.agent.queue needs an action: post|next|claim|reap|status|cancel",
                 "input.action missing or empty");
        return;
    }
    if (strcmp(action, "post") == 0) {
        dvq_post(request, reply);
        return;
    }
    if (strcmp(action, "next") == 0) {
        dvq_next(request, reply);
        return;
    }
    if (strcmp(action, "claim") == 0) {
        dvq_claim(request, reply);
        return;
    }
    if (strcmp(action, "reap") == 0) {
        dvq_reap(request, reply);
        return;
    }
    if (strcmp(action, "cancel") == 0) {
        dvq_cancel(request, reply);
        return;
    }
    if (strcmp(action, "status") == 0) {
        dvq_status(request, reply);
        return;
    }
    dvq_fail(reply, "UNKNOWN_ACTION", "route",
             "action is one of post|next|claim|reap|status|cancel",
             "input.action unknown");
}
