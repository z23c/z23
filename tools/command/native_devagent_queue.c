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
 *   action   string, required: post | next | reap | status. Also the first
 *            positional, so `z23 dev agent queue post ...` works.
 *   kind     post only: leaf | doc | file | fix-gate.
 *   name     post only: [A-Za-z0-9_.-]{1,64}.
 *   group    post only, required for kind=file: a test group name.
 *   path     post only, required for kind=doc|file: a repo-relative path
 *            (never absolute, never containing ..).
 *   brief    post only, required for kind=doc|file: an existing file inside
 *            the repo or the state dir; stored as its absolute path.
 *   model    post only, optional model id, default picks flash until
 *            attempt 3, then the stronger model.
 *   attempt  post only, optional integer >= 1, default 1.
 *   json     status only, optional bool: with true the reply carries the
 *            structured shape only; otherwise screen carries the human
 *            rendering too.
 *   cwd      optional string: checkout root override for path checks.
 *
 * STATE. <platform_state_root>/queue (0700): queue.jsonl (one JSON object
 * per line, O_APPEND single write, 0600), queue.lock (the short scheduler
 * flock), pool.txt (operator-listed warm worktree directories, one per
 * line), outcomes.jsonl, and .reap_stamp. Runs live in
 * <platform_state_root>/engine/<name>/a<attempt>/. No verb blocks on a
 * model, a build, or another process; a long-lived loop is the caller's
 * business.
 *
 * OUTPUT (zcl.agent_queue.v1) on ok=true: leaf is always "dev.agent.queue",
 * plus per action: post {seq, name, state:"queued"}; next {seq, name,
 * worktree, pid_or_unit, state:"running"} or {state:"no_free_worktree"} or
 * {state:"empty"}; reap {state:"reaped", outcomes:[...], requeued}; status
 * {queued, running, outcomes, pool} plus screen unless json=true.
 *
 * PROCESS RULE. Spawn only through zcl_spawn_detached() from util/spawn.h.
 * popen(), system() and a shell command string are forbidden and gated.
 *
 * Implement this file only; the test
 * tests/harness/src/test_devagent_queue.c is the acceptance bar and must
 * not be edited.
 */

#include "command/native_command.h"
#include "command/native_devagent.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/state_root.h"
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

#define DVQ_LEAF "dev.agent.queue"

/* Bounded budgets: every file this leaf reads or writes is capped, so a
 * hostile state dir cannot grow the process without bound. */
#define DVQ_LINE_CAP 8192
#define DVQ_POOL_CAP (64u * 1024u)
#define DVQ_FILE_CAP (1024u * 1024u)
#define DVQ_TASK_CAP (128u * 1024u)
#define DVQ_SNIPPET_CAP (32u * 1024u)
#define DVQ_HARNESS_NAME "zclassic23-engine-unit"

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

static bool dvq_name_ok(const char *s)
{
    size_t n;
    if (!s || !s[0])
        return false;
    n = strlen(s);
    if (n > 64)
        return false;
    for (const char *p = s; *p; p++) {
        bool ok = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                  (*p >= '0' && *p <= '9') || *p == '_' || *p == '.' ||
                  *p == '-';
        if (!ok)
            return false;
    }
    return true;
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

static bool dvq_dirs_make(struct dvq_dirs *d)
{
    int n;
    if (!d || !platform_state_root(d->root, sizeof(d->root)))
        return false;
    n = snprintf(d->queue, sizeof(d->queue), "%s/queue", d->root);
    if (n <= 0 || (size_t)n >= sizeof(d->queue))
        return false;
    n = snprintf(d->engine, sizeof(d->engine), "%s/engine", d->root);
    if (n <= 0 || (size_t)n >= sizeof(d->engine))
        return false;
    return dvq_mkdir_one(d->queue) && dvq_mkdir_one(d->engine);
}

/* ── time ──────────────────────────────────────────────────────────────── */

static void dvq_now_iso(char out[64])
{
    time_t now = time(NULL);
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
    char state[16];
    char worktree[4096];
    char pid_or_unit[128];
    long long started;
};

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
    return true;
}

static bool dvq_encode_row(const struct dvq_row *r, char *out, size_t cap,
                           size_t *len_out)
{
    char esc_kind[32], esc_name[160], esc_group[160], esc_path[1024];
    char esc_brief[8192], esc_model[320], esc_ts[128], esc_state[32];
    char esc_wt[8192], esc_unit[256];
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
    w = snprintf(out, cap,
                 "{\"seq\":%lld,\"ts\":\"%s\",\"kind\":\"%s\",\"name\":\"%s\","
                 "\"group\":\"%s\",\"path\":\"%s\",\"brief\":\"%s\","
                 "\"model\":\"%s\",\"attempt\":%lld,\"state\":\"%s\","
                 "\"worktree\":\"%s\",\"pid_or_unit\":\"%s\","
                 "\"started\":%lld}\n",
                 r->seq, esc_ts, esc_kind, esc_name, esc_group, esc_path,
                 esc_brief, esc_model, r->attempt, esc_state, esc_wt,
                 esc_unit, r->started);
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
                 "name matches [A-Za-z0-9_.-]{1,64}",
                 "input.name missing or misspelled");
        return;
    }
    if (!dvq_dirs_make(&d)) {
        dvq_fail(reply, "STATE_DIR_FAILED", "post",
                 "cannot resolve the owner-private state root",
                 "platform_state_root");
        return;
    }
    group = dvq_str(req, "group");
    path = dvq_str(req, "path");
    brief = dvq_str(req, "brief");
    model = dvq_str(req, "model");
    if (json_get(req->input, "attempt") && !dvq_attempt(req, &attempt)) {
        dvq_fail(reply, "BAD_INPUT", "post",
                 "attempt is an integer attempt number, 1 or more",
                 "input.attempt has the wrong shape");
        return;
    }
    if (model && !dvq_model_ok(model)) {
        dvq_fail(reply, "BAD_INPUT", "post",
                 "model is at most 128 model-id characters",
                 "input.model misspelled");
        return;
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
    memset(&r, 0, sizeof(r));
    if (strcmp(kind, "doc") == 0 || strcmp(kind, "file") == 0) {
        if (!path || !dvq_path_ok(path)) {
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
static void dvq_pool_stats(const char *poolpath, long long *total,
                           long long *warm)
{
    char *text;
    char *save = NULL, *line;
    if (total)
        *total = 0;
    if (warm)
        *warm = 0;
    text = (char *)zcl_malloc(DVQ_POOL_CAP, "devagent.queue.pool");
    if (!text)
        return;
    if (!poolpath || !dvq_read_file(poolpath, text, DVQ_POOL_CAP, NULL)) {
        free(text);
        return;
    }
    for (line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char probe[4096 + 16];
        FILE *f;
        dvq_trim(line);
        if (!line[0])
            continue;
        if (total)
            (*total)++;
        if (snprintf(probe, sizeof(probe), "%s/.eu-warm", line) >=
            (int)sizeof(probe))
            continue;
        f = fopen(probe, "rb");
        if (!f)
            continue;
        (void)fclose(f);
        if (warm)
            (*warm)++;
    }
    free(text);
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
            }
        }
        (void)dvq_rewrite_rows(queuedir, qpath, rows, n);
    }
    free(rows);
    dvq_unlock(lock);
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
    char *task = NULL;
    size_t task_used = 0;
    const char *tmo = "1200", *gtmo = "2400";
    const char *hargv[26];
    const char *sargv[48];
    int lock = -1, wtfd = -1;
    long long total = 0, warm = 0;
    struct zcl_result zr;
    bool doc;
    (void)req;
#if defined(_WIN32)
    dvq_fail(reply, "NEXT_WINDOWS_UNAVAILABLE", "select",
             "dev.agent.queue next needs POSIX worktree locks",
             "run next on a POSIX host");
    return;
#endif
    if (!dvq_dirs_make(&d)) {
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
    for (size_t i = 0; i < nrows && !have_pick; i++) {
        if (strcmp(rows[i].state, "queued") == 0) {
            pick = rows[i];
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
    /* Oldest queued row held under the lock; now find it a free warm
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
        dvq_pool_stats(poolpath, &total, &warm);
        (void)json_push_kv_str(&reply->data, "leaf", DVQ_LEAF);
        (void)json_push_kv_str(&reply->data, "state", "no_free_worktree");
        (void)json_push_kv_int(&reply->data, "pool_total", total);
        (void)json_push_kv_int(&reply->data, "pool_warm", warm);
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = 0;
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
    pick.started = (long long)time(NULL);
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
        if (dvq_have_systemd()) {
            int m = 0;
            (void)snprintf(unitarg, sizeof(unitarg), "--unit=%s", unit);
            (void)snprintf(wdirarg, sizeof(wdirarg),
                           "--working-directory=%s", wt);
            sargv[m++] = "systemd-run";
            sargv[m++] = "--user";
            sargv[m++] = "--quiet";
            sargv[m++] = "--collect";
            sargv[m++] = "-p";
            sargv[m++] = "CPUQuota=600%";
            sargv[m++] = "-p";
            sargv[m++] = "Nice=12";
            sargv[m++] = unitarg;
            sargv[m++] = wdirarg;
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

static bool dvq_receipt_verdict(const char *path, char *out, size_t cap)
{
    char text[DVQ_LINE_CAP];
    if (!path || !out || cap == 0)
        return false;
    if (!dvq_read_file(path, text, sizeof(text), NULL))
        return false;
    return dvq_line_str(text, "verdict", out, cap);
}

static bool dvq_push_outcome(struct json_value *arr, const char *name,
                             long long attempt, const char *verdict,
                             long long rc, const char *ts)
{
    struct json_value item;
    bool ok;
    json_init(&item);
    json_set_object(&item);
    ok = json_push_kv_str(&item, "name", name) &&
         json_push_kv_int(&item, "attempt", attempt) &&
         json_push_kv_str(&item, "verdict", verdict) &&
         json_push_kv_int(&item, "rc", rc) &&
         json_push_kv_str(&item, "ts", ts ? ts : "") &&
         json_push_back(arr, &item);
    json_free(&item);
    return ok;
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
    long long maxseq = 0;
    time_t stamp = 0;
    struct stat st;
    int lock = -1;
    size_t len = 0;
    (void)req;
    if (!dvq_dirs_make(&d)) {
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
        if (stat(receipt, &st) == 0 && (stamp == 0 || st.st_mtime > stamp))
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
            if (!dvq_receipt_verdict(receipt, verdict, sizeof(verdict)))
                (void)snprintf(verdict, sizeof(verdict), "unknown");
        } else {
            (void)snprintf(verdict, sizeof(verdict), "no-receipt");
        }
        dvq_now_iso(ots);
        if (!dvq_push_outcome(&outcomes, r->name, r->attempt, verdict, rc,
                              ots)) {
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
                         "%lld,\"verdict\":\"%s\",\"rc\":%lld}\n",
                         ots, r->name, r->attempt, esc_verdict, rc);
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
                           (long long)time(NULL));
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
        (void)snprintf(now, sizeof(now), "%lld", (long long)time(NULL));
        (void)dvq_write_file(stampp, now, strlen(now));
    }
    free(rows);
    dvq_unlock(lock);
    (void)json_push_kv_str(&reply->data, "leaf", DVQ_LEAF);
    (void)json_push_kv_str(&reply->data, "state", "reaped");
    (void)json_push_kv(&reply->data, "outcomes", &outcomes);
    json_free(&outcomes);
    (void)json_push_kv_int(&reply->data, "requeued", requeued);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* ── status ────────────────────────────────────────────────────────────── */

static bool dvq_push_queued(struct json_value *arr, const struct dvq_row *r)
{
    struct json_value item;
    bool ok;
    json_init(&item);
    json_set_object(&item);
    ok = json_push_kv_int(&item, "seq", r->seq) &&
         json_push_kv_str(&item, "name", r->name) &&
         json_push_kv_str(&item, "kind", r->kind) &&
         json_push_kv_int(&item, "attempt", r->attempt) &&
         json_push_kv_str(&item, "ts", r->ts) &&
         json_push_back(arr, &item);
    json_free(&item);
    return ok;
}

static bool dvq_push_running(struct json_value *arr, const struct dvq_row *r,
                             long long now)
{
    struct json_value item;
    long long age = now - r->started;
    bool ok;
    if (age < 0)
        age = 0;
    json_init(&item);
    json_set_object(&item);
    ok = json_push_kv_int(&item, "seq", r->seq) &&
         json_push_kv_str(&item, "name", r->name) &&
         json_push_kv_str(&item, "kind", r->kind) &&
         json_push_kv_int(&item, "attempt", r->attempt) &&
         json_push_kv_str(&item, "worktree", r->worktree) &&
         json_push_kv_str(&item, "pid_or_unit", r->pid_or_unit) &&
         json_push_kv_int(&item, "age_s", age) &&
         json_push_back(arr, &item);
    json_free(&item);
    return ok;
}

/* A warm entry whose NB lock holds right now counts as free. The probe
 * never holds the lock past this call. */
static void dvq_pool_full(const char *poolpath, long long *total,
                          long long *warm, long long *freew)
{
    char *text;
    char *save = NULL, *line;
    if (total)
        *total = 0;
    if (warm)
        *warm = 0;
    if (freew)
        *freew = 0;
    text = (char *)zcl_malloc(DVQ_POOL_CAP, "devagent.queue.pool");
    if (!text)
        return;
    if (!poolpath || !dvq_read_file(poolpath, text, DVQ_POOL_CAP, NULL)) {
        free(text);
        return;
    }
    for (line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char probe[4096 + 16], lockp[4096 + 16];
        FILE *f;
        int fd;
        dvq_trim(line);
        if (!line[0])
            continue;
        if (total)
            (*total)++;
        if (snprintf(probe, sizeof(probe), "%s/.eu-warm", line) >=
                (int)sizeof(probe) ||
            snprintf(lockp, sizeof(lockp), "%s/.eu-lock", line) >=
                (int)sizeof(lockp))
            continue;
        f = fopen(probe, "rb");
        if (!f)
            continue;
        (void)fclose(f);
        if (warm)
            (*warm)++;
        fd = open(lockp, O_RDWR | O_CREAT, 0600);
        if (fd < 0)
            continue;
#if !defined(_WIN32)
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
            (void)flock(fd, LOCK_UN);
            if (freew)
                (*freew)++;
        }
#endif
        (void)close(fd);
    }
    free(text);
}

static void dvq_status(const struct zcl_command_request *req,
                       struct zcl_command_reply *reply)
{
    struct dvq_dirs d;
    struct dvq_row *rows = NULL;
    size_t nrows = 0;
    char qpath[4096 + 32], opath[4096 + 32], poolpath[4096 + 32];
    struct json_value queued, running, outcomes, pool;
    long long total = 0, warm = 0, freew = 0;
    long long now = (long long)time(NULL);
    bool want_json = false;
    const struct json_value *jv;
    char screen[16384];
    size_t used = 0;
    int w;
    if (req && req->input) {
        jv = json_get(req->input, "json");
        want_json = jv && json_get_bool(jv);
    }
    if (!dvq_dirs_make(&d)) {
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
            if (!dvq_push_queued(&queued, &rows[i]))
                goto fail;
        } else if (strcmp(rows[i].state, "running") == 0) {
            if (!dvq_push_running(&running, &rows[i], now))
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
                kept++;
            }
            for (size_t k = 0; k < kept; k++) {
                if (!dvq_push_outcome(&outcomes, last[k].name,
                                      last[k].attempt, last[k].verdict,
                                      last[k].rc, last[k].ts))
                    break;
            }
        }
        free(text);
    }
    dvq_pool_full(poolpath, &total, &warm, &freew);
    if (!json_push_kv_int(&pool, "total", total) ||
        !json_push_kv_int(&pool, "warm", warm) ||
        !json_push_kv_int(&pool, "free", freew))
        goto fail;
    if (!want_json) {
        w = snprintf(screen, sizeof(screen),
                     "queue: %llu queued, %llu running "
                     "(pool %lld free / %lld warm / %lld total)\n",
                     (unsigned long long)queued.num_children,
                     (unsigned long long)running.num_children, freew, warm,
                     total);
        if (w <= 0 || (size_t)w >= sizeof(screen))
            goto fail;
        used = (size_t)w;
        for (size_t i = 0; i < nrows; i++) {
            const char *tag = NULL;
            if (strcmp(rows[i].state, "queued") == 0)
                tag = "queued ";
            else if (strcmp(rows[i].state, "running") == 0)
                tag = "running";
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
            } else {
                w = snprintf(screen + used, sizeof(screen) - used,
                             "  #%lld %-7s %-12s a%-3lld\n", rows[i].seq,
                             tag, rows[i].name, rows[i].attempt);
            }
            if (w <= 0 || (size_t)w >= sizeof(screen) - used)
                break;
            used += (size_t)w;
        }
    }
    free(rows);
    (void)json_push_kv_str(&reply->data, "leaf", DVQ_LEAF);
    (void)json_push_kv(&reply->data, "queued", &queued);
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

void zcl_native_handle_dev_agent_queue(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *action;
    if (!reply)
        return;
    if (!request || !request->input) {
        dvq_fail(reply, "BAD_INPUT", "route",
                 "dev.agent.queue needs an action: post|next|reap|status",
                 "request.input was missing");
        return;
    }
    action = dvq_str(request, "action");
    if (!action) {
        dvq_fail(reply, "BAD_INPUT", "route",
                 "dev.agent.queue needs an action: post|next|reap|status",
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
    if (strcmp(action, "reap") == 0) {
        dvq_reap(request, reply);
        return;
    }
    if (strcmp(action, "status") == 0) {
        dvq_status(request, reply);
        return;
    }
    dvq_fail(reply, "UNKNOWN_ACTION", "route",
             "action is one of post|next|reap|status",
             "input.action unknown");
}
