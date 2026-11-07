/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.batch.requeue, the C form of the lab bridge requeue.sh, and
 *          the state-directory helpers the other dev.batch leaves share
 *          (native_dev_batch.h).
 *
 * A lane that restack leaves for triage keeps its stacked.tsv rows, so the
 * batch tick drops a plain re-add as "already in sNNN" (11-03: tsan-relay-leak
 * and lint-fast-bounce-gates stranded after s520 failed on another lane's
 * shell budget). requeue drops the lane's ledger rows under the tick lock and
 * then appends the lane to stack-pending.txt unless it is already there.
 *
 * SHADOW STEP: requeue.sh keeps acting on the live lab; this leaf is tested on
 * temp state directories, and every file it writes keeps the bridges' bytes:
 * stacked.tsv rows are kept verbatim, stack-pending.txt rows are
 * "LANE<TAB>NOTE\n". The bridge matches a pending lane by the substring
 * "LANE<TAB>"; this leaf matches the first field, which differs only for a
 * note that itself contains a lane path and a tab. */

#include "command/native_dev_batch.h"

#include "json/json.h"
#include "kernel/command_registry.h"
#include "base/safe_alloc.h"
#include "util/spawn.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if !defined(_WIN32)
#include <sys/file.h>
#endif

/* mingw's <fcntl.h> has no O_CLOEXEC: descriptors on Windows are not
 * inherited unless the handle is explicitly marked inheritable, so the
 * flag is a no-op there rather than a missing guarantee. */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* ── options and refusals ──────────────────────────────────────────────── */

const char *db_opt_str(const struct json_value *in, const char *key)
{
    char alt[64];
    const char *v;
    size_t i;
    if (!in || !key || strlen(key) >= sizeof(alt))
        return "";
    v = json_get_str(json_get(in, key));
    if (v && v[0])
        return v;
    for (i = 0; key[i]; i++)
        alt[i] = key[i] == '_' ? '-' : key[i];
    alt[i] = '\0';
    v = json_get_str(json_get(in, alt));
    return v ? v : "";
}

bool db_opt_flag(const struct json_value *in, const char *key)
{
    char alt[64];
    size_t i;
    if (!in || !key || strlen(key) >= sizeof(alt))
        return false;
    if (json_get_bool(json_get(in, key)))
        return true;
    for (i = 0; key[i]; i++)
        alt[i] = key[i] == '_' ? '-' : key[i];
    alt[i] = '\0';
    return json_get_bool(json_get(in, alt));
}

void db_refuse(struct zcl_command_reply *reply, const char *code,
               const char *phase, const char *message)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED, code, phase, false,
                           false, message, "");
}

/* A refusal about a lane: the reason leads the message (a long path cannot
 * cut it off) and the full path goes in the evidence field. */
static void db_refuse_lane(struct zcl_command_reply *reply, const char *code,
                           const char *message, const char *lane)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED, code, "check", false,
                           false, message, lane);
}

bool db_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

static void db_strip_slashes(char *s)
{
    size_t n = strlen(s);
    while (n > 1 && s[n - 1] == '/')
        s[--n] = '\0';
}

bool db_paths_init(const struct json_value *in, struct db_paths *p,
                   struct zcl_command_reply *reply)
{
    const char *home = db_opt_str(in, "home");
    const char *state = db_opt_str(in, "state_dir");
    if (!home[0])
        home = getenv("HOME");
    if (!home || !home[0] || strlen(home) >= sizeof(p->home)) {
        db_refuse(reply, "BAD_HOME", "paths", "no usable home directory");
        return false;
    }
    (void)snprintf(p->home, sizeof(p->home), "%s", home);
    db_strip_slashes(p->home);
    if (state[0]) {
        if (strlen(state) >= sizeof(p->state)) {
            db_refuse(reply, "BAD_STATE_DIR", "paths", "state-dir too long");
            return false;
        }
        (void)snprintf(p->state, sizeof(p->state), "%s", state);
        db_strip_slashes(p->state);
    } else if (!db_join(p->state, sizeof(p->state), p->home,
                        "development/z23/handoff/handoff-20261025")) {
        db_refuse(reply, "BAD_STATE_DIR", "paths", "state-dir too long");
        return false;
    }
    if (!db_join(p->ledger, sizeof(p->ledger), p->state, "stacked.tsv") ||
        !db_join(p->pending, sizeof(p->pending), p->state,
                 "stack-pending.txt") ||
        !db_join(p->restacked, sizeof(p->restacked), p->state,
                 "restacked.tsv") ||
        !db_join(p->lock, sizeof(p->lock), p->state, ".stack-tick.lock")) {
        db_refuse(reply, "BAD_STATE_DIR", "paths", "state-dir too long");
        return false;
    }
    return true;
}

/* ── the tick lock ─────────────────────────────────────────────────────── */

int db_lock(const char *path)
{
    int fd;
    if (!path)
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

void db_unlock(int fd)
{
    if (fd >= 0)
        (void)close(fd);
}

/* ── files and lines ───────────────────────────────────────────────────── */

static bool db_read_all(int fd, struct db_text *t, size_t size)
{
    size_t got = 0;
    t->p = zcl_malloc(size + 1, "db_text");
    if (!t->p)
        return false;
    while (got < size) {
        ssize_t r = read(fd, t->p + got, size - got);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            break;
        got += (size_t)r;
    }
    t->p[got] = '\0';
    t->n = got;
    return true;
}

bool db_text_load(const char *path, struct db_text *t)
{
    struct stat st;
    int fd;
    bool ok;
    t->p = NULL;
    t->n = 0;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno != ENOENT)
            return false;
        t->p = zcl_calloc(1, 1, "db_text_empty");
        return t->p != NULL;
    }
    if (fstat(fd, &st) != 0 || st.st_size < 0 ||
        (unsigned long long)st.st_size > DB_FILE_CAP) {
        (void)close(fd);
        return false;
    }
    ok = db_read_all(fd, t, (size_t)st.st_size);
    (void)close(fd);
    return ok;
}

void db_text_free(struct db_text *t)
{
    free(t->p);
    t->p = NULL;
    t->n = 0;
}

static bool db_write_fd(int fd, const char *data, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, data + off, n - off);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            return false;
        off += (size_t)w;
    }
    return true;
}

bool db_text_save(const char *path, const char *data, size_t n)
{
    char tmp[DB_PATH + 8];
    int fd;
    bool ok;
    if (snprintf(tmp, sizeof(tmp), "%s.new", path) >= (int)sizeof(tmp))
        return false;
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        return false;
    ok = db_write_fd(fd, data, n) && fsync(fd) == 0;
    if (close(fd) != 0)
        ok = false;
    if (ok && rename(tmp, path) != 0)
        ok = false;
    if (!ok)
        (void)unlink(tmp);
    return ok;
}

bool db_append(const char *path, const char *data, size_t n)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    bool ok;
    if (fd < 0)
        return false;
    ok = db_write_fd(fd, data, n);
    if (close(fd) != 0)
        ok = false;
    return ok;
}

bool db_next_line(const struct db_text *t, size_t *pos, const char **line,
                  size_t *len)
{
    const char *nl;
    size_t rest;
    if (*pos >= t->n)
        return false;
    rest = t->n - *pos;
    nl = memchr(t->p + *pos, '\n', rest);
    *line = t->p + *pos;
    *len = nl ? (size_t)(nl - *line) : rest;
    *pos += *len + (nl ? 1u : 0u);
    return true;
}

bool db_field_is(const char *line, size_t len, size_t idx, const char *key)
{
    size_t start = 0, i;
    for (i = 0; i < len && idx > 0; i++) {
        if (line[i] == '\t') {
            start = i + 1;
            idx--;
        }
    }
    if (idx > 0)
        return false;
    for (i = start; i < len && line[i] != '\t'; i++)
        ;
    return strlen(key) == i - start && memcmp(line + start, key, i - start) == 0;
}

bool db_has_first_field(const struct db_text *t, const char *key)
{
    size_t pos = 0, len;
    const char *line;
    while (db_next_line(t, &pos, &line, &len))
        if (db_field_is(line, len, 0, key))
            return true;
    return false;
}

/* ── git and json ──────────────────────────────────────────────────────── */

int db_git(const char *dir, const char *const *args, char *out, size_t cap)
{
    const char *argv[24];
    size_t n = 0, i;
    char sink[2];
    if (out && cap)
        out[0] = '\0';
    if (!dir || !args)
        return -1;
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = dir;
    for (i = 0; args[i]; i++) {
        if (n + 2 > sizeof(argv) / sizeof(argv[0]))
            return -1;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    return zcl_spawn_capture(argv, out ? out : sink, out ? cap : sizeof(sink),
                             DB_GIT_TIMEOUT_MS);
}

bool db_git_line(const char *dir, const char *const *args, char *out,
                 size_t cap)
{
    if (db_git(dir, args, out, cap) != 0)
        return false;
    out[strcspn(out, "\r\n")] = '\0';
    return true;
}

void db_push_str(struct json_value *arr, const char *s)
{
    struct json_value item;
    json_init(&item);
    json_set_str(&item, s);
    (void)json_push_back(arr, &item);
    json_free(&item);
}

/* ── requeue ───────────────────────────────────────────────────────────── */

/* The ledger key is the literal path the batch tick stored, so a path is
 * only slash-trimmed; a bare name means a lane directory under the lab. */
static bool db_lane_path(const struct db_paths *p, const char *given,
                         char *out, size_t cap)
{
    bool ok;
    if (!given[0])
        return false;
    if (strchr(given, '/'))
        ok = snprintf(out, cap, "%s", given) < (int)cap;
    else
        ok = snprintf(out, cap, "%s/development/lanes/z23/%s", p->home,
                      given) < (int)cap;
    if (ok)
        db_strip_slashes(out);
    return ok && out[0] != '\0';
}

bool db_ledger_drop_lane(const char *path, const char *lane, size_t *dropped)
{
    struct db_text t, out = {NULL, 0};
    size_t pos = 0, len, used = 0;
    const char *line;
    bool ok;
    *dropped = 0;
    if (!db_text_load(path, &t))
        return false;
    out.p = zcl_malloc(t.n + 2, "db_ledger_out");
    if (!out.p) {
        db_text_free(&t);
        return false;
    }
    while (db_next_line(&t, &pos, &line, &len)) {
        if (db_field_is(line, len, 0, lane)) {
            (*dropped)++;
            continue;
        }
        memcpy(out.p + used, line, len);
        out.p[used + len] = '\n';
        used += len + 1;
    }
    ok = db_text_save(path, out.p, used);
    free(out.p);
    db_text_free(&t);
    return ok;
}

static bool db_pending_add(const char *path, const char *lane, const char *note)
{
    struct db_text t;
    char row[DB_PATH + 1100];
    int n;
    bool have;
    if (!db_text_load(path, &t))
        return false;
    have = db_has_first_field(&t, lane);
    db_text_free(&t);
    if (have)
        return true;
    n = snprintf(row, sizeof(row), "%s\t%s\n", lane, note);
    return n > 0 && (size_t)n < sizeof(row) && db_append(path, row, (size_t)n);
}

/* A refusal the lane's owner can act on: why, and what to do. */
static bool db_lane_clean(const char *lane, struct zcl_command_reply *reply)
{
    const char *status[] = {"status", "--porcelain", "--untracked-files=no",
                            NULL};
    char out[4096], msg[DB_PATH + 160];
    struct stat st;
    if (stat(lane, &st) != 0 || !S_ISDIR(st.st_mode)) {
        (void)snprintf(msg, sizeof(msg),
                       "requeue refused: not a directory (lane %s)", lane);
        db_refuse_lane(reply, "NOT_A_LANE", msg, lane);
        return false;
    }
    if (db_git(lane, status, out, sizeof(out)) != 0) {
        (void)snprintf(msg, sizeof(msg), "requeue: git status failed in %s",
                       lane);
        db_refuse(reply, "GIT_FAILED", "check", msg);
        return false;
    }
    if (out[0]) {
        (void)snprintf(msg, sizeof(msg),
                       "requeue refused: uncommitted tracked changes; commit "
                       "or discard them, then requeue again (lane %s)",
                       lane);
        db_refuse_lane(reply, "LANE_DIRTY", msg, lane);
        return false;
    }
    return true;
}

static bool db_requeue_args(const struct json_value *in, const struct db_paths *p,
                            char *lane, size_t cap, const char **note,
                            struct zcl_command_reply *reply)
{
    *note = db_opt_str(in, "note");
    if (!db_lane_path(p, db_opt_str(in, "worktree"), lane, cap)) {
        db_refuse(reply, "BAD_INPUT", "input", "requeue needs --worktree=LANE");
        return false;
    }
    if (!(*note)[0] || strpbrk(*note, "\t\r\n") || strlen(*note) > 1000) {
        db_refuse(reply, "BAD_INPUT", "input",
                  "requeue needs --note=TEXT: one line, no tab, 1000 bytes "
                  "at most");
        return false;
    }
    if (strchr(lane, '\t') || strchr(lane, '\n')) {
        db_refuse(reply, "BAD_INPUT", "input", "worktree holds a tab or newline");
        return false;
    }
    return true;
}

static void db_requeue_report(struct zcl_command_reply *reply, const char *lane,
                              size_t dropped)
{
    const char *rp[] = {"rev-parse", "--short", "HEAD", NULL};
    char head[64] = "", msg[DB_PATH + 128], name[DB_PATH];
    size_t n = strlen(lane);
    const char *base;
    while (n > 1 && lane[n - 1] == '/')
        n--;
    (void)snprintf(name, sizeof(name), "%.*s", (int)n, lane);
    base = strrchr(name, '/');
    (void)db_git_line(lane, rp, head, sizeof(head));
    (void)snprintf(msg, sizeof(msg), "requeue: %s at %s is pending",
                   base ? base + 1 : name, head);
    (void)json_push_kv_str(&reply->data, "leaf", "dev.batch.requeue");
    (void)json_push_kv_str(&reply->data, "worktree", lane);
    (void)json_push_kv_str(&reply->data, "head", head);
    (void)json_push_kv_int(&reply->data, "ledger_rows_dropped", (int64_t)dropped);
    (void)json_push_kv_str(&reply->data, "message", msg);
}

void zcl_native_handle_dev_batch_requeue(const struct zcl_command_request *request,
                                         struct zcl_command_reply *reply)
{
    const struct json_value *in;
    struct db_paths p;
    char lane[DB_PATH];
    const char *note;
    size_t dropped = 0;
    int lock;
    bool ok;
    if (!reply)
        return;
    in = request ? request->input : NULL;
    if (!in) {
        db_refuse(reply, "BAD_INPUT", "input", "dev.batch.requeue needs input");
        return;
    }
    if (!db_paths_init(in, &p, reply) ||
        !db_requeue_args(in, &p, lane, sizeof(lane), &note, reply) ||
        !db_lane_clean(lane, reply))
        return;
    lock = db_lock(p.lock);
    if (lock < 0) {
        db_refuse(reply, "LOCK_FAILED", "lock",
                  "requeue: cannot take the stack tick lock");
        return;
    }
    ok = db_ledger_drop_lane(p.ledger, lane, &dropped) &&
         db_pending_add(p.pending, lane, note);
    db_unlock(lock);
    if (!ok) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "LEDGER_WRITE_FAILED",
                               "write", false, true,
                               "requeue: a ledger file could not be rewritten",
                               p.state);
        return;
    }
    db_requeue_report(reply, lane, dropped);
}

/* Copy tab-separated field `idx` of a line into out; false when absent. */
bool db_field_copy(const char *line, size_t len, size_t idx, char *out,
                   size_t cap)
{
    size_t start = 0, i, end;
    for (i = 0; i < len && idx > 0; i++) {
        if (line[i] == '\t') {
            start = i + 1;
            idx--;
        }
    }
    if (idx > 0)
        return false;
    for (end = start; end < len && line[end] != '\t'; end++)
        ;
    if (end - start >= cap)
        return false;
    memcpy(out, line + start, end - start);
    out[end - start] = '\0';
    return true;
}
