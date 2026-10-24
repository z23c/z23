/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.loop.job.wait: block at most timeout_s (clamped to 1..230) on a job started
 * by dev.loop.job.start, or on an external log that ends in an `rc=<n>` line
 * (a zgate --detach log). `running` at the bound is a normal answer, not an
 * error: the caller waits again. Otherwise it returns passed, failed or lost
 * with the exit code, a capped tail and the FAIL / error: lines. The bounded
 * wait arithmetic is the shared helper in native_dev_bounded_wait.c. */

#include "command/native_command.h"
#include "command/native_dev_bounded_wait.h"
#include "command/native_dev_job.h"

#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/directory_compat.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define JOB_WAIT_DEFAULT_S 60
#define JOB_TAIL_DEFAULT 12
#define JOB_TAIL_READ_BYTES (256u * 1024u)
#define JOB_FAIL_LINES_MAX 10
#define JOB_POLL_MS 500

static const char *const job_state_names[] = {"running", "passed", "failed",
                                              "lost"};

static void job_wait_invalid(struct zcl_command_reply *reply,
                             const char *code, const char *msg,
                             const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "normalize", false,
                           false, msg, evidence);
}

/* Push line [p, p+n) as a printable-ASCII string capped at one line. */
static void job_push_line(struct json_value *arr, const char *p, size_t n)
{
    char buf[ZCL_DEV_JOB_LINE_MAX + 1];
    struct json_value s;
    if (n > ZCL_DEV_JOB_LINE_MAX)
        n = ZCL_DEV_JOB_LINE_MAX;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        buf[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
    }
    buf[n] = '\0';
    json_init(&s);
    json_set_str(&s, buf);
    (void)json_push_back(arr, &s);
    json_free(&s);
}

/* True when needle occurs inside p[0..n). */
static bool job_has(const char *p, size_t n, const char *needle)
{
    size_t k = strlen(needle);
    for (size_t i = 0; i + k <= n; i++)
        if (memcmp(p + i, needle, k) == 0)
            return true;
    return false;
}

/* The last `want` lines of text[0..len), oldest first. */
static void job_emit_tail(struct json_value *arr, const char *text,
                          size_t len, size_t want)
{
    size_t pos, lines = 0;
    while (len > 0 && text[len - 1] == '\n')
        len--;
    pos = len;
    while (pos > 0 && lines < want) {
        pos--;
        while (pos > 0 && text[pos - 1] != '\n')
            pos--;
        lines++;
    }
    for (const char *p = text + pos; p < text + len;) {
        const char *nl = memchr(p, '\n', (size_t)(text + len - p));
        size_t n = nl ? (size_t)(nl - p) : (size_t)(text + len - p);
        job_push_line(arr, p, n);
        p += n + 1;
    }
}

static void job_emit_fail_lines(struct json_value *arr, const char *text,
                                size_t len)
{
    size_t emitted = 0;
    for (const char *p = text; p < text + len && emitted < JOB_FAIL_LINES_MAX;) {
        const char *nl = memchr(p, '\n', (size_t)(text + len - p));
        size_t n = nl ? (size_t)(nl - p) : (size_t)(text + len - p);
        if (job_has(p, n, "FAIL") || job_has(p, n, "error:")) {
            job_push_line(arr, p, n);
            emitted++;
        }
        p += n + 1;
    }
}

static void job_reply_wait(struct zcl_command_reply *reply, const char *id,
                           const char *log, enum zcl_dev_job_state state,
                           int rc, int64_t elapsed_s, int64_t timeout_s,
                           bool clamped, size_t tail_lines)
{
    struct json_value tail, fails;
    size_t len = 0;
    char *text = log ? zcl_dev_job_read_tail(log, JOB_TAIL_READ_BYTES, &len)
                     : NULL;
    json_set_object(&reply->data);
    json_init(&tail);
    json_set_array(&tail);
    json_init(&fails);
    json_set_array(&fails);
    if (text) {
        job_emit_tail(&tail, text, len, tail_lines);
        job_emit_fail_lines(&fails, text, len);
    }
    (void)json_push_kv_str(&reply->data, "state", job_state_names[state]);
    if (state == ZCL_DEV_JOB_PASSED || state == ZCL_DEV_JOB_FAILED)
        (void)json_push_kv_int(&reply->data, "rc", rc);
    (void)json_push_kv_int(&reply->data, "elapsed_s", elapsed_s);
    (void)json_push_kv_int(&reply->data, "timeout_s", timeout_s);
    (void)json_push_kv_bool(&reply->data, "timeout_clamped", clamped);
    (void)json_push_kv_str(&reply->data, "log", log ? log : "");
    (void)json_push_kv(&reply->data, "tail", &tail);
    (void)json_push_kv(&reply->data, "fail_lines", &fails);
    if (id)
        (void)json_push_kv_str(&reply->data, "job_id", id);
    if (state == ZCL_DEV_JOB_RUNNING)
        (void)json_push_kv_str(&reply->data, "next",
                               "z23-dev dev loop job wait --job_id=<job_id>");
    json_free(&tail);
    json_free(&fails);
    free(text);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static bool job_wait_int(const struct json_value *input, const char *key,
                         int64_t *out)
{
    const struct json_value *v = json_get(input, key);
    *out = 0;
    if (!v || v->type == JSON_NULL)
        return true;
    if (v->type != JSON_INT)
        return false;
    *out = json_get_int(v);
    return true;
}

/* One look at the target; fills state and rc. */
static enum zcl_dev_job_state job_probe(const char *id, const char *log,
                                        const struct json_value *handle,
                                        int *rc)
{
    long pid = 0;
    bool have_rc;
    if (id)
        return zcl_dev_job_eval(id, handle, rc, &pid);
    have_rc = zcl_dev_job_log_rc(log, rc);
    if (!have_rc)
        return ZCL_DEV_JOB_RUNNING;
    return *rc == 0 ? ZCL_DEV_JOB_PASSED : ZCL_DEV_JOB_FAILED;
}

struct job_wait_req {
    const char *id;  /* NULL when waiting on an external log */
    const char *log; /* the log being read */
    struct json_value handle;
    bool have_handle;
    int64_t timeout_s;
    bool clamped;
    int64_t tail;
    char log_canon[ZCL_DEV_JOB_PATH_MAX];
};

/* An external log is an absolute path to a regular file under a registered
 * worktree's build/scratch/ or under the job state root. Wait reads and echoes
 * the tail of that file, so any other path is refused, with the reason. */
static bool job_external_log_scope(const char *ext,
                                   struct zcl_command_reply *reply,
                                   struct job_wait_req *r)
{
    struct stat st;
    if (ext[0] != '/' ||
        !platform_directory_canonical_real(ext, r->log_canon,
                                           sizeof(r->log_canon)) ||
        stat(r->log_canon, &st) != 0 || !S_ISREG(st.st_mode)) {
        job_wait_invalid(reply, "LOG_MISSING",
                         "log needs an absolute path to an existing file",
                         "input.log");
        return false;
    }
    if (!zcl_dev_job_log_allowed(r->log_canon)) {
        job_wait_invalid(reply, "LOG_NOT_ALLOWED",
                         "log must be under <worktree>/build/scratch/ of a "
                         "worktree of this repository, or under the dev job "
                         "state root; write the output there and wait on it",
                         "input.log");
        return false;
    }
    r->log = r->log_canon;
    return true;
}

/* Resolve the log to read: a started job's own log, or an external one. */
static bool job_wait_target(const struct json_value *in,
                            struct zcl_command_reply *reply,
                            struct job_wait_req *r)
{
    const char *ext = zcl_dev_job_str(json_get(in, "log"));
    if (r->id) {
        r->have_handle = zcl_dev_job_id_valid(r->id) &&
                         zcl_dev_job_read_handle(r->id, &r->handle);
        r->log = r->have_handle ? zcl_dev_job_str(json_get(&r->handle, "log"))
                                : NULL;
    } else if (ext) {
        return job_external_log_scope(ext, reply, r);
    }
    if (r->log)
        return true;
    job_wait_invalid(reply, r->id ? "JOB_UNKNOWN" : "LOG_MISSING",
                     "job_id needs a handle under the state root; log needs "
                     "an absolute path to an existing file",
                     r->id ? "input.job_id" : "input.log");
    return false;
}

/* Validate the input and resolve the target; the reply is failed on false. */
static bool job_wait_parse(const struct json_value *in,
                           struct zcl_command_reply *reply,
                           struct job_wait_req *r)
{
    int64_t timeout_req = 0;
    memset(r, 0, sizeof(*r));
    json_init(&r->handle);
    r->id = in ? zcl_dev_job_str(json_get(in, "job_id")) : NULL;
    if (!in || (!r->id && !zcl_dev_job_str(json_get(in, "log"))) ||
        !job_wait_int(in, "timeout_s", &timeout_req) ||
        !job_wait_int(in, "tail_lines", &r->tail)) {
        job_wait_invalid(reply, "INVALID_INPUT",
                         "give job_id (from dev loop job start) or log, and "
                         "integer timeout_s / tail_lines",
                         "input");
        return false;
    }
    if (!job_wait_target(in, reply, r))
        return false;
    r->timeout_s = zcl_bounded_wait_clamp(timeout_req, 1, ZCL_DEV_JOB_WAIT_MAX_S,
                                          JOB_WAIT_DEFAULT_S, &r->clamped);
    if (r->tail < 1 || r->tail > ZCL_DEV_JOB_TAIL_MAX)
        r->tail = r->tail < 1 ? JOB_TAIL_DEFAULT : ZCL_DEV_JOB_TAIL_MAX;
    return true;
}

void zcl_native_handle_dev_job_wait(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    struct job_wait_req r;
    struct zcl_bounded_wait wait;
    enum zcl_dev_job_state state;
    int64_t t0;
    int rc = 0;
    if (!reply)
        return;
    if (!job_wait_parse(request ? request->input : NULL, reply, &r)) {
        json_free(&r.handle);
        return;
    }
    t0 = platform_time_monotonic_ms();
    zcl_bounded_wait_begin(&wait, r.timeout_s * 1000);
    for (;;) {
        state = job_probe(r.id, r.log, &r.handle, &rc);
        if (state != ZCL_DEV_JOB_RUNNING ||
            zcl_bounded_wait_sleep(&wait, JOB_POLL_MS) == 0)
            break;
    }
    if (state == ZCL_DEV_JOB_RUNNING)
        state = job_probe(r.id, r.log, &r.handle, &rc); /* last look */
    job_reply_wait(reply, r.id, r.log, state, rc,
                   (platform_time_monotonic_ms() - t0) / 1000, r.timeout_s,
                   r.clamped, (size_t)r.tail);
    json_free(&r.handle);
}
