/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.loop.job.start: launch one allowlisted argv detached in a registered
 * worktree and return a handle at once, so an agent never blocks a tool call
 * past the prompt-cache TTL. dev.loop.job.wait (native_dev_job_wait.c) polls the
 * handle in bounded slices. The detached child is the hidden
 * `z23-dev dev loop job exec --job_id=<id>` (native_dev_job_exec.c), which runs
 * the argv through the host build queue and appends the `rc=<n>` line, so
 * admission stays with the scheduler.
 *
 * STATE: <state root>/devjob/<id>/{handle.json,pid} and
 * <state root>/devjob/key-<hash> (dedupe pointer). Pointer files only; the
 * output lives in <cwd>/build/scratch/job-<id>.log. */

#include "command/native_command.h"
#include "command/native_dev_job.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/os_proc.h"
#include "kernel/command_registry.h"
#include "platform/directory_compat.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#include "util/spawn.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define JOB_HANDLE_MAX 16384u
#define JOB_RC_TAIL_BYTES 65536u
#define JOB_LAUNCH_GRACE_S 20
#define JOB_PID_WAIT_MS 500
#define JOB_ARG_MAX 1024u

static const struct zcl_dev_job_hooks *g_hooks;

void zcl_dev_job_set_hooks(const struct zcl_dev_job_hooks *hooks)
{
    g_hooks = hooks;
}

const struct zcl_dev_job_hooks *zcl_dev_job_hooks(void)
{
    return g_hooks;
}

/* ── state paths ─────────────────────────────────────────────────────────── */

bool zcl_dev_job_root(char *out, size_t cap, bool create)
{
    char state[ZCL_DEV_JOB_PATH_MAX];
    int n;
    if (!(create ? platform_state_root(state, sizeof(state))
                 : platform_state_root_existing(state, sizeof(state))))
        return false;
    n = snprintf(out, cap, "%s/devjob", state);
    if (n <= 0 || (size_t)n >= cap)
        return false;
    return !create || (platform_directory_ensure(state, 0700) &&
                       platform_directory_ensure(out, 0700));
}

bool zcl_dev_job_id_valid(const char *id)
{
    size_t n = id ? strlen(id) : 0;
    if (n == 0 || n > ZCL_DEV_JOB_ID_MAX)
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = id[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-' || c == '_';
        if (!ok)
            return false;
    }
    return true;
}

bool zcl_dev_job_dir(const char *id, char *out, size_t cap)
{
    char root[ZCL_DEV_JOB_PATH_MAX];
    int n;
    if (!zcl_dev_job_id_valid(id) || !zcl_dev_job_root(root, sizeof(root), false))
        return false;
    n = snprintf(out, cap, "%s/%s", root, id);
    return n > 0 && (size_t)n < cap;
}

/* ── small file helpers ──────────────────────────────────────────────────── */

/* The last `max` bytes of `path`, NUL-terminated, heap-owned. NULL on error. */
char *zcl_dev_job_read_tail(const char *path, size_t max, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    char *buf;
    long size;
    size_t got, skip = 0;
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0) {
        (void)fclose(f);
        return NULL;
    }
    if ((size_t)size > max)
        skip = (size_t)size - max;
    buf = zcl_malloc(max + 1, "dev_job_tail");
    if (!buf || fseek(f, (long)skip, SEEK_SET) != 0) {
        free(buf);
        (void)fclose(f);
        return NULL;
    }
    got = fread(buf, 1, max, f);
    bool failed = ferror(f) || got != (size_t)size - skip;
    /* Reject observed growth as well as shortening; a later wait can retry. */
    if (fgetc(f) != EOF || ferror(f))
        failed = true;
    if (fclose(f) != 0)
        failed = true;
    if (failed) {
        free(buf);
        return NULL;
    }
    buf[got] = '\0';
    if (len_out)
        *len_out = got;
    return buf;
}

static bool job_parse_rc(char *text, size_t len, int *rc)
{
    char *digits = text;
    if (*digits == '+' || *digits == '-') digits++;
    if (digits == text + len || strspn(digits, "0123456789") != (size_t)(text + len - digits))
        return false;
    text[len] = '\0';
    errno = 0;
    char *after;
    long value = strtol(text, &after, 10);
    if (errno == ERANGE || after != text + len || value < INT_MIN || value > INT_MAX)
        return false;
    *rc = (int)value;
    return true;
}

bool zcl_dev_job_log_rc(const char *log, int *rc)
{
    size_t len = 0;
    char *text = zcl_dev_job_read_tail(log, JOB_RC_TAIL_BYTES + 1, &len);
    bool found = false;
    if (!text)
        return false;
    /* Completion is a complete final line, never an earlier output line or
     * a partially written marker. Refuse binary/truncated observations. */
    if (!len || text[len - 1] != '\n' || memchr(text, '\0', len))
        goto done;
    size_t start = len - 1;
    while (start && text[start - 1] != '\n') start--;
    if (!start && len == JOB_RC_TAIL_BYTES + 1)
        goto done; /* the tail may start in the middle of this line */
    size_t end = len - 1;
    if (end > start && text[end - 1] == '\r') end--;
    if (end - start < 4 || memcmp(text + start, "rc=", 3))
        goto done;
    found = job_parse_rc(text + start + 3, end - start - 3, rc);
done:
    free(text);
    return found;
}

bool zcl_dev_job_read_handle(const char *id, struct json_value *handle)
{
    char dir[ZCL_DEV_JOB_PATH_MAX], path[ZCL_DEV_JOB_PATH_MAX + 16];
    size_t len = 0;
    char *text;
    bool ok;
    json_init(handle);
    if (!zcl_dev_job_dir(id, dir, sizeof(dir)))
        return false;
    (void)snprintf(path, sizeof(path), "%s/handle.json", dir);
    text = zcl_dev_job_read_tail(path, JOB_HANDLE_MAX, &len);
    if (!text)
        return false;
    ok = json_read(handle, text, len);
    free(text);
    if (!ok)
        json_free(handle);
    return ok;
}

static long job_read_pid(const char *id)
{
    char dir[ZCL_DEV_JOB_PATH_MAX], path[ZCL_DEV_JOB_PATH_MAX + 8];
    char buf[32];
    FILE *f;
    size_t got;
    if (!zcl_dev_job_dir(id, dir, sizeof(dir)))
        return 0;
    (void)snprintf(path, sizeof(path), "%s/pid", dir);
    f = fopen(path, "r");
    if (!f)
        return 0;
    got = fread(buf, 1, sizeof(buf) - 1, f);
    (void)fclose(f);
    buf[got] = '\0';
    return atol(buf);
}

static bool job_pid_alive(long pid)
{
    return pid > 0 && (kill((pid_t)pid, 0) == 0 || errno == EPERM);
}

/* ── classification ──────────────────────────────────────────────────────── */

enum zcl_dev_job_state zcl_dev_job_classify(bool have_rc, int rc, long pid,
                                            bool pid_alive,
                                            int64_t started_unix,
                                            int64_t now_unix)
{
    if (have_rc)
        return rc == 0 ? ZCL_DEV_JOB_PASSED : ZCL_DEV_JOB_FAILED;
    if (pid > 0)
        return pid_alive ? ZCL_DEV_JOB_RUNNING : ZCL_DEV_JOB_LOST;
    return now_unix - started_unix < JOB_LAUNCH_GRACE_S ? ZCL_DEV_JOB_RUNNING
                                                        : ZCL_DEV_JOB_LOST;
}

enum zcl_dev_job_state zcl_dev_job_eval(const char *id,
                                        const struct json_value *handle,
                                        int *rc, long *pid)
{
    const char *log = zcl_dev_job_str(json_get(handle, "log"));
    const struct json_value *st = json_get(handle, "started_unix");
    int64_t started = st && st->type == JSON_INT ? json_get_int(st) : 0;
    bool have_rc = log && zcl_dev_job_log_rc(log, rc);
    bool alive;
    *pid = job_read_pid(id);
    alive = job_pid_alive(*pid);
    if (!have_rc && *pid > 0 && !alive)
        have_rc = log && zcl_dev_job_log_rc(log, rc); /* finished in between */
    return zcl_dev_job_classify(have_rc, have_rc ? *rc : 0, *pid, alive,
                                started, (int64_t)platform_time_wall_time_t());
}

/* ── input validation ────────────────────────────────────────────────────── */

static void job_invalid(struct zcl_command_reply *reply, const char *code,
                        const char *msg, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "normalize", false,
                           false, msg, evidence);
}

static bool job_argv0_allowed(const char *a0)
{
    const char *base;
    if (strcmp(a0, "make") == 0 || strcmp(a0, "devbuild") == 0 ||
        strcmp(a0, "z23-dev") == 0 || strcmp(a0, "z23") == 0)
        return true;
    base = strrchr(a0, '/');
    return a0[0] == '/' && base && strcmp(base + 1, "zgate") == 0;
}

static bool job_argv_check(const struct json_value *argv,
                           struct zcl_command_reply *reply)
{
    size_t n = argv && argv->type == JSON_ARR ? json_size(argv) : 0;
    if (n == 0 || n > ZCL_DEV_JOB_ARGV_MAX) {
        job_invalid(reply, "INVALID_INPUT",
                    "argv is a JSON array of 1..64 strings", "input.argv");
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        const char *s = zcl_dev_job_str(json_at(argv, i));
        if (!s || strlen(s) >= JOB_ARG_MAX || (i > 0 && s[0] == '\0')) {
            job_invalid(reply, "INVALID_INPUT",
                        "every argv element is a non-empty string under 1 KiB",
                        "input.argv");
            return false;
        }
    }
    if (!job_argv0_allowed(zcl_dev_job_str(json_at(argv, 0)))) {
        job_invalid(reply, "ARGV_NOT_ALLOWED",
                    "argv[0] must be make, devbuild, z23-dev, z23 or an "
                    "absolute path to zgate",
                    "input.argv[0]");
        return false;
    }
    return true;
}

/* The primary checkout of THIS binary's repository: the parent of the common
 * git dir that git reports from the binary's own directory. The caller's cwd
 * never decides it. The test seam may pin it instead. */
static bool job_primary_checkout(char *out, size_t cap)
{
    const struct zcl_dev_job_hooks *h = zcl_dev_job_hooks();
    const char *argv[] = {"git", "rev-parse", "--path-format=absolute",
                          "--git-common-dir", NULL};
    char exe[ZCL_DEV_JOB_PATH_MAX], dir[ZCL_DEV_JOB_PATH_MAX];
    char common[ZCL_DEV_JOB_PATH_MAX], *slash;
    size_t n;
    if (h && h->primary_checkout)
        return platform_directory_canonical_real(h->primary_checkout, out, cap);
    if (!os_proc_exe_path(exe, sizeof(exe)) || !(slash = strrchr(exe, '/')) ||
        slash == exe)
        return false;
    n = (size_t)(slash - exe);
    memcpy(dir, exe, n);
    dir[n] = '\0';
    if (zcl_spawn_capture_in_dir_observed(argv, dir, common, sizeof(common),
                                          15000, NULL) != 0)
        return false;
    n = strcspn(common, "\r\n");
    common[n] = '\0';
    if (n <= 5 || strcmp(common + n - 5, "/.git") != 0)
        return false;
    common[n - 5] = '\0';
    return platform_directory_canonical_real(common, out, cap);
}

typedef bool (*job_wt_fn)(const char *worktree, const char *arg);

/* Call fn with each worktree git lists for the primary checkout, its path
 * canonical, and stop at the first true. The list is read from the primary,
 * never from the caller's directory. */
static bool job_any_worktree(job_wt_fn fn, const char *arg)
{
    const char *argv[] = {"git", "worktree", "list", "--porcelain", NULL};
    char primary[ZCL_DEV_JOB_PATH_MAX], path[ZCL_DEV_JOB_PATH_MAX];
    char canon[ZCL_DEV_JOB_PATH_MAX];
    size_t cap = 1u << 20;
    char *out;
    bool found = false;
    if (!job_primary_checkout(primary, sizeof(primary)))
        return false;
    out = zcl_malloc(cap, "dev_job_worktree_list");
    if (!out)
        return false;
    if (zcl_spawn_capture_in_dir_observed(argv, primary, out, cap, 15000,
                                          NULL) == 0) {
        for (const char *p = out; !found && p && *p;) {
            const char *nl = strchr(p, '\n');
            size_t n = nl ? (size_t)(nl - p) : strlen(p);
            if (n > 9 && n - 9 < sizeof(path) && strncmp(p, "worktree ", 9) == 0) {
                memcpy(path, p + 9, n - 9);
                path[n - 9] = '\0';
                found = platform_directory_canonical_real(path, canon,
                                                          sizeof(canon)) &&
                        fn(canon, arg);
            }
            p = nl ? nl + 1 : p + n;
        }
    }
    free(out);
    return found;
}

static bool job_wt_is_cwd(const char *worktree, const char *cwd)
{
    return strcmp(worktree, cwd) == 0;
}

static bool job_wt_holds_log(const char *worktree, const char *log)
{
    char prefix[ZCL_DEV_JOB_PATH_MAX];
    int n = snprintf(prefix, sizeof(prefix), "%s/build/scratch/", worktree);
    return n > 0 && (size_t)n < sizeof(prefix) &&
           strncmp(log, prefix, (size_t)n) == 0;
}

static bool job_in_state_root(const char *log)
{
    char root[ZCL_DEV_JOB_PATH_MAX], canon[ZCL_DEV_JOB_PATH_MAX];
    size_t n;
    if (!zcl_dev_job_root(root, sizeof(root), false) ||
        !platform_directory_canonical_real(root, canon, sizeof(canon)))
        return false;
    n = strlen(canon);
    return strncmp(log, canon, n) == 0 && log[n] == '/';
}

bool zcl_dev_job_log_allowed(const char *log)
{
    return job_in_state_root(log) || job_any_worktree(job_wt_holds_log, log);
}

/* True when `cwd` (canonical) is a worktree git lists for the primary
 * checkout of this binary's repository. */
static bool job_cwd_registered(const char *cwd)
{
    return job_any_worktree(job_wt_is_cwd, cwd);
}

static bool job_head(const char *cwd, char *out, size_t cap)
{
    const char *argv[] = {"git", "rev-parse", "HEAD", NULL};
    char buf[128];
    size_t n;
    if (zcl_spawn_capture_in_dir_observed(argv, cwd, buf, sizeof(buf), 15000,
                                          NULL) != 0)
        return false;
    n = strcspn(buf, "\r\n");
    if (n == 0 || n >= cap)
        return false;
    memcpy(out, buf, n);
    out[n] = '\0';
    return true;
}

/* Resolve the cwd input (default: the process cwd) to a registered
 * worktree. On failure the reply is already failed. */
static bool job_resolve_cwd(const struct json_value *input, char *cwd,
                            size_t cap, struct zcl_command_reply *reply)
{
    const char *in = zcl_dev_job_str(json_get(input, "cwd"));
    char raw[ZCL_DEV_JOB_PATH_MAX];
    if (!in && !getcwd(raw, sizeof(raw))) {
        job_invalid(reply, "INVALID_INPUT", "cwd could not be determined",
                    "input.cwd");
        return false;
    }
    if (in && (in[0] != '/' || strlen(in) >= sizeof(raw))) {
        job_invalid(reply, "INVALID_INPUT", "cwd must be an absolute path",
                    "input.cwd");
        return false;
    }
    if (in)
        (void)snprintf(raw, sizeof(raw), "%s", in);
    if (!platform_directory_canonical_real(raw, cwd, cap) ||
        !job_cwd_registered(cwd)) {
        job_invalid(reply, "CWD_NOT_WORKTREE",
                    "cwd must be an existing git worktree of this repository "
                    "(see git worktree list)",
                    "input.cwd");
        return false;
    }
    return true;
}

/* ── handle and dedupe key ───────────────────────────────────────────────── */

static uint64_t job_key_hash(const char *cwd, const char *head,
                             const struct json_value *argv)
{
    uint64_t h = 1469598103934665603ull;
    const char *parts[2] = {cwd, head};
    for (size_t i = 0; i < 2; i++)
        for (const char *p = parts[i]; *p; p++)
            h = (h ^ (unsigned char)*p) * 1099511628211ull;
    for (size_t i = 0; i < json_size(argv); i++) {
        h = (h ^ 0x1f) * 1099511628211ull;
        for (const char *p = zcl_dev_job_str(json_at(argv, i)); *p; p++)
            h = (h ^ (unsigned char)*p) * 1099511628211ull;
    }
    return h;
}

static bool job_key_path(uint64_t key, char *out, size_t cap)
{
    char root[ZCL_DEV_JOB_PATH_MAX];
    int n;
    if (!zcl_dev_job_root(root, sizeof(root), false))
        return false;
    n = snprintf(out, cap, "%s/key-%016llx", root, (unsigned long long)key);
    return n > 0 && (size_t)n < cap;
}

static bool job_write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    (void)fputs(text, f);
    return fclose(f) == 0;
}

/* The running job already launched for this key, or false. */
static bool job_attach_existing(uint64_t key, char *id, size_t id_cap,
                                struct json_value *handle)
{
    char path[ZCL_DEV_JOB_PATH_MAX];
    char text[ZCL_DEV_JOB_ID_MAX + 8];
    FILE *f;
    size_t got;
    int rc = 0;
    long pid = 0;
    if (!job_key_path(key, path, sizeof(path)) || !(f = fopen(path, "r")))
        return false;
    got = fread(text, 1, sizeof(text) - 1, f);
    (void)fclose(f);
    text[got] = '\0';
    text[strcspn(text, "\r\n")] = '\0';
    if (!zcl_dev_job_read_handle(text, handle))
        return false;
    if (zcl_dev_job_eval(text, handle, &rc, &pid) != ZCL_DEV_JOB_RUNNING) {
        json_free(handle);
        return false;
    }
    (void)snprintf(id, id_cap, "%s", text);
    return true;
}

static bool job_make_handle(struct json_value *handle, const char *id,
                            const char *cwd, const char *head,
                            const struct json_value *input, char *log,
                            size_t log_cap)
{
    const char *label = zcl_dev_job_str(json_get(input, "label"));
    int n = snprintf(log, log_cap, "%s/build/scratch/job-%s.log", cwd, id);
    if (n <= 0 || (size_t)n >= log_cap)
        return false;
    json_init(handle);
    json_set_object(handle);
    return json_push_kv_str(handle, "job_id", id) &&
           json_push_kv_str(handle, "cwd", cwd) &&
           json_push_kv_str(handle, "head", head) &&
           json_push_kv_str(handle, "label", label ? label : "") &&
           json_push_kv(handle, "argv", json_get(input, "argv")) &&
           json_push_kv_int(handle, "started_unix",
                            (int64_t)platform_time_wall_time_t()) &&
           json_push_kv_str(handle, "log", log);
}

/* Create the job directory, scratch dir and handle file. */
static bool job_store(const struct json_value *handle, const char *id,
                      const char *cwd)
{
    char dir[ZCL_DEV_JOB_PATH_MAX], path[ZCL_DEV_JOB_PATH_MAX + 16];
    char text[JOB_HANDLE_MAX];
    char root[ZCL_DEV_JOB_PATH_MAX];
    if (!zcl_dev_job_root(root, sizeof(root), true) ||
        !zcl_dev_job_dir(id, dir, sizeof(dir)) ||
        !platform_directory_ensure(dir, 0700))
        return false;
    (void)snprintf(path, sizeof(path), "%s/build", cwd);
    (void)platform_directory_ensure(path, 0755);
    (void)snprintf(path, sizeof(path), "%s/build/scratch", cwd);
    (void)platform_directory_ensure(path, 0755);
    if (json_write(handle, text, sizeof(text)) == 0)
        return false;
    (void)snprintf(path, sizeof(path), "%s/handle.json", dir);
    return job_write_file(path, text);
}

/* ── launch ──────────────────────────────────────────────────────────────── */

static bool job_launch(const char *id)
{
    char exe[ZCL_DEV_JOB_PATH_MAX], arg[ZCL_DEV_JOB_ID_MAX + 16];
    const char *argv[] = {exe, "dev", "loop", "job", "exec", arg, NULL};
    if (g_hooks && g_hooks->launch)
        return g_hooks->launch(id);
    if (!os_proc_exe_path(exe, sizeof(exe)))
        return false;
    (void)snprintf(arg, sizeof(arg), "--job_id=%s", id);
    return zcl_spawn_detached(argv, NULL).ok;
}

static long job_wait_pid(const char *id)
{
    long pid = 0;
    for (int waited = 0; waited < JOB_PID_WAIT_MS && pid <= 0; waited += 20) {
        pid = job_read_pid(id);
        if (pid <= 0)
            platform_sleep_ms(20);
    }
    return pid;
}

static void job_reply_start(struct zcl_command_reply *reply, const char *id,
                            const struct json_value *handle, const char *state,
                            long pid)
{
    char next[ZCL_DEV_JOB_ID_MAX + 32];
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "job_id", id);
    (void)json_push_kv_str(&reply->data, "state", state);
    (void)json_push_kv_str(&reply->data, "log",
                           zcl_dev_job_str(json_get(handle, "log")));
    (void)json_push_kv_int(&reply->data, "pid", pid);
    (void)json_push_kv_int(&reply->data, "started_unix",
                           json_get_int(json_get(handle, "started_unix")));
    (void)snprintf(next, sizeof(next), "{\"job_id\":\"%s\"}", id);
    (void)json_push_kv_str(&reply->data, "next",
                           "z23-dev dev loop job wait --job_id=<job_id>");
    (void)zcl_command_reply_add_next(
        reply, "dev.loop.job.wait", next,
        "wait for the verdict in slices of at most 230 s");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static void job_new_id(char *id, size_t cap)
{
    static unsigned counter;
    (void)snprintf(id, cap, "j%llx-%x-%x",
                   (unsigned long long)platform_time_wall_time_t(),
                   (unsigned)getpid(), ++counter);
}

static void job_start_new(const struct zcl_command_request *request,
                          const char *cwd, const char *head, uint64_t key,
                          struct zcl_command_reply *reply)
{
    char id[ZCL_DEV_JOB_ID_MAX + 1], log[ZCL_DEV_JOB_PATH_MAX];
    char keypath[ZCL_DEV_JOB_PATH_MAX];
    struct json_value handle;
    job_new_id(id, sizeof(id));
    if (!job_make_handle(&handle, id, cwd, head, request->input, log,
                         sizeof(log)) ||
        !job_store(&handle, id, cwd)) {
        json_free(&handle);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "JOB_STATE_WRITE",
                               "start", false, false,
                               "could not write the job directory under the "
                               "state root or <cwd>/build/scratch",
                               cwd);
        return;
    }
    if (job_key_path(key, keypath, sizeof(keypath)))
        (void)job_write_file(keypath, id);
    if (!job_launch(id)) {
        json_free(&handle);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "JOB_LAUNCH",
                               "start", true, false,
                               "the detached job child could not be started",
                               id);
        return;
    }
    job_reply_start(reply, id, &handle, "started", job_wait_pid(id));
    json_free(&handle);
}

void zcl_native_handle_dev_job_start(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    char cwd[ZCL_DEV_JOB_PATH_MAX], head[128], id[ZCL_DEV_JOB_ID_MAX + 1];
    struct json_value handle;
    const struct json_value *dedupe;
    uint64_t key;
    if (!reply)
        return;
    if (!request || !request->input ||
        !job_argv_check(json_get(request->input, "argv"), reply) ||
        !job_resolve_cwd(request->input, cwd, sizeof(cwd), reply))
        return;
    if (!job_head(cwd, head, sizeof(head))) {
        job_invalid(reply, "CWD_NOT_WORKTREE",
                    "git rev-parse HEAD failed in cwd", "input.cwd");
        return;
    }
    dedupe = json_get(request->input, "dedupe");
    key = job_key_hash(cwd, head, json_get(request->input, "argv"));
    if ((!dedupe || json_get_bool(dedupe)) &&
        job_attach_existing(key, id, sizeof(id), &handle)) {
        job_reply_start(reply, id, &handle, "attached", job_read_pid(id));
        json_free(&handle);
        return;
    }
    job_start_new(request, cwd, head, key, reply);
}

/* json_get_str() answers "" for a missing or non-string value; the job leaves
 * want NULL for "absent", so every string read goes through this. */
const char *zcl_dev_job_str(const struct json_value *v)
{
    const char *s = v && v->type == JSON_STR ? v->val.s : NULL;
    return s && s[0] ? s : NULL;
}
