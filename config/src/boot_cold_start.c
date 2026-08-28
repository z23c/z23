/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_cold_start.c — the `-cold-start` staged, resumable driver. Contract +
 * rationale live in config/boot_cold_start.h.
 *
 * TWO layers, mirroring shutdown_stagewatch.c:
 *   (1) PURE helpers — stage naming, receipt path/write/read/match, and the
 *       resume decision. No child spawn, no global state; unit tested directly.
 *   (2) LIVE driver — fork/exec of each existing verb as a child, then exec of
 *       the plain serving boot. Composes the existing stages; never duplicates
 *       normal boot.
 */

#include "config/boot_cold_start.h"

#include "platform/os_proc.h"    /* os_proc_exe_path */
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "util/file_tree_ops.h"  /* zcl_mkdir_p */
#include "util/log_macros.h"
#include "util/safe_alloc.h"     /* zcl_malloc */
#include "util/write_all.h"      /* zcl_write_all */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define COLD_START_SUBSYS  "cold_start"
#define COLD_START_MAGIC   "ZCLCOLDSTART"
#define COLD_START_VERSION 2 /* v2 adds outcome=/reason= (refusal receipts) */

/* ── (1) Pure helpers ─────────────────────────────────────────────────── */

const char *cold_start_stage_name(enum cold_start_stage stage)
{
    switch (stage) {
    case COLD_START_STAGE_HEADERS: return "headers";
    case COLD_START_STAGE_SEED:    return "seed";
    case COLD_START_STAGE_BUNDLE:  return "bundle";
    case COLD_START_STAGE_SERVE:   return "serve";
    }
    return "?";
}

const char *cold_start_stage_param(const struct cold_start_plan *plan,
                                   enum cold_start_stage stage)
{
    if (!plan)
        return NULL;
    const char *p = NULL;
    switch (stage) {
    case COLD_START_STAGE_HEADERS: p = plan->header_source;  break;
    case COLD_START_STAGE_SEED:    p = plan->seed_snapshot;  break;
    case COLD_START_STAGE_BUNDLE:  p = plan->install_bundle; break;
    case COLD_START_STAGE_SERVE:   p = NULL;                 break;
    }
    return (p && p[0]) ? p : NULL;
}

bool cold_start_stage_configured(const struct cold_start_plan *plan,
                                 enum cold_start_stage stage)
{
    if (stage == COLD_START_STAGE_SERVE)
        return true; /* the driver always ends by serving */
    return cold_start_stage_param(plan, stage) != NULL;
}

int cold_start_receipt_path(const char *datadir, enum cold_start_stage stage,
                            char *buf, size_t n)
{
    if (!datadir || !datadir[0] || !buf || n == 0)
        return -1;
    int w = snprintf(buf, n, "%s/coldstart/%s.receipt", datadir,
                     cold_start_stage_name(stage));
    if (w < 0 || (size_t)w >= n)
        return -1;
    return w;
}

static _Atomic uint64_t g_cold_start_receipt_nonce;

/* Copy at most `in_len` bytes of `in` into `out` (bounded by `out_n`), replacing
 * any CR/LF with a space so the result is a single line. Always NUL-terminates. */
static void cold_start_singleline_bounded(const char *in, size_t in_len,
                                          char *out, size_t out_n)
{
    if (out_n == 0)
        return;
    size_t j = 0;
    for (size_t i = 0; in && i < in_len && in[i] && j + 1 < out_n; i++)
        out[j++] = (in[i] == '\n' || in[i] == '\r') ? ' ' : in[i];
    out[j] = '\0';
}

/* Single-line the NUL-terminated `in` into `out` (bounded); NULL => empty. */
static void cold_start_singleline(const char *in, char *out, size_t out_n)
{
    cold_start_singleline_bounded(in, in ? strlen(in) : 0, out, out_n);
}

bool cold_start_receipt_write(const char *datadir, enum cold_start_stage stage,
                              const char *param, bool refused,
                              const char *reason)
{
    if (!datadir || !datadir[0])
        LOG_FAIL(COLD_START_SUBSYS, "receipt write: empty datadir");

    char dir[PATH_MAX];
    int dn = snprintf(dir, sizeof(dir), "%s/coldstart", datadir);
    if (dn < 0 || (size_t)dn >= sizeof(dir))
        LOG_FAIL(COLD_START_SUBSYS, "receipt write: coldstart dir path too long");
    if (!platform_private_directory_ensure(dir))
        LOG_FAIL(COLD_START_SUBSYS, "receipt write: private directory refused");

    char path[PATH_MAX];
    if (cold_start_receipt_path(datadir, stage, path, sizeof(path)) < 0)
        LOG_FAIL(COLD_START_SUBSYS, "receipt write: path build failed");
    char resolved[PATH_MAX];
    char parent[PATH_MAX];
    if (!platform_private_path_resolve(path, resolved, sizeof(resolved), parent,
                                       sizeof(parent)))
        LOG_FAIL(COLD_START_SUBSYS, "receipt write: path resolution failed");

    char reason_line[COLD_START_REASON_MAX];
    cold_start_singleline(refused ? reason : NULL, reason_line,
                          sizeof(reason_line));

    char content[PATH_MAX + COLD_START_REASON_MAX + 192];
    int cn = snprintf(content, sizeof(content),
                      "magic=%s\nversion=%d\nstage=%s\noutcome=%s\n"
                      "has_param=%d\nparam=%s\nreason=%s\n",
                      COLD_START_MAGIC, COLD_START_VERSION,
                      cold_start_stage_name(stage),
                      refused ? "refused" : "ok",
                      (param && param[0]) ? 1 : 0,
                      (param && param[0]) ? param : "",
                      reason_line);
    if (cn < 0 || (size_t)cn >= sizeof(content))
        LOG_FAIL(COLD_START_SUBSYS, "receipt write: content build failed");

    struct platform_private_file staging;
    platform_private_file_init(&staging);
    char tmp[PATH_MAX];
    bool created = false;
    for (unsigned attempt = 0; attempt < 64 && !created; attempt++) {
        uint64_t nonce = atomic_fetch_add_explicit(
            &g_cold_start_receipt_nonce, 1, memory_order_relaxed);
        int tn = snprintf(tmp, sizeof(tmp), "%s.tmp.%016llx", resolved,
                          (unsigned long long)nonce);
        if (tn < 0 || (size_t)tn >= sizeof(tmp))
            LOG_FAIL(COLD_START_SUBSYS, "receipt write: tmp path too long");
        created = platform_private_file_create(tmp, &staging);
    }
    if (!created)
        LOG_FAIL(COLD_START_SUBSYS, "receipt write: staging create failed");
    bool ok = platform_private_file_write_at(&staging, content, (size_t)cn, 0) &&
              platform_private_file_flush(&staging) &&
              platform_private_file_replace(&staging, tmp, resolved) &&
              platform_private_parent_flush(parent);
    platform_private_file_close(&staging);
    if (!ok) {
        (void)platform_private_file_unlink_missing_ok(tmp);
        LOG_FAIL(COLD_START_SUBSYS, "receipt write: durable replacement failed");
    }
    LOG_INFO(COLD_START_SUBSYS, "stage '%s' %s receipt written (%s)",
             cold_start_stage_name(stage), refused ? "REFUSAL" : "success", path);
    return true;
}

/* Extract the value of `key=` from a receipt buffer into out (bounded). Returns
 * true iff the key line is present. */
static bool cold_start_receipt_field(const char *buf, const char *key,
                                     char *out, size_t out_n)
{
    if (out_n)
        out[0] = '\0';
    size_t keylen = strlen(key);
    const char *p = buf;
    while (p && *p) {
        /* Match key= at the start of a line. */
        if (strncmp(p, key, keylen) == 0 && p[keylen] == '=') {
            const char *v = p + keylen + 1;
            const char *end = strchr(v, '\n');
            size_t len = end ? (size_t)(end - v) : strlen(v);
            if (len >= out_n)
                len = out_n ? out_n - 1 : 0;
            if (out_n) {
                memcpy(out, v, len);
                out[len] = '\0';
            }
            return true;
        }
        const char *nl = strchr(p, '\n');
        if (!nl)
            break;
        p = nl + 1;
    }
    return false;
}

/* Read + validate a receipt into `buf`: true iff it exists, carries the magic,
 * and its parameter matches `param` (both-NULL equal). Leaves the raw receipt in
 * `buf` for the caller to inspect `outcome`. */
static bool cold_start_receipt_load(const char *datadir,
                                    enum cold_start_stage stage,
                                    const char *param, char *buf, size_t buf_n)
{
    char path[PATH_MAX];
    if (cold_start_receipt_path(datadir, stage, path, sizeof(path)) < 0)
        return false;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before;
    struct platform_positioned_file_snapshot after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false;
    bool valid = platform_positioned_file_is_private(&file) &&
                 platform_positioned_file_snapshot(&file, &before) &&
                 before.size > 0 && before.size < buf_n;
    int64_t r = valid ? platform_positioned_file_read(
                            &file, buf, (size_t)before.size, 0)
                      : -1;
    bool stable = valid && r == (int64_t)before.size &&
                  platform_positioned_file_snapshot(&file, &after) &&
                  before.size == after.size &&
                  before.modified_seconds == after.modified_seconds &&
                  before.modified_nanoseconds == after.modified_nanoseconds &&
                  before.changed_seconds == after.changed_seconds &&
                  before.changed_nanoseconds == after.changed_nanoseconds &&
                  before.volume == after.volume &&
                  before.file_low == after.file_low &&
                  before.file_high == after.file_high;
    platform_positioned_file_close(&file);
    if (!stable)
        return false;
    buf[(size_t)r] = '\0';

    char magic[32];
    if (!cold_start_receipt_field(buf, "magic", magic, sizeof(magic)) ||
        strcmp(magic, COLD_START_MAGIC) != 0)
        return false;

    char has_param[8];
    bool recorded_has = cold_start_receipt_field(buf, "has_param", has_param,
                                                 sizeof(has_param)) &&
                        strcmp(has_param, "1") == 0;
    bool want_has = (param && param[0]);
    if (recorded_has != want_has)
        return false;
    if (!want_has)
        return true; /* both parameter-less — parameter matches */

    char recorded_param[PATH_MAX];
    if (!cold_start_receipt_field(buf, "param", recorded_param,
                                  sizeof(recorded_param)))
        return false;
    return strcmp(recorded_param, param) == 0;
}

/* True iff the receipt records a REFUSAL (outcome=refused); an absent outcome
 * field reads as a success receipt (forward-compatible with v1). */
static bool cold_start_receipt_is_refused(const char *buf)
{
    char outcome[16];
    return cold_start_receipt_field(buf, "outcome", outcome, sizeof(outcome)) &&
           strcmp(outcome, "refused") == 0;
}

bool cold_start_receipt_matches(const char *datadir, enum cold_start_stage stage,
                                const char *param)
{
    char buf[PATH_MAX + COLD_START_REASON_MAX + 256];
    if (!cold_start_receipt_load(datadir, stage, param, buf, sizeof(buf)))
        return false;
    return !cold_start_receipt_is_refused(buf); /* a refusal is not "stage done" */
}

bool cold_start_receipt_refused(const char *datadir, enum cold_start_stage stage,
                                const char *param, char *reason, size_t reason_n)
{
    if (reason && reason_n)
        reason[0] = '\0';
    char buf[PATH_MAX + COLD_START_REASON_MAX + 256];
    if (!cold_start_receipt_load(datadir, stage, param, buf, sizeof(buf)))
        return false;
    if (!cold_start_receipt_is_refused(buf))
        return false;
    if (reason && reason_n)
        (void)cold_start_receipt_field(buf, "reason", reason, reason_n);
    return true;
}

enum cold_start_stage cold_start_plan_next(const struct cold_start_plan *plan)
{
    static const enum cold_start_stage order[COLD_START_PREP_STAGE_COUNT] = {
        COLD_START_STAGE_HEADERS,
        COLD_START_STAGE_SEED,
        COLD_START_STAGE_BUNDLE,
    };
    if (!plan || !plan->datadir || !plan->datadir[0])
        return COLD_START_STAGE_SERVE;
    for (int i = 0; i < COLD_START_PREP_STAGE_COUNT; i++) {
        enum cold_start_stage s = order[i];
        if (!cold_start_stage_configured(plan, s))
            continue;
        if (!cold_start_receipt_matches(plan->datadir, s,
                                        cold_start_stage_param(plan, s)))
            return s;
    }
    return COLD_START_STAGE_SERVE;
}

/* Copy `src` into `dst` (bounded, single-lined, always NUL-terminated). */
static void cold_start_reason_copy(char *dst, size_t dst_n, const char *src)
{
    cold_start_singleline(src, dst, dst_n);
}

enum cold_start_result cold_start_drive(const struct cold_start_plan *plan,
                                        cold_start_stage_runner_fn runner,
                                        void *user,
                                        enum cold_start_stage *out_reached,
                                        char *reason, size_t reason_n)
{
    if (reason && reason_n)
        reason[0] = '\0';
    if (out_reached)
        *out_reached = COLD_START_STAGE_SERVE;
    if (!plan || !plan->datadir || !plan->datadir[0]) {
        cold_start_reason_copy(reason, reason_n, "empty plan/datadir");
        LOG_WARN(COLD_START_SUBSYS, "drive: empty plan/datadir");
        return COLD_START_TRANSIENT;
    }
    if (!runner) {
        cold_start_reason_copy(reason, reason_n, "NULL stage runner");
        LOG_WARN(COLD_START_SUBSYS, "drive: NULL stage runner");
        return COLD_START_TRANSIENT;
    }

    /* Bounded: each iteration serves, stops (transient/blocked), or converts one
     * prep stage to "success receipt present" — at most prep-count + 1 loops. */
    for (int guard = 0; guard <= COLD_START_PREP_STAGE_COUNT; guard++) {
        enum cold_start_stage next = cold_start_plan_next(plan);
        if (out_reached)
            *out_reached = next;
        if (next == COLD_START_STAGE_SERVE)
            return COLD_START_OK;

        const char *param = cold_start_stage_param(plan, next);

        /* Sticky refusal: a prior run REFUSED this stage under this same param.
         * Refusals are decisions — never auto-retry; re-emit the verdict. */
        char sticky[COLD_START_REASON_MAX];
        if (cold_start_receipt_refused(plan->datadir, next, param, sticky,
                                       sizeof(sticky))) {
            LOG_WARN(COLD_START_SUBSYS, "stage '%s' has a sticky REFUSAL "
                     "receipt — staying blocked (change the bound parameter to "
                     "re-evaluate): %s", cold_start_stage_name(next), sticky);
            cold_start_reason_copy(reason, reason_n, sticky);
            return COLD_START_BLOCKED;
        }

        LOG_INFO(COLD_START_SUBSYS, "running stage '%s'",
                 cold_start_stage_name(next));
        char stage_reason[COLD_START_REASON_MAX];
        stage_reason[0] = '\0';
        enum cold_start_result rc =
            runner(plan, next, user, stage_reason, sizeof(stage_reason));

        if (rc == COLD_START_BLOCKED) {
            /* A decision refusal — persist a refusal receipt (verbatim) so a
             * rerun stays blocked, then report BLOCKED. */
            if (!cold_start_receipt_write(plan->datadir, next, param, true,
                                          stage_reason))
                LOG_WARN(COLD_START_SUBSYS, "stage '%s' refused but its refusal "
                         "receipt could not be persisted — a rerun will re-run "
                         "the stage", cold_start_stage_name(next));
            LOG_WARN(COLD_START_SUBSYS, "stage '%s' REFUSED (decision — not "
                     "retried): %s", cold_start_stage_name(next), stage_reason);
            cold_start_reason_copy(reason, reason_n, stage_reason);
            return COLD_START_BLOCKED;
        }
        if (rc != COLD_START_OK) {
            LOG_WARN(COLD_START_SUBSYS, "stage '%s' failed transiently — halting "
                     "(no receipt written; rerun -cold-start to resume here): %s",
                     cold_start_stage_name(next), stage_reason);
            cold_start_reason_copy(reason, reason_n, stage_reason);
            return COLD_START_TRANSIENT;
        }
        if (!cold_start_receipt_write(plan->datadir, next, param, false, NULL)) {
            LOG_WARN(COLD_START_SUBSYS, "stage '%s' succeeded but its receipt "
                     "could not be persisted — halting to avoid an unrecordable "
                     "resume point", cold_start_stage_name(next));
            cold_start_reason_copy(reason, reason_n,
                                   "success receipt could not be persisted");
            return COLD_START_TRANSIENT;
        }
    }
    cold_start_reason_copy(reason, reason_n,
                           "exceeded stage bound without reaching serve");
    LOG_WARN(COLD_START_SUBSYS, "drive: exceeded stage bound without reaching "
             "serve (a receipt is not persisting?)");
    return COLD_START_TRANSIENT;
}

/* ── (2) Live driver ──────────────────────────────────────────────────── */

/* Resolve this process's executable path, stripping any kernel " (deleted)"
 * suffix a mid-deploy readlink can append. */
static bool cold_start_self_exe(char *buf, size_t n)
{
    if (!os_proc_exe_path(buf, n))
        return false;
    size_t len = strlen(buf);
    static const char del[] = " (deleted)";
    size_t dl = sizeof(del) - 1;
    if (len >= dl && strcmp(buf + len - dl, del) == 0)
        buf[len - dl] = '\0';
    return buf[0] != '\0';
}

/* The token an existing verb (e.g. -install-consensus-bundle) prints to stderr
 * to signal a DECISION refusal, as opposed to a transient error/crash. */
#define COLD_START_REFUSAL_TOKEN "REFUSED:"

/* Bounded tail of a child's stderr, big enough to hold the final REFUSED line
 * plus surrounding context. */
#define COLD_START_TAIL_CAP 4096

/* Append `n` bytes of `chunk` to the fixed-capacity tail, discarding the oldest
 * bytes on overflow (only the END of the child's stderr matters — verbs print
 * their terminal REFUSED/INSTALLED line last). The copy length is always <= n
 * (bounded by the caller's read), so it never reads past `chunk`. */
static void cold_start_tail_append(char *tail, size_t *tail_len, size_t cap,
                                   const char *chunk, size_t n)
{
    /* Only the final `cap` bytes of the stream ever matter — if a single chunk
     * already exceeds cap, keep just its tail. */
    if (n > cap) {
        chunk += (n - cap);
        n = cap;
    }
    if (*tail_len + n > cap) {
        size_t drop = *tail_len + n - cap;
        memmove(tail, tail + drop, *tail_len - drop);
        *tail_len -= drop;
    }
    memcpy(tail + *tail_len, chunk, n);
    *tail_len += n;
}

/* Extract the verbatim REFUSED line (from the token to end-of-line) out of the
 * child's stderr tail into `reason`. Returns true iff the token was present. */
static bool cold_start_extract_refusal(const char *tail, char *reason,
                                       size_t reason_n)
{
    const char *hit = strstr(tail, COLD_START_REFUSAL_TOKEN);
    if (!hit)
        return false;
    /* Take the LAST occurrence — the terminal refusal is what matters. */
    const char *next;
    while ((next = strstr(hit + 1, COLD_START_REFUSAL_TOKEN)) != NULL)
        hit = next;
    const char *end = strchr(hit, '\n');
    size_t len = end ? (size_t)(end - hit) : strlen(hit);
    cold_start_singleline_bounded(hit, len, reason, reason_n);
    return true;
}

/* Fork/exec a child (argv NULL-terminated), teeing its stderr to ours while
 * capturing a bounded tail, then classify: OK (exit 0); BLOCKED (non-zero exit
 * AND a printed REFUSED line — a decision, `reason` = that verbatim line);
 * TRANSIENT (any other non-zero/signal/spawn failure, `reason` = a short note). */
static enum cold_start_result cold_start_spawn_classify(char *const child_argv[],
                                                        char *reason,
                                                        size_t reason_n)
{
    if (reason && reason_n)
        reason[0] = '\0';

    char exe[PATH_MAX];
    if (!cold_start_self_exe(exe, sizeof(exe))) {
        cold_start_reason_copy(reason, reason_n,
                               "cannot resolve own executable path");
        LOG_ERROR(COLD_START_SUBSYS, "spawn: cannot resolve own executable path");
        return COLD_START_TRANSIENT;
    }

#ifdef _WIN32
    wchar_t command[32768];
    size_t used = 0;
    command[0] = L'\0';
    for (size_t ai = 0; child_argv[ai]; ai++) {
        wchar_t arg[32768];
        int converted = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                             child_argv[ai], -1, arg,
                                             (int)(sizeof(arg) / sizeof(*arg)));
        if (converted <= 0 || (ai && used + 1 >= 32768)) {
            cold_start_reason_copy(reason, reason_n,
                                   "child argument conversion failed");
            return COLD_START_TRANSIENT;
        }
        if (ai)
            command[used++] = L' ';
        if (used + 2 >= 32768)
            return COLD_START_TRANSIENT;
        command[used++] = L'"';
        size_t slashes = 0;
        for (const wchar_t *p = arg;; p++) {
            if (*p == L'\\') {
                slashes++;
                continue;
            }
            size_t copies = slashes;
            if (*p == L'"' || *p == L'\0')
                copies *= 2;
            if (used + copies + 2 >= 32768)
                return COLD_START_TRANSIENT;
            while (copies--)
                command[used++] = L'\\';
            slashes = 0;
            if (*p == L'\0')
                break;
            if (*p == L'"')
                command[used++] = L'\\';
            command[used++] = *p;
        }
        command[used++] = L'"';
        command[used] = L'\0';
    }

    SECURITY_ATTRIBUTES sa = {.nLength = sizeof(sa),
                              .lpSecurityDescriptor = NULL,
                              .bInheritHandle = TRUE};
    HANDLE pipe_read = NULL;
    HANDLE pipe_write = NULL;
    if (!CreatePipe(&pipe_read, &pipe_write, &sa, 0) ||
        !SetHandleInformation(pipe_read, HANDLE_FLAG_INHERIT, 0)) {
        if (pipe_read) CloseHandle(pipe_read);
        if (pipe_write) CloseHandle(pipe_write);
        cold_start_reason_copy(reason, reason_n, "stderr pipe creation failed");
        return COLD_START_TRANSIENT;
    }
    STARTUPINFOW si = {.cb = sizeof(si),
                       .dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW,
                       .wShowWindow = SW_HIDE,
                       .hStdInput = GetStdHandle(STD_INPUT_HANDLE),
                       .hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE),
                       .hStdError = pipe_write};
    PROCESS_INFORMATION pi = {0};
    HANDLE job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    bool job_ok = job && SetInformationJobObject(
                              job, JobObjectExtendedLimitInformation, &limits,
                              sizeof(limits));
    BOOL spawned = job_ok && CreateProcessW(
        NULL, command, NULL, NULL, TRUE, CREATE_NO_WINDOW | CREATE_SUSPENDED,
        NULL, NULL, &si, &pi);
    CloseHandle(pipe_write);
    if (!spawned || !AssignProcessToJobObject(job, pi.hProcess) ||
        ResumeThread(pi.hThread) == (DWORD)-1) {
        if (spawned) {
            TerminateProcess(pi.hProcess, 127);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        CloseHandle(pipe_read);
        if (job) CloseHandle(job);
        cold_start_reason_copy(reason, reason_n, "CreateProcessW failed");
        return COLD_START_TRANSIENT;
    }
    CloseHandle(pi.hThread);
    char tail[COLD_START_TAIL_CAP + 1];
    size_t tail_len = 0;
    char chunk[1024];
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(pipe_read, chunk, sizeof(chunk), &got, NULL) || got == 0)
            break;
        (void)fwrite(chunk, 1, got, stderr);
        (void)fflush(stderr);
        cold_start_tail_append(tail, &tail_len, COLD_START_TAIL_CAP, chunk,
                               (size_t)got);
    }
    CloseHandle(pipe_read);
    DWORD waited = WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 127;
    bool exited = waited == WAIT_OBJECT_0 &&
                  GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(job);
    tail[tail_len] = '\0';
    if (exited && exit_code == 0)
        return COLD_START_OK;
    char refusal[COLD_START_REASON_MAX];
    if (cold_start_extract_refusal(tail, refusal, sizeof(refusal))) {
        cold_start_reason_copy(reason, reason_n, refusal);
        return COLD_START_BLOCKED;
    }
    char msg[96];
    if (exited)
        snprintf(msg, sizeof(msg), "child exited with code %lu",
                 (unsigned long)exit_code);
    else
        snprintf(msg, sizeof(msg), "child wait failed");
    cold_start_reason_copy(reason, reason_n, msg);
    LOG_WARN(COLD_START_SUBSYS, "%s", msg);
    return COLD_START_TRANSIENT;
#else
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        cold_start_reason_copy(reason, reason_n, "stderr pipe creation failed");
        LOG_ERROR(COLD_START_SUBSYS, "spawn: pipe failed: %s", strerror(errno));
        return COLD_START_TRANSIENT;
    }

    pid_t pid = fork();
    if (pid < 0) {
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        cold_start_reason_copy(reason, reason_n, "fork failed");
        LOG_ERROR(COLD_START_SUBSYS, "spawn: fork failed: %s", strerror(errno));
        return COLD_START_TRANSIENT;
    }
    if (pid == 0) {
        (void)close(pipefd[0]);
        if (dup2(pipefd[1], STDERR_FILENO) < 0)
            _exit(126);
        (void)close(pipefd[1]);
        execv(exe, child_argv);
        /* Only reached on exec failure — goes down the captured stderr. */
        fprintf(stderr, "cold_start: execv %s failed: %s\n", exe,
                strerror(errno));
        _exit(127);
    }

    (void)close(pipefd[1]);
    char tail[COLD_START_TAIL_CAP + 1];
    size_t tail_len = 0;
    char chunk[1024];
    for (;;) {
        ssize_t m = read(pipefd[0], chunk, sizeof(chunk));
        if (m < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (m == 0)
            break;
        /* Operator tee, discarded on purpose: the refusal/exit-code decision
         * below reads `tail`, never the terminal, so a dead stderr cannot
         * change it. The loop is the part that matters — an unlooped write(2)
         * short-writes the transcript the operator is reading. */
        (void)zcl_write_all(STDERR_FILENO, chunk, (size_t)m);
        cold_start_tail_append(tail, &tail_len, COLD_START_TAIL_CAP, chunk,
                               (size_t)m);
    }
    (void)close(pipefd[0]);
    tail[tail_len] = '\0';

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR)
            continue;
        cold_start_reason_copy(reason, reason_n, "waitpid failed");
        LOG_ERROR(COLD_START_SUBSYS, "spawn: waitpid failed: %s",
                  strerror(errno));
        return COLD_START_TRANSIENT;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return COLD_START_OK;

    /* Non-zero / abnormal: a printed REFUSED line makes it a decision. */
    char refusal[COLD_START_REASON_MAX];
    if (cold_start_extract_refusal(tail, refusal, sizeof(refusal))) {
        cold_start_reason_copy(reason, reason_n, refusal);
        return COLD_START_BLOCKED;
    }
    if (WIFEXITED(status)) {
        char msg[96];
        snprintf(msg, sizeof(msg), "child exited with code %d",
                 WEXITSTATUS(status));
        cold_start_reason_copy(reason, reason_n, msg);
        LOG_WARN(COLD_START_SUBSYS, "%s", msg);
    } else if (WIFSIGNALED(status)) {
        char msg[96];
        snprintf(msg, sizeof(msg), "child killed by signal %d",
                 WTERMSIG(status));
        cold_start_reason_copy(reason, reason_n, msg);
        LOG_WARN(COLD_START_SUBSYS, "%s", msg);
    } else {
        cold_start_reason_copy(reason, reason_n, "child ended abnormally");
        LOG_WARN(COLD_START_SUBSYS, "child ended abnormally (status=0x%x)",
                 status);
    }
    return COLD_START_TRANSIENT;
#endif
}

/* Live stage runner: fork/exec the existing verb for each prep stage, classifying
 * the child's outcome. The BUNDLE stage dispatches the EXISTING
 * -install-consensus-bundle verb path unchanged (a black box to this driver). */
static enum cold_start_result cold_start_run_stage_live(
    const struct cold_start_plan *plan, enum cold_start_stage stage, void *user,
    char *reason, size_t reason_n)
{
    char exe[PATH_MAX];
    (void)user;
    if (!cold_start_self_exe(exe, sizeof(exe))) {
        cold_start_reason_copy(reason, reason_n, "cannot resolve executable");
        LOG_ERROR(COLD_START_SUBSYS, "run stage: cannot resolve executable");
        return COLD_START_TRANSIENT;
    }

    char datadir_arg[PATH_MAX + 16];
    if (snprintf(datadir_arg, sizeof(datadir_arg), "-datadir=%s",
                 plan->datadir) >= (int)sizeof(datadir_arg)) {
        cold_start_reason_copy(reason, reason_n, "datadir path too long");
        LOG_ERROR(COLD_START_SUBSYS, "run stage: datadir too long");
        return COLD_START_TRANSIENT;
    }

    switch (stage) {
    case COLD_START_STAGE_HEADERS: {
        /* --importblockindex MUST be argv[1] or it silently no-ops; we build
         * argv so it always is. Target db = <datadir>/node.db. */
        char db_path[PATH_MAX + 16];
        if (snprintf(db_path, sizeof(db_path), "%s/node.db", plan->datadir) >=
            (int)sizeof(db_path)) {
            cold_start_reason_copy(reason, reason_n, "node.db path too long");
            LOG_ERROR(COLD_START_SUBSYS, "run stage: node.db path too long");
            return COLD_START_TRANSIENT;
        }
        char *argv[] = { exe, (char *)"--importblockindex",
                         (char *)plan->header_source, db_path, NULL };
        return cold_start_spawn_classify(argv, reason, reason_n);
    }
    case COLD_START_STAGE_SEED: {
        /* Seed as a clean one-shot: -coldstart-seed-oneshot makes app_init apply
         * the seed then exit before services (config/src/boot.c). Headers are
         * already imported (previous stage), so the snapshot gate binds. */
        char seed_arg[PATH_MAX + 40];
        if (snprintf(seed_arg, sizeof(seed_arg),
                     "-load-snapshot-at-own-height=%s", plan->seed_snapshot) >=
            (int)sizeof(seed_arg)) {
            cold_start_reason_copy(reason, reason_n, "seed path too long");
            LOG_ERROR(COLD_START_SUBSYS, "run stage: seed path too long");
            return COLD_START_TRANSIENT;
        }
        char *argv[] = { exe, datadir_arg, seed_arg,
                         (char *)"-coldstart-seed-oneshot", NULL };
        return cold_start_spawn_classify(argv, reason, reason_n);
    }
    case COLD_START_STAGE_BUNDLE: {
        /* -install-consensus-bundle is terminal (installs then _exit()s). Runs
         * after the seed so the bundle installs onto the seeded datadir. Its
         * REFUSED lines are classified by cold_start_spawn_classify as a
         * decision (blocked, never auto-retried). */
        char bundle_arg[PATH_MAX + 40];
        if (snprintf(bundle_arg, sizeof(bundle_arg),
                     "-install-consensus-bundle=%s", plan->install_bundle) >=
            (int)sizeof(bundle_arg)) {
            cold_start_reason_copy(reason, reason_n, "bundle path too long");
            LOG_ERROR(COLD_START_SUBSYS, "run stage: bundle path too long");
            return COLD_START_TRANSIENT;
        }
        char *argv[] = { exe, datadir_arg, bundle_arg, NULL };
        return cold_start_spawn_classify(argv, reason, reason_n);
    }
    case COLD_START_STAGE_SERVE:
        cold_start_reason_copy(reason, reason_n, "SERVE is not a spawned stage");
        LOG_ERROR(COLD_START_SUBSYS, "run stage: SERVE is not a spawned prep "
                  "stage");
        return COLD_START_TRANSIENT;
    }
    cold_start_reason_copy(reason, reason_n, "unknown stage");
    LOG_ERROR(COLD_START_SUBSYS, "run stage: unknown stage %d", (int)stage);
    return COLD_START_TRANSIENT;
}

/* Exec a plain serving boot: the original argv minus the cold-start-only flags
 * (-cold-start, -cold-start-source=, -cold-start-seed=, -cold-start-bundle=) and
 * minus a raw -install-consensus-bundle= (defensive — the driver dispatches that
 * terminal verb itself via the BUNDLE stage; letting it reach the serving boot
 * would re-trigger a terminal install). Does not return on success. */
static int cold_start_exec_serve(int argc, char **argv)
{
    char exe[PATH_MAX];
    if (!cold_start_self_exe(exe, sizeof(exe)))
        LOG_ERR(COLD_START_SUBSYS, "serve: cannot resolve executable");

    char **serve_argv =
        zcl_malloc(((size_t)argc + 1) * sizeof(*serve_argv), "coldstart_serve_argv");
    if (!serve_argv)
        LOG_ERR(COLD_START_SUBSYS, "serve: argv alloc failed");
    int n = 0;
    serve_argv[n++] = exe;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-cold-start") == 0 ||
            strncmp(argv[i], "-cold-start-source=", 19) == 0 ||
            strncmp(argv[i], "-cold-start-seed=", 17) == 0 ||
            strncmp(argv[i], "-cold-start-bundle=", 19) == 0 ||
            strncmp(argv[i], "-install-consensus-bundle=", 26) == 0)
            continue;
        serve_argv[n++] = argv[i];
    }
    serve_argv[n] = NULL;

    LOG_INFO(COLD_START_SUBSYS, "all prep stages complete — exec serving boot");
#ifdef _WIN32
    enum cold_start_result served =
        cold_start_spawn_classify(serve_argv, NULL, 0);
    free(serve_argv);
    return served == COLD_START_OK ? 0 : 1;
#else
    execv(exe, serve_argv);
    int e = errno;
    free(serve_argv);
    LOG_ERR(COLD_START_SUBSYS, "serve: execv failed: %s", strerror(e));
#endif
}

int boot_cold_start_run(int argc, char **argv)
{
    struct cold_start_plan plan = {0};
    plan.datadir = NULL;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-datadir=", 9) == 0)
            plan.datadir = argv[i] + 9;
        else if (strncmp(argv[i], "-cold-start-source=", 19) == 0)
            plan.header_source = argv[i] + 19;
        else if (strncmp(argv[i], "-cold-start-seed=", 17) == 0)
            plan.seed_snapshot = argv[i] + 17;
        else if (strncmp(argv[i], "-cold-start-bundle=", 19) == 0)
            plan.install_bundle = argv[i] + 19;
    }

    /* Default datadir mirrors the rest of the binary. */
    static char default_datadir[PATH_MAX];
    if (!plan.datadir || !plan.datadir[0]) {
        const char *home = getenv("HOME");
        if (snprintf(default_datadir, sizeof(default_datadir),
                     "%s/.zclassic-c23", home ? home : ".") >=
            (int)sizeof(default_datadir))
            LOG_ERR(COLD_START_SUBSYS, "default datadir path too long");
        plan.datadir = default_datadir;
    }

    /* Default header source: a co-located legacy zclassicd datadir with a block
     * index. Absent => skip the header stage and let the serving boot P2P-sync
     * headers. */
    static char default_source[PATH_MAX];
    if (!plan.header_source || !plan.header_source[0]) {
        const char *home = getenv("HOME");
        if (home && home[0]) {
            char idx[PATH_MAX];
            if (snprintf(idx, sizeof(idx), "%s/.zclassic/blocks/index", home) <
                (int)sizeof(idx)) {
                struct platform_directory_list probe = {0};
                if (platform_directory_list_regular_sorted(idx, &probe)) {
                    platform_directory_list_free(&probe);
                    if (snprintf(default_source, sizeof(default_source),
                                 "%s/.zclassic", home) <
                        (int)sizeof(default_source))
                        plan.header_source = default_source;
                }
            }
        }
    }

    LOG_INFO(COLD_START_SUBSYS,
             "cold-start: datadir=%s source=%s seed=%s bundle=%s",
             plan.datadir,
             plan.header_source ? plan.header_source : "(P2P)",
             plan.seed_snapshot ? plan.seed_snapshot : "(none)",
             plan.install_bundle ? plan.install_bundle : "(none)");
    printf("=== ZClassic cold-start driver ===\n"
           "  datadir : %s\n"
           "  headers : %s\n"
           "  seed    : %s\n"
           "  bundle  : %s\n\n",
           plan.datadir,
           plan.header_source ? plan.header_source : "(P2P header sync)",
           plan.seed_snapshot ? plan.seed_snapshot : "(none)",
           plan.install_bundle ? plan.install_bundle : "(none)");

    enum cold_start_stage reached = COLD_START_STAGE_SERVE;
    char reason[COLD_START_REASON_MAX];
    reason[0] = '\0';
    enum cold_start_result rc =
        cold_start_drive(&plan, cold_start_run_stage_live, NULL, &reached,
                         reason, sizeof(reason));

    if (rc == COLD_START_BLOCKED) {
        /* A DECISION refusal — sticky, never auto-retried. The refusal receipt
         * under <datadir>/coldstart/ records the reason verbatim. */
        const char *stage = cold_start_stage_name(reached);
        printf("COLD-START: BLOCKED:%s:%s\n", stage, reason);
        fflush(stdout);
        LOG_ERROR(COLD_START_SUBSYS, "COLD-START: BLOCKED:%s:%s", stage, reason);
        fprintf(stderr,
                "cold-start: BLOCKED at stage '%s' by a decision refusal — NOT "
                "retried. Re-running the SAME -cold-start command stays blocked; "
                "resolve the cause and change/clear the bundle parameter, or "
                "remove %s/coldstart/%s.receipt to re-evaluate.\n",
                stage, plan.datadir, stage);
        return 2;
    }
    if (rc != COLD_START_OK) {
        /* Transient — resumable; a rerun continues at this same stage. */
        const char *stage = cold_start_stage_name(reached);
        printf("COLD-START: INCOMPLETE:%s:%s\n", stage, reason);
        fflush(stdout);
        LOG_WARN(COLD_START_SUBSYS, "COLD-START: INCOMPLETE:%s:%s", stage,
                 reason);
        fprintf(stderr,
                "cold-start: stopped at stage '%s' (transient). Fix the cause "
                "and re-run the SAME -cold-start command; completed stages are "
                "skipped via their receipts under %s/coldstart/.\n",
                stage, plan.datadir);
        return 1;
    }

    /* Every configured prep stage is receipted — announce completion, then
     * become the serving node. */
    printf("COLD-START: COMPLETE\n");
    fflush(stdout);
    LOG_INFO(COLD_START_SUBSYS, "COLD-START: COMPLETE");
    return cold_start_exec_serve(argc, argv);
}
