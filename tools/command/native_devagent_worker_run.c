/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ONE bounded executor run beneath dev.agent.worker — the caps,
 *          the child-side result record, the result parse, the required
 *          gate, the receipt-facing outcome mapping, and the Windows
 *          confined backend. The POSIX fork backend (in
 *          native_devagent_worker.c) and the Windows backend here call the
 *          same functions, so a timeout, a crash, an ENOMEM, or a failing
 *          executor reaches the receipt through the same fields on every
 *          host.
 *
 * WINDOWS BACKEND. No fork: the parent stores the job as executor_job.json
 * in the run dir, then re-enters its own image as
 *     <image> --z23-internal-agent-worker-child <rundir>
 * through platform_confined_start: restricted token (privileges stripped,
 * Administrators and other privileged groups deny-only) at LOW integrity,
 * a kill-on-close job carrying the same memory and CPU caps POSIX puts in
 * RLIMIT_AS/RLIMIT_CPU plus an active-process cap, low-writable labels on
 * exactly the run dir and the brief's named worktree, NUL as the only
 * inherited handle, and an explicit allowlisted environment. The parent
 * keeps the wall clock and kills the whole job (grandchildren included) on
 * timeout or shutdown. The child refuses to run anything unless it can
 * observe that confinement on itself. If the backend cannot arm, nothing
 * runs: the outcome is launch-failed, never an unconfined run.
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/native_devagent.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/confined_process.h"
#include "platform/os_proc.h"
#include "platform/process_lifecycle.h"
#include "platform/time_compat.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define WKR_RESULT_FILE "executor_result.json"
#define WKR_MEM_MB_MAX (1024LL * 1024LL) /* 1 TiB: overflow guard only */
#define WKR_JOB_TEXT_CAP (64u * 1024u)

/* ── bounded small files ──────────────────────────────────────────────── */

bool zcl_devagent_worker_read_file(const char *path, char *out, size_t cap)
{
    FILE *f;
    size_t n;
    if (!path || !out || cap == 0)
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    n = fread(out, 1, cap - 1, f);
    if (ferror(f) || !feof(f)) {
        (void)fclose(f);
        return false;
    }
    out[n] = '\0';
    (void)fclose(f);
    return true;
}

bool zcl_devagent_worker_file_exists(const char *path)
{
    struct stat st;
    return path && stat(path, &st) == 0;
}

/* Atomic small write: temp in the same dir renamed over the target, so a
 * crash never leaves a half claim behind. */
bool zcl_devagent_worker_write_atomic(const char *path, const char *text,
                                      size_t len)
{
    char tmp[4096 + 32];
    FILE *f;
    if (!path || !text)
        return false;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
        return false;
    f = fopen(tmp, "wb");
    if (!f)
        return false;
    if (len > 0 && fwrite(text, 1, len, f) != len) {
        (void)fclose(f);
        (void)unlink(tmp);
        return false;
    }
    if (fclose(f) != 0) {
        (void)unlink(tmp);
        return false;
    }
    if (rename(tmp, path) != 0) {
        (void)unlink(tmp);
        return false;
    }
    return true;
}

static const char *wkr_escape_one(unsigned char c, char tmp[8])
{
    if (c == '"')
        return "\\\"";
    if (c == '\\')
        return "\\\\";
    if (c == '\n')
        return "\\n";
    if (c == '\t')
        return "\\t";
    if (c < 0x20) {
        (void)snprintf(tmp, 8, "\\u%04x", c);
        return tmp;
    }
    return NULL;
}

/* JSON string escape for the small files the worker writes. */
bool zcl_devagent_worker_json_escape(const char *in, char *out, size_t cap)
{
    size_t used = 0;
    if (!in || !out || cap == 0)
        return false;
    for (; *in; in++) {
        char tmp[8];
        const char *rep = wkr_escape_one((unsigned char)*in, tmp);
        size_t n = rep ? strlen(rep) : 1u;
        if (used + n >= cap)
            return false;
        if (rep)
            memcpy(out + used, rep, n);
        else
            out[used] = *in;
        used += n;
    }
    out[used] = '\0';
    return true;
}

/* ── caps ──────────────────────────────────────────────────────────────── */

bool zcl_devagent_worker_caps(const struct wkr_drive_opts *opts,
                              struct wkr_caps *caps)
{
    if (!caps)
        return false;
    memset(caps, 0, sizeof(*caps));
    if (!opts)
        return false;
    if (opts->mem_mb > 0 && opts->mem_mb <= WKR_MEM_MB_MAX)
        caps->memory_bytes =
            (unsigned long long)opts->mem_mb * 1024ull * 1024ull;
    caps->cpu_s = opts->cpu_s > 0 ? opts->cpu_s : 0;
    caps->wall_s = opts->time_cap_s > 0 ? opts->time_cap_s : 0;
    caps->active_processes = WKR_ACTIVE_PROCESS_CAP;
    return caps->memory_bytes > 0 && caps->cpu_s > 0 && caps->wall_s > 0;
}

/* ── outcome: the one receipt-facing mapping ───────────────────────────── */

void zcl_devagent_worker_outcome(const struct wkr_spawn_out *out,
                                 bool terminating, struct wkr_outcome *o)
{
    if (!o)
        return;
    memset(o, 0, sizeof(*o));
    if (!out || out->status < 0) {
        o->rc = 127;
        o->terminal = "launch-failed";
        o->note = "executor-launch-failed";
    } else if (out->status == 0) {
        o->rc = 124;
        o->terminal = "timeout";
        o->note = "executor-time-cap";
    } else if (out->signaled || terminating) {
        o->rc = 130;
        o->terminal = "crashed";
        o->note = "executor-signaled";
    } else {
        o->gate = true;
    }
}

/* ── child record: run, write the result file, pick the exit code ─────── */

int zcl_devagent_worker_child_record(const struct wkr_job *job,
                                     wkr_executor_fn exec)
{
    struct wkr_result res;
    char path[4096 + 64], e_term[96], e_ev[8192], line[12288];
    char e_cand[sizeof(res.candidate) * WKR_JSON_ESCAPE_WORST];
    int w;
    if (!job || !exec)
        return 125;
    memset(&res, 0, sizeof(res));
    if (!exec(job, &res))
        return 125;
    if (!zcl_devagent_worker_json_escape(res.terminal, e_term, sizeof(e_term)) ||
        !zcl_devagent_worker_json_escape(res.candidate, e_cand,
                                         sizeof(e_cand)) ||
        !zcl_devagent_worker_json_escape(res.evidence, e_ev, sizeof(e_ev)))
        return 126;
    w = snprintf(line, sizeof(line),
                 "{\"terminal\":\"%s\",\"rc\":%lld,\"candidate\":\"%s\","
                 "\"evidence\":\"%s\",\"tokens_used\":%lld,\"wall_ms\":%lld}\n",
                 e_term, res.rc, e_cand, e_ev, res.tokens_used, res.wall_ms);
    if (w <= 0 || (size_t)w >= sizeof(line))
        return 126;
    if (snprintf(path, sizeof(path), "%s/%s", job->rundir, WKR_RESULT_FILE) >=
        (int)sizeof(path))
        return 126;
    if (!zcl_devagent_worker_write_atomic(path, line, (size_t)w))
        return 126;
    return res.rc >= 0 && res.rc <= 125 ? (int)res.rc : 125;
}

/* ── result parse ──────────────────────────────────────────────────────
 * The executor's own word is preserved verbatim (bounded charset);
 * "completed" stays "completed" here and the gate refuses to upgrade it. */

static bool wkr_word_ok(const char *s)
{
    size_t i;
    if (!s || !s[0] || strlen(s) > 24)
        return false;
    for (i = 0; s[i]; i++) {
        char c = s[i];
        if ((c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '-' &&
            c != '_')
            return false;
    }
    return true;
}

/* Success-sounding executor words that are NOT the closed pass
 * vocabulary. The gate refuses to carry them into the receipt: only
 * pass/PASS gate to pass, everything else that sounds finished gates to
 * gate-refused so no reader mistakes it for completion. */
static bool wkr_success_alias(const char *s)
{
    static const char *const aliases[] = {
        "completed", "complete", "done", "finished", "success",
        "succeeded", "successful", "ok",
    };
    size_t i;
    if (!s)
        return false;
    for (i = 0; i < sizeof(aliases) / sizeof(aliases[0]); i++) {
        if (strcmp(s, aliases[i]) == 0)
            return true;
    }
    return false;
}

/* One raw string field copied out of the result text, unescaped. */
static void wkr_result_field(const char *text, const char *key, char *out,
                             size_t cap)
{
    char pat[64];
    const char *p;
    size_t n = 0;
    if (!text || !key || !out || cap == 0)
        return;
    out[0] = '\0';
    if (snprintf(pat, sizeof(pat), "\"%s\":\"", key) >= (int)sizeof(pat))
        return;
    p = strstr(text, pat);
    if (!p)
        return;
    p += strlen(pat);
    while (p[n] && p[n] != '"' && n + 1 < cap) {
        out[n] = p[n];
        n++;
    }
    out[n] = '\0';
}

static long long wkr_result_int(const char *text, const char *key,
                                long long dflt)
{
    char pat[64];
    const char *p;
    if (!text || !key)
        return dflt;
    if (snprintf(pat, sizeof(pat), "\"%s\":", key) >= (int)sizeof(pat))
        return dflt;
    p = strstr(text, pat);
    if (!p)
        return dflt;
    return strtoll(p + strlen(pat), NULL, 10);
}

bool zcl_devagent_worker_parse_result(const char *rundir,
                                      struct wkr_result *res)
{
    char path[4096 + 64], text[12288];
    char word[32];
    if (!rundir || !res)
        return false;
    if (snprintf(path, sizeof(path), "%s/%s", rundir, WKR_RESULT_FILE) >=
        (int)sizeof(path))
        return false;
    if (!zcl_devagent_worker_read_file(path, text, sizeof(text)))
        return false;
    memset(res, 0, sizeof(*res));
    wkr_result_field(text, "terminal", word, sizeof(word));
    if (!wkr_word_ok(word))
        return false;
    (void)snprintf(res->terminal, sizeof(res->terminal), "%s", word);
    wkr_result_field(text, "candidate", res->candidate,
                     sizeof(res->candidate));
    wkr_result_field(text, "evidence", res->evidence, sizeof(res->evidence));
    res->rc = wkr_result_int(text, "rc", -1);
    res->tokens_used = wkr_result_int(text, "tokens_used", 0);
    res->wall_ms = wkr_result_int(text, "wall_ms", 0);
    return true;
}

/* ── gate: the required Z23 judgment ─────────────────────────────────────
 * "pass" is written only when every condition holds: the executor's own
 * word is already pass/PASS, rc is 0, a candidate is named AND present
 * under the run dir, evidence is present, and tokens fit the cap. A
 * model "completed" with rc 0 and a candidate still gates to
 * "gate-refused": only the gate plus the closed predicate reap success. */

static bool wkr_gate_ready(const struct wkr_job *job,
                           const struct wkr_result *res)
{
    char candpath[4096 + 256];
    bool word, clean, named, evidenced, budgeted;
    word = strcmp(res->terminal, "pass") == 0 ||
           strcmp(res->terminal, "PASS") == 0;
    clean = res->rc == 0;
    named = res->candidate[0] != '\0';
    evidenced = res->evidence[0] != '\0';
    budgeted = res->tokens_used >= 0 && res->tokens_used <= job->token_cap;
    if (!word || !clean || !named || !evidenced || !budgeted)
        return false;
    if (snprintf(candpath, sizeof(candpath), "%s/%s", job->rundir,
                 res->candidate) >= (int)sizeof(candpath))
        return false;
    return zcl_devagent_worker_file_exists(candpath);
}

long long zcl_devagent_worker_gate(const struct wkr_job *job,
                                   const struct wkr_result *res,
                                   char *verdict, size_t cap)
{
    bool word;
    if (!job || !res || !verdict || cap == 0)
        return 1;
    if (wkr_gate_ready(job, res)) {
        (void)snprintf(verdict, cap, "%s", res->terminal);
        return 0;
    }
    word = strcmp(res->terminal, "pass") == 0 ||
           strcmp(res->terminal, "PASS") == 0;
    if (!wkr_word_ok(res->terminal) || res->terminal[0] == '\0')
        (void)snprintf(verdict, cap, "%s", "failed");
    else if (word || wkr_success_alias(res->terminal))
        (void)snprintf(verdict, cap, "%s", "gate-refused");
    else
        (void)snprintf(verdict, cap, "%s", res->terminal);
    return 1;
}

/* ── the job across the process boundary ───────────────────────────────── */

static bool wkr_job_json(const struct wkr_job *job,
                         unsigned long long memory_bytes,
                         struct json_value *v)
{
    json_set_object(v);
    return json_push_kv_str(v, "name", job->name) &&
           json_push_kv_str(v, "kind", job->kind) &&
           json_push_kv_int(v, "attempt", job->attempt) &&
           json_push_kv_int(v, "seq", job->seq) &&
           json_push_kv_str(v, "task", job->task) &&
           json_push_kv_str(v, "model", job->model) &&
           json_push_kv_int(v, "token_cap", job->token_cap) &&
           json_push_kv_int(v, "time_cap_s", job->time_cap_s) &&
           json_push_kv_int(v, "memory_bytes", (int64_t)memory_bytes);
}

bool zcl_devagent_worker_job_store(const struct wkr_job *job,
                                   unsigned long long memory_bytes)
{
    struct json_value v;
    char path[4096 + 64];
    char *text = NULL;
    size_t n = 0;
    bool ok;
    if (!job || !job->rundir[0] || memory_bytes == 0 ||
        memory_bytes > (unsigned long long)INT64_MAX ||
        snprintf(path, sizeof(path), "%s/%s", job->rundir, WKR_JOB_FILE) >=
            (int)sizeof(path))
        return false;
    json_init(&v);
    if (wkr_job_json(job, memory_bytes, &v))
        text = zcl_malloc(WKR_JOB_TEXT_CAP, "worker-job-text");
    if (text)
        n = json_write(&v, text, WKR_JOB_TEXT_CAP);
    ok = n > 0 && n < WKR_JOB_TEXT_CAP &&
         zcl_devagent_worker_write_atomic(path, text, n);
    free(text);
    json_free(&v);
    return ok;
}

static bool wkr_job_str(const struct json_value *v, const char *key,
                        char *out, size_t cap)
{
    const struct json_value *f = json_get(v, key);
    if (!f || f->type != JSON_STR || strlen(json_get_str(f)) >= cap)
        return false;
    (void)snprintf(out, cap, "%s", json_get_str(f));
    return true;
}

static bool wkr_job_int(const struct json_value *v, const char *key,
                        long long *out)
{
    const struct json_value *f = json_get(v, key);
    if (!f || f->type != JSON_INT)
        return false;
    *out = (long long)json_get_int(f);
    return true;
}

static bool wkr_job_fields(const struct json_value *v, struct wkr_job *job,
                           long long *mem)
{
    return wkr_job_str(v, "name", job->name, sizeof(job->name)) &&
           wkr_job_str(v, "kind", job->kind, sizeof(job->kind)) &&
           wkr_job_str(v, "task", job->task, sizeof(job->task)) &&
           wkr_job_str(v, "model", job->model, sizeof(job->model)) &&
           wkr_job_int(v, "attempt", &job->attempt) &&
           wkr_job_int(v, "seq", &job->seq) &&
           wkr_job_int(v, "token_cap", &job->token_cap) &&
           wkr_job_int(v, "time_cap_s", &job->time_cap_s) &&
           wkr_job_int(v, "memory_bytes", mem) && *mem > 0;
}

bool zcl_devagent_worker_job_load(const char *rundir, struct wkr_job *job,
                                  unsigned long long *memory_bytes)
{
    struct json_value v;
    char path[4096 + 64];
    char *text;
    long long mem = 0;
    bool ok;
    if (!rundir || !job || !memory_bytes || strlen(rundir) >= sizeof(job->rundir) ||
        snprintf(path, sizeof(path), "%s/%s", rundir, WKR_JOB_FILE) >=
            (int)sizeof(path))
        return false;
    memset(job, 0, sizeof(*job));
    text = zcl_malloc(WKR_JOB_TEXT_CAP, "worker-job-text");
    json_init(&v);
    ok = text && zcl_devagent_worker_read_file(path, text, WKR_JOB_TEXT_CAP) &&
         json_read(&v, text, strlen(text)) && v.type == JSON_OBJ &&
         wkr_job_fields(&v, job, &mem);
    json_free(&v);
    free(text);
    if (!ok)
        return false;
    (void)snprintf(job->rundir, sizeof(job->rundir), "%s", rundir);
    *memory_bytes = (unsigned long long)mem;
    return true;
}

/* ── write roots ───────────────────────────────────────────────────────── */

static bool wkr_path_absolute(const char *p)
{
    bool drive = ((p[0] >= 'A' && p[0] <= 'Z') ||
                  (p[0] >= 'a' && p[0] <= 'z')) &&
                 p[1] == ':' && (p[2] == '\\' || p[2] == '/');
    return p[0] == '/' || drive || (p[0] == '\\' && p[1] == '\\');
}

/* A root the relabel must never reach: "/", "C:\", "C:/", "\\host". */
static bool wkr_path_is_root(const char *p)
{
    size_t n = strlen(p);
    while (n > 1 && (p[n - 1] == '/' || p[n - 1] == '\\'))
        n--;
    if (n <= 1)
        return true;
    if (n <= 3 && p[1] == ':')
        return true;
    return p[0] == '\\' && p[1] == '\\' && strpbrk(p + 2, "\\/") == NULL;
}

static bool wkr_path_climbs(const char *p)
{
    const char *s = p;
    while ((s = strstr(s, "..")) != NULL) {
        bool start = s == p || s[-1] == '/' || s[-1] == '\\';
        bool end = s[2] == '\0' || s[2] == '/' || s[2] == '\\';
        if (start && end)
            return true;
        s += 2;
    }
    return false;
}

static bool wkr_workspace_ok(const char *ws)
{
    struct stat st;
    char git[4096 + 8];
    if (!ws[0] || !wkr_path_absolute(ws) || wkr_path_is_root(ws) ||
        wkr_path_climbs(ws))
        return false;
    if (stat(ws, &st) != 0 || !S_ISDIR(st.st_mode))
        return false;
    if (snprintf(git, sizeof(git), "%s/.git", ws) >= (int)sizeof(git))
        return false;
    return zcl_devagent_worker_file_exists(git);
}

/* One "<key>: value" line in the header block, the same grammar the Muse
 * executor reads (mx_header_line): the block ends at the first empty line,
 * and the key must start a line followed by ':' and a blank. The worker's
 * identity lines come first and never carry a muse- key. */
static const char *wkr_task_value(const char *task, const char *key,
                                  size_t *len)
{
    size_t kl = strlen(key);
    const char *p = task;
    for (;;) {
        const char *eol = strchr(p, '\n');
        size_t n = eol ? (size_t)(eol - p) : strlen(p);
        if (n == 0 || (n == 1 && p[0] == '\r'))
            return NULL;
        if (n > kl + 2 && strncmp(p, key, kl) == 0 && p[kl] == ':' &&
            (p[kl + 1] == ' ' || p[kl + 1] == '\t')) {
            *len = n - (kl + 2);
            return p + kl + 2;
        }
        if (!eol)
            return NULL;
        p = eol + 1;
    }
}

bool zcl_devagent_worker_task_workspace(const char *task, char *out,
                                        size_t cap)
{
    const char *v;
    size_t n = 0;
    if (!out || cap == 0)
        return false;
    out[0] = '\0';
    if (!task)
        return false;
    v = wkr_task_value(task, "muse-workspace", &n);
    while (v && n > 0 &&
           (v[n - 1] == ' ' || v[n - 1] == '\t' || v[n - 1] == '\r'))
        n--;
    if (!v || n == 0 || n >= cap)
        return false;
    memcpy(out, v, n);
    out[n] = '\0';
    if (!wkr_workspace_ok(out)) {
        out[0] = '\0';
        return false;
    }
    return true;
}

/* ── explicit child environment ──────────────────────────────────────── */

static const char *const wkr_env_allow[] = {
    "SystemRoot", "SystemDrive", "windir",       "PATH",
    "PATHEXT",    "ComSpec",     "USERPROFILE",  "HOMEDRIVE",
    "HOMEPATH",   "LOCALAPPDATA", "APPDATA",     "XDG_STATE_HOME",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
};

static bool wkr_env_put(char storage[][WKR_ENV_ENTRY_MAX], const char **ptrs,
                        size_t cap, size_t *n, const char *key,
                        const char *val)
{
    if (*n >= cap || snprintf(storage[*n], WKR_ENV_ENTRY_MAX, "%s=%s", key,
                              val) >= (int)WKR_ENV_ENTRY_MAX)
        return false;
    ptrs[*n] = storage[*n];
    (*n)++;
    ptrs[*n] = NULL;
    return true;
}

int zcl_devagent_worker_child_env(const char *rundir,
                                  char storage[][WKR_ENV_ENTRY_MAX],
                                  const char **ptrs, size_t cap)
{
    size_t n = 0;
    if (!rundir || !storage || !ptrs || cap == 0)
        return -1;
    ptrs[0] = NULL;
    for (size_t i = 0; i < sizeof(wkr_env_allow) / sizeof(wkr_env_allow[0]);
         i++) {
        const char *val = getenv(wkr_env_allow[i]);
        if (val && val[0] &&
            !wkr_env_put(storage, ptrs, cap, &n, wkr_env_allow[i], val))
            return -1;
    }
    if (!wkr_env_put(storage, ptrs, cap, &n, "TEMP", rundir) ||
        !wkr_env_put(storage, ptrs, cap, &n, "TMP", rundir))
        return -1;
    return (int)n;
}

/* ── Windows backend ───────────────────────────────────────────────────── */

#if defined(_WIN32)
struct wkr_confined_run {
    char image[4096];
    char workspace[4096];
    const char *argv[4];
    const char *roots[2];
    char env_store[WKR_ENV_MAX][WKR_ENV_ENTRY_MAX];
    const char *env[WKR_ENV_MAX + 1];
    struct platform_confined_spec spec;
};

static bool wkr_confined_prepare(const struct wkr_job *job,
                                 const struct wkr_caps *caps,
                                 struct wkr_confined_run *run)
{
    size_t roots = 1;
    if (!os_proc_exe_path(run->image, sizeof(run->image)) ||
        zcl_devagent_worker_child_env(job->rundir, run->env_store, run->env,
                                      WKR_ENV_MAX) < 0)
        return false;
    run->argv[0] = run->image;
    run->argv[1] = WKR_CHILD_FLAG;
    run->argv[2] = job->rundir;
    run->argv[3] = NULL;
    run->roots[0] = job->rundir;
    if (zcl_devagent_worker_task_workspace(job->task, run->workspace,
                                           sizeof(run->workspace)))
        run->roots[roots++] = run->workspace;
    run->spec.image = run->image;
    run->spec.argv = run->argv;
    run->spec.cwd = job->rundir;
    run->spec.env = run->env;
    run->spec.write_roots = run->roots;
    run->spec.write_root_count = roots;
    run->spec.memory_bytes = caps->memory_bytes;
    run->spec.cpu_seconds = (uint64_t)caps->cpu_s;
    run->spec.active_processes = caps->active_processes;
    return true;
}

/* Parent wait in slices: wall cap, shutdown, and exit capture. The same
 * shape as the POSIX wait, with the whole job as the kill target. */
static struct wkr_spawn_out wkr_confined_wait(struct platform_process *proc,
                                              long long cap_s, long long t0_s,
                                              const volatile int *terminating)
{
    struct wkr_spawn_out out;
    memset(&out, 0, sizeof(out));
    out.status = -1;
    for (;;) {
        enum platform_process_wait_result w;
        if (terminating && *terminating) {
            (void)platform_process_terminate(proc, 130u);
            (void)platform_process_wait(proc, 5000u, NULL);
            out.signaled = true;
            break;
        }
        if (cap_s > 0 && platform_time_wall_unix() - t0_s >= cap_s) {
            (void)platform_process_terminate(proc, 124u);
            (void)platform_process_wait(proc, 5000u, NULL);
            out.status = 0;
            break;
        }
        w = platform_process_wait(proc, 25u, NULL);
        if (w == PLATFORM_PROCESS_WAIT_EXITED) {
            out.status = 1;
            break;
        }
        if (w == PLATFORM_PROCESS_WAIT_FAILED)
            break;
    }
    out.wall_ms = (platform_time_wall_unix() - t0_s) * 1000LL;
    return out;
}

/* A release that could not relabel a root is recorded beside run.out:
 * the tree it names is still low-writable and the operator must know. */
static void wkr_note_release_failure(const struct wkr_job *job)
{
    char path[4096 + 64];
    const char *text = "confinement-release=failed\n";
    if (snprintf(path, sizeof(path), "%s/confinement.txt", job->rundir) <
        (int)sizeof(path))
        (void)zcl_devagent_worker_write_atomic(path, text, strlen(text));
}

static struct wkr_spawn_out wkr_spawn_windows(const struct wkr_drive_opts *opts,
                                              const struct wkr_job *job,
                                              const volatile int *terminating)
{
    struct wkr_spawn_out out;
    struct wkr_caps caps;
    struct platform_confined_report report;
    struct platform_process proc;
    struct wkr_confined_run *run;
    long long t0_s;
    memset(&out, 0, sizeof(out));
    out.status = -1;
    if (!zcl_devagent_worker_caps(opts, &caps) ||
        !zcl_devagent_worker_job_store(job, caps.memory_bytes))
        return out;
    run = zcl_calloc(1, sizeof(*run), "worker-confined-run");
    if (!run || !wkr_confined_prepare(job, &caps, run)) {
        free(run);
        return out;
    }
    platform_process_init(&proc);
    t0_s = platform_time_wall_unix();
    if (platform_confined_start(&proc, &run->spec) != PLATFORM_CONFINE_ARMED) {
        free(run);
        return out;
    }
    out = wkr_confined_wait(&proc, caps.wall_s, t0_s, terminating);
    if (!platform_confined_report(&proc, &report))
        out.signaled = true; /* stragglers survived the kill: not a clean exit */
    else if (out.status == 1 && (report.crashed || report.cpu_limit_hit))
        out.signaled = true;
    platform_process_close(&proc);
    if (!platform_confined_release_roots(run->roots,
                                         run->spec.write_root_count))
        wkr_note_release_failure(job);
    free(run);
    return out;
}
#endif

struct wkr_spawn_out zcl_devagent_worker_spawn_confined(
    const struct wkr_drive_opts *opts, const struct wkr_job *job,
    const volatile int *terminating)
{
#if defined(_WIN32)
    struct wkr_spawn_out out;
    if (!opts || !job || !job->rundir[0]) {
        memset(&out, 0, sizeof(out));
        out.status = -1;
        return out;
    }
    return wkr_spawn_windows(opts, job, terminating);
#else
    struct wkr_spawn_out out;
    (void)opts;
    (void)job;
    (void)terminating;
    memset(&out, 0, sizeof(out));
    out.status = -1;
    return out;
#endif
}

int zcl_devagent_worker_child_main(const char *rundir, wkr_executor_fn exec)
{
#if defined(_WIN32)
    struct wkr_job *job;
    unsigned long long mem = 0;
    int rc = 123;
    platform_process_child_prepare_headless();
    if (!rundir || !exec)
        return 2;
    job = zcl_calloc(1, sizeof(*job), "worker-child-job");
    if (!job)
        return 126;
    /* Fail closed: nothing runs unless this process can observe its own
     * job caps and low-integrity token. The parent sees no result file and
     * records executor-no-result. */
    if (zcl_devagent_worker_job_load(rundir, job, &mem) &&
        platform_confined_self_check(mem) == PLATFORM_CONFINE_ARMED)
        rc = zcl_devagent_worker_child_record(job, exec);
    free(job);
    return rc;
#else
    (void)rundir;
    (void)exec;
    return 2;
#endif
}
